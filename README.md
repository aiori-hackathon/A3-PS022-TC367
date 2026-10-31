# A3-PS022-TC367: Kavach — eBPF/XDP Rate Limiting for DNS Query Floods

[![AIORI-3 Track](https://img.shields.io/badge/AIORI--3-Cybersecurity-blue.svg)](https://aiori.in/)
![Problem Statement](https://img.shields.io/badge/Problem%20Statement-PS--022-brightgreen.svg)
![Target OS](https://img.shields.io/badge/Target%20OS-Ubuntu%2024.04.4%20LTS-orange.svg)
![Kernel](https://img.shields.io/badge/Linux%20Kernel-6.14.0--1020--oem-red.svg)
![Data Path](https://img.shields.io/badge/Data%20Path-XDP%20%2F%20eBPF-purple.svg)
![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-lightgrey.svg)

**Team Submission:** `A3-PS022-TC367`  
**Video Demonstration:** [Team Introduction & System Demonstration Video](https://youtu.be/7cTRoE_1nWI)

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Technical Architecture & Algorithms](#2-technical-architecture--algorithms)
3. [Dual Execution Strategy & Testbed Topologies](#3-dual-execution-strategy--testbed-topologies)
4. [Generator Safety Guards & PS-022 Containment](#4-generator-safety-guards--ps-022-containment)
5. [Empirical Calibration](#5-empirical-calibration-s--100000-pps)
6. [Physical Benchmark Matrix Results (108 Runs)](#6-physical-benchmark-matrix-results-108-runs)
7. [Publication Figures](#7-publication-figures)
8. [Repository Organization](#8-repository-organization)
9. [Quickstart & Reproduction Guide](#9-quickstart--reproduction-guide)
10. [Compliance with PS-022 Deliverables](#10-compliance-with-ps-022-deliverables)

---

## 1. Executive Summary

Volumetric UDP DNS query floods exhaust Linux servers because the operating system kernel spends excessive CPU cycles allocating metadata descriptors—the socket buffer (`struct sk_buff`)—before packets ever reach user space. At high packet arrival rates (100k+ PPS), the kernel spends heavy CPU effort in software interrupt (`softirq`) context, causing UDP socket receive queue overflows (`UdpInErrors`) and starving legitimate client queries.

While firewall utilities such as `nftables` can rate-limit traffic, their standard hooks execute **after** `sk_buff` allocation. They protect user-space applications from excess packets, but fail to eliminate per-packet kernel allocation overhead.

**Kavach** implements in-kernel packet filtering and rate limiting at the network interface driver's receive path via **eXpress Data Path (XDP)**:

- **`XDP_DROP`:** Discards flood packets immediately in driver memory, recycling the RX ring buffer descriptor without allocating an `sk_buff` or invoking the network stack.
- **`XDP_PASS`:** Delivers verified, rate-conforming DNS queries and non-DNS infrastructure traffic up the standard Linux network stack to an authoritative DNS daemon (NSD).

```
Conventional Packet Processing Flow:
[Physical NIC] ──> [NIC Driver] ──> [Allocate struct sk_buff] ──> [Netfilter/nftables] ──> [UDP Socket] ──> [DNS Server]
                                           │
                                    Heavy CPU Softirqs
                                 Socket Backlog Overflows

Kavach XDP In-Kernel Flow:
[Physical NIC] ──> [NIC Driver] ──> [Kavach XDP Filter] ──(Drop: Limit/Malformed)──> [Recycle Ring Buffer]
                                           │
                                     (Pass: Legit)
                                           ▼
                                [Allocate struct sk_buff] ──> [Standard Stack] ──> [NSD DNS Server]
```

> **Native vs. generic mode.** The drop-before-`sk_buff` behaviour above applies to **native driver mode** (validated on `veth`, Section 3.2). On the physical lab PCs the Intel `e1000e` driver rejects native attachment on kernel `6.14.0-1020-oem`, so Kavach runs in **generic mode (`xdpgeneric`)**, where the `sk_buff` already exists when the program runs. Drops there still occur before the IP/UDP stack and the UDP socket queue (see Section 3.1).

---

## 2. Technical Architecture & Algorithms

### 2.1 Bounded UDP/DNS Packet Parsing

eBPF safety mandates verifier-guaranteed execution bounds and absence of out-of-bounds memory accesses:

1. **Ethernet & Protocol Validation:** Truncated frames pass (`pass_truncated`). Non-IPv4 frames (including IPv6, ARP and VLAN-tagged frames) pass unchanged (`pass_non_ipv4`).
2. **IPv4 Inspection:** Enforces IPv4 version, dynamic IP Header Length (`ihl = ip->ihl * 4; ihl >= 20`), and frame boundary checks; invalid IPv4 headers pass unchanged (`pass_invalid_ipv4`). Non-UDP traffic passes transparently (`pass_non_udp`).
3. **Fragment Handling:** Non-first IP fragments (`frag_off & 0x1FFF`) lack UDP headers and pass safely (`pass_fragment`). First fragments (`frag_off == 0`) are inspected normally.
4. **UDP & DNS Header Validation:** Enforces UDP destination port 53 (`pass_non53`). Malformed packets are dropped: UDP length < 8 bytes (`drop_bad_udp`), UDP length < 20 bytes, i.e. 8-byte UDP header + minimum 12-byte RFC 1035 DNS header (`drop_short_dns`), or UDP length larger than the IP payload on unfragmented packets (`drop_bad_udp`).
5. **Zero Query Name Looping (ADR-005):** Strictly verifies the 12-byte fixed DNS header (ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT). **Never loops through variable-length DNS question labels**, eliminating verifier complexity and state explosion.

### 2.2 Dual-Tier Generic Cell Rate Algorithm (GCRA)

Kavach implements the **Generic Cell Rate Algorithm (GCRA)** (ITU-T Recommendation I.371), a continuous-time leaky bucket tracking a single 64-bit integer timestamp per flow: the **Theoretical Arrival Time ($TAT$)**.

- **Parameters (precomputed in user space):**

  $$\text{Emission Interval: } T = \frac{10^9}{\text{rate\_pps}} \quad (\text{nanoseconds})$$

  $$\text{Burst Tolerance: } \tau = (\text{burst\_packets} - 1) \times T \quad (\text{nanoseconds})$$

- **Conformance check at packet arrival ($t_{\text{now}} = \text{bpf\_ktime\_get\_ns()}$):**

  $$TAT' = \max(TAT_{\text{stored}}, t_{\text{now}})$$

  $$\text{If } (TAT' - t_{\text{now}}) > \tau \implies \mathbf{XDP\_DROP}$$

  $$TAT_{\text{new}} = TAT' + T \implies \mathbf{XDP\_PASS}$$

All arithmetic runs in pure 64-bit integer nanoseconds without floating-point math, periodic timers, or token multiplication overflow hazards.

### 2.3 Evaluation Order: Per-Source FIRST, Global SECOND (ADR-002)

- **Why this order is mandatory:** If the global limit were evaluated first, high-volume query traffic from a single attacking IP would exhaust the aggregate global budget before being dropped by the per-source filter, starving legitimate queries.
- Evaluating per-source first drops offending flows immediately without consuming global capacity. Packets passing per-source are then evaluated against the shared global threshold.

### 2.4 Multicore Concurrency via BPF Atomic CAS

To prevent race conditions across CPU cores updating the shared global $TAT$, Kavach uses a bounded 8-iteration atomic compare-and-swap loop (`__sync_val_compare_and_swap` with `#pragma unroll`) in [`xdp/gcra.h`](xdp/gcra.h). This maintains a single, globally accurate aggregate limit across all CPU cores without locks. If all 8 attempts lose the race, the packet is dropped and counted as `drop_busy`.

### 2.5 In-Kernel BPF Maps Layout

| Map | Type | Size | Purpose |
|---|---|---|---|
| `counters` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 14 entries | Lockless per-CPU datapath counters ensuring exactly one terminal verdict per packet |
| `kavach_cfg` | `BPF_MAP_TYPE_ARRAY` | 1 entry, 40 bytes | Runtime configuration updated dynamically from user space without recompiling or detaching |
| `src_tat` | `BPF_MAP_TYPE_LRU_HASH` | 100,000 entries | Per-source flow state; automatically evicts idle sources during distributed spoofed attacks |
| `global_tat` | `BPF_MAP_TYPE_ARRAY` | 1 entry | Shared aggregate theoretical arrival time |

---

## 3. Dual Execution Strategy & Testbed Topologies

To thoroughly evaluate both hardware-level constraints and native driver execution, the project was executed in **two complementary modes**:

| | **Mode 1: Two Physical Hosts** | **Mode 2: Single System (Namespaces)** |
|---|---|---|
| **XDP mode** | Generic (`xdpgeneric`) | Native driver (`xdpdrv` / `veth_xdp`, `xdp_mode: native`) |
| **Setup** | 2 physical bare-metal workstations (HP ProDesk 4 Tower G1i, Intel Core Ultra 5 245) | 1 Linux host with isolated network namespaces |
| **Link** | CAT6 direct cable, `eno1`, `10.99.0.0/24` | Virtual Ethernet pair (`veth`, `drivers/net/veth.c`) |
| **Interface / driver** | Intel Gigabit Ethernet (`eno1`, driver `e1000e`) | `vgen` ↔ `vsrv` |
| **Dataset** | Full 108-run randomized matrix (frozen with SHA-256 checksums) | 36-run matrix (frozen with SHA-256 checksums) |
| **Focus** | Real-world hardware interrupt routing, Core 1 affinity, socket queue protection | Driver-level drop verification before `sk_buff` allocation, 65% SoftIRQ reduction |

```
MODE 1 — TWO PHYSICAL HOSTS (generic XDP)

  [Generator PC 2: aiori-2] <==== CAT6 direct cable (eno1, 10.99.0.0/24) ====> [Target PC 1: aiori]


MODE 2 — SINGLE SYSTEM (native driver XDP)

  [Namespace 'gen': vgen] <======== Virtual Ethernet Pair (veth) ========> [Namespace 'srv': vsrv]
```

### 3.1 Two-Host Physical Testbed (Generic Mode)

- **Workstations:** Twin HP ProDesk 4 Tower G1i Desktop AI PCs
  - PC 1 (Target / DUT): `aiori-HP-ProDesk-4-Tower-G1i-Desktop-AI-PC`, `10.99.0.2`
  - PC 2 (Generator): `aiori-2-HP-ProDesk-4-Tower-G1i-Desktop-AI-PC`, `10.99.0.1`
- **CPU:** Intel Core Ultra 5 245 (14 cores, 14 threads)
- **NIC:** Intel Gigabit Ethernet (`eno1`, driver: `e1000e`), 1000 Mb/s full duplex
- **Operating System:** Ubuntu 24.04.4 LTS, OEM kernel `6.14.0-1020-oem`
- **Toolchain:** Clang/LLVM, `libbpf`, `bpftool`, `nftables` v1.0.9 (installed via `apt`, see [Section 9.1](#91-prerequisites))
- **Authoritative DNS Daemon:** NSD bound to `10.99.0.2:53`, single worker process (`server-count: 1`), Response Rate Limiting (RRL) disabled (`rrl-ratelimit: 0`).
- **System Tuning** ([`src/scripts/pin_core.sh`](src/scripts/pin_core.sh), [`src/dns/start_dns.sh`](src/dns/start_dns.sh)):
  - Forced CPU governor to `performance` across all 14 cores.
  - Pinned NIC IRQ `0000:80:1f.6` (`eno1`) to Core 1 (`pin_core.sh`) and the NSD worker to Core 1 (`taskset -c 1`, `start_dns.sh`).
  - Disabled background jitter services (`irqbalance`, `unattended-upgrades`, `ufw`).
- **Operational Finding (ADR-027):** Under kernel `6.14.0-1020-oem`, the Intel `e1000e` driver on physical `eno1` rejects native attachment (`Operation not supported`) and attaches in generic XDP mode (`xdpgeneric`). This setup is fully documented per PS-022 Item 6 (*"Use an XDP-capable kernel/NIC, or document generic-mode setup"*). See [`docs/known-issues.md`](docs/known-issues.md).

### 3.2 Single-System Namespace Testbed (Native Mode)

- Configured using network namespaces (`gen` $\leftrightarrow$ `srv`) over a virtual ethernet pair (`veth`).
- In this environment, the Linux `veth` driver provides native XDP driver support (`xdp_mode: native`), executing drops directly inside the driver receive hook (`drivers/net/veth.c`) before `alloc_skb`.
- Confirmed a **65% reduction in kernel SoftIRQ CPU load** (from 2.37% down to 0.84%), verifying native driver efficiency (ADR-031).

### 3.3 Physical Testbed Photographic Evidence

Photographs and screenshots are archived in [`docs/media/`](docs/media/README.md) (see ADR-033).

| File | Host | Description |
|---|---|---|
| [`generator_pc2_run47_s2.jpg`](docs/media/testbed_photos/generator_pc2_run47_s2.jpg) | Generator PC 2 (`10.99.0.1`) | Generator console (run S2 baseline) |
| [`generator_pc2_run48_laptop.jpg`](docs/media/testbed_photos/generator_pc2_run48_laptop.jpg) | Generator PC 2 (`10.99.0.1`) | Generator console with operator station |
| [`target_pc1_daemon_drops.jpg`](docs/media/testbed_photos/target_pc1_daemon_drops.jpg) | Target PC 1 (`10.99.0.2`) | Target console: telemetry and Layer 3 drops |
| [`target_pc1_daemon_setup.jpg`](docs/media/testbed_photos/target_pc1_daemon_setup.jpg) | Target PC 1 (`10.99.0.2`) | Target console: daemon execution and setup |
| [`lab_pc2_calibration_screenshot.png`](docs/media/screenshots/lab_pc2_calibration_screenshot.png) | Generator PC 2 | Calibration (saturation sweep) console capture |

---

## 4. Generator Safety Guards & PS-022 Containment

To strictly comply with AIORI-3 cybersecurity safety rules, all traffic generation incorporates non-bypassable programmatic guards ([`src/traffic/guard.py`](src/traffic/guard.py), `guard.sh`, and checks built into `kavach_gen.c`):

1. **Target Subnet Assertion:** Target destination IP must strictly reside in `10.99.0.0/24`. Attempting to target the campus LAN (`10.126.0.0/16`) or public IPs immediately aborts with fatal exit code `100`.
2. **Source IP Isolation:** Synthetic spoofed source addresses are drawn exclusively from RFC 2544 benchmark prefix `198.18.0.0/15`; legitimate queries originate strictly from `10.99.0.1`.
3. **Forwarding Guard:** Host `/proc/sys/net/ipv4/ip_forward` must be `0` to prevent reflecting packets outside the lab link.
4. **Negative Constraints Respected:** Zero public flood testing, zero variable QNAME label parsing, zero universal PRSD detection claims, and zero claims of eliminating reflection attacks.

---

## 5. Empirical Calibration ($S = 100,000$ PPS)

Rather than selecting arbitrary flood volumes, an empirical saturation sweep on Baseline B0 (No Filter) determined the hardware capacity knee. A step is flagged saturated when legitimate query success drops below 99%.

| Offered Rate (PPS) | Queries Sent | Answered | Success % | $p50$ Latency | $p95$ Latency | Status |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 5,000 | 1,000 | 1,000 | 100.0% | 0.626 ms | 0.902 ms | OK |
| 10,000 | 1,000 | 1,000 | 100.0% | 0.520 ms | 0.776 ms | OK |
| 15,000 | 1,000 | 1,000 | 100.0% | 0.581 ms | 0.794 ms | OK |
| 20,000 | 1,000 | 1,000 | 100.0% | 0.471 ms | 0.655 ms | OK |
| 25,000 | 1,000 | 1,000 | 100.0% | 0.548 ms | 0.724 ms | OK |
| 30,000 | 1,000 | 1,000 | 100.0% | 0.562 ms | 0.727 ms | OK |
| 40,000 | 1,000 | 1,000 | 100.0% | 0.550 ms | 0.708 ms | OK |
| 50,000 | 1,000 | 1,000 | 100.0% | 0.556 ms | 0.686 ms | OK |
| 60,000 | 1,000 | 1,000 | 100.0% | 0.551 ms | 0.685 ms | OK |
| 75,000 | 1,000 | 1,000 | 100.0% | 0.572 ms | 0.679 ms | OK |
| **100,000 ($S$)** | 1,000 | 886 | **88.60%** | **15.603 ms** | **28.224 ms** | **SATURATED** |

At 100,000 PPS the queue saturates: success falls to 88.60% and median latency rises about 27× compared with the 75,000 PPS step. Raw data: [`results/calibration/`](results/calibration/).

### Calibrated Parameters ([`src/params.yaml`](src/params.yaml))

- **Saturation Point:** $S = 100,000$ PPS
- **Matrix Load Levels:** $0.5\times S = 50,000$ PPS, $1.0\times S = 100,000$ PPS, $2.0\times S = 200,000$ PPS
- **Limiter Limits:** Per-source rate: 500 PPS (burst: 20) | Global aggregate rate: 70,000 PPS ($0.70\times S$, burst: 20)
- **Legitimate Client:** Open-loop, fixed 100 QPS (10 ms interval), 0 retries, 1.5 s hard timeout.

---

## 6. Physical Benchmark Matrix Results (108 Runs)

The benchmark matrix evaluates **3 attack scenarios × 4 configurations × 3 load levels (0.5×, 1.0×, 2.0× $S$) × 3 repetitions = 108 runs**, executed in a seeded pseudo-random order (seed 42) under identical physical lab conditions. This gives **9 runs per scenario/configuration cell**. Telemetry was synchronously harvested across driver, kernel softnet, filter, and socket layers.

**Scenarios**

| ID | Description |
|---|---|
| **S1** | Single-source constant-rate flood (`198.18.0.10`) |
| **S2** | Distributed flood across 1,000 randomized sources (`198.18.0.0/15`) |
| **S3** | Pulsing bursts of 0.5×, 1.0× and 2.0× the burst tolerance (10, 20 and 40 packets) with a 5 s period (1 s active, 4 s idle) |

**Configurations**

| ID | Description |
|---|---|
| **B0** | No filter (raw Linux stack + NSD DNS server) |
| **B1** | `nftables` prerouting table (priority `raw`, connection tracking bypassed via `notrack`) |
| **B2** | `nftables` netdev ingress table (earliest netfilter hook, priority -500) |
| **X** | Kavach XDP in-kernel filter |

### 6.1 Statistical Summary

Median across the 9 runs of each row, **pooled over the 0.5×, 1.0× and 2.0× $S$ load levels** (source: [`results/analysis_table.csv`](results/analysis_table.csv)).

| Scenario | Config | Runs | Legit Success (Median) | Legit Success (IQR) | $p50$ Latency (ms) | $p95$ Latency (ms) | Core 1 CPU % | Filter Drops | Socket Drops (`UdpInErrors`) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **S1 (Single-Source)** | **B0 (No Filter)** | 9 | **87.00%** | 27.19% | 14.30 | 27.85 | 14.14% | 0 | **920,180** |
| | **B1 (nftables Raw)** | 9 | 100.00% | 0.00% | 0.47 | 1.60 | 6.55% | 5,966,670 | 0 |
| | **B2 (nftables Netdev)** | 9 | 100.00% | 0.00% | 0.51 | 1.60 | 6.60% | 5,966,710 | 0 |
| | **X (Kavach XDP)** | 9 | **100.00%** | 0.00% | **0.45** | **1.55** | 6.78% | 5,966,949 | **0** |
| **S2 (Distributed)** | **B0 (No Filter)** | 9 | **72.30%** | 28.44% | 31.39 | 61.45 | 14.47% | 0 | **896,938** |
| | **B1 (nftables Raw)** | 9 | 73.53% | 37.22% | 0.60 | 1.67 | 12.69% | 1,802,758 | 0 |
| | **B2 (nftables Netdev)** | 9 | 72.87% | 11.88% | 0.57 | 1.72 | 12.96% | 1,802,834 | 0 |
| | **X (Kavach XDP)** | 9 | **74.04%** | 37.10% | **0.59** | **1.66** | 12.55% | 1,759,349 | **0** |
| **S3 (Pulsing)** | **B0 (No Filter)** | 9 | 100.00% | 0.00% | 1.47 | 1.99 | 1.33% | 0 | 0 |
| | **B1 (nftables Raw)** | 9 | 100.00% | 0.00% | 1.52 | 2.02 | 1.28% | 240 | 0 |
| | **B2 (nftables Netdev)** | 9 | 100.00% | 0.00% | 1.43 | 1.99 | 1.29% | 0 | 0 |
| | **X (Kavach XDP)** | 9 | **100.00%** | 0.00% | **1.44** | **1.98** | 1.20% | 0 | **0** |

### 6.2 Key Empirical Takeaways

1. **S1 (Single-Source Flood Mitigation):**
   - Under Baseline B0, socket receive queues saturated: median 920,180 socket-layer drops per run (up to 2,400,595), median legitimate success of 87.00%, and median $p50$ latency of $14.30\text{ ms}$.
   - Kavach XDP completely neutralized the flood, achieving **100.00% query success in every S1 run**, **$0.45\text{ ms}$ median $p50$ latency** and zero socket drops. This is roughly 12% lower than `nftables netdev` ($0.51\text{ ms}$) and roughly 4% lower than `nftables raw` ($0.47\text{ ms}$); these differences are small compared with the run-to-run spread ($p50$ IQR of about 0.9–1.0 ms), so the three filters are comparable on latency in this testbed.
2. **S2 (Distributed Flood Resilience):**
   - Under Baseline B0, median query success collapsed to **72.30%** with median $p95$ latency exploding to **61.45 ms**.
   - Kavach XDP maintained sub-millisecond median response times ($0.59\text{ ms}$) and eliminated all socket buffer drops (`UdpInErrors == 0`); the `nftables` baselines reached comparable values (0.60 ms and 0.57 ms).
3. **Drops by Layer Hierarchy:**
   - Across all 27 Kavach XDP runs, no drops were recorded at the NIC, softnet or socket layers. Every drop was a filter-layer (Layer 3) drop, so UDP socket queue overflow never occurred.

---

## 7. Publication Figures

High-resolution (300 DPI) PNG and vector PDF figures are stored in [`results/figures/`](results/figures/):

| Figure | Content |
|---|---|
| [`fig1_physical_benchmark_matrix`](results/figures/fig1_physical_benchmark_matrix.png) | Multi-panel physical benchmark matrix summary |
| [`fig2_rate_levels_and_saturation`](results/figures/fig2_rate_levels_and_saturation.png) | Metric scaling across 0.5×, 1.0×, 2.0× flood intensity |
| [`fig3_native_namespaces_validation`](results/figures/fig3_native_namespaces_validation.png) | Native-mode driver-level drop fate and SoftIRQ reduction |
| [`fig4_latency_cdf_distribution`](results/figures/fig4_latency_cdf_distribution.png) | Empirical CDF of query response times |

Additional figures (`fig1_h2_…`, `fig2_h3_…`, `fig3_socket_buffer_exhaustion`, `fig4_h1_h4_…`, `fig5_latency_cdf_detail`) and summary plots in `results/plots/` are included in the same folder.

---

## 8. Repository Organization

```
A3-PS022-TC367/
├── A3-PS022-TC367_ProposedSolution.pdf  # Technical Proposal Document
├── README.md                            # Project Documentation
├── xdp/                                 # In-Kernel eBPF Engine
│   ├── kavach_xdp.c                     # Bounded Packet Parser & GCRA Limiter
│   ├── gcra.h                           # Atomic Integer GCRA Implementation
│   ├── kavach_ctl.py                    # User-Space Loader, Controller & Watchdog
│   ├── Makefile                         # Clang -target bpf Compilation Targets
│   └── tests/                           # Host-Side Mock Unit Test Suite
├── src/                                 # Testing & Measurement Harness (key files shown)
│   ├── traffic/                         # Traffic Generation Subsystem
│   │   ├── kavach_gen.c                 # C Raw Socket Generator (S1, S2, S3)
│   │   ├── legit_client.py              # Open-Loop Legitimate Client (fixed 100 QPS)
│   │   ├── guard.sh & guard.py          # Programmatic Safety Boundary Guards
│   │   └── Makefile                     # Generator build
│   ├── baselines/                       # Parameter-Matched Firewall Baselines
│   │   ├── none.sh                      # B0: No Filter
│   │   ├── b1_prerouting.sh             # B1: nftables Raw Prerouting (notrack)
│   │   ├── b2_netdev.sh                 # B2: nftables Netdev Ingress (-500)
│   │   └── verify_baselines.py          # Baseline Configuration Validator
│   ├── dns/                             # Authoritative DNS Server Profile
│   │   ├── nsd.conf                     # NSD Daemon Profile (RRL disabled)
│   │   ├── start_dns.sh                 # Starts NSD pinned to Core 1
│   │   └── zones/lab.test.zone          # RFC 1035 Zone File
│   ├── scripts/                         # Automation & Analysis Utilities
│   │   ├── pin_core.sh                  # Hardware IRQ & CPU Governor Tuning
│   │   ├── calibrate.py                 # Empirical Saturation Sweep Harness
│   │   ├── target_daemon.py             # Control Daemon for PC 1
│   │   ├── orchestrator.py              # Seeded Random Matrix Orchestrator
│   │   ├── analyze.py                   # Statistical Aggregation & Plotter
│   │   └── generate_publication_figures.py  # 300-DPI Publication Figures
│   └── params.yaml                      # Unified Experiment Configuration Profile
├── docs/                                # System Architecture & Engineering Logs
│   ├── architecture.md                  # System Architecture (pseudocode in Section 3)
│   ├── decisions.md                     # 33 Architecture Decision Records (ADRs)
│   ├── setup.md                         # Physical Lab Bring-Up Runbook
│   ├── known-issues.md                  # Hardware & Toolchain Findings
│   └── media/                           # Photographic Evidence & Screenshots
│       ├── README.md                    # Media Catalog
│       ├── screenshots/                 # Calibration console capture
│       └── testbed_photos/              # Physical Testbed Photos
└── results/                             # Empirical Artifacts & Frozen Telemetry
    ├── analysis_table.csv               # 108-Run Physical Summary Table
    ├── analysis_summary.json            # Machine-Readable Statistics
    ├── checksums_physical_108.sha256    # SHA-256 Checksums of 108 Runs
    ├── checksums_namespaces_36.sha256   # SHA-256 Checksums of 36 Runs
    ├── figures/                         # 300-DPI Publication Figures
    ├── plots/                           # Summary Plots
    ├── calibration/                     # Saturation Calibration Data
    ├── raw/                             # Raw Telemetry (108 physical run folders + smoke tests)
    └── raw_namespaces/                  # Raw Telemetry (36 native-mode namespace runs)
```

---

## 9. Quickstart & Reproduction Guide

The two lab PCs are connected by a direct cable on `eno1`: PC 1 (Target) `10.99.0.2/24`, PC 2 (Generator) `10.99.0.1/24`. See [`docs/setup.md`](docs/setup.md) for the full bring-up procedure.

### 9.1 Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common \
    linux-tools-$(uname -r) nsd nftables sysstat ethtool iproute2 python3-pip
pip3 install pyyaml matplotlib numpy
```

### 9.2 Build eBPF Bytecode & C Flooder

```bash
# Build eBPF bytecode (xdp/kavach_xdp.o)
cd xdp && make && cd ..

# Build high-speed synthetic generator (src/traffic/kavach_gen)
cd src/traffic && make && cd ../..
```

### 9.3 Hardware Tuning (Execute on Target PC 1)

```bash
# Pin Intel e1000e IRQ to Core 1 and force performance governor
sudo ./src/scripts/pin_core.sh --role target

# Start authoritative NSD daemon on Core 1
sudo ./src/dns/start_dns.sh --host --iface eno1
```

On Generator PC 2, run `sudo ./src/scripts/pin_core.sh --role generator`.

### 9.4 Run Empirical Calibration (Execute on Generator PC 2)

```bash
# Ramp traffic from 5k PPS until saturation to identify the knee S
# (results are archived in results/calibration/)
sudo python3 src/scripts/calibrate.py --target 10.99.0.2 --iface eno1
```

### 9.5 Execute Automated Benchmark Matrix

```bash
# Launch target daemon on PC 1
sudo python3 src/scripts/target_daemon.py --iface eno1 --port 9999

# Run the full randomized 108-run matrix from PC 2
sudo python3 src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon

# Regenerate statistical summaries and plots
python3 src/scripts/analyze.py --input-dir results/raw/ --output-dir results/
```

---

## 10. Compliance with PS-022 Deliverables

| Deliverable | Location in Repository | Verification Status |
|---|---|:---:|
| **eBPF/XDP Rate Limiting Program** | [`xdp/kavach_xdp.c`](xdp/kavach_xdp.c), [`xdp/gcra.h`](xdp/gcra.h) | Fully Implemented & Verified |
| **Controlled Traffic-Generation Harness** | [`src/traffic/kavach_gen.c`](src/traffic/kavach_gen.c), [`guard.py`](src/traffic/guard.py) | Non-Bypassable Safety Guards |
| **No-Filter & nftables Baselines** | [`src/baselines/none.sh`](src/baselines/none.sh), [`b1_prerouting.sh`](src/baselines/b1_prerouting.sh), [`b2_netdev.sh`](src/baselines/b2_netdev.sh) | Parameter-Matched Parity |
| **Three Synthetic Load Scenarios** | S1 (Single Source), S2 (Distributed 1,000 IPs), S3 (Pulsing Bursts) | Implemented & Calibrated |
| **Performance Measurements** | [`results/analysis_table.csv`](results/analysis_table.csv), [`analysis_summary.json`](results/analysis_summary.json) | 108 Physical Runs Analyzed |
| **Analysis of Legitimate Query Impact** | Open-Loop Client ([`legit_client.py`](src/traffic/legit_client.py)), $p50/p95/p99$ Latencies | 100 QPS, 0 Retries, 1.5 s Timeout |
| **Technical Proposal & Demonstration** | [`A3-PS022-TC367_ProposedSolution.pdf`](A3-PS022-TC367_ProposedSolution.pdf), [Video](https://youtu.be/7cTRoE_1nWI) | Verified & Uploaded |
| **Pseudocode Snippet for Mentors** | [`docs/architecture.md`](docs/architecture.md), Section 3 | Ready for Defense |
