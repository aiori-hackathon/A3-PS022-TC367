# Kavach: eBPF/XDP Rate Limiting for DNS Query Floods

**Submission ID:** A3-PS022-TC367  
**Category:** Cybersecurity (AIORI Hackathon 3)  
**Team Kavach:** Keerthi Virupapura, U Kruthik (BMS College of Engineering, CSE)  
**Faculty Mentor:** Dr. Manjunath D R  

---

## 1. Executive Summary

High-volume UDP/53 DNS query floods overwhelm Linux systems because the operating system spends substantial CPU cycles allocating socket buffers (`sk_buff`) in the networking stack before packets reach user-space daemons or firewalls. Even early nftables hooks (such as `netdev ingress`) operate after `sk_buff` allocation has already occurred.

**Kavach** implements an eBPF/XDP (eXpress Data Path) kernel filter that runs directly inside the network interface card (NIC) driver layer. By performing bounded parsing on incoming packets and evaluating dual-tier Generic Cell Rate Algorithm (GCRA) rate limits, Kavach drops excess or malformed flood queries **before kernel memory allocation occurs**, preserving system CPU and protecting legitimate DNS queries.

---

## 2. Key Architecture & Features

- **Bounded UDP/DNS Packet Parsing:** Parses Ethernet -> IPv4 -> UDP headers strictly bounded against `data_end`. Evaluates the fixed 12-byte DNS header (RFC 1035) without looping over arbitrary query names (no unbounded loops, verifier-safe).
- **Dual-Tier GCRA Rate Limiter:**
  - **Per-Source Rate Limiting:** Enforced via `BPF_MAP_TYPE_LRU_HASH` (keyed by source IPv4) to bound memory consumption under random spoofed source floods.
  - **Global Rate Limiting:** Shared single-bucket rate limiter via an array map (`u64 tat`).
  - **Evaluation Order:** Per-source check is performed *first*, followed by the global check, preventing a single high-volume source from exhausting the global bucket.
- **Early Malformed Packet Rejection:** Drops malformed UDP/53 payloads (< 12 bytes or inconsistent UDP length fields) immediately.
- **Controlled Baselines for Comparison:**
  - **B0:** No filter (pure DNS daemon handling).
  - **B1:** `nftables` prerouting raw table (standard firewall baseline).
  - **B2:** `nftables` netdev ingress table (earliest netfilter hook).
  - **X:** Kavach XDP program (native/generic driver modes).
- **Three Synthetic Flood Scenarios:**
  - **S1 (Single-source flood):** Sustained flood testing per-source GCRA and CPU reduction.
  - **S2 (Distributed flood):** Many random sources from `198.18.0.0/15` testing global limit and LRU eviction under memory pressure.
  - **S3 (Pulsing flood):** Periodic burst flood evaluating GCRA burst tolerance parameter and refill dynamics.

---

## 3. Directory Structure

```text
kavach/
├── xdp/                       # Core eBPF/XDP kernel program & controller
│   ├── kavach_xdp.c           # Core BPF packet filter (bounded parser + GCRA)
│   ├── gcra.h                 # Atomic CAS Generic Cell Rate Algorithm
│   ├── kavach_ctl.py          # Loader, runtime config, telemetry, and watchdog
│   ├── Makefile               # eBPF build targets (-mcpu=v3 and approximate)
│   └── tests/                 # Unit tests (controller, parser, host-test)
├── src/                       # Lab harness, traffic, baselines & metrics
│   ├── AGENTS.md              # Project context, rules, and synchronization guidelines
│   ├── README.md              # Project overview and quick start guide
│   ├── params.yaml            # Shared parameters (calibration, limits, timings)
│   ├── params.json            # Mirrored JSON parameter definitions
│   ├── docs/                  # Architecture specifications and ADRs
│   │   ├── architecture.md    # Detailed packet pipeline and GCRA formulation
│   │   ├── decisions.md       # Architecture Decision Records (ADRs 001 - 032)
│   │   ├── known-issues.md    # Hardware caveats and limitations
│   │   └── setup.md           # Lab hardware inventory and host tuning
│   ├── scripts/               # Testbed automation and experiment orchestration
│   │   ├── pin_core.sh        # Host tuning & hardware NIC IRQ core pinning utility
│   │   ├── calibrate.py       # Phase B3 unflooded saturation calibration harness
│   │   ├── target_daemon.py   # Target server network synchronization daemon (PC 1)
│   │   ├── smoke_runner.py    # Phase B3 smoke test runner across 4 configs (PC 2)
│   │   ├── run_smoke.sh       # Shell wrapper for smoke test runner (PC 2)
│   │   ├── run_smoke_target.sh# Target smoke run helper for twin-console mode (PC 1)
│   │   ├── setup_env.sh       # Automated namespace ('gen' & 'srv') setup
│   │   ├── teardown_env.sh    # Clean removal of namespaces and virtual links
│   │   ├── status_env.sh      # Diagnostics and link inspection script
│   │   ├── collect.sh         # Telemetry collection orchestrator
│   │   ├── collect_metrics.py # Multi-layer stats engine (CPU, NIC, SNMP, XDP, nft)
│   │   ├── orchestrator.py    # Orchestrator v1 (seeded random, run lifecycle)
│   │   ├── run_orchestrator.sh# Shell wrapper for orchestrator
│   │   ├── analyze.py         # Statistical analysis engine & plot generator
│   │   └── run_b0_test.sh     # End-to-end Baseline B0 validation runner
│   ├── baselines/             # Comparative benchmark firewall definitions
│   │   ├── none.sh            # Baseline B0 (No filter: detaches XDP, flushes nft)
│   │   ├── b1_prerouting.sh   # Baseline B1 (nftables prerouting raw, no conntrack)
│   │   ├── b2_netdev.sh       # Baseline B2 (nftables netdev ingress)
│   │   └── verify_baselines.py# Measured limit verification across B1, B2, X
│   ├── traffic/               # Traffic generation harnesses & safety guards
│   │   ├── guard.sh           # Non-bypassable boundary check (<= 10.99.0.0/24)
│   │   ├── guard.py           # Python safety module and CLI
│   │   ├── kavach_gen.c       # High-speed C packet generator (S1, S2, S3, ceiling)
│   │   ├── Makefile           # Build system for C generator
│   │   ├── flood.py           # Unified Python CLI for flood scenarios
│   │   ├── test_ceiling.sh    # Generator ceiling benchmark script
│   │   ├── legit_client.py    # Open-loop client (100 QPS, dedicated IP)
│   │   └── run_legit.sh       # Runner wrapper for legitimate client
│   └── dns/                   # Authoritative DNS server configurations
│       ├── nsd.conf           # Production NSD daemon configuration (RRL off)
│       ├── zones/             # Authoritative zone definitions (lab.test.zone)
│       ├── start_dns.sh       # Starts NSD or lightweight fallback in 'srv'
│       ├── stop_dns.sh        # Graceful shutdown of DNS daemons
│       └── test_dns.sh        # DNS resolution verification tool
├── docs/                      # Consolidated technical documentation & runbooks
└── results/raw/               # Raw experimental telemetry artifacts
```

---

## 4. Confirmed Physical Testbed Profile (Lab Host Pair)

From the B0 fact collection on 27 Oct 2026:
- **Workstations:** 2x HP ProDesk 4 Tower G1i Desktop AI PCs (Twin hardware).
- **CPUs:** Intel(R) Core(TM) Ultra 5 245 (14 cores, 14 threads).
- **RAM & Storage:** 30 GiB RAM, 488 GB NVMe SSD per machine.
- **OS & Kernel:** Ubuntu 24.04.4 LTS, Kernel `6.14.0-1020-oem` (BTF enabled, BPF atomics supported).
- **Network Interface:** Onboard Intel Gigabit `eno1` (Driver: `e1000e`). Direct CAT6 cable between PC 1 (`10.99.0.2`) and PC 2 (`10.99.0.1`).
- **Tuning:** CPU governor forced to `performance`, `unattended-upgrades` disabled, `ufw` disabled, IPv6 disabled on `eno1`.

---

## 4. Safety Guardrails & Lab Protocol

1. **Strictly Isolated Network Link:** Flood traffic is confined strictly to dedicated test interfaces (`10.99.0.0/24`) or local network namespaces (`gen` <-> `srv`). No packets route to public networks or campus LANs.
2. **Generator Destination Guard:** Traffic generators explicitly abort if destination IP addresses fall outside the designated lab subnet.
3. **Synthetic Source Allocation:** Synthetic flood traffic strictly uses `198.18.0.0/15` (RFC 2544 benchmark reservation).
4. **XDP Interface Isolation & Watchdog:** Never attach XDP programs to SSH/management interfaces. Every attach invocation is guarded by an automatic detachment watchdog timer.
5. **No Spoofed Replies:** The target server's default gateway routes back exclusively through the generator host with `ip_forward=0`.

---

## 5. Development & Testing Quick Start

### 6.1 Local Namespace Environment (Development)
```bash
# Automated setup of isolated namespaces (gen and srv) joined by veth pair
sudo ./src/scripts/setup_env.sh

# Verify status
sudo ./src/scripts/status_env.sh

# Teardown when finished
sudo ./src/scripts/teardown_env.sh
```

### 5.2 Building and Attaching XDP
```bash
# Build eBPF bytecode using clang (targeting kernel 5.15 / v3 verifier)
clang -target bpf -O2 -g -c xdp/dns_ratelimit.bpf.c -o xdp/dns_ratelimit.bpf.o

# Load and attach via generic mode on development veth
sudo ip netns exec srv ip link set dev vsrv xdpgeneric obj xdp/dns_ratelimit.bpf.o sec xdp
```

---

## 6. Experimental Results & Publication Artifacts (Phase B4 / B5)

The full experimental matrix has been completed and frozen:
- **Physical Testbed Benchmark (108 Runs):** Executed across 4 configurations (B0, B1, B2, X) $\times$ 3 scenarios (S1, S2, S3) $\times$ 3 levels $\times$ 3 reps on twin HP ProDesk 4 workstations with Intel `e1000e` NICs. Demonstrates 100% legitimate query availability and $0.44\text{ ms}$ median latency under XDP vs severe socket exhaustion and $14.3\text{ ms}$ delay under B0.
- **Namespace Native Mode Validation (36 Runs):** Executed in Linux network namespaces on `veth_xdp` in native driver mode (`xdpdrv`). Confirms $5.96\text{M}$ packets dropped directly at the driver hook with a 65% reduction in kernel SoftIRQ overhead.
- **SHA-256 Checksums Frozen:**
  - Physical 108 runs (648 artifacts): `results/checksums_physical_108.sha256` and `results/raw/checksums.sha256`
  - Namespace 36 runs (216 artifacts): `results/checksums_namespaces_36.sha256`
- **300 DPI Publication Figures & Vector PDFs (`results/figures/`):**
  - `fig1_physical_benchmark_matrix.png` / `.pdf`: 4-panel overview (success %, log latency, CPU %, socket vs filter drops)
  - `fig2_rate_levels_and_saturation.png` / `.pdf`: Performance scaling across 50k, 100k, 200k pps flood levels
  - `fig3_native_namespaces_validation.png` / `.pdf`: Driver-level drop fate and SoftIRQ reduction
  - `fig4_latency_cdf_distribution.png` / `.pdf`: Empirical latency CDF highlighting sub-millisecond determinism

---

## 7. References

- RFC 1035: Domain Names - Implementation and Specification
- RFC 2827 / BCP 38: Network Ingress Filtering
- ITU-T I.371: Generic Cell Rate Algorithm (GCRA)
- Linux Kernel BPF & XDP Documentation: https://docs.kernel.org/bpf/
