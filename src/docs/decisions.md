# Architecture Decision Records (ADRs)

**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods  
**Submission ID:** A3-PS022-TC367  

This document logs architectural and design decisions made throughout the lifecycle of the project, including settled rationale, alternatives considered, and items validated on lab hardware.

---

## Settled Decisions

### ADR-001: Drop Malformed DNS Packets Early
- **Status:** Accepted
- **Context:** Flooding traffic often includes malformed packets designed to crash resolvers or waste server cycles.
- **Decision:** Drop packets in XDP (`XDP_DROP`) if UDP destination port is 53 and:
  1. DNS payload size is strictly less than 12 bytes (the minimum RFC 1035 header size).
  2. UDP header `length` field is inconsistent with the IP packet length.
- **Rationale:** Discarding invalid packets at the driver level saves `sk_buff` allocation and CPU parsing further up the stack.
- **Alternatives Considered:** Passing malformed packets to the user-space DNS server to generate FORMERR responses (rejected: wastes server CPU during query floods).

### ADR-002: Rate Limiting Check Order: Per-Source First, Global Second
- **Status:** Accepted
- **Context:** Kavach implements two tiers of rate limiting: per-source IP and global aggregate.
- **Decision:** Evaluate per-source rate limits *first*. Only if the packet passes the per-source limiter is it evaluated against the global rate limiter.
- **Rationale:** If the global check ran first, high-volume query traffic from a single attacking IP would consume the global rate budget, starving legitimate queries from other clients before the offending IP is penalized. The nftables baselines follow the same sequence for fairness.
- **Consequence:** A packet passing per-source but dropped globally still updates the per-source arrival timestamp.

### ADR-003: Rate Limiting Algorithm: Integer-Only GCRA
- **Status:** Accepted
- **Context:** eBPF verifier restrictions prohibit floating-point arithmetic and complex division instructions at packet arrival time.
- **Decision:** Use the Generic Cell Rate Algorithm (GCRA, ITU-T I.371) tracking Theoretical Arrival Time ($TAT$) in nanoseconds via `bpf_ktime_get_ns()`. Emission intervals and burst tolerances are precomputed in user space.
- **Rationale:** GCRA requires only one 64-bit integer timestamp per flow, zero floating-point math, and no periodic tick timer.

### ADR-004: Per-Source State Tracking via BPF LRU Hash Map
- **Status:** Accepted
- **Context:** S2 flood scenarios use thousands of spoofed source IPs from `198.18.0.0/15`, threatening map memory exhaustion.
- **Decision:** Use `BPF_MAP_TYPE_LRU_HASH` for per-source tracking.
- **Rationale:** Standard hash maps return `-ENOMEM` when saturated, dropping new legitimate flows. An LRU map automatically evicts idle source states, providing bounded memory overhead. Evicted sources reset to standard burst allowance.

### ADR-005: Scope Boundary: No DNS Query Name Parsing & No IPv6
- **Status:** Accepted
- **Context:** Project time budget is strictly limited, and the Linux kernel verifier restricts complex looping.
- **Decision:** Do not parse variable-length DNS question names or labels (no PRSD detection). Treat IPv6 as out of scope by explicitly disabling IPv6 on the test network interface.
- **Rationale:** Variable-length label iteration risks verifier rejection and path explosion. IPv6 extension header chains complicate bounded parsing and require prefix aggregation.

### ADR-006: IP Fragmentation Handling
- **Status:** Accepted
- **Context:** Fragmented IP packets divide transport and payload data.
- **Decision:** Non-first IP fragments (`fragment_offset > 0`) lack UDP headers and are passed to the kernel (`XDP_PASS`) and tracked via `fragments_passed`. First fragments are parsed normally.
- **Rationale:** Reassembling fragments at the XDP layer requires complex packet buffering outside the scope of single-packet driver processing.

### ADR-007: Baseline Configurations for Performance Benchmark
- **Status:** Accepted
- **Decision:** Compare Kavach against three controlled baselines:
  - **B0:** No filter (pure DNS daemon handling).
  - **B1:** `nftables` prerouting table (raw priority, without connection tracking).
  - **B2:** `nftables` netdev ingress table (earliest netfilter hook).
- **Rationale:** Demonstrates the exact performance differential between user-space handling, early netfilter hooks, and driver-level XDP.

### ADR-008: Safety Isolation and Watchdog Timer
- **Status:** Accepted
- **Decision:** 
  1. All flood traffic is restricted to a dedicated lab subnet (`10.99.0.0/24`).
  2. Synthetic flood sources are drawn exclusively from RFC 2544 benchmark reservation `198.18.0.0/15`.
  3. Traffic generation tools integrate a destination guard that aborts execution outside the lab subnet.
  4. An automatic background watchdog process detaches the XDP program after $N$ minutes (default: 10 minutes) unless renewed.
- **Rationale:** Protects campus network infrastructure and prevents developer lockout.

---

## Hardware-Validated & Updated Decisions

### ADR-009: Testbed Target Kernel & OS Update
- **Status:** Accepted (Updated from Lab Data)
- **Context:** The initial plan assumed Ubuntu 22.04 LTS with kernel 5.15. The lab PCs were provisioned with Ubuntu 24.04.4 LTS and OEM Kernel `6.14.0-1020-oem`.
- **Decision:** Target `6.14.0-1020-oem` as the definitive lab environment while keeping the BPF program verifier-clean.
- **Rationale:** Kernel 6.14 provides built-in BTF (`/sys/kernel/btf/vmlinux`), reliable modern BPF atomic operations, and robust libbpf integration.

### ADR-010: Multi-Core Concurrency via BPF Atomics
- **Status:** Accepted
- **Context:** Kernel 6.14 natively supports 64-bit BPF atomic operations with Clang `-mcpu=v3`.
- **Decision:** Implement atomic compare-and-swap (`__sync_val_compare_and_swap`) for updating the global `u64 tat` in `map_glob_tat`.
- **Rationale:** Eliminates race conditions across multiple CPU cores on the Intel Core Ultra 5 245 without requiring heavier spinlocks.

### ADR-011: Physical Testbed Cabling & Single NIC Isolation
- **Status:** Accepted
- **Context:** The two HP ProDesk PCs have only one physical NIC (`eno1`, Intel `e1000e`), initially connected to the campus network (`10.126.12.x/16`).
- **Decision:** 
  1. Complete package installation over the campus LAN.
  2. Disconnect `eno1` from the campus network.
  3. Physically connect PC 1 and PC 2 directly with a CAT6 Ethernet cable on `eno1`.
  4. Assign static IPs `10.99.0.1/24` (PC 2, Gen) and `10.99.0.2/24` (PC 1, Target).
- **Rationale:** Prevents any packet flood from leaking to the institutional network and strictly complies with the lab containment rule.

### ADR-012: DNS Server Selection: NSD & Zero-RRL Policy
- **Status:** Accepted & Implemented (27 Oct 2026)
- **Context:** Need an authoritative DNS daemon with simple zone management and disableable Response Rate Limiting (RRL) to ensure drops originate exclusively from packet filtering layers (XDP/nftables).
- **Decision:** Standardize on NSD with explicit configuration:
  1. Bound strictly to `10.99.0.2:53` (preventing host port conflicts).
  2. Single worker process (`server-count: 1`) pinned to Core 1 (`taskset -c 1`).
  3. Response Rate Limiting disabled (`rrl-ratelimit: 0`, `rrl-slip: 0`).
  4. Authoritative zone `lab.test` providing standard RFC 1035 records.
  5. Built-in pure-Python fallback DNS daemon (`src/dns/mock_dns.py`) and query tester (`src/dns/query_test.py`) to support development environments where NSD is not yet installed.
- **Rationale:** Guarantees deterministic single-core capacity limits during flood saturation and zero response throttling by the DNS daemon itself.

### ADR-013: XDP Attachment Mode Strategy for `e1000e`
- **Status:** In Progress / Validation Protocol
- **Context:** Both PCs use Intel Gigabit `eno1` powered by the `e1000e` driver.
- **Decision:** Attempt native driver attachment (`xdpdrv`) first. If `e1000e` under kernel 6.14 rejects `xdpdrv`, fall back to generic mode (`xdpgeneric`) and log the mode in all experiment outputs.

### ADR-014: Generator Safety Guard Architecture & Containment Boundary
- **Status:** Accepted & Implemented (27 Oct 2026)
- **Context:** Hard project safety rules strictly prohibit generating traffic outside the isolated lab subnet or leaking spoofed reflection packets into campus or public networks.
- **Decision:** Implement dual-implementation safety guards in `src/traffic/guard.sh` (pure Bash integer CIDR logic) and `src/traffic/guard.py` (Python `ipaddress` module) supporting both standalone CLI verification and module sourcing.
- **Enforced Boundaries:**
  1. Destination Target IP must strictly belong to `10.99.0.0/24` (specifically rejecting campus LAN `10.126.0.0/16`, loopback, or public IPs).
  2. Synthetic source addresses must strictly reside in RFC 2544 benchmark prefix `198.18.0.0/15`; legitimate client address must be `10.99.0.1`.
  3. Generator kernel forwarding must be disabled (`net.ipv4.ip_forward = 0`).
  4. Transmission interfaces cannot be loopback or external gateways.
- **Rationale:** Pre-execution programmatic assertions prevent operator error from ever leaking flood packets outside the isolated link. Violations immediately abort with exit code `100+`.

### ADR-015: Open-Loop Legitimate Traffic Generator Architecture & Metrics
- **Status:** Accepted & Implemented (27 Oct 2026)
- **Context:** To evaluate the real-world impact of DNS flood attacks and mitigation filters, the test harness requires an objective client to measure the experience of a legitimate user.
- **Decision:** Implement a strictly **open-loop** client (`src/traffic/legit_client.py`) with:
  1. **Fixed Schedule Transmission:** Emits queries on a deterministic schedule (default 100 QPS, interval 10 ms) using high-resolution timers regardless of whether previous queries were answered or delayed.
  2. **Dedicated Source Identity:** Binds exclusively to `10.99.0.1`, completely isolated from the synthetic flood address range (`198.18.0.0/15`).
  3. **Zero Retries & Hard Timeout:** Enforces a 1.5s timeout without retransmissions (retries would mask packet drops during floods).
  4. **Per-Query Telemetry:** Outputs granular CSV logs (`seq, domain, send_time, recv_time, latency_ms, rcode, status`).
  5. **Headline Metrics:** Evaluates Legitimate Success Rate ($\frac{\text{Answered}}{\text{Sent}} \times 100\%$) and latency percentiles ($p50, p90, p95, p99$).
- **Rationale:** Closed-loop clients naturally throttle when backpressure or packet loss occurs, concealing the severity of server degradation. Open-loop generation accurately exposes service degradation and packet loss rates.

### ADR-016: Multi-Layer Telemetry Metric Collector & Drop-by-Layer Accounting
- **Status:** Accepted & Implemented (27 Oct 2026)
- **Context:** Evaluating XDP mitigation efficiency against nftables and unfiltered baselines requires synchronous telemetry across multiple architectural layers during the 60-second measurement window.
- **Decision:** Implement `src/scripts/collect_metrics.py` and `src/scripts/collect.sh` to harvest:
  1. **CPU Utilization:** Per-core and total busy %, with specific emphasis on software interrupt (%softirq) overhead on the server's pinned core via `/proc/stat` and `mpstat`.
  2. **Throughput:** Ingestion packet rate (pps) and bandwidth (Mbps) via `/sys/class/net/<iface>/statistics`.
  3. **Drops by Layer:**
     - Layer 1 (NIC Driver): `rx_dropped` / `ethtool -S`
     - Layer 2 (Kernel Softnet): `/proc/net/softnet_stat`
     - Layer 3 (XDP / eBPF): BPF stats map counters (`drop_source`, `drop_global`, `malformed`)
     - Layer 4 (Socket Buffer): `/proc/net/snmp` (`UdpInErrors`, `UdpRcvbufErrors`)
  4. **Output Format:** Generates raw per-second time-series CSVs (`cpu_util.csv`, `throughput_pps.csv`, `bpf_stats.csv`) and a normalized `metrics_summary.json`.
- **Rationale:** Direct kernel `/proc` and `/sys` scraping eliminates third-party binary dependencies while providing the exact "Drops by Layer" decomposition required by the problem statement.

### ADR-017: Baseline B0 (No Filter) Harness & Validation Protocol
- **Status:** Accepted & Implemented (27 Oct 2026)
- **Context:** Baseline B0 serves as the primary control in the experimental matrix, representing standard Linux network stack handling without firewalls or XDP mitigation. It is required for finding the server saturation threshold $S$ during calibration.
- **Decision:** Implement `src/baselines/none.sh` to enforce complete filter detachment (unloading XDP and flushing `nftables`) and `src/scripts/run_b0_test.sh` to automate end-to-end baseline execution.
- **Verification Protocol:**
  1. Synchronously execute the telemetry collector in `srv` alongside the open-loop client in `gen` (100 QPS).
  2. Acceptance threshold: Under unflooded conditions, legitimate query success rate must achieve $\ge 99.0\%$ (nominally $100\%$), with zero socket buffer errors (`UdpInErrors == 0`) and sub-millisecond median latency.
  3. Preserves all raw telemetry artifacts (`metrics_summary.json`, `legit_client.csv`, `cpu_util.csv`, `throughput_pps.csv`) in `results/raw/namespaces_B0_validation/`.
- **Rationale:** Proves that the lab harness, DNS daemon, and telemetry pipeline operate with zero packet loss or measurement noise before introducing attack traffic, explicitly labeled as namespace-based functional validation.
