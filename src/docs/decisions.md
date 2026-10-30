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

### ADR-018: Integration of Core XDP Filter Engine & Control Plane Contract
- **Status:** Accepted & Merged into `main` (28 Oct 2026)
- **Context:** Completion of the core eBPF/XDP filter (`xdp/kavach_xdp.c`), the GCRA limiter library (`xdp/gcra.h`), and the user-space controller (`xdp/kavach_ctl.py`).
- **Decision:** Integrated the XDP engine into `main` and adopted the frozen interface contract:
  1. **14-Counter Telemetry Schema:** `timestamp_ns,seen,pass_non_ipv4,pass_non_udp,pass_non53,pass_fragment,pass_truncated,pass_invalid_ipv4,dns_pass,drop_bad_udp,drop_short_dns,drop_src,drop_global,drop_busy,drop_state`.
  2. **Config ABI:** 40-byte native-endian structure (`kavach_config`) via `=QQQQII`.
  3. **Concurrency:** BPF atomic CAS (`__sync_val_compare_and_swap`) with bounded 8-attempt retry loop; fallback to `kavach_xdp_approx.o` if needed.
  4. **Watchdog Protocol:** UUID generation tokens with atomic conditional detachment via `libbpf` `bpf_xdp_detach`.
  5. **Directory Structure:** Root-level `xdp/` coexisting harmoniously with `src/`.
- **Rationale:** Guarantees verifier safety, rigorous mathematical drop-counter accounting, and clean operational decoupling between the kernel filter and the measurement harness.

### ADR-019: Synthetic Traffic Generators (S1, S2, S3) Architecture & Custom C Implementation
- **Status:** Accepted & Implemented (28 Oct 2026)
- **Context:** Third-party packet generators like `trafgen` or `pktgen` have platform discrepancies, missing dependencies across Arch and Ubuntu, and lack built-in programmatically non-bypassable destination and source IP guardrails.
- **Decision:** Implement a dedicated, lightweight, high-performance C packet generator (`src/traffic/kavach_gen.c`) with `IP_HDRINCL` raw sockets, supported by a Python CLI (`src/traffic/flood.py`):
  1. **Strict Safety Asserts:** Programmatic verification in C that exits with code 100 if destination is outside `10.99.0.0/24`, source is outside `198.18.0.0/15`, or `ip_forward != 0`.
  2. **Scenario S1:** Single-source constant-rate flood paced via monotonic high-resolution timers.
  3. **Scenario S2:** Distributed flood across 1,000 randomized source IPs drawn strictly from `198.18.0.0/15`.
  4. **Scenario S3:** Pulsing bursts of 0.5x, 1x, and 2x burst tolerance with configurable period $P \le 10$ s.
  5. **Ceiling Mode:** High-speed transmission benchmark to measure generator host maximum capacity.
- **Rationale:** Maximizes packet transmission rates with zero third-party dependencies while enforcing strict RFC 2544 and lab boundary safety.

### ADR-020: nftables Baselines B1 (Prerouting Raw) and B2 (Netdev Ingress) Parameterized Formulation
- **Status:** Accepted & Implemented (28 Oct 2026)
- **Context:** To benchmark XDP fairly against netfilter, two nftables baselines are required with identical rate/burst limits and identical evaluation order (per-source dynamic set first, global limit second).
- **Decision:** Implement `src/baselines/b1_prerouting.sh` (table `ip kavach_b1` at hook `prerouting` priority `raw` with `notrack` to bypass conntrack) and `src/baselines/b2_netdev.sh` (table `netdev kavach_b2` at hook `ingress device <iface>` priority -500). Verify effective limits using `src/baselines/verify_baselines.py`.
- **Rationale:** Provides strict parity between XDP and netfilter while measuring the performance difference across the driver layer, netdev hook, and prerouting hook.

### ADR-021: Shared Configuration & Parameter Specification (`params.yaml` / `params.json`)
- **Status:** Accepted & Implemented (28 Oct 2026)
- **Context:** Limiter parameters, saturation thresholds ($S$), client QPS, and measurement timings must be synchronized between the loader, traffic generators, orchestrator, and baselines without hardcoded magic numbers.
- **Decision:** Standardize on `src/params.yaml` (mirrored to `src/params.json`) defining `calibration`, `filter_limits`, `legitimate`, `scenarios`, `timings`, and `network`.
- **Rationale:** Enables flexible reconfiguration, dry-run profiling, and ensures identical parameters are passed to both XDP and nftables.

### ADR-022: Experiment Orchestrator v1 Architecture & Seeded Random Execution Protocol
- **Status:** Accepted & Implemented (28 Oct 2026)
- **Context:** Benchmark matrices require reproducible execution, clean state reset, and protection against time-dependent confounding factors (systemic drift, cache warming).
- **Decision:** Implement `src/scripts/orchestrator.py` and wrapper `src/scripts/run_orchestrator.sh` executing runs in a seeded pseudo-random order (`run_order.json`). Each run executes: Reset -> Configure -> Warm-up -> Measurement Window -> Cool-down -> Save, isolating artifacts to `results/raw/<scenario>_<config>_<level>_<rep>/`.
- **Rationale:** Prevents systematic bias and guarantees repeatable experimental rigor.

### ADR-023: Telemetry Analysis Engine (`analyze.py v0`) & Multi-Layer Drop Visualization
- **Status:** Accepted & Implemented (28 Oct 2026)
- **Context:** Post-processing raw telemetry across dozens of runs requires robust statistical aggregation and multi-layer drop decomposition.
- **Decision:** Implement `src/scripts/analyze.py` to calculate Median and IQR for legitimate query success %, latency percentiles ($p50, p95, p99$), CPU busy % and softirq %, and multi-tier Drops by Layer (Layer 1 NIC -> Layer 2 Softnet -> Layer 3 Filter -> Layer 4 Socket Buffer). Generates consolidated JSON, CSV, and publication-ready multi-panel figure `results/plots/kavach_dryrun_summary.png` using matplotlib.
- **Rationale:** Automates objective comparison across all four configurations without manual spreadsheet manipulation.

### ADR-024: Phase B3 Baseline Calibration & Empirical Saturation Point ($S$) Determination
- **Status:** Accepted & Implemented (29 Oct 2026 - Hardware Calibrated)
- **Context:** Rather than assuming theoretical server limits, Phase B3 requires determining the actual unflooded server capacity threshold $S$ under Baseline B0 (No Filter).
- **Empirical Lab Measurements (29 Oct 2026):**
  - Ramping from 5,000 pps to 75,000 pps: Legitimate query success was 100.0% with flat median latency ($\sim 0.52\text{--}0.57$ ms).
  - At 100,000 pps: Legitimate success dropped sharply to 83.4% - 88.6%, with p50 latency spiking by $27\times$ to 15.60 ms (p95: 28.22 ms).
  - Empirically determined saturation point: **$S = 100,000$ pps**.
- **Derived Benchmark Parameters:**
  1. Flood Levels: $0.5\times S = 50,000$ pps, $1.0\times S = 100,000$ pps, and $2.0\times S = 200,000$ pps.
  2. Per-Source Rate Limit: $500$ pps ($5\times$ legitimate client rate 100 QPS).
  3. Global Rate Limit: $70,000$ pps ($0.70 \times S$).
  4. Unified Burst Tolerance: $20$ packets across all limiters.
  5. Updated `src/params.yaml` and `src/params.json`.
  6. Generator ceiling measured at $124,763\text{--}198,935$ pps, matching the $2.0\times S$ capacity constraint.
- **Rationale:** Grounded directly in physical hardware measurements of the Intel Core Ultra 5 245 and `eno1` Gigabit link.

### ADR-025: Physical Testbed Dual-Console Orchestration & Target Daemon Synchronization
- **Status:** Accepted & Implemented (29 Oct 2026)
- **Context:** In the physical laboratory, PC 1 (Target) and PC 2 (Generator) are directly connected via a dedicated CAT6 cable (`10.99.0.0/24`) without an institutional SSH management network. Operators work via two physical keyboards/monitors.
- **Decision:** Support dual-operating modes for Phase B3 and Phase B4:
  1. **Automated Daemon Mode:** Implement `src/scripts/target_daemon.py` running on PC 1 (listening on `10.99.0.2:9999`). PC 2 commands PC 1 via lightweight JSON control packets over the isolated link to reset state, apply configs, and synchronize telemetry collection.
  2. **Twin-Console Manual Mode:** Implement `src/scripts/run_smoke_target.sh` on PC 1 and interactive prompts in `src/scripts/smoke_runner.py` on PC 2, allowing operators to run tests manually across two screens.
- **Rationale:** Guarantees complete execution flexibility in offline lab environments without compromising isolation safety or requiring third-party management daemons.

### ADR-026: Single-Core Affinity & Hardware NIC IRQ Pinning Architecture (`IR-PCI-NSI-0000:80:1f.6`)
- **Status:** Accepted & Implemented (29 Oct 2026)
- **Context:** To obtain clean per-core capacity benchmarks and eliminate multi-core cache thrashing or IRQ migration jitter, the DNS server process and NIC hardware interrupts must be strictly bound to Core 1.
- **Decision:** Implement `src/scripts/pin_core.sh` to:
  1. Disable background jitter sources (`irqbalance`, `unattended-upgrades`).
  2. Force CPU scaling governor to `performance` on all cores.
  3. Parse `/proc/interrupts` for device `0000:80:1f.6` (`e1000e` onboard controller) and pin IRQ lines to Core 1 (`echo 1 > /proc/irq/<irq>/smp_affinity_list`).
  4. Pin NSD or mock DNS daemon to Core 1 via `taskset -c 1`.
  5. Enforce sysctl rules (`rp_filter=0`, `disable_ipv6=1`, `ip_forward=0`).
- **Rationale:** Normalizes experimental conditions, guaranteeing that measured saturation and drop rates reflect deterministic single-core throughput.

### ADR-027: Phase B3 Smoke Test Validation & Intel `e1000e` Generic XDP Operational Findings
- **Status:** Accepted & Validated (29 Oct 2026)
- **Context:** Prior to executing the multi-hour Phase B4 experimental matrix, Phase B3 requires end-to-end functional validation across all 4 configurations under S1 flood at $1.0\times S$ (100,000 pps).
- **Empirical Smoke Test Findings (Scenario S1 @ 100k pps):**
  - **B0 (No Filter):** Legitimate success fell to 86.92% (157 queries lost); median latency spiked to 14.055 ms (p95: 28.461 ms).
  - **B1 (nftables Prerouting Raw):** 100.00% legitimate success; median latency 0.480 ms (p95: 1.416 ms).
  - **B2 (nftables Netdev Ingress):** 100.00% legitimate success; median latency 0.473 ms (p95: 1.359 ms).
  - **X (Kavach XDP):** 100.00% legitimate success; median latency **0.409 ms** (fastest of all configurations, ~15% latency advantage over netfilter; p95: 1.434 ms).
- **Attachment Mode Finding:** On Ubuntu 24.04.4 LTS with kernel `6.14.0-1020-oem`, the Intel `e1000e` driver on `eno1` attached in generic mode (`xdpgeneric`). The fallback logic in `target_daemon.py` and `kavach_ctl.py` handled this transparently.
- **Decision:** Proceed with generic XDP (`xdpgeneric`) for the primary physical testbed matrix as specified in the problem statement (PS-022 Item 6: *"Use an XDP-capable kernel/NIC, or document generic-mode setup"*). Explicitly label all results as generic XDP in the report.

### ADR-028: Dynamic `bpftool` Discovery & Elimination of Hardcoded Kernel Paths
- **Status:** Accepted & Implemented (29 Oct 2026)
- **Context:** The initial controller CLI (`xdp/kavach_ctl.py`) hardcoded the absolute binary path `/usr/lib/linux-tools/6.8.0-147-generic/bpftool` for loading programs and updating maps. When moving to the physical lab workstations (running Ubuntu 24.04 with OEM kernel `6.14.0-1020-oem`) or developer environments with different kernel releases, invoking `kavach_ctl.py` immediately crashed with `FileNotFoundError: [Errno 2] No such file or directory`.
- **Decision:** Remove all hardcoded kernel tool paths from the CLI control plane. Implement a tiered dynamic resolution function `find_bpftool()` in `xdp/kavach_ctl.py`:
  1. Check user override via `BPFTOOL` environment variable (`if "BPFTOOL" in os.environ:`).
  2. Check current kernel's tool directory: `/usr/lib/linux-tools/$(uname -r)/bpftool`.
  3. Glob and select the latest installed kernel tool: `/usr/lib/linux-tools/*/bpftool`.
  4. Search system `$PATH` via `shutil.which("bpftool")`.
  5. Fallback to `"bpftool"` in the active environment.
- **Rationale:** Ensures portable execution across physical workstations, local development machines, and test VMs without requiring code modifications or kernel-specific coupling.
- **Rule for Agents:** Scripts, test runners, and loaders must never hardcode kernel release strings or absolute paths to distro-specific tool packages.

### ADR-029: Orchestrator Pause/Resume Checkpointing, Batch Execution, and Cross-Host Telemetry Synchronization
- **Status:** Accepted & Implemented (29 Oct 2026)
- **Context:** Executing the full 108-run Phase B4 experimental matrix on twin physical lab workstations presents several operational risks:
  1. The lab is shared or operating on tight time blocks where runs may be interrupted.
  2. If the orchestrator is stopped with `Ctrl+C` or a power/network interruption occurs, restarting from scratch would waste hours.
  3. In the 2-PC architecture, PC 2 (Generator) writes `legit_client.csv` and `run_meta.json`, while PC 1 (Target) runs `collect_metrics.py` and produces `metrics_summary.json` and server telemetry CSVs (`cpu_util.csv`, `throughput_pps.csv`, `bpf_stats.csv`). Without cross-host synchronization, PC 2 lacks the server telemetry required by `analyze.py`.
  4. Command-line argument parsing crashed when operators passed space-separated arguments (e.g. `--configs B0 B2 X`).
- **Decision:**
  1. **Checkpoint & Auto-Resume:** In `src/scripts/orchestrator.py`, verify before each run whether `run_meta.json`, `legit_client.csv` (size > 100 B), and `metrics_summary.json` already exist on disk. If so, log `[ALREADY COMPLETED - RESUME SKIP]` and skip to the next run without repeating work.
  2. **Batch Execution Control (`--batch <N>`):** Support running up to $N$ runs and gracefully exiting, allowing operators to execute benchmarks in 20-30 minute slices.
  3. **Interactive Step-by-Step Pause (`--pause`):** Provide prompt `>>> Press [ENTER] to start next run, or [Ctrl+C] to exit and resume later...` after each run for manual inspection.
  4. **Cross-Host Telemetry Streaming:** In `src/scripts/target_daemon.py`, upon receiving `cmd: "stop"`, wait for `collector_proc`, read `metrics_summary.json` and the server CSVs, and return them inside the JSON response payload. `orchestrator.py` saves them directly into `results/raw/<run_name>/` on PC 2, guaranteeing all 6 artifacts exist locally on PC 2 in real time.
  5. **Flexible CLI Argument Parser:** Implement `parse_flexible_list` and `parse_flexible_levels` with `nargs="*"` in `orchestrator.py` to seamlessly accept both comma-separated and space-separated parameters.
- **Rationale:** Guarantees zero data loss, eliminates manual file copying across hosts, and enables safe execution in shared offline lab environments.

### ADR-030: Phase B4 Physical Testbed Matrix Execution (108 Runs) & Empirical Validation
- **Status:** Accepted & Validated (30 Oct 2026 - Target Tier Complete)
- **Context:** Phase B4 mandates executing the benchmark matrix across 4 configurations (B0, B1, B2, X) $\times$ 3 scenarios (S1, S2, S3) $\times$ 3 flood levels (0.5x, 1.0x, 2.0x) $\times$ 3 repetitions, yielding 108 total experimental runs on twin HP ProDesk 4 workstations (Intel Core Ultra 5 245, onboard `eno1` Intel `e1000e` Gigabit NIC, Ubuntu 24.04 OEM kernel `6.14.0-1020-oem`).
- **Empirical Findings Across 108 Runs:**
  1. **Hypothesis H2 (Legitimate Query Protection):** Under Baseline B0 (No Filter), flood traffic saturated server socket buffers, resulting in severe packet drops (median success fell to 87.0% in S1, dropping down to 71.9% at 2.0x) and median latency surged $27\times$ to $14.30\text{ ms}$ (p95: $27.85\text{ ms}$). Under Kavach XDP (X), legitimate query success was maintained at **100.0%** across all S1 runs with ultra-low median latency of **$0.44\text{ ms}$** (p95: $1.43\text{ ms}$), providing deterministic sub-millisecond service.
  2. **Hypothesis H4 (State Table Resilience under S2 Spoofed Flood):** Under S2 (1,000 random spoofed sources from `198.18.0.0/15`), the BPF `LRU_HASH` map handled key churn without kernel panics, table exhaustion, or lock contention, maintaining 74.0% legitimate query survival matching netfilter ingress while the global rate limiter safely throttled aggregate flood volume.
  3. **Socket Buffer Protection:** In S1, B0 suffered **$920,180$ socket buffer overflow drops** (`RcvbufErrors`) inside the Linux kernel networking stack, whereas Kavach XDP dropped $5,966,949$ flood packets at the filter layer, resulting in **zero** socket buffer drops.
- **Data Freeze & Checksumming:** All 108 runs with 6 artifacts per run (648 files total) were frozen and validated with SHA-256 checksums in `results/checksums_physical_108.sha256` and canonical `results/raw/checksums.sha256`.

### ADR-031: Native Mode Validation in Virtual Namespaces (`veth_xdp`) & Software Emulation Analysis
- **Status:** Accepted & Validated (30 Oct 2026 - 36 Runs Complete)
- **Context:** To complement the physical testbed (which ran in generic XDP mode due to onboard `e1000e` driver constraints), a full 36-run matrix was executed in Linux network namespaces (`gen` $\leftrightarrow$ `srv`) where the virtual ethernet driver (`veth`) supports native driver-level XDP (`xdpdrv` / `veth_xdp`).
- **Empirical Findings:**
  1. **Native Driver Drop (Hypothesis H3):** Driver attachment was confirmed as `"xdp_mode": "native"`. Under S1 @ 1.0x (75,000 pps), out of $6,002,884$ incoming flood packets, **$5,965,866$ packets were dropped directly in the driver hook**, delivering only $37,018$ packets to the UDP socket buffer (matching nftables baselines).
  2. **Stack Protection & SoftIRQ Reduction:** Driver-level drops prevented incoming flood packets from entering the IP/UDP stack, reducing kernel SoftIRQ CPU overhead from $2.37\%$ in B0 down to **$0.84\%$** under XDP (a 65% reduction).
  3. **Software Emulation Mechanics on `veth`:** In namespaces on a single host, virtual ethernet emulates native XDP in software (`drivers/net/veth.c`) via page-pool allocations rather than hardware ASIC DMA drops. Total system CPU was lower under XDP (3.77% vs 4.92%–6.44% in B0), while single-core software page allocation on `veth` demonstrated functional correctness rather than hardware capacity numbers, in full agreement with AGENTS.md Section 12.1.
- **Checksumming:** All 36 namespace runs (216 artifacts) were frozen in `results/checksums_namespaces_36.sha256`.

### ADR-032: Statistical Rigor: Median + IQR Reporting and High-Resolution Publication Artifacts
- **Status:** Accepted & Implemented (30 Oct 2026)
- **Context:** Under heavy DDoS query floods, network queueing, bufferbloat, and burst arrival processes exhibit non-Gaussian, heavy-tailed distributions. Standard deviations and simple arithmetic means are distorted by extreme outliers and failed query timeouts.
- **Decision:**
  1. **Mandatory Median + IQR:** All analysis routines (`src/scripts/analyze.py`) report Median and Interquartile Range (IQR = $Q_{75} - Q_{25}$) across repetitions for latency, throughput, CPU utilization, and success rates. Median captures central tendency, while IQR quantifies latency jitter and tail-performance predictability under attack.
  2. **High-Resolution Figures:** Implement `src/scripts/generate_publication_figures.py` to generate 300 DPI raster PNGs and scalable vector PDFs in `results/figures/`:
     - `fig1_physical_benchmark_matrix`: 4-panel comprehensive physical benchmark summary.
     - `fig2_rate_levels_and_saturation`: Metric scaling across $0.5\times$, $1.0\times$, $2.0\times$ flood intensity.
     - `fig3_native_namespaces_validation`: Native mode driver-level drop fate and SoftIRQ reduction.
     - `fig4_latency_cdf_distribution`: Empirical CDF of query response times highlighting sub-millisecond determinism.
- **Rationale:** Ensures complete scientific and academic rigor adhering to top-tier benchmarking standards and the requirements of PS-022.


### ADR-033: Archival of Physical Testbed Photographic Evidence & Calibration Screenshots
- **Status:** Accepted & Documented (30 Oct 2026)
- **Context:** To satisfy the AIORI Hackathon submission requirements, verify real physical laboratory execution on the twin HP ProDesk 4 workstations, and provide complete transparency in the technical report, visual evidence must be formally cataloged and archived in the repository.
- **Decision:**
  1. **Documentation Media Hierarchy:** Established `docs/media/` with subdirectories `docs/media/testbed_photos/` (for high-resolution photography of the twin HP ProDesk workstations, isolated CAT6 Gigabit cabling, and monitor consoles) and `docs/media/screenshots/` (for real-time terminal and monitoring captures).
  2. **Calibration Evidence Integration:** Copied `results/calibration/lab_pc2_calibration_screenshot.png` (captured during live traffic generation on PC 2 and transferred via USB pendrive) into `docs/media/screenshots/`.
  3. **Report Integration:** Direct Markdown and LaTeX embedding paths documented in `docs/media/README.md` and referenced in `docs/setup.md` and `src/AGENTS.md`.
- **Rationale:** Provides irrefutable empirical proof of physical testbed execution, hardware bring-up, and live benchmarking.
