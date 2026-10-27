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

### ADR-012: DNS Server Selection: NSD
- **Status:** Accepted
- **Context:** Need an authoritative DNS daemon on Ubuntu 24.04 with simple zone management and disableable RRL.
- **Decision:** Use NSD (`sudo apt install nsd`) bound strictly to `10.99.0.2:53` with zero Response Rate Limiting enabled.
- **Rationale:** NSD is lightweight, authoritative-only, and easily pinned to a single core for controlled saturation testing.

### ADR-013: XDP Attachment Mode Strategy for `e1000e`
- **Status:** In Progress / Validation Protocol
- **Context:** Both PCs use Intel Gigabit `eno1` powered by the `e1000e` driver.
- **Decision:** Attempt native driver attachment (`xdpdrv`) first. If `e1000e` under kernel 6.14 rejects `xdpdrv`, fall back to generic mode (`xdpgeneric`) and log the mode in all experiment outputs.
