# Architecture Decision Records (ADRs)

**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods  
**Submission ID:** A3-PS022-TC367  

This document logs architectural and design decisions made throughout the lifecycle of the project, including settled rationale, alternatives considered, and items pending lab hardware verification.

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
- **Context:** Project time budget is strictly limited, and the Linux kernel 5.15 verifier restricts complex looping.
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
- **Rationale:** Protects campus network infrastructure and prevents developer SSH lockout.

---

## Open / Hardware-Dependent Decisions

### ADR-009: XDP Attachment Mode: Native vs Generic
- **Status:** Proposed / Pending Lab Hardware
- **Context:** Native XDP (`xdpdrv`) requires hardware driver support, while Generic XDP (`xdpgeneric`) functions across all Linux interfaces at reduced efficiency.
- **Strategy:** Verify NIC driver on lab PCs (`ethtool -i`). Attempt `xdpdrv` attachment first. If unsupported, fall back to `xdpgeneric`, clearly documenting the mode in benchmark results.

### ADR-010: Multi-Core Concurrency Strategy for Global Rate Limiter
- **Status:** Proposed / Verification Needed
- **Context:** In multi-queue NIC environments, multiple CPUs concurrently access the global `u64 tat`.
- **Strategy:** 
  1. Preferred: Atomic compare-and-swap loop (`__sync_val_compare_and_swap`) using Clang `-mcpu=v3`.
  2. Alternative: In-kernel `bpf_spin_lock` on array map value.
  3. Fallback: Tolerated racy update, documenting limiter accuracy variance.

### ADR-011: Authoritative DNS Server Selection (NSD vs Knot)
- **Status:** Proposed
- **Context:** The target server requires an authoritative DNS daemon with Response Rate Limiting (RRL) disabled.
- **Decision:** Default to NSD (or Knot DNS) depending on package availability on Ubuntu 22.04 LTS lab images, with RRL modules explicitly disabled.

