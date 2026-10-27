# Kavach System Architecture Specification

**Submission ID:** A3-PS022-TC367  
**Project:** eBPF/XDP Rate Limiting for DNS Query Floods in a Lab  
**Target Platform:** Linux Kernel 5.15+ (Ubuntu 22.04 LTS), Clang 14 / libbpf  

---

## 1. System Overview

Kavach is an in-kernel high-performance packet filtering and rate-limiting system designed to mitigate UDP/53 DNS query floods directly at the Network Interface Card (NIC) driver layer via **eXpress Data Path (XDP)**.

### 1.1 Problem Context & Motivation
Under conventional Linux packet processing:
1. Every packet arriving on the physical wire triggers an interrupt and NIC ring buffer consumption.
2. The kernel networking subsystem allocates a complex metadata descriptor: the socket buffer (`struct sk_buff`).
3. The packet traverses protocol layers (IP, Netfilter/iptables/nftables hooks, UDP socket lookup) before finally being delivered to the user-space DNS server (e.g., NSD or Knot) or dropped by firewall rules.

During high-volume DNS query floods (hundreds of thousands to millions of packets per second), the CPU spends the vast majority of its processing capacity allocating and deallocating `sk_buff` structures and servicing software interrupts (`softirq`), resulting in host CPU exhaustion, elevated latency, and dropped legitimate queries.

```
Conventional Packet Flow:
[Physical NIC] ---> [NIC Driver] ---> [Allocate sk_buff] ---> [Netfilter/nftables] ---> [UDP Socket] ---> [DNS Server]
                                             │
                                     Heavy CPU Overhead
```

### 1.2 The XDP Solution
XDP executes sandboxed eBPF bytecode inside the NIC driver's receive path before `sk_buff` allocation occurs:
- **`XDP_DROP`:** The packet is discarded immediately in driver memory, recycling the RX ring buffer descriptor without allocating an `sk_buff` or invoking the network stack.
- **`XDP_PASS`:** The packet continues normally up the standard Linux network stack.

```
Kavach XDP Packet Flow:
[Physical NIC] ---> [NIC Driver] ---> [Kavach XDP Filter] ─── (Drop: malformed/rate-limit) ───> [Recycle Ring Buffer]
                                              │
                                        (Pass: legitimate)
                                              ▼
                                     [Allocate sk_buff] ---> [Linux Stack] ---> [DNS Daemon]
```

---

## 2. End-to-End System Architecture

The experimental setup comprises two hosts connected via an isolated, dedicated network link (or two isolated network namespaces linked via a `veth` pair for development):

```
+-------------------------------------------------------------+
|                      GENERATOR HOST                         |
|                                                             |
|  +-------------------------------------------------------+  |
|  |             Legitimate Client (Open-Loop)             |  |
|  |          50-200 QPS, Dedicated Source IP              |  |
|  +-------------------------------------------------------+  |
|  +-------------------------------------------------------+  |
|  |               Synthetic Flood Generators              |  |
|  |     S1: Single-source  |  S2: Distributed (198.18/15) |  |
|  |               S3: Pulsing Burst Flood                 |  |
|  +-------------------------------------------------------+  |
|  +-------------------------------------------------------+  |
|  |         Generator Guard (Strict Lab Boundary)         |  |
|  +-------------------------------------------------------+  |
+------------------------------│------------------------------+
                               │ Isolated Test Subnet
                               │ (10.99.0.0/24)
                               ▼
+-------------------------------------------------------------+
|              TARGET HOST (Device Under Test)                |
|                                                             |
|  KERNEL SPACE (NIC Driver Layer):                           |
|  +-------------------------------------------------------+  |
|  |                    Kavach XDP Filter                  |  |
|  |                                                       |  |
|  |  [Bounded Ethernet / IPv4 / UDP / DNS Parsing]        |  |
|  |                         │                             |  |
|  |  [Tier 1: Per-Source GCRA Limiter (LRU Hash Map)]     |  |
|  |                         │                             |  |
|  |  [Tier 2: Global GCRA Limiter (Array Map)]            |  |
|  +-------------------------------------------------------+  |
|                            │                                |
|                   XDP_PASS │ (Legitimate traffic)           |
|                            ▼                                |
|  [Standard Linux Network Stack & UDP Socket Buffer]         |
|                            │                                |
|                            ▼                                |
|  USER SPACE:                                                |
|  +-------------------------------------------------------+  |
|  |           DNS Server Daemon (NSD / Knot, RRL off)     |  |
|  +-------------------------------------------------------+  |
|  +-------------------------------------------------------+  |
|  |           Kavach Loader / Controller / Watchdog       |  |
|  +-------------------------------------------------------+  |
|  +-------------------------------------------------------+  |
|  |           Metric Collectors (mpstat, ethtool, BPF)    |  |
|  +-------------------------------------------------------+  |
+-------------------------------------------------------------+
```

---

## 3. Bounded Packet Parsing Pipeline

eBPF programs run inside an in-kernel verifier that guarantees safety, bounded execution time, and absence of out-of-bounds memory accesses.

```
Incoming Packet (xdp_md: data, data_end)
  │
  ├── 1. Boundary check: data + sizeof(ethhdr) <= data_end
  │      No ──> PASS (unparsable_passed)
  │      Yes: eth->h_proto == ETH_P_IP?
  │           No ──> PASS (non_dns_passed)
  │
  ├── 2. Boundary check: data + eth_len + sizeof(iphdr) <= data_end
  │      No ──> PASS (unparsable_passed)
  │      Yes: ip->protocol == IPPROTO_UDP?
  │           No ──> PASS (non_dns_passed)
  │      IP Header Length (IHL): ihl = ip->ihl * 4; ihl >= 20?
  │           No ──> DROP (malformed)
  │      Non-first fragment check: (frag_off & 0x1FFF) != 0?
  │           Yes ──> PASS (fragments_passed)
  │
  ├── 3. Boundary check: udp_ptr + sizeof(udphdr) <= data_end
  │      No ──> PASS (unparsable_passed)
  │      Yes: udp->dest == htons(53)?
  │           No ──> PASS (non_dns_passed)
  │      UDP length consistency: ntohs(udp->len) >= sizeof(udphdr)?
  │           No ──> DROP (malformed)
  │
  ├── 4. Boundary check: dns_ptr + 12 <= data_end
  │      No ──> DROP (malformed: payload < 12 bytes)
  │
  └── 5. Pass to Rate Limiting Engine
```

### Parsing Rules & Constraints
1. **No Query Name Looping:** The DNS query payload contains variable-length DNS name labels (`<length><label>...0x00`). Parsing or looping through these labels in eBPF introduces complex verifier loops and state-space explosion. Kavach strictly inspects the fixed 12-byte DNS header (RFC 1035: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) and **never parses the query name**.
2. **IHL Accounting:** IP header length is dynamically calculated via `ip->ihl * 4` to account for IP options, ensuring correct UDP header offsetting.
3. **Fragment Policy:** Non-first fragments lack UDP headers and pass unfiltered (`fragments_passed`). First fragments (`offset == 0`) contain UDP headers and are parsed normally.
4. **IPv6 Excluded:** IPv6 parsing is out of scope to prevent verifier explosion from extension header chaining. IPv6 is explicitly disabled on the test interface (`disable_ipv6=1`).

---

## 4. Rate Limiting Engine: Generic Cell Rate Algorithm (GCRA)

Kavach employs the **Generic Cell Rate Algorithm (GCRA)**, a continuous-time leaky bucket variant defined in ITU-T Recommendation I.371.

### 4.1 Mathematical Formulation
Unlike token bucket limiters requiring periodic replenishment or floating-point division, GCRA tracks a single 64-bit timestamp per bucket: the **Theoretical Arrival Time ($TAT$)**.

- **Parameters (Precomputed in User Space):**
  - Emission Interval:
    $$T = \frac{10^9}{\text{rate\_pps}} \quad (\text{nanoseconds})$$
  - Burst Tolerance:
    $$\tau = (\text{burst\_packets} - 1) \times T \quad (\text{nanoseconds})$$

- **Packet Arrival Evaluation at Time $t_{\text{now}}$ (monotonic ns via `bpf_ktime_get_ns()`):**
  1. Determine current baseline arrival time:
     $$TAT' = \max(TAT_{\text{stored}}, t_{\text{now}})$$
     *(If no prior arrival recorded, $TAT' = t_{\text{now}}$, granting a full initial burst capacity).*
  2. Evaluate limit condition:
     $$\text{If } (TAT' - t_{\text{now}}) > \tau \implies \mathbf{DROP}$$
  3. If within tolerance:
     $$TAT_{\text{new}} = TAT' + T \implies \mathbf{PASS}$$

All calculations run in integer nanosecond arithmetic without division or floating-point operations.

### 4.2 Two-Tier Bucket Hierarchy and Check Order
Kavach implements two distinct GCRA tiers:
1. **Tier 1 (Per-Source):** Evaluated against the source IPv4 address.
2. **Tier 2 (Global):** Evaluated across all aggregate DNS query arrivals.

#### Check Order Decision: Per-Source FIRST, then Global
The evaluation order is strictly **Per-Source first, Global second**:
- **Why this order is mandatory:** If the global check were performed first, high-rate malicious query floods from a single source would decrement and deplete the shared global bucket *before* being dropped by the per-source filter. This would starve legitimate traffic.
- By placing the per-source check first, packets exceeding an individual source's threshold are dropped immediately without consuming global capacity.
- Packets that pass per-source but exceed the global threshold are dropped by the global limiter. The per-source bucket update is retained to maintain accurate flow history.

---

## 5. BPF Maps Specification

### 5.1 Per-Source State Map (`map_src_tat`)
- **Type:** `BPF_MAP_TYPE_LRU_HASH`
- **Key:** `u32` (Source IPv4 Address)
- **Value:** `u64` ($TAT$, Theoretical Arrival Time in ns)
- **Max Entries:** 65,536 (configurable)
- **Design Rationale:** An LRU (Least Recently Used) map automatically evicts idle source flows when full, preventing memory exhaustion under spoofed-source floods ($S2$). Evicted sources restart with standard burst tolerance upon subsequent arrival.

### 5.2 Global State Map (`map_glob_tat`)
- **Type:** `BPF_MAP_TYPE_ARRAY`
- **Key:** `u32` (Index `0`)
- **Value:** `u64` ($TAT$, Global Theoretical Arrival Time in ns)
- **Max Entries:** 1

### 5.3 Configuration Map (`map_config`)
- **Type:** `BPF_MAP_TYPE_ARRAY`
- **Key:** `u32` (Index)
- **Value:** `u64`
- **Entries:**
  - `[0]`: `src_interval_ns` ($T_{\text{src}}$)
  - `[1]`: `src_tolerance_ns` ($\tau_{\text{src}}$)
  - `[2]`: `glob_interval_ns` ($T_{\text{glob}}$)
  - `[3]`: `glob_tolerance_ns` ($\tau_{\text{glob}}$)
  - `[4]`: `filter_enabled` (Boolean flag: 1 = active, 0 = pass-through)

*Advantage:* Limits and burst parameters are adjusted dynamically from user space without recompiling or detaching the XDP program.

### 5.4 Telemetry & Statistics Map (`map_stats`)
- **Type:** `BPF_MAP_TYPE_PERCPU_ARRAY`
- **Key:** `u32` (Index)
- **Value:** `u64` (Packet Counter)
- **Counter Indices:**
  - `0`: `dns_seen` (Total UDP/53 candidate packets received)
  - `1`: `non_dns_passed` (Non-IP, non-UDP, or non-port-53 packets passed)
  - `2`: `passed` (Legitimate DNS queries passed up the stack)
  - `3`: `drop_source` (Packets dropped by per-source GCRA)
  - `4`: `drop_global` (Packets dropped by global GCRA)
  - `5`: `malformed` (Malformed DNS/UDP packets dropped)
  - `6`: `fragments_passed` (Non-first fragments passed)
  - `7`: `unparsable_passed` (Truncated headers passed)

*Design Rationale:* `PERCPU_ARRAY` eliminates cache-line bouncing and lock contention across CPU cores during multi-gigabit packet ingestion.

---

## 6. Concurrency Strategy

On multi-core systems, multiple RX ring buffers process incoming packets concurrently across different CPU cores.

1. **Global Bucket Race Condition:** Multiple CPUs reading and updating the single global `u64 tat` simultaneously can cause lost updates or stale reads.
2. **Design Hierarchy:**
   - **Preferred: BPF Atomic CAS (`__sync_val_compare_and_swap`):** Uses kernel 5.12+ 64-bit BPF atomic operations with Clang `-mcpu=v3` in a bounded compare-and-swap retry loop.
   - **Alternative: `bpf_spin_lock`:** Supported inside BPF array map elements.
   - **Fallback: Tolerated Racy Update:** Under massive flood conditions, slight timing approximation in the global timestamp has minimal operational impact on aggregate throughput control.

---

## 7. Loader, Controller, and Watchdog Contract

The user-space control plane interfaces with the BPF subsystem via `bpftool` and libbpf:

```
+-------------------------------------------------------------+
|                      USER-SPACE LOADER                      |
|                                                             |
|  [load]    bpftool prog loadall -> pin maps in /sys/fs/bpf  |
|  [attach]  Attach to interface (xdpdrv or xdpgeneric)       |
|  [config]  Update map_config with rate/burst parameters     |
|  [stats]   Periodic JSON/CSV export from map_stats          |
|  [detach]  Clean detachment & map unpinning                 |
+-------------------------------------------------------------+
                               │
                               ▼
+-------------------------------------------------------------+
|                     SAFETY WATCHDOG                         |
|                                                             |
|  - Spawns background watchdog process upon attachment       |
|  - Auto-detaches XDP program after N minutes (default: 10m) |
|    unless explicitly renewed by orchestrator                |
|  - Prevents host isolation or lockout during testing        |
+-------------------------------------------------------------+
```

---

## 8. Baseline Comparisons & Experimental Fairness

To scientifically evaluate the efficiency of the XDP layer, four configurations are benchmarked under identical hardware and network states:

| Configuration | Description | Filtering Location | Memory Cost |
|---|---|---|---|
| **B0 (No filter)** | Raw Linux stack + DNS server | None (all packets reach socket) | Full `sk_buff` allocated for all packets |
| **B1 (nftables raw)** | nftables prerouting chain | PREROUTING hook (raw priority) | `sk_buff` already allocated |
| **B2 (nftables netdev)** | nftables netdev ingress chain | Earliest Netfilter hook | `sk_buff` already allocated |
| **X (Kavach XDP)** | In-kernel XDP program | NIC Driver layer | **Zero `sk_buff` allocated** for dropped packets |

### Fairness Controls
- Identical rate thresholds and burst parameters configured across XDP and nftables.
- Reverse Path Filtering disabled (`rp_filter=0`) across all configurations.
- DNS daemon internal response rate limiting (RRL) strictly disabled.
- Single-core affinity pinning for DNS server and network interrupt processing.
- Clean system state reset between successive benchmark runs.

