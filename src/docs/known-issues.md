# Known Issues, Constraints & Limitations

**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods  
**Submission ID:** A3-PS022-TC367  

This document tracks known architectural limitations, verifier compatibility issues, and environment-specific constraints.

---

## 1. Kernel Verifier & Toolchain Compatibility

### Kernel 5.15 Verifier Restrictions
- **Context:** The target lab workstations run Ubuntu 22.04 LTS (default kernel 5.15, Clang 14, libbpf 0.5).
- **Issue:** Modern eBPF features supported on recent kernels (Linux 6.x, modern libbpf 1.x) may be rejected by the Linux 5.15 verifier:
  - Loop bounded verifications are strictly bounded.
  - 64-bit atomic operations require Clang `-mcpu=v3` flags.
  - Libbpf 1.0+ API calls are not backwards-compatible with libbpf 0.5.
- **Mitigation:**
  - Compile with restricted C idioms targeting kernel 5.15.
  - Test all eBPF objects in an Ubuntu 22.04 LTS environment before lab deployment.
  - Include `-I/usr/include/$(uname -m)-linux-gnu` if `asm/types.h` is missing.

---

## 2. Driver & Operating Mode Differences

### Generic XDP (`xdpgeneric`) Performance Differential
- **Issue:** If lab NICs lack driver-level native XDP support (`xdpdrv`), Kavach must attach in Generic mode (`xdpgeneric`).
- **Impact:** In Generic mode, the Linux networking core allocates `struct sk_buff` *before* invoking the XDP program. While packet drop logic functions identically, CPU cycle savings are substantially reduced compared to native driver-level drops.
- **Mitigation:**
  - Clearly identify and log the active XDP mode (`xdpdrv` vs `xdpgeneric`) in all benchmark outputs.
  - Treat Generic mode results as valid functional validation, noting the CPU overhead limitation in the final report.

### Veth Namespace Development Limitations
- **Issue:** Network namespaces connected via `veth` pairs share the host CPU and kernel scheduler.
- **Impact:** Benchmarks collected over `veth` interfaces do not reflect true physical NIC driver performance or hardware ring buffer constraints.
- **Mitigation:** All namespace measurements are classified strictly as **functional validation**, not definitive performance benchmarks.

---

## 3. Protocol & Filtering Scope Limitations

### Non-First IP Fragments Bypass
- **Issue:** Non-first fragments lack UDP headers and destination port information.
- **Behavior:** Kavach passes non-first fragments to the kernel (`XDP_PASS`) and increments the `fragments_passed` counter.
- **Security Impact:** Attackers could theoretically craft fragmented UDP floods to bypass XDP port inspection. First fragments (`offset == 0`) are inspected normally.

### VLAN Tagged Frames
- **Issue:** Ethernet frames containing IEEE 802.1Q (VLAN) tags offset the IPv4 header by 4 bytes.
- **Behavior:** By default, Kavach treats VLAN frames as non-IPv4 (`non_dns_passed`) unless explicit single-tag parsing is enabled.

### IPv6 Exclusion
- **Issue:** IPv6 traffic is not parsed or rate limited.
- **Mitigation:** IPv6 must be explicitly disabled on the test interface (`net.ipv6.conf.<iface>.disable_ipv6 = 1`).

### Unbounded Subdomain / PRSD Attacks
- **Issue:** Pseudo-Random Subdomain (PRSD) query floods generate valid UDP/53 DNS packets with random query names.
- **Limitation:** Kavach implements shallow, bounded parsing (12-byte DNS header only). It does not parse DNS query strings and therefore cannot distinguish between valid domain queries and PRSD attacks based on payload semantics.

---

## 4. Rate Limiting Dynamics & Map Behavior

### LRU Hash Map Eviction Under Massive Distributed Floods (S2)
- **Issue:** Under scenario S2 (tens of thousands of spoofed source IPs), the `BPF_MAP_TYPE_LRU_HASH` reaches capacity and evicts older keys.
- **Behavior:** When an evicted IP address returns, it is treated as a newly observed flow, granting it a fresh initial burst tolerance window.
- **Mitigation:** This behavior is inherent to finite-memory state tracking. The global rate limiter serves as the secondary backstop against aggregate volume exhaustion.

### nftables Dynamic Set Inelasticity
- **Issue:** In baseline configurations (B1/B2), `nftables` dynamic sets do not support LRU eviction.
- **Behavior:** When the set reaches its configured maximum limit (`size 65535`), new IP entries are dropped or rejected until older elements timeout, diverging from BPF LRU behavior under distributed floods.

### Multi-Core Concurrency on Global TAT
- **Issue:** In multi-queue setups, concurrent updates to the single global Theoretical Arrival Time ($TAT$) can experience atomic contention or race conditions.
- **Impact:** Potential minor limiter accuracy variance (+/- 5%) at multi-gigabit saturating loads.

