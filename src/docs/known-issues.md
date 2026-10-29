# Known Issues, Constraints & Limitations

**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods  
**Submission ID:** A3-PS022-TC367  
**Updated:** 27 October 2026 (incorporating B0 lab fact findings)  

---

## 1. Physical Hardware & Testbed Topology Constraints

### Single NIC Interface (`eno1`) on Lab Workstations
- **Observation:** `ip -br link` reports only `lo` and `eno1` on both HP ProDesk PCs. The `eno1` port was initially attached to the campus network (`10.126.12.x/16`).
- **Risk:** If flood traffic is generated while `eno1` is connected to the campus network, institutional switches and firewalls will be flooded, violating safety rules.
- **Enforced Solution:**
  1. Both machines must be physically disconnected from the campus network before running any traffic generators.
  2. A direct physical CAT6 patch cable must bridge `eno1` (PC 1) and `eno1` (PC 2).
  3. Work must proceed via direct console access (physical monitor and keyboard) or via an added USB-Ethernet adapter dedicated to management.

### CPU Frequency Scaling (`powersave` Governor)
- **Observation:** Both machines report `/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` set to `powersave`.
- **Impact:** Dynamic CPU clock frequency throttling during flood ramp-up will introduce severe measurement jitter in CPU utilization (`mpstat`) and query response latencies.
- **Enforced Solution:** The CPU governor must be explicitly forced to `performance` on all 14 cores prior to benchmark execution:
  ```bash
  echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
  ```

### Background Service Noise (`unattended-upgrades`, `ufw`)
- **Observation:** `unattended-upgrades` and `ufw` are active by default on Ubuntu 24.04.
- **Impact:** Periodic apt background scans and default firewall hooks cause packet drops and spurious CPU spikes.
- **Enforced Solution:** Disable `unattended-upgrades` and `ufw` on both test machines via `pin_core.sh`.

### Offline Execution & Absence of Out-of-Band SSH Management
- **Observation:** Both machines operate completely offline without active SSH links between them over the isolated link (`10.99.0.0/24`). Operators interact via twin physical keyboards and monitors.
- **Impact:** Benchmark runners on PC 2 cannot natively trigger remote execution on PC 1 via standard `ssh` commands.
- **Enforced Solution:** Implemented `src/scripts/target_daemon.py` listening on `10.99.0.2:9999` to accept JSON control instructions across the isolated link, alongside fallback twin-console interactive manual prompts in `src/scripts/smoke_runner.py`.

---

## 2. Kernel & Toolchain Specifics

### Target Kernel: `6.14.0-1020-oem` (Ubuntu 24.04.4 LTS)
- **Status:** Verified.
- **Advantages:** Full BTF support (`/sys/kernel/btf/vmlinux`), reliable 64-bit BPF atomics, modern libbpf support.
- **Cross-Environment Warning:** If developing or testing on older distributions (such as Ubuntu 22.04 with kernel 5.15), avoid kernel 6.x-specific kfuncs or newer libbpf APIs that might break if executed on older kernels.

### Missing Packages in Base Image
- **Status:** Neither PC currently has `clang`, `nsd`, `dnsperf`, or `trafgen` (`netsniff-ng`).
- **Action:** Must be installed via `apt` while campus internet access is available on `eno1` before cable reconfiguration.

---

## 3. Driver & Operating Mode Differences

### Intel `e1000e` Driver & Native XDP (`xdpdrv`)
- **Context:** Both lab machines use onboard Intel gigabit interfaces driven by `e1000e`.
- **Behavior:** The Linux `e1000e` driver has native XDP support, but may enforce constraints on MTU (typically must be <= 1500) and packet buffer allocations.
- **Fallback:** If `xdpdrv` fails to attach or drops the link, the loader must fall back to `xdpgeneric`, logging the generic mode status.

### Veth Namespace Development Limitations
- **Issue:** Network namespaces connected via `veth` pairs share the host CPU and kernel scheduler.
- **Impact:** Benchmarks collected over `veth` interfaces do not reflect true physical NIC driver performance or hardware ring buffer constraints.
- **Mitigation:** All namespace measurements are classified strictly as **functional validation**, not definitive performance benchmarks.

### BPF Map Pinning in Network Namespaces (`nsenter` vs `ip netns exec`)
- **Issue:** Standard `ip netns exec <ns>` unshares the mount namespace and mounts a private sysfs on `/sys`, which masks the host's `/sys/fs/bpf` mount and prevents access to pinned BPF maps.
- **Solution:** Invoke BPF control commands using `nsenter --net=/run/netns/<ns>`, switching strictly the network namespace while retaining access to the host `/sys/fs/bpf` hierarchy.

### bpftool JSON Option Syntax
- **Issue:** Passing `-j` after the subcommand (e.g., `bpftool map dump pinned <path> -j`) fails with return code 255 on newer bpftool builds.
- **Solution:** Place `-j` immediately before the subcommand (e.g., `bpftool -j map dump pinned <path>`).

---

## 4. Protocol & Filtering Scope Limitations

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

## 5. Rate Limiting Dynamics & Map Behavior

### LRU Hash Map Eviction Under Massive Distributed Floods (S2)
- **Issue:** Under scenario S2 (tens of thousands of spoofed source IPs), the `BPF_MAP_TYPE_LRU_HASH` reaches capacity and evicts older keys.
- **Behavior:** When an evicted IP address returns, it is treated as a newly observed flow, granting it a fresh initial burst tolerance window.
- **Mitigation:** Inherent to finite-memory state tracking. The global rate limiter serves as the secondary backstop against aggregate volume exhaustion.

### nftables Dynamic Set Inelasticity
- **Issue:** In baseline configurations (B1/B2), `nftables` dynamic sets do not support LRU eviction.
- **Behavior:** When the set reaches its configured maximum limit (`size 65535`), new IP entries are dropped or rejected until older elements timeout, diverging from BPF LRU behavior under distributed floods.
