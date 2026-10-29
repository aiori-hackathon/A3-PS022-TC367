---
name: debugging
description: Debugging eBPF/XDP programs, verifier rejection errors, kernel tracing, bpftool inspection, and packet drop anomalies in Kavach.
---

# eBPF/XDP Debugging Skill

This skill provides step-by-step procedures for diagnosing and troubleshooting the Kavach eBPF/XDP kernel program, loader interactions, map states, and packet drop discrepancies.

## 1. Diagnosing eBPF Verifier Rejections

When `clang` compiles the eBPF code or when `bpftool` / `ip` attempts to load the program into the kernel, the BPF verifier may reject the bytecode.

### 1.1 Bounds Checking Failures (`invalid access to packet`)
- **Symptom:** `math between pkt pointer and register with unbounded min value` or `invalid access to packet, id=0, off=..., size=... R1 offset is outside of the packet`.
- **Cause:** Dereferencing a packet pointer without an explicit verification check against `data_end` in the immediately preceding instruction path.
- **Remedy:** Ensure every header pointer access has a strictly bounded check:
  ```c
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
      return XDP_PASS;
  ```
- **Rule:** Never reuse a verified pointer offset after modifying another pointer unless explicitly re-checked against `data_end`.

### 1.2 Bounded Loop Rejections
- **Symptom:** `back-edge from insn ... to ...` or `loop detected`.
- **Cause:** Kernel 5.15 verifier restricts loops. While bounded loops `#pragma unroll` exist, unbounded loops over DNS labels will fail verification.
- **Remedy:** Do not parse variable-length DNS names. Only inspect the fixed 12-byte header.

### 1.3 Verifier Log Inspection
To capture the full verifier diagnostic trace:
```bash
# Dump detailed verifier log using bpftool
sudo bpftool prog loadall xdp/dns_ratelimit.bpf.o /sys/fs/bpf/kavach_debug -d
```

---

## 2. In-Kernel Tracing via `bpf_printk`

To inspect live variable states during packet processing:
1. Add `bpf_printk()` in `dns_ratelimit.bpf.c`:
   ```c
   bpf_printk("Kavach: src_ip=%x tat=%llu now=%llu\n", src_ip, tat, now);
   ```
2. Read the kernel trace pipe:
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe | grep Kavach
   ```
   *(Note: Remove `bpf_printk` calls before conducting performance benchmarks as trace logging incurs significant overhead).*

---

## 3. Map Inspection and Verification

Verify that maps are properly pinned and populated:

```bash
# List all active BPF maps
sudo bpftool map list

# Dump config map to verify rates and burst tolerances
sudo bpftool map dump pinned /sys/fs/bpf/kavach/maps/map_config

# Dump per-source LRU map to verify IP tracking
sudo bpftool map dump pinned /sys/fs/bpf/kavach/maps/map_src_tat

# Dump per-CPU statistics map
sudo bpftool map dump pinned /sys/fs/bpf/kavach/maps/map_stats
```

> [!TIP]
> When inspecting pinned maps on an interface located within a network namespace, run bpftool directly from the host mount namespace, or use `nsenter --net=/run/netns/<ns>` to avoid unsharing `/sys` and masking `/sys/fs/bpf`. Note also that the `-j` flag in bpftool must precede the subcommand (e.g. `bpftool -j map dump pinned ...`).

---

## 4. Troubleshooting Packet Drops and Network Anomalies

### 4.1 Intel `e1000e` Driver & XDP Attach Verification
The lab PCs use the Intel `e1000e` Gigabit driver on Linux kernel `6.14.0-1020-oem`.
- Check active attach mode:
  ```bash
  ip link show dev eno1
  # Look for "xdp" (native xdpdrv) or "xdpgeneric" (generic mode)
  ```
- **Lab Finding:** On Linux `6.14.0-1020-oem`, native attach (`xdpdrv`) is rejected with `Operation not supported` by the `e1000e` driver. The system attaches in `xdpgeneric` mode. This satisfies PS-022 Item 6 ("Use an XDP-capable kernel/NIC, or document generic-mode setup").
- Verify CPU frequency scaling is pinned:
  ```bash
  cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
  # Must report "performance" across all 14 cores
  ```

### 4.2 Missing Expected Drops or Leakage
- Verify XDP attach mode:
  ```bash
  ip link show dev <iface>
  # Look for "xdp" (native) or "xdpgeneric" (generic)
  ```
- Check if `rp_filter` is dropping packets before the stack:
  ```bash
  sysctl net.ipv4.conf.all.rp_filter
  sysctl net.ipv4.conf.<iface>.rp_filter
  ```
- If testing in namespaces (`gen` / `srv`), run `sudo ./src/scripts/status_env.sh` to confirm link states, IP routes, and `rp_filter=0`.
- Verify DNS server Response Rate Limiting (RRL) is disabled so drops originate exclusively from XDP.

### 4.3 Software Interrupt and Ring Buffer Saturation
- Inspect dropped packets at the NIC driver layer:
  ```bash
  ethtool -S <iface> | grep -E 'drop|discard|miss'
  ```
- Check kernel softirq drops:
  ```bash
  cat /proc/net/softnet_stat
  ```
- Monitor CPU core distribution:
  ```bash
  mpstat -P ALL 1
  ```

### 4.4 Generator Socket Ring-Lock Contention
- **Symptom:** Generator effective transmit rate throttles down from ~200k pps to ~125k pps when setting target rate to 500k pps.
- **Cause:** Single-threaded raw socket (`SOCK_RAW` / `IP_HDRINCL`) ring-buffer syscall lock contention under excessive request rates.
- **Fix:** Keep generator rates within physical link headroom ($\le 200,000$ pps for $2.0\times S$).

### 4.5 Clean Interface Recovery After Manual Interrupt (Ctrl+C)
If `target_daemon.py`, a smoke run, or the orchestrator is interrupted with `Ctrl+C`, the test interface `eno1` may retain residual XDP programs or nftables rules, causing `dig` to report `no servers could be reached`:
```bash
# On PC 1 (Target):
sudo ./src/baselines/none.sh
sudo ./src/dns/start_dns.sh --host --iface eno1
# Test resolution locally:
dig @10.99.0.2 www.lab.test +short
```

### 4.6 Legitimate Client Response Status Validation
`legit_client.py` reports `status: ANSWERED` (with `rcode: 0` / `NOERROR`) when resolving queries. Any parsing scripts must accept `status in ["ANSWERED", "SUCCESS"] or rcode in ["0", "NOERROR"]` rather than strictly matching `"SUCCESS"`.

---

## 5. Watchdog Auto-Detachment Debugging

If the XDP program unexpectedly detaches during a test:
- Check if the background watchdog process timer expired:
  ```bash
  ps aux | grep watchdog
  ```
- Check kernel dmesg for driver reset or interface reload events:
  ```bash
  dmesg -T | grep -E 'xdp|link'
  ```

