---
name: testing
description: Executing unit tests, verifier validation, network namespace integration testing, physical lab bring-up, traffic generation scenarios, and baseline benchmarks in Kavach.
---

# Testing and Validation Skill

This skill defines the complete testing and validation lifecycle for Kavach, spanning local development network namespaces to the physical lab host-pair (HP ProDesk 4 Tower G1i PCs, Ubuntu 24.04 LTS, Kernel 6.14.0-oem).

---

## 1. Physical Lab Host Bring-Up Protocol (Two HP ProDesk PCs)

### 1.1 Package Installation (Run over Campus LAN before Disconnect)
On both PC 1 (`aiori-HP-ProDesk-4...`) and PC 2 (`aiori-2-HP-ProDesk-4...`):
```bash
sudo apt update
sudo apt install -y \
    clang llvm libbpf-dev linux-tools-common linux-tools-generic \
    nsd dnsperf netsniff-ng \
    python3-pandas python3-matplotlib python3-yaml \
    sysstat ethtool
```

### 1.2 System Tuning & Single-NIC Direct Cabling
1. Disconnect `eno1` from the campus wall jack / switch on both PCs.
2. Connect a direct CAT6 Ethernet patch cable between `eno1` (PC 1) and `eno1` (PC 2).
3. On PC 1 (Target / Server):
   ```bash
   sudo ip addr flush dev eno1
   sudo ip addr add 10.99.0.2/24 dev eno1
   sudo ip link set dev eno1 up
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   sudo systemctl stop unattended-upgrades && sudo ufw disable
   sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.eno1.disable_ipv6=1
   sudo sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eno1.rp_filter=0
   ```
4. On PC 2 (Traffic Generator):
   ```bash
   sudo ip addr flush dev eno1
   sudo ip addr add 10.99.0.1/24 dev eno1
   sudo ip link set dev eno1 up
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   sudo systemctl stop unattended-upgrades && sudo ufw disable
   sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.eno1.disable_ipv6=1
   sudo sysctl -w net.ipv4.ip_forward=0
   ```
5. Connectivity sanity check:
   ```bash
   # From PC 2:
   ping -c 3 10.99.0.2
   ```

---

## 2. Local Network Namespace Test Environment Setup

For local functional testing and development without touching physical interfaces:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Create isolated namespaces
sudo ip netns add gen
sudo ip netns add srv

# 2. Create and link veth pair
sudo ip link add vgen type veth peer name vsrv
sudo ip link set vgen netns gen
sudo ip link set vsrv netns srv

# 3. Configure IP addressing on isolated test subnet (10.99.0.0/24)
sudo ip -n gen addr add 10.99.0.1/24 dev vgen
sudo ip -n srv addr add 10.99.0.2/24 dev vsrv

# 4. Bring interfaces up
sudo ip -n gen link set lo up
sudo ip -n gen link set vgen up
sudo ip -n srv link set lo up
sudo ip -n srv link set vsrv up

# 5. Disable IPv6 and configure routing
sudo ip netns exec gen sysctl -qw net.ipv6.conf.all.disable_ipv6=1
sudo ip netns exec srv sysctl -qw net.ipv6.conf.all.disable_ipv6=1
sudo ip netns exec srv sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.vsrv.rp_filter=0
sudo ip -n srv route add default via 10.99.0.1
sudo ip netns exec gen sysctl -qw net.ipv4.ip_forward=0
```

---

## 2. Person A Acceptance Test Protocol

Run these verification tests inside the development namespace to validate the XDP program:

### 2.1 Compilation & Verifier Acceptance
```bash
clang -target bpf -O2 -g -Wall -c xdp/dns_ratelimit.bpf.c -o xdp/dns_ratelimit.bpf.o
sudo ip netns exec srv bpftool prog loadall xdp/dns_ratelimit.bpf.o /sys/fs/bpf/kavach type xdp pinmaps /sys/fs/bpf/kavach/maps
```
*Criteria:* Compiles without warnings; passes Linux kernel 5.15 verifier without errors.

### 2.2 Packet Parsing & Drop Verification
Inject synthetic packets using `bpftool prog run` or Scapy:
1. **Valid DNS Query:** UDP/53 with length >= 12 bytes -> Verdict: `XDP_PASS`, increments `dns_seen` and `passed`.
2. **Malformed DNS Query:** UDP/53 with DNS payload < 12 bytes -> Verdict: `XDP_DROP`, increments `dns_seen` and `malformed`.
3. **Non-DNS Packet:** UDP dst port != 53 or TCP/ICMP -> Verdict: `XDP_PASS`, increments `non_dns_passed`.
4. **Non-First Fragment:** IPv4 fragment offset > 0 -> Verdict: `XDP_PASS`, increments `fragments_passed`.

### 2.3 Rate Limiter Accuracy & Concurrency Tests
1. **Under-Limit Test:** Send queries at 0.5x configured rate -> Expect ~100% pass rate.
2. **Over-Limit Test:** Send queries at 2.0x configured rate -> Expect ~50% pass rate (+/- 10%).
3. **Burst Capacity Test:** Send instantaneous burst of $N$ packets -> All $N$ packets pass up to configured `burst_tolerance`.
4. **Check-Order Isolation Test:** Two distinct source IPs send queries simultaneously: Source 1 floods at 10x limit while Source 2 sends at normal rate.
   - *Expected Result:* Source 1 experiences heavy drops (`drop_source`); Source 2 suffers zero drops. Global limit is not depleted.
5. **Dynamic Reconfiguration:** Update `map_config` rates from user space -> New rates take effect immediately without reloading the XDP program.

---

## 3. Calibration & Parameter Determination

Before running comparative benchmark matrices:
1. **Pin Server Core:** Pin the DNS daemon process and network queue interrupts to a single core:
   ```bash
   sudo taskset -c 1 systemctl restart nsd
   ```
2. **Find Saturation Point $S$:**
   Under **B0 (No Filter)**, ramp the flood rate until the legitimate client success rate drops below 99%. Record this rate as $S$ pps.
3. **Derive Scenario Levels:**
   - 0.5x $S$, 1.0x $S$, 2.0x $S$
4. **Set Filter Parameters:**
   - Global Rate: ~70% of $S$
   - Per-Source Rate: 5x-10x the legitimate client rate
   - Record in `params.yaml`.

---

## 4. Benchmark Matrix Execution Protocol

Each benchmark run follows a strict temporal sequence:

```
[0s] ────────── Reset state (detach XDP, flush nftables, restart DNS, clear conntrack)
 │
[0s - 10s] ──── Warmup period (Legitimate client active at 100 QPS)
 │
[10s - 70s] ─── 60-second Measurement Window (Legitimate client + Flood active)
 │               Collect: mpstat, ethtool -S, bpftool map dump, nstat
 │
[70s - 80s] ─── Cooldown period (Stop flood generator, stop collectors)
 │
[80s] ────────── Export and save metrics to results/raw/<scenario>_<config>_<level>_<rep>/
```

### Comparative Configurations
- **B0:** No filter (unmodified baseline).
- **B1:** `nftables` prerouting table (raw priority).
- **B2:** `nftables` netdev ingress table.
- **X:** Kavach XDP program (`xdpdrv` or `xdpgeneric`).

