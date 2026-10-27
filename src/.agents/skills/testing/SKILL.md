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

For local functional testing and development without touching physical interfaces, use the testbed automation scripts in `src/scripts/`:

```bash
# 1. Initialize isolated namespaces ('gen' and 'srv') joined by veth pair
sudo ./src/scripts/setup_env.sh

# 2. Inspect link status, IP assignments, sysctl flags, and ping connectivity
sudo ./src/scripts/status_env.sh

# 3. Execute commands inside specific namespaces
sudo ip netns exec gen ping -c 3 10.99.0.2
sudo ip netns exec srv ip addr show vsrv

# 4. Teardown and clean up virtual links and namespaces
sudo ./src/scripts/teardown_env.sh
```

### 2.1 Generator Safety Guard Self-Test
Before launching any traffic generator, verify that the guard enforces lab boundaries:
```bash
# Valid tests (must succeed with exit code 0)
./src/traffic/guard.sh --target 10.99.0.2 --source 10.99.0.1
./src/traffic/guard.sh --target 10.99.0.2 --source 198.18.5.10
python3 ./src/traffic/guard.py --target 10.99.0.2 --source 198.18.5.10

# Security containment tests (must fail with exit code >= 100)
./src/traffic/guard.sh --target 10.126.12.151 2>&1 || echo "Blocked campus IP"
./src/traffic/guard.sh --target 8.8.8.8 2>&1 || echo "Blocked public IP"
./src/traffic/guard.sh --target 10.99.0.2 --source 1.1.1.1 2>&1 || echo "Blocked unreserved source IP"
```

### 2.2 Authoritative DNS Server Bring-Up & Resolution Test
Verify that the DNS server starts cleanly inside the `srv` namespace and resolves queries from `gen`:
```bash
# 1. Start DNS Server in 'srv' (NSD or Python fallback, Core 1, RRL off)
sudo ./src/dns/start_dns.sh

# 2. Query from 'gen' namespace to verify resolution (10.99.0.2:53)
./src/dns/test_dns.sh

# 3. Stop DNS Server when testing is complete
sudo ./src/dns/stop_dns.sh
```

### 2.3 Legitimate Client Open-Loop Verification
Run the open-loop legitimate client from the `gen` namespace against the DNS server:
```bash
# Run test at 100 QPS (e.g. 10s duration = 1,000 queries)
sudo ip netns exec gen python3 ./src/traffic/legit_client.py \
    --server 10.99.0.2 --source-ip 10.99.0.1 --qps 100 --duration 10 --output /tmp/kavach_legit_test.csv

# Or use the wrapper script:
sudo ./src/traffic/run_legit.sh
```
*Verification criteria:* Under unflooded conditions, query success rate must be 100% with sub-millisecond latency over `veth` ($p50 < 1.0$ ms).

### 2.4 Telemetry Metric Collection Verification
Test the multi-layer metric collector during a benchmark window:
```bash
# Collect telemetry for 10 seconds inside 'srv' namespace
sudo ./src/scripts/collect.sh --duration 10 --output-dir /tmp/kavach_metrics_test --netns srv --iface vsrv --core 1
```
*Verification criteria:* Inspect `/tmp/kavach_metrics_test/metrics_summary.json` to confirm:
- Throughput and CPU metrics (total busy % and %softirq) are populated.
- Drops-by-layer hierarchy (NIC, softnet, XDP, socket buffer) is reported.

### 2.5 Baseline B0 End-to-End Validation Run
Execute a full automated validation of Baseline B0 (No Filter) in namespaces:
```bash
# Run end-to-end B0 baseline test (starts DNS, flushes filters, runs collector & legit client)
sudo ./src/scripts/run_b0_test.sh
```
*Acceptance criteria:*
- Legitimate query success rate: $100\%$ (minimum $\ge 99\%$).
- Socket buffer drops (`UdpInErrors`): $0$.
- Median latency: $< 1.0$ ms over `veth`.
- Preserves all raw telemetry artifacts in `results/raw/namespaces_B0_validation/`.

---

## 3. Person A Acceptance Test Protocol

Run these verification tests inside the development namespace to validate the XDP program:

### 3.1 Compilation & Verifier Acceptance
```bash
clang -target bpf -O2 -g -Wall -c xdp/dns_ratelimit.bpf.c -o xdp/dns_ratelimit.bpf.o
sudo ip netns exec srv bpftool prog loadall xdp/dns_ratelimit.bpf.o /sys/fs/bpf/kavach type xdp pinmaps /sys/fs/bpf/kavach/maps
```
*Criteria:* Compiles without warnings; passes Linux kernel 5.15 verifier without errors.

### 3.2 Packet Parsing & Drop Verification
Inject synthetic packets using `bpftool prog run` or Scapy:
1. **Valid DNS Query:** UDP/53 with length >= 12 bytes -> Verdict: `XDP_PASS`, increments `dns_seen` and `passed`.
2. **Malformed DNS Query:** UDP/53 with DNS payload < 12 bytes -> Verdict: `XDP_DROP`, increments `dns_seen` and `malformed`.
3. **Non-DNS Packet:** UDP dst port != 53 or TCP/ICMP -> Verdict: `XDP_PASS`, increments `non_dns_passed`.
4. **Non-First Fragment:** IPv4 fragment offset > 0 -> Verdict: `XDP_PASS`, increments `fragments_passed`.

### 3.3 Rate Limiter Accuracy & Concurrency Tests
1. **Under-Limit Test:** Send queries at 0.5x configured rate -> Expect ~100% pass rate.
2. **Over-Limit Test:** Send queries at 2.0x configured rate -> Expect ~50% pass rate (+/- 10%).
3. **Burst Capacity Test:** Send instantaneous burst of $N$ packets -> All $N$ packets pass up to configured `burst_tolerance`.
4. **Check-Order Isolation Test:** Two distinct source IPs send queries simultaneously: Source 1 floods at 10x limit while Source 2 sends at normal rate.
   - *Expected Result:* Source 1 experiences heavy drops (`drop_source`); Source 2 suffers zero drops. Global limit is not depleted.
5. **Dynamic Reconfiguration:** Update `map_config` rates from user space -> New rates take effect immediately without reloading the XDP program.

---

## 4. Calibration & Parameter Determination

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

## 5. Benchmark Matrix Execution Protocol

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

