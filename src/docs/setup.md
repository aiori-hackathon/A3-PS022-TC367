# Physical Lab Testbed Setup & Environment Facts

**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods  
**Submission ID:** A3-PS022-TC367  
**Date Collected:** 27 October 2026 (via B0 Fact Collector Script)  

---

## 1. Hardware Inventory & Host Specifications

The physical laboratory environment consists of two identical dedicated workstations.

| Component | PC 1 (Target / Device Under Test) | PC 2 (Traffic Generator Host) |
|---|---|---|
| **Hostname** | `aiori-HP-ProDesk-4-Tower-G1i-Desktop-AI-PC` | `aiori-2-HP-ProDesk-4-Tower-G1i-Desktop-AI-PC` |
| **System Model** | HP ProDesk 4 Tower G1i Desktop AI PC | HP ProDesk 4 Tower G1i Desktop AI PC |
| **Processor** | Intel(R) Core(TM) Ultra 5 245 | Intel(R) Core(TM) Ultra 5 245 |
| **Cores / Threads** | 14 cores, 14 threads (1 socket) | 14 cores, 14 threads (1 socket) |
| **Memory (RAM)** | 30 GiB total (~26 GiB free) | 30 GiB total (~26 GiB free) |
| **Storage** | 488 GB NVMe/SSD ext4 (3% used, ~450 GB free) | 485 GB NVMe/SSD ext4 (3% used, ~447 GB free) |
| **Active Interface** | `eno1` (MAC: `10:b6:76:51:01:d5`) | `eno1` (MAC: `10:b6:76:50:fb:ac`) |
| **NIC Model & Driver** | Intel Gigabit (`e1000e`), 1000 Mb/s Full Duplex | Intel Gigabit (`e1000e`), 1000 Mb/s Full Duplex |
| **Initial IP (Campus)** | `10.126.12.151/16` (Gateway: `10.126.0.11`) | `10.126.12.152/16` (Gateway: `10.126.0.11`) |

---

## 2. Operating System & Kernel Details

- **Distribution:** Ubuntu 24.04.4 LTS (Noble Numbat)
- **Kernel Release:** `6.14.0-1020-oem`
- **Architecture:** `x86_64`
- **BPF Subsystem Status:**
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_JIT=y`
  - **BTF Support:** Fully enabled (`/sys/kernel/btf/vmlinux` present)
  - **BPF Filesystem:** Mounted at `/sys/fs/bpf` (`type bpf`, mode 700)
- **Firewall:** `nftables` v1.0.9 installed (initial ruleset is clean, exit code 0)

---

## 3. Toolchain Status & Package Gaps

### Installed Tools
- `bpftool`: Installed & verified
- `nft`: Installed (`v1.0.9`)
- `python3`: Installed
- `ethtool`: Installed
- `mpstat` (sysstat): Installed
- `nstat`: Installed

### Missing Packages
- Compilers / eBPF dev: `clang`, `llc`, `libbpf-dev`
- DNS Server: `nsd` or `knotd`
- Load Generators: `trafgen` (`netsniff-ng`), `dnsperf`

### Installation Command for Both Hosts:
```bash
sudo apt update
sudo apt install -y \
    clang llvm libbpf-dev linux-tools-common linux-tools-generic \
    nsd dnsperf netsniff-ng \
    python3-pandas python3-matplotlib python3-yaml \
    sysstat ethtool
```

---

## 4. Critical Architecture & Operational Adjustments

### 4.1 The Single NIC Physical Isolation Strategy
Both machines currently expose only **one** network interface (`eno1`), which connects to the university campus LAN.
- **Rule:** Flood traffic must NEVER cross onto the campus network (`10.126.0.0/16`).
- **Procedure:**
  1. Complete all package installations via `eno1` while connected to campus LAN.
  2. Disconnect `eno1` from the campus network on both machines.
  3. Connect a direct CAT6 Ethernet patch cable directly between `eno1` of PC 1 and `eno1` of PC 2.
  4. Configure isolated test IP addressing:
     - PC 1 (Target / Server): `10.99.0.2/24`
     - PC 2 (Generator): `10.99.0.1/24`
  5. Work locally via physical keyboard and monitor (or secondary USB-Ethernet adapter if SSH over campus network is required).

### 4.2 Required Host Tuning Before Benchmark Runs
Run the following commands on both hosts:

```bash
# 1. Switch CPU Governor from 'powersave' to 'performance'
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 2. Prevent background upgrade jitter
sudo systemctl stop unattended-upgrades
sudo systemctl disable unattended-upgrades

# 3. Disable UFW firewall (nftables will be controlled directly)
sudo ufw disable

# 4. Disable IPv6 on the test interface
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.eno1.disable_ipv6=1

# 5. Disable Reverse Path Filtering on the Server (PC 1)
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.eno1.rp_filter=0
```

