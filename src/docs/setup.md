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

### 4.2 Automated Host Tuning & Core Pinning Script
Instead of running manual tuning commands, run `src/scripts/pin_core.sh` on both hosts:

```bash
# On PC 1 (Target / Server):
sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role target

# On PC 2 (Traffic Generator):
sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role generator
```

This utility automatically:
1. Disables `irqbalance` and `unattended-upgrades`.
2. Sets all 14 cores to the `performance` scaling governor.
3. Automatically identifies the NIC IRQ for device `0000:80:1f.6` (`eno1`, Intel `e1000e`) and binds it to Core 1 (`echo 1 > /proc/irq/<irq>/smp_affinity_list`).
4. Enforces role-specific sysctl rules (`rp_filter=0` and `disable_ipv6=1` on Target; `ip_forward=0` and `disable_ipv6=1` on Generator).

---

## 5. Phase B3 Operational Runbook (Offline Lab Bring-Up)

Because the two lab PCs operate without campus network connectivity and without SSH, use this runbook from their physical consoles:

### Step 1: Pre-flight Verification
1. On PC 1 (Target, `10.99.0.2`):
   ```bash
   sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role target
   sudo ./src/dns/start_dns.sh --host --iface eno1
   ```
2. On PC 2 (Generator, `10.99.0.1`):
   ```bash
   sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role generator
   ping -c 3 10.99.0.2
   ```

### Step 2: Baseline Saturation Calibration (Find $S$)
On PC 2 (Generator):
```bash
sudo python3 ./src/scripts/calibrate.py --target 10.99.0.2 --iface eno1
```
- The harness verifies unflooded resolution (100 QPS).
- Automatically ramps flood traffic (5k $\to$ 10k $\to$ 20k $\to$ ... pps).
- Identifies the saturation threshold $S$ where legitimate query success drops below 99%.
- Verifies that the generator ceiling can sustain $\ge 2.0\times S$.
- Updates `src/params.yaml` and `src/params.json` with derived rates and levels.

### Step 3: Smoke Runs (B0, B1, B2, X)
**Option A (Automated with Target Daemon):**
1. On PC 1 (Target):
   ```bash
   sudo python3 ./src/scripts/target_daemon.py --iface eno1
   ```
2. On PC 2 (Generator):
   ```bash
   sudo ./src/scripts/run_smoke.sh
   ```
   *(PC 2 automatically orchestrates all 4 runs across the link, collects telemetry, and outputs summary).*

**Option B (Twin-Console Manual Mode):**
If not using the daemon:
1. On PC 2: run `sudo ./src/scripts/run_smoke.sh`.
2. When prompted for each configuration, execute on PC 1:
   ```bash
   sudo ./src/scripts/run_smoke_target.sh --config {B0|B1|B2|X} --duration 14
   ```
   and press Enter on PC 2.
3. Review the final 4-configuration summary table!

---

## 6. Phase B4 Main Benchmark Matrix Execution

### Step 1: Pre-run Verification
Ensure both hosts are tuned to Core 1:
```bash
# PC 1 (Target):
sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role target
# PC 2 (Generator):
sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role generator
```

### Step 2: Start Target Daemon on PC 1
```bash
sudo python3 ./src/scripts/target_daemon.py --iface eno1
```
*(Leave running in Console 1 of PC 1; it resets state and attaches filters automatically for each run).*

### Step 3: Launch Orchestrator on PC 2
Choose the matrix tier according to time constraints:

- **Target Tier (Recommended, 108 runs, ~3.0 hrs):**
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon
  ```
- **Fallback Tier (Drop B1, 81 runs, ~2.3 hrs):**
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --configs B0 B2 X --mode daemon
  ```
- **Minimum Viable Tier (Emergency, 36 runs, ~1.0 hr):**
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --configs B0 B2 X --levels 1.0 2.0 --reps 2 --mode daemon
  ```

### Step 4: Data Verification & USB Extraction
1. Verify raw runs are populated:
   ```bash
   ls results/raw/
   ```
2. Generate SHA-256 checksums:
   ```bash
   sha256sum results/raw/*/*.csv > results/raw/checksums.sha256
   ```
3. Run statistical analysis:
   ```bash
   python3 ./src/scripts/analyze.py --input-dir results/raw/ --output-dir results/
   ```
4. Copy `results/raw/`, `results/analysis_summary.json`, `results/analysis_table.csv`, and `results/plots/` to USB pendrive for ingestion.

