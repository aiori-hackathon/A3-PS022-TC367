# Phase B4 Main Matrix Execution Runbook

**Role:** Person B  
**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods (PS-022)  
**Submission ID:** A3-PS022-TC367  
**Testbed:** 2x HP ProDesk 4 Tower G1i PCs, Direct CAT6 on `eno1` (`10.99.0.0/24`)  
**Data Freeze Deadline:** Thursday 29 Oct, 12:00  

---

## 1. Pre-Flight Host Configuration

Execute on twin physical consoles before starting runs:

### On PC 1 (Target DUT, `10.99.0.2`):
```bash
cd ~/kavach
git pull origin main
sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role target
sudo ./src/dns/start_dns.sh --host --iface eno1
# Verify local resolution
dig @10.99.0.2 www.lab.test +short
```

### On PC 2 (Generator Host, `10.99.0.1`):
```bash
cd ~/kavach
git pull origin main
sudo ./src/scripts/pin_core.sh --iface eno1 --core 1 --role generator
# Verify link reachability
ping -c 3 10.99.0.2
# Verify remote DNS resolution
dig @10.99.0.2 www.lab.test +short
```

---

## 2. Execution Setup (Automated via Target Daemon)

### Step 1: Launch Target Daemon on PC 1
```bash
sudo python3 ./src/scripts/target_daemon.py --iface eno1
```
*Leave this running in its own terminal on PC 1.*

### Step 2: Select Matrix Tier & Launch Orchestrator on PC 2

Choose the tier based on your lab time budget:

#### Option 1: Target Tier (Recommended - 108 Runs, ~3.0 Hours)
- Full matrix: 4 configs (B0, B1, B2, X) $\times$ 3 scenarios (S1, S2, S3) $\times$ 3 levels (50k, 100k, 200k) $\times$ 3 reps.
- Command:
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon
  ```

#### Option 2: Fallback Tier (Drop B1 - 81 Runs, ~2.3 Hours)
- Drops nftables prerouting raw baseline (B1), retaining netdev ingress (B2), B0, and X:
- Command:
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --configs B0 B2 X --mode daemon
  ```

#### Option 3: Minimum Viable Tier (Emergency Crunch - 36 Runs, ~1.0 Hour)
- 3 configs (B0, B2, X) $\times$ 3 scenarios $\times$ 2 levels (100k, 200k) $\times$ 2 reps:
- Command:
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --configs B0 B2 X --levels 1.0 2.0 --reps 2 --mode daemon
  ```

---

## 3. Monitoring & Anomaly Handling

- **Live Progress:** The orchestrator prints progress for each run:
  `[1/108] Running S1_B0_1.0x_1 (Warmup 10s, Measure 60s, Cooldown 10s)...`
- **If Interrupted (Ctrl+C):**
  If a run is manually aborted, clean up PC 1 before restarting:
  ```bash
  # On PC 1:
  sudo ./src/baselines/none.sh
  sudo ./src/dns/start_dns.sh --host --iface eno1
  sudo python3 ./src/scripts/target_daemon.py --iface eno1
  ```

---

## 4. Post-Run Verification & Data Extraction

Once the orchestrator completes all runs:

### Step 1: Verify Data Integrity
On PC 2:
```bash
# Check number of completed runs
ls -1d results/raw/* | wc -l

# Generate SHA-256 checksums of all CSV artifacts
sha256sum results/raw/*/*.csv > results/raw/checksums.sha256
```

### Step 2: Generate Statistical Analysis & Summary Plots
On PC 2:
```bash
python3 ./src/scripts/analyze.py --input-dir results/raw/ --output-dir results/
```
Verify generated outputs:
- `results/analysis_summary.json`
- `results/analysis_table.csv`
- `results/plots/kavach_summary.png`

### Step 3: Copy to USB Pendrive
Mount the pendrive on PC 2 and copy:
```bash
# Example USB mount path: /media/aiori-2/.../
cp -r results/raw/ /media/aiori-2/<PENDRIVE>/kavach_b4_results/
cp results/analysis_summary.json /media/aiori-2/<PENDRIVE>/kavach_b4_results/
cp results/analysis_table.csv /media/aiori-2/<PENDRIVE>/kavach_b4_results/
cp -r results/plots/ /media/aiori-2/<PENDRIVE>/kavach_b4_results/
sync
```
Eject pendrive and ingest results into git repository!

