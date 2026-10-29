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

## 3. Pausing, Batching, and Resuming (When Lab is in Intermittent Use)

If the lab is shared or computers might be needed by others during the day, use these built-in controls:

### Method A: Step-by-Step Interactive Pause (`--pause`)
Add `--pause` to the orchestrator command:
```bash
sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon --pause
```
- After each individual run finishes, the orchestrator safely cleans up filters and prints:
  `[PAUSED] Run S1_B0_1.0x_1 finished. Progress: [1/108 complete].`
  `>>> Press [ENTER] to start next run, or [Ctrl+C] to exit and resume later...`
- You can let it sit paused on screen as long as you want, or hit `Ctrl+C` to close terminal safely.

### Method B: Batch Mode (`--batch <N>`)
If you only have 30 or 45 minutes between lab sessions, tell the orchestrator to run only $N$ runs and then stop:
```bash
# Run a batch of 15 runs (~25 mins), then stop:
sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon --batch 15
```
- It completes 15 runs, saves all data to `results/raw/`, resets target state, and cleanly exits.

### Method C: Seamless Auto-Resume Anytime (`Ctrl+C` Friendly)
- You can press `Ctrl+C` at **any time** while the orchestrator is running.
- The orchestrator cleanly resets the target server and leaves all completed runs untouched in `results/raw/`.
- When you return to the lab hours later (or the next day), simply rerun the **exact same command**:
  ```bash
  sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon
  ```
- The orchestrator automatically inspects `results/raw/`, detects all runs that already have `run_meta.json`, `legit_client.csv`, and `metrics_summary.json`, prints `[ALREADY COMPLETED - RESUME SKIP]`, and seamlessly resumes from the next unfinished run!

### Method D: Automated Cross-Host Telemetry Streaming
- PC 1 (`target_daemon.py`) automatically streams back `metrics_summary.json` and server telemetry CSVs (`cpu_util.csv`, `throughput_pps.csv`, `bpf_stats.csv`) to PC 2 upon run completion.
- PC 2 immediately possesses all 6 required artifacts per run in `results/raw/<run_name>/` without requiring manual file copying or network sharing between runs.

---

## 4. Monitoring & Anomaly Handling

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

## 5. Post-Run Verification & Data Extraction

Once the orchestrator completes all runs:

### Step 1: Verify Data Integrity
On PC 2:
```bash
# Check number of completed benchmark runs (108 for Target Tier):
ls -1d results/raw/S*_* | wc -l

# Verify all 6 artifacts exist in each run directory:
for d in results/raw/S*_*; do
    c=$(ls -1 "$d"/*.csv "$d"/*.json 2>/dev/null | wc -l)
    if [ "$c" -lt 6 ]; then echo "[WARN] Incomplete run: $d ($c files)"; fi
done

# Generate SHA-256 checksums of all CSV and JSON artifacts
sha256sum results/raw/*/*.csv results/raw/*/*.json > results/raw/checksums.sha256
```

### Step 2: Generate Statistical Analysis & Summary Plots
On PC 2:
```bash
python3 ./src/scripts/analyze.py --input-dir results/raw/ --output-dir results/
```
Verify generated outputs:
- `results/analysis_summary.json`
- `results/analysis_table.csv`
- `results/plots/kavach_dryrun_summary.png`

### Step 3: Copy to USB Pendrive
Mount the pendrive on PC 2 (and optionally PC 1 as ground-truth backup) and copy:
```bash
# Example USB mount path: /media/aiori-2/.../
cp -r results/raw/ /media/aiori-2/<PENDRIVE>/kavach_b4_results/
cp results/analysis_summary.json /media/aiori-2/<PENDRIVE>/kavach_b4_results/
cp results/analysis_table.csv /media/aiori-2/<PENDRIVE>/kavach_b4_results/
cp -r results/plots/ /media/aiori-2/<PENDRIVE>/kavach_b4_results/
sync
```
Eject pendrive and ingest results into git repository!

---

## 6. Pre-Run Feature Verification on Lab PCs (5-Minute Smoke Protocol)

Before committing to the full multi-hour Target Tier run, execute these 4 quick validation steps:

1. **Verify Daemon Ping:**
   On PC 2:
   ```bash
   python3 -c "import socket, json; s=socket.socket(); s.connect(('10.99.0.2', 9999)); s.send(b'{\"cmd\":\"ping\"}'); print(s.recv(1024).decode())"
   ```
   *Expected:* `{"status": "ok", ...}`

2. **Verify Batch Mode (`--batch 2`):**
   On PC 2:
   ```bash
   sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon --dry-run --batch 2
   ```
   *Expected:* Runs exactly 2 rapid dry-runs and exits cleanly with `[BATCH LIMIT]`.

3. **Verify Interactive Pause & Auto-Resume:**
   On PC 2:
   ```bash
   sudo python3 ./src/scripts/orchestrator.py --target 10.99.0.2 --iface eno1 --mode daemon --dry-run --batch 3 --pause
   ```
   *Expected:*
   - Skips the first 2 already completed runs (`[ALREADY COMPLETED - RESUME SKIP]`).
   - Runs run 3, then prompts: `>>> Press [ENTER] to start next run, or [Ctrl+C] to exit and resume later...`.
   - Hit `Ctrl+C` to exit cleanly.

4. **Verify Telemetry Completeness:**
   On PC 2, check that the dry run directory contains all 6 artifacts:
   ```bash
   ls -la results/raw/S*_*_1/
   ```
   *Expected:* `legit_client.csv`, `run_meta.json`, `metrics_summary.json`, `cpu_util.csv`, `throughput_pps.csv`, `bpf_stats.csv`.

