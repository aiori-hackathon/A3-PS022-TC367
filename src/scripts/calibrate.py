#!/usr/bin/env python3
"""
Kavach PS-022: Automated Calibration Harness (Phase B3)
Submission ID: A3-PS022-TC367

Executes Phase B3 calibration protocol to empirically determine the unflooded
server saturation threshold (S) under Baseline B0 (No Filter):
  1. Verifies unflooded baseline legitimate query resolution (100 QPS).
  2. Ramps flood traffic across configurable rate increments (default: 5k to 150k pps).
  3. Detects the saturation threshold S where legitimate query success drops below 99%.
  4. Derives empirical flood levels (0.5x, 1.0x, 2.0x S) and filter limits:
       - Per-Source Rate: 5x-10x legitimate query rate (e.g. 500 pps)
       - Global Rate: ~70% of S (0.70 * S)
       - Common Burst: One unified burst tolerance for all filters (default: 20 pkts)
  5. Verifies the traffic generator host ceiling can comfortably sustain 2x S.
  6. Automatically updates src/params.yaml and src/params.json.
"""

import os
import sys
import time
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src"
TRAFFIC_DIR = SRC_DIR / "traffic"
SCRIPTS_DIR = SRC_DIR / "scripts"
PARAMS_YAML = SRC_DIR / "params.yaml"
PARAMS_JSON = SRC_DIR / "params.json"

# Enforce Generator Guard
sys.path.insert(0, str(TRAFFIC_DIR))
try:
    from guard import enforce_all, SecurityViolation
except ImportError:
    print("[ERROR] Cannot import guard module from src/traffic!", file=sys.stderr)
    sys.exit(101)


def parse_args():
    parser = argparse.ArgumentParser(description="Kavach Phase B3 Calibration Harness")
    parser.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    parser.add_argument("--source", default="10.99.0.1", help="Legitimate client source IP (default: 10.99.0.1)")
    parser.add_argument("--iface", default="eno1", help="Network interface (default: eno1)")
    parser.add_argument("--netns", default="", help="Network namespace for generator (default: host/empty)")
    parser.add_argument("--legit-qps", type=float, default=100.0, help="Legitimate client QPS (default: 100.0)")
    parser.add_argument("--step-duration", type=float, default=10.0, help="Window per ramp step in seconds (default: 10.0)")
    parser.add_argument("--threshold", type=float, default=99.0, help="Legitimate success %% threshold for S (default: 99.0)")
    parser.add_argument("--burst", type=int, default=20, help="Common burst value for per-source and global (default: 20)")
    parser.add_argument("--rates", default="5000,10000,15000,20000,25000,30000,40000,50000,60000,75000,100000,125000,150000",
                        help="Comma-separated flood rate ramp progression in pps")
    parser.add_argument("--no-update", action="store_true", help="Do not update params.yaml and params.json")
    return parser.parse_args()


def run_cmd(cmd: List[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, stdout=subprocess.PIPE if capture else None,
                         stderr=subprocess.PIPE if capture else None, text=True)
    if check and res.returncode != 0:
        err = res.stderr.strip() if res.stderr else res.stdout.strip()
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd)}\n{err}")
    return res


def compute_legit_metrics(csv_path: Path) -> Tuple[int, int, float, float, float]:
    """Parses legitimate client CSV and returns (sent, answered, success_rate, p50_ms, p95_ms)."""
    if not csv_path.is_file():
        return 0, 0, 0.0, 0.0, 0.0

    latencies = []
    answered = 0
    total = 0

    with open(csv_path, "r") as f:
        lines = f.readlines()

    header = True
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if header:
            header = False
            continue
        parts = line.split(",")
        if len(parts) >= 7:
            total += 1
            status = parts[6].strip().upper()
            if status == "SUCCESS":
                answered += 1
                try:
                    lat_ms = float(parts[4])
                    latencies.append(lat_ms)
                except ValueError:
                    pass

    success_rate = (answered / total * 100.0) if total > 0 else 0.0
    latencies.sort()
    n = len(latencies)
    p50 = latencies[int(n * 0.50)] if n > 0 else 0.0
    p95 = latencies[int(n * 0.95)] if n > 0 else 0.0

    return total, answered, success_rate, p50, p95


def update_parameter_files(S_pps: int, burst: int, legit_qps: float):
    """Updates src/params.yaml and src/params.json with calibrated numbers."""
    src_rate = int(legit_qps * 5)  # 5x legitimate rate (500 pps for 100 QPS)
    glob_rate = int(round(S_pps * 0.70))  # 70% of S
    levels = [0.5, 1.0, 2.0]

    # 1. Update YAML if pyyaml available
    if PARAMS_YAML.is_file():
        # Create timestamped backup
        backup_path = PARAMS_YAML.with_suffix(f".yaml.bak.{int(time.time())}")
        shutil.copy2(PARAMS_YAML, backup_path)
        print(f"[Backup] Saved original params backup to: {backup_path.name}")

        try:
            import yaml
            with open(PARAMS_YAML, "r") as f:
                data = yaml.safe_load(f)

            data.setdefault("calibration", {})
            data["calibration"]["S_pps"] = S_pps
            data["calibration"]["levels"] = levels

            data.setdefault("filter_limits", {})
            data["filter_limits"]["src_rate"] = src_rate
            data["filter_limits"]["src_burst"] = burst
            data["filter_limits"]["glob_rate"] = glob_rate
            data["filter_limits"]["glob_burst"] = burst

            with open(PARAMS_YAML, "w") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            print(f"[SUCCESS] Updated {PARAMS_YAML.name} with calibrated profile.")
        except ImportError:
            print("[WARN] PyYAML not installed; updating params.yaml via line replacement...")
            # Fallback direct file replacement
            with open(PARAMS_YAML, "r") as f:
                lines = f.readlines()
            new_lines = []
            for line in lines:
                if line.strip().startswith("S_pps:"):
                    new_lines.append(f"  S_pps: {S_pps}\n")
                elif line.strip().startswith("src_rate:"):
                    new_lines.append(f"  src_rate: {src_rate}\n")
                elif line.strip().startswith("src_burst:"):
                    new_lines.append(f"  src_burst: {burst}\n")
                elif line.strip().startswith("glob_rate:"):
                    new_lines.append(f"  glob_rate: {glob_rate}\n")
                elif line.strip().startswith("glob_burst:"):
                    new_lines.append(f"  glob_burst: {burst}\n")
                else:
                    new_lines.append(line)
            with open(PARAMS_YAML, "w") as f:
                f.writelines(new_lines)

    # 2. Update JSON
    if PARAMS_JSON.is_file():
        with open(PARAMS_JSON, "r") as f:
            jdata = json.load(f)

        jdata.setdefault("calibration", {})
        jdata["calibration"]["S_pps"] = S_pps
        jdata["calibration"]["levels"] = levels

        jdata.setdefault("filter_limits", {})
        jdata["filter_limits"]["src_rate"] = src_rate
        jdata["filter_limits"]["src_burst"] = burst
        jdata["filter_limits"]["glob_rate"] = glob_rate
        jdata["filter_limits"]["glob_burst"] = burst

        with open(PARAMS_JSON, "w") as f:
            json.dump(jdata, f, indent=2)
        print(f"[SUCCESS] Updated {PARAMS_JSON.name} with calibrated profile.")


def main():
    args = parse_args()

    print("=" * 75)
    print(" KAVACH PS-022: BASELINE B0 SATURATION CALIBRATION (PHASE B3)")
    print("=" * 75)
    print(f"Target Server   : {args.target}:53")
    print(f"Legitimate IP   : {args.source} ({args.legit_qps} QPS)")
    print(f"Interface       : {args.iface} (Namespace: '{args.netns or 'host'}')")
    print(f"Step Duration   : {args.step_duration}s per ramp level")
    print(f"Saturation Cutoff: Legitimate query success < {args.threshold}%\n")

    # 1. Enforce Generator Safety Guard
    enforce_all(target_ip=args.target, source_ip=args.source)
    print("[Guard] Pre-execution safety guard assertions PASSED.")

    # 2. Verify kavach_gen binary exists
    kavach_gen = TRAFFIC_DIR / "kavach_gen"
    if not kavach_gen.is_file():
        print("[Build] Compiling traffic generator binary (kavach_gen)...")
        run_cmd(["make", "-C", str(TRAFFIC_DIR)])

    # Setup temporary directory for calibration telemetry
    calib_dir = REPO_ROOT / "results" / "calibration"
    calib_dir.mkdir(parents=True, exist_ok=True)

    # 3. Pre-flight Baseline Sanity Check (Unflooded)
    print("\n" + "-" * 75)
    print("STEP 1: Pre-flight Unflooded Baseline Check (5 seconds at 100 QPS)...")
    print("-" * 75)

    base_csv = calib_dir / "preflight_legit.csv"
    if base_csv.exists():
        base_csv.unlink()

    legit_exec = ["sudo"]
    if args.netns:
        legit_exec += ["ip", "netns", "exec", args.netns]

    preflight_cmd = legit_exec + [
        "python3", str(TRAFFIC_DIR / "legit_client.py"),
        "--server", args.target,
        "--source-ip", args.source,
        "--qps", str(args.legit_qps),
        "--duration", "5.0",
        "--output", str(base_csv)
    ]

    p_pre = subprocess.run(preflight_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    tot, ans, rate, p50, p95 = compute_legit_metrics(base_csv)
    print(f"Pre-flight Results: Sent={tot}, Answered={ans}, Success={rate:.1f}%, p50={p50:.2f}ms, p95={p95:.2f}ms")

    if rate < 95.0:
        print("\n\033[1;31m[FATAL ERROR] Target DNS server is not responding reliably under unflooded conditions!\033[0m")
        print("Please check PC 1 (Target):")
        print("  1. Verify CAT6 direct cable connectivity: ping -c 3 10.99.0.2")
        print("  2. Verify Baseline B0 is applied: sudo ./src/baselines/none.sh --iface eno1")
        print("  3. Verify DNS server is running: sudo ./src/dns/start_dns.sh --host --iface eno1")
        print("  4. Verify resolution locally on Target: dig @10.99.0.2 www.lab.test")
        sys.exit(1)

    print("\033[1;32m[PASS] Unflooded DNS resolution confirmed. Starting flood ramp...\033[0m\n")

    # 4. Ramping Flood Traffic to find S
    rates = [int(r.strip()) for r in args.rates.split(",") if r.strip()]
    print("-" * 75)
    print("STEP 2: Ramping Flood Traffic to Find Saturation Threshold S")
    print(f"Ramp sequence: {rates} pps")
    print("-" * 75)
    print(f"{'Flood Rate (pps)':<18} | {'Sent':<8} | {'Answered':<8} | {'Success %':<10} | {'p50 (ms)':<10} | {'p95 (ms)':<10} | {'Status'}")
    print("-" * 75)

    S_detected: Optional[int] = None
    calib_history = []

    for r in rates:
        step_csv = calib_dir / f"ramp_{r}pps.csv"
        if step_csv.exists():
            step_csv.unlink()

        # Start legitimate client
        p_legit = subprocess.Popen(legit_exec + [
            "python3", str(TRAFFIC_DIR / "legit_client.py"),
            "--server", args.target,
            "--source-ip", args.source,
            "--qps", str(args.legit_qps),
            "--duration", str(args.step_duration),
            "--output", str(step_csv)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Start flood traffic (Scenario S1: single source, constant rate)
        flood_exec = ["sudo"]
        if args.netns:
            flood_exec += ["ip", "netns", "exec", args.netns]

        flood_cmd = flood_exec + [
            str(kavach_gen), "s1",
            "--target", args.target,
            "--source", "198.18.0.10",
            "--rate", str(r),
            "--duration", str(args.step_duration)
        ]

        res_flood = subprocess.run(flood_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p_legit.wait()

        # Evaluate metrics
        tot, ans, success, p50, p95 = compute_legit_metrics(step_csv)
        status_label = "OK" if success >= args.threshold else "SATURATED"

        calib_history.append({
            "rate_pps": r, "sent": tot, "answered": ans,
            "success_pct": success, "p50_ms": p50, "p95_ms": p95, "status": status_label
        })

        color = "\033[1;32m" if status_label == "OK" else "\033[1;31m"
        print(f"{r:<18} | {tot:<8} | {ans:<8} | {color}{success:<9.2f}%\033[0m | {p50:<10.2f} | {p95:<10.2f} | {color}{status_label}\033[0m")

        if success < args.threshold:
            S_detected = r
            print(f"\n\033[1;33m[THRESHOLD DETECTED] Legitimate success dropped to {success:.2f}% (< {args.threshold}%) at {r} pps!\033[0m")
            break

        time.sleep(1.0)  # Brief cooldown between steps

    if S_detected is None:
        print(f"\n[WARN] Server did not saturate at maximum tested rate ({rates[-1]} pps).")
        print(f"Assigning S = {rates[-1]} pps.")
        S_detected = rates[-1]

    # Save calibration run record
    calib_record = {
        "timestamp": time.time(),
        "target": args.target,
        "S_pps": S_detected,
        "threshold_pct": args.threshold,
        "history": calib_history
    }
    with open(calib_dir / "calibration_summary.json", "w") as f:
        json.dump(calib_record, f, indent=2)

    # 5. Calculate Derived Parameters
    level_05 = int(S_detected * 0.5)
    level_10 = int(S_detected * 1.0)
    level_20 = int(S_detected * 2.0)
    src_rate = int(args.legit_qps * 5)
    glob_rate = int(round(S_detected * 0.70))
    burst = args.burst

    print("\n" + "=" * 75)
    print("STEP 3: EMPIRICAL CALIBRATION PROFILE DETERMINED")
    print("=" * 75)
    print(f"  * Baseline Saturation Point S : {S_detected:,} pps")
    print(f"  * Flood Level 0.5x S          : {level_05:,} pps")
    print(f"  * Flood Level 1.0x S          : {level_10:,} pps")
    print(f"  * Flood Level 2.0x S          : {level_20:,} pps")
    print(f"  * Per-Source Rate Limit       : {src_rate:,} pps (5x legitimate QPS)")
    print(f"  * Per-Source Burst Tolerance  : {burst} packets")
    print(f"  * Global Rate Limit           : {glob_rate:,} pps (~70% of S)")
    print(f"  * Global Burst Tolerance      : {burst} packets (Common Burst)")
    print("=" * 75)

    # 6. Generator Ceiling Capacity Check
    print("\n" + "-" * 75)
    print(f"STEP 4: Traffic Generator Capacity Verification (Target: >= 2x S = {level_20:,} pps)")
    print("-" * 75)

    ceiling_cmd = flood_exec + [
        str(kavach_gen), "ceiling",
        "--target", args.target,
        "--duration", "5.0"
    ]
    res_ceil = subprocess.run(ceiling_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    ceil_pps = 0
    for line in res_ceil.stdout.splitlines():
        if "rate:" in line.lower() or "throughput:" in line.lower() or "pps" in line.lower():
            parts = line.split()
            for i, p in enumerate(parts):
                if p.lower() in ["pps", "pkts/sec", "packets/sec"] and i > 0:
                    try:
                        ceil_pps = int(float(parts[i - 1].replace(",", "")))
                    except ValueError:
                        pass
        print("  " + line)

    if ceil_pps > 0:
        headroom = ceil_pps / level_20 if level_20 > 0 else 1.0
        if ceil_pps >= level_20:
            print(f"\n\033[1;32m[PASS] Generator Capacity Confirmed: {ceil_pps:,} pps >= 2x S ({level_20:,} pps). Headroom: {headroom:.1f}x.\033[0m")
        else:
            print(f"\n\033[1;31m[WARNING] Generator ceiling ({ceil_pps:,} pps) is LOWER than 2x S ({level_20:,} pps)!\033[0m")
            print("Consider adjusting S downwards or tuning the generator host.")

    # 7. Update Configuration Files
    if not args.no_update:
        print("\n" + "-" * 75)
        print("STEP 5: Updating Configuration Files (params.yaml & params.json)...")
        print("-" * 75)
        update_parameter_files(S_detected, burst, args.legit_qps)

    print("\n" + "=" * 75)
    print(" PHASE B3 CALIBRATION COMPLETED SUCCESSFULLY")
    print(f" Results archived in: {calib_dir}/calibration_summary.json")
    print(" Next Step: Run Smoke Tests (B0, B1, B2, X)")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()

