#!/usr/bin/env python3
"""
Kavach PS-022: Smoke Test Runner (Phase B3)
Submission ID: A3-PS022-TC367

Executes 1 smoke test run per configuration (B0, B1, B2, X) under Scenario S1
at level 1.0x S to validate the end-to-end benchmark harness before Phase B4.

Supports dual operating modes:
  1. Automated Mode: Communicates with target_daemon.py on PC 1 (10.99.0.2:9999).
  2. Manual Twin-Console Mode: Prompts operator to trigger PC 1 via run_smoke_target.sh.
"""

import os
import sys
import time
import json
import socket
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src"
TRAFFIC_DIR = SRC_DIR / "traffic"
SCRIPTS_DIR = SRC_DIR / "scripts"
RESULTS_RAW_DIR = REPO_ROOT / "results" / "raw"
PARAMS_YAML = SRC_DIR / "params.yaml"

# Enforce Generator Safety Guard
sys.path.insert(0, str(TRAFFIC_DIR))
try:
    from guard import enforce_all, SecurityViolation
except ImportError:
    print("[ERROR] Cannot import guard module from src/traffic!", file=sys.stderr)
    sys.exit(101)


def parse_args():
    parser = argparse.ArgumentParser(description="Kavach Phase B3 Smoke Test Runner")
    parser.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    parser.add_argument("--source", default="10.99.0.1", help="Legitimate client IP (default: 10.99.0.1)")
    parser.add_argument("--daemon-port", type=int, default=9999, help="Target daemon port (default: 9999)")
    parser.add_argument("--configs", default="B0,B1,B2,X", help="Comma-separated configs (default: B0,B1,B2,X)")
    parser.add_argument("--scenario", default="S1", help="Flood scenario (default: S1)")
    parser.add_argument("--level", type=float, default=1.0, help="Flood level multiplier (default: 1.0)")
    parser.add_argument("--warmup", type=int, default=2, help="Warmup duration in seconds (default: 2)")
    parser.add_argument("--window", type=int, default=10, help="Measurement window in seconds (default: 10)")
    parser.add_argument("--cooldown", type=int, default=2, help="Cooldown duration in seconds (default: 2)")
    parser.add_argument("--netns", default="", help="Network namespace (default: host/empty)")
    return parser.parse_args()


def load_params():
    if PARAMS_YAML.is_file():
        try:
            import yaml
            with open(PARAMS_YAML, "r") as f:
                return yaml.safe_load(f)
        except ImportError:
            pass
    json_path = PARAMS_YAML.with_suffix(".json")
    if json_path.is_file():
        with open(json_path, "r") as f:
            return json.load(f)
    return {}


def get_git_commit():
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)
        return res.stdout.strip() if res.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def test_target_daemon(host: str, port: int) -> bool:
    """Checks whether target_daemon.py is listening on PC 1."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((host, port))
        s.sendall(json.dumps({"cmd": "ping"}).encode("utf-8"))
        data = s.recv(1024).decode("utf-8")
        s.close()
        resp = json.loads(data)
        return resp.get("status") == "ok"
    except Exception:
        return False


def send_daemon_cmd(host: str, port: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sends JSON command to target daemon on PC 1 and returns response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15.0)
    s.connect((host, port))
    s.sendall(json.dumps(payload).encode("utf-8"))
    data = s.recv(4096).decode("utf-8")
    s.close()
    return json.loads(data)


def parse_legit_csv(csv_path: Path) -> Tuple[int, int, float, float]:
    """Parses legitimate CSV and returns (sent, answered, success_rate, p50_ms)."""
    if not csv_path.is_file():
        return 0, 0, 0.0, 0.0

    total = 0
    answered = 0
    latencies = []

    with open(csv_path, "r") as f:
        lines = f.readlines()

    header = True
    for line in lines:
        line = line.strip()
        if not line or header:
            header = False
            continue
        parts = line.split(",")
        if len(parts) >= 7:
            total += 1
            status = parts[6].strip().upper()
            rcode = parts[5].strip().upper()
            if status in ["SUCCESS", "ANSWERED"] or rcode in ["0", "NOERROR"]:
                answered += 1
                try:
                    latencies.append(float(parts[4]))
                except ValueError:
                    pass

    rate = (answered / total * 100.0) if total > 0 else 0.0
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.5)] if latencies else 0.0
    return total, answered, rate, p50


def main():
    args = parse_args()

    print("=" * 75)
    print(" KAVACH PS-022: PHASE B3 SMOKE TEST HARNESS")
    print("=" * 75)
    print(f"Target Server   : {args.target}:53")
    print(f"Legitimate IP   : {args.source}")
    print(f"Configs to Test : {args.configs}")
    print(f"Timings         : Warmup={args.warmup}s, Window={args.window}s, Cooldown={args.cooldown}s (Total: {args.warmup + args.window + args.cooldown}s)")

    # 1. Enforce Generator Guard
    enforce_all(target_ip=args.target, source_ip=args.source)
    print("[Guard] Pre-execution safety guard assertions PASSED.")

    # 2. Check for traffic generator binary
    kavach_gen = TRAFFIC_DIR / "kavach_gen"
    if not kavach_gen.is_file():
        print("[Build] Compiling traffic generator binary (kavach_gen)...")
        subprocess.run(["make", "-C", str(TRAFFIC_DIR)], check=True)

    # 3. Read parameters
    params = load_params()
    S_pps = params.get("calibration", {}).get("S_pps", 10000)
    limits = params.get("filter_limits", {})
    src_rate = limits.get("src_rate", 500)
    src_burst = limits.get("src_burst", 20)
    glob_rate = limits.get("glob_rate", 7000)
    glob_burst = limits.get("glob_burst", 20)
    flood_rate = int(S_pps * args.level)

    print(f"[Params] S_pps={S_pps:,} | Flood Rate={flood_rate:,} pps | SrcLimit={src_rate:,} | GlobLimit={glob_rate:,}")

    # 4. Detect Target Daemon Mode
    has_daemon = test_target_daemon(args.target, args.daemon_port)
    if has_daemon:
        print(f"\033[1;32m[Mode] Target Daemon detected on {args.target}:{args.daemon_port}. Running FULLY AUTOMATED!\033[0m\n")
    else:
        print(f"\033[1;33m[Mode] Target Daemon NOT detected on {args.target}:{args.daemon_port}.\033[0m")
        print("Operating in Twin-Console Manual Mode. You will be prompted before each run.\n")

    configs = [c.strip().upper() for c in args.configs.split(",") if c.strip()]
    total_duration = args.warmup + args.window + args.cooldown
    legit_duration = args.warmup + args.window
    RESULTS_RAW_DIR.mkdir(parents=True, exist_ok=True)

    smoke_results = []
    git_commit = get_git_commit()

    for idx, c in enumerate(configs):
        run_name = f"smoke_{args.scenario}_{c}_{args.level}x_1"
        run_dir = RESULTS_RAW_DIR / run_name
        run_dir.mkdir(parents=True, exist_ok=True)

        print("-" * 75)
        print(f">>> [{idx + 1}/{len(configs)}] RUNNING SMOKE TEST: {c} ({run_name})")
        print("-" * 75)

        xdp_mode = "none"

        # Step A: Target Preparation
        if has_daemon:
            print(f"  [PC 1 Sync] Commanding PC 1 target daemon to prepare '{c}'...")
            prep_payload = {
                "cmd": "prepare",
                "config": c,
                "duration": total_duration,
                "run_dir": str(run_dir),
                "src_rate": src_rate,
                "src_burst": src_burst,
                "glob_rate": glob_rate,
                "glob_burst": glob_burst
            }
            resp = send_daemon_cmd(args.target, args.daemon_port, prep_payload)
            if resp.get("status") != "ready":
                print(f"\033[1;31m[ERROR] PC 1 failed to prepare config '{c}': {resp}\033[0m")
                sys.exit(1)
            xdp_mode = resp.get("xdp_mode", "none")
            print(f"  [PC 1 Sync] PC 1 is ready! (XDP Mode: {xdp_mode})")
        else:
            print(f"\033[1;33m>>> ACTION REQUIRED ON PC 1 (Target Console): <<<\033[0m")
            print(f"    sudo ./src/scripts/run_smoke_target.sh --config {c} --duration {total_duration}")
            input("Press [Enter] here once the command is executing on PC 1...")
            xdp_mode = "native" if c == "X" else "none"

        legit_csv = run_dir / "legit_client.csv"
        legit_exec = ["sudo"]
        if args.netns:
            legit_exec += ["ip", "netns", "exec", args.netns]

        # Step B: Launch Legitimate Client
        print(f"  [Warmup] Starting legitimate client (100 QPS) for {args.warmup}s...")
        p_legit = subprocess.Popen(legit_exec + [
            "python3", str(TRAFFIC_DIR / "legit_client.py"),
            "--server", args.target,
            "--source-ip", args.source,
            "--qps", "100.0",
            "--duration", str(legit_duration),
            "--output", str(legit_csv)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(args.warmup)

        # Step C: Launch Flood Traffic (Scenario S1)
        print(f"  [Window] Injecting Scenario S1 flood at {flood_rate:,} pps for {args.window}s...")
        flood_exec = ["sudo"]
        if args.netns:
            flood_exec += ["ip", "netns", "exec", args.netns]

        flood_cmd = flood_exec + [
            str(kavach_gen), "s1",
            "--target", args.target,
            "--source", "198.18.0.10",
            "--rate", str(flood_rate),
            "--duration", str(args.window)
        ]
        subprocess.run(flood_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        # Step D: Cooldown
        print(f"  [Cooldown] Cooling down for {args.cooldown}s...")
        p_legit.wait()
        time.sleep(args.cooldown)

        if has_daemon:
            send_daemon_cmd(args.target, args.daemon_port, {"cmd": "stop"})

        # Step E: Parse and Save Metadata
        sent, answered, success_rate, p50_ms = parse_legit_csv(legit_csv)

        meta = {
            "run_name": run_name,
            "scenario": args.scenario,
            "config": c,
            "xdp_mode": xdp_mode,
            "level": args.level,
            "timestamp": time.time(),
            "git_commit": git_commit,
            "parameters": {
                "S_pps": S_pps,
                "flood_rate": flood_rate,
                "src_rate": src_rate,
                "src_burst": src_burst,
                "glob_rate": glob_rate,
                "glob_burst": glob_burst,
                "warmup_s": args.warmup,
                "window_s": args.window,
                "cooldown_s": args.cooldown
            }
        }
        with open(run_dir / "run_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        smoke_results.append({
            "config": c,
            "mode": xdp_mode,
            "sent": sent,
            "answered": answered,
            "success_pct": success_rate,
            "p50_ms": p50_ms
        })

        color = "\033[1;32m" if success_rate >= 95.0 else ("\033[1;33m" if success_rate >= 50.0 else "\033[1;31m")
        print(f"\033[1m  [Result] Config {c:<2} ({xdp_mode:<7}) | Sent: {sent} | Answered: {answered} | Success: {color}{success_rate:.1f}%\033[0m | p50: {p50_ms:.2f}ms")
        time.sleep(1.0)

    # 5. Final Summary Table
    print("\n" + "=" * 75)
    print(" PHASE B3 SMOKE TEST RESULTS SUMMARY")
    print("=" * 75)
    print(f"{'Config':<8} | {'XDP Mode':<10} | {'Sent':<8} | {'Answered':<10} | {'Success Rate':<14} | {'p50 Latency'}")
    print("-" * 75)
    for r in smoke_results:
        color = "\033[1;32m" if r["success_pct"] >= 95.0 else ("\033[1;33m" if r["success_pct"] >= 50.0 else "\033[1;31m")
        print(f"{r['config']:<8} | {r['mode']:<10} | {r['sent']:<8} | {r['answered']:<10} | {color}{r['success_pct']:<13.1f}%\033[0m | {r['p50_ms']:.2f} ms")
    print("=" * 75)

    # 6. Run Telemetry Analysis Engine
    print("\n[Analysis] Invoking analyze.py to verify data processing pipeline...")
    analyze_script = SCRIPTS_DIR / "analyze.py"
    if analyze_script.is_file():
        subprocess.run(["python3", str(analyze_script)], check=False)

    print("\n\033[1;32m[SUCCESS] Phase B3 smoke tests completed successfully!\033[0m")
    print(f"Artifacts saved in: {RESULTS_RAW_DIR}/smoke_*\n")


if __name__ == "__main__":
    main()

