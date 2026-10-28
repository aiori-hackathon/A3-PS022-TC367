#!/usr/bin/env python3
"""
Kavach PS-022: Unified Flood Traffic Generation CLI
Submission ID: A3-PS022-TC367

Wraps the high-performance C packet generator (kavach_gen) with safety guard
assertions, parameter validation, and process monitoring.
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

# Enforce safety guard assertions
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
try:
    from guard import enforce_all, SecurityViolation
except ImportError:
    print("[ERROR] Cannot import guard.py from traffic directory!", file=sys.stderr)
    sys.exit(101)

BIN_PATH = SCRIPT_DIR / "kavach_gen"


def ensure_binary():
    """Ensure kavach_gen binary is compiled."""
    if not BIN_PATH.is_file():
        print(f"[INFO] Compiling {BIN_PATH} via make...")
        res = subprocess.run(["make", "-C", str(SCRIPT_DIR)], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[ERROR] Failed to compile kavach_gen:\n{res.stderr}", file=sys.stderr)
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Kavach Unified DNS Flood Traffic CLI")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Flood scenario mode")

    # Mode: ceiling
    p_ceil = subparsers.add_parser("ceiling", help="Measure generator host maximum TX PPS")
    p_ceil.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    p_ceil.add_argument("--port", type=int, default=53, help="Target port (default: 53)")
    p_ceil.add_argument("--duration", type=float, default=5.0, help="Duration in seconds (default: 5.0)")

    # Mode: s1
    p_s1 = subparsers.add_parser("s1", help="Scenario S1: Single source constant-rate flood")
    p_s1.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    p_s1.add_argument("--port", type=int, default=53, help="Target port (default: 53)")
    p_s1.add_argument("--source", default="198.18.0.10", help="Source IP (default: 198.18.0.10)")
    p_s1.add_argument("--rate", type=int, default=10000, help="Rate in PPS (default: 10000)")
    p_s1.add_argument("--duration", type=float, default=60.0, help="Duration in seconds (default: 60.0)")

    # Mode: s2
    p_s2 = subparsers.add_parser("s2", help="Scenario S2: Distributed flood from 198.18.0.0/15")
    p_s2.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    p_s2.add_argument("--port", type=int, default=53, help="Target port (default: 53)")
    p_s2.add_argument("--sources", type=int, default=1000, help="Number of random sources (default: 1000)")
    p_s2.add_argument("--rate", type=int, default=10000, help="Aggregate rate in PPS (default: 10000)")
    p_s2.add_argument("--duration", type=float, default=60.0, help="Duration in seconds (default: 60.0)")

    # Mode: s3
    p_s3 = subparsers.add_parser("s3", help="Scenario S3: Pulsing burst flood")
    p_s3.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    p_s3.add_argument("--port", type=int, default=53, help="Target port (default: 53)")
    p_s3.add_argument("--source", default="198.18.0.10", help="Source IP (default: 198.18.0.10)")
    p_s3.add_argument("--burst", type=int, default=20, help="Base burst size in packets (default: 20)")
    p_s3.add_argument("--multiplier", type=float, default=1.0, help="Burst multiplier: 0.5, 1.0, or 2.0 (default: 1.0)")
    p_s3.add_argument("--period", type=float, default=5.0, help="Pulse period in seconds (default: 5.0)")
    p_s3.add_argument("--duration", type=float, default=60.0, help="Duration in seconds (default: 60.0)")

    args = parser.parse_args()

    # Pre-execution safety guard validation
    src_to_check = getattr(args, "source", None)
    if args.mode == "s2":
        src_to_check = "198.18.0.1"  # Check that benchmark prefix is valid
    try:
        enforce_all(target_ip=args.target, source_ip=src_to_check)
    except SecurityViolation as sv:
        print(f"\033[1;31m{sv}\033[0m", file=sys.stderr)
        sys.exit(100)

    ensure_binary()

    cmd = [str(BIN_PATH), args.mode, "--target", args.target, "--port", str(args.port), "--duration", str(args.duration)]
    if args.mode == "s1":
        cmd.extend(["--source", args.source, "--rate", str(args.rate)])
    elif args.mode == "s2":
        cmd.extend(["--sources", str(args.sources), "--rate", str(args.rate)])
    elif args.mode == "s3":
        cmd.extend(["--source", args.source, "--burst", str(args.burst), "--multiplier", str(args.multiplier), "--period", str(args.period)])

    res = subprocess.run(cmd)
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()

