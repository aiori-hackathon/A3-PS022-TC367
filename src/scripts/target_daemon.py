#!/usr/bin/env python3
"""
Kavach PS-022: Target Server Synchronization Daemon (Phase B3 / B4)
Submission ID: A3-PS022-TC367

Runs on PC 1 (Target / Server / DUT) to automate state reset, configuration
switching (B0, B1, B2, X), and synchronous telemetry collection over the
isolated lab link (10.99.0.0/24) without requiring SSH.

Usage on PC 1:
    sudo python3 target_daemon.py [--iface eno1] [--port 9999] [--host 10.99.0.2]
"""

import os
import sys
import time
import json
import socket
import argparse
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src"
BASELINES_DIR = SRC_DIR / "baselines"
SCRIPTS_DIR = SRC_DIR / "scripts"
DNS_DIR = SRC_DIR / "dns"
XDP_DIR = REPO_ROOT / "xdp"
RESULTS_RAW_DIR = REPO_ROOT / "results" / "raw"
PARAMS_YAML = SRC_DIR / "params.yaml"

collector_proc = None
current_run_dir = None


def parse_args():
    parser = argparse.ArgumentParser(description="Kavach Target Server Daemon")
    parser.add_argument("--host", default="10.99.0.2", help="Bind IP address (default: 10.99.0.2)")
    parser.add_argument("--port", type=int, default=9999, help="Listen TCP port (default: 9999)")
    parser.add_argument("--iface", default="eno1", help="Test network interface (default: eno1)")
    parser.add_argument("--core", type=int, default=1, help="Pinned CPU core (default: 1)")
    return parser.parse_args()


def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        err = res.stderr.strip() if res.stderr else res.stdout.strip()
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd)}\n{err}")
    return res


def reset_target_state(iface: str):
    """Cleanly detaches XDP, flushes nftables, restarts DNS server pinned to Core 1."""
    global collector_proc
    if collector_proc and collector_proc.poll() is None:
        try:
            collector_proc.terminate()
            collector_proc.wait(timeout=2.0)
        except Exception:
            pass
        collector_proc = None

    print("  [Reset] Detaching filters and resetting host state...")
    # 1. Detach XDP
    run_cmd(["ip", "link", "set", "dev", iface, "xdpgeneric", "off"], check=False)
    run_cmd(["ip", "link", "set", "dev", iface, "xdp", "off"], check=False)
    run_cmd(["python3", str(XDP_DIR / "kavach_ctl.py"), "detach", "--iface", iface], check=False)
    run_cmd(["python3", str(XDP_DIR / "kavach_ctl.py"), "unload"], check=False)
    run_cmd(["rm", "-rf", "/sys/fs/bpf/kavach"], check=False)
    run_cmd(["rm", "-f", "/run/kavach/state.json"], check=False)

    # 2. Flush nftables
    run_cmd(["nft", "flush", "ruleset"], check=False)

    # 3. Flush neighbor cache
    run_cmd(["ip", "neigh", "flush", "all"], check=False)

    # 4. Restart DNS daemon on Core 1
    run_cmd([str(DNS_DIR / "start_dns.sh"), "--host", "--iface", iface], check=True)
    time.sleep(0.5)


def apply_target_config(config: str, iface: str, src_rate: int, src_burst: int, glob_rate: int, glob_burst: int) -> str:
    """Applies target filter configuration; returns active XDP mode if applicable."""
    print(f"  [Config] Applying Configuration '{config}' (iface: {iface})...")
    mode = "none"

    if config == "B0":
        run_cmd([str(BASELINES_DIR / "none.sh"), "--iface", iface, "--netns", ""])
        mode = "none"
    elif config == "B1":
        run_cmd([
            str(BASELINES_DIR / "b1_prerouting.sh"),
            "--iface", iface, "--netns", "",
            "--src-rate", str(src_rate), "--src-burst", str(src_burst),
            "--glob-rate", str(glob_rate), "--glob-burst", str(glob_burst)
        ])
        mode = "none"
    elif config == "B2":
        run_cmd([
            str(BASELINES_DIR / "b2_netdev.sh"),
            "--iface", iface, "--netns", "",
            "--src-rate", str(src_rate), "--src-burst", str(src_burst),
            "--glob-rate", str(glob_rate), "--glob-burst", str(glob_burst)
        ])
        mode = "none"
    elif config == "X":
        # Load and config
        run_cmd(["python3", str(XDP_DIR / "kavach_ctl.py"), "load"])
        run_cmd([
            "python3", str(XDP_DIR / "kavach_ctl.py"), "config",
            "--src-rate", str(src_rate), "--src-burst", str(src_burst),
            "--glob-rate", str(glob_rate), "--glob-burst", str(glob_burst)
        ])
        # Attempt native attach first, fall back to generic
        print("  [XDP] Attempting native driver attach (xdpdrv)...")
        res_native = run_cmd(["python3", str(XDP_DIR / "kavach_ctl.py"), "attach", "native", "--iface", iface, "--watchdog-minutes", "5"], check=False)
        if res_native.returncode == 0:
            mode = "native"
            print("\033[1;32m  [XDP SUCCESS] Native mode (xdpdrv) attached successfully!\033[0m")
        else:
            print(f"\033[1;33m  [XDP WARN] Native attach failed ({res_native.stderr.strip()}). Falling back to generic mode...\033[0m")
            run_cmd(["python3", str(XDP_DIR / "kavach_ctl.py"), "attach", "generic", "--iface", iface, "--watchdog-minutes", "5"], check=True)
            mode = "generic"
            print("\033[1;32m  [XDP SUCCESS] Generic mode (xdpgeneric) attached successfully!\033[0m")
    else:
        raise ValueError(f"Unknown config: {config}")

    return mode


def handle_client(conn, addr, args):
    global collector_proc, current_run_dir
    try:
        chunks = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            try:
                raw_text = b"".join(chunks).decode("utf-8").strip()
                if raw_text:
                    json.loads(raw_text)
                    break
            except ValueError:
                pass

        raw_text = b"".join(chunks).decode("utf-8").strip()
        if not raw_text:
            return
        msg = json.loads(raw_text)
        cmd = msg.get("cmd")

        if cmd == "ping":
            resp = {"status": "ok", "host": socket.gethostname()}
            conn.sendall(json.dumps(resp).encode("utf-8"))

        elif cmd == "prepare":
            config = msg.get("config", "B0")
            duration = msg.get("duration", 80)
            run_name = Path(msg.get("run_dir", f"kavach_run_{int(time.time())}")).name
            run_dir = RESULTS_RAW_DIR / run_name
            run_dir.mkdir(parents=True, exist_ok=True)
            current_run_dir = run_dir

            src_rate = msg.get("src_rate", 500)
            src_burst = msg.get("src_burst", 20)
            glob_rate = msg.get("glob_rate", 70000)
            glob_burst = msg.get("glob_burst", 20)

            print(f"\n>>> Received Prepare Command: Config={config}, Duration={duration}s, RunDir={run_dir.name}")
            reset_target_state(args.iface)
            mode = apply_target_config(config, args.iface, src_rate, src_burst, glob_rate, glob_burst)

            # Launch metrics collector
            collect_cmd = [
                "python3", str(SCRIPTS_DIR / "collect_metrics.py"),
                "-d", str(duration),
                "-o", str(run_dir),
                "-i", args.iface,
                "-c", str(args.core),
                "--interval", "1.0"
            ]
            print(f"  [Collector] Launching telemetry collector for {duration}s...")
            collector_proc = subprocess.Popen(collect_cmd)

            resp = {"status": "ready", "xdp_mode": mode}
            conn.sendall(json.dumps(resp).encode("utf-8"))

        elif cmd == "stop":
            print("  [Stop] Finalizing run and stopping collector...")
            if collector_proc and collector_proc.poll() is None:
                try:
                    collector_proc.wait(timeout=10.0)
                except subprocess.TimeoutExpired:
                    collector_proc.terminate()
                    collector_proc.wait(timeout=2.0)
            collector_proc = None

            # Harvest metrics summary and telemetry files for PC 2
            summary_data = {}
            telemetry_files = {}
            if current_run_dir and current_run_dir.is_dir():
                summary_file = current_run_dir / "metrics_summary.json"
                if summary_file.is_file():
                    try:
                        with open(summary_file, "r", encoding="utf-8") as f:
                            summary_data = json.load(f)
                    except Exception as e:
                        print(f"  [WARN] Failed to read metrics_summary.json: {e}", file=sys.stderr)

                for fname in ["cpu_util.csv", "throughput_pps.csv", "bpf_stats.csv"]:
                    fpath = current_run_dir / fname
                    if fpath.is_file():
                        try:
                            telemetry_files[fname] = fpath.read_text(encoding="utf-8")
                        except Exception as e:
                            print(f"  [WARN] Failed to read {fname}: {e}", file=sys.stderr)

            resp = {
                "status": "done",
                "metrics_summary": summary_data,
                "telemetry_files": telemetry_files
            }
            conn.sendall(json.dumps(resp).encode("utf-8"))

        else:
            conn.sendall(json.dumps({"status": "error", "message": f"Unknown command: {cmd}"}).encode("utf-8"))

    except Exception as e:
        print(f"\033[1;31m[ERROR] Exception handling client {addr}: {e}\033[0m", file=sys.stderr)
        try:
            conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))
        except Exception:
            pass
    finally:
        conn.close()


def main():
    args = parse_args()
    if os.geteuid() != 0:
        print("[ERROR] target_daemon.py requires root privileges: sudo python3 target_daemon.py", file=sys.stderr)
        sys.exit(1)

    print("=" * 70)
    print(" KAVACH TARGET SERVER SYNCHRONIZATION DAEMON (PC 1)")
    print("=" * 70)
    print(f"Binding on      : {args.host}:{args.port}")
    print(f"Test Interface  : {args.iface}")
    print(f"Core Affinity   : Core {args.core}")
    print("Listening for experiment runner commands from PC 2...\n")

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind((args.host, args.port))
    srv_sock.listen(5)

    print("\033[1;32m[READY] Daemon active. You can now launch experiments from PC 2.\033[0m\n")

    try:
        while True:
            conn, addr = srv_sock.accept()
            handle_client(conn, addr, args)
    except KeyboardInterrupt:
        print("\n[Shutdown] Stopping target daemon...")
    finally:
        srv_sock.close()


if __name__ == "__main__":
    main()

