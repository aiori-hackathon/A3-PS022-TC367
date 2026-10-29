#!/usr/bin/env python3
"""
Kavach PS-022: Experiment Orchestrator (v1)
Submission ID: A3-PS022-TC367

Coordinates multi-configuration, multi-scenario benchmarking:
  - Reads configuration from src/params.yaml (or params.json)
  - Executes runs in a seeded pseudo-random order to prevent systematic bias
  - Enforces the strict run lifecycle:
      [Reset State] -> [Apply Config] -> [Warmup] -> [Measurement Window] -> [Cooldown] -> [Save]
  - Isolates raw telemetry into results/raw/<scenario>_<config>_<level>_<rep>/
  - Automatically triggers analyze.py upon completion to generate plots
"""

import os
import sys
import time
import json
import socket
import random
import signal
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src"
TRAFFIC_DIR = SRC_DIR / "traffic"
BASELINES_DIR = SRC_DIR / "baselines"
SCRIPTS_DIR = SRC_DIR / "scripts"
DNS_DIR = SRC_DIR / "dns"
XDP_DIR = REPO_ROOT / "xdp"
RESULTS_RAW_DIR = REPO_ROOT / "results" / "raw"

# Guard check
sys.path.insert(0, str(TRAFFIC_DIR))
try:
    from guard import enforce_all
except ImportError:
    pass


def run_cmd(cmd: List[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Execute command with optional check."""
    res = subprocess.run(cmd, stdout=subprocess.PIPE if capture else None,
                         stderr=subprocess.PIPE if capture else None, text=True)
    if check and res.returncode != 0:
        err = res.stderr.strip() if res.stderr else res.stdout.strip()
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd)}\n{err}")
    return res


def test_target_daemon(host: str, port: int) -> bool:
    """Checks whether target_daemon.py is listening on the target host."""
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
    """Sends JSON command to target daemon on target host and returns response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20.0)
    s.connect((host, port))
    s.sendall(json.dumps(payload).encode("utf-8"))
    data = s.recv(4096).decode("utf-8")
    s.close()
    return json.loads(data)


def load_params(params_path: Path) -> Dict[str, Any]:
    """Loads benchmark parameters from YAML or JSON."""
    if not params_path.is_file():
        raise FileNotFoundError(f"Parameters file not found: {params_path}")

    if params_path.suffix in [".yaml", ".yml"]:
        try:
            import yaml
            with open(params_path, "r") as f:
                return yaml.safe_load(f)
        except ImportError:
            json_fallback = params_path.with_suffix(".json")
            if json_fallback.is_file():
                with open(json_fallback, "r") as f:
                    return json.load(f)
            raise RuntimeError("PyYAML not installed and params.json missing!")
    else:
        with open(params_path, "r") as f:
            return json.load(f)


def get_git_commit() -> str:
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)
        return res.stdout.strip() if res.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def get_xdp_mode(netns: str, iface: str) -> str:
    """Detects active XDP attachment mode (native, generic, or none)."""
    try:
        cmd = ["ip", "-n", netns, "link", "show", "dev", iface] if netns else ["ip", "link", "show", "dev", iface]
        res = subprocess.run(cmd, capture_output=True, text=True)
        out = res.stdout
        if "xdpdrv" in out or "prog/xdp" in out:
            return "native"
        if "xdpgeneric" in out or "prog/xdpgeneric" in out:
            return "generic"
        return "none"
    except Exception:
        return "unknown"


class Orchestrator:
    def __init__(self, params: Dict[str, Any], dry_run: bool = False, seed: int = 42,
                 custom_configs: Optional[List[str]] = None, custom_scenarios: Optional[List[str]] = None,
                 custom_levels: Optional[List[float]] = None, custom_reps: Optional[int] = None,
                 host_mode: bool = False, iface: Optional[str] = None,
                 target_ip: Optional[str] = None, daemon_port: int = 9999,
                 mode: str = "auto", pause_between: bool = False,
                 resume: bool = True, batch_size: int = 0):
        self.params = params
        self.dry_run = dry_run
        self.seed = seed
        self.host_mode = host_mode
        self.pause_between = pause_between
        self.resume = resume
        self.batch_size = batch_size
        self.daemon_port = daemon_port

        self.target_ip = target_ip or params.get("network", {}).get("target_ip", "10.99.0.2")
        self.target_port = params.get("network", {}).get("target_port", 53)

        if host_mode or not Path("/run/netns/srv").exists():
            self.netns_gen = ""
            self.netns_srv = ""
            self.iface_gen = iface or params.get("network", {}).get("iface_gen", "eno1")
            self.iface_srv = iface or params.get("network", {}).get("iface_srv", "eno1")
        else:
            self.netns_gen = params.get("network", {}).get("netns_gen", "gen")
            self.netns_srv = params.get("network", {}).get("netns_srv", "srv")
            self.iface_gen = iface or params.get("network", {}).get("iface_gen", "vgen")
            self.iface_srv = iface or params.get("network", {}).get("iface_srv", "vsrv")

        # Daemon detection
        if mode == "daemon":
            self.use_target_daemon = True
            print(f"\033[1;32m[Orchestrator] Target Daemon mode explicitly enabled for {self.target_ip}:{self.daemon_port}.\033[0m")
        elif mode == "local":
            self.use_target_daemon = False
            print("[Orchestrator] Running in local/direct host execution mode.")
        else:
            # Auto-detect
            has_daemon = test_target_daemon(self.target_ip, self.daemon_port)
            if has_daemon:
                self.use_target_daemon = True
                print(f"\033[1;32m[Orchestrator] Target Daemon detected on {self.target_ip}:{self.daemon_port}. Automated remote control ACTIVE!\033[0m")
            else:
                self.use_target_daemon = False
                print(f"[Orchestrator] Target Daemon not detected on {self.target_ip}:{self.daemon_port}. Running in local mode.")

        # Durations
        if dry_run:
            timings = params.get("timings", {}).get("dry_run", {})
            self.warmup_s = timings.get("warmup_s", 2)
            self.window_s = timings.get("window_s", 5)
            self.cooldown_s = timings.get("cooldown_s", 2)
        else:
            timings = params.get("timings", {})
            self.warmup_s = timings.get("warmup_s", 10)
            self.window_s = timings.get("window_s", 60)
            self.cooldown_s = timings.get("cooldown_s", 10)

        # Limits & Rates
        self.limits = params.get("filter_limits", {})
        self.src_rate = self.limits.get("src_rate", 500)
        self.src_burst = self.limits.get("src_burst", 20)
        self.glob_rate = self.limits.get("glob_rate", 70000)
        self.glob_burst = self.limits.get("glob_burst", 20)

        self.calibration = params.get("calibration", {})
        self.S_pps = self.calibration.get("S_pps", 100000)
        self.levels = custom_levels or (self.calibration.get("levels", [0.5, 1.0, 2.0]) if not dry_run else [1.0])

        # Configs and Scenarios
        orch_cfg = params.get("orchestrator", {})
        self.configs = custom_configs or orch_cfg.get("configs", ["B0", "B1", "B2", "X"])
        self.scenarios = custom_scenarios or orch_cfg.get("scenarios", ["S1", "S2", "S3"])
        self.reps = custom_reps or (1 if dry_run else orch_cfg.get("repetitions", 3))

        RESULTS_RAW_DIR.mkdir(parents=True, exist_ok=True)

    def reset_state(self):
        """Clean teardown of filters, caches, and daemons between runs."""
        print("  [Reset] Flushing filters, detaching XDP, clearing state...")
        if self.use_target_daemon:
            try:
                send_daemon_cmd(self.target_ip, self.daemon_port, {"cmd": "prepare", "config": "B0", "duration": 1})
                send_daemon_cmd(self.target_ip, self.daemon_port, {"cmd": "stop"})
            except Exception as e:
                print(f"  [Reset WARN] Remote daemon reset notice: {e}")
            time.sleep(0.5)
            return

        ns_srv_arg = f"--net=/run/netns/{self.netns_srv}" if (self.netns_srv and Path(f"/run/netns/{self.netns_srv}").exists()) else None
        ctl_prefix = ["sudo", "nsenter", ns_srv_arg] if ns_srv_arg else ["sudo"]

        if self.netns_srv:
            # 1. Unconditional driver/generic XDP detach via iproute2
            run_cmd(["sudo", "ip", "netns", "exec", self.netns_srv, "ip", "link", "set", "dev", self.iface_srv, "xdpgeneric", "off"], check=False)
            run_cmd(["sudo", "ip", "netns", "exec", self.netns_srv, "ip", "link", "set", "dev", self.iface_srv, "xdp", "off"], check=False)

            # 2. Controller cleanup
            run_cmd(ctl_prefix + ["python3", str(XDP_DIR / "kavach_ctl.py"), "detach", "--iface", self.iface_srv], check=False)
            run_cmd(ctl_prefix + ["python3", str(XDP_DIR / "kavach_ctl.py"), "unload"], check=False)
            run_cmd(["sudo", "rm", "-rf", "/sys/fs/bpf/kavach"], check=False)
            run_cmd(["sudo", "rm", "-f", "/run/kavach/state.json"], check=False)

            # 3. Flush nftables in srv namespace
            run_cmd(["sudo", "ip", "netns", "exec", self.netns_srv, "nft", "flush", "ruleset"], check=False)

            # 4. Flush neighbor cache and conntrack
            run_cmd(["sudo", "ip", "netns", "exec", self.netns_srv, "ip", "neigh", "flush", "all"], check=False)
            if self.netns_gen:
                run_cmd(["sudo", "ip", "netns", "exec", self.netns_gen, "ip", "neigh", "flush", "all"], check=False)

            # 5. Restart DNS server in srv namespace (Core 1, RRL off)
            run_cmd(["sudo", str(DNS_DIR / "start_dns.sh"), "--netns", self.netns_srv, "--iface", self.iface_srv], check=False)
        else:
            # Host Mode
            run_cmd(["sudo", "ip", "link", "set", "dev", self.iface_srv, "xdpgeneric", "off"], check=False)
            run_cmd(["sudo", "ip", "link", "set", "dev", self.iface_srv, "xdp", "off"], check=False)

            run_cmd(["sudo", "python3", str(XDP_DIR / "kavach_ctl.py"), "detach", "--iface", self.iface_srv], check=False)
            run_cmd(["sudo", "python3", str(XDP_DIR / "kavach_ctl.py"), "unload"], check=False)
            run_cmd(["sudo", "rm", "-rf", "/sys/fs/bpf/kavach"], check=False)
            run_cmd(["sudo", "rm", "-f", "/run/kavach/state.json"], check=False)

            run_cmd(["sudo", "nft", "flush", "ruleset"], check=False)
            run_cmd(["sudo", "ip", "neigh", "flush", "all"], check=False)

            run_cmd(["sudo", str(DNS_DIR / "start_dns.sh"), "--host", "--iface", self.iface_srv], check=False)

        time.sleep(0.5)

    def apply_config(self, config: str):
        """Applies the target configuration under test."""
        print(f"  [Config] Applying Configuration '{config}'...")
        if config == "B0":
            # No filter
            run_cmd(["sudo", str(BASELINES_DIR / "none.sh"), "--netns", self.netns_srv, "--iface", self.iface_srv])
        elif config == "B1":
            # nftables prerouting raw, no conntrack
            run_cmd([
                "sudo", str(BASELINES_DIR / "b1_prerouting.sh"),
                "--netns", self.netns_srv, "--iface", self.iface_srv,
                "--src-rate", str(self.src_rate), "--src-burst", str(self.src_burst),
                "--glob-rate", str(self.glob_rate), "--glob-burst", str(self.glob_burst)
            ])
        elif config == "B2":
            # nftables netdev ingress
            run_cmd([
                "sudo", str(BASELINES_DIR / "b2_netdev.sh"),
                "--netns", self.netns_srv, "--iface", self.iface_srv,
                "--src-rate", str(self.src_rate), "--src-burst", str(self.src_burst),
                "--glob-rate", str(self.glob_rate), "--glob-burst", str(self.glob_burst)
            ])
        elif config == "X":
            # Kavach XDP program
            ns_srv_arg = f"--net=/run/netns/{self.netns_srv}" if (self.netns_srv and Path(f"/run/netns/{self.netns_srv}").exists()) else None
            ctl_prefix = ["sudo", "nsenter", ns_srv_arg] if ns_srv_arg else ["sudo"]

            run_cmd(ctl_prefix + ["python3", str(XDP_DIR / "kavach_ctl.py"), "load"])
            run_cmd(ctl_prefix + [
                "python3", str(XDP_DIR / "kavach_ctl.py"), "config",
                "--src-rate", str(self.src_rate), "--src-burst", str(self.src_burst),
                "--glob-rate", str(self.glob_rate), "--glob-burst", str(self.glob_burst)
            ])
            # Attempt native driver attach first, fall back to generic
            res_native = run_cmd(ctl_prefix + [
                "python3", str(XDP_DIR / "kavach_ctl.py"), "attach", "native",
                "--iface", self.iface_srv, "--watchdog-minutes", "5"
            ], check=False)
            if res_native.returncode == 0:
                print("  [XDP] Successfully attached native driver mode (xdpdrv).")
            else:
                print(f"  [XDP] Native attach failed; falling back to generic mode (xdpgeneric)...")
                run_cmd(ctl_prefix + [
                    "python3", str(XDP_DIR / "kavach_ctl.py"), "attach", "generic",
                    "--iface", self.iface_srv, "--watchdog-minutes", "5"
                ])
        else:
            raise ValueError(f"Unknown configuration: {config}")

    def execute_run(self, scenario: str, config: str, level: float, rep: int):
        """Executes a single benchmark run."""
        run_name = f"{scenario}_{config}_{level}x_{rep}"
        run_dir = RESULTS_RAW_DIR / run_name
        run_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n{'='*70}")
        print(f">>> STARTING RUN: {run_name} (Warmup: {self.warmup_s}s, Window: {self.window_s}s, Cooldown: {self.cooldown_s}s)")
        print(f"{'='*70}")

        total_collect_duration = self.warmup_s + self.window_s + self.cooldown_s
        legit_duration = self.warmup_s + self.window_s
        flood_rate = int(self.S_pps * level)
        legit_csv = run_dir / "legit_client.csv"

        detected_xdp_mode = "none"
        p_collect = None

        if self.use_target_daemon:
            payload = {
                "cmd": "prepare",
                "config": config,
                "duration": total_collect_duration,
                "run_dir": str(run_dir),
                "src_rate": self.src_rate,
                "src_burst": self.src_burst,
                "glob_rate": self.glob_rate,
                "glob_burst": self.glob_burst
            }
            resp = send_daemon_cmd(self.target_ip, self.daemon_port, payload)
            detected_xdp_mode = resp.get("xdp_mode", "none")
            print(f"  [Daemon] Target prepared successfully (XDP Mode: {detected_xdp_mode}).")
        else:
            self.reset_state()
            self.apply_config(config)
            detected_xdp_mode = get_xdp_mode(self.netns_srv, self.iface_srv)

            # Start Telemetry Collector locally
            collect_prefix = ["sudo", "nsenter", f"--net=/run/netns/{self.netns_srv}"] if self.netns_srv else ["sudo"]
            collect_cmd = collect_prefix + [
                "python3", str(SCRIPTS_DIR / "collect_metrics.py"),
                "-d", str(total_collect_duration),
                "-o", str(run_dir),
                "-i", self.iface_srv,
                "-c", "1",
                "--interval", "1.0"
            ]
            p_collect = subprocess.Popen(collect_cmd)

        # 2. Start Legitimate Client (100 QPS)
        gen_prefix = ["sudo", "ip", "netns", "exec", self.netns_gen] if self.netns_gen else ["sudo"]
        legit_cmd = gen_prefix + [
            "python3", str(TRAFFIC_DIR / "legit_client.py"),
            "--server", self.target_ip,
            "--source-ip", "10.99.0.1",
            "--qps", "100",
            "--duration", str(legit_duration),
            "--output", str(legit_csv)
        ]
        p_legit = subprocess.Popen(legit_cmd)

        # 3. Warm-up Period
        print(f"  [Warmup] Running legitimate client only for {self.warmup_s}s...")
        time.sleep(self.warmup_s)

        # 4. Measurement Window: Start Flood Traffic
        print(f"  [Window] Launching Flood Scenario {scenario} at {flood_rate:,} pps for {self.window_s}s...")
        kavach_gen = TRAFFIC_DIR / "kavach_gen"
        if not kavach_gen.is_file():
            run_cmd(["make", "-C", str(TRAFFIC_DIR)])

        if scenario == "S1":
            flood_cmd = gen_prefix + [
                str(kavach_gen), "s1",
                "--target", self.target_ip,
                "--source", "198.18.0.10",
                "--rate", str(flood_rate),
                "--duration", str(self.window_s)
            ]
        elif scenario == "S2":
            flood_cmd = gen_prefix + [
                str(kavach_gen), "s2",
                "--target", self.target_ip,
                "--sources", "1000",
                "--rate", str(flood_rate),
                "--duration", str(self.window_s)
            ]
        elif scenario == "S3":
            flood_cmd = gen_prefix + [
                str(kavach_gen), "s3",
                "--target", self.target_ip,
                "--source", "198.18.0.10",
                "--burst", str(self.src_burst),
                "--multiplier", str(level),
                "--period", "5.0",
                "--duration", str(self.window_s)
            ]
        else:
            raise ValueError(f"Unknown scenario: {scenario}")

        res_flood = run_cmd(flood_cmd, check=True)
        print(f"  [Window] Flood finished. Generator output: {res_flood.stdout.strip()}")

        # 5. Cool-down Period
        print(f"  [Cooldown] Cooling down for {self.cooldown_s}s...")
        p_legit.wait()
        if p_collect:
            p_collect.wait()
        if self.use_target_daemon:
            try:
                send_daemon_cmd(self.target_ip, self.daemon_port, {"cmd": "stop"})
            except Exception as e:
                print(f"  [WARN] Daemon stop notification notice: {e}")

        # 6. Save Run Metadata
        meta = {
            "run_name": run_name,
            "scenario": scenario,
            "config": config,
            "xdp_mode": detected_xdp_mode,
            "level": level,
            "rep": rep,
            "timestamp": time.time(),
            "git_commit": get_git_commit(),
            "dry_run": self.dry_run,
            "parameters": {
                "S_pps": self.S_pps,
                "flood_rate": flood_rate,
                "src_rate": self.src_rate,
                "src_burst": self.src_burst,
                "glob_rate": self.glob_rate,
                "glob_burst": self.glob_burst,
                "warmup_s": self.warmup_s,
                "window_s": self.window_s,
                "cooldown_s": self.cooldown_s,
            }
        }
        with open(run_dir / "run_meta.json", "w") as f_meta:
            json.dump(meta, f_meta, indent=2)

        print(f"[COMPLETED] Run {run_name} finished successfully. Artifacts saved in {run_dir}")

    def run_matrix(self):
        """Generates and executes the randomized benchmark matrix with resume & pause support."""
        runs = []
        for s in self.scenarios:
            for c in self.configs:
                for lvl in self.levels:
                    for rep in range(1, self.reps + 1):
                        runs.append((s, c, lvl, rep))

        total_runs = len(runs)
        print(f"==============================================================================")
        print(f"Kavach Benchmark Matrix: {total_runs} Total Runs (Seed={self.seed}, DryRun={self.dry_run})")
        print(f"Configs   : {self.configs}")
        print(f"Scenarios : {self.scenarios}")
        print(f"Levels    : {self.levels}")
        print(f"Reps      : {self.reps}")
        print(f"AutoResume: {self.resume} | PauseBetween: {self.pause_between} | BatchSize: {self.batch_size}")
        print(f"==============================================================================")

        # Seeded pseudo-random shuffle
        rng = random.Random(self.seed)
        shuffled_runs = list(runs)
        rng.shuffle(shuffled_runs)

        # Save run order
        order_meta = [
            {"order": idx + 1, "scenario": s, "config": c, "level": lvl, "rep": rep}
            for idx, (s, c, lvl, rep) in enumerate(shuffled_runs)
        ]
        with open(RESULTS_RAW_DIR / "run_order.json", "w") as f_order:
            json.dump(order_meta, f_order, indent=2)

        start_time = time.time()
        completed_count = 0
        skipped_count = 0

        try:
            for idx, (s, c, lvl, rep) in enumerate(shuffled_runs):
                run_name = f"{s}_{c}_{lvl}x_{rep}"
                run_dir = RESULTS_RAW_DIR / run_name
                meta_file = run_dir / "run_meta.json"
                legit_csv = run_dir / "legit_client.csv"

                # Check if run is already completed (Checkpoint / Auto-Resume)
                if self.resume and meta_file.is_file() and legit_csv.is_file() and legit_csv.stat().st_size > 100:
                    print(f"--- Progress: [{idx + 1}/{total_runs}] {run_name} \033[1;36m[ALREADY COMPLETED - RESUME SKIP]\033[0m ---")
                    skipped_count += 1
                    continue

                print(f"\n--- Progress: [{idx + 1}/{total_runs}] ---")
                self.execute_run(s, c, lvl, rep)
                completed_count += 1

                # Check batch limit
                if self.batch_size > 0 and completed_count >= self.batch_size:
                    print(f"\n\033[1;32m[BATCH LIMIT] Completed {completed_count} runs in this batch. Stopping gracefully.\033[0m")
                    print("You can resume the remaining runs whenever the lab is free!")
                    break

                # Check pause-between
                if self.pause_between and (idx + 1 < total_runs):
                    print(f"\n\033[1;33m[PAUSED] Run {run_name} finished. Progress: [{idx + 1}/{total_runs} complete].\033[0m")
                    print("\033[1;33m>>> Press [ENTER] to start next run, or [Ctrl+C] to exit and resume later...\033[0m")
                    try:
                        input()
                    except EOFError:
                        pass

        except KeyboardInterrupt:
            print("\n\n\033[1;33m[INTERRUPTED] Experiment paused by user (Ctrl+C).\033[0m")
            print(f"Runs completed this session: {completed_count} | Runs previously completed: {skipped_count}")
            print(f"Total progress: {completed_count + skipped_count}/{total_runs} runs.")
            print("\033[1;32m[SAFE] All completed runs are saved on disk in results/raw/.\033[0m")
            print("To resume whenever the lab is free, simply rerun:")
            print(f"    sudo python3 {' '.join(sys.argv)}")
            self.reset_state()
            sys.exit(0)

        elapsed = time.time() - start_time
        print(f"\n==============================================================================")
        print(f"Benchmark Session Ended. Completed {completed_count} runs (Skipped {skipped_count}) in {elapsed:.1f}s.")
        print(f"==============================================================================")

        # Final cleanup
        self.reset_state()

        # Trigger analysis
        print("\n[INFO] Launching analyze.py to compute metrics and generate summary plot...")
        analyze_cmd = ["python3", str(SCRIPTS_DIR / "analyze.py")]
        subprocess.run(analyze_cmd)


def main():
    parser = argparse.ArgumentParser(description="Kavach Experiment Orchestrator v1")
    parser.add_argument("--params", default=str(SRC_DIR / "params.yaml"), help="Path to params.yaml or params.json")
    parser.add_argument("--dry-run", action="store_true", help="Execute rapid dry run with shortened windows")
    parser.add_argument("--host", action="store_true", help="Execute on physical host network stack without namespaces")
    parser.add_argument("--iface", help="Physical interface name (e.g. eno1)")
    parser.add_argument("--target", default="10.99.0.2", help="Target server IP (default: 10.99.0.2)")
    parser.add_argument("--daemon-port", type=int, default=9999, help="Target daemon port (default: 9999)")
    parser.add_argument("--mode", choices=["auto", "daemon", "local"], default="auto",
                        help="Execution mode (auto: detect daemon; daemon: require daemon; local: namespaces/host)")
    parser.add_argument("--pause", action="store_true", help="Pause and prompt for [ENTER] between runs")
    parser.add_argument("--no-resume", action="store_true", help="Disable auto-resume; re-run even if data exists")
    parser.add_argument("--batch", type=int, default=0, help="Run at most N runs then stop gracefully (0 = all)")
    parser.add_argument("--seed", type=int, default=42, help="Randomization seed (default: 42)")
    parser.add_argument("--configs", help="Comma-separated configs: B0,B1,B2,X")
    parser.add_argument("--scenarios", help="Comma-separated scenarios: S1,S2,S3")
    parser.add_argument("--levels", help="Comma-separated levels (e.g. 0.5,1.0,2.0)")
    parser.add_argument("--reps", type=int, help="Number of repetitions per combination (default: 3)")
    args = parser.parse_args()

    params = load_params(Path(args.params))

    custom_configs = [c.strip().upper() for c in args.configs.split(",")] if args.configs else None
    custom_scenarios = [s.strip().upper() for s in args.scenarios.split(",")] if args.scenarios else None
    custom_levels = [float(lvl.strip()) for lvl in args.levels.split(",")] if args.levels else None

    orchestrator = Orchestrator(
        params=params,
        dry_run=args.dry_run,
        seed=args.seed,
        custom_configs=custom_configs,
        custom_scenarios=custom_scenarios,
        custom_levels=custom_levels,
        custom_reps=args.reps,
        host_mode=args.host,
        iface=args.iface,
        target_ip=args.target,
        daemon_port=args.daemon_port,
        mode=args.mode,
        pause_between=args.pause,
        resume=not args.no_resume,
        batch_size=args.batch
    )
    orchestrator.run_matrix()


if __name__ == "__main__":
    main()
