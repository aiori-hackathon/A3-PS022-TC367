#!/usr/bin/env python3
"""
Kavach PS-022: Multi-Layer Telemetry Metric Collector (v1)
Submission ID: A3-PS022-TC367

Synchronously harvests multi-layer telemetry across the benchmark window:
  - CPU Utilization: Total, per-core, and software interrupts (%softirq) via /proc/stat
  - Interface Throughput: rx_packets, rx_bytes, rx_dropped via /sys/class/net/
  - Drops by Layer Hierarchy:
      Layer 1 (NIC Driver): rx_dropped via sysfs
      Layer 2 (Kernel Softnet): dropped frames via /proc/net/softnet_stat
      Layer 3 (Filter): In-kernel BPF drops (14 counters) or nftables drop counters
      Layer 4 (Socket Buffer): UdpInErrors & UdpRcvbufErrors via /proc/net/snmp
"""

import os
import sys
import time
import json
import socket
import argparse
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path

BPF_PIN_COUNTERS = Path("/sys/fs/bpf/kavach/counters")
COUNTER_NAMES = [
    "seen", "pass_non_ipv4", "pass_non_udp", "pass_non53",
    "pass_fragment", "pass_truncated", "pass_invalid_ipv4", "dns_pass",
    "drop_bad_udp", "drop_short_dns", "drop_src", "drop_global",
    "drop_busy", "drop_state"
]


def read_proc_stat_cpus() -> Dict[str, List[int]]:
    """Reads /proc/stat and returns tick counters per CPU."""
    cpus = {}
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("cpu"):
                    parts = line.split()
                    name = parts[0]
                    vals = [int(x) for x in parts[1:]]
                    cpus[name] = vals
    except Exception as e:
        print(f"[WARN] Failed to read /proc/stat: {e}", file=sys.stderr)
    return cpus


def read_net_snmp_udp() -> Dict[str, int]:
    """Reads /proc/net/snmp and returns UDP counter mappings."""
    udp_stats = {}
    try:
        with open("/proc/net/snmp", "r") as f:
            lines = f.readlines()
        for i in range(len(lines) - 1):
            if lines[i].startswith("Udp:") and lines[i + 1].startswith("Udp:"):
                keys = lines[i].split()[1:]
                vals = [int(x) for x in lines[i + 1].split()[1:]]
                for k, v in zip(keys, vals):
                    udp_stats[k] = v
                break
    except Exception as e:
        print(f"[WARN] Failed to read /proc/net/snmp: {e}", file=sys.stderr)
    return udp_stats


def read_iface_stats(iface: str) -> Dict[str, int]:
    """Reads network interface statistics from /proc/net/dev or sysfs."""
    stats = {"rx_packets": 0, "rx_bytes": 0, "rx_dropped": 0, "rx_errors": 0, "tx_packets": 0, "tx_bytes": 0}
    # 1. Parse /proc/net/dev (accurate inside network namespaces and under nsenter)
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                if ":" in line:
                    dev, rest = line.split(":", 1)
                    if dev.strip() == iface:
                        vals = rest.split()
                        stats["rx_bytes"] = int(vals[0])
                        stats["rx_packets"] = int(vals[1])
                        stats["rx_errors"] = int(vals[2])
                        stats["rx_dropped"] = int(vals[3])
                        stats["tx_bytes"] = int(vals[8])
                        stats["tx_packets"] = int(vals[9])
                        return stats
    except Exception:
        pass

    # 2. Fallback to sysfs if available
    stat_dir = f"/sys/class/net/{iface}/statistics"
    if os.path.isdir(stat_dir):
        for m in ["rx_packets", "rx_bytes", "rx_dropped", "rx_errors", "tx_packets", "tx_bytes"]:
            path = os.path.join(stat_dir, m)
            if os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        stats[m] = int(f.read().strip())
                except Exception:
                    stats[m] = 0
    return stats


def read_softnet_stat() -> Dict[str, int]:
    """Reads /proc/net/softnet_stat for total processed and dropped frames."""
    processed = 0
    dropped = 0
    time_squeeze = 0
    try:
        with open("/proc/net/softnet_stat", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    processed += int(parts[0], 16)
                    dropped += int(parts[1], 16)
                    time_squeeze += int(parts[2], 16)
    except Exception as e:
        print(f"[WARN] Failed to read /proc/net/softnet_stat: {e}", file=sys.stderr)
    return {"processed": processed, "dropped": dropped, "time_squeeze": time_squeeze}


def read_bpf_stats(map_path: Path = BPF_PIN_COUNTERS) -> Dict[str, int]:
    """Dumps Kavach per-CPU stats map via bpftool using the 14-counter schema."""
    stats = {k: 0 for k in COUNTER_NAMES}
    if not map_path.exists():
        return stats

    try:
        # Note: -j must precede the subcommand in bpftool
        res = subprocess.run(
            ["/usr/lib/linux-tools/6.8.0-147-generic/bpftool", "-j", "map", "dump", "pinned", str(map_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2.0,
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for entry in data:
                if "formatted" in entry and "values" in entry["formatted"]:
                    key_idx = entry["formatted"].get("key", 0)
                    total_val = sum(v.get("value", 0) for v in entry["formatted"].get("values", []))
                else:
                    k_bytes = [int(x, 16) if isinstance(x, str) else x for x in entry.get("key", [0])]
                    key_idx = int.from_bytes(bytes(k_bytes), "little")
                    total_val = 0
                    for v in entry.get("values", []):
                        val_raw = v.get("value", [])
                        if isinstance(val_raw, list):
                            v_bytes = [int(x, 16) if isinstance(x, str) else x for x in val_raw]
                            total_val += int.from_bytes(bytes(v_bytes), "little")
                        elif isinstance(val_raw, int):
                            total_val += val_raw

                if 0 <= key_idx < len(COUNTER_NAMES):
                    stats[COUNTER_NAMES[key_idx]] = total_val
    except Exception:
        pass
    return stats


def read_nft_stats() -> Dict[str, int]:
    """Parses drop counters from nftables ruleset if B1 or B2 is active."""
    stats = {"drop_src": 0, "drop_global": 0, "total_drops": 0}
    try:
        res = subprocess.run(["nft", "-j", "list", "ruleset"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for item in data.get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                exprs = rule.get("expr", [])
                has_drop = any("drop" in e for e in exprs)
                counter = next((e.get("counter") for e in exprs if "counter" in e), None)
                if has_drop and counter:
                    pkts = counter.get("packets", 0)
                    has_flood_set = any("add" in e and "@flood" in str(e) for e in exprs)
                    if has_flood_set:
                        stats["drop_src"] += pkts
                    else:
                        stats["drop_global"] += pkts
            stats["total_drops"] = stats["drop_src"] + stats["drop_global"]
    except Exception:
        pass
    return stats


class MetricCollector:
    def __init__(
        self,
        duration: float = 60.0,
        output_dir: str = "/tmp/kavach_metrics",
        iface: str = "vsrv",
        pinned_core: int = 1,
        interval: float = 1.0,
    ):
        self.duration = duration
        self.output_dir = output_dir
        self.iface = iface
        self.pinned_core = pinned_core
        self.interval = interval

        os.makedirs(self.output_dir, exist_ok=True)
        self.cpu_log_path = os.path.join(self.output_dir, "cpu_util.csv")
        self.throughput_log_path = os.path.join(self.output_dir, "throughput_pps.csv")
        self.bpf_log_path = os.path.join(self.output_dir, "bpf_stats.csv")
        self.summary_path = os.path.join(self.output_dir, "metrics_summary.json")

    def run(self) -> Dict[str, Any]:
        print(f"[INFO] MetricCollector started: duration={self.duration}s, iface={self.iface}, core={self.pinned_core}")

        # Baseline snapshots
        cpu_start = read_proc_stat_cpus()
        snmp_start = read_net_snmp_udp()
        iface_start = read_iface_stats(self.iface)
        softnet_start = read_softnet_stat()
        bpf_start = read_bpf_stats()
        nft_start = read_nft_stats()

        t_start = time.perf_counter()
        next_sample_time = t_start + self.interval

        cpu_records = []
        throughput_records = []
        bpf_records = []

        prev_cpu = cpu_start
        prev_rx_pkts = iface_start.get("rx_packets", 0)
        prev_rx_bytes = iface_start.get("rx_bytes", 0)

        with open(self.cpu_log_path, "w") as f_cpu, \
             open(self.throughput_log_path, "w") as f_thru, \
             open(self.bpf_log_path, "w") as f_bpf:

            f_cpu.write("timestamp,pinned_core_busy_pct,pinned_core_softirq_pct,total_busy_pct\n")
            f_thru.write("timestamp,rx_pps,rx_mbps,rx_dropped\n")
            # Frozen 14-counter header
            f_bpf.write("timestamp_ns," + ",".join(COUNTER_NAMES) + "\n")

            while True:
                now_pc = time.perf_counter()
                elapsed = now_pc - t_start
                if elapsed >= self.duration:
                    break

                sleep_time = next_sample_time - now_pc
                if sleep_time > 0:
                    time.sleep(sleep_time)
                next_sample_time += self.interval

                now_ts = time.time()
                now_ts_ns = int(now_ts * 1e9)
                cur_cpu = read_proc_stat_cpus()
                iface_now = read_iface_stats(self.iface)

                # CPU Metrics
                dt = self.interval
                core_key = f"cpu{self.pinned_core}"
                c_prev = prev_cpu.get(core_key, [0] * 10)
                c_now = cur_cpu.get(core_key, [0] * 10)

                d_user = c_now[0] - c_prev[0]
                d_nice = c_now[1] - c_prev[1]
                d_sys = c_now[2] - c_prev[2]
                d_idle = c_now[3] - c_prev[3]
                d_iowait = c_now[4] - c_prev[4]
                d_irq = c_now[5] - c_prev[5]
                d_softirq = c_now[6] - c_prev[6]

                total_ticks = max(1, sum(c_now) - sum(c_prev))
                busy_ticks = total_ticks - (d_idle + d_iowait)
                pinned_busy = (busy_ticks / total_ticks) * 100.0
                pinned_soft = (d_softirq / total_ticks) * 100.0

                tot_prev = prev_cpu.get("cpu", [0] * 10)
                tot_now = cur_cpu.get("cpu", [0] * 10)
                tot_total = max(1, sum(tot_now) - sum(tot_prev))
                tot_busy_ticks = tot_total - ((tot_now[3] - tot_prev[3]) + (tot_now[4] - tot_prev[4]))
                tot_busy = (tot_busy_ticks / tot_total) * 100.0

                prev_cpu = cur_cpu

                f_cpu.write(f"{now_ts:.3f},{pinned_busy:.2f},{pinned_soft:.2f},{tot_busy:.2f}\n")
                f_cpu.flush()
                cpu_records.append({"pinned_busy": pinned_busy, "pinned_softirq": pinned_soft, "total_busy": tot_busy})

                # Throughput Metrics
                cur_rx_pkts = iface_now.get("rx_packets", 0)
                cur_rx_bytes = iface_now.get("rx_bytes", 0)
                cur_rx_drop = iface_now.get("rx_dropped", 0)

                rx_pps = max(0.0, (cur_rx_pkts - prev_rx_pkts) / dt)
                rx_mbps = max(0.0, ((cur_rx_bytes - prev_rx_bytes) * 8.0 / 1e6) / dt)
                prev_rx_pkts = cur_rx_pkts
                prev_rx_bytes = cur_rx_bytes

                f_thru.write(f"{now_ts:.3f},{rx_pps:.1f},{rx_mbps:.2f},{cur_rx_drop}\n")
                f_thru.flush()
                throughput_records.append({"pps": rx_pps, "mbps": rx_mbps})

                # BPF Stats
                bpf_now = read_bpf_stats()
                vals_str = ",".join(str(bpf_now[k]) for k in COUNTER_NAMES)
                f_bpf.write(f"{now_ts_ns},{vals_str}\n")
                f_bpf.flush()
                bpf_records.append(bpf_now)

        # Final Snapshots
        snmp_end = read_net_snmp_udp()
        iface_end = read_iface_stats(self.iface)
        softnet_end = read_softnet_stat()
        bpf_end = read_bpf_stats()
        nft_end = read_nft_stats()
        t_end = time.perf_counter()
        total_time = t_end - t_start

        # Calculate Diffs
        delta_rx_packets = iface_end.get("rx_packets", 0) - iface_start.get("rx_packets", 0)
        delta_rx_bytes = iface_end.get("rx_bytes", 0) - iface_start.get("rx_bytes", 0)
        delta_rx_dropped = iface_end.get("rx_dropped", 0) - iface_start.get("rx_dropped", 0)

        delta_udp_in = snmp_end.get("InDatagrams", 0) - snmp_start.get("InDatagrams", 0)
        delta_udp_err = snmp_end.get("InErrors", 0) - snmp_start.get("InErrors", 0)
        delta_udp_rcvbuf = snmp_end.get("RcvbufErrors", 0) - snmp_start.get("RcvbufErrors", 0)

        delta_softnet_drop = softnet_end.get("dropped", 0) - softnet_start.get("dropped", 0)

        # BPF Drops
        delta_bpf = {k: bpf_end[k] - bpf_start[k] for k in COUNTER_NAMES}
        delta_bpf_total_drops = delta_bpf["drop_src"] + delta_bpf["drop_global"] + delta_bpf["drop_bad_udp"] + delta_bpf["drop_short_dns"]

        # nftables Drops
        delta_nft_src = nft_end["drop_src"] - nft_start["drop_src"]
        delta_nft_glob = nft_end["drop_global"] - nft_start["drop_global"]
        delta_nft_total_drops = delta_nft_src + delta_nft_glob

        # Active Filter Drops (XDP if attached, else nftables, else 0)
        is_xdp_active = delta_bpf["seen"] > 0
        is_nft_active = delta_nft_total_drops > 0

        if is_xdp_active:
            filter_layer_drops = delta_bpf_total_drops
            filter_src_drops = delta_bpf["drop_src"]
            filter_glob_drops = delta_bpf["drop_global"]
            filter_type = "xdp"
        elif is_nft_active:
            filter_layer_drops = delta_nft_total_drops
            filter_src_drops = delta_nft_src
            filter_glob_drops = delta_nft_glob
            filter_type = "nftables"
        else:
            filter_layer_drops = 0
            filter_src_drops = 0
            filter_glob_drops = 0
            filter_type = "none"

        avg_offered_pps = (delta_rx_packets / total_time) if total_time > 0 else 0.0
        avg_offered_mbps = (delta_rx_bytes * 8.0 / 1e6 / total_time) if total_time > 0 else 0.0

        avg_pinned_busy = (sum(r["pinned_busy"] for r in cpu_records) / len(cpu_records)) if cpu_records else 0.0
        avg_pinned_soft = (sum(r["pinned_softirq"] for r in cpu_records) / len(cpu_records)) if cpu_records else 0.0
        avg_tot_busy = (sum(r["total_busy"] for r in cpu_records) / len(cpu_records)) if cpu_records else 0.0

        summary = {
            "window_duration_seconds": round(total_time, 2),
            "interface": self.iface,
            "pinned_core": self.pinned_core,
            "throughput": {
                "total_rx_packets": delta_rx_packets,
                "total_rx_bytes": delta_rx_bytes,
                "avg_rx_pps": round(avg_offered_pps, 1),
                "avg_rx_mbps": round(avg_offered_mbps, 2),
            },
            "cpu_utilization": {
                "pinned_core_busy_pct": round(avg_pinned_busy, 2),
                "pinned_core_softirq_pct": round(avg_pinned_soft, 2),
                "system_total_busy_pct": round(avg_tot_busy, 2),
            },
            "drops_by_layer": {
                "layer1_nic_driver": delta_rx_dropped,
                "layer2_kernel_softnet": delta_softnet_drop,
                "layer3_filter": {
                    "type": filter_type,
                    "total_drops": filter_layer_drops,
                    "per_source_drops": filter_src_drops,
                    "global_drops": filter_glob_drops,
                },
                "layer4_socket_buffer": {
                    "udp_in_errors": delta_udp_err,
                    "udp_rcvbuf_errors": delta_udp_rcvbuf,
                },
            },
            "bpf_counters_delta": delta_bpf,
            "udp_delivered_to_socket": delta_udp_in,
        }

        with open(self.summary_path, "w", encoding="utf-8") as f_sum:
            json.dump(summary, f_sum, indent=2)

        print("\033[1;32m=== Telemetry Collection Complete ===\033[0m")
        print(f"Offered Traffic      : {delta_rx_packets:,} packets (~{avg_offered_pps:,.0f} pps, {avg_offered_mbps:.1f} Mbps)")
        print(f"Core {self.pinned_core} CPU Utilization : \033[1;33m{avg_pinned_busy:.1f}%\033[0m (softirq: {avg_pinned_soft:.1f}%)")
        print(f"UDP Delivered to App : {delta_udp_in:,} packets")
        print("--- Drops by Layer ---")
        print(f"  Layer 1 (NIC Driver)    : {delta_rx_dropped:,}")
        print(f"  Layer 2 (Kernel Softnet): {delta_softnet_drop:,}")
        print(f"  Layer 3 (Filter: {filter_type:8s}): {filter_layer_drops:,} (src={filter_src_drops}, glob={filter_glob_drops})")
        print(f"  Layer 4 (Socket Buffer) : {delta_udp_err:,} (rcvbuf_errors: {delta_udp_rcvbuf:,})")
        print(f"\033[1;34m[SAVED]\033[0m Raw summary written to: {self.summary_path}")

        return summary


def main():
    parser = argparse.ArgumentParser(description="Kavach Multi-Layer Telemetry Metric Collector")
    parser.add_argument("-d", "--duration", type=float, default=60.0, help="Measurement window in seconds (default: 60)")
    parser.add_argument("-o", "--output-dir", default="/tmp/kavach_metrics", help="Directory for raw metric CSVs")
    parser.add_argument("-i", "--iface", default="vsrv", help="Network interface to monitor (default: vsrv)")
    parser.add_argument("-c", "--core", type=int, default=1, help="Pinned server CPU core ID (default: 1)")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds (default: 1.0)")
    args = parser.parse_args()

    collector = MetricCollector(
        duration=args.duration,
        output_dir=args.output_dir,
        iface=args.iface,
        pinned_core=args.core,
        interval=args.interval,
    )
    collector.run()


if __name__ == "__main__":
    main()
