#!/usr/bin/env python3
"""
Kavach PS-022: Multi-Layer Telemetry Metric Collector (v0)

Collects system, hardware, kernel, and BPF statistics during a benchmark window:
  - CPU Utilization: Total, per-core, and software interrupts (%softirq) via /proc/stat
  - Interface Throughput: rx_packets, rx_bytes, rx_dropped via /sys/class/net/
  - Kernel Socket Drops: UdpInDatagrams, UdpInErrors, UdpRcvbufErrors via /proc/net/snmp
  - Software Interrupt Drops: via /proc/net/softnet_stat
  - In-Kernel BPF Drops: via bpftool map dump (if Kavach XDP is attached)
  - Drops by Layer Analysis: NIC vs Softnet vs XDP vs Socket Buffer
"""

import os
import sys
import time
import json
import socket
import argparse
import subprocess
from typing import Dict, Any, List, Optional


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
    """Reads network interface statistics from sysfs."""
    stats = {}
    stat_dir = f"/sys/class/net/{iface}/statistics"
    metrics = ["rx_packets", "rx_bytes", "rx_dropped", "rx_errors", "tx_packets", "tx_bytes"]
    if os.path.isdir(stat_dir):
        for m in metrics:
            path = os.path.join(stat_dir, m)
            if os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        stats[m] = int(f.read().strip())
                except Exception:
                    stats[m] = 0
            else:
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


def read_bpf_stats(map_path: str = "/sys/fs/bpf/kavach/maps/map_stats") -> Dict[str, int]:
    """Dumps Kavach per-CPU stats map via bpftool if present."""
    stats = {
        "dns_seen": 0,
        "non_dns_passed": 0,
        "passed": 0,
        "drop_source": 0,
        "drop_global": 0,
        "malformed": 0,
        "fragments_passed": 0,
        "unparsable_passed": 0,
    }
    key_names = [
        "dns_seen",
        "non_dns_passed",
        "passed",
        "drop_source",
        "drop_global",
        "malformed",
        "fragments_passed",
        "unparsable_passed",
    ]
    if not os.path.exists(map_path):
        return stats

    try:
        res = subprocess.run(
            ["bpftool", "map", "dump", "pinned", map_path, "-j"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2.0,
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            # Sum values across CPU cores
            for entry in data:
                key_idx = entry.get("key", 0)
                values = entry.get("values", [])
                total_val = sum(v.get("value", 0) for v in values if isinstance(v, dict))
                if key_idx < len(key_names):
                    stats[key_names[key_idx]] = total_val
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
        print("\033[1;34m=== Kavach Telemetry Collector (v0) ===\033[0m")
        print(f"Monitoring Interface : {self.iface}")
        print(f"Server Pinned Core   : CPU {self.pinned_core}")
        print(f"Window Duration      : {self.duration:.1f} s (Sampling interval: {self.interval:.1f} s)")
        print(f"Metrics Output Dir   : {self.output_dir}")
        print("----------------------------------------------------------------------")

        # Initial Snapshots
        snmp_start = read_net_snmp_udp()
        iface_start = read_iface_stats(self.iface)
        softnet_start = read_softnet_stat()
        bpf_start = read_bpf_stats()
        cpu_prev = read_proc_stat_cpus()
        t_start = time.perf_counter()

        pinned_core_name = f"cpu{self.pinned_core}"
        cpu_records: List[Dict[str, float]] = []
        throughput_records: List[Dict[str, float]] = []
        bpf_records: List[Dict[str, Any]] = []

        with open(self.cpu_log_path, "w", encoding="utf-8") as f_cpu, \
             open(self.throughput_log_path, "w", encoding="utf-8") as f_thru, \
             open(self.bpf_log_path, "w", encoding="utf-8") as f_bpf:

            f_cpu.write("timestamp,total_busy_pct,pinned_busy_pct,pinned_softirq_pct\n")
            f_thru.write("timestamp,rx_pps,rx_mbps,rx_dropped\n")
            f_bpf.write("timestamp,dns_seen,passed,drop_source,drop_global,malformed\n")

            iterations = int(self.duration / self.interval)
            prev_time = t_start
            prev_rx_pkts = iface_start.get("rx_packets", 0)
            prev_rx_bytes = iface_start.get("rx_bytes", 0)

            for i in range(iterations):
                time.sleep(self.interval)
                now_perf = time.perf_counter()
                now_ts = time.time()
                dt = now_perf - prev_time
                prev_time = now_perf

                # Sample CPU
                cpu_now = read_proc_stat_cpus()
                # Compute total CPU %
                tot_v1, tot_v2 = cpu_prev.get("cpu", []), cpu_now.get("cpu", [])
                tot_diff = [b - a for a, b in zip(tot_v1, tot_v2)]
                tot_sum = sum(tot_diff)
                total_busy_pct = ((tot_sum - tot_diff[3]) / tot_sum * 100.0) if tot_sum > 0 else 0.0

                # Compute Pinned Core CPU % and softirq %
                p_v1, p_v2 = cpu_prev.get(pinned_core_name, []), cpu_now.get(pinned_core_name, [])
                p_diff = [b - a for a, b in zip(p_v1, p_v2)]
                p_sum = sum(p_diff)
                pinned_busy_pct = ((p_sum - p_diff[3]) / p_sum * 100.0) if p_sum > 0 else 0.0
                pinned_soft_pct = (p_diff[6] / p_sum * 100.0) if (p_sum > 0 and len(p_diff) > 6) else 0.0
                cpu_prev = cpu_now

                f_cpu.write(f"{now_ts:.3f},{total_busy_pct:.2f},{pinned_busy_pct:.2f},{pinned_soft_pct:.2f}\n")
                f_cpu.flush()
                cpu_records.append({
                    "total_busy": total_busy_pct,
                    "pinned_busy": pinned_busy_pct,
                    "pinned_softirq": pinned_soft_pct,
                })

                # Sample Interface Throughput
                iface_now = read_iface_stats(self.iface)
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

                # Sample BPF Stats if map exists
                bpf_now = read_bpf_stats()
                f_bpf.write(
                    f"{now_ts:.3f},{bpf_now['dns_seen']},{bpf_now['passed']},"
                    f"{bpf_now['drop_source']},{bpf_now['drop_global']},{bpf_now['malformed']}\n"
                )
                f_bpf.flush()
                bpf_records.append(bpf_now)

        # Final Snapshots
        snmp_end = read_net_snmp_udp()
        iface_end = read_iface_stats(self.iface)
        softnet_end = read_softnet_stat()
        bpf_end = read_bpf_stats()
        t_end = time.perf_counter()
        total_time = t_end - t_start

        # Calculate Absolute Diffs
        delta_rx_packets = iface_end.get("rx_packets", 0) - iface_start.get("rx_packets", 0)
        delta_rx_bytes = iface_end.get("rx_bytes", 0) - iface_start.get("rx_bytes", 0)
        delta_rx_dropped = iface_end.get("rx_dropped", 0) - iface_start.get("rx_dropped", 0)

        delta_udp_in = snmp_end.get("InDatagrams", 0) - snmp_start.get("InDatagrams", 0)
        delta_udp_err = snmp_end.get("InErrors", 0) - snmp_start.get("InErrors", 0)
        delta_udp_rcvbuf = snmp_end.get("RcvbufErrors", 0) - snmp_start.get("RcvbufErrors", 0)

        delta_softnet_drop = softnet_end.get("dropped", 0) - softnet_start.get("dropped", 0)

        delta_bpf_seen = bpf_end["dns_seen"] - bpf_start["dns_seen"]
        delta_bpf_passed = bpf_end["passed"] - bpf_start["passed"]
        delta_bpf_drop_src = bpf_end["drop_source"] - bpf_start["drop_source"]
        delta_bpf_drop_glob = bpf_end["drop_global"] - bpf_start["drop_global"]
        delta_bpf_malformed = bpf_end["malformed"] - bpf_start["malformed"]
        delta_bpf_total_drops = delta_bpf_drop_src + delta_bpf_drop_glob + delta_bpf_malformed

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
                "nic_driver_drops": delta_rx_dropped,
                "kernel_softnet_drops": delta_softnet_drop,
                "xdp_bpf_drops": {
                    "total": delta_bpf_total_drops,
                    "per_source": delta_bpf_drop_src,
                    "global": delta_bpf_drop_glob,
                    "malformed": delta_bpf_malformed,
                },
                "socket_buffer_drops": {
                    "udp_in_errors": delta_udp_err,
                    "udp_rcvbuf_errors": delta_udp_rcvbuf,
                },
            },
            "udp_delivered_to_socket": delta_udp_in,
        }

        with open(self.summary_path, "w", encoding="utf-8") as f_sum:
            json.dump(summary, f_sum, indent=2)

        print("\033[1;32m=== Telemetry Collection Complete ===\033[0m")
        print(f"Offered Traffic      : {delta_rx_packets:,} packets (~{avg_offered_pps:,.0f} pps, {avg_offered_mbps:.1f} Mbps)")
        print(f"Core {self.pinned_core} CPU Utilization : \033[1;33m{avg_pinned_busy:.1f}%\033[0m (softirq: {avg_pinned_soft:.1f}%)")
        print(f"UDP Delivered to App : {delta_udp_in:,} packets")
        print("--- Drops by Layer ---")
        print(f"  NIC Driver Drops   : {delta_rx_dropped:,}")
        print(f"  Softnet Drops      : {delta_softnet_drop:,}")
        print(f"  XDP / eBPF Drops   : {delta_bpf_total_drops:,} (src={delta_bpf_drop_src}, glob={delta_bpf_drop_glob}, malformed={delta_bpf_malformed})")
        print(f"  Socket Buffer Drops: {delta_udp_err:,} (rcvbuf_errors: {delta_udp_rcvbuf:,})")
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

