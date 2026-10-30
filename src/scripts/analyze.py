#!/usr/bin/env python3
"""
Kavach PS-022: Telemetry Analysis & Visualization Engine (v0)
Submission ID: A3-PS022-TC367

Processes raw benchmark telemetry across experimental runs:
  - Computes statistical summaries: Median and IQR (Interquartile Range)
  - Evaluates Legitimate Query Success Rate (%) and latency percentiles (p50, p95, p99)
  - Analyzes Server CPU Utilization (%total busy and %softirq) on the pinned core
  - Calculates multi-tier Drops by Layer (NIC vs Softnet vs Filter vs Socket Buffer)
  - Generates publication-ready comparative multi-panel plots in results/plots/
"""

import os
import sys

# Ensure matplotlib uses a writable cache directory
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

import csv
import json
import math
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_RAW_DIR = REPO_ROOT / "results" / "raw"
PLOTS_DIR = REPO_ROOT / "results" / "plots"


def compute_median_iqr(values: List[float]) -> Dict[str, float]:
    """Computes median and IQR (or spread if few samples)."""
    if not values:
        return {"median": 0.0, "iqr": 0.0, "q25": 0.0, "q75": 0.0, "min": 0.0, "max": 0.0}
    arr = np.array(values, dtype=float)
    med = float(np.median(arr))
    q25 = float(np.percentile(arr, 25))
    q75 = float(np.percentile(arr, 75))
    return {
        "median": round(med, 2),
        "iqr": round(q75 - q25, 2),
        "q25": round(q25, 2),
        "q75": round(q75, 2),
        "min": round(float(np.min(arr)), 2),
        "max": round(float(np.max(arr)), 2),
    }


def parse_legit_client_csv(csv_path: Path) -> Dict[str, Any]:
    """Parses legitimate client CSV to extract success rate and latencies."""
    if not csv_path.is_file():
        return {"sent": 0, "answered": 0, "success_rate": 0.0, "latencies": [], "p50": 0.0, "p95": 0.0, "p99": 0.0}

    total_sent = 0
    answered = 0
    latencies = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_sent += 1
            status = row.get("status", "").strip().upper()
            rcode = row.get("rcode", "").strip()
            if status == "SUCCESS" or rcode in ["0", "NOERROR"]:
                answered += 1
                try:
                    lat = float(row.get("latency_ms", 0.0))
                    latencies.append(lat)
                except ValueError:
                    pass

    success_rate = (answered / total_sent * 100.0) if total_sent > 0 else 0.0
    p50 = float(np.percentile(latencies, 50)) if latencies else 0.0
    p95 = float(np.percentile(latencies, 95)) if latencies else 0.0
    p99 = float(np.percentile(latencies, 99)) if latencies else 0.0

    return {
        "sent": total_sent,
        "answered": answered,
        "success_rate": round(success_rate, 2),
        "latencies": latencies,
        "p50": round(p50, 3),
        "p95": round(p95, 3),
        "p99": round(p99, 3),
    }


def parse_run_dir(run_dir: Path) -> Dict[str, Any]:
    """Parses all telemetry artifacts within a single run directory."""
    summary_path = run_dir / "metrics_summary.json"
    legit_csv_path = run_dir / "legit_client.csv"
    meta_path = run_dir / "run_meta.json"

    meta = {}
    if meta_path.is_file():
        with open(meta_path, "r") as f:
            meta = json.load(f)

    metrics = {}
    if summary_path.is_file():
        with open(summary_path, "r") as f:
            metrics = json.load(f)

    legit = parse_legit_client_csv(legit_csv_path)

    # Infer scenario and config from directory name if meta missing
    dir_name = run_dir.name
    parts = dir_name.split("_")
    scenario = meta.get("scenario", parts[0] if len(parts) > 0 else "unknown")
    config = meta.get("config", parts[1] if len(parts) > 1 else "unknown")
    level = meta.get("level", parts[2] if len(parts) > 2 else "1x")
    rep = meta.get("rep", parts[3] if len(parts) > 3 else "1")

    cpu_util = metrics.get("cpu_utilization", {})
    drops = metrics.get("drops_by_layer", {})
    filter_drops = drops.get("layer3_filter", {})
    socket_drops = drops.get("layer4_socket_buffer", {})

    return {
        "run_name": dir_name,
        "scenario": scenario,
        "config": config,
        "level": str(level),
        "rep": str(rep),
        "legit_success_rate": legit["success_rate"],
        "legit_p50": legit["p50"],
        "legit_p95": legit["p95"],
        "legit_p99": legit["p99"],
        "cpu_pinned_busy": cpu_util.get("pinned_core_busy_pct", 0.0),
        "cpu_pinned_softirq": cpu_util.get("pinned_core_softirq_pct", 0.0),
        "cpu_total_busy": cpu_util.get("system_total_busy_pct", 0.0),
        "drops_layer1_nic": drops.get("layer1_nic_driver", 0),
        "drops_layer2_softnet": drops.get("layer2_kernel_softnet", 0),
        "drops_layer3_filter": filter_drops.get("total_drops", 0),
        "drops_layer4_socket": socket_drops.get("udp_in_errors", 0),
    }


def generate_plots(grouped_data: Dict[str, Dict[str, Any]], output_plot: Path, title: str = "Kavach PS-022: Multi-Layer eBPF/XDP Rate Limiting Benchmark"):
    """Generates a 2x2 publication-quality comparison figure using matplotlib."""
    output_plot.parent.mkdir(parents=True, exist_ok=True)

    scenarios = ["S1", "S2", "S3"]
    configs = ["B0", "B1", "B2", "X"]
    config_labels = {"B0": "B0 (No Filter)", "B1": "B1 (nft raw)", "B2": "B2 (nft netdev)", "X": "X (Kavach XDP)"}
    colors = {"B0": "#d9534f", "B1": "#f0ad4e", "B2": "#5bc0de", "X": "#5cb85c"}

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(title, fontsize=16, fontweight="bold")

    bar_width = 0.18
    x_indices = np.arange(len(scenarios))

    # --- Subplot 1: Legitimate Query Success Rate (%) ---
    ax1 = axes[0, 0]
    for i, cfg in enumerate(configs):
        success_vals = []
        for s in scenarios:
            cell = grouped_data.get(s, {}).get(cfg, {})
            success_vals.append(cell.get("legit_success_rate", {}).get("median", 0.0))
        offset = (i - 1.5) * bar_width
        ax1.bar(x_indices + offset, success_vals, width=bar_width, label=config_labels[cfg], color=colors[cfg], edgecolor="black", alpha=0.85)

    ax1.set_title("Legitimate Query Success Rate (%) [Higher is Better]", fontweight="bold")
    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(["S1 (Single Source)", "S2 (Distributed)", "S3 (Pulsing)"])
    ax1.set_ylabel("Success Rate (%)")
    ax1.set_ylim(0, 105)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)
    ax1.legend(loc="lower right")

    # --- Subplot 2: Server CPU Busy % and Softirq % ---
    ax2 = axes[0, 1]
    for i, cfg in enumerate(configs):
        cpu_busy_vals = []
        for s in scenarios:
            cell = grouped_data.get(s, {}).get(cfg, {})
            cpu_busy_vals.append(cell.get("cpu_pinned_busy", {}).get("median", 0.0))
        offset = (i - 1.5) * bar_width
        ax2.bar(x_indices + offset, cpu_busy_vals, width=bar_width, label=config_labels[cfg], color=colors[cfg], edgecolor="black", alpha=0.85)

    ax2.set_title("Server Core 1 CPU Utilization Busy % [Lower is Better]", fontweight="bold")
    ax2.set_xticks(x_indices)
    ax2.set_xticklabels(["S1 (Single Source)", "S2 (Distributed)", "S3 (Pulsing)"])
    ax2.set_ylabel("CPU Busy (%)")
    ax2.set_ylim(0, 100)
    ax2.grid(axis="y", linestyle="--", alpha=0.5)
    ax2.legend(loc="upper right")

    # --- Subplot 3: Drops by Layer Breakdown (Stacked Bars for S1) ---
    ax3 = axes[1, 0]
    cfg_indices = np.arange(len(configs))
    layer_nic = [grouped_data.get("S1", {}).get(c, {}).get("drops_layer1_nic", {}).get("median", 0) for c in configs]
    layer_soft = [grouped_data.get("S1", {}).get(c, {}).get("drops_layer2_softnet", {}).get("median", 0) for c in configs]
    layer_filter = [grouped_data.get("S1", {}).get(c, {}).get("drops_layer3_filter", {}).get("median", 0) for c in configs]
    layer_socket = [grouped_data.get("S1", {}).get(c, {}).get("drops_layer4_socket", {}).get("median", 0) for c in configs]

    p1 = ax3.bar(cfg_indices, layer_nic, label="Layer 1: NIC Driver", color="#777777", edgecolor="black")
    p2 = ax3.bar(cfg_indices, layer_soft, bottom=layer_nic, label="Layer 2: Kernel Softnet", color="#ffbb33", edgecolor="black")
    bottom_filter = np.array(layer_nic) + np.array(layer_soft)
    p3 = ax3.bar(cfg_indices, layer_filter, bottom=bottom_filter, label="Layer 3: Filter (XDP/nft)", color="#00C851", edgecolor="black")
    bottom_socket = bottom_filter + np.array(layer_filter)
    p4 = ax3.bar(cfg_indices, layer_socket, bottom=bottom_socket, label="Layer 4: Socket Buffer", color="#ff4444", edgecolor="black")

    ax3.set_title("Drops by Layer Architecture (Scenario S1)", fontweight="bold")
    ax3.set_xticks(cfg_indices)
    ax3.set_xticklabels([config_labels[c] for c in configs])
    ax3.set_ylabel("Total Packet Drops")
    ax3.grid(axis="y", linestyle="--", alpha=0.5)
    ax3.legend(loc="upper left")

    # --- Subplot 4: Query Latency (p50 & p95) ---
    ax4 = axes[1, 1]
    for i, cfg in enumerate(configs):
        p50_vals = []
        for s in scenarios:
            cell = grouped_data.get(s, {}).get(cfg, {})
            p50_vals.append(cell.get("legit_p50", {}).get("median", 0.0))
        offset = (i - 1.5) * bar_width
        ax4.bar(x_indices + offset, p50_vals, width=bar_width, label=config_labels[cfg], color=colors[cfg], edgecolor="black", alpha=0.85)

    ax4.set_title("Legitimate Query Latency Median p50 (ms) [Lower is Better]", fontweight="bold")
    ax4.set_xticks(x_indices)
    ax4.set_xticklabels(["S1 (Single Source)", "S2 (Distributed)", "S3 (Pulsing)"])
    ax4.set_ylabel("Latency (ms)")
    ax4.grid(axis="y", linestyle="--", alpha=0.5)
    ax4.legend(loc="upper right")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_plot, dpi=200)
    plt.close()
    print(f"\033[1;32m[PLOT SAVED]\033[0m Summary figure generated: {output_plot}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kavach Telemetry Analysis Engine")
    parser.add_argument("--input-dir", default=str(RESULTS_RAW_DIR), help="Path to raw results directory")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "results"), help="Path to output directory")
    parser.add_argument("--title", default="Kavach PS-022: Multi-Layer eBPF/XDP Rate Limiting Benchmark", help="Plot super title")
    parser.add_argument("--plot-name", default="kavach_summary.png", help="Plot filename")
    args = parser.parse_args()

    input_raw_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_raw_dir.is_dir():
        print(f"[ERROR] Raw results directory '{input_raw_dir}' does not exist!", file=sys.stderr)
        sys.exit(1)

    run_dirs = [d for d in input_raw_dir.iterdir() if d.is_dir() and d.name.startswith(("S1_", "S2_", "S3_")) and (d / "metrics_summary.json").is_file()]
    if not run_dirs:
        print(f"[WARN] No completed run directories found in {input_raw_dir}.")
        sys.exit(0)

    print(f"=== Kavach PS-022 Analysis Engine: Processing {len(run_dirs)} Runs from {input_raw_dir} ===")

    parsed_runs = [parse_run_dir(d) for d in run_dirs]

    # Organize by (scenario, config)
    groups: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for r in parsed_runs:
        s = r["scenario"]
        c = r["config"]
        groups.setdefault(s, {}).setdefault(c, []).append(r)

    # Compute Median and IQR per cell
    analysis_summary: Dict[str, Dict[str, Any]] = {}
    csv_rows = []

    print("\n----------------------------------------------------------------------------------------------------------")
    print(f"{'Scenario':<10} {'Config':<8} {'Runs':<6} {'Legit Success %':<18} {'CPU Busy %':<16} {'Filter Drops':<14} {'Socket Drops':<14}")
    print("----------------------------------------------------------------------------------------------------------")

    for s in sorted(groups.keys()):
        analysis_summary[s] = {}
        for c in sorted(groups[s].keys()):
            runs = groups[s][c]
            success_stats = compute_median_iqr([x["legit_success_rate"] for x in runs])
            p50_stats = compute_median_iqr([x["legit_p50"] for x in runs])
            p95_stats = compute_median_iqr([x["legit_p95"] for x in runs])
            cpu_busy_stats = compute_median_iqr([x["cpu_pinned_busy"] for x in runs])
            cpu_soft_stats = compute_median_iqr([x["cpu_pinned_softirq"] for x in runs])

            drop1_stats = compute_median_iqr([x["drops_layer1_nic"] for x in runs])
            drop2_stats = compute_median_iqr([x["drops_layer2_softnet"] for x in runs])
            drop3_stats = compute_median_iqr([x["drops_layer3_filter"] for x in runs])
            drop4_stats = compute_median_iqr([x["drops_layer4_socket"] for x in runs])

            analysis_summary[s][c] = {
                "sample_count": len(runs),
                "legit_success_rate": success_stats,
                "legit_p50": p50_stats,
                "legit_p95": p95_stats,
                "cpu_pinned_busy": cpu_busy_stats,
                "cpu_pinned_softirq": cpu_soft_stats,
                "drops_layer1_nic": drop1_stats,
                "drops_layer2_softnet": drop2_stats,
                "drops_layer3_filter": drop3_stats,
                "drops_layer4_socket": drop4_stats,
            }

            print(f"{s:<10} {c:<8} {len(runs):<6} "
                  f"{success_stats['median']:>5.1f}% (IQR {success_stats['iqr']:>4.1f})   "
                  f"{cpu_busy_stats['median']:>5.1f}% (IQR {cpu_busy_stats['iqr']:>4.1f})   "
                  f"{drop3_stats['median']:>10.0f}     "
                  f"{drop4_stats['median']:>10.0f}")

            csv_rows.append({
                "scenario": s,
                "config": c,
                "samples": len(runs),
                "success_median": success_stats["median"],
                "success_iqr": success_stats["iqr"],
                "p50_latency_median": p50_stats["median"],
                "p95_latency_median": p95_stats["median"],
                "cpu_busy_median": cpu_busy_stats["median"],
                "cpu_busy_iqr": cpu_busy_stats["iqr"],
                "filter_drops_median": drop3_stats["median"],
                "socket_drops_median": drop4_stats["median"],
            })

    print("----------------------------------------------------------------------------------------------------------\n")

    # Save outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_json_path = output_dir / "analysis_summary.json"
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(analysis_summary, f, indent=2)
    print(f"[SAVED] Analysis summary JSON written to: {summary_json_path}")

    csv_path = output_dir / "analysis_table.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "scenario", "config", "samples", "success_median", "success_iqr",
            "p50_latency_median", "p95_latency_median", "cpu_busy_median", "cpu_busy_iqr",
            "filter_drops_median", "socket_drops_median"
        ])
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"[SAVED] Consolidated CSV written to: {csv_path}")

    # Generate multi-panel matplotlib figure
    plot_path = output_dir / "plots" / args.plot_name
    generate_plots(analysis_summary, plot_path, title=args.title)


if __name__ == "__main__":
    main()

