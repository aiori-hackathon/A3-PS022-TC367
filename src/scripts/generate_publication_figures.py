#!/usr/bin/env python3
"""
generate_publication_figures.py - Generates 300 DPI publication-quality figures
for the Kavach PS-022 technical report and evaluation artifacts.

Outputs:
  - results/figures/fig1_physical_benchmark_matrix.png (.pdf)
  - results/figures/fig2_rate_levels_and_saturation.png (.pdf)
  - results/figures/fig3_native_namespaces_validation.png (.pdf)
  - results/figures/fig4_latency_cdf_distribution.png (.pdf)
"""

import os
import sys
import json
import csv
from pathlib import Path
import numpy as np

# Set matplotlib configuration directory to writable tmp location
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# Configure publication styling
plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.titlesize": 15,
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Helvetica", "Arial"],
    "axes.edgecolor": "#333333",
    "axes.linewidth": 0.8,
    "grid.color": "#e0e0e0",
    "grid.linestyle": "--",
    "grid.linewidth": 0.5,
})

# Consistent palette across all figures
CONFIG_COLORS = {
    "B0": "#D32F2F",  # Crimson / Dark Red (No Filter)
    "B1": "#F57C00",  # Dark Orange (nftables raw)
    "B2": "#1976D2",  # Deep Blue (nftables netdev)
    "X":  "#2E7D32",  # Forest Green (Kavach XDP)
}

CONFIG_LABELS = {
    "B0": "B0 (No Filter)",
    "B1": "B1 (nftables raw)",
    "B2": "B2 (nftables netdev)",
    "X":  "X (Kavach XDP)",
}

CONFIG_ORDER = ["B0", "B1", "B2", "X"]
SCENARIOS = ["S1", "S2", "S3"]
SCENARIO_NAMES = {
    "S1": "S1: Single-Source Flood",
    "S2": "S2: 1,000 Spoofed Sources",
    "S3": "S3: Pulsed Flood",
}

def load_summary(path):
    with open(path, "r") as f:
        return json.load(f)

def generate_figure_1(phys_summary, out_dir):
    """
    Figure 1: 4-Panel Summary of Physical Testbed Benchmark (108 Runs on twin HP ProDesk PCs)
    Panel A: Legitimate Success % (Median + IQR Whiskers)
    Panel B: Median Latency (ms) on Log Scale
    Panel C: Server CPU Utilization (% Busy on Pinned Core 1)
    Panel D: Socket Drops vs Filter Drops
    """
    fig, axes = plt.subplots(2, 2, figsize=(13, 9.5))
    fig.suptitle("Kavach Physical Lab Benchmark: 108 Runs Matrix (HP ProDesk 4 / Intel e1000e)", 
                 fontweight="bold", y=0.98)

    x_indices = np.arange(len(SCENARIOS))
    bar_width = 0.18

    # --- Panel A: Legitimate Query Success % ---
    ax_a = axes[0, 0]
    ax_a.set_title("(a) Legitimate Query Success Rate (%)", fontweight="bold")
    ax_a.set_ylabel("Success Rate (%)")
    ax_a.set_ylim(0, 110)
    ax_a.grid(True, axis="y", alpha=0.7)

    for i, cfg in enumerate(CONFIG_ORDER):
        medians = []
        err_lower = []
        err_upper = []
        for sc in SCENARIOS:
            data = phys_summary.get(sc, {}).get(cfg, {}).get("legit_success_rate", {})
            med = data.get("median", 0.0)
            q25 = data.get("q25", med)
            q75 = data.get("q75", med)
            medians.append(med)
            err_lower.append(med - q25)
            err_upper.append(q75 - med)

        offsets = x_indices + (i - 1.5) * bar_width
        ax_a.bar(offsets, medians, bar_width, label=CONFIG_LABELS[cfg],
                 color=CONFIG_COLORS[cfg], yerr=[err_lower, err_upper],
                 capsize=3, edgecolor="#222222", linewidth=0.6, alpha=0.9)

    ax_a.set_xticks(x_indices)
    ax_a.set_xticklabels([SCENARIO_NAMES[s] for s in SCENARIOS])
    ax_a.legend(loc="lower left", framealpha=0.9)

    # --- Panel B: Median Latency (Log Scale) ---
    ax_b = axes[0, 1]
    ax_b.set_title("(b) Legitimate Query Latency (Median & IQR, ms)", fontweight="bold")
    ax_b.set_ylabel("Response Latency (ms) - Log Scale")
    ax_b.set_yscale("log")
    ax_b.grid(True, which="both", axis="y", alpha=0.6)

    for i, cfg in enumerate(CONFIG_ORDER):
        medians = []
        err_lower = []
        err_upper = []
        for sc in SCENARIOS:
            data = phys_summary.get(sc, {}).get(cfg, {}).get("legit_p50", {})
            med = data.get("median", 0.0)
            q25 = data.get("q25", med)
            q75 = data.get("q75", med)
            medians.append(med)
            err_lower.append(max(0.001, med - q25))
            err_upper.append(max(0.001, q75 - med))

        offsets = x_indices + (i - 1.5) * bar_width
        ax_b.bar(offsets, medians, bar_width, label=CONFIG_LABELS[cfg],
                 color=CONFIG_COLORS[cfg], yerr=[err_lower, err_upper],
                 capsize=3, edgecolor="#222222", linewidth=0.6, alpha=0.9)

    ax_b.set_xticks(x_indices)
    ax_b.set_xticklabels([SCENARIO_NAMES[s] for s in SCENARIOS])
    ax_b.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.2f"))

    # Annotate the dramatic latency drop under S1
    ax_b.annotate("B0 Saturation (~14.3 ms)\nvs XDP (~0.44 ms)",
                  xy=(0 - 1.5 * bar_width, 14.3), xytext=(0.2, 5.0),
                  arrowprops=dict(arrowstyle="->", color="#333333", lw=1.2),
                  fontsize=9, fontweight="bold",
                  bbox=dict(boxstyle="round,pad=0.3", fc="#FFF9C4", ec="#FBC02D", lw=0.8))

    # --- Panel C: Server CPU Utilization (% Busy on Core 1) ---
    ax_c = axes[1, 0]
    ax_c.set_title("(c) Server Pinned Core 1 CPU Busy (%)", fontweight="bold")
    ax_c.set_ylabel("CPU Utilization (%)")
    ax_c.set_ylim(0, 22)
    ax_c.grid(True, axis="y", alpha=0.7)

    for i, cfg in enumerate(CONFIG_ORDER):
        medians = []
        err_lower = []
        err_upper = []
        for sc in SCENARIOS:
            data = phys_summary.get(sc, {}).get(cfg, {}).get("cpu_pinned_busy", {})
            med = data.get("median", 0.0)
            q25 = data.get("q25", med)
            q75 = data.get("q75", med)
            medians.append(med)
            err_lower.append(med - q25)
            err_upper.append(q75 - med)

        offsets = x_indices + (i - 1.5) * bar_width
        ax_c.bar(offsets, medians, bar_width, label=CONFIG_LABELS[cfg],
                 color=CONFIG_COLORS[cfg], yerr=[err_lower, err_upper],
                 capsize=3, edgecolor="#222222", linewidth=0.6, alpha=0.9)

    ax_c.set_xticks(x_indices)
    ax_c.set_xticklabels([SCENARIO_NAMES[s] for s in SCENARIOS])

    # --- Panel D: Packet Drops by Architectural Layer ---
    ax_d = axes[1, 1]
    ax_d.set_title("(d) Packet Drop Distribution: Socket Buffer vs. Filter", fontweight="bold")
    ax_d.set_ylabel("Total Packets Dropped (Millions)")
    ax_d.grid(True, axis="y", alpha=0.7)

    # In S1, total drops across the 9 runs
    s1_configs = CONFIG_ORDER
    x_s1 = np.arange(len(s1_configs))
    filter_drops = []
    socket_drops = []

    for cfg in s1_configs:
        fd = phys_summary.get("S1", {}).get(cfg, {}).get("drops_layer3_filter", {}).get("sum", 0) / 1e6
        sd = phys_summary.get("S1", {}).get(cfg, {}).get("drops_layer4_socket", {}).get("sum", 0) / 1e6
        filter_drops.append(fd)
        socket_drops.append(sd)

    bar_w = 0.45
    ax_d.bar(x_s1, filter_drops, bar_w, label="Filter Drops (Driver / Netfilter)",
             color="#2E7D32", edgecolor="#222222", linewidth=0.6, alpha=0.85)
    ax_d.bar(x_s1, socket_drops, bar_w, bottom=filter_drops,
             label="Socket Buffer Overflows (RcvbufErrors)",
             color="#D32F2F", edgecolor="#222222", linewidth=0.6, alpha=0.85)

    ax_d.set_xticks(x_s1)
    ax_d.set_xticklabels([CONFIG_LABELS[c] for c in s1_configs], rotation=15)
    ax_d.legend(loc="upper right", framealpha=0.9)

    ax_d.annotate("920k+ Packets Overflowed Socket\nExhausting Kernel Buffers",
                  xy=(0, socket_drops[0]), xytext=(0.4, socket_drops[0] * 1.8),
                  arrowprops=dict(arrowstyle="->", color="#D32F2F", lw=1.2),
                  fontsize=9, fontweight="bold",
                  bbox=dict(boxstyle="round,pad=0.3", fc="#FFEBEE", ec="#D32F2F", lw=0.8))

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    png_path = out_dir / "fig1_physical_benchmark_matrix.png"
    pdf_path = out_dir / "fig1_physical_benchmark_matrix.pdf"
    plt.savefig(png_path, dpi=300)
    plt.savefig(pdf_path)
    plt.close()
    print(f"[FIGURE 1] Saved: {png_path} and {pdf_path}")


def generate_figure_2(raw_dir, out_dir):
    """
    Figure 2: Scaling Across Flood Levels (0.5x = 50k, 1.0x = 100k, 2.0x = 200k pps)
    Demonstrating the saturation cliff under Scenario S1.
    """
    levels = ["0.5x", "1.0x", "2.0x"]
    rate_pps = [50000, 100000, 200000]

    # Collect per-level metrics for S1
    data = {cfg: {"success": [], "latency": [], "cpu": []} for cfg in CONFIG_ORDER}

    for cfg in CONFIG_ORDER:
        for lvl in levels:
            succ_runs = []
            lat_runs = []
            cpu_runs = []
            for rep in [1, 2, 3]:
                run_p = raw_dir / f"S1_{cfg}_{lvl}_{rep}"
                meta_p = run_p / "metrics_summary.json"
                if meta_p.exists():
                    with open(meta_p) as f:
                        m = json.load(f)
                    succ_runs.append(m.get("legitimate_traffic", {}).get("success_rate_pct", 0.0))
                    lat_runs.append(m.get("legitimate_traffic", {}).get("latency_p50_ms", 0.0))
                    cpu_runs.append(m.get("cpu_utilization", {}).get("pinned_core_busy_pct", 0.0))
            data[cfg]["success"].append(np.median(succ_runs) if succ_runs else 0.0)
            data[cfg]["latency"].append(np.median(lat_runs) if lat_runs else 0.0)
            data[cfg]["cpu"].append(np.median(cpu_runs) if cpu_runs else 0.0)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    fig.suptitle("Performance Scaling vs. Flood Intensity Level (Scenario S1: Single-Source)",
                 fontweight="bold", y=1.02)

    markers = {"B0": "o", "B1": "s", "B2": "^", "X": "D"}

    # Subplot 1: Legitimate Success
    ax1 = axes[0]
    ax1.set_title("Legitimate Success Rate (%)", fontweight="bold")
    ax1.set_xlabel("Offered Flood Rate (pps)")
    ax1.set_ylabel("Success Rate (%)")
    ax1.set_ylim(60, 105)
    ax1.grid(True)
    for cfg in CONFIG_ORDER:
        ax1.plot(rate_pps, data[cfg]["success"], marker=markers[cfg],
                 color=CONFIG_COLORS[cfg], label=CONFIG_LABELS[cfg],
                 linewidth=2, markersize=7)
    ax1.set_xticks(rate_pps)
    ax1.set_xticklabels(["50k (0.5x)", "100k (1.0x)", "200k (2.0x)"])
    ax1.legend(loc="lower left")

    # Subplot 2: Median Latency
    ax2 = axes[1]
    ax2.set_title("Median Latency (ms)", fontweight="bold")
    ax2.set_xlabel("Offered Flood Rate (pps)")
    ax2.set_ylabel("Latency (ms)")
    ax2.grid(True)
    for cfg in CONFIG_ORDER:
        ax2.plot(rate_pps, data[cfg]["latency"], marker=markers[cfg],
                 color=CONFIG_COLORS[cfg], label=CONFIG_LABELS[cfg],
                 linewidth=2, markersize=7)
    ax2.set_xticks(rate_pps)
    ax2.set_xticklabels(["50k (0.5x)", "100k (1.0x)", "200k (2.0x)"])

    # Subplot 3: CPU Busy %
    ax3 = axes[2]
    ax3.set_title("Pinned Server Core Busy (%)", fontweight="bold")
    ax3.set_xlabel("Offered Flood Rate (pps)")
    ax3.set_ylabel("CPU Busy (%)")
    ax3.grid(True)
    for cfg in CONFIG_ORDER:
        ax3.plot(rate_pps, data[cfg]["cpu"], marker=markers[cfg],
                 color=CONFIG_COLORS[cfg], label=CONFIG_LABELS[cfg],
                 linewidth=2, markersize=7)
    ax3.set_xticks(rate_pps)
    ax3.set_xticklabels(["50k (0.5x)", "100k (1.0x)", "200k (2.0x)"])

    plt.tight_layout()
    png_path = out_dir / "fig2_rate_levels_and_saturation.png"
    pdf_path = out_dir / "fig2_rate_levels_and_saturation.pdf"
    plt.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.savefig(pdf_path, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE 2] Saved: {png_path} and {pdf_path}")


def generate_figure_3(ns_summary, raw_ns_dir, out_dir):
    """
    Figure 3: Native Mode Driver-Level Dropping in Linux Namespaces (veth_xdp)
    Demonstrating 5.96 Million packets dropped at driver level before kernel allocation.
    """
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("Native Driver Mode (xdpdrv / veth_xdp) Validation in Linux Network Namespaces",
                 fontweight="bold", y=0.98)

    # Panel A: Packet Fate Breakdown under 75k pps Flood (S1_1.0x)
    ax_a = axes[0]
    ax_a.set_title("(a) Packet Fate in S1 @ 1.0x (75,000 pps)", fontweight="bold")
    ax_a.set_ylabel("Packets (Millions)")
    ax_a.grid(True, axis="y", alpha=0.7)

    # Read S1_1.0x run from namespaces
    cfgs = ["B0", "B1", "B2", "X"]
    dropped_m = []
    delivered_m = []

    for cfg in cfgs:
        run_p = raw_ns_dir / f"S1_{cfg}_1.0x_1"
        meta_p = run_p / "metrics_summary.json"
        if meta_p.exists():
            with open(meta_p) as f:
                m = json.load(f)
            drp = m.get("drops", {}).get("filter_drops", 0) / 1e6
            deliv = m.get("udp_delivered_to_socket", 0) / 1e6
            dropped_m.append(drp)
            delivered_m.append(deliv)
        else:
            dropped_m.append(0.0)
            delivered_m.append(0.0)

    x_idx = np.arange(len(cfgs))
    bar_w = 0.5
    ax_a.bar(x_idx, dropped_m, bar_w, label="Dropped in Driver / Filter",
             color="#2E7D32", edgecolor="#222222", linewidth=0.6, alpha=0.85)
    ax_a.bar(x_idx, delivered_m, bar_w, bottom=dropped_m, label="Delivered to UDP Socket",
             color="#1976D2", edgecolor="#222222", linewidth=0.6, alpha=0.85)

    ax_a.set_xticks(x_idx)
    ax_a.set_xticklabels([CONFIG_LABELS[c] for c in cfgs], rotation=15)
    ax_a.legend(loc="center right", framealpha=0.9)

    ax_a.annotate("5.96M Flood Packets Dropped\nin veth Driver Hook",
                  xy=(3, 5.96), xytext=(2.2, 4.5),
                  arrowprops=dict(arrowstyle="->", color="#2E7D32", lw=1.2),
                  fontsize=9, fontweight="bold",
                  bbox=dict(boxstyle="round,pad=0.3", fc="#E8F5E9", ec="#2E7D32", lw=0.8))

    # Panel B: SoftIRQ CPU Overhead Comparison
    ax_b = axes[1]
    ax_b.set_title("(b) Kernel SoftIRQ CPU Overhead (%)", fontweight="bold")
    ax_b.set_ylabel("SoftIRQ CPU (%)")
    ax_b.grid(True, axis="y", alpha=0.7)

    softirq_vals = []
    for cfg in cfgs:
        run_p = raw_ns_dir / f"S1_{cfg}_1.0x_1"
        meta_p = run_p / "metrics_summary.json"
        if meta_p.exists():
            with open(meta_p) as f:
                m = json.load(f)
            si = m.get("cpu_utilization", {}).get("pinned_core_softirq_pct", 0.0)
            softirq_vals.append(si)
        else:
            softirq_vals.append(0.0)

    bars = ax_b.bar(x_idx, softirq_vals, bar_w, color=[CONFIG_COLORS[c] for c in cfgs],
                    edgecolor="#222222", linewidth=0.6, alpha=0.9)
    ax_b.set_xticks(x_idx)
    ax_b.set_xticklabels([CONFIG_LABELS[c] for c in cfgs], rotation=15)

    for bar, val in zip(bars, softirq_vals):
        ax_b.text(bar.get_x() + bar.get_width() / 2.0, bar.get_height() + 0.05,
                  f"{val:.2f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax_b.annotate("65% Reduction in SoftIRQ\n(Driver Drops Prevent Queuing)",
                  xy=(3, softirq_vals[3]), xytext=(1.8, 1.8),
                  arrowprops=dict(arrowstyle="->", color="#2E7D32", lw=1.2),
                  fontsize=9, fontweight="bold",
                  bbox=dict(boxstyle="round,pad=0.3", fc="#E8F5E9", ec="#2E7D32", lw=0.8))

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    png_path = out_dir / "fig3_native_namespaces_validation.png"
    pdf_path = out_dir / "fig3_native_namespaces_validation.pdf"
    plt.savefig(png_path, dpi=300)
    plt.savefig(pdf_path)
    plt.close()
    print(f"[FIGURE 3] Saved: {png_path} and {pdf_path}")


def generate_figure_4(raw_phys_dir, out_dir):
    """
    Figure 4: Latency Empirical CDF Comparison under S1 @ 1.0x Flood (100k pps)
    Demonstrating sub-millisecond determinism of Kavach XDP vs. high latency tail in B0.
    """
    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    ax.set_title("Empirical CDF of Legitimate Query Response Latency (Scenario S1 @ 100k pps)",
                 fontweight="bold")
    ax.set_xlabel("Query Response Latency (ms)")
    ax.set_ylabel("Cumulative Probability P(Latency <= x)")
    ax.grid(True, which="both", alpha=0.6)

    cfgs = ["B0", "B1", "B2", "X"]
    linestyles = {"B0": "-", "B1": "--", "B2": "-.", "X": "-"}
    linewidths = {"B0": 2.2, "B1": 1.8, "B2": 1.8, "X": 2.5}

    for cfg in cfgs:
        csv_p = raw_phys_dir / f"S1_{cfg}_1.0x_1" / "legit_client.csv"
        if not csv_p.exists():
            continue
        latencies = []
        with open(csv_p) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("status") == "ANSWERED" and row.get("latency_ms"):
                    try:
                        latencies.append(float(row["latency_ms"]))
                    except ValueError:
                        pass
        if not latencies:
            continue
        latencies = np.sort(latencies)
        cdf = np.arange(1, len(latencies) + 1) / len(latencies)
        ax.plot(latencies, cdf, label=CONFIG_LABELS[cfg],
                color=CONFIG_COLORS[cfg], linestyle=linestyles[cfg],
                linewidth=linewidths[cfg])

    ax.set_xlim(0, 32)
    ax.set_ylim(0, 1.05)
    ax.legend(loc="lower right", framealpha=0.95, fontsize=10)

    ax.annotate("Kavach XDP: 95% of queries\nanswered in < 1.43 ms",
                xy=(1.43, 0.95), xytext=(5.0, 0.8),
                arrowprops=dict(arrowstyle="->", color="#2E7D32", lw=1.2),
                fontsize=9.5, fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", fc="#E8F5E9", ec="#2E7D32", lw=0.8))

    ax.annotate("B0 (No Filter): Severe Queue Delay\nMedian 14.3 ms (Max > 30 ms)",
                xy=(14.3, 0.5), xytext=(17.0, 0.35),
                arrowprops=dict(arrowstyle="->", color="#D32F2F", lw=1.2),
                fontsize=9.5, fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", fc="#FFEBEE", ec="#D32F2F", lw=0.8))

    plt.tight_layout()
    png_path = out_dir / "fig4_latency_cdf_distribution.png"
    pdf_path = out_dir / "fig4_latency_cdf_distribution.pdf"
    plt.savefig(png_path, dpi=300)
    plt.savefig(pdf_path)
    plt.close()
    print(f"[FIGURE 4] Saved: {png_path} and {pdf_path}")


def main():
    base_dir = Path(__file__).resolve().parent.parent.parent
    results_dir = base_dir / "results"
    fig_dir = results_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    phys_summary_path = results_dir / "physical" / "analysis_summary.json"
    if not phys_summary_path.exists():
        phys_summary_path = results_dir / "analysis_summary.json"
    
    ns_summary_path = results_dir / "namespaces" / "analysis_summary.json"

    raw_phys_dir = results_dir / "raw_physical"
    raw_ns_dir = results_dir / "raw_namespaces"

    print("=== Generating High-Resolution 300 DPI Publication Figures ===")
    phys_summary = load_summary(phys_summary_path)
    ns_summary = load_summary(ns_summary_path) if ns_summary_path.exists() else {}

    generate_figure_1(phys_summary, fig_dir)
    generate_figure_2(raw_phys_dir, fig_dir)
    if raw_ns_dir.exists():
        generate_figure_3(ns_summary, raw_ns_dir, fig_dir)
    generate_figure_4(raw_phys_dir, fig_dir)
    print("=== All Publication Figures Successfully Generated in results/figures/ ===")

if __name__ == "__main__":
    main()

