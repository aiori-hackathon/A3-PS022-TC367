# Person B Status & Handoff to B4 Matrix Execution

**Role:** Person B (Lab Bring-Up, Traffic Generation, Baselines, Benchmarking & Telemetry)  
**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods (PS-022)  
**Submission ID:** A3-PS022-TC367  
**Date:** 29 October 2026  

---

## 1. Milestones Completed by Person B

### Phase B1 (Mon 26 Oct)
- Initialized unified repository layout, `.gitignore`, and shared contract.
- Built development network namespace testbed (`gen` <-> `srv` via `veth` pair in `src/scripts/setup_env.sh`).
- Configured authoritative NSD server (`src/dns/nsd.conf`) with RFC 1035 zone file (`lab.test.zone`) and Response Rate Limiting (RRL) disabled.
- Implemented open-loop legitimate client (`src/traffic/legit_client.py`) generating Poisson/fixed 100 QPS with nanosecond-resolution latency tracking.
- Implemented multi-layer telemetry metric collector (`src/scripts/collect_metrics.py`) capturing CPU (`mpstat`), driver queue drops (`ethtool -S`), softnet stats (`/proc/net/softnet_stat`), socket errors (`/proc/net/snmp`), and firewall counters.
- Executed B0 fact collector script on physical HP ProDesk workstations, uncovering Ubuntu 24.04 OEM kernel (`6.14.0-1020-oem`), single NIC interface (`eno1`), and `powersave` governor.

### Phase B2 (Tue 27 Oct)
- Implemented high-performance synthetic flood generators in C (`src/traffic/kavach_gen.c`) with non-bypassable destination and source guards (`src/traffic/guard.sh` and `src/traffic/guard.py` enforcing `10.99.0.0/24` destination and `198.18.0.0/15` synthetic source ranges).
- Formulated parameterized baseline firewall scripts:
  - **B0:** `src/baselines/none.sh` (No filter).
  - **B1:** `src/baselines/b1_prerouting.sh` (nftables prerouting raw table, conntrack bypassed).
  - **B2:** `src/baselines/b2_netdev.sh` (nftables netdev ingress table).
- Built automated Experiment Orchestrator v1 (`src/scripts/orchestrator.py`) supporting seeded random execution order, temporal phases (warmup, 60s measurement, cooldown), and multi-layer telemetry recording.
- Successfully executed 12-run unattended dry run matrix in development namespaces and produced statistical analysis (`analyze.py`).

### Phase B3 (Wed 28 Oct - Thu 29 Oct)
- Engineered physical host tuning utility (`src/scripts/pin_core.sh`) binding NIC IRQ `0000:80:1f.6` to Core 1, forcing `performance` CPU governor across all 14 cores, and disabling `unattended-upgrades`.
- Upgraded DNS scripts to `--host` and `--iface` mode for bare-metal execution on physical `eno1`.
- Built automated calibration harness (`src/scripts/calibrate.py`) and executed empirical flood ramp on physical link.
- **Empirical Saturation Threshold:** Identified $S = 100,000$ pps under Baseline B0 (query success collapsed to $86.92\%$ and median latency surged $27\times$ to $14.055$ ms).
- **Physical Generator Ceiling:** Discovered raw socket single-core limit of $\sim 198,935$ pps, locking matrix levels to $[50\text{k}, 100\text{k}, 200\text{k}]$ pps.
- **Driver Finding:** Confirmed Intel `e1000e` operates in `xdpgeneric` (generic mode) on Linux kernel `6.14.0-1020-oem`.
- Built lightweight network target daemon (`src/scripts/target_daemon.py`) for automated remote orchestration across the isolated offline link.
- Executed physical smoke test across all 4 configurations (**B0**, **B1**, **B2**, **X**), proving Kavach XDP achieves 100% legitimate query resolution with $p50 = 0.409$ ms (15% faster than nftables).
- Synchronized parameters to `src/params.yaml` / `params.json`, archived raw data to `results/raw/smoke_S1_*` and calibration to `results/calibration/`, and logged ADR-024 through ADR-027.

---

## 2. Transition to Phase B4: Main Matrix Execution

Person B is completely unblocked and ready to execute the main benchmark matrix on the lab hardware.
See `docs/person-b/B4_READINESS.md` for dependency audit and `docs/person-b/B4_RUNBOOK.md` for the exact operational steps.
