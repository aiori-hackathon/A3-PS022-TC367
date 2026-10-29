# Phase B4 Readiness & Person A Dependency Audit

**Project:** Kavach - eBPF/XDP Rate Limiting for DNS Query Floods  
**Submission ID:** A3-PS022-TC367  
**Question:** *"Do I need anything from Person A before going ahead with B4?"*  
**Verdict:** **NO. Person B has ZERO blocking dependencies on Person A and is 100% ready to execute Phase B4.**

---

## 1. Deliverables Audit from Person A

Per `src/AGENTS.md` Section 13 (Roles and plans), Person A was responsible for Phases A1, A2, and A3:

| Component / Artifact | Expected Deliverable | Verification Status in Phase B3 | Ready for B4? |
|---|---|---|---|
| **eBPF Kernel Program** | `xdp/kavach_xdp.c`, `kavach_xdp.o` | Compiled with `-mcpu=v3`, verified against kernel verifier. | **YES (Frozen)** |
| **Dual-Tier GCRA Algorithm** | `xdp/gcra.h` | 64-bit atomic integer CAS limiter, verified under S1 flood. | **YES (Frozen)** |
| **User-Space Controller CLI** | `xdp/kavach_ctl.py` | Implements `load`, `attach`, `config`, `stats`, `detach`, and watchdog (with dynamic `bpftool` discovery for kernel 6.14). | **YES (Frozen)** |
| **Config ABI & Pinned Maps** | 40-byte binary struct | Tested via `kavach_ctl.py config` reading `src/params.yaml`. | **YES (Frozen)** |
| **Telemetry Stats Contract** | 14-counter CSV dump | Tested in Phase B3 smoke run, outputs complete 14-column CSV. | **YES (Frozen)** |
| **Generic XDP Support** | Fallback attach mode | Successfully attached to physical Intel `eno1` in `xdpgeneric` mode. | **YES (Frozen)** |

**Conclusion:** Person A's code is already integrated, compiled, and empirically proven to work on the physical lab workstations during Phase B3.

---

## 2. Parameter Self-Containment

All experimental parameters required for Phase B4 are locked in `src/params.yaml` and `src/params.json`:
- $S = 100,000$ pps
- Levels: $[50\text{k}, 100\text{k}, 200\text{k}]$ pps
- `src_rate`: $500$ pps
- `glob_rate`: $70,000$ pps
- `burst`: $20$ pkts
- Run duration: $60$s (measurement window), $10$s warmup, $10$s cooldown.

Both `kavach_ctl.py` (Person A's controller) and `orchestrator.py` (Person B's runner) consume these files without hardcoded dependencies.

---

## 3. Physical Lab Infrastructure Ownership

Person B independently owns and operates:
1. **Physical Hosts:** PC 1 (`10.99.0.2`) and PC 2 (`10.99.0.1`) with Core 1 affinity via `pin_core.sh`.
2. **DNS Server:** NSD on bare-metal host with zero RRL (`src/dns/start_dns.sh --host`).
3. **Baselines:** B0 (`none.sh`), B1 (`b1_prerouting.sh`), B2 (`b2_netdev.sh`).
4. **Traffic Generation:** `kavach_gen` (C binary) with `guard.sh` boundary safety.
5. **Orchestration:** `src/scripts/orchestrator.py` communicating over TCP `10.99.0.2:9999` with `target_daemon.py`.
6. **Telemetry & Metrics:** `collect_metrics.py` and `analyze.py`.

---

## 4. Person A's Parallel Role During Phase B4

While Person B executes the matrix runs in the offline lab, Person A is scheduled to work on:
- Phase A4: Drafting report sections (system architecture, bounded parsing rationale, integer-only GCRA formulation, CAS concurrency analysis, and limitations).
- Assisting in counter verification from raw logs once data is extracted.

**Summary:** Person B can proceed directly to running Phase B4 without waiting for any new code, configuration, or input from Person A.

