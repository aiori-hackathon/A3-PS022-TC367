# Kavach: PS-022 Project Context (for AI coding agents)

**Project:** eBPF/XDP Rate Limiting for DNS Query Floods in a Lab
**Event:** AIORI Hackathon 3 (AIORI-3), category Cybersecurity
**Team name / submission name:** Kavach  |  **Submission ID:** A3-PS022-TC367
**Team:** 2 students (Keerthi Virupapura, U Kruthik), BMS College of Engineering, CSE; faculty mentor Dr. Manjunath D R
**Document date:** 26 October 2026 (Monday)  |  **Deadline:** 31 October 2026  |  **Practical submit target:** Friday 30 October 2026

> This file was written from the team's planning conversation. If it conflicts with the official problem statement (PS-022 PDF), the problem statement wins.
> Markers: **[DECISION]** = team has decided or must decide; **[VERIFY]** = depends on lab hardware/kernel or on facts that must be checked before relying on them.
> Nothing here is a measured result. All performance claims are hypotheses until the experiments produce data.

---

## 0. Read this first (30-second summary)

- We build a small **XDP/eBPF program (C)** that parses UDP/53 DNS packets with **bounded parsing** and applies a **per-source** and a **global** rate limit, dropping excess packets **in the NIC driver before the kernel allocates an sk_buff**.
- We benchmark it on a **controlled, isolated pair of Linux hosts** against two baselines (**no filter** and **nftables**) under **three synthetic flood patterns**, measuring **CPU, throughput, packet drops, and legitimate-query success**.
- Deliverables: private GitHub repo, a PDF report in the organizers' structure, and a live demo with a pseudocode snippet.
- **Time is very short:** about 4 working days remain (26-30 Oct, 31 Oct buffer). The plan has been compressed (section 14).
- Two roles: **Person A = XDP program + loader**, **Person B = lab, traffic, baselines, measurement**.
- Hard safety rule: **no flooding outside the isolated lab link, ever** (section 3).

---

## 1. Problem statement (PS-022, condensed)

High-volume UDP DNS query floods saturate Linux servers because the kernel spends substantial CPU allocating socket buffers (sk_buff) before packets reach user space. XDP runs eBPF bytecode inside the NIC driver, so packets can be processed or dropped before kernel memory allocation. The project: build an XDP filter on a Linux host pair that performs **bounded UDP DNS parsing**, apply **per-source and global rate limits** across **three synthetic query-flood patterns**, and benchmark **CPU utilization, packet drops, and legitimate-query success** against **nftables** and **no-filter** baselines.

**Key requirements (from the PS):**
1. Use 1 Linux host pair in a controlled lab.
2. Implement bounded UDP/DNS packet parsing.
3. Support per-source and global rate limits.
4. Test 3 synthetic DNS load patterns.
5. Compare XDP against no-filter and nftables baselines under identical conditions.
6. Use an XDP-capable kernel/NIC, **or document generic-mode setup**.
7. Measure throughput, CPU usage, legitimate-query success and packet drops.
8. **Not allowed / not claimed:** public flood testing, full DNS semantic parsing, universal PRSD (random-subdomain) detection, any claim of eliminating reflection attacks.

**Expected outcomes:** eBPF/XDP rate-limiting program; controlled DNS traffic-generation harness; no-filter and nftables baseline configurations; three synthetic load scenarios; performance measurements and comparison; analysis of legitimate-query impact; technical report and demonstration.

**Deliverables (all required for the participation certificate):**
1. GitHub collaboration: private repo **named after the team**; add `https://github.com/aiori-hackathon` as collaborator; once accepted, all teammates and that account **transfer ownership** of the repo to `aiori-hackathon`. Mentors oversee progress through the repo, so **commit at least daily**.
2. A **PDF uploaded to the repo**, following the organizers' file `Proposed-structure-hackathon.pdf` (**[VERIFY]** obtain this file; not yet in our hands).
3. **Prototype demonstration with a pseudocode snippet** to the mentor.

Reference given by the PS: https://docs.kernel.org/bpf/

---

## 2. What has already been submitted

A 12-slide presentation (ID A3-PS022-TC367, dated 10-11 Oct 2026) has been submitted: Problem Description, Background, Literature & RFC Review, Proposed Solution (text + decision flowchart), Optimization Proposed (before/after table), Solution Architecture & Design, Data Flow Diagram, Deployment Timeline, Bibliography, Thank You. Everything in this document is consistent with that deck. Known typos in the deck (not fixed in the submitted file): slide 4 "eXPD"/"wrte-ups", slide 7 "stak" and "any order" (should say **randomised order**).

The deck's Deployment Timeline (6-30 Oct) is now **obsolete**; use section 14.

---

## 3. Hard rules and safety (non-negotiable)

1. **All flood traffic stays on an isolated link** between the two lab machines (or between two network namespaces on one machine during development). No route to campus network or internet. No IP forwarding between the test link and any other network.
2. **Never attach XDP to the management/SSH/campus-facing interface.** Only the dedicated test NIC. First attach in **generic mode** with a **watchdog** that auto-detaches after N minutes unless renewed.
3. **Generator guard:** every traffic-generation script has a fixed destination and **refuses any destination outside the lab subnet** (default test subnet `10.99.0.0/24`). This is a safeguard against mistakes, not the main security boundary; the isolated link is.
4. **Synthetic source addresses** come only from `198.18.0.0/15` (reserved for benchmarking), only inside the isolated lab.
5. **Replies must not escape:** spoofed-source queries make the server reply to fake addresses. The server's default route is only via the generator host/namespace; the generator has `ip_forward=0` and blocks egress.
6. **No public network testing, no random-subdomain attack detection, no full DNS parsing, no reflection-attack claims.**
7. Lab PCs: written permission from lab admin and mentor approval before flood tests; record every system change (packages, sysctl, network config) and revert on request; do not touch other PCs, services, or existing firewall rules.
8. **Honesty:** never invent measurements. Namespace/veth results are **functional validation only**, not performance numbers. Report limitations (generic-mode savings are smaller, per-core capacity if pinned, etc.). If a hypothesis is not supported, say so.

---

## 4. Background in brief

- **Normal path:** NIC -> driver -> **sk_buff allocation** -> netfilter/nftables -> UDP socket -> DNS server. The sk_buff cost is paid for every packet, even packets dropped later. Even the earliest nftables hook (netdev ingress) runs after the sk_buff exists.
- **XDP path:** NIC -> driver -> **XDP program** -> `XDP_DROP` (discarded, no sk_buff) or `XDP_PASS` (continue on the normal path).
- **Attach modes:** *native* (driver) runs before sk_buff allocation, needs driver support, biggest saving; *generic* runs after sk_buff allocation, works on any NIC, smaller saving; *offload* needs SmartNIC (not used). Record which mode was used for every result.
- **Verifier:** the kernel rejects eBPF programs that might read outside the packet or loop without bound, so every header read is bounds-checked against `data_end` and only fixed-size headers are parsed.
- **GCRA** (generic cell rate algorithm): a rate limiter that stores one timestamp per flow (the *theoretical arrival time*, `tat`); integer math only.

---

## 5. Hypotheses (tested, not assumed)

- **H1:** in native mode, XDP spends less CPU per dropped packet than nftables.
- **H2:** under heavy flood, legitimate-query success is higher with XDP than with nftables or no filter.
- **H3:** per-source limits handle a single-source flood well but are weaker against many low-rate sources, where the global limit matters (and may also drop legitimate queries).
- **H4:** generic-mode XDP gives smaller gains than native mode.
- If only generic mode is available: evaluate H1/H2 in generic mode and label it; state H4 is untestable.

---

## 6. System architecture

```
 GENERATOR host / netns "gen"                      TARGET host / netns "srv" (device under test)
 +-------------------------------+   isolated    +------------------------------------------------+
 | legitimate probe (open-loop)  |   direct link | KERNEL: test NIC -> [XDP filter] --PASS--> Linux |
 | flood generators S1/S2/S3     | ============> |         stack (sk_buff, netfilter, UDP) -> DNS   |
 | generator guard               | <============ |         BPF maps: per-source tat (LRU hash),     |
 | run orchestrator + plots      |  DNS answers  |         global tat, config, per-CPU counters     |
 +-------------------------------+               | USER:   loader (+watchdog), collectors,          |
                                                 |         DNS server (NSD or Knot, RRL off)        |
                                                 +------------------------------------------------+
```

- One configuration is active per run: **B0** (no filter), **B1** (nftables prerouting), **B2** (nftables netdev ingress), or **X** (XDP). nftables baselines and XDP are never active together.
- Development first in network namespaces + veth on one machine; final numbers from two physical lab PCs.

---

## 7. XDP filter specification (Person A owns this)

**Language/toolchain:** restricted C, clang `-target bpf -O2 -g`, libbpf headers. Confirmed lab platform: **Ubuntu 24.04.4 LTS** with OEM kernel **6.14.0-1020-oem** (verified 27 Oct 2026; BTF enabled in `/sys/kernel/btf/vmlinux`; BPF atomic CAS supported). Clang 14/18. If you get `asm/types.h not found`, add `-I/usr/include/$(uname -m)-linux-gnu`. Ensure bytecode compiles cleanly with `-mcpu=v3`.

### 7.1 Bounded parsing

Every pointer access checked against `data_end`. No loops over DNS names; the **query name is never parsed**.

| Case | Handling |
|---|---|
| Non-IPv4, ARP, non-UDP | `XDP_PASS`, count `non_dns_passed` |
| VLAN-tagged frames | **[DECISION]** pass untouched (default) or parse one tag (stretch) |
| IP header length (IHL) > 20 bytes | compute UDP offset from IHL; never assume 20 bytes |
| Truncated IP/UDP header (cannot identify as DNS) | `XDP_PASS`, count `unparsable_passed` |
| Non-first IP fragment (no UDP header) | `XDP_PASS`, count `fragments_passed` (documented bypass); first fragments parsed normally |
| UDP dst port != 53 | `XDP_PASS`, count `non_dns_passed` |
| **Malformed DNS (team decision: DROP)**: UDP/53 with DNS payload < 12 bytes, or UDP length field inconsistent with the IP packet | `XDP_DROP`, count `malformed` |
| IPv6 | **Out of scope** (team decision). Passes unfiltered; disable IPv6 on the test interface, document as limitation. (Rationale: extension-header chains complicate bounded parsing; per-source key needs prefix aggregation; doubles test matrix.) |

### 7.2 Rate limiting: GCRA, integer math only

Per bucket store one `u64 tat` (theoretical arrival time, ns from `bpf_ktime_get_ns()`, monotonic).

```
interval  = 1e9 / rate_pps               # precomputed in user space, written to config map
tolerance = (burst - 1) * interval       # precomputed in user space
# at packet time (no division, no multiplication):
tat = max(stored_tat or now, now)        # absent entry => full burst available
if tat - now > tolerance:  DROP
else: stored_tat = tat + interval; pass this limiter
```

- **Per-source:** `BPF_MAP_TYPE_LRU_HASH`, key = source IPv4 (`u32`), value = `u64 tat`. LRU eviction bounds memory under spoofed-source floods; an evicted source restarts with a full burst (documented; LRU stress study measures it).
- **Global:** single-entry array map holding one shared `u64 tat`.
- **Check order: per-source FIRST, then global.** Reason: if global were first, packets later dropped per-source would already have drained the global bucket, and a single-source flood would starve legitimate users. A packet that passes per-source but is dropped by the global limit has still consumed its per-source slot (documented). The nftables baselines use the same order.
- **Config map (proposed layout, array of `u64`):** `[0]` src_interval_ns, `[1]` src_tolerance_ns, `[2]` glob_interval_ns, `[3]` glob_tolerance_ns, `[4]` enabled flag. Limits are changed at runtime from user space **without reloading the program**.
- **Stats map:** `PERCPU_ARRAY`, counters: `dns_seen, non_dns_passed, passed, drop_source, drop_global, malformed, fragments_passed, unparsable_passed`. User space sums across CPUs.

### 7.3 Concurrency decision (**[DECISION]**, record in `docs/decisions.md`)

Multiple CPUs can race on the same bucket. Global bucket is the worst case; per-source buckets are rarely contended.
- **Preferred try-order:** (1) compare-and-swap loop on the `u64 tat` (BPF atomics, roughly kernel >= 5.12 and clang with `-mcpu=v3`, **[VERIFY]** on lab kernel/clang 14); (2) `bpf_spin_lock` in the map value (array maps support it; support inside LRU hash value **[VERIFY]**); (3) fallback: accept approximate limiting and document it.
- **Do not** split the global rate across CPUs (result depends on RSS hashing, a single source could get a fraction of its limit).
- Measure the resulting error in a limiter-accuracy test.

### 7.4 Pseudocode (also used for the mentor demo)

```
xdp_dns_ratelimit(pkt):
    parse eth -> ip -> udp with bounds checks            # UDP offset from IHL
    if not IPv4 or not UDP or truncated headers:  return PASS
    if non-first fragment:                        count; return PASS
    if udp.dport != 53:                           return PASS
    if dns_payload_len < 12 or udp_len bad:       count malformed; return DROP

    now = ktime_get_ns()
    # per-source GCRA first
    tat = max(lru_map[src_ip] or now, now)
    if tat - now > src_tolerance:                 count drop_source; return DROP
    lru_map[src_ip] = tat + src_interval

    # global GCRA second (CAS or spin-locked)
    g = max(global_tat, now)
    if g - now > glob_tolerance:                  count drop_global; return DROP
    global_tat = g + glob_interval

    count passed; return PASS
```

### 7.5 Loader / controller contract (shared with Person B)

Default implementation: a **Python/shell wrapper around `bpftool` and `ip`** (a C/libbpf loader only if time remains). **[VERIFY]** exact syntax on the lab's bpftool:

```bash
bpftool prog loadall xdp/dns_ratelimit.bpf.o /sys/fs/bpf/kavach type xdp pinmaps /sys/fs/bpf/kavach/maps
bpftool net attach xdpgeneric pinned /sys/fs/bpf/kavach/<prog> dev <iface>   # or xdpdrv for native
bpftool net detach xdpgeneric dev <iface>
bpftool map update pinned /sys/fs/bpf/kavach/maps/config key 0 0 0 0 value ...
bpftool map dump pinned /sys/fs/bpf/kavach/maps/stats -j
```

Required commands: `load`, `attach <iface> <native|generic|auto>` (log which mode was used), `config` (per-source rate+burst, global rate+burst), `stats` (CSV every second to a file), `detach`, plus a **watchdog** that detaches after N minutes unless renewed. Interface name, mode and limits are **parameters, never hardcoded**.

**Stats CSV columns (frozen contract):**
`timestamp, dns_seen, non_dns_passed, passed, drop_source, drop_global, malformed, fragments_passed, unparsable_passed`

### 7.6 Acceptance tests for A (run in namespaces, single core)

- Compiles with clang 14; **verifier accepts on kernel 5.15** (test in an Ubuntu 22.04 VM or the lab PC).
- Crafted packets (scapy or `bpftool prog run`): non-DNS passed, valid DNS passed, malformed dropped, fragments/truncated counted and passed.
- Below the configured limit: about 100% of DNS packets pass. At 2x the limit: about 50% pass (within about +/-10%). Burst up to burst size passes.
- Two sources: a flood from one does not starve the other (check-order test).
- `config` change takes effect without reloading; `detach`/watchdog works.

---

## 8. Baselines and fairness (Person B owns this)

| Config | Description |
|---|---|
| **B0** | No filter. DNS server only. |
| **B1** | nftables, **prerouting at raw priority, no conntrack**. Common deployment. |
| **B2** | nftables, **netdev ingress** (earliest hook). Strongest nftables baseline. |
| **X** | The XDP program (native mode if available; also generic if comparison possible). |

Same numerical limits and **same burst value** across all; **verify effective limits by measurement** (nftables burst semantics differ from GCRA). Illustrative B2 ruleset (placeholder numbers; verify syntax on the installed `nft`; per-source rule first, then global, matching XDP order):

```
table netdev dnsfilter {
  set flood { type ipv4_addr; flags dynamic; size 65535; timeout 10s; }
  chain ingress {
    type filter hook ingress device "eth0" priority -500;
    udp dport 53 add @flood { ip saddr limit rate over 100/second burst 20 packets } drop
    udp dport 53 limit rate over 50000/second burst 100 packets drop
  }
}
```

The nftables dynamic set does not evict like an LRU map: with many sources it fills up (set size and timeout chosen deliberately). Note this in analysis.

**Identical conditions for every config:** `rp_filter=0` on the server in **all** configs (XDP runs before rp_filter); the DNS server's own response rate limiting **verified off** (Knot RRL is a module, off unless configured; NSD depends on build); same kernel, driver, firmware, tool versions, zone, query set, CPU governor, IRQ affinity, core pinning; state reset between runs.

---

## 9. Traffic generation (Person B owns this)

### 9.1 Legitimate client
Open-loop: sends on a fixed schedule regardless of replies, **50-200 queries/s**, from its own dedicated source IP (not in the flood set), **1-2 s timeout, no retries**, queries only for names that exist in the test zone. Late replies count as failures. Per-query log: `seq, send_ts, recv_ts, rcode, latency`. Headline metric: success rate = answered / sent in the measurement window; latency p50/p95/p99.

### 9.2 Three flood scenarios

| ID | Definition | Tests |
|---|---|---|
| **S1** single-source | one source IP, constant rate at each flood level | per-source limiter; CPU saving per dropped packet |
| **S2** distributed | N random sources from `198.18.0.0/15` (start about 1,000; stretch tens of thousands), same aggregate rate as S1, per-source rate below the per-source limit | global limiter, LRU map behavior, collateral damage to legitimate traffic |
| **S3** pulsing | one source, fixed period **P <= 10 s**, pulse sizes 0.5x, 1x, 2x the per-source burst; period long enough for a full bucket to refill; at least 5 full cycles in the 60 s window | burst parameter, fairness to bursty legitimate sources |

All use well-formed UDP/53 queries. Generators: dnsperf/flamethrower (S1, rate control), **trafgen/pktgen/custom C** for raw many-source traffic; Scapy only for functional tests. **Measure the generator's own ceiling** and monitor its CPU/TX counters so it is not the bottleneck. **[VERIFY]** ask organizers whether random-label query names count as PRSD before using them as a payload variant.

---

## 10. Calibration and parameter selection (Person B)

Calibration was completed empirically on the physical testbed (HP ProDesk 4 Core Ultra 5 245, Core 1 pinned):
1. **Host Tuning & Core Pinning:** DNS daemon (`nsd`) and network interrupts for `IR-PCI-NSI-0000:80:1f.6` (`eno1`, Intel `e1000e`) pinned strictly to **Core 1** via `pin_core.sh`.
2. **Empirical Saturation Point $S$:** Under **B0 (No Filter)**, legitimate client success maintained 100% up to 75,000 pps, then collapsed to **86.92%** at 100,000 pps (with median latency surging $27\times$ from 0.5 ms to 14.055 ms). Thus, **$S = 100,000$ pps**.
3. **Physical Generator Ceiling:** Single-threaded raw socket (`kavach_gen`) reaches $198,935$ pps across the CAT6 link on `eno1`. Over-subscribing to 500k pps causes socket ring-lock contention, reducing throughput to $\sim 125,000$ pps.
4. **Defined Matrix Levels:** $0.5\times S = 50,000$ pps, $1.0\times S = 100,000$ pps, $2.0\times S = 200,000$ pps (matching generator headroom).
5. **Configured Rate Limits:** `src_rate` = 500 pps, `glob_rate` = 70,000 pps (70% of $S$), `burst` = 20 packets.
6. **Shared Parameters:** Synchronized and locked in `src/params.yaml` and `src/params.json`.
7. **Driver Mode:** Intel `e1000e` operates in `xdpgeneric` (generic mode) on Linux kernel `6.14.0-1020-oem`.
8. **Smoke Test Verification:** Single-run smoke tests across all 4 configs (B0, B1, B2, X) under Scenario S1 @ 100k pps verified XDP achieves 100% legitimate resolution at $p50 = 0.409$ ms (15% faster than nftables B1/B2). Results archived in `results/raw/smoke_S1_*/`.

---

## 11. Measurement methodology

**Metrics:** offered load (pps); server CPU total/per-core/softirq share (mpstat); NIC rx and `rx_dropped` (`ethtool -S`); XDP drops by reason (stats map); nftables counters; `UdpInErrors`/`RcvbufErrors` (`/proc/net/snmp`, `nstat`); generic-mode drops (`/proc/net/softnet_stat`); answered queries/s; legitimate success % and latency p50/p95/p99; limiter accuracy (passed vs configured rate); derived CPU per processed packet; and **drops by layer** (XDP vs NIC vs nftables vs socket buffer), likely the most informative result.

**Run protocol (every run):**
1. **Reset:** detach XDP, clear maps/counters, flush nftables, restart DNS server, clear neighbor entries and conntrack.
2. Apply the configuration under test.
3. Warm-up **10 s** with legitimate traffic only.
4. Start flood; measure for a fixed **60 s** window.
5. Cool-down 10 s; stop collectors; save to `results/raw/<scenario>_<config>_<level>_<rep>/`.
- Raw data is **never edited**; failed runs are logged and re-run, not dropped. Record kernel, NIC, driver, XDP mode, limits, params file and git commit with each run.
- **Randomised run order** (seeded shuffle, order logged); fixed CPU governor; median + IQR (or min-max) across repetitions.

**Experiment matrix (compressed tiers):**

| Tier | Runs | Approx. time (about 100 s/run incl. reset) |
|---|---|---|
| **Target** | 4 configs x 3 scenarios x 3 levels (0.5x,1x,2x) x 3 reps = **108** | about 3 h |
| **Fallback** (drop B1) | 3 configs x 3 x 3 x 3 = **81** | about 2.3 h |
| **Minimum viable** | B0,B2,X x 3 scenarios x 2 levels (1x,2x) x 2 reps = **36** | about 1 h |

(The original plan was 240 runs; the submitted deck still says 240 and 5 reps. The report must state the reduced matrix honestly.) Extras (saturation curves, collateral-damage study, limiter accuracy, native vs generic, LRU stress, live dashboard) are **cut** unless everything else is done early.

---

## 12. Environments

### 12.1 Development: namespaces + veth (any Linux, e.g. Person B's Arch PC)
Functional validation only (generator and server share CPU; veth bypasses a real NIC). Use `taskset` to separate cores.

```bash
# Automated scripts available in src/scripts/:
sudo ./src/scripts/setup_env.sh      # creates gen + srv, vgen + vsrv, sets rp_filter=0, disables offloads
sudo ./src/scripts/status_env.sh     # displays link states, IP addresses, sysctls, ping status
sudo ./src/scripts/teardown_env.sh   # cleanly terminates namespace processes and deletes links
```
Checks: `sudo ip netns exec gen ping -c2 10.99.0.2`; `sudo ip netns exec gen dig @10.99.0.2 www.lab.test`.

**Caution:** an Arch (rolling) kernel/clang is newer than Ubuntu 22.04's. A program that loads on Arch can still be **rejected by the 5.15 verifier**. Test A's code in an Ubuntu 22.04 VM (QEMU/virt-manager) or on the lab PC as early as possible.

### 12.2 Final: two physical lab PCs (Confirmed via B0 Collector 27 Oct 2026)
- **Hosts:** Two twin HP ProDesk 4 Tower G1i Desktop AI PCs (`aiori-HP-ProDesk-4...` and `aiori-2-HP-ProDesk-4...`).
- **CPU:** Intel(R) Core(TM) Ultra 5 245 (14 cores, 14 threads).
- **RAM / Disk:** 30 GiB RAM (~26 GiB free), 488 GB NVMe ext4 (~450 GB free).
- **OS / Kernel:** Ubuntu 24.04.4 LTS, Kernel `6.14.0-1020-oem`. BTF is enabled (`/sys/kernel/btf/vmlinux`).
- **Network Interface & Driver:** Onboard Intel Gigabit `eno1` (Driver: `e1000e`, 1000 Mb/s Full Duplex).
- **⚠️ Single NIC Constraint:** Both PCs expose only `eno1` (originally connected to campus LAN `10.126.12.x/16`). **Flood traffic must never reach campus LAN.** Procedure:
  1. Install all apt packages over campus network first.
  2. Disconnect `eno1` from the campus network on both PCs.
  3. Direct-connect `eno1` of PC 1 (Target, `10.99.0.2/24`) and PC 2 (Generator, `10.99.0.1/24`) with a CAT6 cable.
  4. Work via physical console or secondary USB-Ethernet adapter.
- **Required Host Tuning:**
  - Set governor: `echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`
  - Stop jitter: `sudo systemctl stop unattended-upgrades && sudo ufw disable`
  - Disable IPv6: `sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.eno1.disable_ipv6=1`
  - Server `rp_filter=0`: `sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eno1.rp_filter=0`
- **Missing Packages to Install:**
  `sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic nsd dnsperf netsniff-ng python3-pandas python3-matplotlib python3-yaml sysstat ethtool`

### 12.3 B0 checklist (lab readiness): what to verify
Written lab permission; mentor approval for flood tests; root/sudo; package install possible; reboot/reset behavior of the PCs; time slots; kernel (`uname -r`, plan assumes >= 5.15); OS; NIC list and **driver** (`ethtool -i`); link speed; queue count (`ethtool -l`); CPU cores/governor; BPF support (`/sys/kernel/btf/vmlinux`, `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, bpffs mounted); management vs test NIC identification; no existing firewall surprises (`sudo nft list ruleset`, read only); IPv6 state; installed tools; auto-updates (`unattended-upgrades`) and sleep settings; disk/RAM. Read-only collector (run on each PC; send output to Person A):

```bash
#!/usr/bin/env bash
# b0_check.sh: read-only fact collector, changes nothing
echo "== host =="; hostname; date
echo "== OS / kernel =="; head -3 /etc/os-release; uname -r
echo "== CPU / RAM / disk =="; nproc; lscpu | grep -E 'Model name|Thread|Socket'
free -h | head -2; df -h / | tail -1; findmnt -no FSTYPE /
echo "== governor =="; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a
echo "== network =="; ip -br link; ip -br addr; ip route
for i in $(ls /sys/class/net | grep -v '^lo$'); do
  echo "-- $i"; ethtool -i "$i" 2>/dev/null | grep -E 'driver|^version|firmware'
  ethtool "$i" 2>/dev/null | grep -E 'Speed|Duplex|Link detected'
  ethtool -l "$i" 2>/dev/null | sed -n '1,12p'
done
echo "== BPF =="; ls /sys/kernel/btf/vmlinux 2>/dev/null
grep -E 'CONFIG_BPF(_SYSCALL|_JIT)?=' /boot/config-"$(uname -r)" 2>/dev/null; mount | grep bpf
echo "== tools =="
for t in clang llc bpftool xdp-loader nft python3 ethtool mpstat nstat nsd knotd trafgen dnsperf; do
  printf "%s: " "$t"; command -v "$t" >/dev/null && echo yes || echo MISSING; done
echo "== services =="; systemctl is-active ufw firewalld NetworkManager unattended-upgrades 2>/dev/null
echo "== ipv6 =="; sysctl net.ipv6.conf.all.disable_ipv6
echo "== firewall (needs sudo, read only) =="; sudo -n nft list ruleset 2>/dev/null | head -20
```

---

## 13. Roles and plans

Roles are labelled A and B (assignment of names to roles decided by the team; **work was deliberately not split by name in earlier documents**).

### Person A: XDP program and loader
| Phase | When | Work | Hand to B |
|---|---|---|---|
| A1 | Mon 26 | Bounded parser, malformed drop, counters, config map, **loader v1** (load/attach/config/stats/detach + watchdog) | loader CLI, CSV header, pinned map names (Mon night) |
| A2 | Tue 27 | GCRA per-source (LRU) + global, check order, **concurrency decision** (log it), acceptance tests (7.6) | limiter build + frozen config format (Tue night) |
| A3 | Wed 28 AM | Lab bring-up: build on lab PC, attach **generic first** with watchdog, try native (`xdpdrv`), record result; **code freeze tag by 12:00** | frozen commit |
| A4 | Wed PM-Thu | Support runs (dmesg, counters), limiter-accuracy check from data, write report sections (design, parsing, GCRA, concurrency, pseudocode, limitations) | report sections by Thu |
| A5 | Thu-Fri | Demo script (XDP side), repo cleanup (README, `docs/decisions.md`, `xdp/Makefile`), PDF assembly, ownership transfer, submit | |

### Person B: lab, traffic, baselines, measurement
| Phase | When | Work | Hand to A / team |
|---|---|---|---|
| B1 | Mon 26 | Repo + `docs/contract.md`; toolchain; namespace env; DNS server (RRL off); legit client v0; collectors v0; **B0 fact script on lab PCs when ready** | kernel/driver/NIC facts to A |
| B2 | Tue 27 | Generators S1-S3 + guard; baselines B1/B2 with measured-limit verification; orchestrator v1 + `analyze.py` v0; 12-run dry run in namespaces | |
| B3 | Wed 28 AM | **Calibration on lab PCs** (no XDP needed); levels/limits into params file; smoke test one run per config | `params` file |
| B4 | Wed PM-Thu AM | Run chosen matrix tier; log failures and re-run; checksums; **data freeze Thu 12:00** | `results/raw/` |
| B5 | Thu | Plots/tables; report sections: environment, methodology, results, legitimate-query impact, limitations; `setup.md`; document `run_matrix.sh` | report sections |
| B6 | Fri | Traffic side of demo; backup demo video; rehearse at least twice; check repo and deliverables | |

**B can do today without lab access or XDP:** repo, toolchain, namespace env, DNS server, legit client, generators + guard, nftables baselines, collectors, orchestrator + analysis (test with B0/B2 and shortened windows), an Ubuntu 22.04 VM for dry-running the install and B0 scripts.

### Handoff contract (agree first; keep in `docs/contract.md`)
- Loader commands: `load`, `attach`, `config`, `stats`, `detach` (+ watchdog).
- Stats CSV columns (section 7.5), run-directory naming `<scenario>_<config>_<level>_<rep>` (scenario S1/S2/S3; config B0/B1/B2/X; level 0.5x/1x/2x), shared params file.

---

## 14. Revised schedule (compressed; replaces the submitted timeline)

| Day | Person A | Person B | Checkpoint |
|---|---|---|---|
| **Mon 26 Oct** | A1: XDP v1 + loader v1 | B1: repo, namespaces, DNS, legit client, lab facts | C1 22:00: XDP v1 loads/counts on veth; B0 end-to-end in namespaces |
| **Tue 27** | A2: limiters + tests | B2: generators, baselines, orchestrator, dry run | C2 22:00: limiters pass tests; one dry run completes |
| **Wed 28** | A3: lab bring-up, **freeze 12:00**; start report | B3: calibration, then matrix | Freeze 12:00; **tier decision 18:00** |
| **Thu 29** | A4: report, support re-runs | B4/B5: finish matrix, **data freeze 12:00**, analysis | Draft complete 20:00 |
| **Fri 30** | A5: demo, repo, **submit** | B6: plots, backup video, rehearsal | Submit |
| **Sat 31** | buffer only | buffer only | |

**Go/no-go rules:**
- C2 missed: A fixes Wed morning while B calibrates (calibration needs no XDP).
- Wed 12:00: freeze whatever passes its tests; document what does not.
- Wed 18:00: choose the matrix tier; do not start a tier that cannot finish by Thu 12:00.
- Thu 12:00: data freezes with whatever is complete.

**If the schedule slips, cut in this order:** extras (dashboard first) -> repetitions 5 to 3 -> 5x level -> S2 down to about 1,000 sources -> B1 (keep B2). **Never cut:** calibration, containment, the demo.

**Fallbacks:** lab not usable by Wed noon -> run everything in namespaces on own machines with core pinning, label results functional validation, try for a short lab smoke-test session. No native XDP -> generic mode (see section 5). Verifier/loader trouble -> `bpftool`-based loader and a simpler program.

---

## 15. Repository layout (starting point; reconcile with the organizers' structure PDF, theirs takes precedence)

```
kavach/                      # repo named after the team; confirm exact naming rule with organizers
  README.md                  overview, scope rules, how to reproduce
  docs/
    decisions.md             every design decision and why (both of us write entries)
    contract.md              loader CLI, stats CSV columns, run-dir naming, params format
    setup.md                 lab setup and environment table (kernel, NIC, driver, XDP mode, tool versions)
    (required submission PDF per the organizers' structure)
  xdp/
    dns_ratelimit.bpf.c      XDP program
    loader.py (or loader.c)  loader + stats exporter + watchdog
    Makefile
  baselines/
    none.sh   nft_prerouting.nft   nft_netdev_ingress.nft
  traffic/
    legit_client.*   flood_s1_single.*   flood_s2_distributed.*   flood_s3_pulse.*   guard.*
  scripts/
    setup_env.sh   teardown_env.sh   b0_check.sh   install_lab.sh
    run_matrix.sh  collect.sh  analyze.py  demo.sh
  results/
    raw/                     untouched run data (one directory per run)
    plots/
  report/                    technical report sources
```

Commit at least daily, by directory to avoid conflicts. No full clean-machine `reproduce.sh`; `setup.md` + `run_matrix.sh` + a one-command demo run are enough.

---

## 16. Report and demo

**Report (PDF in repo, organizers' structure):** objectives and hypotheses; scope and safety; design (parsing, GCRA, maps, check order, concurrency decision); baselines and fairness controls; traffic and scenarios; calibration; methodology; results (median/IQR, drops by layer, CPU per packet, legitimate success and latency); analysis of legitimate-query impact (collateral damage in S2); limitations; reduced-matrix disclosure.

**Demo (about 4 minutes):** (1) start DNS server and legitimate client, show normal success; (2) flood with no filter, show legitimate success and CPU affected; (3) repeat with nftables, then XDP, show drop counters and legitimate success; (4) show plots, limitations, and the pseudocode (section 7.4). Keep a **recorded backup video**. Rehearse at least twice.

**Known limitations to state:** one lab pair and one hardware/driver combination; generic mode saves less than native; namespace results are functional only; per-core capacity if pinned; per-source limits weak against spoofed/distributed sources and the global limit then drops legitimate queries; non-first fragments and IPv6 unfiltered, truncated headers pass; no reflection-attack claims; rate limiting can drop legitimate queries (size measured, not assumed zero); shallow parsing only.

---

## 17. Decisions: settled vs open

**Settled:** malformed DNS packets are dropped; 60 s measurement window; per-source check before global; GCRA integer limiter with LRU per-source state; IPv6 out of scope (disabled on test NIC); fragments passed and counted; both nftables baselines (B1 prerouting, B2 netdev ingress); 4 configs; compressed matrix (section 11); extras/dashboard cut; loader = bpftool-based wrapper by default; XDP code freeze Wed 28 Oct 12:00; namespace-first development; replies routed back via the generator; synthetic sources from 198.18.0.0/15.

**Open:** native vs generic mode (depends on lab NIC driver) **[VERIFY]**; concurrency method (CAS vs spin lock vs approximate) **[VERIFY]**; VLAN handling **[DECISION]**; DNS server NSD vs Knot **[DECISION]**; whether the organizers' structure PDF requires different report sections **[VERIFY]**; PRSD wording for random-label queries **[VERIFY]**; exact repo naming rule (team name "Kavach" vs submission ID) **[VERIFY]**; repo status and how far XDP v1 has progressed (unknown at time of writing).

---

## 18. Literature (as cited in the submitted deck; open each source and confirm before quoting)

1. P. Mockapetris, "Domain Names - Implementation and Specification," RFC 1035, IETF, Nov. 1987 (12-byte DNS header basis).
2. P. Ferguson and D. Senie, "Network Ingress Filtering," BCP 38 / RFC 2827, IETF, May 2000 (spoofed sources defeat per-source limits).
3. P. Vixie and V. Schryver, "DNS Response Rate Limiting (DNS RRL)," ISC Technical Note ISC-TN-2012-1-Draft1, Apr. 2012 (complementary: acts on responses in the DNS server).
4. T. Hoiland-Jorgensen et al., "The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel," ACM CoNEXT 2018, pp. 54-66.
5. A. Fabre, "L4Drop: XDP DDoS Mitigations," Cloudflare Blog, 2018.
6. ITU-T Recommendation I.371, "Traffic control and congestion control in B-ISDN" (Annex A: Generic Cell Rate Algorithm), 2004.
Also used: Linux kernel BPF documentation (docs.kernel.org/bpf), nftables documentation.

---

## 19. Glossary

**XDP** eXpress Data Path, eBPF hook in the NIC driver. **eBPF** in-kernel sandboxed bytecode, checked by the **verifier**. **sk_buff** kernel socket buffer allocated per packet. **GCRA** generic cell rate algorithm (one timestamp per flow). **tat** theoretical arrival time. **LRU map** hash map evicting least-recently-used entries. **RRL** DNS response rate limiting. **PRSD** pseudo-random subdomain attack. **S** saturation point of the unfiltered server. **B0/B1/B2/X** the four configurations. **S1/S2/S3** the three flood scenarios.

---

## 20. Instructions for agents

- **Mandatory State & Decision Synchronization (COMPULSORY RULE):** After each milestone, implementation step, code change, or when new architectural/hardware findings emerge, agents MUST systematically and compulsively update all relevant documentation and agent files (`docs/decisions.md` with explicit ADR entries, `docs/known-issues.md`, `docs/setup.md`, `README.md`, and skills in `.agents/skills/`), recording decisions, rationale, commands, and state updates without requiring manual prompting from the user.
- **Know your role.** If you work on the **XDP program/loader**, focus on sections 4, 7, 12.1-12.2 and the A rows of section 13. If you work on **lab/traffic/baselines/measurement**, focus on sections 3, 6, 8-12 and the B rows of section 13.
- **Safety first:** never write code that sends traffic to a destination outside the lab subnet; every generator must call the guard. Never attach XDP to a non-test interface. Default to generic mode and the watchdog.
- **Parameterize everything** (interface, mode, rates, bursts, durations, paths); read limits from the shared params file and the config map. No hardcoded interface names or magic numbers. Never hardcode kernel-versioned binary paths (e.g. `/usr/lib/linux-tools/<version>/bpftool`); use dynamic discovery via PATH, `uname -r`, or environment variables (`BPFTOOL`).
- **Target the lab kernel:** write for kernel 5.15 / clang 14 / libbpf 0.5 unless told otherwise; keep newer-feature code behind a compile-time switch.
- **Keep it simple and verifiable.** Prefer small steps that pass the acceptance tests in section 7.6. Every counter must be incremented exactly once per packet verdict.
- **Never invent numbers or results.** Label namespace results as functional validation. If asked for expected performance, say it is a hypothesis.
- **Reproducibility:** deterministic seeds, logged run order, raw data untouched, record environment details with every run.
- **Record decisions** in `docs/decisions.md` (what, why, alternatives). Commit small and often.
- **Time budget:** the deadline is real. When unsure, choose the cut order in section 14 rather than adding features. Do not add IPv6, DNS name parsing, PRSD detection or a dashboard.
- **When something conflicts with this file,** ask the humans; the official PS-022 text and the organizers' structure PDF override this document.
