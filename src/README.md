# Kavach: eBPF/XDP Rate Limiting for DNS Query Floods

**Submission ID:** A3-PS022-TC367  
**Category:** Cybersecurity (AIORI Hackathon 3)  
**Team Kavach:** Keerthi Virupapura, U Kruthik (BMS College of Engineering, CSE)  
**Faculty Mentor:** Dr. Manjunath D R  

---

## 1. Executive Summary

High-volume UDP/53 DNS query floods overwhelm Linux systems because the operating system spends substantial CPU cycles allocating socket buffers (`sk_buff`) in the networking stack before packets reach user-space daemons or firewalls. Even early nftables hooks (such as `netdev ingress`) operate after `sk_buff` allocation has already occurred.

**Kavach** implements an eBPF/XDP (eXpress Data Path) kernel filter that runs directly inside the network interface card (NIC) driver layer. By performing bounded parsing on incoming packets and evaluating dual-tier Generic Cell Rate Algorithm (GCRA) rate limits, Kavach drops excess or malformed flood queries **before kernel memory allocation occurs**, preserving system CPU and protecting legitimate DNS queries.

---

## 2. Key Architecture & Features

- **Bounded UDP/DNS Packet Parsing:** Parses Ethernet -> IPv4 -> UDP headers strictly bounded against `data_end`. Evaluates the fixed 12-byte DNS header (RFC 1035) without looping over arbitrary query names (no unbounded loops, verifier-safe).
- **Dual-Tier GCRA Rate Limiter:**
  - **Per-Source Rate Limiting:** Enforced via `BPF_MAP_TYPE_LRU_HASH` (keyed by source IPv4) to bound memory consumption under random spoofed source floods.
  - **Global Rate Limiting:** Shared single-bucket rate limiter via an array map (`u64 tat`).
  - **Evaluation Order:** Per-source check is performed *first*, followed by the global check, preventing a single high-volume source from exhausting the global bucket.
- **Early Malformed Packet Rejection:** Drops malformed UDP/53 payloads (< 12 bytes or inconsistent UDP length fields) immediately.
- **Controlled Baselines for Comparison:**
  - **B0:** No filter (pure DNS daemon handling).
  - **B1:** `nftables` prerouting raw table (standard firewall baseline).
  - **B2:** `nftables` netdev ingress table (earliest netfilter hook).
  - **X:** Kavach XDP program (native/generic driver modes).
- **Three Synthetic Flood Scenarios:**
  - **S1 (Single-source flood):** Sustained flood testing per-source GCRA and CPU reduction.
  - **S2 (Distributed flood):** Many random sources from `198.18.0.0/15` testing global limit and LRU eviction under memory pressure.
  - **S3 (Pulsing flood):** Periodic burst flood evaluating GCRA burst tolerance parameter and refill dynamics.

---

## 3. Directory Structure

```text
src/
├── AGENTS.md                  # Comprehensive project context, guidelines, and agent instructions
├── README.md                  # Project overview, architecture, and quick start guide
├── docs/                      # Technical specifications and architectural records
│   ├── architecture.md        # Detailed packet pipeline, GCRA math, and map definitions
│   ├── decisions.md           # Architecture Decision Records (ADRs: settled vs lab-validated)
│   ├── known-issues.md        # Verifier constraints, single NIC hardware caveats, and limitations
│   └── setup.md               # Lab hardware inventory, Ubuntu 24.04 specs, and tuning guide
└── .agents/                   # Operational agent skills
    └── skills/
        ├── debugging/         # eBPF verifier, e1000e driver, bpftool, and drop tracing skill
        │   └── SKILL.md
        ├── code-review/       # eBPF safety, verifier compliance, isolation guard review skill
        │   └── SKILL.md
        └── testing/           # Acceptance testing, physical lab setup, and matrix runner skill
            └── SKILL.md
```

---

## 4. Confirmed Physical Testbed Profile (Lab Host Pair)

From the B0 fact collection on 27 Oct 2026:
- **Workstations:** 2x HP ProDesk 4 Tower G1i Desktop AI PCs (Twin hardware).
- **CPUs:** Intel(R) Core(TM) Ultra 5 245 (14 cores, 14 threads).
- **RAM & Storage:** 30 GiB RAM, 488 GB NVMe SSD per machine.
- **OS & Kernel:** Ubuntu 24.04.4 LTS, Kernel `6.14.0-1020-oem` (BTF enabled, BPF atomics supported).
- **Network Interface:** Onboard Intel Gigabit `eno1` (Driver: `e1000e`). Direct CAT6 cable between PC 1 (`10.99.0.2`) and PC 2 (`10.99.0.1`).
- **Tuning:** CPU governor forced to `performance`, `unattended-upgrades` disabled, `ufw` disabled, IPv6 disabled on `eno1`.

---

## 4. Safety Guardrails & Lab Protocol

1. **Strictly Isolated Network Link:** Flood traffic is confined strictly to dedicated test interfaces (`10.99.0.0/24`) or local network namespaces (`gen` <-> `srv`). No packets route to public networks or campus LANs.
2. **Generator Destination Guard:** Traffic generators explicitly abort if destination IP addresses fall outside the designated lab subnet.
3. **Synthetic Source Allocation:** Synthetic flood traffic strictly uses `198.18.0.0/15` (RFC 2544 benchmark reservation).
4. **XDP Interface Isolation & Watchdog:** Never attach XDP programs to SSH/management interfaces. Every attach invocation is guarded by an automatic detachment watchdog timer.
5. **No Spoofed Replies:** The target server's default gateway routes back exclusively through the generator host with `ip_forward=0`.

---

## 5. Development & Testing Quick Start

### 5.1 Local Namespace Environment (Development)
```bash
# Set up isolated namespaces (gen and srv) joined by veth pair
sudo ip netns add gen
sudo ip netns add srv
sudo ip link add vgen type veth peer name vsrv
sudo ip link set vgen netns gen
sudo ip link set vsrv netns srv
sudo ip -n gen addr add 10.99.0.1/24 dev vgen
sudo ip -n srv addr add 10.99.0.2/24 dev vsrv
sudo ip -n gen link set lo up && sudo ip -n gen link set vgen up
sudo ip -n srv link set lo up && sudo ip -n srv link set vsrv up
sudo ip netns exec srv sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.vsrv.rp_filter=0
```

### 5.2 Building and Attaching XDP
```bash
# Build eBPF bytecode using clang (targeting kernel 5.15 / v3 verifier)
clang -target bpf -O2 -g -c xdp/dns_ratelimit.bpf.c -o xdp/dns_ratelimit.bpf.o

# Load and attach via generic mode on development veth
sudo ip netns exec srv ip link set dev vsrv xdpgeneric obj xdp/dns_ratelimit.bpf.o sec xdp
```

---

## 6. References

- RFC 1035: Domain Names - Implementation and Specification
- RFC 2827 / BCP 38: Network Ingress Filtering
- ITU-T I.371: Generic Cell Rate Algorithm (GCRA)
- Linux Kernel BPF & XDP Documentation: https://docs.kernel.org/bpf/
