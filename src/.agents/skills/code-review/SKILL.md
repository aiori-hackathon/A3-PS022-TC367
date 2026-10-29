---
name: code-review
description: Reviewing eBPF/XDP C code, loader scripts, and measurement automation against safety, verifier constraints, and project specifications.
---

# eBPF/XDP Code Review Skill

This skill provides an authoritative checklist and review procedure for validating code contributions to the Kavach repository.

---

## 1. Safety and Boundary Guardrails Review

Before any script or program is merged or executed, verify the following non-negotiable safety conditions:

- [ ] **Strict Lab Destination Guard & Integration:**
  Does the traffic generator import or source `src/traffic/guard.sh` (or `src/traffic/guard.py`) and invoke `guard_enforce_all` before creating sockets or sending packets? Does it verify the target IP is strictly inside `10.99.0.0/24` (rejecting campus LAN `10.126.0.0/16`) and exit with code >= 100 on violation?
- [ ] **Physical Network Isolation & Single NIC Guard:**
  Is `eno1` verified to be physically disconnected from the campus network and wired directly to the peer machine before flood scripts run?
- [ ] **CPU Frequency Governor Check:**
  Is the CPU scaling governor verified to be set to `performance` on all cores prior to running metrics?
- [ ] **Synthetic Source Range:**
  Are synthetic flood source IPs drawn exclusively from the benchmark reservation `198.18.0.0/15`?
- [ ] **Interface Safety Check:**
  Does the loader reject attempts to attach XDP to the management, default route, or SSH network interface?
- [ ] **Watchdog Requirement:**
  Does the loader deploy an auto-detaching background watchdog timer?
- [ ] **Egress Containment:**
  Is `ip_forward` disabled on the generator host, and is `rp_filter` appropriately managed only on the isolated test interface?

---

## 2. eBPF C Code & Verifier Safety Review

When reviewing `xdp/dns_ratelimit.bpf.c`:

- [ ] **Universal Bounds Checks:**
  Is every pointer dereference (`eth`, `ip`, `udp`, `dns`) checked against `ctx->data_end` immediately before access?
  ```c
  if ((void *)(hdr + 1) > (void *)(long)ctx->data_end)
      return XDP_PASS;
  ```
- [ ] **Bounded Parsing Scope:**
  Is the parsing strictly limited to fixed-size headers (Ethernet, IPv4, UDP, 12-byte DNS header)? Confirm there are **no loops over DNS query name labels**.
- [ ] **Dynamic IP Header Length (IHL):**
  Does IP header parsing compute the UDP offset dynamically using `ip->ihl * 4` rather than assuming a static 20-byte IPv4 header?
- [ ] **Fragment Handling:**
  Are non-first fragments (`(frag_off & 0x1FFF) != 0`) passed safely with the `fragments_passed` counter incremented?
- [ ] **Integer-Only Arithmetic:**
  Are all GCRA calculations performed using 64-bit integer addition, subtraction, and comparisons? Confirm there is **no division or floating-point arithmetic** in the packet-processing path.
- [ ] **Target Kernel 5.15 Compatibility:**
  Does the code avoid helper functions, kfuncs, or libbpf 1.0+ idioms that fail verification on Linux kernel 5.15?
- [ ] **Exact Verdict Counter Increment:**
  Is exactly one metric counter incremented per packet verdict (`dns_seen`, `drop_source`, `drop_global`, `malformed`, `passed`, etc.)?

---

## 3. Rate Limiting (GCRA) and Concurrency Review

- [ ] **Check Order Verification:**
  Is the per-source GCRA check evaluated **first**, and the global GCRA check evaluated **second**? Ensure that packets dropped by the per-source limiter never touch or deplete the global bucket.
- [ ] **Burst Tolerance Calculation:**
  Does the GCRA tolerance calculation conform to $\tau = (\text{burst} - 1) \times T$?
- [ ] **Initial Arrival Handling:**
  Does the algorithm handle new or evicted keys properly using `max(stored_tat, now)`?
- [ ] **Global TAT Concurrency:**
  Is the global Theoretical Arrival Time updated via atomic compare-and-swap (`__sync_val_compare_and_swap`) or documented as a bounded racy update?
- [ ] **Map Selection:**
  Is the per-source map explicitly `BPF_MAP_TYPE_LRU_HASH` to guarantee bounded memory consumption? Are stats tracked via `BPF_MAP_TYPE_PERCPU_ARRAY`?

---

## 4. Control Plane and Script Parameterization Review

- [ ] **No Hardcoded Parameters:**
  Are network interfaces, rates, burst thresholds, run durations, and file paths passed via command-line arguments or loaded from `params.yaml`?
- [ ] **No Hardcoded Tool / Kernel Paths:**
  Do scripts and controller CLIs avoid hardcoding kernel-versioned paths (e.g. `/usr/lib/linux-tools/6.8.0-147-generic/bpftool`)? Are binaries discovered dynamically via `PATH`, `/usr/lib/linux-tools/$(uname -r)/`, or environment overrides (`BPFTOOL`)?
- [ ] **Clean State Reset:**
  Does the benchmark runner cleanly flush maps, reset interfaces, and restart services between test iterations?
- [ ] **Telemetry Header Adherence:**
  Does the exported stats CSV strictly match the frozen header format:
  `timestamp, dns_seen, non_dns_passed, passed, drop_source, drop_global, malformed, fragments_passed, unparsable_passed`

