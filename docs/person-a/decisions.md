# Implementation decisions

## Parser boundaries

Every dereference is protected by physical packet bounds; IPv4 total length also limits logical header/payload availability. IHL controls the UDP offset. Unknown EtherTypes, VLAN, non-UDP and non-53 destination traffic pass. Structurally invalid IPv4 passes with a dedicated counter. Truncated Ethernet/IPv4/UDP headers before UDP/53 identification pass. Once UDP/53 is identified, missing DNS-header bytes drop. UDP length below 8 is bad UDP, lengths 8..19 are short DNS. Bad unfragmented UDP lengths extending beyond IP payload or captured UDP bytes drop. The parser verifies header presence, not DNS semantics/checksums.

This explicitly resolves the request's overlapping truncated-header and short-DNS rules. Counter precedence is defined by code order: one terminal reason per packet, so an input violating multiple conditions receives the first matching reason.

## Fragments

Nonzero fragment offset passes. Offset zero with MF set is a first fragment: its advertised UDP length may legitimately exceed the fragment's IP payload. Require the complete UDP and 12-byte DNS headers inside the first fragment; do not require the whole datagram. Only that first fragment is rate-limited. No reassembly or universal fragment protection is claimed.

## Concurrency: CAS, then explicit approximate fallback

Default: compare-and-swap on one aligned u64 TAT in both source LRU_HASH and global ARRAY. Read old TAT, compute candidate, reject without updating if too early, then CAS; retry at most eight times. A successful CAS reserves one slot. Read time once per packet. Source-first admission consumes its source slot even if global subsequently rejects it.

Spin locks were not selected: a lock changes the required one-u64 value layout, and the documented helper restrictions list ordinary HASH/ARRAY rather than the required source LRU_HASH. No spin-lock variant has been tested.

CAS retry exhaustion **drops**, increments `drop_busy`, and does not fail open. Source allocation/lookup or global-state lookup failure drops with `drop_state`. Overflow/zero interval rejects without TAT mutation. Kernel build/load support must be checked on each target. Host tests of CAS do not prove kernel support or throughput.

If the lab cannot load CAS: preserve the exact error and first rule out flags/toolchain errors. An explicitly separate fallback is available:

```bash
make -C xdp approximate
sudo python3 xdp/kavach_ctl.py load --obj xdp/kavach_xdp_approx.o --allow-approximate
```

It uses a plain TAT store and may lose updates under concurrent execution. Report it as **approximate limiting**, with a separate object hash and new measurements. It has no multi-CPU strict-limit guarantee. The fallback does not overwrite the CAS object, and the controller does not select it automatically. No claim is made that every old kernel will accept it. Do not rename it to conceal the fallback. The host evidence in this package is for the default CAS build.

## Config and counters

Userspace computes intervals/tolerances. Enabled rates use ceiling division to avoid rounding the admitted rate upward. Config is a forty-byte array value, not an assumed atomic multi-field live snapshot: the controller refuses config while this program is attached. Stop kernel test runners too. Reload between independent runs, because config alone does not clear TATs.

Per-CPU counters use atomic increments. User space sums all possible CPU entries supplied by bpftool; it does not assume that possible CPU count equals online CPU count. CSV/JSON stdout contains data only. Final counts are retained on detach/watchdog expiry.

## Ownership and watchdog

One managed attachment at a time. Attach refuses occupied interfaces and default-route interfaces identified from IPv4/IPv6 routes. Root still must explicitly select the dedicated test NIC; the route guard cannot identify every possible management path.

libbpf attaches with UPDATE_IF_NOEXIST. A separate session/process holds the program FD, signals readiness before attach, and checks a generation token. Detachment uses libbpf's expected old FD to prevent replacement-program removal in the kernel, including across a check/detach race. Interface index/name and mode are checked. Manual detach invalidates the generation. State and mutations are serialized with flock. Pins remain after detach for inspection.

The watchdog is independent of the interactive terminal, but it is not an external supervisor: process termination, a suspended/dead machine, or kernel failure can prevent timely action. Test expiry on the actual NIC/mode; use console access for initial lab bring-up. Failed operations report errors and do not authorize replacing other XDP programs.

## Fairness and measurement limits

Per-source-first reduces the global budget consumed by a single flood source; it cannot promise starvation freedom for all burst/rate settings. Provision enough global budget in the isolation test and count the legitimate source separately. LRU churn resets evicted sources. The namespace sender is deliberately small and capped; it is not B's high-rate calibration/performance harness. Native and generic results must be labelled separately.

References: [UDP](https://datatracker.ietf.org/doc/html/rfc768), [IPv4](https://datatracker.ietf.org/doc/html/rfc791), [libbpf attach implementation](https://github.com/libbpf/libbpf/blob/master/src/netlink.c), [spin-lock restrictions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h).
