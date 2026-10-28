# Frozen Person A / Person B interface, version 1

Invoke from repository root on Linux. Build: `make -C xdp`; object: `xdp/kavach_xdp.o`. Default build uses CAS. This defines the handoff format; final lab freeze is pending.

## Commands

```bash
sudo python3 xdp/kavach_ctl.py load
sudo python3 xdp/kavach_ctl.py attach generic --iface TESTNIC --watchdog-minutes 5
sudo python3 xdp/kavach_ctl.py attach native --iface TESTNIC --watchdog-minutes 5
sudo python3 xdp/kavach_ctl.py config --src-rate 50 --src-burst 5 --glob-rate 100 --glob-burst 10
sudo python3 xdp/kavach_ctl.py stats --csv --interval 1
sudo python3 xdp/kavach_ctl.py stats --once
sudo python3 xdp/kavach_ctl.py status
sudo python3 xdp/kavach_ctl.py detach --iface TESTNIC
sudo python3 xdp/kavach_ctl.py unload
```

`config` must precede attachment and requires the owned program to be detached. Rate zero disables that limiter. Omitted config options reset that limiter to disabled; every config command replaces the complete record. Default load starts with zero config, so valid DNS passes; malformed DNS still drops. Detach retains counters and invalidates the watchdog generation. Unload requires detachment and removes pins. All operational diagnostics are stderr. `stats --once` emits one JSON object; default streaming is JSON Lines. `--csv` emits one header plus cumulative samples, default one-second interval, with first sample immediately. `--count N` limits sample count. Timestamps are Unix wall-clock nanoseconds; GCRA and watchdog use monotonic time.

## Pinned objects

| Path under `/sys/fs/bpf/kavach/` | Type | Key | Value | Entries |
|---|---|---|---|---|
| `prog` | XDP program | — | — | — |
| `counters` | PERCPU_ARRAY | u32 index | u64 per possible CPU | 14 |
| `kavach_cfg` | ARRAY | u32 zero | config struct below | 1 |
| `src_tat` | LRU_HASH | source IPv4 bytes, network order | u64 TAT ns | 100000 |
| `global_tat` | ARRAY | u32 zero | u64 TAT ns | 1 |

## CSV header and counter meanings

```csv
timestamp_ns,seen,pass_non_ipv4,pass_non_udp,pass_non53,pass_fragment,pass_truncated,pass_invalid_ipv4,dns_pass,drop_bad_udp,drop_short_dns,drop_src,drop_global,drop_busy,drop_state
```

Counter order is the order after `timestamp_ns`; `seen` is index 0. Each packet increments `seen` and exactly one terminal reason. Reasons distinguish non-IPv4 (includes VLAN/ARP/IPv6), non-UDP, other UDP destination, non-first fragment, pre-DNS header truncation, invalid IPv4, accepted DNS, bad UDP length, short DNS, source/global rate rejection, CAS retry exhaustion and state failure.

On a quiet system, `seen == sum(all other counters)`. A live read is not a simultaneous snapshot of all CPUs/counters, so check this after the sender stops. Use before/after differences. `dns_pass` is filter admission, not a successful DNS response.

## Config ABI: 40 bytes, native endian

Offsets: 0 source interval (u64); 8 source tolerance (u64); 16 global interval (u64); 24 global tolerance (u64); 32 flags (u32); 36 zero padding (u32). Python format `=QQQQII`. Flags: 1 source enabled, 2 global enabled. TAT is monotonic nanoseconds. Source key preserves IPv4 network bytes.

For an enabled limiter: interval = **ceil(1e9 / rate)**; tolerance = `(burst-1)*interval`. Ceiling avoids slightly exceeding the requested rate at non-divisor rates. CLI bounds: rate 0..1e9, burst 1..1e6, tolerance <= one hour. Actual discrete rate can be slightly lower. Direct map writes bypass validation and are outside this interface.

## Reset and handoff

Between independent measurement runs: stop sender, save final counters, detach, unload, load, config, attach. Coordinate with B before changing this format. B can calibrate without any XDP program attached. B's baseline/benchmark code is not supplied here.

The watchdog requires a running Linux process. Read `/run/kavach/watchdog.log` after expiry. State and lock files are local runtime data, not repository files.
