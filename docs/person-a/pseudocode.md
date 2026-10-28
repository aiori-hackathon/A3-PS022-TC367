# Pseudocode matching the delivered default build

```text
on packet:
    increment seen
    validate physical Ethernet header; truncated -> pass_truncated + PASS
    non-IPv4 EtherType (including VLAN) -> pass_non_ipv4 + PASS
    validate physical IPv4 fixed header
    validate version, IHL >= 5, total_length >= IHL_bytes
    validate physical full IHL-sized header
    non-UDP -> pass_non_udp + PASS
    nonzero fragment offset -> pass_fragment + PASS
    validate physical AND IP-logical UDP header; truncated -> PASS
    UDP destination != 53 -> pass_non53 + PASS
    UDP length < 8 -> drop_bad_udp + DROP
    UDP length < 20 -> drop_short_dns + DROP
    if not MF and UDP length exceeds IP payload -> drop_bad_udp + DROP
    require DNS header inside physical frame AND IP payload
    if not MF and complete UDP datagram exceeds frame -> drop_bad_udp + DROP
    lookup config; failure -> drop_state + DROP
    now = monotonic nanoseconds
    if source limiter enabled:
        lookup source IPv4 bucket
        if absent: attempt BPF_NOEXIST insert of zero; lookup again
        absent -> drop_state + DROP
        run GCRA CAS; reject -> drop_src + DROP; busy -> drop_busy + DROP
    if global limiter enabled:
        lookup shared bucket; absent -> drop_state + DROP
        run GCRA CAS; reject -> drop_global + DROP; busy -> drop_busy + DROP
    dns_pass + PASS

GCRA(slot, now, interval, tolerance):
    repeat at most 8 times:
        old = load slot
        base = max(old, now)
        if base - now > tolerance: reject, leaving slot unchanged
        if interval == 0 or base + interval would overflow: reject
        if CAS(slot, old, base + interval) succeeds: allow
    busy
```

Each packet increments `seen` and exactly one terminal outcome. A global rejection leaves its previously reserved source slot consumed. Only the explicitly selected approximate object replaces CAS with a plain TAT store.
