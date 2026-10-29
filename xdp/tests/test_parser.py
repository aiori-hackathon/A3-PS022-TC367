#!/usr/bin/env python3
"""A1 parser checks using bpftool prog run; does not transmit packets."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

PIN = "/sys/fs/bpf/kavach"
NAMES = (
    "seen", "pass_non_ipv4", "pass_non_udp", "pass_non53",
    "pass_fragment", "pass_truncated", "pass_invalid_ipv4", "dns_pass",
    "drop_bad_udp", "drop_short_dns", "drop_src", "drop_global",
    "drop_busy", "drop_state",
)

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from kavach_ctl import BPFTOOL_BIN

def bpf(*args):
    result = subprocess.run(
        [BPFTOOL_BIN, "-j", *args], capture_output=True, text=True
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return json.loads(result.stdout)

def number(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int.from_bytes(bytes(number(x) for x in value), "little")

def snapshot():
    entries = bpf("map", "dump", "pinned", PIN + "/counters")
    totals = {}
    for entry in entries:
        entry = entry.get("formatted", entry)
        key = number(entry["key"])
        if not 0 <= key < len(NAMES):
            raise RuntimeError("Unexpected counter map layout")
        totals[NAMES[key]] = sum(number(v["value"]) for v in entry["values"])
    if set(totals) != set(NAMES):
        raise RuntimeError("Counter map does not contain all 14 counters")
    return totals

def packet(version=4, ihl=5, iplen=None, proto=17, frag=0,
           port=53, ulen=20, payload=12, etype=0x0800):
    if iplen is None:
        iplen = ihl * 4 + 8 + payload
    eth = bytes.fromhex("020000000001020000000002") + struct.pack("!H", etype)
    ip = struct.pack(
        "!BBHHHBBHII", (version << 4) | ihl, 0, iplen, 0, frag,
        64, proto, 0, 0x0AC80102, 0x0AC80101
    )
    options = bytes(max(0, ihl * 4 - 20))
    udp = struct.pack("!HHHH", 12345, port, ulen, 0)
    return eth + ip + options + udp + bytes(payload)

def cases():
    p = packet()
    tests = [
        ("valid_dns", p, "dns_pass"),
        ("arp_ethertype", packet(etype=0x0806), "pass_non_ipv4"),
        ("ipv6_ethertype", packet(etype=0x86DD), "pass_non_ipv4"),
        ("vlan_ethertype", packet(etype=0x8100), "pass_non_ipv4"),
        ("tcp_protocol", packet(proto=6), "pass_non_udp"),
        ("other_udp_port", packet(port=5353), "pass_non53"),
        ("nonfirst_fragment", packet(frag=1), "pass_fragment"),
        ("truncated_ip", p[:24], "pass_truncated"),
        ("truncated_udp", p[:38], "pass_truncated"),
        ("truncated_options", packet(ihl=15)[:50], "pass_truncated"),
        ("bad_ip_version", packet(version=6), "pass_invalid_ipv4"),
        ("bad_ihl", packet(ihl=4), "pass_invalid_ipv4"),
        ("bad_ip_total", packet(iplen=10), "pass_invalid_ipv4"),
        ("ip_udp_header_short", packet(iplen=24), "pass_truncated"),
        ("udp_length_7", packet(ulen=7), "drop_bad_udp"),
        ("dns_payload_11", packet(ulen=19, payload=11), "drop_short_dns"),
        ("udp_length_400", packet(ulen=400), "drop_bad_udp"),
        ("padding_not_dns", packet(iplen=28), "drop_bad_udp"),
        ("truncated_dns", p[:53], "drop_short_dns"),
        ("truncated_udp_body", packet(iplen=60, ulen=40), "drop_bad_udp"),
        ("first_fragment", packet(frag=0x2000, ulen=100, payload=16), "dns_pass"),
        ("first_fragment_short", packet(frag=0x2000, iplen=28, ulen=100), "drop_short_dns"),
    ]
    for ihl in range(6, 16):
        tests.append((f"ip_options_ihl_{ihl}", packet(ihl=ihl), "dns_pass"))
    return tests

def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo python3 xdp/tests/test_parser.py")
    # Run only while detached and after config --src-rate 0 --glob-rate 0.
    report = Path(__file__).resolve().parents[2] / "docs/person-a/evidence/a1-parser.txt"
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("w") as log, tempfile.TemporaryDirectory(prefix="kavach-test-") as work:
        def say(message):
            print(message, flush=True)
            log.write(message + "\n")
            log.flush()
        try:
            tests = cases()
            for index, (name, data, reason) in enumerate(tests, 1):
                path = Path(work) / "packet.bin"
                path.write_bytes(data)
                before = snapshot()
                result = bpf("prog", "run", "pinned", PIN + "/prog",
                             "data_in", str(path), "repeat", "1")
                after = snapshot()
                delta = {key: after[key] - before[key] for key in NAMES}
                expected = {key: 0 for key in NAMES}
                expected["seen"] = 1
                expected[reason] = 1
                action = 1 if reason.startswith("drop_") else 2
                if result["retval"] != action or delta != expected:
                    raise RuntimeError(
                        f"{name}: verdict={result['retval']} expected={action}; "
                        f"counter_delta={delta}; expected={expected}"
                    )
                say(f"PASS {index:02d} {name}")
            say(f"PASS: {len(tests)}/{len(tests)} parser tests; verdicts and counters match.")
            say("Ethernet frames shorter than 14 bytes are excluded: kernel test-run requires an Ethernet header.")
        except Exception as error:
            say(f"FAIL: {error}")
            return 1
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
