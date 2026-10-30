#!/usr/bin/env python3
"""Small functional-test sender, restricted to the isolated test veth namespace.
Ethernet frames use IPv4/UDP/53.
"""
import argparse
import ipaddress
import json
import math
import socket
import struct
import subprocess
import time

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def frame(src, src_mac, dst_mac):
    payload = struct.pack('!HHHHHH', 1, 0x0100, 0, 0, 0, 0)
    udp = struct.pack('!HHHH', 12000, 53, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0,
                     64, 17, 0, ipaddress.IPv4Address(src).packed,
                     ipaddress.IPv4Address('10.200.1.1').packed)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return dst_mac + src_mac + b'\x08\x00' + ip + udp

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dst-mac', required=True)
    p.add_argument('--sources', default='10.200.1.2')
    p.add_argument('--rates', default='100', help='pps per source, comma separated')
    p.add_argument('--duration', type=float, default=10)
    p.add_argument('--burst-count', type=int, default=0)
    args = p.parse_args()
    sources, rates = args.sources.split(','), [float(r) for r in args.rates.split(',')]
    if len(sources) != len(rates) or any(s not in ('10.200.1.2','10.200.1.3') for s in sources):
        p.error('Use assigned test sources .2/.3 and one rate per source')
    if any(not math.isfinite(r) or not 0 < r <= 2000 for r in rates):
        p.error('Functional-test rates must be >0 and <=2000 pps')
    if not math.isfinite(args.duration) or not 0 < args.duration <= 60:
        p.error('duration must be >0 and <=60 seconds')
    if not 0 <= args.burst_count <= 1000 or (args.burst_count and len(sources) != 1):
        p.error('burst-count must be 0..1000 and needs exactly one source')
    data = json.loads(subprocess.check_output(['ip','-j','addr','show','dev','veth1'],text=True))[0]
    local = {a['local'] for a in data['addr_info'] if a['family']=='inet'}
    if not set(sources) <= local:
        p.error('Run in kavach-test; source IPs must be assigned to veth1')
    src_mac = bytes.fromhex(data['address'].replace(':',''))
    dst_mac = bytes.fromhex(args.dst_mac.replace(':',''))
    if len(dst_mac) != 6:
        p.error('Invalid destination MAC')
    packets = [frame(s,src_mac,dst_mac) for s in sources]
    sent = [0] * len(sources)
    late = 0.0
    start = time.monotonic()
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as sock:
        sock.bind(('veth1',0))
        if args.burst_count:
            for _ in range(args.burst_count):
                sock.send(packets[0]); sent[0] += 1
        else:
            while True:
                due = [start + sent[i] / rates[i] for i in range(len(sources))]
                i = min(range(len(sources)),key=lambda j:due[j])
                if due[i] >= start + args.duration:
                    break
                delay = due[i] - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                late = max(late,time.monotonic()-due[i])
                sock.send(packets[i]); sent[i] += 1
    print(json.dumps({'sent':dict(zip(sources,sent)), 'elapsed_s':time.monotonic()-start,
                      'max_lateness_s':late}))

if __name__ == '__main__': main()
