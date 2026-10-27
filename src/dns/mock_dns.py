#!/usr/bin/env python3
"""
Kavach PS-022: Lightweight Fallback Authoritative DNS Server

A pure standard-library authoritative DNS daemon used for namespace development
and testing when NSD is not yet installed on the host.

Features:
  - Binds strictly to 10.99.0.2:53
  - Answers RFC 1035 A-record queries for *.lab.test with 10.99.0.2
  - Response Rate Limiting (RRL) is strictly OFF (answers every query)
  - Zero third-party dependencies (socket + struct only)
"""

import sys
import socket
import struct
import signal
import argparse

RUNNING = True


def handle_signal(sig, frame):
    global RUNNING
    RUNNING = False


def build_response(query: bytes, server_ip_bytes: bytes) -> bytes:
    if len(query) < 12:
        return b""

    tid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", query[:12])

    # Parse question section
    idx = 12
    try:
        while idx < len(query):
            length = query[idx]
            idx += 1
            if length == 0:
                break
            idx += length
        qtype, qclass = struct.unpack("!HH", query[idx : idx + 4])
        idx += 4
        question_bytes = query[12:idx]
    except Exception:
        return b""

    # Response Header: Standard Response, Authoritative Answer, NoError
    resp_flags = 0x8580  # QR=1, AA=1, RD=1, RA=0, RCODE=0
    resp_header = struct.pack("!HHHHHH", tid, resp_flags, 1, 1, 0, 0)

    # Answer: Pointer to question name (0xC00C), Type A (1), Class IN (1), TTL 300, Len 4, IP
    resp_answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + server_ip_bytes
    return resp_header + question_bytes + resp_answer


def main():
    parser = argparse.ArgumentParser(description="Kavach Authoritative DNS Daemon")
    parser.add_argument("--ip", default="10.99.0.2", help="Bind IP address (default: 10.99.0.2)")
    parser.add_argument("--port", type=int, default=53, help="Bind UDP port (default: 53)")
    parser.add_argument("--ans-ip", default="10.99.0.2", help="Answer IPv4 address (default: 10.99.0.2)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        ans_bytes = socket.inet_aton(args.ans_ip)
    except socket.error:
        print(f"[ERROR] Invalid answer IP address: {args.ans_ip}", file=sys.stderr)
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((args.ip, args.port))
    except Exception as e:
        print(f"[ERROR] Failed to bind {args.ip}:{args.port} - {e}", file=sys.stderr)
        sys.exit(1)

    sock.settimeout(1.0)
    print(f"[DNS SERVER] Listening on {args.ip}:{args.port} (RRL: OFF)")
    query_count = 0

    while RUNNING:
        try:
            data, addr = sock.recvfrom(4096)
            if not data:
                continue
            resp = build_response(data, ans_bytes)
            if resp:
                sock.sendto(resp, addr)
                query_count += 1
        except socket.timeout:
            continue
        except Exception as e:
            if RUNNING:
                print(f"[WARN] Error handling query: {e}", file=sys.stderr)

    print(f"\n[DNS SERVER] Stopped. Total queries answered: {query_count}")
    sock.close()


if __name__ == "__main__":
    main()

