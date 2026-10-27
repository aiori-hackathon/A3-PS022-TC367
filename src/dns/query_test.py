#!/usr/bin/env python3
"""
Kavach PS-022: Lightweight DNS Query Verification Tool

A standalone pure-Python query client to test DNS resolution against 10.99.0.2
without requiring 'dig' or external resolver libraries.
"""

import sys
import time
import socket
import struct
import argparse


def send_query(server_ip: str, domain: str, port: int = 53, timeout: float = 2.0):
    tid = 0x1A2B
    flags = 0x0100  # Standard query, recursion desired
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)

    # Encode domain name (e.g. www.lab.test -> \x03www\x03lab\x04test\x00)
    qname = b""
    for part in domain.strip(".").split("."):
        qname += struct.pack("B", len(part)) + part.encode("ascii")
    qname += b"\x00"

    qtype = 1  # Type A
    qclass = 1  # Class IN
    question = qname + struct.pack("!HH", qtype, qclass)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    t_start = time.perf_counter()
    try:
        sock.sendto(packet, (server_ip, port))
        data, _ = sock.recvfrom(4096)
        t_end = time.perf_counter()
        latency_ms = (t_end - t_start) * 1000.0

        if len(data) < 12:
            return False, "Response too short (< 12 bytes)", latency_ms

        resp_tid, resp_flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        rcode = resp_flags & 0x000F

        if resp_tid != tid:
            return False, f"Transaction ID mismatch ({resp_tid} != {tid})", latency_ms

        if rcode != 0:
            return False, f"DNS error response (RCODE={rcode})", latency_ms

        if ancount == 0:
            return False, "Received 0 answers", latency_ms

        # Extract answered IP from the last 4 bytes if single A record
        ans_ip = socket.inet_ntoa(data[-4:])
        return True, f"Answer: {ans_ip} (ancount={ancount})", latency_ms

    except socket.timeout:
        return False, "Query timed out", (timeout * 1000.0)
    except Exception as e:
        return False, f"Socket error: {e}", 0.0
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Kavach DNS Query Verification Tool")
    parser.add_argument("--server", default="10.99.0.2", help="DNS server IP (default: 10.99.0.2)")
    parser.add_argument("--domain", default="www.lab.test", help="Domain to query (default: www.lab.test)")
    parser.add_argument("--port", type=int, default=53, help="DNS port (default: 53)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    args = parser.parse_args()

    success, msg, lat = send_query(args.server, args.domain, args.port, args.timeout)
    status_str = "\033[1;32mSUCCESS\033[0m" if success else "\033[1;31mFAILED\033[0m"

    print(f"Query: {args.domain} -> Server: {args.server}:{args.port}")
    print(f"Status: {status_str} | Latency: {lat:.2f} ms | Details: {msg}")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

