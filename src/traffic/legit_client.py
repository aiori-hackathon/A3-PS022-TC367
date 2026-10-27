#!/usr/bin/env python3
"""
Kavach PS-022: Open-Loop Legitimate DNS Client (v0)

Features & Methodology (PS-022 Section 9.1):
  - Strictly open-loop: Sends queries at a fixed schedule (default 100 QPS)
    regardless of whether prior queries were answered or delayed.
  - Dedicated Source IP: Binds to 10.99.0.1 (separate from attack flood prefix).
  - Fixed timeout (default 1.5s) with NO retries (dropped queries count as failures).
  - Queries real domains existing in the test zone (*.lab.test).
  - Detailed telemetry logging: seq, domain, send_time, recv_time, latency_ms, rcode, status.
  - Headline metrics: Success Rate (%), Latency p50 / p90 / p95 / p99.
  - Fully integrated with Generator Safety Guard (aborts outside 10.99.0.0/24).
"""

import os
import sys
import time
import math
import socket
import struct
import argparse
import threading
from typing import List, Dict, Any, Optional

# Enforce Generator Safety Guard before opening any network sockets
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
try:
    from guard import enforce_all, SecurityViolation
except ImportError:
    print("[ERROR] Cannot import guard.py from traffic directory!", file=sys.stderr)
    sys.exit(101)


def build_dns_query(seq: int, domain: str) -> tuple[int, bytes]:
    """Construct standard RFC 1035 UDP/53 DNS Type A query."""
    tid = seq & 0xFFFF
    flags = 0x0100  # Standard query, recursion desired (RD=1)
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)

    qname = b""
    for part in domain.strip(".").split("."):
        qname += struct.pack("B", len(part)) + part.encode("ascii")
    qname += b"\x00"

    qtype = 1  # Type A
    qclass = 1  # Class IN
    question = qname + struct.pack("!HH", qtype, qclass)
    return tid, header + question


class LegitClient:
    def __init__(
        self,
        server_ip: str = "10.99.0.2",
        server_port: int = 53,
        source_ip: str = "10.99.0.1",
        qps: float = 100.0,
        duration: float = 60.0,
        timeout: float = 1.5,
        domains: Optional[List[str]] = None,
        output_csv: Optional[str] = None,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.source_ip = source_ip
        self.qps = qps
        self.duration = duration
        self.timeout = timeout
        self.domains = domains or [
            "www.lab.test",
            "mail.lab.test",
            "api.lab.test",
            "dns.lab.test",
            "test1.lab.test",
            "test2.lab.test",
        ]
        self.output_csv = output_csv

        # Safety Guard assertion
        enforce_all(target_ip=self.server_ip, source_ip=self.source_ip)

        # Thread-safe query book-keeping
        self.lock = threading.Lock()
        self.queries: Dict[int, Dict[str, Any]] = {}
        self.tid_to_seq: Dict[int, int] = {}
        self.running = False
        self.sock: Optional[socket.socket] = None

    def _receiver_loop(self):
        """Continuously listens for DNS answers without blocking the sender."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                recv_time = time.time()
                perf_now = time.perf_counter()

                if len(data) < 12:
                    continue

                resp_tid, resp_flags = struct.unpack("!HH", data[:4])
                rcode = resp_flags & 0x000F

                with self.lock:
                    if resp_tid in self.tid_to_seq:
                        seq = self.tid_to_seq[resp_tid]
                        q = self.queries[seq]
                        if q["status"] == "PENDING":
                            latency_ms = (perf_now - q["perf_send"]) * 1000.0
                            q["recv_time"] = recv_time
                            q["latency_ms"] = latency_ms
                            q["rcode"] = rcode
                            q["status"] = "ANSWERED"
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    pass

    def run(self) -> Dict[str, Any]:
        """Executes the open-loop query benchmark."""
        total_queries = int(self.duration * self.qps)
        interval = 1.0 / self.qps

        print("\033[1;34m=== Kavach Legitimate Client (Open-Loop v0) ===\033[0m")
        print(f"Target Server   : {self.server_ip}:{self.server_port}")
        print(f"Source IP       : {self.source_ip}")
        print(f"Target Rate     : {self.qps:.1f} QPS (interval: {interval*1000:.2f} ms)")
        print(f"Test Duration   : {self.duration:.1f} s (~{total_queries} queries)")
        print(f"Query Timeout   : {self.timeout:.2f} s (no retries)")
        print(f"Test Domains    : {', '.join(self.domains[:3])} (+{len(self.domains)-3} more)")
        print("----------------------------------------------------------------------")

        # Initialize UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.2)
        try:
            self.sock.bind((self.source_ip, 0))
        except Exception as e:
            # If running in host or netns where 10.99.0.1 is not on local interface
            self.sock.bind(("0.0.0.0", 0))

        self.running = True
        recv_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        recv_thread.start()

        # Open-loop transmission loop
        t_start = time.perf_counter()
        domain_idx = 0

        for i in range(total_queries):
            seq = i + 1
            domain = self.domains[domain_idx % len(self.domains)]
            domain_idx += 1

            tid, packet = build_dns_query(seq, domain)

            # Wait for exact scheduled emission time
            target_time = t_start + (i * interval)
            now = time.perf_counter()
            if target_time > now:
                time.sleep(target_time - now)

            perf_send = time.perf_counter()
            send_time = time.time()

            with self.lock:
                self.queries[seq] = {
                    "seq": seq,
                    "domain": domain,
                    "tid": tid,
                    "send_time": send_time,
                    "perf_send": perf_send,
                    "recv_time": None,
                    "latency_ms": None,
                    "rcode": None,
                    "status": "PENDING",
                }
                self.tid_to_seq[tid] = seq

            try:
                self.sock.sendto(packet, (self.server_ip, self.server_port))
            except Exception as e:
                with self.lock:
                    self.queries[seq]["status"] = "SEND_ERROR"

        # Cooldown period: wait for in-flight responses up to timeout duration
        time.sleep(self.timeout)
        self.running = False
        recv_thread.join(timeout=1.0)
        self.sock.close()

        # Compute results
        sent = len(self.queries)
        answered = 0
        latencies = []

        for seq, q in self.queries.items():
            if q["status"] == "PENDING":
                q["status"] = "TIMEOUT"
            elif q["status"] == "ANSWERED":
                answered += 1
                latencies.append(q["latency_ms"])

        dropped = sent - answered
        success_rate = (answered / sent * 100.0) if sent > 0 else 0.0

        latencies.sort()

        def percentile(p):
            if not latencies:
                return 0.0
            k = (len(latencies) - 1) * (p / 100.0)
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return latencies[int(k)]
            d0 = latencies[int(f)] * (c - k)
            d1 = latencies[int(c)] * (k - f)
            return d0 + d1

        p50 = percentile(50)
        p90 = percentile(90)
        p95 = percentile(95)
        p99 = percentile(99)
        avg_lat = (sum(latencies) / len(latencies)) if latencies else 0.0
        min_lat = latencies[0] if latencies else 0.0
        max_lat = latencies[-1] if latencies else 0.0

        print("\033[1;32m=== Benchmark Results Summary ===\033[0m")
        print(f"Queries Sent    : {sent}")
        print(f"Queries Answered: {answered}")
        print(f"Queries Dropped : {dropped}")
        print(f"Success Rate    : \033[1;33m{success_rate:.2f}%\033[0m")
        print(f"Latency Min/Avg : {min_lat:.2f} ms / {avg_lat:.2f} ms")
        print(f"Latency p50     : {p50:.2f} ms")
        print(f"Latency p90     : {p90:.2f} ms")
        print(f"Latency p95     : {p95:.2f} ms")
        print(f"Latency p99     : {p99:.2f} ms")
        print(f"Latency Max     : {max_lat:.2f} ms")

        # Export CSV if requested
        if self.output_csv:
            os.makedirs(os.path.dirname(os.path.abspath(self.output_csv)), exist_ok=True)
            with open(self.output_csv, "w", encoding="utf-8") as f:
                f.write("seq,domain,send_time,recv_time,latency_ms,rcode,status\n")
                for seq in sorted(self.queries.keys()):
                    q = self.queries[seq]
                    r_time = f"{q['recv_time']:.6f}" if q["recv_time"] else ""
                    lat = f"{q['latency_ms']:.3f}" if q["latency_ms"] is not None else ""
                    rc = str(q["rcode"]) if q["rcode"] is not None else ""
                    f.write(f"{q['seq']},{q['domain']},{q['send_time']:.6f},{r_time},{lat},{rc},{q['status']}\n")
            print(f"\033[1;34m[SAVED]\033[0m Detailed query trace exported to: {self.output_csv}")

        return {
            "sent": sent,
            "answered": answered,
            "dropped": dropped,
            "success_rate": success_rate,
            "latency_p50": p50,
            "latency_p90": p90,
            "latency_p95": p95,
            "latency_p99": p99,
            "latency_avg": avg_lat,
        }


def main():
    parser = argparse.ArgumentParser(description="Kavach Open-Loop Legitimate DNS Client")
    parser.add_argument("--server", default="10.99.0.2", help="Target DNS server IP (default: 10.99.0.2)")
    parser.add_argument("--port", type=int, default=53, help="Target UDP port (default: 53)")
    parser.add_argument("--source-ip", default="10.99.0.1", help="Source IP to bind (default: 10.99.0.1)")
    parser.add_argument("--qps", type=float, default=100.0, help="Target queries per second (default: 100.0)")
    parser.add_argument("--duration", type=float, default=60.0, help="Test duration in seconds (default: 60.0)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Query timeout in seconds (default: 1.5)")
    parser.add_argument("--output", help="Path to save detailed per-query CSV log")
    parser.add_argument("--domains", help="Comma-separated domains to query (default: lab.test domains)")
    args = parser.parse_args()

    domain_list = [d.strip() for d in args.domains.split(",")] if args.domains else None

    client = LegitClient(
        server_ip=args.server,
        server_port=args.port,
        source_ip=args.source_ip,
        qps=args.qps,
        duration=args.duration,
        timeout=args.timeout,
        domains=domain_list,
        output_csv=args.output,
    )
    client.run()


if __name__ == "__main__":
    main()

