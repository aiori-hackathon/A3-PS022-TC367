#!/usr/bin/env python3
"""
Kavach PS-022: Generator Safety Guard (Python Module & CLI)

Enforces non-negotiable containment boundaries for traffic generators:
  - Destination IP must strictly belong to 10.99.0.0/24 (Target).
  - Synthetic source IPs must strictly belong to 198.18.0.0/15 (RFC 2544).
  - Legitimate source IP is 10.99.0.1.
  - net.ipv4.ip_forward must be 0 on generator host.
"""

import sys
import ipaddress
import argparse
from typing import Optional

LAB_SUBNET = ipaddress.ip_network("10.99.0.0/24")
SYNTHETIC_SRC_SUBNET = ipaddress.ip_network("198.18.0.0/15")
LEGIT_SRC_IP = ipaddress.ip_address("10.99.0.1")


class SecurityViolation(Exception):
    """Raised when a traffic generation parameter violates lab isolation."""
    pass


def validate_target_ip(target_ip_str: str) -> bool:
    """
    Validate that target destination IP strictly resides within 10.99.0.0/24
    and is neither the network address nor broadcast address.
    """
    try:
        addr = ipaddress.ip_address(target_ip_str)
    except ValueError as e:
        raise SecurityViolation(f"Invalid target IP format: '{target_ip_str}': {e}")

    if addr not in LAB_SUBNET:
        raise SecurityViolation(
            f"[FATAL SECURITY VIOLATION] Target IP '{target_ip_str}' is OUTSIDE the lab subnet ({LAB_SUBNET})!\n"
            f"Kavach traffic generators are strictly prohibited from transmitting outside the isolated testbed."
        )

    if addr == LAB_SUBNET.network_address or addr == LAB_SUBNET.broadcast_address:
        raise SecurityViolation(f"Target IP '{target_ip_str}' is network/broadcast address!")

    return True


def validate_source_ip(source_ip_str: str) -> bool:
    """
    Validate that source IP is either the legitimate client IP (10.99.0.1)
    or strictly within the synthetic flood reservation (198.18.0.0/15).
    """
    try:
        addr = ipaddress.ip_address(source_ip_str)
    except ValueError as e:
        raise SecurityViolation(f"Invalid source IP format: '{source_ip_str}': {e}")

    if addr == LEGIT_SRC_IP:
        return True

    if addr in SYNTHETIC_SRC_SUBNET:
        return True

    raise SecurityViolation(
        f"[FATAL SECURITY VIOLATION] Source IP '{source_ip_str}' is not permitted!\n"
        f"Synthetic flood sources must strictly fall within RFC 2544 reservation: {SYNTHETIC_SRC_SUBNET} "
        f"or legitimate address: {LEGIT_SRC_IP}"
    )


def validate_ip_forward() -> bool:
    """Validate that net.ipv4.ip_forward is 0 to prevent reply leakage."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            val = f.read().strip()
            if val != "0":
                raise SecurityViolation(
                    f"net.ipv4.ip_forward is enabled ({val})! "
                    f"Must be 0 to prevent reply leakage. Fix with: sudo sysctl -w net.ipv4.ip_forward=0"
                )
    except FileNotFoundError:
        pass  # Non-Linux system or testbed environment without procfs
    return True


def enforce_all(target_ip: str, source_ip: Optional[str] = None) -> bool:
    """Execute all mandatory guard checks."""
    validate_target_ip(target_ip)
    if source_ip:
        validate_source_ip(source_ip)
    validate_ip_forward()
    return True


def main():
    parser = argparse.ArgumentParser(description="Kavach Generator Safety Guard CLI")
    parser.add_argument("-t", "--target", help="Target destination IP (must be in 10.99.0.0/24)")
    parser.add_argument("-s", "--source", help="Source IP (must be in 198.18.0.0/15 or 10.99.0.1)")
    parser.add_argument("--check-forwarding", action="store_true", help="Check net.ipv4.ip_forward == 0")
    args = parser.parse_args()

    try:
        if args.target:
            validate_target_ip(args.target)
        if args.source:
            validate_source_ip(args.source)
        if args.check_forwarding:
            validate_ip_forward()
        print("\033[1;32m[GUARD PASSED] Traffic safety boundaries verified.\033[0m")
        sys.exit(0)
    except SecurityViolation as sv:
        print(f"\033[1;31m{sv}\033[0m", file=sys.stderr)
        sys.exit(100)


if __name__ == "__main__":
    main()

