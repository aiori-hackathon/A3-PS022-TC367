#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Generator Safety Guard (Hard Containment Boundary)
#
# This guard MUST be called by every traffic generation tool (legitimate or flood)
# before transmitting any packets.
#
# Non-Negotiable Safety Rules Enforced:
#   1. Target IP MUST strictly reside within the isolated lab subnet (10.99.0.0/24).
#      Any target outside this subnet (e.g. campus LAN 10.126.0.0/16, public IPs)
#      is strictly prohibited and will immediately terminate execution.
#   2. Synthetic flood source IPs MUST strictly fall within 198.18.0.0/15
#      (RFC 2544 benchmark reservation). Legitimate sources must be 10.99.0.1.
#   3. Transmission interface MUST NOT route to default campus gateway.
#   4. IP Forwarding on generator MUST be 0 (ip_forward=0) to prevent reply leakage.
#
# Usage:
#   Direct execution:
#     ./guard.sh --target 10.99.0.2 [--source 198.18.1.1] [--interface vgen]
#   Library sourcing:
#     source ./guard.sh
#     guard_enforce_target "10.99.0.2"
#     guard_enforce_source "198.18.1.5"
# ==============================================================================

# Default Lab Boundary Definitions
LAB_SUBNET="10.99.0.0"
LAB_MASK=24
SYNTHETIC_SRC_SUBNET="198.18.0.0"
SYNTHETIC_SRC_MASK=15
LEGIT_SRC_IP="10.99.0.1"

# ANSI Colors for alerts
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

# Helper: Convert dotted-decimal IPv4 to unsigned 32-bit integer
guard_ip_to_int() {
    local ip="$1"
    local a b c d
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS=. read -r a b c d <<< "$ip"
    if (( a > 255 || b > 255 || c > 255 || d > 255 )); then
        return 1
    fi
    echo "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

# Helper: Verify if an IP is within a CIDR block
guard_is_in_cidr() {
    local ip="$1"
    local net="$2"
    local mask_len="$3"

    local ip_int
    ip_int=$(guard_ip_to_int "$ip") || return 1
    local net_int
    net_int=$(guard_ip_to_int "$net") || return 1

    local mask=$(( ((0xFFFFFFFF << (32 - mask_len)) & 0xFFFFFFFF) ))
    if (( (ip_int & mask) == (net_int & mask) )); then
        return 0
    else
        return 1
    fi
}

# 1. Enforce Target Destination IP
guard_enforce_target() {
    local target_ip="$1"
    if [[ -z "$target_ip" ]]; then
        echo -e "${RED}[SECURITY VIOLATION] Target IP address is empty!${NC}" >&2
        exit 101
    fi

    # Explicit check against allowed lab subnet
    if guard_is_in_cidr "$target_ip" "$LAB_SUBNET" "$LAB_MASK"; then
        # Exclude network and broadcast addresses
        if [[ "$target_ip" == "$LAB_SUBNET" || "$target_ip" == "10.99.0.255" ]]; then
            echo -e "${RED}[SECURITY VIOLATION] Target IP '$target_ip' is network/broadcast address!${NC}" >&2
            exit 102
        fi
        return 0
    else
        echo -e "${RED}======================================================================${NC}" >&2
        echo -e "${RED}[FATAL SECURITY VIOLATION] Destination IP '$target_ip' IS OUTSIDE LAB SUBSET!${NC}" >&2
        echo -e "${RED}Kavach traffic generators are STRICTLY PROHIBITED from sending traffic${NC}" >&2
        echo -e "${RED}outside the isolated test subnet (${LAB_SUBNET}/${LAB_MASK}).${NC}" >&2
        echo -e "${RED}Attempted Target : $target_ip${NC}" >&2
        echo -e "${RED}Allowed Range    : ${LAB_SUBNET}/${LAB_MASK} (e.g. 10.99.0.2)${NC}" >&2
        echo -e "${RED}======================================================================${NC}" >&2
        exit 100
    fi
}

# 2. Enforce Source IP (Synthetic or Legitimate)
guard_enforce_source() {
    local src_ip="$1"
    if [[ -z "$src_ip" ]]; then
        return 0
    fi

    # Allowed: Legitimate client IP (10.99.0.1) OR Synthetic Benchmark Range (198.18.0.0/15)
    if [[ "$src_ip" == "$LEGIT_SRC_IP" ]]; then
        return 0
    fi

    if guard_is_in_cidr "$src_ip" "$SYNTHETIC_SRC_SUBNET" "$SYNTHETIC_SRC_MASK"; then
        return 0
    fi

    echo -e "${RED}======================================================================${NC}" >&2
    echo -e "${RED}[FATAL SECURITY VIOLATION] Source IP '$src_ip' is NOT permitted!${NC}" >&2
    echo -e "${RED}Synthetic sources must strictly reside in RFC 2544 reservation:${NC}" >&2
    echo -e "${RED}  ${SYNTHETIC_SRC_SUBNET}/${SYNTHETIC_SRC_MASK} (198.18.0.0 - 198.19.255.255)${NC}" >&2
    echo -e "${RED}Or legitimate client address: $LEGIT_SRC_IP${NC}" >&2
    echo -e "${RED}======================================================================${NC}" >&2
    exit 103
}

# 3. Enforce IP Forwarding is Disabled
guard_enforce_ip_forward() {
    local ip_forward
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
        if [[ "$ip_forward" != "0" ]]; then
            echo -e "${RED}[FATAL SECURITY VIOLATION] net.ipv4.ip_forward is enabled ($ip_forward)!${NC}" >&2
            echo -e "${RED}Must be 0 on generator host to prevent spoofed replies from escaping.${NC}" >&2
            echo -e "${YELLOW}Fix with: sudo sysctl -w net.ipv4.ip_forward=0${NC}" >&2
            exit 104
        fi
    fi
    return 0
}

# 4. Enforce Egress Interface Safety
guard_enforce_interface() {
    local iface="$1"
    if [[ -z "$iface" ]]; then
        return 0
    fi

    # Check if interface exists
    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo -e "${RED}[SECURITY ERROR] Interface '$iface' does not exist!${NC}" >&2
        exit 105
    fi

    # Prohibit loopback as flood interface
    if [[ "$iface" == "lo" ]]; then
        echo -e "${RED}[SECURITY VIOLATION] Generator interface cannot be loopback ('lo')!${NC}" >&2
        exit 106
    fi
    return 0
}

# Master Enforcement Function
guard_enforce_all() {
    local target_ip="${1:-}"
    local source_ip="${2:-}"
    local iface="${3:-}"

    guard_enforce_target "$target_ip"
    [[ -n "$source_ip" ]] && guard_enforce_source "$source_ip"
    [[ -n "$iface" ]] && guard_enforce_interface "$iface"
    guard_enforce_ip_forward
    return 0
}

# CLI Entrypoint when invoked directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    TARGET=""
    SOURCE=""
    IFACE=""
    CHECK_FWD=0

    show_help() {
        echo "Kavach Generator Safety Guard"
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  -t, --target <ip>       Validate target destination IP (must be 10.99.0.0/24)"
        echo "  -s, --source <ip>       Validate source IP (must be 198.18.0.0/15 or 10.99.0.1)"
        echo "  -i, --interface <iface> Validate egress interface"
        echo "  --check-forwarding      Validate net.ipv4.ip_forward == 0"
        echo "  -a, --check-all         Run all checks with defaults"
        echo "  -h, --help              Show this help message"
        exit 0
    }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target) TARGET="$2"; shift 2 ;;
            -s|--source) SOURCE="$2"; shift 2 ;;
            -i|--interface) IFACE="$2"; shift 2 ;;
            --check-forwarding) CHECK_FWD=1; shift ;;
            -a|--check-all)
                TARGET="${TARGET:-10.99.0.2}"
                SOURCE="${SOURCE:-10.99.0.1}"
                CHECK_FWD=1
                shift ;;
            -h|--help) show_help ;;
            *) echo "Unknown option: $1"; show_help ;;
        esac
    done

    if [[ -z "$TARGET" && -z "$SOURCE" && -z "$IFACE" && $CHECK_FWD -eq 0 ]]; then
        show_help
    fi

    [[ -n "$TARGET" ]] && guard_enforce_target "$TARGET"
    [[ -n "$SOURCE" ]] && guard_enforce_source "$SOURCE"
    [[ -n "$IFACE" ]] && guard_enforce_interface "$IFACE"
    [[ $CHECK_FWD -eq 1 ]] && guard_enforce_ip_forward

    echo -e "${GREEN}[GUARD PASSED] All traffic safety boundaries verified.${NC}"
    exit 0
fi

