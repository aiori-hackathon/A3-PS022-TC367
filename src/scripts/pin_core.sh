#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Host Core Pinning & System Tuning Script
# Submission ID: A3-PS022-TC367
#
# Configures single-core affinity, NIC IRQ pinning, CPU scaling governor, and
# sysctl containment rules on the physical lab hosts (Target and Generator).
#
# Usage:
#   sudo ./pin_core.sh [--iface eno1] [--core 1] [--irq <num>] [--role target|generator]
# ==============================================================================

set -euo pipefail

IFACE="eno1"
CORE=1
ROLE="target"
EXPLICIT_IRQ=""

BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface) IFACE="$2"; shift 2 ;;
        --core) CORE="$2"; shift 2 ;;
        --irq) EXPLICIT_IRQ="$2"; shift 2 ;;
        --role) ROLE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--iface <dev>] [--core <cpu_id>] [--irq <irq_num>] [--role target|generator]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script requires root privileges: sudo $0"
    exit 1
fi

echo -e "${BLUE}[INFO]${NC} ===================================================================="
echo -e "${BLUE}[INFO]${NC} Kavach Host Tuning & Core Pinning (Role: ${ROLE}, Interface: ${IFACE}, Core: ${CORE})"
echo -e "${BLUE}[INFO]${NC} ===================================================================="

# 1. Stop background jitter services
echo -e "${BLUE}[1/5] Stopping background jitter services (irqbalance, unattended-upgrades)...${NC}"
systemctl stop irqbalance unattended-upgrades 2>/dev/null || true
systemctl disable unattended-upgrades 2>/dev/null || true
echo -e "${GREEN}[OK] Background jitter services disabled.${NC}"

# 2. Force CPU frequency scaling governor to 'performance' on all cores
echo -e "${BLUE}[2/5] Setting CPU governor to 'performance' across all cores...${NC}"
GOV_PATHS=(/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
if [[ -e "${GOV_PATHS[0]}" ]]; then
    for g in "${GOV_PATHS[@]}"; do
        echo "performance" > "$g" 2>/dev/null || true
    done
    ACTUAL_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[OK] CPU scaling governor set to '${ACTUAL_GOV}'.${NC}"
else
    echo -e "${YELLOW}[WARN] CPU frequency governor path not found (virtualized/container environment).${NC}"
fi

# 3. Pin NIC Interrupts to Core
echo -e "${BLUE}[3/5] Pinning NIC Interrupts for interface '${IFACE}' to Core ${CORE}...${NC}"
IRQS=()
if [[ -n "$EXPLICIT_IRQ" ]]; then
    IRQS+=("$EXPLICIT_IRQ")
else
    # Auto-detect IRQs associated with the interface or the Intel controller PCI device (0000:80:1f.6 / e1000e)
    while IFS= read -r line; do
        irq_num=$(echo "$line" | awk -F: '{print $1}' | tr -d ' ')
        if [[ -n "$irq_num" && "$irq_num" =~ ^[0-9]+$ ]]; then
            IRQS+=("$irq_num")
        fi
    done < <(grep -E "${IFACE}|80:1f\.6|e1000e" /proc/interrupts 2>/dev/null || true)
fi

if [[ ${#IRQS[@]} -gt 0 ]]; then
    for irq in "${IRQS[@]}"; do
        if [[ -f "/proc/irq/${irq}/smp_affinity_list" ]]; then
            echo "$CORE" > "/proc/irq/${irq}/smp_affinity_list"
            AFF=$(cat "/proc/irq/${irq}/smp_affinity_list" 2>/dev/null || echo "err")
            echo -e "${GREEN}[OK] Pinned IRQ ${irq} to Core list: ${AFF}${NC}"
        else
            echo -e "${YELLOW}[WARN] /proc/irq/${irq}/smp_affinity_list does not exist.${NC}"
        fi
    done
else
    echo -e "${YELLOW}[WARN] No IRQs found matching '${IFACE}' or '80:1f.6' in /proc/interrupts.${NC}"
    echo -e "${YELLOW}[NOTE] If testing in namespaces or virtual interfaces, hardware IRQ pinning is skipped.${NC}"
fi

# 4. Configure Sysctl Parameters
echo -e "${BLUE}[4/5] Applying network sysctl parameters for role '${ROLE}'...${NC}"
if [[ "$ROLE" == "target" ]]; then
    # Server / DUT: rp_filter=0 (XDP executes before rp_filter), disable IPv6 on test NIC
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w "net.ipv4.conf.${IFACE}.rp_filter=0" >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
    sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=1" >/dev/null 2>&1 || true
    echo -e "${GREEN}[OK] Target sysctls: rp_filter=0, disable_ipv6=1.${NC}"
else
    # Generator: ip_forward=0 (hard safety guard), disable IPv6 on test NIC
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
    sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=1" >/dev/null 2>&1 || true
    echo -e "${GREEN}[OK] Generator sysctls: ip_forward=0, disable_ipv6=1.${NC}"
fi

# 5. Verification Summary
echo -e "${BLUE}[5/5] Host Tuning Verification Summary:${NC}"
echo -e "  - CPU Core Pinning Target : Core ${CORE}"
echo -e "  - CPU Governor             : $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'n/a')"
echo -e "  - Tested Interface        : ${IFACE}"
echo -e "  - Active IPv4 Address     : $(ip -br addr show dev "$IFACE" 2>/dev/null | awk '{print $3}' || echo 'unassigned')"
echo -e "  - net.ipv4.ip_forward     : $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'n/a')"
echo -e "  - rp_filter (all)         : $(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 'n/a')"
echo -e "  - disable_ipv6 (all)      : $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 'n/a')"
echo -e "${GREEN}====================================================================${NC}"
echo -e "${GREEN}[SUCCESS] Host successfully tuned and pinned to Core ${CORE}!${NC}"
echo -e "${GREEN}====================================================================${NC}"

