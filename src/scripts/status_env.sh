#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Namespace Environment Status Inspection Script
#
# Inspects namespaces, interface link states, addresses, routes, and sysctls.
# ==============================================================================

set -euo pipefail

NS_GEN="${NS_GEN:-gen}"
NS_SRV="${NS_SRV:-srv}"
IF_GEN="${IF_GEN:-vgen}"
IF_SRV="${IF_SRV:-vsrv}"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Please run with root privileges: sudo $0"
    exit 1
fi

echo -e "${BLUE}=== Kavach Namespace Environment Status ===${NC}"

# Check namespaces
echo -n "Namespaces: "
if ip netns list | grep -qw "$NS_GEN" && ip netns list | grep -qw "$NS_SRV"; then
    echo -e "${GREEN}ACTIVE ($NS_GEN, $NS_SRV)${NC}"
else
    echo -e "${RED}INACTIVE or INCOMPLETE${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}--- Generator Namespace ('$NS_GEN') ---${NC}"
ip -n "$NS_GEN" -br addr
echo -n "ip_forward: "
ip netns exec "$NS_GEN" sysctl -n net.ipv4.ip_forward
echo -n "disable_ipv6: "
ip netns exec "$NS_GEN" sysctl -n net.ipv6.conf.all.disable_ipv6

echo ""
echo -e "${BLUE}--- Server Namespace ('$NS_SRV') ---${NC}"
ip -n "$NS_SRV" -br addr
echo -n "Default route: "
ip -n "$NS_SRV" route show default || echo "none"
echo -n "rp_filter (all / $IF_SRV): "
echo "$(ip netns exec "$NS_SRV" sysctl -n net.ipv4.conf.all.rp_filter) / $(ip netns exec "$NS_SRV" sysctl -n "net.ipv4.conf.${IF_SRV}.rp_filter")"
echo -n "disable_ipv6: "
ip netns exec "$NS_SRV" sysctl -n net.ipv6.conf.all.disable_ipv6

echo ""
echo -e "${BLUE}--- Connectivity Test ---${NC}"
if ip netns exec "$NS_GEN" ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; then
    echo -e "${GREEN}Ping 10.99.0.1 -> 10.99.0.2: SUCCESS${NC}"
else
    echo -e "${RED}Ping 10.99.0.1 -> 10.99.0.2: FAILED${NC}"
fi

