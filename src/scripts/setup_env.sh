#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Namespace Development Environment Setup Script
#
# Sets up two isolated network namespaces ('gen' and 'srv') interconnected by
# a virtual ethernet (veth) pair ('vgen' <-> 'vsrv').
#
# Network Topology:
#   Namespace 'gen' (Traffic Generator):  vgen -> 10.99.0.1/24
#   Namespace 'srv' (Target Server / XDP): vsrv -> 10.99.0.2/24
#
# Safety & Containment:
#   - IPv6 explicitly disabled in both namespaces.
#   - IP forwarding disabled on 'gen' (ip_forward=0) to prevent reply leakage.
#   - Reverse path filtering disabled on 'srv' (rp_filter=0) for synthetic IPs.
#   - Checksum & segmentation offloads disabled on veth for reliable XDP handling.
# ==============================================================================

set -euo pipefail

# Configuration parameters (can be overridden via environment variables)
NS_GEN="${NS_GEN:-gen}"
NS_SRV="${NS_SRV:-srv}"
IF_GEN="${IF_GEN:-vgen}"
IF_SRV="${IF_SRV:-vsrv}"
IP_GEN="${IP_GEN:-10.99.0.1}"
IP_SRV="${IP_SRV:-10.99.0.2}"
SUBNET_MASK="${SUBNET_MASK:-24}"

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err() { echo -e "${RED}[ERROR]${NC} $*"; }

# 1. Enforce root privileges
if [[ $EUID -ne 0 ]]; then
    log_err "This script requires root privileges to configure network namespaces."
    log_err "Please run with: sudo $0"
    exit 1
fi

log_info "Initializing Kavach development testbed in network namespaces..."

# 2. Clean up any existing state (idempotency)
cleanup_existing() {
    if ip netns list | grep -qw "$NS_GEN"; then
        log_warn "Namespace '$NS_GEN' already exists. Cleaning up..."
        ip netns del "$NS_GEN" 2>/dev/null || true
    fi
    if ip netns list | grep -qw "$NS_SRV"; then
        log_warn "Namespace '$NS_SRV' already exists. Cleaning up..."
        ip netns del "$NS_SRV" 2>/dev/null || true
    fi
    # Delete leftover veth interfaces in host if detached
    ip link del "$IF_GEN" 2>/dev/null || true
    ip link del "$IF_SRV" 2>/dev/null || true
}

cleanup_existing

# 3. Create isolated network namespaces
log_info "Creating namespaces: '$NS_GEN' (generator) and '$NS_SRV' (server)..."
ip netns add "$NS_GEN"
ip netns add "$NS_SRV"

# 4. Create and attach veth pair
log_info "Creating veth pair '$IF_GEN' <---> '$IF_SRV'..."
ip link add "$IF_GEN" type veth peer name "$IF_SRV"
ip link set "$IF_GEN" netns "$NS_GEN"
ip link set "$IF_SRV" netns "$NS_SRV"

# 5. Configure IP addressing & bring links up
log_info "Configuring IP addresses on isolated test subnet (10.99.0.0/$SUBNET_MASK)..."
ip -n "$NS_GEN" addr add "${IP_GEN}/${SUBNET_MASK}" dev "$IF_GEN"
ip -n "$NS_SRV" addr add "${IP_SRV}/${SUBNET_MASK}" dev "$IF_SRV"

log_info "Bringing interfaces up..."
ip -n "$NS_GEN" link set lo up
ip -n "$NS_SRV" link set lo up
ip -n "$NS_GEN" link set "$IF_GEN" up
ip -n "$NS_SRV" link set "$IF_SRV" up

# 6. Safety and protocol containment rules
log_info "Configuring protocol flags and safety containment..."

# 6.1 Disable IPv6 across both namespaces (project scope exclusion)
for ns in "$NS_GEN" "$NS_SRV"; do
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
done

# 6.2 Disable Reverse Path Filtering on server (allows synthetic flood source IPs)
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.rp_filter=0
ip netns exec "$NS_SRV" sysctl -qw "net.ipv4.conf.${IF_SRV}.rp_filter=0"

# 6.3 Routing: route synthetic benchmark subnet back to generator (avoids default route conflict with XDP guard)
ip -n "$NS_SRV" route add 198.18.0.0/15 via "$IP_GEN" dev "$IF_SRV"

# 6.4 Generator containment: disable IP forwarding so spoofed replies never escape
ip netns exec "$NS_GEN" sysctl -qw net.ipv4.ip_forward=0

# 7. Disable offloads on veth interfaces for accurate packet processing in XDP
if command -v ethtool >/dev/null 2>&1; then
    log_info "Disabling hardware checksum / segmentation offloads on veth interfaces..."
    ip netns exec "$NS_GEN" ethtool -K "$IF_GEN" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
    ip netns exec "$NS_SRV" ethtool -K "$IF_SRV" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
else
    log_warn "ethtool not found; skipping offload disabling. If checksum oddities appear, install ethtool."
fi

# 8. Verify connectivity with ping test
log_info "Testing connectivity between namespaces ($IP_GEN -> $IP_SRV)..."
if ip netns exec "$NS_GEN" ping -c 2 -W 2 "$IP_SRV" >/dev/null 2>&1; then
    log_success "Connectivity verified successfully!"
else
    log_err "Connectivity test failed. Please check 'ip netns' and interface configurations."
    exit 1
fi

echo ""
log_success "Kavach development environment is ready!"
echo "----------------------------------------------------------------------"
echo "  Generator Namespace : $NS_GEN  (${IP_GEN}/${SUBNET_MASK} on $IF_GEN)"
echo "  Server Namespace    : $NS_SRV  (${IP_SRV}/${SUBNET_MASK} on $IF_SRV)"
echo ""
echo "Useful Commands:"
echo "  Execute command in generator : sudo ip netns exec $NS_GEN <command>"
echo "  Execute command in server    : sudo ip netns exec $NS_SRV <command>"
echo "  Test ping from generator     : sudo ip netns exec $NS_GEN ping $IP_SRV"
echo "  Teardown environment        : sudo ./src/scripts/teardown_env.sh"
echo "----------------------------------------------------------------------"

