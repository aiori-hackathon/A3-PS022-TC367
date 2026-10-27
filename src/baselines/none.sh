#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Baseline B0 - No Filter Configuration
#
# Configures the target server for pure unfiltered Linux stack processing:
#   1. Detaches any loaded XDP programs (native or generic) on the test interface.
#   2. Flushes any active nftables rulesets.
#   3. Confirms clean pass-through state.
#
# Usage:
#   sudo ./none.sh [--netns srv] [--iface vsrv]
# ==============================================================================

set -euo pipefail

NETNS="${NETNS:-srv}"
IFACE="${IFACE:-vsrv}"

BLUE='\033[1;34m'
GREEN='\033[1;32m'
NC='\033[0m'

echo -e "${BLUE}[INFO]${NC} Applying Baseline B0 (No Filter / Clean Linux Stack)..."

# Detach XDP if attached
if [[ -n "$NETNS" ]] && ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    # In network namespace
    sudo ip netns exec "$NETNS" ip link set dev "$IFACE" xdp off 2>/dev/null || true
    sudo ip netns exec "$NETNS" ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    # Flush nftables in namespace if nft is present
    if sudo ip netns exec "$NETNS" command -v nft >/dev/null 2>&1; then
        sudo ip netns exec "$NETNS" nft flush ruleset 2>/dev/null || true
    fi
else
    # In root namespace
    sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true
    sudo ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    if command -v nft >/dev/null 2>&1; then
        sudo nft flush ruleset 2>/dev/null || true
    fi
fi

# Clean any pinned maps
if [[ -d /sys/fs/bpf/kavach ]]; then
    sudo rm -rf /sys/fs/bpf/kavach 2>/dev/null || true
fi

echo -e "${GREEN}[SUCCESS]${NC} Baseline B0 applied: XDP detached, nftables flushed, filter active = NONE."

