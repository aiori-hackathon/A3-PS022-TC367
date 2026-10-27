#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Namespace Development Environment Teardown Script
#
# Cleans up the namespaces ('gen' and 'srv') and associated veth links.
# ==============================================================================

set -euo pipefail

NS_GEN="${NS_GEN:-gen}"
NS_SRV="${NS_SRV:-srv}"
IF_GEN="${IF_GEN:-vgen}"
IF_SRV="${IF_SRV:-vsrv}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_err() { echo -e "${RED}[ERROR]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
    log_err "This script requires root privileges to remove network namespaces."
    log_err "Please run with: sudo $0"
    exit 1
fi

log_info "Tearing down Kavach namespace development environment..."

# Kill any lingering processes inside the namespaces (e.g. nsd, dnsperf, loaders)
for ns in "$NS_GEN" "$NS_SRV"; do
    if ip netns list | grep -qw "$ns"; then
        log_info "Terminating processes inside namespace '$ns'..."
        # Find pids associated with the network namespace
        pids=$(ip netns pids "$ns" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            echo "$pids" | xargs kill -9 2>/dev/null || true
        fi
        log_info "Deleting namespace '$ns'..."
        ip netns del "$ns" 2>/dev/null || true
    fi
done

# Ensure leftover veth peer interfaces in host root namespace are removed
ip link del "$IF_GEN" 2>/dev/null || true
ip link del "$IF_SRV" 2>/dev/null || true

log_success "Kavach development environment torn down cleanly."

