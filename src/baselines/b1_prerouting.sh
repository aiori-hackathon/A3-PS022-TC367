#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Baseline B1 - nftables Prerouting (Raw, No Conntrack)
# Submission ID: A3-PS022-TC367
#
# Configures netfilter prerouting hook at raw priority (-300) with conntrack
# explicitly bypassed (notrack).
#
# Matching rule structure with Kavach XDP:
#   1. Per-source rate limit checked FIRST (dynamic set @flood)
#   2. Global aggregate rate limit checked SECOND
# ==============================================================================

set -euo pipefail

NETNS="${NETNS:-srv}"
IFACE="${IFACE:-vsrv}"
SRC_RATE=500
SRC_BURST=20
GLOB_RATE=7000
GLOB_BURST=100
FLUSH_ONLY=false
PARAMS_FILE=""

BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --netns) NETNS="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --src-rate) SRC_RATE="$2"; shift 2 ;;
        --src-burst) SRC_BURST="$2"; shift 2 ;;
        --glob-rate) GLOB_RATE="$2"; shift 2 ;;
        --glob-burst) GLOB_BURST="$2"; shift 2 ;;
        --params) PARAMS_FILE="$2"; shift 2 ;;
        --flush) FLUSH_ONLY=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--netns <ns>] [--iface <dev>] [--src-rate <pps>] [--src-burst <pkts>] [--glob-rate <pps>] [--glob-burst <pkts>] [--flush]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} nftables configuration requires root privileges: sudo $0"
    exit 1
fi

# Load parameters from JSON/YAML if provided
if [[ -n "$PARAMS_FILE" && -f "$PARAMS_FILE" ]]; then
    if python3 -c "import yaml" >/dev/null 2>&1; then
        SRC_RATE=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d['filter_limits']['src_rate'])")
        SRC_BURST=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d['filter_limits']['src_burst'])")
        GLOB_RATE=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d['filter_limits']['glob_rate'])")
        GLOB_BURST=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d['filter_limits']['glob_burst'])")
    fi
fi

NFT_EXEC=()
if [[ -n "$NETNS" ]] && ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    NFT_EXEC=(ip netns exec "$NETNS")
fi

# Always clean existing B1 table
"${NFT_EXEC[@]}" nft delete table ip kavach_b1 2>/dev/null || true

if [[ "$FLUSH_ONLY" == "true" ]]; then
    echo -e "${GREEN}[SUCCESS]${NC} Baseline B1 (ip kavach_b1) flushed cleanly."
    exit 0
fi

echo -e "${BLUE}[INFO]${NC} Applying Baseline B1 (prerouting raw, no conntrack) in ns '${NETNS}'..."
echo -e "${BLUE}[CONFIG]${NC} Per-Source: ${SRC_RATE} pps (burst ${SRC_BURST}) | Global: ${GLOB_RATE} pps (burst ${GLOB_BURST})"

# Build and apply atomic nftables ruleset
"${NFT_EXEC[@]}" nft -f - <<EOF
table ip kavach_b1 {
    set flood {
        type ipv4_addr
        flags dynamic, timeout
        size 65535
        timeout 10s
    }

    chain prerouting {
        type filter hook prerouting priority raw; policy accept;

        # Explicitly bypass connection tracking (no conntrack)
        notrack

        # Tier 1: Per-source GCRA/Token-bucket rate limit evaluated FIRST
        udp dport 53 add @flood { ip saddr limit rate over ${SRC_RATE}/second burst ${SRC_BURST} packets } counter drop

        # Tier 2: Global aggregate rate limit evaluated SECOND
        udp dport 53 limit rate over ${GLOB_RATE}/second burst ${GLOB_BURST} packets counter drop
    }
}
EOF

echo -e "${GREEN}[SUCCESS]${NC} Baseline B1 ruleset active on prerouting hook (raw priority -300, notrack enabled)."

