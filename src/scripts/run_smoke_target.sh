#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Target Server Smoke Run Helper (PC 1)
# Submission ID: A3-PS022-TC367
#
# Automates state reset, configuration application, and metric collection on
# PC 1 (Target / Server) during Phase B3 smoke tests.
#
# Usage:
#   sudo ./run_smoke_target.sh [--config B0|B1|B2|X] [--iface eno1] [--duration 14]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
XDP_DIR="$REPO_ROOT/xdp"
BASELINES_DIR="$REPO_ROOT/src/baselines"
DNS_DIR="$REPO_ROOT/src/dns"
PARAMS_FILE="$REPO_ROOT/src/params.yaml"

CONFIG=""
IFACE="eno1"
DURATION=14
CORE=1

BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --core) CORE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--config B0|B1|B2|X] [--iface <dev>] [--duration <sec>]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script requires root privileges: sudo $0"
    exit 1
fi

# Interactive menu if config not provided
if [[ -z "$CONFIG" ]]; then
    echo -e "${BLUE}====================================================================${NC}"
    echo -e "${BLUE} KAVACH TARGET SMOKE RUN HELPER (PC 1)${NC}"
    echo -e "${BLUE}====================================================================${NC}"
    echo "Choose Configuration to Apply on PC 1:"
    echo "  1) B0 : No Filter (Clean Linux Stack + DNS Server)"
    echo "  2) B1 : nftables Prerouting (Raw priority, no conntrack)"
    echo "  3) B2 : nftables Netdev Ingress (Earliest netfilter hook)"
    echo "  4) X  : Kavach XDP (Native driver mode, fallback to generic)"
    echo ""
    read -rp "Select configuration [1-4]: " choice
    case "$choice" in
        1) CONFIG="B0" ;;
        2) CONFIG="B1" ;;
        3) CONFIG="B2" ;;
        4) CONFIG="X" ;;
        *) echo -e "${RED}[ERROR] Invalid choice.${NC}"; exit 1 ;;
    esac
fi

CONFIG=$(echo "$CONFIG" | tr '[:lower:]' '[:upper:]')
RUN_DIR="$REPO_ROOT/results/raw/smoke_S1_${CONFIG}_1.0x_1"
mkdir -p "$RUN_DIR"

echo -e "\n${BLUE}[INFO] Running Smoke Setup for '${CONFIG}' on interface '${IFACE}' (Duration: ${DURATION}s)...${NC}"

# Read parameters
SRC_RATE=500
SRC_BURST=20
GLOB_RATE=7000
GLOB_BURST=20

if [[ -f "$PARAMS_FILE" ]] && python3 -c "import yaml" 2>/dev/null; then
    SRC_RATE=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d.get('filter_limits', {}).get('src_rate', 500))")
    SRC_BURST=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d.get('filter_limits', {}).get('src_burst', 20))")
    GLOB_RATE=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d.get('filter_limits', {}).get('glob_rate', 7000))")
    GLOB_BURST=$(python3 -c "import yaml; d=yaml.safe_load(open('$PARAMS_FILE')); print(d.get('filter_limits', {}).get('glob_burst', 20))")
fi

# 1. State Reset
echo -e "${BLUE}[1/4] Resetting system state...${NC}"
ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
ip link set dev "$IFACE" xdp off 2>/dev/null || true
python3 "$XDP_DIR/kavach_ctl.py" detach --iface "$IFACE" 2>/dev/null || true
python3 "$XDP_DIR/kavach_ctl.py" unload 2>/dev/null || true
rm -rf /sys/fs/bpf/kavach 2>/dev/null || true
nft flush ruleset 2>/dev/null || true
ip neigh flush all 2>/dev/null || true

# 2. Start DNS Server on Core 1
echo -e "${BLUE}[2/4] Ensuring Authoritative DNS Server is running on Core ${CORE}...${NC}"
"$DNS_DIR/start_dns.sh" --host --iface "$IFACE" --core "$CORE"

# 3. Apply Configuration
echo -e "${BLUE}[3/4] Applying filter configuration '${CONFIG}'...${NC}"
XDP_MODE="none"
if [[ "$CONFIG" == "B0" ]]; then
    "$BASELINES_DIR/none.sh" --iface "$IFACE" --netns ""
elif [[ "$CONFIG" == "B1" ]]; then
    "$BASELINES_DIR/b1_prerouting.sh" --iface "$IFACE" --netns "" \
        --src-rate "$SRC_RATE" --src-burst "$SRC_BURST" --glob-rate "$GLOB_RATE" --glob-burst "$GLOB_BURST"
elif [[ "$CONFIG" == "B2" ]]; then
    "$BASELINES_DIR/b2_netdev.sh" --iface "$IFACE" --netns "" \
        --src-rate "$SRC_RATE" --src-burst "$SRC_BURST" --glob-rate "$GLOB_RATE" --glob-burst "$GLOB_BURST"
elif [[ "$CONFIG" == "X" ]]; then
    python3 "$XDP_DIR/kavach_ctl.py" load
    python3 "$XDP_DIR/kavach_ctl.py" config \
        --src-rate "$SRC_RATE" --src-burst "$SRC_BURST" --glob-rate "$GLOB_RATE" --glob-burst "$GLOB_BURST"
    echo -e "${BLUE}[INFO] Attempting native XDP attachment (xdpdrv)...${NC}"
    if python3 "$XDP_DIR/kavach_ctl.py" attach native --iface "$IFACE" --watchdog-minutes 5 2>/dev/null; then
        XDP_MODE="native"
        echo -e "${GREEN}[SUCCESS] Attached XDP in native mode (xdpdrv).${NC}"
    else
        echo -e "${YELLOW}[WARN] Native attach failed; falling back to generic mode (xdpgeneric)...${NC}"
        python3 "$XDP_DIR/kavach_ctl.py" attach generic --iface "$IFACE" --watchdog-minutes 5
        XDP_MODE="generic"
        echo -e "${GREEN}[SUCCESS] Attached XDP in generic mode (xdpgeneric).${NC}"
    fi
else
    echo -e "${RED}[ERROR] Unknown config: $CONFIG${NC}"; exit 1
fi

# 4. Launch Metric Collector
echo -e "\n${BLUE}[4/4] Starting Metric Collector for ${DURATION}s...${NC}"
echo -e "${YELLOW}>>> READY FOR TRAFFIC FROM PC 2 NOW! <<<${NC}"
python3 "$SCRIPT_DIR/collect_metrics.py" \
    -d "$DURATION" \
    -o "$RUN_DIR" \
    -i "$IFACE" \
    -c "$CORE" \
    --interval 1.0

echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN}[SUCCESS] Smoke test collection complete for '${CONFIG}'!${NC}"
echo -e "Telemetry artifacts saved in: ${RUN_DIR}"
echo -e "${GREEN}====================================================================${NC}\n"

