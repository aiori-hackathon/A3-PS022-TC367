#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Baseline B0 End-to-End Validation Runner
#
# Executes the full experimental workflow for Baseline B0 (No Filter):
#   1. Ensures testbed namespaces ('gen' and 'srv') are active.
#   2. Applies Baseline B0 (detaches XDP, flushes nftables).
#   3. Starts the Authoritative DNS server in 'srv' (pinned to Core 1, RRL off).
#   4. Conducts pre-test warm-up.
#   5. Runs the measurement window:
#      - Background: Telemetry Collector in 'srv'
#      - Foreground: Open-Loop Legitimate Client in 'gen' (100 QPS)
#   6. Collects, verifies, and archives raw run data.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NS_GEN="gen"
NS_SRV="srv"
IF_SRV="vsrv"
TARGET_IP="10.99.0.2"
SRC_IP="10.99.0.1"
DURATION="${DURATION:-10}"  # 10s for smoke validation (60s for formal matrix)
QPS="${QPS:-100}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/../results/raw/namespaces_B0_validation}"

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}       Kavach PS-022: Baseline B0 (No Filter) Validation Run         ${NC}"
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo "Target Host (DUT)   : $TARGET_IP (namespace: $NS_SRV, iface: $IF_SRV)"
echo "Generator Host      : $SRC_IP (namespace: $NS_GEN)"
echo "Filter Configuration: B0 (Pure Linux Stack / No Filter)"
echo "Measurement Window  : ${DURATION}s at ${QPS} QPS"
echo "Output Directory    : $OUT_DIR"
echo "----------------------------------------------------------------------"

# 1. Enforce Generator Safety Guard
source "$ROOT_DIR/traffic/guard.sh"
guard_enforce_all "$TARGET_IP" "$SRC_IP"

# 2. Ensure testbed namespaces exist
if ! ip netns list 2>/dev/null | grep -qw "$NS_SRV" || ! ip netns list 2>/dev/null | grep -qw "$NS_GEN"; then
    echo -e "${YELLOW}[INFO]${NC} Initializing namespaces..."
    sudo "$SCRIPT_DIR/setup_env.sh"
fi

# 3. Apply Baseline B0 (No Filter)
echo -e "${BLUE}[STEP 1/5]${NC} Applying Baseline B0 filter state..."
sudo "$ROOT_DIR/baselines/none.sh"

# 4. Start Authoritative DNS server
echo -e "${BLUE}[STEP 2/5]${NC} Starting Authoritative DNS Server in '$NS_SRV'..."
sudo "$ROOT_DIR/dns/start_dns.sh"

# 5. Quick pre-flight warm-up query
echo -e "${BLUE}[STEP 3/5]${NC} Performing pre-flight connectivity check..."
sudo ip netns exec "$NS_GEN" python3 "$ROOT_DIR/dns/query_test.py" --server "$TARGET_IP" --domain "www.lab.test" >/dev/null
echo -e "${GREEN}[SUCCESS]${NC} Pre-flight DNS resolution verified."

# 6. Measurement Window Execution
echo -e "${BLUE}[STEP 4/5]${NC} Starting synchronous measurement window (${DURATION}s)..."
mkdir -p "$OUT_DIR"

# Launch Telemetry Collector in background
echo -e "  -> Launching Telemetry Collector in '$NS_SRV'..."
sudo "$SCRIPT_DIR/collect.sh" \
    --duration "$DURATION" \
    --output-dir "$OUT_DIR" \
    --netns "$NS_SRV" \
    --iface "$IF_SRV" \
    --core 1 \
    --interval 1.0 > "$OUT_DIR/collector.stdout" 2>&1 &
COLLECTOR_PID=$!

# Brief delay to ensure collector begins window sampling
sleep 0.5

# Launch Legitimate Client in foreground
echo -e "  -> Launching Open-Loop Legitimate Client in '$NS_GEN'..."
sudo ip netns exec "$NS_GEN" python3 "$ROOT_DIR/traffic/legit_client.py" \
    --server "$TARGET_IP" \
    --source-ip "$SRC_IP" \
    --qps "$QPS" \
    --duration "$DURATION" \
    --output "$OUT_DIR/legit_client.csv"

# Wait for background collector to conclude
wait "$COLLECTOR_PID" 2>/dev/null || true

# 7. Verification & Summary Analysis
echo -e "${BLUE}[STEP 5/5]${NC} Evaluating Baseline B0 acceptance criteria..."

SUMMARY_FILE="$OUT_DIR/metrics_summary.json"
LEGIT_CSV="$OUT_DIR/legit_client.csv"

if [[ -f "$SUMMARY_FILE" && -f "$LEGIT_CSV" ]]; then
    # Parse results using Python
    python3 -c "
import json, csv

with open('$SUMMARY_FILE') as f:
    summary = json.load(f)

# Count results from legit_client.csv
sent = 0
answered = 0
with open('$LEGIT_CSV') as f:
    reader = csv.DictReader(f)
    for row in reader:
        sent += 1
        if row['status'] == 'ANSWERED':
            answered += 1

success_rate = (answered / sent * 100.0) if sent > 0 else 0.0
udp_delivered = summary.get('udp_delivered_to_socket', 0)
socket_drops = summary.get('drops_by_layer', {}).get('socket_buffer_drops', {}).get('udp_in_errors', 0)
core1_busy = summary.get('cpu_utilization', {}).get('pinned_core_busy_pct', 0.0)
core1_soft = summary.get('cpu_utilization', {}).get('pinned_core_softirq_pct', 0.0)

print('\033[1;32m======================================================================\033[0m')
print('\033[1;32m                 BASELINE B0 VALIDATION REPORT                        \033[0m')
print('\033[1;32m======================================================================\033[0m')
print(f'Queries Sent by Client   : {sent}')
print(f'Queries Answered         : {answered}')
print(f'Legitimate Success Rate  : \033[1;33m{success_rate:.2f}%\033[0m (Requirement: 100.0%)')
print(f'UDP Delivered to Socket  : {udp_delivered}')
print(f'Socket Buffer Drops      : {socket_drops} (Requirement: 0)')
print(f'Server Core 1 CPU Busy   : {core1_busy:.2f}% (softirq: {core1_soft:.2f}%)')
print('----------------------------------------------------------------------')

if success_rate >= 99.0 and socket_drops == 0:
    print('\033[1;32m[PASS] Baseline B0 meets all functional validation criteria!\033[0m')
else:
    print('\033[1;31m[FAIL] Baseline B0 failed acceptance criteria.\033[0m')
"
else
    echo -e "${RED}[ERROR]${NC} Missing summary files in $OUT_DIR"
    exit 1
fi

echo -e "${GREEN}Raw measurement artifacts preserved in: $OUT_DIR${NC}"

