#!/bin/bash
# Creates only Person A's isolated functional-test network.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash xdp/tests/lab_up.sh' >&2; exit 1; }
if ip link show veth0 >/dev/null 2>&1 || ip netns list | awk '{print $1}' | grep -qx kavach-test; then
    echo 'Existing veth0 or kavach-test found. Inspect/reuse it; this script does not overwrite it.' >&2
    exit 1
fi
made_ns=0
made_link=0
cleanup() {
    status=$?
    if [[ $status -ne 0 ]]; then
        if [[ $made_link -eq 1 ]]; then ip link del veth0 || true; fi
        if [[ $made_ns -eq 1 ]]; then ip netns del kavach-test || true; fi
    fi
    exit "$status"
}
trap cleanup EXIT
ip netns add kavach-test
made_ns=1
ip link add veth0 type veth peer name veth1
made_link=1
ip link set veth1 netns kavach-test
ip addr add 10.200.1.1/24 dev veth0
ip -n kavach-test addr add 10.200.1.2/24 dev veth1
ip -n kavach-test addr add 10.200.1.3/24 dev veth1
ip link set veth0 mtu 1500
ip -n kavach-test link set veth1 mtu 1500
sysctl -qw net.ipv6.conf.veth0.disable_ipv6=1
ip netns exec kavach-test sysctl -qw net.ipv6.conf.veth1.disable_ipv6=1
ip link set veth0 up
ip -n kavach-test link set veth1 up
ip -n kavach-test link set lo up
echo 'READY: veth0 10.200.1.1 <-> kavach-test/veth1 10.200.1.2 and .3'
