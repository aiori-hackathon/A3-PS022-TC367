#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
echo 'Removing only the explicitly named Person A functional-test network.'
ip -4 addr show dev veth0 | grep -q '10.200.1.1/24' || { echo 'Unexpected veth0 identity; refusing cleanup' >&2; exit 1; }
ip -n kavach-test -4 addr show dev veth1 | grep -q '10.200.1.2/24' || { echo 'Unexpected peer identity; refusing cleanup' >&2; exit 1; }
ip link del veth0 2>/dev/null || true
ip netns del kavach-test 2>/dev/null || true
echo 'Test namespace removed. Pinned Kavach maps remain; use the controller to unload.'
