# Linux VM and lab instructions — Person A only

Commands below run in a **Linux terminal at the repository/package root** containing `xdp/`. They do not run in Windows PowerShell. Stop on an unexpected error and preserve its text. Loaded programs/maps disappear on reboot; a namespace also disappears. Existing source files can be absent even when old kernel programs remain.

## 1. Install/check dependencies

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev linux-libc-dev pkg-config bpftool iproute2 ethtool python3
clang --version
bpftool version
python3 --version
findmnt -t bpf
```

Expected: tools print versions and bpffs is mounted at `/sys/fs/bpf`. If bpffs is absent:

```bash
sudo mkdir -p /sys/fs/bpf
sudo mount -t bpf bpf /sys/fs/bpf
```

GitHub CLI (`gh`) is not required. All Python functional tests use the standard library. Record environment with `uname -r`, `clang --version`, `bpftool version`, `ip -br link`, `ip route show default`, and `ethtool -i TESTNIC` under `docs/person-a/evidence/`.

## 2. Build and host tests

```bash
mkdir -p docs/person-a/evidence
make -C xdp
file xdp/kavach_xdp.o
python3 -m unittest discover -s xdp/tests -p test_ctl.py -v
make -C xdp host-test
```

Expected: eBPF relocatable object, controller tests `OK`, GCRA host test `PASS`. Make uses GNU make's explicit `>` recipe prefix, so copied tabs are not required. Clang's BPF backend and architecture userspace headers are required. No full system upgrade is required to build.

## 3. Inspect existing resources once

```bash
ip netns list
ip -br addr
sudo bpftool net show
sudo ls -l /sys/fs/bpf/kavach
```

The earlier smoke program may be pinned separately at `/sys/fs/bpf/kavach_smoke`; this controller does not remove it. If program `smoke_test` is still attached to **veth0**, detach that known test attachment with `sudo bpftool net detach xdpgeneric dev veth0`, after verifying its name/ID with `bpftool prog show id ID`. Do not detach an unidentified program or use the management NIC.

If the OLD parser named `kavach_xdp` is pinned under `/sys/fs/bpf/kavach`, use:

```bash
sudo python3 xdp/kavach_ctl.py detach --iface veth0
sudo python3 xdp/kavach_ctl.py unload
```

Detach reads the old pinned program's identity and removes only its attachment. Unload accepts the old named map pins, requires detachment, and refuses unexpected files. If `veth0` does not exist and the old program is detached, run only `unload`. If there are no existing pins, skip these commands.

## 4. Create or reuse the namespace

Fresh setup:

```bash
sudo bash xdp/tests/lab_up.sh
```

Expected: `READY: veth0 10.200.1.1 <-> kavach-test/veth1 10.200.1.2 and .3`.

If the script reports existing resources, inspect them. For the previously confirmed `kavach-test`/`veth0`/`veth1` pair, set/verify:

```bash
sudo ip addr replace 10.200.1.1/24 dev veth0
sudo ip -n kavach-test addr replace 10.200.1.2/24 dev veth1
sudo ip -n kavach-test addr replace 10.200.1.3/24 dev veth1
sudo sysctl -qw net.ipv6.conf.veth0.disable_ipv6=1
sudo ip netns exec kavach-test sysctl -qw net.ipv6.conf.veth1.disable_ipv6=1
sudo ip link set veth0 up
sudo ip -n kavach-test link set veth1 up
sudo ip -n kavach-test link set lo up
sudo ip netns exec kavach-test ping -c 3 10.200.1.1
```

Expected: three received, zero loss. These are private functional tests only. Do not point the sender at public networks.

## 5. Load the FULL delivered build and verify

After confirming the old Kavach pins are gone:

```bash
sudo python3 xdp/kavach_ctl.py load > docs/person-a/evidence/load.log 2>&1
echo $?
sudo bpftool prog show pinned /sys/fs/bpf/kavach/prog
sudo python3 xdp/kavach_ctl.py status
```

Expected exit status `0`, XDP program `kavach_xdp` and four map IDs. This delivered version reads config/source/global state, unlike the earlier parser-only version. Status should show an empty attachments list. On failure, inspect `docs/person-a/evidence/load.log`; do not claim verifier acceptance or enable the approximate fallback without recording the reason.

## 6. Parser regression, detached

```bash
sudo python3 xdp/kavach_ctl.py config --src-rate 0 --glob-rate 0
sudo python3 xdp/tests/test_parser.py
```

Expected `PASS: 32/32 parser tests; verdicts and counters match.` Evidence goes to `docs/person-a/evidence/a1-parser.txt`. Frames shorter than 14 bytes are excluded by the kernel's test-run interface; that branch is covered by host tests, not claimed as a kernel test. Keep the filter detached and other test runners stopped for exact counter deltas.

## 7. Verify generic attachment, CSV and watchdog

Use a fresh reset so the CSV starts from known state:

```bash
sudo python3 xdp/kavach_ctl.py unload
sudo python3 xdp/kavach_ctl.py load
sudo python3 xdp/kavach_ctl.py attach generic --iface veth0 --watchdog-minutes 0.1
sudo ip netns exec kavach-test ping -c 3 10.200.1.1
sudo python3 xdp/kavach_ctl.py stats --csv --count 3 > docs/person-a/evidence/stats.csv
sleep 7
sudo python3 xdp/kavach_ctl.py status
sudo python3 xdp/kavach_ctl.py stats --once
sudo cat /run/kavach/watchdog.log
```

`0.1` minutes is six seconds, for this short watchdog test. Expected: ping replies; `stats.csv` has exactly one header and three samples; after timeout, status attachments are empty and final counters remain readable. The log reports detachment in generic mode. The exact packet count may exceed pings due to ARP. Failure of status/log/counter checks means watchdog acceptance has not passed.

Operational attachment defaults to five minutes; choose a documented duration longer than a measurement run. A timeout that fires during a run changes that run's conditions.

## 8. Limiter acceptance in namespaces, one CPU

This runner requires exactly ONE online CPU. Temporarily shut down the VM and set its processor configuration to one vCPU if needed. Boot, rebuild if necessary, recreate the namespace, and load the full program again using steps 4–5. Pinning only the sending process is not proof of one-core receive processing.

```bash
cat /sys/devices/system/cpu/online
sudo python3 xdp/tests/test_limiters.py
```

Expected: `0` for online CPUs, then six `PASS` cases: below, twice, isolation, burst, global and both. Final line starts `PASS: 6/6 live limiter scenarios.` The runner resets all maps between cases, attaches generic with a two-minute watchdog, sends low-rate traffic only over the test veth pair, records received DNS packets by source, and detaches after each case. JSON evidence: `docs/person-a/evidence/a2-limiters.json`.

Acceptance details: below-limit approximately all pass; 2x load admits about half; legitimate source `.3` receives at least 98% while `.2` floods; burst five admits five of six quickly sent packets; global-only and both-limiter cases drop at the expected stage. Review actual timing/lateness, counts and all failures; do not edit evidence to force a pass. A busy/state drop makes the functional scenario fail.

## 9. Lab bring-up and native mode (A3)

Use the dedicated test NIC identified with B. Replace the literal `TESTNIC` below; never select the default-route/management interface. Save environment, driver, command, result and code hash in evidence.

```bash
make -C xdp
sudo python3 xdp/kavach_ctl.py config --src-rate 50 --src-burst 5 --glob-rate 100 --glob-burst 10
sudo python3 xdp/kavach_ctl.py attach generic --iface TESTNIC --watchdog-minutes 5
sudo python3 xdp/kavach_ctl.py stats --csv --count 5
sudo python3 xdp/kavach_ctl.py detach --iface TESTNIC
sudo python3 xdp/kavach_ctl.py attach native --iface TESTNIC --watchdog-minutes 5
```

Check the actual native attachment with `status`, send controlled test traffic with B, and test watchdog expiry in native mode too. If native fails, preserve the exact error, confirm clean state with `status`, and reattach generic. There is no silent native-to-generic fallback. Label every run with actual mode. Run source/global acceptance on the target machine before a freeze; namespace correctness results are not lab performance measurements.

After actual acceptance, record the commit hash and tag the agreed freeze commit in the team repository. The package contains no freeze tag and does not claim the original Wednesday-noon deadline was met.

## 10. Stop and clean up

Save final stats before unloading. From the same namespace where attached:

```bash
sudo python3 xdp/kavach_ctl.py detach --iface veth0
sudo python3 xdp/kavach_ctl.py stats --once
sudo python3 xdp/kavach_ctl.py unload
sudo bash xdp/tests/lab_down.sh
```

If the device is already gone and the program is detached, skip the detach command and unload. Cleanup scripts affect the named functional-test network only. Preserve evidence files on disk and coordinate any lab changes with B.
