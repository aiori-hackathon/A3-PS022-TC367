# Kavach — Person A implementation

Start with **PUSH_FROM_WINDOWS.md** in the delivered package for copying this work into the existing team repository. Windows/VS Code is used for editing and GitHub upload. Compilation, verifier loading, XDP attachment and lab tests run on Linux.

This package contains Person A's `xdp/` implementation and `docs/person-a/` documentation only. The sender under `xdp/tests/` generates small functional tests in an isolated namespace. Person B still owns the performance generator, calibration, baselines, results matrix and benchmark runner. This package does not claim to complete those tasks or the team's final report/demo.

## What is implemented

- Bounds-checked Ethernet/IPv4 (including IHL)/UDP/DNS-header parsing.
- Separate counters for bypass reasons and drop reasons, in a per-CPU array.
- Source GCRA in an LRU hash with one `u64` value per source IPv4; shared global GCRA checked second.
- CAS updates with eight attempts. Retry exhaustion and state failure drop and have dedicated counters.
- Forty-byte config map, separate load/attach/config/stats/detach/unload commands.
- CSV cumulative totals once per second by default, with diagnostics on stderr.
- Independent watchdog process, ready before attachment, with generation token and conditional expected-program-FD detachment.
- Functional parser tests, limiter acceptance runner, controller unit tests and a native pthread GCRA test.

## Important validation status

The earlier parser-only revision was reported by the user to compile and load on Kali 7.1.5, and to pass 32 kernel `prog run` cases. **This delivered build adds limiters and the controller, so it requires a new Linux build, verifier load and acceptance run.** Host tests are recorded in `docs/person-a/evidence/`; they do not replace kernel or lab checks. No performance numbers, native-mode result or freeze tag are fabricated. See `docs/person-a/VALIDATION.md`.

## Linux quick reference

From the team repository root, read `docs/person-a/VM_STEPS.md` for exact first-run steps, existing-pin cleanup, expected outputs and watchdog verification.

```bash
make -C xdp
python3 -m unittest discover -s xdp/tests -p test_ctl.py -v
make -C xdp host-test
sudo python3 xdp/kavach_ctl.py load
sudo python3 xdp/kavach_ctl.py config --src-rate 0 --glob-rate 0
sudo python3 xdp/tests/test_parser.py
sudo python3 xdp/kavach_ctl.py attach generic --iface veth0 --watchdog-minutes 5
sudo python3 xdp/kavach_ctl.py stats --csv --count 5
sudo python3 xdp/kavach_ctl.py detach --iface veth0
```

`load` requires an unused `/sys/fs/bpf/kavach` directory. For a new independent run: detach, unload, load, config, attach. Detach retains final counters; unload removes maps and resets state on the next load. Configure while detached, with no concurrent packet-test runner.

## Scope and limitations

UDP destination port 53 is the protected direction. This checks the 12-byte DNS header's presence, not DNS names, QR flags, checksums, recursion policy or full semantics. IPv6, VLAN-tagged frames and non-first fragments pass. A first fragment may be limited if its UDP and DNS headers are present. LRU eviction resets a source's allowance, and per-source-first ordering does not promise fairness when the shared global budget is exhausted.

Generic mode is functional but is not equivalent to native-mode early-drop performance. The watchdog depends on the Linux process and system continuing to run; it is not protection against a dead machine. Use the dedicated test NIC and verify both management access and timeout behavior before lab measurements.
