# Person A handoff to Person B

Use `interface.md` for exact command names, the complete CSV header, native-endian forty-byte config and pinned map names. Read `VM_STEPS.md` and the current validation status before running measurements.

Before joint work, agree: dedicated NIC, management NIC, link addressing, generator/server hosts, query load patterns, rates/bursts, mode, watchdog duration longer than the run, and evidence file names. Record the full source commit and compiled object's SHA256. B can calibrate without a filter before the limiter build passes acceptance.

For every independent filtered run: save previous results, stop generator, detach/unload/load/config/attach. Confirm actual attachment mode. After traffic stops, save stats and check the terminal-counter partition. Compare generator sent counts, XDP seen counts, and receiver success using B's harness. Filter admission (`dns_pass`) is not proof of a DNS answer. Preserve NIC/kernel/socket drops separately.

Do not change the limiter configuration between a matched baseline/XDP comparison without recording why. Keep generic and native runs separate. Any source fix changes the version associated with subsequent results; preserve earlier run versions.

The delivery contains Person A's functional sender/tests only. It does not populate B's `traffic/`, `baselines/`, `scripts/`, or `results/`. Repository collaboration/ownership, report format and demo requirements from PS-022 still require the team's actual completion. This handoff document does not send any message to B or grant repository access.
