# Validation status — 28 October 2026

This is a source delivery with host validation. It is not a claim of completed VM/lab acceptance for the final full build.

## Earlier VM observations supplied by the user

- Kali rolling 2026.3, kernel `7.1.5+kali-amd64`, x86_64, clang 21.1.8, bpftool 7.8.0/libbpf 1.8.
- Smoke program ID 1579, counter map 165, generic veth attachment; counters increased 7 to 14 while five pings received replies. Extra packets were not identified.
- Parser-only program ID 1588, counter map 168 (14 entries), config map 169 (40-byte value), verifier load succeeded.
- User reported 32/32 parser test-run cases passed for that parser-only revision.

Those IDs are historical, ephemeral kernel IDs, not constants to hardcode. The full delivered source adds source/global limiter maps and new behavior; it must be rebuilt and reloaded. These earlier observations were reported from the development VM. They are separate from the host tests recorded below; the original VM logs are not reproduced in this package.

## Checks executed while preparing this delivery

- 92 host-side checks of full C source with mock kernel maps and deterministic clock: parser boundaries/verdicts/counters, source burst, source/global overload, source-first/global-second ordering, asymmetric two-source isolation and allocation-failure drop.
- Controller unit tests of config ABI/validation, per-CPU raw/formatted decoding, clean CSV/JSON, default-route guard, conditional-detach arguments, no-overwrite flag, state handling, stale/replacement watchdog behavior, native-mode expiry logic, load rollback and live-config refusal.
- Native pthread test of the shared GCRA helper: deterministic burst/overload, unchanged state on rejection, idle recovery, overflow guard and eight-thread fixed-time burst.
- Python syntax and shell/PowerShell syntax checks. Exact execution records and source hashes are under `evidence/` and in `FILE_SHA256SUMS.txt`.

The host C harness uses replacement definitions for Linux packet structs/context/helpers and adapts pointer width on Windows. It exercises the same parser/limiter functions, not the kernel verifier. Mock watchdog checks do not establish real Linux daemon, netlink or NIC behavior.

## Pending — must be recorded on Linux

- [ ] BPF compilation of this exact full build.
- [ ] Verifier load; save compiler/kernel versions, object hash, program/map descriptions and log.
- [ ] 32 parser tests on this build with both limiters disabled.
- [ ] Real libbpf attach/detach and watchdog readiness/expiry on veth.
- [ ] CSV once-per-second output and retained counters after detach.
- [ ] Six namespace limiter acceptance scenarios on one online CPU.
- [ ] Actual kernel multi-CPU contention behavior, or an explicit untested limitation.
- [ ] Lab build, generic test NIC checks and management-session continuity.
- [ ] Explicit native-mode attempt and its exact result; watchdog test if native works.
- [ ] Handoff to B from documented commands and a freeze commit only after acceptance.

No throughput, CPU-saving percentage, legitimate DNS-response success or final benchmark comparison is supplied. B's lab measurements and the team's report/demo remain separate work.
