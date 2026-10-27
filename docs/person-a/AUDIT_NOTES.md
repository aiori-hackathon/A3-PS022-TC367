# Changes made after auditing the Person A PDF

This delivery uses the guide as a starting point, with corrected code and explicit test status. Relevant PDF page references use the printed page numbers.

| Guide issue | Delivered treatment |
|---|---|
| Pages 37–38: UDP length could exceed unfragmented IP payload | Check UDP/IP logical lengths and physical bounds; regression cases included |
| Pages 37–38: padding beyond IP total length could satisfy DNS header | Require DNS bytes inside IP payload and frame |
| Pages 35–38: bypass reasons merged into not_dns | Fourteen counters with one terminal outcome per packet |
| Pages 45–48: trace output corrupts counters --json | Data-only stdout; operational messages and verifier diagnostics use stderr |
| Pages 47–49: load and attach combined; failed attach can strand pins | Separate load/attach/detach/unload, ownership checks and explicit state |
| Page 49: missing CSV/watchdog interface | CSV streaming, configurable independent watchdog and status |
| Page 66: generic-only timeout after possible native switch | Stored mode, expected program FD, interface identity and token |
| Page 40: no-CAS build overwrites CAS object | Separate `_approx.o` object; explicit acknowledgement required |
| Page 46: zero intervals at extreme rates and unchecked inputs | Bounded inputs, ceiling interval calculation and overflow checks |
| Pages 51–54: socket size alone does not guarantee exact fragmentation | Deterministic packet bytes test first/non-first fragment branches |
| Pages 60–62: volatile pthread stop/shared state is not proper host synchronization | No volatile stop race; atomic host accesses and fixed-time threaded test |
| Pages 39/60: fail-open contention weakens strict limit | Default retry exhaustion drops, with dedicated outcome counter |

Host checks do not certify target-kernel verifier support. The package's final full build has not been loaded on the user's VM by this Windows session. Follow `VALIDATION.md` and `VM_STEPS.md`; preserve real Linux results before freeze. No final code correctness guarantee or benchmark claim is implied by providing the folder.
