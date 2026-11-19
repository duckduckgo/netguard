# AppTP: SNI blocking

AppTP blocks other apps' connections to tracker domains by reading the server name (SNI) from the TLS ClientHello. netguard parses it (`tls.c`, `tls_parser.c`) and asks the app whether the domain is blocked. The DuckDuckGo app itself, system apps, apps on the exclusion lists and apps without a label are never blocked, so the subject is always the probe app.

## Sub-features

- `parse`: reading the server name out of the hello (`tls_parser.c`), whatever bytes an app sends.
- `block`: dropping the connection when the app says the name is a tracker (`tls.c`, `tcp.c`).
- `segments`: finding the name however the hello is cut into TCP segments, which depends on the window netguard advertises.

## How to get to it

AppTP on (`steps.enable_apptp`), then a third-party app (the probe, `probe/src/dev/verifynetguard/probe/ProbeActivity.java`) connects to port 443 of a tracker and of a control host, sending a hand-built ClientHello, so the run controls where the SNI sits and how the hello is segmented. The hosts are live: AppTP only routes public addresses through its tunnel, so a fixture on the host or the LAN would bypass it.

## Checks

Run all three for a change to the parser; the first two need no device.

### Unit tests

`make && ./test_tls && ./test_tls_split && ./test_tls_fuzz` in `src/test`. They must pass, but they check only the hellos someone wrote down (and random ones), so they don't replace the other two.

### Formal check

```
.claude/skills/verify-netguard/formal/tls-parser/run.sh --reach   # a few seconds: confirms the bound reaches a found name
.claude/skills/verify-netguard/formal/tls-parser/run.sh           # about 3 minutes on 9 parallel jobs
```

The parser reads bytes any app on the phone sends, so it must be safe on every input. CBMC turns the C code into a logic formula and a solver proves no input up to the bound breaks it, or returns one that does. Needs `cbmc` (`brew install cbmc`; confirmed with 6.11.0). Keep logs out of the repo: `LOG_DIR=<scratch dir>` keeps each length's CBMC output; `MAX_TLS=68` raises the bound (past ~70 a run takes many minutes).

**What it proves**, for every packet with 2 bytes of headers before the TCP payload and every payload of 0 to 64 bytes, through `get_server_name()` the way `is_sni_found_and_blocked()` in `src/netguard/tls.c` calls it:

1. **Memory safety.** No read or write outside the packet or the 256-byte `sn` buffer; no signed overflow, unsigned wrap, lossy conversion or bad shift in the parser.
2. **The name comes from the packet.** If a name is found, it was copied once, from inside the TLS payload.
3. **The name is the one the hello encodes.** The returned length equals the copied length and the `host_name` length field just before it; `sn` holds exactly those bytes and is NUL-terminated.
4. **`strlen(sn)` is the whole name.** `tls.c` uses `strlen(sn)`, not the returned length (see the finding below).
5. **No name means an empty `sn`.**

A ClientHello has 49 bytes before its extensions, so 64 leaves 15 bytes for them: enough for a server-name extension with a name of a few bytes.

**Results.** `PASS: every other property holds ...`, exit 0 (a `KNOWN FINDING still present` block before it is the finding below). `FAIL: a property fails for payload lengths: ...`, exit 10, with the failing properties and a counterexample trace (the values of `pkt`, `pos`, `len`, ... at each step, with line numbers in `tls_parser.c`). `CBMC didn't run`, exit 2: a compile error or a missing tool, the harness, not the parser.

**A real bug or the harness?** A real bug fails on the real code and the trace reads as a packet: walk `pos` and `len` through `parse_tls_server_name`, `parse_extensions` and `parse_server_name_extension` against the C. Harness errors:
- `unwinding assertion ... FAILURE` with no other failure: a loop bound in `run.sh` is too small for a changed loop. Raise it in `unwindset` (loop names from `cbmc ... --show-loops`). Never remove `--unwinding-assertions`: it's what makes the bound honest.
- A failure inside `harness.c` with a conversion or cast: the harness's own expression.
- `reach: FAILED`: the harness never finds a name, so every pass would be empty. Fix the harness before trusting anything.
- `couldn't find is10x() and is_valid_utf8()`: `util.c` changed shape; update the `awk` extraction in `run.sh`.

To tell them apart, rerun on `main`'s parser (`git show origin/main:src/netguard/tls_parser.c > <scratch>/tls_parser.c`, then `TLS_PARSER=<scratch>/tls_parser.c run.sh`): a harness error fails there too. Don't weaken a property or shrink the bound to make a run pass. If the change is intended (a new error code, a larger `FQDN_LENGTH`), update the harness and say so in the PR.

**Finding: a name with a NUL byte in it** (property 4, `KNOWN_FINDING` in `run.sh`). This 59-byte payload makes `get_server_name` return 1 (a 1-byte name) while `sn` is the empty string:

```
16 20 00 xx xx                  record header: handshake, version 0x2000, any length
01 + 37 bytes, any              handshake type ClientHello; length, version, random
00                              session id: none
00 00                           cipher suites: none
00                              compression methods: none
00 0a                           extensions: 10 bytes
00 00 03 03                     extension server_name, declared longer than present
xx xx                           server name list length, any
00 00 01 00                     host_name, length 1, the byte 0x00
```

`parse_server_name_extension` copies the name with `memcpy` and `is_valid_utf8` accepts it (it stops at the first NUL). `is_sni_found_and_blocked` then sees `strlen(sn) == 0`, logs "TLS server name not found" and never asks whether the name is blocked: a name like `"x\0app.adjust.com"` is checked as `"x"`. The effect matches a hello with no SNI, which AppTP also lets through, so the harm is low. The fix is a product decision (reject names containing NUL, or compare against the returned length). When it's fixed, delete the `KNOWN_FINDING` line in `run.sh`, so a regression fails the run.

**Not covered:** payloads over 64 bytes (real hellos are ~250-1500), names longer than ~6 bytes and the `FQDN_LENGTH` limit itself; header offsets other than 2 bytes; the rest of `tls.c` (`inet_ntop`, `is_domain_blocked`, the log calls: logging is off in the harness); how `tcp.c` picks the payload; hellos split across segments (the device proof's `split` and `late-sni`); NDK 21's clang (CBMC models arm64 macOS's C).

**Coverage record.**

| Covered | What |
|---|---|
| `src/netguard/tls_parser.c` | all of it: `get_server_name`, `parse_tls_server_name`, `parse_extensions`, `parse_server_name_extension`, `read_u16` |
| `src/netguard/util.c` | `is_valid_utf8`, `is10x` (copied verbatim by `run.sh`) |
| `src/netguard/include/tls.h` | `FQDN_LENGTH`, `get_server_name`'s signature |
| `src/netguard/tls.c` | only how `is_sni_found_and_blocked` calls `get_server_name` and reads `sn` (modeled in `harness.c`, not run) |

Sync commit: `b7db69ad24c128480b7fda589a28d6706754795b`. To see whether the check needs another look:

```
git diff b7db69ad24c128480b7fda589a28d6706754795b -- src/netguard/tls_parser.c src/netguard/util.c src/netguard/include/tls.h src/netguard/tls.c
```

If that shows changes, read them against `harness.c` (does it still call the code the way `tls.c` does, and model every buffer the parser touches?), run `--reach` and the full check, and only then move the sync commit. A passing run alone isn't enough: it can't see code the harness no longer reaches. After changing the harness, prove it can still fail: run it with `TLS_PARSER=` on a scratch copy of `tls_parser.c` with a check removed (for example `pos + 3 + len > data_len` in `parse_server_name_extension`); it must report `FAIL`.

### Device proof

Write the proof for your change from this recipe; `tests/apptp.py` is the selftest's version of it, a starting point:

```
$V prove .claude/skills/verify-netguard/proofs/<name>.py                       # your proof
$V prove .claude/skills/verify-netguard/tests/apptp.py --param modes=window --like-moto   # the selftest's, one mode
```

The recipe: probe once with AppTP off (baseline), turns AppTP on and checks the VPN start pixel, then probes `app.adjust.com`, `api2.branch.io` (trackers) and `example.com` (control) in each mode, reading each mode's logs from its own `mark()` and requiring a netguard session to the address of every host that resolved. The report adds the window scales and first-segment sizes per mode.

| Mode | What it sends | Trackers | Control |
|---|---|---|---|
| `single` | one write, SNI first | blocked | allowed |
| `window` | one write, SNI after ~400 bytes: the kernel segments it by the window netguard advertised | blocked | allowed |
| `split` | two writes, cut right after the SNI | blocked | allowed |
| `late-sni` | two writes, cut right before the SNI | allowed: netguard reads only the first segment (known limitation) | allowed |

"Blocked" means the probe got `TIMEOUT` (netguard drops the connection without a reset) **and** the log has `shouldAllowDomain for <host> (<probe uid>) = AppTracker(...)`: the app's decision for the probe, not for another app. A tracker blocked at the DNS lookup instead (`NO_ADDRESS` with that decision logged) fails as "blocked by DNS, TLS blocking not reached". The run also fails if AppTP's tunnel is gone at the end. `CONNECT_TIMEOUT`, an incomplete probe run, or probe connections netguard never logged stop the run with exit 2, never a pass. Per-mode logs (`logcat-<mode>.txt`) keep the netguard lines: `TLS server <host> (<ip>) found` is the SNI it parsed, and a garbled name there is a parser bug.

## Gotchas

- **`late-sni` is a known limitation, expected to stay allowed.** A `late-sni` tracker that gets blocked fails with a hint: if the change makes netguard read the SNI from a later segment, that's the fix, so expect `late-sni` blocked in your proof and in `tests/apptp.py`'s `EXPECTED`.
- **The tracker blocklist is downloaded at runtime.** If a tracker check fails with "block decision missing" and the logs show `= null`, check the domain is still on the list.
- **Device-specific window bug.** `window` exercises the SYN-ACK window: netguard before 1.10.3 scaled it by the app's window scale. Linux picks an app's window scale from the larger of `rmem_max` and the last value of the TCP receive buffer setting. The moto g(60) has `rmem_max` = 128 MB, so apps advertise scale 12 and netguard's 524288-byte window became 128 bytes: apps sent the hello in 128-byte segments that cut the SNI, and trackers went through. Stock emulators have `rmem_max` = 256 KB (scale 6), so both versions block there. `--like-moto` sets the moto's `rmem_max` on the skill's rooted emulator for the run: netguard 1.10.2 then shows scale 12 and 128-byte first segments and lets `window` trackers through; 1.10.3 and later block them. A real phone isn't rooted, so `--like-moto` works only on the emulator.
- **Other ClientHello shapes.** For large post-quantum key shares, ECH or other shapes the probe doesn't send, add a mode to the probe (or a throwaway proof with its own client), and add a temporary `[PROBE]` log in `tls.c` with the ClientHello length and whether the SNI was found, in both builds. Compare `TLS server name not found` counts only per session: it's logged for every packet of a session that carries no hello (`tcp.c` checks each one).
- **Shown failing:** `selftest --with-broken-build` breaks this feature three ways (1.10.2 with `--like-moto`, a `tls.c` that never reads the name, a `tls.c` that blocks every name) and the formal check catches a removed bounds check and a wrong copy offset. Last driven: 2026-11-17, API 34 arm64 emulator.
