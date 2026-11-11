# AppTP: SNI blocking

AppTP blocks a tracker connection when the server name in the TLS ClientHello is on the blocklist. netguard parses the SNI (`tls.c`, `tls_parser.c`) and asks the app whether the domain is blocked.

**Before the device:** run `make && ./test_tls && ./test_tls_split && ./test_tls_fuzz` in `src/test`. They must pass, but they don't replace the device check.

## Trigger

1. AppTP on, NetP off.
2. Open Chrome and 5-10 apps with known trackers; browse for a few minutes.
3. Do the same on the `main` build and the branch build, same apps, same order.

## Pass

- Blocked tracker domains appear in the app's AppTP activity, and in `NetGuard.JNI` logs for the debug build.
- `TLS server name not found` count does not go up compared with `main`. For a parser fix, it goes down for the case fixed.
- Non-tracker sites keep loading: no new breakage compared with `main`.

For a change that targets a specific ClientHello shape (split across segments, large post-quantum key shares, ECH), add a temporary `[PROBE]` log in `tls.c` with the ClientHello length and whether the SNI was found, then count found vs. not found per build.
