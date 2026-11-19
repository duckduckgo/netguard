# netguard verification map

One page per feature: what it does, how a run reaches it, the checks that verify it, and what has bitten before. Commands use `$V` from the skill's `SKILL.md`.

## Features

| Change touches | Page | Checks |
|---|---|---|
| SNI parsing or blocking (`tls.c`, `tls_parser.c`, TCP handling in AppTP) | [apptp-sni.md](apptp-sni.md) | unit tests, formal check `formal/tls-parser/run.sh`, device proof |
| WireGuard / NetP (`src/wireguard`) | [wireguard-netp.md](wireguard-netp.md) (one-time sign-in first) | device proof |
| DNS parsing or blocking (`dns.c`, `udp.c`) | [dns-blocking.md](dns-blocking.md) | none yet |
| Speed, stalls, CPU (`tcp.c` queues and windows, `tun.c`, the event loop) | [throughput.md](throughput.md) | none yet |

A change can touch more than one row: run the checks of each.

## Kinds of check

- **Unit tests** (`src/test`): the cases someone wrote down. Fast; never enough alone.
- **Formal check** (`formal/<name>/run.sh`): a tool (CBMC) proves a property of the C code for every input up to a bound, on this machine, with no device. It answers "can this code ever do X?", for one narrow property.
- **Proof** (`proofs/<name>.py`, run with `$V prove`): the app carrying the build, on a device, with real traffic, compared with the base build. It answers "does it work in the app?", for the cases the proof drives. A proof is throwaway, written for one change from the page's recipe and never committed; the page is what stays.

## Adding a feature

1. Find where the feature lives in `src/` and how traffic reaches it on a device.
2. Create `<feature>.md` here: an H1, one paragraph of what it does, then exactly these H2s: `Sub-features` (short ids, one line each), `How to get to it` (the setup and trigger a run needs), `Checks` (each check's command and what passing means), `Gotchas` (ending with what has been shown failing, and when it was last driven).
3. Add a row to the table above.
4. Write a proof from the page (one `check` per observable end state, `lib/verify_netguard/steps.py` for shared steps), run it on the base and the branch until it separates them, and fix the page where it drifted. To have the selftest catch breaks of the feature, add the proof as `tests/<feature>.py` with a break in `selftest --with-broken-build` that it must catch; otherwise don't commit it.
5. If a property must hold for every input (parsing untrusted bytes, bounds), add `formal/<name>/` with a `run.sh`, show it failing on a scratch break, and put its coverage record and sync commit in the page's `Checks`.
