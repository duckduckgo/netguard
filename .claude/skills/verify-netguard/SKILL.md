---
name: verify-netguard
description: Verify a netguard change on an Android device, not only in unit tests. Use before calling any change to src/netguard or src/wireguard done, when reviewing or testing a netguard PR, when reproducing a netguard bug, or when measuring netguard throughput or CPU.
---

# Verify netguard

Unit tests in `src/test` prove a function. This skill proves the change works in the app: the libraries built from your checkout, inside the DuckDuckGo app, on a device, with real traffic.

A verification is a **proof**: a short Python file that acts on the device, checks the result, and would come out differently if the change were wrong. Every proof runs twice, on the libraries built from the base (`main`, or a PR's base branch) and on the ones from your branch, with the same app, device and network. A result without its base counterpart is not evidence.

```
V=.claude/skills/verify-netguard/scripts/verify-netguard      # from the repo root; every command below uses $V
```

If a step here fails or is wrong because the repo changed (a command, a path, a log message), fix this skill in the same commit as your change and say so in the PR. Don't work around it silently.

## Prerequisites

macOS or Linux, with:
- The Android SDK (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, `sdk.dir` in local.properties under `android/`, or the default location) with platform-tools, emulator, cmdline-tools, build-tools, NDK 21.4.7075529, cmake 3.22.1, a platform, and a `google_apis` system image for the host's architecture (`arm64-v8a` on Apple Silicon, `x86_64` otherwise). `device start` names the image to install when it's missing.
- `ninja`, `go`, a JDK 17+, Python 3.9+ and the [Android CLI](https://developer.android.com/tools/agents/android-cli) (`android`) on the PATH; the harness runs it with `--no-metrics`. It leaves its instrumentation server on the device (`restore` removes it from a phone), and only one UI driver can run at a time.
- A DuckDuckGo Android **debug** APK, universal (all ABIs): a local `internalDebug` build of the Android app, or one from its CI. Release builds don't log netguard. Ask the user for one if you have none.
- A device in English: UI targets match the app's English text.

## Loop

1. **Find the checks.** [features/README.md](features/README.md) maps what your change touches to its feature page, and the page lists its checks: unit tests, a formal check that needs no device (`formal/`), and the device proof. Run every check the page lists; the rest of this loop is the device proof.

   Then write a proof for this change (see Writing a proof) from the page's `How to get to it` and `Checks`, in `proofs/<name>.py`. A proof is throwaway: written to verify one change and never committed (`.gitignore` keeps them out); `pr-summary` carries its source into the PR. The selftest's fixtures (`tests/apptp.py`, `tests/netp.py`) are starting points. What a proof taught that the next one needs (a check, a log line, a gotcha) goes into the feature page, and an app quirk into `steps.py`. Done when you can name the check that separates pass from fail.
2. **Get a device.** `$V device start` creates (once) and boots this checkout's own rootable emulator, headless. Commands use it unless `ANDROID_SERIAL` names another device. Name a real phone only when the bug needs that model: proofs wipe the debug app's data on it. `$V device stop` shuts the emulator down.
3. **Give it the app.** `$V app --apk <DuckDuckGo debug APK>` records the APK the libraries go into. `$V app --pull` takes the one installed on the device instead.
4. **Build and install.** `$V build` builds `libnetguard.so` and `libwg-go.so` for the device's ABI and records the native source it was built from (`src/` and the CMake project, committed and uncommitted). `$V install` swaps both libraries into the app, re-signs it with the debug key, installs it, and checks the installed APK's hash. It refuses if the native source changed since the build. `$V doctor` (read-only) says whether a proof can run now: the device and whether the tool owns it, the commit, and whether the installed app is the current build.
5. **Run it, on the base and on the branch.**
   ```
   $V build --base origin/main && $V build                # the "before" (git fetch first) and the "after"
   $V compare --expect fix <proof.py>                      # a fix: fails on the base, passes on the branch
   $V compare --expect same <proof.py>                     # a refactor or perf change: passes on both
   ```
   `build --base` builds where your branch left the ref (their merge base, resolved locally), not the ref's tip, in a worktree the tool owns; `compare` refuses a base build from before a rebase; libraries are kept per commit, so the same base is built once. `compare` installs the base build and runs the proof, installs the branch's and runs it again, and prints the summary of step 6 (also saved as compare.md in the after run's evidence). It exits 0 when the runs show the expectation, 1 when they don't, 2 when either couldn't run. A proof that passes on the base proves nothing about a fix: fix the proof before writing code. `prove` runs a proof once, on whatever is installed (`install` or `install --base`).
6. **Report.** For the PR's Verification section, paste the summary `compare` printed (or `$V pr-summary --expect fix|same <before-evidence> <after-evidence>` for two runs made with `prove`): a verdict line that says whether the runs show what you expected (`fix`: fails on the base, passes on the branch; `same`: passes on both), the changed native files the proof doesn't cover, the checks that changed between the runs, device, builds, app and live services, all results collapsed, and rerun commands. A changed file the proof doesn't cover needs another proof, or a line saying why it doesn't. It carries no local paths, logs or screenshots, so it's safe for this public repo. Each evidence folder's report.md has the full run for you. Say plainly what was not run; a fix verified only by unit tests is unverified.
7. **Restore a real phone.** `$V restore` reinstalls the app that was on it before the tool's first install (or uninstalls the tool's if there was none), uninstalls the probe and restores device settings. Say in the report what was restored; if the original app had another signature, its data is gone and the user has to know. The emulator needs no restore.

One command runs at a time per checkout (they share its records, emulator and app); use a separate worktree to run two.

Exit codes: `0` pass (at least one check, none failed), `1` a check failed, `2` error: no device, stale or wrong build, a setup step failed, the network failed before the behavior was exercised, the probe's traffic never went through netguard, or the proof raised. An error is never a pass: report it as "couldn't verify", with the reason.

## Writing a proof

```python
"""AppTP blocks a tracker whose ClientHello carries a post-quantum key share."""   # required: what it proves
from verify_netguard import steps

LIVE = ["app.adjust.com", "example.com"]        # live services the proof depends on; listed in the evidence
COVERS = ["src/netguard/tls.c"]                 # the native files it exercises; pr-summary flags changed files outside

def run(android):
    steps.fresh_start(android)                   # app data cleared: AppTP and NetP off
    steps.enable_apptp(android)
    android.mark()                               # logs count from here
    results = android.probe(LIVE, "window")
    android.require_netguard_saw_probe(LIVE)     # exit 2 unless netguard opened a session to each host's address
    android.check("tracker blocked", results["app.adjust.com"] == "TIMEOUT", results)
    android.check("control allowed", results["example.com"] == "ALLOWED", results)
```

What `android` gives you (`lib/verify_netguard/harness.py`):
- **Act:** `probe(hosts, mode)` connects to port 443 of each host as a third-party app (the probe, `probe/`), sending a hand-built ClientHello, and returns each host's outcome (`features/apptp-sni.md` lists the modes); the app's UI through the Android CLI: `launch()`, `tap(target, wait=10, first=False)`, `type(text, target, submit=False)`, `scroll_to(target)`, `key(name)`, `hide_keyboard()`. A target is the CLI's selector (`id=skipOnboardingButton`, `text=/^OK$/`, `id=foo,text=Continue`): strings match as case-insensitive substrings, so anchor a `/regex/` when a short text could match a longer one. A UI action that fails is a setup error (exit 2) and saves the screen's layout to the evidence; every CLI call goes to its UI log. Also `broadcast(action, **extras)`; `shell(...)`.
- **Read:** `layout()` (every element on screen, in every window), `visible(target)`, `wait_for(*targets, timeout=30)` (the first to appear, or None), `logs(since)`, `wait_for_log(pattern, timeout=30)`, `netguard_sessions(uid)` (the sessions netguard opened for an app, from its `new session` lines), `probe_uid()`, `probe_addresses` (the address the last probe of each host connected to), `crashes(since)` (the app's crash and ANR lines), `tunnel_up()`, `pixels(since)`, `param(name, default)` for `--param`.
- **Check:** `check(what, ok, detail)`, `expect_visible(what, target, timeout=30)` (when what's on screen is the behavior under proof), `expect_log(what, pattern)`, `expect_pixel(name)`, `require_netguard_saw_probe(hosts)` (AppTP), `require_wireguard_saw_probe(hosts)` (NetP). Call `mark()` right before the action under test; reads without a mark fail. Every run also checks that the app didn't crash or stop responding (any of its processes, the VPN's included), so a crash the app recovered from still fails; its log lines go to crashes.txt in the evidence, never into the summary.
- **Start state:** `SNAPSHOT = "<name>"` in the proof loads that emulator snapshot first (a state a person set up once, like a signed-in account; `$V snapshot save|load|list`), then reinstalls the build under test over it.
- **Evidence:** `shot(name)`, `save(name, text)`, `note(text)`, `unverified(what, why)`, `section(title, markdown)` for report tables.

Rules:
- **netguard must see the traffic.** A connection that never went through netguard (VPN down, NetP's stack handling it, the app outside the tunnel) is "allowed" for the wrong reason. After every probe while the feature under test is on, call `require_netguard_saw_probe` for the hosts that resolved. Turn on only the feature under test: with NetP and AppTP both on, NetP's stack handles the traffic and netguard sees none of it.
- Act through the user's path (the UI, the probe as another app); `shell` and `broadcast` set up or read back. Confirm every end state with an independent read: a log line, the tunnel, a probe result.
- Debug builds log netguard under the tag `NetGuard.JNI`. For a temporary log line in the C code, use `log_print(PLATFORM_LOG_PRIORITY_WARN, "[PROBE] ...")` in both the base and the branch builds, so the only difference is the change, and remove it before committing.
- Numbers (throughput, CPU): at least 5 runs per build, alternating builds, median and spread reported. Compare debug with debug only.
- Raise `verify_netguard.Error` for setup problems (exit 2), never a failed check.

Shared steps (`lib/verify_netguard/steps.py`) handle app quirks once: `fresh_start`, `open_settings`, `enable_apptp`, `enable_apptp_from_settings` (keeps the app's data), `enable_netp`. Add one when a second proof needs it. They match the Android app's UI, which changes in the Android repo: when a step fails on a newer app, fix the step and say so in the PR. The Android repo's verify-android skill is to get its own AppTP and NetP features, which check the app around netguard after a version bump; when both exist, a fix to a step on one side likely applies to the other.

## Evidence

Each run writes `~/.ddg-verify-netguard/<checkout>/evidence/<stamp>-<proof>/` (`VERIFY_NETGUARD_HOME` moves the root): a copy of the proof, report.md, manifest.json (verdict, proof and params, device, the libraries' commit and hashes, the app's version and hash, the installed APK's hash, the source fingerprint at run time, live services, the privacy config version the app downloaded, every check, rerun command; AppTP's tracker blocklist is downloaded at runtime too, but the app doesn't log its version), files the proof saved, `final.png`, and a screen recording of the run in 3-minute clips (`video-1.mp4`, `video-2.mp4`, ...; a failed recording is listed as none, never fails the run). Evidence never goes in the repo; `pr-summary` leaves screenshots and videos out. Device settings a run changes (such as `rmem_max`) are restored when it ends, pass or fail; a run killed before that is undone by the next one.

## Check the tool itself

```
$V selftest                       # a few minutes; add --with-broken-build for the full check
```

Run it after changing this skill, on a new machine, after an SDK or emulator update, and after recording a newer app. It builds and installs if needed, then checks: `tests/must_fail.py` (logs before `mark()` don't count, netguard's session lines are read per uid, a probe that never connected and probe results netguard never saw are refused, sessions are matched per host and not by count, a real app crash is seen), that a proof with no checks and a proof that raises are errors, `tests/apptp.py` (the AppTP device proof of `features/apptp-sni.md`) passes on this build and the device is restored, `pr-summary` leaks no local paths, a change outside the native sources doesn't make the build stale, and the tool refuses a stale build, an app it didn't install and a missing device. `--with-broken-build` also checks the proof catches real bugs, each failing exactly the checks it should: netguard 1.10.2 with `--like-moto` (the window-mode trackers), and two breaks of this commit's `tls.c` (`MUTATIONS` in the script): never reading the server name (the `single`, `window` and `split` trackers), and blocking every name without asking the app (the control and the trackers' "decision logged" checks in `single`, `window` and `split`; `late-sni` never reaches that code). It also checks a before/after `pr-summary` of a failing and a passing run. When a change to `tls.c` makes a mutation stop applying, update it in the same commit. With the `netp-signed-in` snapshot, it also runs `tests/netp.py` and, with `--with-broken-build`, a `tun_android.go` that ignores netguard's block (only the NetP+AppTP tracker checks may fail); without the snapshot it says it skipped them. Never shown failing yet: "AppTP still running at the end", and NetP's server and handshake checks. It ends with `"ok": true` or names the step that failed.

## Disk space

Libraries, APKs, the base worktree and evidence live under the state directory. `$V cleanup` removes builds and APKs no record points at and evidence older than 30 days (`--evidence-days N`); `$V cleanup --all` also removes the base worktree, this checkout's emulator and every file the tool created (run `restore` on real phones first).

## Reviewing a PR

The same loop, with four differences:

1. **Build the PR's base.** `gh pr view <number> --json baseRefName`, then `$V build --base origin/<baseRefName>`, not `main`: for a stacked PR, comparing with `main` tests the PRs below it too.
2. **Run the author's steps first.** Turn the PR's "Steps to test this PR" into a proof, then the feature page's device proof for what the diff touches, then the edge cases you think the author missed. If the PR gives no steps, write your own trigger and pass and say in the review that they were missing.
3. **Don't change the PR or this skill.** If a step here is stale, say so in the review; the author fixes it.
4. **Post the result as a review comment** (the summary `compare` prints), so it isn't lost in your terminal, and what you didn't check. Ask the user before posting.
