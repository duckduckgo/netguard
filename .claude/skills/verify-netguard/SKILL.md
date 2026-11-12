---
name: verify-netguard
description: Verify a netguard change on an Android device, not only in unit tests. Use before calling any change to src/netguard or src/wireguard done, when reviewing or testing a netguard PR, when reproducing a netguard bug, or when measuring netguard throughput or CPU.
---

# Verify netguard

Unit tests in `src/test` prove a function. This skill proves the change works in the app: a netguard library built from your checkout, inside the DuckDuckGo app, on a real phone, with real traffic.

Every check compares two builds of the library on the same phone, app, network and steps: one built from `main` (or the release the app ships) and one from your branch. A result without its `main` counterpart is not evidence. Reviewing a PR? Read "Reviewing a PR" at the end first: the comparison is with the PR's base branch.

If a step here fails or is wrong because the repo changed (a command, a path, a log message), fix this skill in the same commit as your change and say so in the PR. Don't work around it silently.

## Before you start

Check these first, and tell the user what's missing before building anything:

- A phone on `adb devices`, with the DuckDuckGo debug app (see step 3 if it isn't installed).
- The Android SDK with NDK 21.4.7075529, cmake 3.22.1 and build-tools 36.0.0. The paths below assume macOS (`~/Library/Android/sdk`); on Linux the SDK is usually `~/Android/Sdk`.
- `ninja` and `go` on the PATH.

## 1. Pick the feature check

Read the reference file for the feature you changed:

| Change touches | Read |
|---|---|
| SNI parsing or blocking (`tls.c`, `tls_parser.c`, TCP handling in AppTP) | [references/apptp-sni.md](references/apptp-sni.md) |
| DNS parsing or blocking (`dns.c`, `udp.c`) | [references/dns-blocking.md](references/dns-blocking.md) |
| QUIC, or which UDP flows AppTP blocks (`ip.c`, `udp.c`) | [references/apptp-quic.md](references/apptp-quic.md) |
| WireGuard / NetP (`src/wireguard`) | [references/wireguard-netp.md](references/wireguard-netp.md) |
| Speed, stalls, CPU (`tcp.c` queues and windows, `tun.c`, the event loop) | [references/throughput.md](references/throughput.md) |

**No file fits?** Before changing any code, write down:

1. **Trigger:** the exact steps that exercise the behavior (app, URL or command, network).
2. **Pass:** what you will see when it works, and where (a log line, a pcap, a number). Make it something that differs between a broken and a working build.

Run the trigger on the `main` build first. A bug must reproduce there, or a new feature must be absent there, or a perf change must give a baseline number. If it doesn't, the check proves nothing: fix the check before writing code. When the change is verified, save the trigger and pass as `references/<feature>.md` and add a row to the table above.

## 2. Build the libraries

Gradle's native build doesn't work on Apple Silicon Macs (it runs x86 ninja under Rosetta). Build with the SDK's cmake directly. This builds both `libnetguard.so` and `libwg-go.so` for arm64; it needs Go on the PATH for the WireGuard library.

```bash
SDK=~/Library/Android/sdk
NDK=$SDK/ndk/21.4.7075529
OUT=<an empty directory outside the repo>
$SDK/cmake/3.22.1/bin/cmake -S android/netguard/src/main/cpp -B $OUT -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$(which ninja)" \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$OUT/lib
$SDK/cmake/3.22.1/bin/cmake --build $OUT --target netguard libwg-go.so
ls $OUT/lib   # libnetguard.so, libwg-go.so
```

Build the `main` libraries the same way from a `main` worktree into a different `OUT`.

For a temporary log line, use `log_print(PLATFORM_LOG_PRIORITY_WARN, "[PROBE] ...")` and remove it before committing. The native code logs under the tag `NetGuard.JNI`.

## 3. Put the libraries in the app

Use a debug build of the DuckDuckGo Android app: native `NetGuard.JNI` logs are off in release builds. Start from the one already on the phone:

```bash
APP=com.duckduckgo.mobile.android.debug
adb shell pm path $APP                    # one line expected: base.apk
adb pull <the base.apk path> app-debug.apk
unzip -l app-debug.apk | grep -E 'arm64.*(netguard|wg-go)'   # the libraries must be in base.apk
```

If `pm path` lists split APKs and the libraries are in a split, swap them in that split and install all parts with `adb install-multiple`.

**No debug app on the phone?** Any debug APK works, whoever built and signed it: the libraries are replaced and the APK re-signed below. Ask the user for one (from the Android app's CI, or a local build of the Android app, unchanged). Don't use the store app: re-signing it means uninstalling the user's real app, and its native logs are off. The debug app is a separate package, so installing it leaves the store app alone. On a fresh install:

- Install the `main` build first and the branch build after; both carry your key, so the second installs as an update and keeps the setup.
- Onboarding and the VPN permission dialog have to be done once. Drive them as in "Drive the app" below; ask the user only for what that can't reach.
- NetP needs access to the VPN service in the new install; AppTP doesn't. If NetP can't be turned on, say so and ask the user, rather than reporting the NetP check as failed.

Before packaging, confirm each build contains what you expect, e.g. `strings $OUT/lib/libwg-go.so | grep -c '<a log message only your change adds>'` returns 0 for `main` and 1 or more for the branch. Instrument both builds the same way, so the only difference is the change.

```bash
BT=$SDK/build-tools/36.0.0
cp app-debug.apk work.apk
mkdir -p lib/arm64-v8a && cp $OUT/lib/libnetguard.so $OUT/lib/libwg-go.so lib/arm64-v8a/
zip -0 work.apk lib/arm64-v8a/libnetguard.so lib/arm64-v8a/libwg-go.so   # stored, not compressed
$BT/zipalign -f -p 4 work.apk aligned.apk
$BT/apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out signed.apk aligned.apk
$BT/apksigner verify --print-certs app-debug.apk | head -2   # must match signed.apk
$BT/apksigner verify --print-certs signed.apk | head -2
adb install --no-incremental -r signed.apk
```

- Swap only the library that changed when the other must stay the shipped one.
- Same certificate digest: the APK installs as an update and keeps the app's data. A different digest (e.g. a CI build) means uninstalling first, which clears the app's data; ask before doing that.
- The install stops the app, so the new library loads when the VPN starts again. Check whether it's up with `adb shell dumpsys connectivity | grep -c 'Transports: VPN'` (non-zero when up); a plain `grep VPN` also matches `NOT_VPN` on every network. If it isn't up, start it yourself (below).

### Drive the app

Do these yourself; don't ask the user to tap through the app.

```bash
adb shell monkey -p $APP -c android.intent.category.LAUNCHER 1   # launch the app
adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml # what's on screen, with each element's text and bounds
adb shell input tap <x> <y>                                          # tap the centre of an element's bounds
adb shell input keyevent KEYCODE_BACK
```

- To turn AppTP or NetP on: launch the app, dump the screen, find the element by its text (e.g. "App Tracking Protection", then its toggle), tap it, dump again to confirm the new state. Repeat per screen.
- The VPN permission dialog is a system dialog; it shows up in the dump too, and its OK button can be tapped the same way.
- After each step, check the result (the next dump, or the `Transports: VPN` check), not the tap.
- Ask the user only when the dump can't reach something (a sign-in in a web view, a fingerprint prompt) or a tap doesn't change the screen after two tries. Say what you tried.
- Use the same network for the base and branch runs, and note which in the report. When the trigger depends on the network (e.g. a connection to an IPv6 address failing straight away needs a network without IPv6), confirm the network qualifies first.

### Check netguard is handling the trigger's traffic

Do this before every trigger, on each build. A VPN that's up, or netguard logging other apps' traffic, doesn't mean the trigger's own packets reach netguard.

1. **A test app of your own has network access.** Android 15+ can cut off the network of an app that was never launched: allowlist it with `adb shell cmd deviceidle whitelist +<package>` before running it. A cut-off app's connections time out exactly like ones netguard drops, so nothing else tells you.
2. **Only the feature under test is on.** With NetP and AppTP both on, they share one VPN and NetP's stack handles the traffic, so netguard sees none of it.
3. **netguard is running your library.** `adb logcat -c`, browse for a few seconds, then `adb logcat -d -s NetGuard.JNI | wc -l`: the debug app runs netguard at DEBUG level, so this is in the hundreds. Then look for a line only your build logs, or your `[PROBE]` lines.
4. **The trigger's own packets reach netguard.** Run the trigger once and find its packets in `adb logcat -d -s NetGuard.JNI`, e.g. by its destination address. If they aren't there, the result says nothing about the change.

If any of these fails, fix the setup before running the trigger; a result from such a setup is not a result for the change. If you can't fix it, say the check couldn't run, and why.

To find an app's uid, e.g. to match it in logs: `adb shell dumpsys package <package> | grep -oE '(userId|appId)=[0-9]+'`. Android 16 prints only `appId=`.

## 4. Capture evidence

- **Logs:** `adb logcat -c` before the trigger, then `adb logcat -s NetGuard.JNI` (add the app's own tags when the decision happens in Kotlin).
- **Packets:** a pcap from the device or the other end when the pass is about what goes on the wire.
- **Numbers:** the same workload, at least 5 runs per build, the spread reported along with the median. Debug builds log at DEBUG level, so their CPU numbers are inflated: compare debug with debug, never with release.

Save raw logs and pcaps outside the repo. Count from the raw file with `grep -c` or a script, not by eye.

## 5. Report

For each check: the trigger, the phone and Android version, the app version, and the result on `main` and on the branch, side by side. Say plainly when a check was not run or was inconclusive; a fix verified only by unit tests is unverified.

netguard is a public repository. Keep app-internal names, internal links and user data out of commits, PR descriptions and issue comments.

## 6. Restore the phone

Leave the phone as you found it, and say in the report what you restored:

- Reinstall the original app: `adb install --no-incremental -r app-debug.apk`, the copy pulled in step 3. Same key, so it keeps the app's data. If you had to uninstall a differently signed app, say so: its data is gone and the user has to reinstall it.
- Uninstall test apps you installed (`adb uninstall <package>`).
- Turn features back to how they were (AppTP, NetP), and remove files you left on the device (e.g. `/sdcard/ui.xml`).

## Reviewing a PR

The same steps, with four differences:

1. **Check out and find the base.** `gh pr checkout <number>`, then `gh pr view <number> --json baseRefName`. Build the comparison from that base branch, not `main`: for a stacked PR, comparing with `main` tests the PRs below it too.
2. **Run the author's steps first.** Use the trigger and pass in the PR's "Steps to test this PR", then the feature file for what the diff touches, then the edge cases you think the author missed. If the PR gives no steps, write your own trigger and pass as in step 1 and say in the review that they were missing.
3. **Don't change the PR or this skill.** If a step here is stale, say so in the review; the author fixes it.
4. **Post the result as a review comment**, so it isn't lost in your terminal: each check with the base and PR results side by side, as in step 5, and what you didn't check. Ask the user before posting.
