# connprobe

Checks that App Tracking Protection (AppTP) doesn't leak a socket for each connection it fails to open.

When an app opens a connection through AppTP, netguard opens one to the real server on its behalf. connprobe makes
connections that netguard can't open (by default to an IPv6 address, on a network without IPv6), and the script
counts the sockets open in AppTP's process before and after.

## Running it

Connect a device on a network without IPv6 (eg. most home WiFi), with a **debug build** of the DuckDuckGo app and
AppTP on, then from the repo root:

```sh
tools/connprobe/run.sh                                  # 50 connections to 2001:4860:4860::8888 port 443
tools/connprobe/run.sh 2001:4860:4860::8888 443 200
APP=com.duckduckgo.mobile.android.debug tools/connprobe/run.sh
```

The script builds connprobe and a small app for it, installs the app, checks that AppTP covers it, runs connprobe
and compares AppTP's open sockets. It needs `adb`, an Android SDK (build-tools and a platform) and an NDK. The
app must be a debug build so that its sockets can be counted with `run-as`.

Expected results, for 50 connections:

| | Sockets open in AppTP |
|---|---|
| netguard 1.10.2 | about 100 more: one per attempt, including retries, never released |
| With the fix | unchanged |

If any connection succeeds the result is inconclusive: the network could reach the address, so netguard never
failed to open a connection.

Remove the app afterwards with `adb uninstall dev.netguard.connprobe`.

## Why the extra app

Same as for `tools/dnsprobe`: the probe must run as an app that AppTP covers. `adb shell` is outside AppTP, AppTP
never protects `com.duckduckgo.*` packages, and a new app has no network until it leaves the most restricted
standby bucket.
