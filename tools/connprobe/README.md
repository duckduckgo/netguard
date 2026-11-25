# connprobe

Checks that App Tracking Protection (AppTP) resets each connection it fails to open, and doesn't leak a socket for it.

When an app opens a connection through AppTP, netguard opens one to the real server on its behalf. connprobe makes
connections that netguard can't open (by default to an IPv6 address, on a network without IPv6), times each one, and
the script counts the sockets open in AppTP's process before and after.

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

| | Connections in connprobe | Sockets open in AppTP |
|---|---|---|
| netguard 1.10.2 | time out | about 100 more: one per attempt, including retries, never released |
| Before the reset | time out: netguard doesn't answer | unchanged |
| Now | refused in a few ms: netguard resets them | unchanged |

When netguard's `connect()` fails with a network error (eg. network unreachable), it answers the app's SYN with a
reset, so the connection is refused straight away instead of timing out. A connection that times out means netguard
didn't answer, and the run fails. So does a refusal slower than 500 ms: the app resends its SYN after about 1 s, so a
reset that late answered the resend, not the first SYN. If any connection succeeds or fails with another error, the result is inconclusive:
it either reached the address, or failed on the device without reaching netguard (eg. the VPN doesn't route that
address). It's also inconclusive when netguard logged no failed `connect()`: then no connection reached the code this
checks (eg. Android blocked the probe app's network).

The Android emulator's network has an IPv6 route, so there netguard's `connect()` fails later instead of straight away,
and the run is inconclusive. Remove the route first: `adb root`, then for `wlan0` and `eth0`,
`adb shell "sysctl -w net.ipv6.conf.<dev>.accept_ra=0; ip -6 route del default dev <dev> table <dev>"`.

It exits 0 when every connection was refused within 500 ms and no sockets leaked, 1 when one wasn't or sockets leaked,
and 2 when it couldn't check (a setup step failed, or the run was inconclusive).

Remove the app afterwards with `adb uninstall dev.netguard.connprobe`.

## Why the extra app

Same as for `tools/dnsprobe`: the probe must run as an app that AppTP covers. `adb shell` is outside AppTP, AppTP
never protects `com.duckduckgo.*` packages, and a new app has no network until it leaves the most restricted
standby bucket and, on recent Android versions, is on the deviceidle allowlist. The script does both.
