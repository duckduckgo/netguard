# dnsprobe

Checks that DNS queries sent from one UDP socket all get an answer through App Tracking Protection (AppTP). Some
DNS libraries send several queries from the same socket, either at the same time or one after the other.

It runs two tests against a public DNS server (8.8.8.8 by default):

1. A and AAAA queries sent together from one socket.
2. An A query, then the AAAA query from the same socket once the A one is answered.

Missing answers are retried from the same socket every 2 seconds, up to 3 times.

## Running it

Connect a device with AppTP on, then from the repo root:

```sh
tools/dnsprobe/run.sh                      # 8.8.8.8, example.com
tools/dnsprobe/run.sh 1.1.1.1 duckduckgo.com
```

The script builds the probe and a small app for it, installs the app, checks that AppTP covers it and runs the
probe. It needs `adb`, an Android SDK (build-tools and a platform) and an NDK.

Expected results:

| | Test 1 | Test 2 |
|---|---|---|
| AppTP off | OK | OK |
| AppTP with netguard 1.10.2 | OK | FAIL: the AAAA query and its retries get no answer |
| AppTP with this fix | OK | OK |

Remove the app afterwards with `adb uninstall dev.netguard.dnsprobe`.

## Why the extra app

The probe has to send its queries from an app that AppTP covers, which rules out the easy ways to run it:

- **`adb shell` is outside AppTP.** The shell user (uid 2000) isn't part of AppTP's VPN, so the probe runs as the
  `dev.netguard.dnsprobe` app instead, with `run-as`. The app has no code; it only gives the probe an app uid.
- **AppTP never protects packages named `com.duckduckgo.*`**, so the app is named `dev.netguard.dnsprobe`.
- **A newly installed app has no network** until it leaves the most restricted standby bucket and, on recent Android
  versions, is on the deviceidle allowlist. The script does both (`am set-standby-bucket`, `cmd deviceidle whitelist`);
  otherwise every send fails with "Operation not permitted".
