# NetP: WireGuard

NetP is the VPN: it sends the device's traffic through our WireGuard servers, using `libwg-go.so`, built from `src/wireguard`. Every outgoing IPv4 TCP packet goes through `tun_android.go`, which asks netguard through `jni.c` (`is_pkt_allowed`): it reads the server name, logs `TLS server <name> (<address>) found`, and asks the app, which logs its decision under the `GoBackend` tag. With AppTP off the app allows everything; with AppTP on too, it blocks trackers there.

## Sub-features

- `tunnel`: connecting to the server the app picked, and sending other apps' traffic through it.
- `apptp-in-netp`: with AppTP on too, blocking trackers inside the tunnel (`tun_android.go`, `jni.c`).

## How to get to it

NetP needs a DuckDuckGo subscription with the VPN, signed in to the app. The tool keeps it as a snapshot of this checkout's emulator, so signing in is a one-time step:

```
$V install                                     # the app the snapshot will hold must be the tool's
$V device stop && $V device start --window     # the emulator, with its screen
```

On the emulator: open the app, menu > Settings > Internal Features > Subscription Settings > Recover subscription, and sign in (email, then the code it sends). Back in Settings, a VPN entry shows under DuckDuckGo Subscription. Leave NetP and AppTP off, then:

```
$V snapshot save netp-signed-in
```

The snapshot stays with the emulator on this machine, never in the repo. It has to be the whole emulator: the app encrypts its tokens with an Android keystore key, so a copy of its data folder wouldn't survive. Sign in again only if the account is signed out, or after `cleanup --all`. Only this checkout's emulator has the snapshot, so a NetP proof doesn't run on a real phone.

Each run loads the snapshot, sets the emulator's clock to now with automatic time off, and installs the build under test over the app, which keeps its data. Then `steps.enable_netp` turns NetP on from Settings > VPN, and `steps.enable_apptp_from_settings` adds AppTP.

## Checks

Write the proof for your change from this recipe; `tests/netp.py` is the selftest's version of it, a starting point (`$V prove .claude/skills/verify-netguard/tests/netp.py`). It checks, from the logs:

1. **Traffic goes through our server.** The app picked a NetP server (`Selected Egress server is WgServerData(serverName=...`), NetP's stack runs the tunnel (`creating the NETP_VPN network stack`), and WireGuard completed a handshake with that server (`peer(<key>) - Received handshake response`, the peer named by the first 4 characters of its public key and the 4 before the closing `=`).
2. **The probe's traffic is in the tunnel.** For each host, `TLS server <host> (<address the probe connected to>) found` (`require_wireguard_saw_probe`), and the app's decision for the probe's uid under `GoBackend`. The control is reached, and so are the trackers: NetP alone doesn't block them.
3. **With AppTP on too, trackers are blocked.** AppTP turned on from Settings (which restarts the VPN, so a new handshake), then the trackers time out with a block decision for the probe, and the control is still reached.

Checking where traffic exits (a what's-my-IP service) and the VPN screen belongs to the Android app's verification, after the netguard version bump.

## Gotchas

- **The app logs its WireGuard private key**, twice (as PrivateKey = and as private_key=). A proof saves only the lines it reads (logcat-NetP.txt and logcat-NetP+AppTP.txt), never the configuration.
- **A snapshot can stop loading.** An emulator or system image update can leave old snapshots unloadable; the run then stops with an error saying so. Sign in again as in How to get to it and save the snapshot again.
- **The backend can refuse the snapshot's account.** If the VPN switch turns itself off ("The VPN is disabled", the run stops with "NetP's tunnel didn't come up") and the app logs the pixel m_netp_ev_backend_api_error_device_registration_failed, the NetP backend refused to register the device: netguard never ran. Seen 2026-11-19 with a snapshot from 2026-11-17. Sign in again as in How to get to it and save the snapshot again.
- **A snapshot brings back its clock.** With automatic time on, the clock jumps back to the snapshot's when the VPN starts, and logs written after a mark are timestamped before it; `snapshot load` turns automatic time off for that reason.
- **Retransmitted hellos to a tracker get through.** In every run so far, after the probe gives up on a blocked tracker and closes its socket, the kernel retransmits the hello once more; the app can no longer find the connection's owner (`shouldAllowDomain for <tracker> (0) = null`) and lets it through. The probe has already counted the tracker as blocked, but the tracker's server receives a ClientHello. That's the app's uid lookup (GoBackend.kt in the Android repo), not netguard: the proof reports it as a note, not a failed check.
- **Not covered yet:** throughput and stalls under NetP, IPv6 (`tun_android.go` doesn't filter it yet), DNS through NetP's resolver, malware blocking (`dns-malware.go`), server switches.
- **Shown failing:** `selftest --with-broken-build` runs a `tun_android.go` that ignores netguard's block; only the two NetP+AppTP tracker checks fail. Never shown failing: the server and handshake checks. Last driven: 2026-11-17, API 34 arm64 emulator.
