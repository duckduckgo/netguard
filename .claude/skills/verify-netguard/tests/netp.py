"""NetP sends other apps' traffic through our WireGuard server, and with AppTP on too, blocks trackers in the tunnel.

The selftest's NetP fixture, like tests/apptp.py: for a change, write your own proof from features/wireguard-netp.md.

Needs the snapshot netp-signed-in: the app signed in to a subscription with the VPN, NetP and AppTP off. See
features/wireguard-netp.md for how to make it once.
"""
import re

from verify_netguard import steps

SNAPSHOT = "netp-signed-in"
TRACKERS = ["app.adjust.com", "api2.branch.io"]
CONTROL = "example.com"
LIVE = TRACKERS + [CONTROL, "the NetP servers"]
COVERS = ["src/wireguard/jni.c", "src/wireguard/tun_android.go", "src/wireguard/api-android.go",
          "src/netguard/tls_parser.c"]

SERVER = re.compile(r"Selected Egress server is WgServerData\(serverName=([^,]+), publicKey=([^,]+),")
# Saved to the evidence: only these lines. The app also logs its WireGuard private key (twice), never saved.
KEPT = re.compile(r"TLS server \S+ \(\S+\) found|shouldAllowDomain for|Blocking connection|handshake (initiation|response)|"
                  r"creating the \w+ network stack|Interface state was")


def run(android):
    start = android.mark()
    steps.enable_netp(android)
    log = android.logs(start)
    server = SERVER.search(log)
    android.check("the app picked a NetP server", server, server.group(1) if server else "no Selected Egress server line")
    if not server:
        return
    name, key = server.group(1), server.group(2)
    # How WireGuard names the peer: the first 4 characters of its base64 key and the 4 before the closing "=".
    peer = f"peer({key[:4]}…{key.rstrip('=')[-4:]})"
    android.check("NetP's stack runs the tunnel", "creating the NETP_VPN network stack" in log)
    android.check(f"WireGuard handshake with {name}",
                  android.wait_for_log(re.escape(f"{peer} - Received handshake response"), since=start))
    uid = None

    def probe(part):
        nonlocal uid
        android.mark()
        results = android.probe(TRACKERS + [CONTROL], "single")
        uid = uid or android.probe_uid()
        android.require_wireguard_saw_probe([h for h, o in results.items() if o != "NO_ADDRESS"])
        part_log = android.logs()
        android.save(f"logcat-{part}.txt", "\n".join(l for l in part_log.splitlines() if KEPT.search(l)) + "\n")
        android.check(f"{part}: control {CONTROL} reached through the tunnel", results[CONTROL] == "ALLOWED", results[CONTROL])
        return results, part_log

    def decided(log, host, verdict):
        # GoBackend is NetP's tunnel asking the app; under AppTP alone it would be NgVpnNetworkStack.
        return re.search(rf"GoBackend: shouldAllowDomain for {re.escape(host)} \({uid}\) = {verdict}", log)

    results, part_log = probe("NetP")
    for tracker in TRACKERS:
        # The control for the next part: without AppTP, NetP lets trackers through.
        android.check(f"NetP: {tracker} reached (AppTP off)",
                      results[tracker] == "ALLOWED" and decided(part_log, tracker, "null"),
                      f"{results[tracker]}, decision for the probe {'logged' if decided(part_log, tracker, 'null') else 'missing'}")

    restart = android.mark()
    steps.enable_apptp_from_settings(android)
    android.check("WireGuard handshake with the server again after AppTP restarted the VPN",
                  android.wait_for_log(re.escape(f"{peer} - Received handshake response"), since=restart))
    results, part_log = probe("NetP+AppTP")
    for tracker in TRACKERS:
        logged = decided(part_log, tracker, "AppTracker")
        android.check(f"NetP+AppTP: {tracker} blocked", results[tracker] == "TIMEOUT" and logged,
                      f"{results[tracker]}, block decision for the probe {'logged' if logged else 'missing'}")
        # Found on the first runs: once the probe gives up and closes its socket, the kernel retransmits the hello, the
        # app can't find its owner (uid 0) and lets it through. The app's behavior, not netguard's: noted, not checked.
        leaked = len(re.findall(rf"GoBackend: shouldAllowDomain for {re.escape(tracker)} \(0\) = null", part_log))
        if leaked:
            android.note(f"{tracker}: {leaked} retransmitted hello(s) allowed with an unknown owner (uid 0) after the "
                         "probe closed its socket")
    android.check("NetP still running at the end", android.tunnel_up())
