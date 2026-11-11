# NetP: WireGuard

NetP runs WireGuard through `libwg-go.so`, built from `src/wireguard`. Its packet checks call into netguard through `jni.c` (`is_pkt_allowed`), which looks at IPv4 TCP only.

The tunnel MTU is 1280, so a ClientHello can be split across TCP segments here even when it fits in one segment under AppTP.

## Trigger

1. NetP on. For tracker blocking in NetP, AppTP on too.
2. Confirm the tunnel is up: the app shows connected and a page loads.
3. Browse in Chrome for a few minutes, including sites with trackers.
4. Same steps on the `main` build and the branch build. Swap both `libnetguard.so` and `libwg-go.so`: they are linked together.

## Pass

- The tunnel connects and stays up; pages load as on `main`.
- For SNI changes: tracker connections in NetP are blocked, counted with a temporary `[PROBE]` log in `jni.c`. Don't count `TLS server name not found`: it's logged for every SYN and ACK too.
- No crash or ANR in `adb logcat -b crash`.
