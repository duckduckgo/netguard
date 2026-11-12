# AppTP: QUIC

AppTP can only read the server name from TCP. netguard blocks new UDP flows to port 443 (QUIC) in `ip.c`, so apps fall back to TCP, where the SNI check runs.

## Trigger

1. AppTP on, NetP off.
2. In Chrome open a few Google and Cloudflare sites, then open Instagram and YouTube and scroll each for 20 seconds.
3. Same steps on the `main` build and the branch build.

## Pass

- `main`: `UDP new session` lines to port 443 from Chrome, Instagram and YouTube, so the trigger sends QUIC through netguard. If there are none, change the trigger.
- Branch: no `UDP new session` lines to port 443; `UDP blocked session` lines to port 443 instead.
- Branch: the same apps open new TCP connections to port 443, and `TLS server` found lines go up compared with `main`.
- Pages and feeds still load. Check the screen, not only the log.
