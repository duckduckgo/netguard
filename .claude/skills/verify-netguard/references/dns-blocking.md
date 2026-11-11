# AppTP: DNS blocking

netguard reads DNS answers that pass through the tunnel (`dns.c`) and can block lookups of tracker domains.

Most system lookups never reach netguard: the VPN only gets DNS servers on a few device models, and never with a Private DNS provider set. Only apps that send their own DNS queries go through it. Check that the trigger really sends DNS through the tunnel before trusting a pass.

## Trigger

1. Private DNS off.
2. From an app that does its own DNS (or a small test app sending UDP port 53 queries), look up one blocked tracker domain and one allowed domain.
3. Same steps on the `main` build and the branch build.

## Pass

- The `NetGuard.JNI` log shows the query for both domains, attributed to the app's uid.
- The tracker lookup is blocked; the allowed one resolves.
- If no query shows up at all on `main` either, the trigger isn't going through netguard: change the trigger, not the code.
