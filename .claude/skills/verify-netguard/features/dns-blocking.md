# AppTP: DNS blocking

netguard reads DNS answers that pass through the tunnel (`dns.c`) and can block lookups of tracker domains.

## Sub-features

- `parse`: reading the query and answers of a DNS packet (`dns.c`).
- `block`: refusing a lookup of a tracker domain (`dns.c`, `udp.c`).

## How to get to it

AppTP on, Private DNS off, and an app that sends its own DNS queries (or a small test app sending UDP port 53 queries). Most system lookups never reach netguard: the VPN only gets DNS servers on a few device models, and never with a Private DNS provider set. Look up one blocked tracker domain and one allowed domain, on the `main` build and the branch build.

## Checks

No proof yet: write one from this page (the probe would need a DNS mode). Pass:

- The `NetGuard.JNI` log shows the query for both domains, attributed to the app's uid.
- The tracker lookup is blocked; the allowed one resolves.

## Gotchas

- **Check the trigger reaches netguard before trusting a pass.** If no query shows up at all on `main` either, the trigger isn't going through netguard: change the trigger, not the code.
- **Never driven by the tool.**
