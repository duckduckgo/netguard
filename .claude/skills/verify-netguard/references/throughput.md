# Throughput, stalls and CPU

Changes to TCP queues and windows (`tcp.c`), `tun.c` or the event loop can slow traffic or stall it.

## Trigger

1. AppTP on, NetP off, the same Wi-Fi network for every run.
2. Run a fixed workload with several parallel connections:
   - **Upload:** at least 4 connections, 50 MB or more each.
   - **Download:** a large file from a server without a request cap. Some speed-test servers cap the size per request or rate-limit repeated runs; if results drop suddenly, check for that first.
3. At least 5 runs per build, alternating builds, on the `main` build, the branch build and with the VPN off.

## Pass

- Median throughput within the noise of `main`, or better for a perf fix. Report median and spread for each build, and the VPN-off number as the ceiling.
- No stalls: a transfer that stops for many seconds and then gets reset by the server counts as a failure, and the count of failures per build is part of the result.
- CPU: compare debug with debug only (debug builds log at DEBUG level).
