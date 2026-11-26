# speedprobe

Measures how much App Tracking Protection slows down an app's downloads and uploads on a device.

```sh
tools/speedprobe/run.sh
STREAMS=4 DIRECTIONS=up tools/speedprobe/run.sh      # uploads only, four connections at once
DIRECTIONS=down HOST=scaleway.testdebit.info URL_PATH=/1G.iso tools/speedprobe/run.sh
```

It needs a device connected over adb with a debug build of the DuckDuckGo app and AppTP on.

`speed.cloudflare.com` refuses downloads over 10 MB and rate-limits a network that downloads a lot (HTTP 403 and
429), so the probe sends 10 MB requests on each connection, and `HOST` with `URL_PATH` downloads a large file from
another server instead (it must serve byte ranges). Uploads only work with Cloudflare.

The script builds `speedprobe`, a small program that downloads or uploads a number of bytes over plain HTTP from
`speed.cloudflare.com`, and runs it two ways on the same device and network, alternating:

- **through AppTP**, as a code-less probe app (`dev.netguard.speedprobe`) that AppTP covers, and
- **direct**, as the DuckDuckGo app itself, which AppTP never covers.

For each run it also reads the CPU time of AppTP's VPN process (`<app>:vpn`), where netguard runs. 100% means one
core was fully busy for the whole transfer.

It ends with the medians and a verdict: `SLOWER` (exit 1) when AppTP's median is below 80% of the direct one in
either direction, `SAME` (exit 0) otherwise.

## Reading the result

- **Slower, and AppTP's CPU near 100%:** netguard's single thread can't keep up, so the device's CPU is the limit.
- **Slower, and AppTP's CPU well below 100%:** something other than CPU limits it, such as the TCP window netguard
  advertises, the TUN interface or buffering.
- **The same:** this device and network aren't affected. Try `STREAMS=4`, mobile data, a faster Wi-Fi, or an older
  device.

- **An upload through AppTP fails after about 15 seconds with "Connection reset by peer":** netguard stopped forwarding
  one of its connections and the server gave up on it. netguard 1.10.3 and earlier do this when an app resends a segment
  with different boundaries than it first sent, for example longer (see `src/netguard/include/tcp_queue.h`).

Debug builds of the app run netguard with debug logging, a few log lines per packet, so the CPU use they show is higher
than in release builds.

The direct speed is the network's own. A network that changes speed during the run makes the comparison noisy; more
`ROUNDS` help.
