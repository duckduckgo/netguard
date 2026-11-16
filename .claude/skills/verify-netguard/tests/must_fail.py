"""The harness only counts what happened after mark(), reads every pixel log format and netguard's session lines, refuses a
probe that never connected or whose traffic netguard never saw (per host, not by count), reports a UI element that never
shows up as a failed check, refuses a tap on an element that isn't there, and sees the app crash.

Run it after changing the library: verify-netguard prove tests/must_fail.py
"""
import time

from verify_netguard import Error, steps
from verify_netguard.core import APP_ID
from verify_netguard.harness import crashes, matches


def log(android, tag, text):
    android.shell("log", "-t", tag, f"'{text}'")


def run(android):
    log(android, "RxBasedPixel", "Pixel sent: m_verify_before_mark with params: {} {}")
    time.sleep(0.1)
    android.mark()
    log(android, "RxBasedPixel", "Pixel sent: m_verify_sent with params: {} {}")
    log(android, "PixelEntity", "Pixel sent: 7 m_verify_sent_queued with params: {appVersion=1} {}")
    log(android, "RxBasedPixel", "Pixel enqueued: m_verify_enqueued with params: {} {}")
    log(android, "NetGuard.JNI", "TCP S 10.0.0.2/40000 > 192.0.2.7/443 seq 0 ack 0 data 0 win 65535 uid 10999 "
                                 "new session mss 1460 ws 6 window 4194240")
    time.sleep(1)  # let logd flush before reading

    fired = android.pixels()
    android.check("a pixel logged before mark() isn't counted", "m_verify_before_mark" not in fired, fired)
    for name in ("m_verify_sent", "m_verify_sent_queued", "m_verify_enqueued"):
        android.check(f"reads the {name} log format", name in fired, fired)
    android.check("a pixel that wasn't fired isn't reported", "m_verify_never" not in fired, fired)
    sessions = android.netguard_sessions("10999")
    android.check("reads netguard's new session lines", sessions == ["192.0.2.7/443"], sessions)
    android.check("counts only the uid asked for", android.netguard_sessions("10998") == [])

    never = "text=verify-netguard: this text is never on screen"
    android.launch()
    shown = android.expect_visible("(expected to fail)", never, timeout=2)
    failed = android.checks.pop()
    android.check("an element that never shows up is reported as a failed check", not shown and not failed["ok"], failed)
    android.check("the layout at that failure is kept with the evidence", (android.evidence / "layout-at-failure.json").exists())
    try:
        android.tap(never, wait=2)
        android.check("refuses a tap on an element that isn't there", False, "the tap succeeded")
    except Error as e:
        android.check("refuses a tap on an element that isn't there", "failed" in str(e), e)
    android.check("matches the CLI's selectors", all([
        matches("id=skipOnboarding", {"resource-id": "com.duckduckgo.mobile.android.debug:id/skipOnboardingButton"}),
        matches("text=ok", {"text": "OK"}),
        not matches("text=/^OK$/", {"text": "Book"}),
        matches(r"id=/:id\/(a|b)$/,text=/^x, y$/i", {"resource-id": "p:id/b", "text": "X, Y"}),
    ]))

    try:
        android.probe(["10.255.255.1"], "single", 2000)
        android.check("refuses a probe that never connected", False, "the probe returned a result")
    except Error as e:
        android.check("refuses a probe that never connected", "never opened" in str(e), e)

    steps.fresh_start(android)   # AppTP off: the probe's traffic doesn't go through netguard
    android.mark()
    android.probe(["example.com"], "single")
    try:
        android.require_netguard_saw_probe(["example.com"])
        android.check("refuses probe results netguard never saw", False, "it accepted them")
    except Error as e:
        android.check("refuses probe results netguard never saw", "didn't go through netguard" in str(e), e)

    # Two sessions to one host can't stand in for a second host netguard never saw.
    android.mark()
    uid = android.probe_uid()
    for port in (40001, 40002):
        log(android, "NetGuard.JNI", f"TCP S 10.0.0.2/{port} > 192.0.2.7/443 seq 0 ack 0 data 0 win 65535 uid {uid} "
                                     "new session mss 1460 ws 6 window 4194240")
    time.sleep(1)
    android.probe_addresses.update({"a.verify.test": "192.0.2.7", "b.verify.test": "192.0.2.8"})
    try:
        android.require_netguard_saw_probe(["a.verify.test", "b.verify.test"])
        android.check("matches netguard's sessions per host, not by count", False, "it accepted them")
    except Error as e:
        android.check("matches netguard's sessions per host, not by count", "b.verify.test" in str(e) and
                      "a.verify.test" not in str(e), e)

    android.check("reads the app's crash and ANR lines, and only the app's", crashes(
        f"F DEBUG   : pid: 1, tid: 1, name: e.android.debug  >>> {APP_ID}:vpn <<<\n"
        "E AndroidRuntime: Process: com.example.other, PID: 2\n",
        f"E ActivityManager: ANR in {APP_ID}\n") == [
        f"F DEBUG   : pid: 1, tid: 1, name: e.android.debug  >>> {APP_ID}:vpn <<<", f"E ActivityManager: ANR in {APP_ID}"])
    # A real crash: the debug app may signal itself. Last, because every run fails on a crash after its start.
    android.launch()
    since = android.mark()
    android.shell("run-as", APP_ID, "kill", "-11", android.shell("pidof", APP_ID).split()[0])
    deadline = time.time() + 15
    while not android.crashes(since) and time.time() < deadline:
        time.sleep(1)
    android.check("sees the app crash", android.crashes(since))
    android.started = android.mark()   # the crash above is this test's, not the run's
