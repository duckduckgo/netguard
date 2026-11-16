"""The `android` handle a proof acts and checks through, and `prove`, which runs a proof and writes its evidence."""
import datetime
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

from . import core
from .core import APP_ID, SKILL, Error, adb

PIXEL_LINE = re.compile(r"Pixel (?:sent|enqueued): (?:\S+ )?(\S+) with params")
# A Java crash names the process on its "Process:" line, a native crash on its ">>> name <<<" line; the app's VPN runs
# in its own process (<app id>:vpn).
CRASH_LINE = re.compile(rf"(?:Process: |>>> ){re.escape(APP_ID)}(?::\w+)?\b")
ANR_LINE = re.compile(rf"ANR in {re.escape(APP_ID)}(?::\w+)?\b")
PRIVACY_CONFIG_VERSION = re.compile(r"RealPrivacyConfigPersister: new: (\d+)\)")


def crashes(crash_log, main_log=""):
    """The app's crash and ANR lines in logcat's crash buffer and main log."""
    return [l for l in crash_log.splitlines() if CRASH_LINE.search(l)] + \
           [l for l in main_log.splitlines() if ANR_LINE.search(l)]


def ip(address):
    """One spelling per address: Java writes IPv6 in full, netguard compressed."""
    try:
        return ipaddress.ip_address(address).compressed
    except ValueError:
        return address
SELECTOR_PAIR = re.compile(r"\s*(\w+)\s*[=:]\s*(/(?:\\.|[^/])*/i?|[^,]*)\s*(?:,|$)")
SELECTOR_FIELDS = {"text": "text", "txt": "text", "id": "resource-id", "res": "resource-id", "desc": "content-desc",
                   "content": "content-desc", "class": "class", "clazz": "class", "cls": "class", "clz": "class"}


def matches(target, node):
    """The CLI's selector matching for its string fields, for reading the layout: `android input` matches the same way."""
    pairs = SELECTOR_PAIR.findall(target)
    if not pairs:
        raise Error(f"not a selector: {target}")
    for key, value in pairs:
        if key not in SELECTOR_FIELDS:
            raise Error(f"visible()/wait_for() match text, id, desc and class, not {key}")
        actual = node.get(SELECTOR_FIELDS[key], "")
        if value.startswith("/"):
            pattern, flags = (value[1:-2], re.I) if value.endswith("/i") else (value[1:-1], 0)
            if not re.search(pattern.replace("\\/", "/"), actual, flags):
                return False
        elif not (actual if value == "*" else value.lower() in actual.lower()):
            return False
    return True


class Android:
    def __init__(self, serial, evidence, params):
        self.serial = serial
        self.evidence = evidence
        self.params = params
        self.model = adb("shell", "getprop", "ro.product.model").strip()
        self.api = adb("shell", "getprop", "ro.build.version.sdk").strip()
        self.checks, self.notes, self.unverified_items, self.sections = [], [], [], []
        self._mark = None
        self.started = self._now()   # crashes count from here; not a mark, so reads still need one
        self.probe_addresses = {}
        self._probe_installed = False
        self._ui_ready = False

    # --- checks and evidence

    def check(self, what, ok, detail=""):
        if isinstance(detail, dict):
            detail = ", ".join(f"{k}={v}" for k, v in detail.items())
        self.checks.append({"check": what, "ok": bool(ok), "detail": str(detail)})
        return bool(ok)

    def note(self, text):
        self.notes.append(text)

    def unverified(self, what, why):
        self.unverified_items.append({"what": what, "why": why})

    def section(self, title, markdown):
        """Extra report content, e.g. a table of what the proof measured."""
        self.sections.append((title, markdown))

    def save(self, name, text):
        (self.evidence / name).write_text(text)

    def shot(self, name):
        png = subprocess.run(["adb", "exec-out", "screencap", "-p"], capture_output=True).stdout
        (self.evidence / f"{name}.png").write_bytes(png)

    def param(self, name, default=None):
        return self.params.get(name, default)

    # --- device

    def shell(self, *cmd, check=True):
        return adb("shell", *cmd, check=check)

    def broadcast(self, action, **extras):
        args = [arg for key, value in extras.items() for arg in ("--es", key, str(value))]
        self.shell("am", "broadcast", "-a", action, *args)

    def tunnel_up(self):
        return bool(re.search(r"\btun\d+:", self.shell("ip", "-o", "link")))

    # --- the UI, through the Android CLI (https://developer.android.com/tools/agents/android-cli)
    # A target is the CLI's selector: comma-separated key=value pairs; strings match as case-insensitive substrings,
    # /regex/ matches exactly what it says. `id=skipOnboardingButton` works on the .debug package as on release.

    def _android(self, *args):
        if not self._ui_ready:
            core.require("android", "install the Android CLI (https://developer.android.com/tools/agents/android-cli)")
            locale = self.shell("getprop", "persist.sys.locale").strip() or self.shell("getprop", "ro.product.locale").strip()
            if locale and not locale.startswith("en"):
                raise Error(f"UI targets match English text; set the device language to English (it's {locale})")
            self._ui_ready = True
        result = core.run(["android", "--no-metrics", *args, f"--device={self.serial}"], check=False)
        with open(self.evidence / "ui.log", "a") as log:
            log.write(f"$ android {' '.join(args)}\n" + (result.stdout + result.stderr if result.returncode else ""))
        return result

    def _input(self, *args):
        result = self._android("input", *args)
        if result.returncode != 0:
            self.save("layout-at-failure.json", json.dumps(self.layout(), indent=1))
            errors = re.findall(r'"error": "([^"]*)"', result.stdout) or [result.stderr.strip()]
            raise Error(f"android input {' '.join(args)} failed: {'; '.join(errors)}; see ui.log and layout-at-failure.json")

    def launch(self, allow_notifications=True):
        """Starts the app. Its notification permission is granted first unless a proof is about that prompt."""
        if allow_notifications and int(self.api) >= 33:
            self.shell("pm", "grant", APP_ID, "android.permission.POST_NOTIFICATIONS")
        # Named, because debug builds have a second launcher activity (LeakCanary's).
        self.shell("am", "start", "-W", "-n", f"{APP_ID}/com.duckduckgo.app.launch.Launcher")

    def tap(self, target, wait=10, first=False):
        """Taps the element, waiting up to `wait` seconds for it; `first` picks the first of several matches."""
        self._input("tap", target, f"--wait={wait * 1000}", *(["--match=first"] if first else []))

    def type(self, text, target, submit=False, wait=10):
        self._input("text", text, target, f"--wait={wait * 1000}", *(["--submit"] if submit else []))

    def scroll_to(self, target, container="scrollable=true", direction="down", wait=10):
        self._input("scroll", container, f"--until={target}", f"--dir={direction}", f"--wait={wait * 1000}",
                    "--match=first")

    def key(self, key):
        """back, home, recents, enter, tab, esc, or an Android keycode."""
        self._input("key", key)

    def hide_keyboard(self):
        if any(window["type"] == "INPUT_METHOD" for window in self._windows()):
            self.key("back")

    def _windows(self):
        # Animated screens (AppTP's enabled screen) never go idle; wait_for() polls instead.
        result = self._android("layout", "--flat", "--no-idle")
        if result.returncode != 0:
            raise Error(f"android layout failed: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def layout(self):
        """Every element on screen, in every window (app, system dialogs, keyboard), as the CLI reports it."""
        return [node for window in self._windows() for node in window["content"]]

    def visible(self, target):
        return any(matches(target, node) for node in self.layout())

    def wait_for(self, *targets, timeout=30):
        """The first of `targets` to appear within `timeout` seconds, or None."""
        deadline = time.time() + timeout
        while True:
            nodes = self.layout()
            for target in targets:
                if any(matches(target, node) for node in nodes):
                    return target
            if time.time() > deadline:
                return None
            time.sleep(0.5)

    def expect_visible(self, what, target, timeout=30):
        shown = self.wait_for(target, timeout=timeout) is not None
        if not shown:
            self.save("layout-at-failure.json", json.dumps(self.layout(), indent=1))
        return self.check(what, shown, "" if shown else f"{target} not on screen after {timeout}s; see layout-at-failure.json")

    # --- logs and telemetry

    def _now(self):
        return self.shell("date", "+%s.%N").strip()[:14]   # logcat -T takes seconds.milliseconds

    def mark(self):
        """Logs and telemetry count from here: call it right before the action under test."""
        self._mark = self._now()
        return self._mark

    def logs(self, since=None):
        since = since or self._mark
        if not since:
            raise Error("logs() needs a mark: call android.mark() before the action")
        return adb("logcat", "-d", "-T", since)

    def wait_for_log(self, pattern, since=None, timeout=30):
        """The first match of `pattern` in the logs since the mark, waiting up to `timeout` seconds for it; or None."""
        deadline = time.time() + timeout
        while True:
            found = re.search(pattern, self.logs(since))
            if found or time.time() > deadline:
                return found
            time.sleep(1)

    def pixels(self, since=None):
        return PIXEL_LINE.findall(self.logs(since))

    def expect_log(self, what, pattern, since=None):
        return self.check(what, re.search(pattern, self.logs(since)))

    def expect_pixel(self, name, since=None):
        """Debug builds log every pixel they fire (and send it as a dev pixel); this reads those lines."""
        fired = self.pixels(since)
        return self.check(f"pixel {name} fired", name in fired, "fired" if name in fired else f"not among {sorted(set(fired))}")

    def expect_no_pixel(self, name, since=None):
        fired = self.pixels(since)
        return self.check(f"pixel {name} not fired", name not in fired, "fired" if name in fired else "")

    # --- the probe app

    def probe(self, hosts, mode="single", timeout_ms=3000):
        """Connects to each host as a third-party app and returns {host: outcome}; see probe/ProbeActivity.java."""
        if not self._probe_installed:
            subprocess.run([str(SKILL / "scripts/probe.sh"), "install"], check=True, capture_output=True,
                           env=core.java_env())
            self._probe_installed = True
        out = core.run([str(SKILL / "scripts/probe.sh"), "run", ",".join(hosts), mode, str(timeout_ms)], check=False)
        if out.returncode != 0:
            raise Error(f"probe run incomplete ({mode}): {out.stderr.strip()}")
        results = {}
        for line in out.stdout.splitlines():
            if line.startswith("RESULT"):
                fields = dict(f.split("=", 1) for f in line.split()[1:] if "=" in f)
                results[fields["host"]] = fields["outcome"]
                if fields.get("ip"):
                    self.probe_addresses[fields["host"]] = ip(fields["ip"])
        missing = [h for h in hosts if h not in results]
        if missing:
            raise Error(f"probe returned no result for {missing} in {mode}; rerun")
        if {"CONNECT_TIMEOUT", "CONNECT_FAILED"} & set(results.values()):
            raise Error(f"connection never opened in {mode} ({results}): the network, not the app; rerun")
        return results

    def probe_uid(self):
        """The probe's uid, as netguard logs it."""
        out = self.shell("dumpsys", "package", core.PROBE_ID)
        uid = re.search(r"\b(?:userId|appId)=(\d+)", out)   # Android 16 prints only appId=
        if not uid:
            raise Error(f"{core.PROBE_ID} isn't installed: probe() installs it")
        return uid.group(1)

    def netguard_sessions(self, uid, since=None):
        """The TCP sessions netguard opened for this uid since the mark, as "<dest>/<port>" strings."""
        return re.findall(rf"> (\S+) seq \d+ ack \d+ data \d+ win \d+ uid {uid} new session", self.logs(since))

    def require_netguard_saw_probe(self, hosts, since=None):
        """A result only says something about netguard if the probe's own connection to each host went through it:
        otherwise (VPN down, the probe outside the tunnel, logs off) an "allowed" passes for the wrong reason. Matched
        by the address the probe connected to, so a second session to one host can't stand in for another host. An
        error, not a failed check."""
        unknown = [h for h in hosts if h not in self.probe_addresses]
        if unknown:
            raise Error(f"the probe never connected to {unknown}: probe() them before require_netguard_saw_probe()")
        seen = {ip(s.rsplit("/", 1)[0]) for s in self.netguard_sessions(self.probe_uid(), since)}
        missing = [h for h in hosts if self.probe_addresses[h] not in seen]
        if missing:
            raise Error(f"netguard logged no session from the probe to {', '.join(f'{h} ({self.probe_addresses[h]})' for h in missing)}: "
                        "its traffic didn't go through netguard, so the results say nothing about it")
        return seen

    def require_wireguard_saw_probe(self, hosts, since=None):
        """With NetP on, netguard's WireGuard side (src/wireguard/jni.c) reads the server name of every TCP packet the
        tunnel sends and logs `TLS server <name> (<address>) found`. That line, for the address the probe connected to,
        shows the probe's connection to each host went into the tunnel and through netguard. An error, not a failed
        check."""
        unknown = [h for h in hosts if h not in self.probe_addresses]
        if unknown:
            raise Error(f"the probe never connected to {unknown}: probe() them before require_wireguard_saw_probe()")
        seen = set(re.findall(r"NetGuard\.JNI: TLS server (\S+) \((\S+)\) found", self.logs(since)))
        missing = [h for h in hosts if (h, self.probe_addresses[h]) not in {(n, ip(a)) for n, a in seen}]
        if missing:
            raise Error(f"netguard's WireGuard side never saw the probe's hello to {', '.join(missing)}: its traffic didn't "
                        "go through the tunnel, so the results say nothing about it")

    def crashes(self, since=None):
        """The app's crashes and ANRs since `since` (default: the start of the run)."""
        since = since or self.started
        return crashes(adb("logcat", "-b", "crash", "-d", "-T", since, check=False), adb("logcat", "-d", "-T", since))


class Recording:
    """Records the screen for the whole run, as 3-minute clips (screenrecord's limit): video-1.mp4, video-2.mp4, ..."""
    DIR = "/sdcard/verify-netguard-video"

    def __init__(self, evidence):
        self.evidence = evidence
        adb("shell", "rm", "-rf", self.DIR, check=False)
        adb("shell", "mkdir", "-p", self.DIR)
        # Each clip ends at the time limit or on SIGINT; the stop file ends the loop.
        loop = (f"i=1; while [ ! -f {self.DIR}/stop ]; do "
                f"screenrecord --bit-rate 2000000 --time-limit 180 {self.DIR}/video-$i.mp4; i=$((i+1)); done")
        self.process = subprocess.Popen(["adb", "shell", loop], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self):
        """Saves the clips to the evidence and returns their names; a recording that failed never fails the run."""
        adb("shell", "touch", f"{self.DIR}/stop", check=False)
        adb("shell", "pkill", "-INT", "screenrecord", check=False)
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
        clips = sorted(adb("shell", "ls", self.DIR, check=False).split(), key=lambda f: (len(f), f))
        saved = []
        for clip in [c for c in clips if c.endswith(".mp4")]:
            if core.run(["adb", "pull", f"{self.DIR}/{clip}", str(self.evidence / clip)], check=False).returncode == 0:
                saved.append(clip)
        adb("shell", "rm", "-rf", self.DIR, check=False)
        return saved


def load_proof(path):
    if not Path(path).is_file():
        raise Error(f"no proof at {path}")
    spec = importlib.util.spec_from_file_location(Path(path).stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise Error(f"{path} doesn't load:\n{traceback.format_exc(limit=1)}")
    if not (module.__doc__ or "").strip():
        raise Error(f"{path}: a proof starts with a docstring saying what it proves")
    if not callable(getattr(module, "run", None)):
        raise Error(f"{path}: a proof defines run(android)")
    return module


def prove(path, params, rmem_max=None, rerun=""):
    serial = core.use_device()
    proof = load_proof(path)
    snapshot = getattr(proof, "SNAPSHOT", None)
    if snapshot:
        # A state a person set up once (an account signed in): load it, then put the build under test back over the
        # app the snapshot has, keeping its data.
        core.check_installed()
        core.load_snapshot(snapshot)
        core.reinstall()
    installed = core.check_installed()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence = core.STATE / "evidence" / f"{stamp}-{Path(path).stem}"
    evidence.mkdir(parents=True)
    shutil.copyfile(path, evidence / "proof.py")
    android = Android(serial, evidence, params)

    error = None
    problems = [p for p in [core.restore_device_settings()] if p]
    recording = Recording(evidence)
    try:
        if rmem_max:
            core.set_rmem_max(rmem_max)
        android.rmem_max = adb("shell", "cat", core.RMEM_MAX).strip()
        proof.run(android)
        if not android.checks:
            # The crash check below would otherwise be the only one, and pass.
            raise Error("the proof made no checks: a proof checks what it claims")
        # Every proof: a crash or ANR of the app during the run fails it, even when the app restarted the VPN after.
        # The lines go to the evidence, not the detail: pr-summary prints details, and it carries no logs.
        found = android.crashes()
        if found:
            android.save("crashes.txt", "\n".join(found) + "\n")
        android.check("the app didn't crash or stop responding", not found,
                      f"{len(found)} crash or ANR line(s), see crashes.txt" if found else "")
    except Error as e:
        error = str(e) or "Error"
    except Exception:
        error = "the proof raised:\n" + traceback.format_exc()
    finally:
        problems += [p for p in [core.restore_device_settings()] if p]
    android.shot("final")
    videos = recording.stop()
    configs = PRIVACY_CONFIG_VERSION.findall(adb("logcat", "-d", "-T", android.started, check=False))

    if error is not None or problems:
        verdict = "ERROR"
    elif android.checks and all(c["ok"] for c in android.checks):
        verdict = "PASS"
    else:
        verdict = "FAIL"
    manifest = {
        "verdict": verdict,
        "error": error or ("; ".join(problems) if problems else None),
        "problems": problems,
        "proof": {"path": str(Path(path).resolve()), "doc": proof.__doc__.strip(), "params": params,
                  "rmem_max": rmem_max},
        "live": getattr(proof, "LIVE", []),
        "snapshot": snapshot,
        "covers": getattr(proof, "COVERS", []),
        # Downloaded at runtime, so two runs can differ in it. AppTP's tracker blocklist is too, but the app doesn't
        # log its version.
        "privacy_config": configs[-1] if configs else None,
        "device": {"serial": serial, "model": android.model, "api": android.api,
                   "rmem_max": getattr(android, "rmem_max", None)},
        "build": installed,
        "source_now": core.source_fingerprint(),
        "checks": android.checks,
        "notes": android.notes,
        "unverified": android.unverified_items,
        "sections": android.sections,
        "videos": videos,
        "rerun": rerun,
    }
    (evidence / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (evidence / "report.md").write_text(report(manifest, android.sections))
    print(json.dumps({"verdict": verdict, "evidence": str(evidence), **({"error": error} if error else {})}, indent=2))
    return {"PASS": 0, "FAIL": 1}.get(verdict, 2)


def report(m, sections):
    b, d = m["build"], m["device"]
    if b.get("base"):
        origin = f"base {b['base']} ({b['head'][:10]})"
    else:
        origin = f"this branch, {b['head'][:10]}{' (dirty)' if b['dirty'] else ''}"
    lines = [
        f"# {m['proof']['doc'].splitlines()[0]}",
        "",
        f"**{m['verdict']}**" + (f": {m['error'].splitlines()[0]}" if m["error"] else ""),
        "",
        f"- Device: {d['model']} (API {d['api']}, {d['serial']}), rmem_max {d['rmem_max']}",
        f"- Libraries: {origin}, {b['abi']}, " + ", ".join(f"{n} {h[:12]}" for n, h in b["libs"].items()),
        f"- App: DuckDuckGo debug {b['app']['version']} ({b['app']['source']}, sha256 {b['app']['sha256'][:12]}), "
        f"installed APK sha256 {b['sha256'][:16]}",
        f"- Live services: {', '.join(m['live']) or 'none'}; privacy config {m['privacy_config'] or 'not downloaded in the run'}",
        f"- Video: {', '.join(m['videos']) or 'none recorded'}",
        f"- Rerun: `{m['rerun']}`",
        "",
        "## Checks",
        "",
        "| | Check | Detail |",
        "|---|---|---|",
        *[f"| {'✅' if c['ok'] else '❌'} | {c['check']} | {c['detail']} |" for c in m["checks"]],
    ]
    if m["unverified"]:
        lines += ["", "## Unverified", "", *[f"- {u['what']}: {u['why']}" for u in m["unverified"]]]
    if m["notes"]:
        lines += ["", "## Notes", "", *[f"- {n}" for n in m["notes"]]]
    for title, markdown in sections:
        lines += ["", f"## {title}", "", markdown]
    return "\n".join(lines) + "\n"
