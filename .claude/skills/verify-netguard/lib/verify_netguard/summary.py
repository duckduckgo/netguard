"""Markdown for a PR's Verification section, from one run (after) or two (before and after).

The repo is public: nothing here may carry local paths, user names, logs or screenshots, only what the manifests
record about the proof, the builds, the device and the checks.
"""
import json
import subprocess
from pathlib import Path

from .core import NATIVE_SOURCES, REPO, Error

CLI = ".claude/skills/verify-netguard/scripts/verify-netguard"


def load_run(evidence):
    manifest = Path(evidence) / "manifest.json"
    if not manifest.exists():
        raise Error(f"{evidence} isn't an evidence folder (no manifest.json)")
    run = json.loads(manifest.read_text())
    run["proof_source"] = (Path(evidence) / "proof.py").read_text() if (Path(evidence) / "proof.py").exists() else ""
    return run


def build_label(build):
    if build.get("base"):
        return f"base `{build['base']}` (`{build['head'][:10]}`)"
    return f"this branch (`{build['head'][:10]}`{', uncommitted changes' if build['dirty'] else ''})"


def committed_path(path):
    """The proof's repo path if it's committed, else None: a throwaway proof's source goes in the summary instead."""
    path = Path(path)
    if not path.is_relative_to(REPO):
        return None
    rel = str(path.relative_to(REPO))
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files", "--error-unmatch", rel], capture_output=True)
    return rel if tracked.returncode == 0 else None


def side(build):
    """How the summary names a run's build: the base ref, or this branch."""
    return "the base" if build.get("base") else "this branch"


def failed(run):
    return [c for c in run["checks"] if not c["ok"]]


def verdict_line(before, after):
    def state(run, where):
        if run["verdict"] == "PASS":
            return f"passes on {where}"
        if run["verdict"] == "ERROR":
            return f"couldn't run on {where} ({(run['error'] or 'error').splitlines()[0]})"
        if not run["checks"]:
            return f"fails on {where} (no checks ran)"
        reasons = {c["detail"] for c in failed(run)}
        reason = f": {reasons.pop()}" if len(reasons) == 1 else ""
        return f"fails on {where} ({len(failed(run))} of {len(run['checks'])} checks{reason})"

    sentence = "; ".join(([state(before, side(before["build"]))] if before else []) + [state(after, side(after["build"]))])
    return sentence[0].upper() + sentence[1:] + "."


EXPECTATIONS = {
    # what each run should show: (before, after)
    "fix": (("FAIL",), ("PASS",), "a fix", "fails on the base, passes on this branch"),
    "same": (("PASS",), ("PASS",), "a change that shouldn't alter behavior", "passes on both"),
}


def expectation_line(expect, before, after):
    want_before, want_after, what, shape = EXPECTATIONS[expect]
    if before["verdict"] in want_before and after["verdict"] in want_after:
        return f"✅ As expected for {what}: {shape}."
    return f"⚠️ Not what {what} should show ({shape})."


def changed_native_files(before, after):
    """The native files the after build's commit changed since it left the before build's (uncommitted changes aren't
    listed). From their merge base: commits only the before has aren't the change."""
    out = subprocess.run(["git", "-C", str(REPO), "diff", "--name-only", f"{before['build']['head']}...{after['build']['head']}",
                          "--", *NATIVE_SOURCES], capture_output=True, text=True)
    return out.stdout.split() if out.returncode == 0 else None


def coverage_line(before, after):
    changed = changed_native_files(before, after)
    if changed is None:
        return "- Changed native files: unknown (a build's commit isn't in this checkout)"
    covers = set(after.get("covers", []))
    covered = [f for f in changed if f in covers]
    other = [f for f in changed if f not in covers]
    dirty = " (plus uncommitted changes, not listed)" if after["build"].get("dirty") else ""
    if not changed:
        return f"- Changed native files: none between the builds' commits{dirty}"
    return (f"- Changed native files{dirty}: " + (f"covered by this proof: {', '.join(f'`{f}`' for f in covered)}" if covered else "none covered by this proof")
            + (f"; ⚠️ not covered by it: {', '.join(f'`{f}`' for f in other)}" if other else ""))


def differences(before, after):
    """What differs between the two runs besides the build: a comparison is only fair when this is empty."""
    found = []
    if before["proof"]["doc"] != after["proof"]["doc"]:
        found.append("proof")
    if before["proof"]["params"] != after["proof"]["params"]:
        found.append("params")
    for key in ("model", "api", "rmem_max"):
        if before["device"].get(key) != after["device"].get(key):
            found.append(f"device {key}")
    if before["build"]["app"]["sha256"] != after["build"]["app"]["sha256"]:
        found.append("app")
    if before.get("privacy_config") != after.get("privacy_config"):
        found.append("privacy config")
    return found


def cell(check):
    if check is None:
        return "not run"
    return f"{'✅' if check['ok'] else '❌'} {check['detail']}".strip()


def rerun(run, proof):
    """Rebuilt from the manifest rather than copied, so a proof outside the repo doesn't leak its local path."""
    build = run["build"]
    setup = f"$V build --base {build['base']} && $V install --base" if build.get("base") else "$V build && $V install"
    params = "".join(f" --param {k}={v}" for k, v in run["proof"]["params"].items())
    rmem = f" --rmem-max {run['proof']['rmem_max']}" if run["proof"].get("rmem_max") else ""
    return f"{setup} && $V prove {proof}{params}{rmem}"


def summarize(after_dir, before_dir=None, expect=None):
    after = load_run(after_dir)
    before = load_run(before_dir) if before_dir else None
    if before and expect not in EXPECTATIONS:
        raise Error("comparing two runs needs --expect fix (fails on the base, passes on the branch) or --expect same "
                    "(passes on both)")
    proof_path = committed_path(after["proof"]["path"])
    device = after["device"]
    params = " ".join(f"`{k}={v}`" for k, v in after["proof"]["params"].items())

    lines = [
        "### Verification",
        "",
        f"**{verdict_line(before, after)}**" + (f" {expectation_line(expect, before, after)}" if before else ""),
        "",
        f"- Proof: {f'`{proof_path}`' if proof_path else 'a proof written for this change (source below)'}: "
        f"{after['proof']['doc'].splitlines()[0]}",
        f"- Device: {device['model']}, API {device['api']}, rmem_max {device['rmem_max']}" + (f"; params {params}" if params else ""),
        f"- Builds: {(build_label(before['build']) + ' → ') if before else ''}{build_label(after['build'])}, "
        f"{after['build']['abi']}",
        f"- App: DuckDuckGo Android debug {after['build']['app']['version']}, with the build's {' and '.join(after['build']['libs'])}",
        f"- Live services: {', '.join(after['live']) or 'none'}",
    ]
    if before:
        lines.append(coverage_line(before, after))
    if before and differences(before, after):
        lines.append(f"- ⚠️ The runs also differ in: {', '.join(differences(before, after))}, so the comparison isn't like for like")

    if before:
        before_checks = {c["check"]: c for c in before["checks"]}
        after_checks = {c["check"]: c for c in after["checks"]}
        names = list(dict.fromkeys([*before_checks, *after_checks]))
        changed = [n for n in names if (before_checks.get(n) or {}).get("ok") != (after_checks.get(n) or {}).get("ok")]
        header = f"| Check | {side(before['build']).capitalize()} | {side(after['build']).capitalize()} |"
        lines += ["", header, "|---|---|---|"]
        rows = changed or []
        lines += [f"| {n} | {cell(before_checks.get(n))} | {cell(after_checks.get(n))} |" for n in rows]
        if not changed:
            lines.append(f"| all {len(names)} checks | same result | same result |")
        lines += ["", "<details><summary>All checks</summary>", "", header, "|---|---|---|",
                  *[f"| {n} | {cell(before_checks.get(n))} | {cell(after_checks.get(n))} |" for n in names],
                  "", "</details>"]
    else:
        bad = failed(after)
        if bad:
            lines += ["", "| Check | Result |", "|---|---|", *[f"| {c['check']} | {cell(c)} |" for c in bad]]
        elif after["verdict"] == "PASS":
            lines += ["", "The check passed." if len(after["checks"]) == 1 else f"All {len(after['checks'])} checks passed."]
        elif not after["checks"]:
            lines += ["", "No checks ran."]
        lines += ["", "<details><summary>All checks</summary>", "", "| Check | Result |", "|---|---|",
                  *[f"| {c['check']} | {cell(c)} |" for c in after["checks"]], "", "</details>"]

    for item in after.get("unverified", []):
        lines.append(f"- Not verified: {item['what']} ({item['why']})")
    for run in [r for r in (before, after) if r]:
        for title, markdown in run.get("sections", []):
            lines += ["", f"<details><summary>{title} ({side(run['build'])})</summary>", "", markdown, "", "</details>"]
    if not proof_path and after["proof_source"]:
        lines += ["", "<details><summary>Proof source</summary>", "", "```python", after["proof_source"].rstrip(), "```",
                  "", "</details>"]

    proof = proof_path or "proof.py"
    lines += ["", "<details><summary>Rerun</summary>", "", "```",
              *([] if proof_path else ["# save the proof source above as proof.py"]),
              f"V={CLI}",
              "$V app --apk <a DuckDuckGo Android debug APK>",
              *([rerun(before, proof)] if before else []),
              rerun(after, proof), "```", "", "</details>"]
    return "\n".join(lines) + "\n"
