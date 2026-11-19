"""Environment, state, build identity and the device: everything below a proof."""
import datetime
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

SKILL = Path(__file__).resolve().parents[2]
REPO = Path(subprocess.check_output(["git", "-C", str(SKILL), "rev-parse", "--show-toplevel"], text=True).strip())

def _find_sdk():
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(var):
            return Path(os.environ[var])
    props = REPO / "android/local.properties"
    if props.exists():
        match = re.search(r"^sdk\.dir=(.+)$", props.read_text(), re.M)
        if match:
            return Path(match.group(1).strip().replace("\\:", ":"))
    for default in (Path.home() / "Library/Android/sdk", Path.home() / "Android/Sdk"):   # macOS, Linux
        if default.exists():
            return default
    return None


SDK = _find_sdk()
if SDK:
    os.environ["ANDROID_HOME"] = str(SDK)   # scripts/probe.sh and the SDK tools read it
    if not shutil.which("adb") and (SDK / "platform-tools/adb").exists():
        os.environ["PATH"] = f"{SDK / 'platform-tools'}{os.pathsep}{os.environ['PATH']}"
APP_ID = "com.duckduckgo.mobile.android.debug"
PROBE_ID = "dev.verifynetguard.probe"
# What the Android CLI installs on a device to read the layout and act on it: it stays there after the CLI exits.
UI_DRIVER_ID = "com.android.cli.interact.instrumentation"
REPO_KEY = f"{REPO.name}-{hashlib.sha1(str(REPO).encode()).hexdigest()[:8]}"
STATE = Path(os.environ.get("VERIFY_NETGUARD_HOME", Path.home() / ".ddg-verify-netguard")) / REPO_KEY
AVD = f"verify-netguard-{REPO_KEY}"
# 5680-5758: clear of the ports emulators take by default (5554 up), such as the Android repo's verify-android ones,
# which can run at the same time.
EMULATOR_PORT = 5680 + int(hashlib.sha1(REPO_KEY.encode()).hexdigest(), 16) % 40 * 2
RMEM_MAX = "/proc/sys/net/core/rmem_max"
NDK_VERSION = "21.4.7075529"
CMAKE_VERSION = "3.22.1"
LIBS = ("libnetguard.so", "libwg-go.so")
# Everything the native build reads: a change anywhere else (the skill, tools/, the Gradle project) can't make a
# build stale.
NATIVE_SOURCES = ("src", "android/netguard/src/main/cpp")
KEYSTORE = Path.home() / ".android/debug.keystore"


class Error(Exception):
    """Setup or environment problem: exit 2, never a pass."""


def lock():
    """One command at a time per checkout: two would share its records, its emulator and the app on the device. A
    command's own child commands (selftest's) inherit the lock."""
    if os.environ.get("VERIFY_NETGUARD_LOCKED"):
        return None
    STATE.mkdir(parents=True, exist_ok=True)
    handle = open(STATE / "lock", "a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.seek(0)
        raise Error(f"another verify-netguard command is running in this checkout ({handle.read().strip() or 'unknown'}); "
                    "wait for it, or use a separate worktree")
    handle.seek(0)
    handle.truncate()
    handle.write(f"pid {os.getpid()}: {' '.join(sys.argv[1:3])}")
    handle.flush()
    os.environ["VERIFY_NETGUARD_LOCKED"] = "1"
    return handle   # held until the process exits


def sdk():
    if not SDK:
        raise Error("Android SDK not found: set ANDROID_HOME, or sdk.dir in android/local.properties")
    return SDK


def require(tool, how):
    if not shutil.which(tool):
        raise Error(f"{tool} isn't on PATH: {how}")


def run(cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kw)


def adb(*args, check=True):
    return run(["adb", *args], check=check).stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(name):
    path = STATE / name
    return json.loads(path.read_text()) if path.exists() else None


def save(name, data):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / name).write_text(json.dumps(data, indent=2) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def java_env():
    """avdmanager and the probe build need a JDK 17 or later; on macOS one is found by version."""
    env = dict(os.environ)
    if not env.get("JAVA_HOME") and Path("/usr/libexec/java_home").exists():
        home = run(["/usr/libexec/java_home", "-v", "17+"], check=False).stdout.strip()
        if home:
            env["JAVA_HOME"] = home
    java = str(Path(env["JAVA_HOME"]) / "bin/java") if env.get("JAVA_HOME") else shutil.which("java")
    version = re.search(r'version "(\d+)', run([java, "-version"], check=False).stderr) if java else None
    if not version or int(version.group(1)) < 17:
        raise Error(f"needs JDK 17 or later (found {version.group(1) if version else 'no java'}): set JAVA_HOME")
    if env.get("JAVA_HOME"):
        env["PATH"] = f"{env['JAVA_HOME']}/bin{os.pathsep}{env['PATH']}"
    return env


def build_tools():
    # Stable releases only: preview and rc build-tools sort last but may be incomplete.
    versions = [p.name for p in (sdk() / "build-tools").glob("*") if re.fullmatch(r"\d+(\.\d+)*", p.name)]
    if not versions:
        raise Error("the SDK has no build-tools: `sdkmanager \"build-tools;36.0.0\"`")
    return sdk() / "build-tools" / max(versions, key=lambda v: [int(n) for n in v.split(".")])


# --- build identity -------------------------------------------------------------------------------------------------

def source_fingerprint(root=REPO):
    """The committed native sources and every uncommitted change to them. Only NATIVE_SOURCES go into the libraries,
    so editing the skill or anything else doesn't make a build stale."""
    git = ["git", "-C", str(root)]
    head = run(git + ["rev-parse", "HEAD"]).stdout.strip()
    # A tree entry hashes everything below it.
    h = hashlib.sha256(run(git + ["ls-tree", "HEAD", "--", *NATIVE_SOURCES]).stdout.encode())
    h.update(subprocess.run(git + ["diff", "HEAD", "--binary", "--", *NATIVE_SOURCES],
                            check=True, capture_output=True).stdout)
    untracked = [n for n in run(git + ["ls-files", "-z", "--others", "--exclude-standard", "--", *NATIVE_SOURCES])
                 .stdout.split("\0") if n]
    for name in sorted(untracked):
        h.update(name.encode())
        h.update(sha256(root / name).encode())
    dirty = bool(run(git + ["status", "--porcelain", "--", *NATIVE_SOURCES]).stdout.strip())
    return {"head": head, "dirty": dirty, "fingerprint": h.hexdigest()}


def target_abi():
    """The ABI of the device the build is for: the one in use if it's up, else the skill's emulator's."""
    serial = os.environ.get("ANDROID_SERIAL") or emulator_serial()
    if shutil.which("adb") and device_online(serial):
        return run(["adb", "-s", serial, "shell", "getprop", "ro.product.cpu.abi"]).stdout.strip()
    return host_abi()


def compile_libs(kept, abi, root=REPO, name="branch"):
    """Builds both libraries with the SDK's cmake (Gradle's native build fails on Apple Silicon) and keeps a copy, so a
    later build can't change the files a record points at."""
    ndk = sdk() / "ndk" / NDK_VERSION
    cmake = sdk() / "cmake" / CMAKE_VERSION / "bin/cmake"
    for path, package in ((ndk, f"ndk;{NDK_VERSION}"), (cmake, f"cmake;{CMAKE_VERSION}")):
        if not path.exists():
            raise Error(f"the SDK has no {path.relative_to(sdk())}: `sdkmanager \"{package}\"`")
    require("ninja", "install ninja (e.g. `brew install ninja`)")
    require("go", "install Go, for libwg-go.so (e.g. `brew install go`)")
    # One cmake directory per checkout and ABI, so later builds are incremental.
    work = STATE / "cmake" / f"{name}-{abi}"
    log = STATE / "cmake" / f"{name}-{abi}.log"
    work.mkdir(parents=True, exist_ok=True)
    with open(log, "w") as out:
        for cmd in (
            [str(cmake), "-S", str(root / "android/netguard/src/main/cpp"), "-B", str(work), "-G", "Ninja",
             f"-DCMAKE_MAKE_PROGRAM={shutil.which('ninja')}",
             f"-DCMAKE_TOOLCHAIN_FILE={ndk / 'build/cmake/android.toolchain.cmake'}",
             f"-DANDROID_ABI={abi}", "-DANDROID_PLATFORM=android-23", "-DCMAKE_BUILD_TYPE=Release",
             f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={work / 'lib'}"],
            [str(cmake), "--build", str(work), "--target", "netguard", "libwg-go.so"],
        ):
            if subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT).returncode != 0:
                raise Error(f"the native build failed; see {log}")
    kept.mkdir(parents=True, exist_ok=True)
    for lib in LIBS:
        shutil.copyfile(work / "lib" / lib, kept / lib)
    return {lib: sha256(kept / lib) for lib in LIBS}


def build(abi=None):
    abi = abi or target_abi()
    source = source_fingerprint()
    kept = STATE / "builds" / f"{source['fingerprint'][:16]}-{abi}"
    if (kept / LIBS[-1]).exists():
        libs = {lib: sha256(kept / lib) for lib in LIBS}   # the same source was built before
    else:
        print(f"building {', '.join(LIBS)} for {abi} ...", file=sys.stderr)
        libs = compile_libs(kept, abi)
    if source_fingerprint()["fingerprint"] != source["fingerprint"]:
        raise Error("the source changed during the build; build again")
    record = {**source, "abi": abi, "dir": str(kept), "libs": libs, "built_at": now()}
    save("build.json", record)
    return record


def fork_point(ref):
    """Where this checkout's branch left `ref`: the "before" of its change. The tip of `ref` would also carry the
    commits made there since, which the branch doesn't have."""
    git = ["git", "-C", str(REPO)]
    sha = run(git + ["rev-parse", "--verify", f"{ref}^{{commit}}"]).stdout.strip()
    return run(git + ["merge-base", sha, "HEAD"]).stdout.strip()


def build_base(ref, abi=None, record="base.json", mutation=None):
    """Builds where this branch left `ref` (e.g. origin/main, or a PR's base branch) in a worktree the tool owns, for
    the "before" side of a comparison. One worktree is moved between base commits; libraries are kept per commit and
    ABI. With record=None the build isn't recorded as the base, and `ref` itself is built (selftest's builds).
    `mutation` (file, old, new) replaces `old` with `new` in the worktree first: selftest breaks the code on purpose to
    see a proof fail."""
    abi = abi or target_abi()
    git = ["git", "-C", str(REPO)]
    sha = fork_point(ref) if record else run(git + ["rev-parse", "--verify", f"{ref}^{{commit}}"]).stdout.strip()
    kind = "mutant" if mutation else "base" if record else "release"
    tag = f"-{hashlib.sha256(json.dumps(mutation).encode()).hexdigest()[:8]}" if mutation else ""
    kept = STATE / "builds" / f"{kind}-{sha[:12]}{tag}-{abi}"
    if not (kept / LIBS[-1]).exists():
        tree = STATE / "base-worktree"
        if not (tree / ".git").exists():
            run(git + ["worktree", "add", "--detach", str(tree), sha])
        else:
            # Nobody edits this worktree, so forcing the checkout can't lose work (it also undoes a mutation).
            run(["git", "-C", str(tree), "checkout", "--detach", "--force", sha])
        if mutation:
            path, old, new = mutation
            text = (tree / path).read_text()
            if text.count(old) != 1:
                raise Error(f"the mutation no longer applies: `{old}` isn't in {path} exactly once; update selftest")
            (tree / path).write_text(text.replace(old, new))
        print(f"building {ref} ({sha[:10]}){' with a mutation' if mutation else ''} for {abi} in {tree} ...",
              file=sys.stderr)
        compile_libs(kept, abi, root=tree, name="base")
    built = {"base": ref + (f" with {mutation[0]} broken on purpose" if mutation else ""), "head": sha, "abi": abi,
             "dir": str(kept), "libs": {lib: sha256(kept / lib) for lib in LIBS}, "built_at": now()}
    if record:
        save(record, built)
    return built


# --- the app the libraries go into ----------------------------------------------------------------------------------

def apk_package(apk):
    out = run([str(build_tools() / "aapt2"), "dump", "badging", str(apk)], check=False).stdout
    package = re.search(r"package: name='([^']+)'.*versionName='([^']*)'", out)
    if not package:
        raise Error(f"{apk} isn't an APK aapt2 can read")
    return package.group(1), package.group(2)


def set_app(apk=None, pull=False):
    """Records the DuckDuckGo debug APK the libraries are swapped into: a file (a local build of the Android app, or
    one from its CI), or the one installed on the device. Any signature works: the tool re-signs it."""
    if pull:
        serial = use_device()
        paths = [line.split(":", 1)[1] for line in adb("shell", "pm", "path", APP_ID, check=False).split()
                 if line.startswith("package:")]
        if not paths:
            raise Error(f"{APP_ID} isn't installed on {serial}: pass the APK with `app --apk <path>`")
        if len(paths) > 1:
            raise Error(f"{APP_ID} is installed as split APKs on {serial}: pass a universal APK with `app --apk`")
        (STATE / "apps").mkdir(parents=True, exist_ok=True)
        staging = STATE / "apps" / "pulled.apk"
        adb("pull", paths[0], str(staging))
        source = f"pulled from {adb('shell', 'getprop', 'ro.product.model').strip()}"
    else:
        if not apk or not Path(apk).is_file():
            raise Error("pass the DuckDuckGo debug APK with `app --apk <path>`, or `app --pull` from a device")
        (STATE / "apps").mkdir(parents=True, exist_ok=True)
        staging = STATE / "apps" / "staging.apk"
        shutil.copyfile(apk, staging)
        source = "a file"
    package, version = apk_package(staging)
    if package != APP_ID:
        staging.unlink()
        raise Error(f"the APK is {package}, not the debug app {APP_ID}: release builds don't log netguard")
    with zipfile.ZipFile(staging) as z:
        abis = sorted({n.split("/")[1] for n in z.namelist() if n.startswith("lib/") and n.endswith("/libnetguard.so")})
    if not abis:
        staging.unlink()
        raise Error("the APK has no libnetguard.so: it must be a universal APK, not one split by ABI")
    digest = sha256(staging)
    kept = staging.rename(staging.with_name(f"{digest[:16]}.apk"))
    record = {"path": str(kept), "sha256": digest, "version": version, "abis": abis, "source": source,
              "recorded_at": now()}
    save("app.json", record)
    return record


def package_apk(app, libs):
    """The app with its libraries swapped for the build's, re-signed with the debug key. The rest of the APK is
    unchanged, so the base and branch APKs differ only in the libraries."""
    abi = libs["abi"]
    if abi not in app["abis"]:
        raise Error(f"the app has no {abi} libraries (it has {', '.join(app['abis'])})")
    swapped = {f"lib/{abi}/{lib}" for lib in LIBS}
    libs_id = hashlib.sha256("".join(libs["libs"][lib] for lib in LIBS).encode()).hexdigest()[:12]
    out = STATE / "apks" / f"{app['sha256'][:12]}-{libs_id}.apk"
    if out.exists():
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    unaligned, aligned = out.with_suffix(".unaligned"), out.with_suffix(".aligned")
    signature = re.compile(r"META-INF/([^/]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)$")
    with zipfile.ZipFile(app["path"]) as src, zipfile.ZipFile(unaligned, "w") as dst:
        for info in src.infolist():
            if info.filename not in swapped and not signature.match(info.filename):
                dst.writestr(info, src.read(info))
        for lib in LIBS:
            # Stored, not compressed: the app may load libraries straight from the APK.
            dst.write(Path(libs["dir"]) / lib, f"lib/{abi}/{lib}", compress_type=zipfile.ZIP_STORED)
    tools = build_tools()
    # 16 KB alignment for the stored libraries (-P, build-tools 35+), else 4 KB pages (-p).
    if run([str(tools / "zipalign"), "-f", "-P", "16", "4", str(unaligned), str(aligned)], check=False).returncode:
        run([str(tools / "zipalign"), "-f", "-p", "4", str(unaligned), str(aligned)])
    unaligned.unlink()
    if not KEYSTORE.exists():
        # Gradle creates this key on the first debug build; a machine that never built one has none yet.
        KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
        run(["keytool", "-genkeypair", "-keystore", str(KEYSTORE), "-storepass", "android", "-alias",
             "androiddebugkey", "-keypass", "android", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
             "-dname", "CN=Android Debug,O=Android,C=US"], env=java_env())
    run([str(tools / "apksigner"), "sign", "--ks", str(KEYSTORE), "--ks-pass", "pass:android", "--key-pass",
         "pass:android", "--ks-key-alias", "androiddebugkey", "--out", str(out), str(aligned)], env=java_env())
    aligned.unlink()
    return out


# --- installing -----------------------------------------------------------------------------------------------------

def installed_sha256():
    path = adb("shell", "pm", "path", APP_ID, check=False).strip()
    if not path.startswith("package:"):
        return None
    out = adb("shell", "sha256sum", path.split(":", 1)[1].splitlines()[0], check=False).split()
    return out[0] if out else None


def _original_record():
    return f"original-{os.environ['ANDROID_SERIAL']}.json"


def remember_original():
    """Before the tool first installs on a device, keeps the app that was there (or that there was none), so `restore`
    can put it back. Not on the skill's own emulator, which nobody else uses."""
    if os.environ["ANDROID_SERIAL"] == emulator_serial() or load(_original_record()):
        return
    paths = [line.split(":", 1)[1] for line in adb("shell", "pm", "path", APP_ID, check=False).split()
             if line.startswith("package:")]
    record = {"installed": bool(paths), "apks": []}
    for i, path in enumerate(paths):
        kept = STATE / "originals" / os.environ["ANDROID_SERIAL"] / f"{i}.apk"
        kept.parent.mkdir(parents=True, exist_ok=True)
        adb("pull", path, str(kept))
        record["apks"].append(str(kept))
    save(_original_record(), record)


def install(base=False, replace=False, libs=None):
    """Installs the app with the build's libraries (the base build's with `base`, or a build_base record passed as
    `libs`). Refuses a stale build."""
    serial = use_device()
    app = load("app.json")
    if not app:
        raise Error("no app recorded: run `verify-netguard app --apk <DuckDuckGo debug APK>`, or `app --pull`")
    if libs is None and base:
        libs = load("base.json")
        if not libs:
            raise Error("no base build: run `verify-netguard build --base <ref>` first")
    elif libs is None:
        libs = load("build.json")
        if not libs:
            raise Error("no recorded build: run `verify-netguard build` first")
        if libs["fingerprint"] != source_fingerprint()["fingerprint"]:
            raise Error("stale build: the source changed since `verify-netguard build`; build again")
    abis = adb("shell", "getprop", "ro.product.cpu.abilist").strip().split(",")
    if libs["abi"] not in abis:
        raise Error(f"the build is for {libs['abi']}, the device runs {', '.join(abis)}: build again with this device up")
    apk = package_apk(app, libs)
    remember_original()
    result = run(["adb", "install", "--no-incremental", "-r", "-d", str(apk)], check=False)
    if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in result.stdout + result.stderr:
        # The installed app has another signature. Replacing it clears its data, so only on request off the emulator.
        if serial != emulator_serial() and not replace:
            raise Error(f"the app on {serial} is signed with another key: installing means uninstalling it, which clears "
                        "its data. Pass --replace to do that (`restore` reinstalls the original afterwards)")
        adb("uninstall", APP_ID)
        result = run(["adb", "install", "--no-incremental", "-r", "-d", str(apk)], check=False)
    if result.returncode != 0:
        raise Error(f"adb install failed: {(result.stdout + result.stderr).strip()}")
    digest = sha256(apk)
    if installed_sha256() != digest:
        raise Error("the installed APK doesn't match the one just installed")
    record = {**libs, "sha256": digest, "apk": str(apk), "app": {k: app[k] for k in ("sha256", "version", "source")},
              "serial": serial, "installed_at": now()}
    save(installed_record(), record)
    return apk, record


def installed_record():
    """One record per device, so moving between the emulator and a phone doesn't force a reinstall."""
    return f"installed-{os.environ['ANDROID_SERIAL']}.json"


def reinstall():
    """Installs the recorded APK again over the app, keeping its data (same key): after a snapshot load, which brings
    back the app the snapshot was saved with."""
    record = load(installed_record())
    if not record or not Path(record.get("apk", "")).exists():
        raise Error("nothing installed by verify-netguard on this device, or its APK is gone: run `verify-netguard install`")
    result = run(["adb", "install", "--no-incremental", "-r", "-d", record["apk"]], check=False)
    if result.returncode != 0:
        raise Error(f"reinstalling after the snapshot failed: {(result.stdout + result.stderr).strip()}")
    if installed_sha256() != record["sha256"]:
        raise Error("the installed APK doesn't match the one just installed")


def check_installed():
    """The app on the device must carry the recorded build of the current source, or the base build installed
    explicitly (the evidence says which)."""
    record = load(installed_record())
    if not record:
        raise Error("nothing installed by verify-netguard on this device: run `verify-netguard install`")
    if installed_sha256() != record["sha256"]:
        raise Error("the app on the device isn't the APK verify-netguard installed; install again")
    if not record.get("base") and record["fingerprint"] != source_fingerprint()["fingerprint"]:
        raise Error("stale build: the source changed since it was built; build and install again")
    return record


def restore():
    """Puts the device back as it was before the tool: the original app (or none), no probe or UI driver, the device's
    settings."""
    serial = use_device()
    done = []
    problem = restore_device_settings()
    for package in (PROBE_ID, UI_DRIVER_ID):
        if adb("shell", "pm", "path", package, check=False).strip():
            adb("uninstall", package)
            done.append(f"uninstalled {package}")
    original = load(_original_record())
    if original:
        if not original["installed"]:
            adb("uninstall", APP_ID, check=False)
            done.append(f"uninstalled {APP_ID}, which wasn't installed before")
        else:
            cmd = ["install-multiple"] if len(original["apks"]) > 1 else ["install"]
            result = run(["adb", *cmd, "--no-incremental", "-r", "-d", *original["apks"]], check=False)
            if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in result.stdout + result.stderr:
                adb("uninstall", APP_ID)
                result = run(["adb", *cmd, "--no-incremental", "-r", "-d", *original["apks"]], check=False)
                done.append(f"{APP_ID} had another signature: uninstalled it, so its data is gone")
            if result.returncode != 0:
                raise Error(f"couldn't reinstall the original app: {(result.stdout + result.stderr).strip()}")
            done.append(f"reinstalled the original {APP_ID}")
        (STATE / _original_record()).unlink()
    (STATE / installed_record()).unlink(missing_ok=True)
    if problem:
        raise Error(problem)
    return {"device": serial, "restored": done or ["nothing to restore"]}



# --- device ---------------------------------------------------------------------------------------------------------

def emulator_serial():
    return f"emulator-{EMULATOR_PORT}"


def device_online(serial):
    require("adb", "install the SDK's platform-tools")
    return run(["adb", "-s", serial, "get-state"], check=False).stdout.strip() == "device"


def own_emulator_online():
    """Whether this checkout's emulator runs. Two checkouts can hash to the same port: another's emulator there is an
    error, never used."""
    serial = emulator_serial()
    if not device_online(serial):
        return False
    avd = run(["adb", "-s", serial, "emu", "avd", "name"], check=False).stdout.splitlines()[:1]
    if [a.strip() for a in avd] != [AVD]:
        raise Error(f"{serial} runs {avd[0].strip() if avd else 'another emulator'}, not this checkout's {AVD}: stop it, "
                    "or set ANDROID_SERIAL")
    return True


def use_device():
    """An explicit ANDROID_SERIAL wins (e.g. a real device); otherwise the skill's own emulator, never whatever is attached."""
    serial = os.environ.get("ANDROID_SERIAL") or emulator_serial()
    if not (device_online(serial) if os.environ.get("ANDROID_SERIAL") else own_emulator_online()):
        raise Error(f"device {serial} isn't running: `verify-netguard device start`, or set ANDROID_SERIAL")
    os.environ["ANDROID_SERIAL"] = serial
    return serial


def host_abi():
    """An emulator only runs at usable speed on the host's own architecture."""
    return "arm64-v8a" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"


def rootable_image():
    abi = host_abi()
    images = sorted(sdk().glob(f"system-images/android-*/google_apis/{abi}/system.img"),
                    key=lambda p: int(re.sub(r"\D", "", p.parts[-4]) or 0))
    if not images:
        raise Error("no rootable system image for this machine; install one, e.g. "
                    f"`sdkmanager \"system-images;android-34;google_apis;{abi}\"`")
    api, tag, abi = images[-1].parts[-4:-1]
    return f"system-images;{api};{tag};{abi}"


def start_emulator(window=False):
    """Headless, unless `window`: a person signs in to the app on it (see `snapshot save`)."""
    serial = emulator_serial()
    if own_emulator_online():
        if window:
            raise Error(f"{serial} is already running; `verify-netguard device stop` first to start it with a window")
        return serial
    emulator = sdk() / "emulator/emulator"
    if not emulator.exists():
        raise Error("the SDK has no emulator: `sdkmanager emulator`")
    avds = run([str(emulator), "-list-avds"]).stdout.split()
    if AVD not in avds:
        subprocess.run([str(avdmanager()), "create", "avd", "-n", AVD, "-k", rootable_image(), "-d", "pixel_6"],
                       input="no\n", text=True, check=True, capture_output=True, env=java_env())
    STATE.mkdir(parents=True, exist_ok=True)
    with open(STATE / "emulator.log", "w") as log:
        subprocess.Popen([str(emulator), "-avd", AVD, "-port", str(EMULATOR_PORT),
                          *([] if window else ["-no-window"]), "-no-audio", "-no-snapshot-save"],
                         stdout=log, stderr=log, start_new_session=True)
    deadline = time.time() + 300
    while time.time() < deadline:
        if device_online(serial) and run(["adb", "-s", serial, "shell", "getprop", "sys.boot_completed"],
                                         check=False).stdout.strip() == "1":
            break
        time.sleep(3)
    else:
        raise Error(f"{AVD} didn't boot in 5 minutes; see {STATE / 'emulator.log'}")
    run(["adb", "-s", serial, "root"])
    run(["adb", "-s", serial, "wait-for-device"])
    return serial


# --- snapshots: device states a person set up once, e.g. an account signed in to the app -------------------------------

def _require_own_emulator(what):
    if os.environ.get("ANDROID_SERIAL", emulator_serial()) != emulator_serial():
        raise Error(f"{what} needs this checkout's emulator (`verify-netguard device start`), not {os.environ['ANDROID_SERIAL']}")


def snapshots():
    out = run(["adb", "-s", emulator_serial(), "emu", "avd", "snapshot", "list"], check=False).stdout
    return [line.split()[1] for line in out.splitlines() if re.match(r"\s*--\s+\S", line)]


def save_snapshot(name):
    """Saves the whole emulator (app data, keystore, settings) as `name`. The app's account tokens are encrypted with a
    keystore key, so a copy of its data folder alone wouldn't survive; a snapshot does."""
    _require_own_emulator("a snapshot")
    if "OK" not in run(["adb", "-s", emulator_serial(), "emu", "avd", "snapshot", "save", name]).stdout:
        raise Error(f"the emulator didn't save snapshot {name}")


def load_snapshot(name):
    """Brings the emulator back to `name`, then sets its clock to now: a snapshot keeps the clock it was saved with, and
    an old clock breaks TLS and the app's tokens. Automatic time goes off first: on the next network change (a VPN
    starting) it would take the time from the emulated modem, which still has the snapshot's, and logs written after a
    mark would be timestamped before it."""
    _require_own_emulator(f"snapshot {name}")
    if name not in snapshots():
        raise Error(f"no snapshot {name} on this checkout's emulator; see the proof's docstring for how to make it")
    if "OK" not in run(["adb", "-s", emulator_serial(), "emu", "avd", "snapshot", "load", name]).stdout:
        # An emulator or system image update can leave old snapshots unloadable.
        raise Error(f"the emulator couldn't load snapshot {name}: set the state up again and `verify-netguard snapshot "
                    f"save {name}` (for netp-signed-in, features/wireguard-netp.md)")
    run(["adb", "-s", emulator_serial(), "wait-for-device"])
    run(["adb", "-s", emulator_serial(), "shell", "settings", "put", "global", "auto_time", "0"])
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%m%d%H%M%Y.%S")
    run(["adb", "-s", emulator_serial(), "shell", "date", "-u", stamp])


def avdmanager():
    tools = list(sdk().glob("cmdline-tools/*/bin/avdmanager"))
    if not tools:
        raise Error("the SDK has no cmdline-tools: `sdkmanager \"cmdline-tools;latest\"`")

    def version(path):   # "latest" wins, then the highest numeric version (so 11.0 beats 9.0)
        name = path.parts[-3]
        return name == "latest", [int(n) for n in re.findall(r"\d+", name)]

    return max(tools, key=version)


def stop_emulator():
    serial = emulator_serial()
    if own_emulator_online():
        run(["adb", "-s", serial, "emu", "kill"])
    return serial


# --- device settings a run changes ----------------------------------------------------------------------------------

def _rmem_record():
    return STATE / f"rmem-max-{os.environ['ANDROID_SERIAL']}.json"


def set_rmem_max(value):
    """Remembers the device's own value before the first change, so a run killed mid-way is undone by the next one."""
    original = adb("shell", "cat", RMEM_MAX).strip()
    adb("shell", f"echo {value} > {RMEM_MAX}", check=False)
    if adb("shell", "cat", RMEM_MAX).strip() != str(value):
        raise Error(f"couldn't set rmem_max to {value}: the device needs root (`adb root`)")
    if not _rmem_record().exists():
        save(_rmem_record().name, {"original": original})


def restore_device_settings():
    """Returns a problem to report, or None. The record goes either way, so one failed restore can't block every
    later run on the device."""
    if not _rmem_record().exists():
        return None
    original = json.loads(_rmem_record().read_text())["original"]
    _rmem_record().unlink()
    adb("shell", f"echo {original} > {RMEM_MAX}", check=False)
    if adb("shell", "cat", RMEM_MAX, check=False).strip() != original:
        return f"couldn't restore rmem_max to {original}; reboot the device to reset it"
    return None


# --- cleanup --------------------------------------------------------------------------------------------------------

def _size(path):
    if path.is_file():
        return path.stat().st_size
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())


def _remove(path):
    freed = _size(path)
    shutil.rmtree(path) if path.is_dir() else path.unlink()
    return freed


def cleanup(everything=False, evidence_days=30):
    """Removes what the tool created. By default: builds, apps and APKs no record points at, and evidence older than
    evidence_days. With everything: the base worktree, this checkout's emulator and all state too, but not a device's
    original app while `restore` still needs it."""
    removed, freed = [], 0
    if everything:
        if list(STATE.glob("original-*.json")):
            raise Error("a device still has the tool's app installed: run `verify-netguard restore` on it first")
        tree = STATE / "base-worktree"
        if tree.exists():
            freed += _size(tree)
            run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(tree)], check=False)
            run(["git", "-C", str(REPO), "worktree", "prune"])
            removed.append("base worktree")
        if own_emulator_online():
            stop_emulator()
            time.sleep(3)
        if AVD in run([str(sdk() / "emulator/emulator"), "-list-avds"], check=False).stdout.split():
            run([str(avdmanager()), "delete", "avd", "-n", AVD], env=java_env())
            removed.append(f"emulator {AVD}")
        if STATE.exists():
            freed += _remove(STATE)
            removed.append(str(STATE))
        return {"removed": removed, "freed_mb": freed // (1 << 20)}

    records = [r for r in [load("build.json"), load("base.json"), load("app.json"),
                           *(load(f.name) for f in STATE.glob("installed-*.json"))] if r]
    keep_builds = {Path(r["dir"]).name for r in records if "dir" in r}
    keep_apps = {Path(load("app.json")["path"]).name} if load("app.json") else set()
    installed = {r["sha256"] for r in records if "serial" in r}
    head = run(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip()[:12]
    for build_dir in sorted((STATE / "builds").glob("*")):
        # selftest --with-broken-build reuses the release build, which never changes, and this commit's mutants.
        if build_dir.name not in keep_builds and not build_dir.name.startswith(("release-", f"mutant-{head}")):
            freed += _remove(build_dir)
            removed.append(f"builds/{build_dir.name}")
    for apk in sorted((STATE / "apps").glob("*.apk")):
        if apk.name not in keep_apps:
            freed += _remove(apk)
            removed.append(f"apps/{apk.name}")
    for apk in sorted((STATE / "apks").glob("*.apk")):
        if sha256(apk) not in installed:
            freed += _remove(apk)
            removed.append(f"apks/{apk.name}")
    cutoff = time.time() - evidence_days * 86400
    for run_dir in sorted((STATE / "evidence").glob("*")):
        if run_dir.stat().st_mtime < cutoff:
            freed += _remove(run_dir)
            removed.append(f"evidence/{run_dir.name}")
    return {"removed": removed, "freed_mb": freed // (1 << 20)}

