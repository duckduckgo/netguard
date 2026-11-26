#!/bin/sh
# Measures how much App Tracking Protection slows down an app's downloads and uploads. Builds speedprobe and its
# app, then on the same device and network alternates runs through AppTP (as the probe app, which AppTP covers) and
# around it (as the DuckDuckGo app, which AppTP never covers), and compares the throughput. Also reports how busy
# AppTP's VPN process was during each run. See README.md.
#
# Usage: tools/speedprobe/run.sh
#
# Environment: ROUNDS (3), STREAMS (1), DIRECTIONS ("down up"), DOWN_BYTES (50000000), UP_BYTES (20000000),
# HOST (speed.cloudflare.com), URL_PATH (a file on HOST to download instead of Cloudflare's /__down, see speedprobe.c),
# APP (com.duckduckgo.mobile.android.debug).
#
# Needs adb, an Android SDK with build-tools and a platform, an NDK, and a debug build of the DuckDuckGo app with
# AppTP on, so that the probe can run as that app with run-as.
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
BUILD="$DIR/build"
PKG=dev.netguard.speedprobe
APP=${APP:-com.duckduckgo.mobile.android.debug}
ROUNDS=${ROUNDS:-3}
STREAMS=${STREAMS:-1}
DOWN_BYTES=${DOWN_BYTES:-50000000}
UP_BYTES=${UP_BYTES:-20000000}
HOST=${HOST:-speed.cloudflare.com}
URL_PATH=${URL_PATH:-}
DIRECTIONS=${DIRECTIONS:-down up}
# AppTP is slower when its median is below this percentage of the direct one
THRESHOLD=80
mkdir -p "$BUILD"

fail() {
    echo "$1" >&2
    exit 1
}

# Tools
SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}
[ -d "$SDK" ] || fail "Android SDK not found, set ANDROID_HOME"
NDK=${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)}
[ -d "$NDK" ] || fail "NDK not found, set ANDROID_NDK_HOME"
BUILD_TOOLS=$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)
[ -d "$BUILD_TOOLS" ] || fail "No build-tools in $SDK"
PLATFORM=$(ls -d "$SDK"/platforms/android-* 2>/dev/null | sort -V | tail -1)
[ -d "$PLATFORM" ] || fail "No platform in $SDK"
command -v adb >/dev/null || fail "adb not found"
[ "$(adb get-state 2>/dev/null)" = "device" ] || fail "No device connected (or several: pick one with ANDROID_SERIAL)"

# AppTP must be running, in a debug build
VPN_PID=$(adb shell pidof $APP:vpn | tr -d '\r')
[ -n "$VPN_PID" ] || fail "$APP:vpn isn't running: install a debug build of the app and turn AppTP on"
adb shell "run-as $APP true" 2>/dev/null || fail "Can't run-as $APP: it must be a debug build"
# CPU time of the VPN process, in clock ticks (100 a second on Android)
vpn_ticks() {
    adb shell "run-as $APP cat /proc/$VPN_PID/stat" | awk '{print $14 + $15}'
}
[ -n "$(vpn_ticks)" ] || fail "Can't read the CPU time of $APP:vpn (pid $VPN_PID)"

# Probe binary, for the device's ABI
case $(adb shell getprop ro.product.cpu.abi | tr -d '\r') in
    arm64-v8a) TARGET=aarch64-linux-android23 ;;
    armeabi-v7a) TARGET=armv7a-linux-androideabi23 ;;
    x86_64) TARGET=x86_64-linux-android23 ;;
    x86) TARGET=i686-linux-android23 ;;
    *) fail "Unsupported device ABI" ;;
esac
CLANG=$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/$TARGET-clang | head -1)
"$CLANG" -Wall -O2 -o "$BUILD/speedprobe" "$DIR/speedprobe.c"

# Probe app: no code, debuggable so that run-as can run the probe as the app, signed with a throwaway key
KEYSTORE="$BUILD/speedprobe.keystore"
[ -f "$KEYSTORE" ] || keytool -genkeypair -keystore "$KEYSTORE" -storepass speedprobe -keypass speedprobe \
    -alias speedprobe -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=speedprobe" >/dev/null 2>&1
"$BUILD_TOOLS/aapt2" link -o "$BUILD/unsigned.apk" --manifest "$DIR/AndroidManifest.xml" -I "$PLATFORM/android.jar"
"$BUILD_TOOLS/zipalign" -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:speedprobe --out "$BUILD/speedprobe.apk" "$BUILD/aligned.apk"

adb install -r "$BUILD/speedprobe.apk" >/dev/null || {
    adb uninstall $PKG >/dev/null 2>&1 || true
    adb install "$BUILD/speedprobe.apk" >/dev/null
}
# A new app that was never opened starts in the most restricted standby bucket, which blocks its network, and from
# Android 15 an app with nothing in the foreground has no network unless it's on the battery optimisation allowlist
adb shell am set-standby-bucket $PKG active
adb shell dumpsys deviceidle whitelist +$PKG >/dev/null

# The probe app must go through AppTP's VPN and the DuckDuckGo app around it
uid_of() {
    adb shell pm list packages -U "$1" | tr -d '\r' | grep "^package:$1 " | sed 's/.*uid://'
}
VPN_UIDS=$(adb shell dumpsys connectivity | grep "VPN CONNECTED" | grep -oE "Uids: <[^>]*>" | head -1)
covered() {
    echo "$VPN_UIDS" | grep -oE "[0-9]+-[0-9]+" | awk -F- -v uid="$1" '$1 <= uid && uid <= $2 {found = 1} END {exit !found}'
}
PROBE_UID=$(uid_of $PKG)
APP_UID=$(uid_of $APP)
covered "$PROBE_UID" || fail "AppTP's VPN doesn't cover the probe app (uid $PROBE_UID): protect it in App Tracking Protection"
covered "$APP_UID" && fail "AppTP's VPN covers $APP (uid $APP_UID), so it can't measure the speed without AppTP"

adb push "$BUILD/speedprobe" /data/local/tmp/speedprobe >/dev/null
for pkg in $PKG $APP; do
    adb shell "run-as $pkg sh -c 'cat /data/local/tmp/speedprobe > speedprobe && chmod 700 speedprobe'"
done
trap 'adb shell "run-as $APP rm -f speedprobe" 2>/dev/null; adb shell rm -f /data/local/tmp/speedprobe 2>/dev/null
    adb shell dumpsys deviceidle whitelist -$PKG >/dev/null 2>&1' EXIT

echo "Device: $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r'), $(adb shell nproc | tr -d '\r') cores online"
LINK=$(adb shell dumpsys wifi 2>/dev/null | grep -oE "Link speed: [0-9]+Mbps" | head -1 || true)
echo "Wi-Fi: ${LINK:-not connected or not reported}"
echo "Server: $HOST$URL_PATH, $DIRECTIONS, $STREAMS stream(s), $DOWN_BYTES bytes down, $UP_BYTES bytes up, $ROUNDS rounds"
echo

RESULTS="$BUILD/results"
: >"$RESULTS"
# Runs one transfer as the given path (direct or apptp) and records its Mbit/s and the VPN process's CPU use
measure() {
    path=$1 dir=$2 bytes=$3
    if [ "$path" = apptp ]; then pkg=$PKG; else pkg=$APP; fi
    before=$(vpn_ticks)
    out=$(adb shell "run-as $pkg ./speedprobe $dir $bytes $STREAMS $HOST $URL_PATH" | tr -d '\r')
    after=$(vpn_ticks)
    seconds=$(echo "$out" | sed -nE 's/.* in ([0-9.]+) s.*/\1/p')
    mbits=$(echo "$out" | sed -nE 's/.*: ([0-9.]+) Mbit\/s.*/\1/p')
    [ -n "$mbits" ] || fail "$path $dir: $out"
    cpu=$(awk -v t=$((after - before)) -v s="$seconds" 'BEGIN {printf "%.0f", t / s}')
    printf "%-6s %-4s %8s Mbit/s  AppTP CPU %4s%%\n" "$path" "$dir" "$mbits" "$cpu"
    echo "$path $dir $mbits $cpu" >>"$RESULTS"
}

for round in $(seq "$ROUNDS"); do
    # Alternate which path goes first, so that a network getting faster or slower doesn't favour one
    if [ $((round % 2)) = 1 ]; then order="direct apptp"; else order="apptp direct"; fi
    for dir in $DIRECTIONS; do
        if [ "$dir" = down ]; then bytes=$DOWN_BYTES; else bytes=$UP_BYTES; fi
        for path in $order; do measure $path $dir "$bytes"; done
    done
done
[ "$(adb shell pidof $APP:vpn | tr -d '\r')" = "$VPN_PID" ] || fail "$APP:vpn restarted during the run"

median() {
    awk -v p="$1" -v d="$2" -v f="$3" '$1 == p && $2 == d {print $f}' "$RESULTS" | sort -n |
        awk '{v[NR] = $1} END {print (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2}'
}
echo
echo "Medians (100% CPU is one core fully busy):"
SLOWER=
for dir in $DIRECTIONS; do
    direct=$(median direct $dir 3)
    apptp=$(median apptp $dir 3)
    percent=$(awk -v a="$apptp" -v d="$direct" 'BEGIN {printf "%.0f", (d > 0 ? 100 * a / d : 0)}')
    printf "%-4s direct %8s Mbit/s, through AppTP %8s Mbit/s (%s%%), AppTP CPU %s%% through it, %s%% direct\n" \
        $dir "$direct" "$apptp" "$percent" "$(median apptp $dir 4)" "$(median direct $dir 4)"
    [ "$percent" -ge $THRESHOLD ] || SLOWER="$SLOWER $dir"
done
echo
if [ -n "$SLOWER" ]; then
    echo "SLOWER: AppTP is below $THRESHOLD% of the direct speed for:$SLOWER"
    exit 1
fi
echo "SAME: AppTP is within $THRESHOLD% of the direct speed"
