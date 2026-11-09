#!/bin/sh
# Checks that AppTP doesn't leak a socket for each connection it fails to open. Builds connprobe and its app,
# installs them, and counts the sockets open in AppTP's VPN process before and after connprobe makes connections
# that netguard can't open. See README.md.
#
# Usage: tools/connprobe/run.sh [address] [port] [count]   (defaults: 2001:4860:4860::8888 443 50)
#
# Needs adb, an Android SDK with build-tools and a platform, an NDK, and a debug build of the DuckDuckGo app
# (APP, default com.duckduckgo.mobile.android.debug) so that its sockets can be counted with run-as.
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
BUILD="$DIR/build"
PKG=dev.netguard.connprobe
APP=${APP:-com.duckduckgo.mobile.android.debug}
ADDRESS=${1:-2001:4860:4860::8888}
PORT=${2:-443}
COUNT=${3:-50}
mkdir -p "$BUILD"

fail() {
    echo "$1" >&2
    exit 1
}

# Fewer connections can't tell a leak from AppTP's own traffic
[ "$COUNT" -ge 10 ] 2>/dev/null || fail "count must be at least 10"

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
# The VPN process always has sockets open, so finding none means its fds couldn't be listed
sockets() {
    count=$(adb shell "run-as $APP ls -l /proc/$VPN_PID/fd" 2>/dev/null | grep -c "socket:") || true
    [ "${count:-0}" -gt 0 ] || fail "Can't count the sockets of $APP:vpn (pid $VPN_PID)"
    echo "$count"
}
adb shell "run-as $APP true" 2>/dev/null || fail "Can't run-as $APP: it must be a debug build"

# Probe binary, for the device's ABI
case $(adb shell getprop ro.product.cpu.abi | tr -d '\r') in
    arm64-v8a) TARGET=aarch64-linux-android23 ;;
    armeabi-v7a) TARGET=armv7a-linux-androideabi23 ;;
    x86_64) TARGET=x86_64-linux-android23 ;;
    x86) TARGET=i686-linux-android23 ;;
    *) fail "Unsupported device ABI" ;;
esac
CLANG=$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/$TARGET-clang | head -1)
"$CLANG" -Wall -O2 -o "$BUILD/connprobe" "$DIR/connprobe.c"

# Probe app: no code, debuggable so that run-as can run the probe as the app, signed with a throwaway key
KEYSTORE="$BUILD/connprobe.keystore"
[ -f "$KEYSTORE" ] || keytool -genkeypair -keystore "$KEYSTORE" -storepass connprobe -keypass connprobe \
    -alias connprobe -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=connprobe" >/dev/null 2>&1
"$BUILD_TOOLS/aapt2" link -o "$BUILD/unsigned.apk" --manifest "$DIR/AndroidManifest.xml" -I "$PLATFORM/android.jar"
"$BUILD_TOOLS/zipalign" -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:connprobe --out "$BUILD/connprobe.apk" "$BUILD/aligned.apk"

adb install -r "$BUILD/connprobe.apk" >/dev/null || {
    adb uninstall $PKG >/dev/null 2>&1 || true
    adb install "$BUILD/connprobe.apk" >/dev/null
}
# A new app that was never opened starts in the most restricted standby bucket, which blocks its network
adb shell am set-standby-bucket $PKG active

# The app must be covered by AppTP's VPN
APP_UID=$(adb shell dumpsys package $PKG | grep -m1 -oE "userId=[0-9]+" | cut -d= -f2)
VPN_UIDS=$(adb shell dumpsys connectivity | grep "VPN CONNECTED" | grep -oE "Uids: <[^>]*>" | head -1)
echo "$VPN_UIDS" | grep -oE "[0-9]+-[0-9]+" | awk -F- -v uid="$APP_UID" '$1 <= uid && uid <= $2 {found = 1} END {exit !found}' ||
    fail "AppTP's VPN doesn't cover the probe app (uid $APP_UID): protect it in App Tracking Protection"

adb push "$BUILD/connprobe" /data/local/tmp/connprobe >/dev/null
adb shell "run-as $PKG sh -c 'cat /data/local/tmp/connprobe > connprobe && chmod 700 connprobe'"

BEFORE=$(sockets) || exit 1
RESULT=$(adb shell "run-as $PKG ./connprobe $ADDRESS $PORT $COUNT" | tr -d '\r')
echo "$RESULT"
sleep 3
AFTER=$(sockets) || exit 1
[ "$(adb shell pidof $APP:vpn | tr -d '\r')" = "$VPN_PID" ] || fail "$APP:vpn restarted during the run, so its sockets can't be compared"
echo "Sockets open in AppTP ($APP:vpn, pid $VPN_PID): $BEFORE before, $AFTER after"
echo

if ! echo "$RESULT" | grep -q " 0 connected"; then
    echo "INCONCLUSIVE: some connections succeeded, so netguard could open them. Use an address the network can't" \
        "reach, eg. an IPv6 address on a network without IPv6."
    exit 2
elif ! echo "$RESULT" | grep -q " 0 failed"; then
    # netguard doesn't answer a connection it can't open, so the ones it saw time out. A failed one never reached it.
    echo "INCONCLUSIVE: some connections failed on the device before reaching netguard, eg. because the VPN doesn't" \
        "route that address, so netguard never tried to open them."
    exit 2
elif [ $((AFTER - BEFORE)) -ge $((COUNT / 2)) ]; then
    echo "LEAK: $((AFTER - BEFORE)) more sockets open after $COUNT connections netguard couldn't open"
    exit 1
else
    echo "OK: no sockets leaked"
fi
