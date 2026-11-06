#!/bin/sh
# Builds dnsprobe and its app, installs them on the connected device and runs the probe through App Tracking
# Protection. See README.md.
#
# Usage: tools/dnsprobe/run.sh [server ip] [name]   (defaults: 8.8.8.8 example.com)
#
# Needs adb, an Android SDK with build-tools and a platform, and an NDK. The SDK is looked up in ANDROID_HOME,
# ANDROID_SDK_ROOT or ~/Library/Android/sdk, and the NDK in ANDROID_NDK_HOME or the SDK's newest ndk/ folder.
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
BUILD="$DIR/build"
PKG=dev.netguard.dnsprobe
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

# Probe binary, for the device's ABI
case $(adb shell getprop ro.product.cpu.abi | tr -d '\r') in
    arm64-v8a) TARGET=aarch64-linux-android23 ;;
    armeabi-v7a) TARGET=armv7a-linux-androideabi23 ;;
    x86_64) TARGET=x86_64-linux-android23 ;;
    x86) TARGET=i686-linux-android23 ;;
    *) fail "Unsupported device ABI" ;;
esac
CLANG=$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/$TARGET-clang | head -1)
"$CLANG" -Wall -O2 -o "$BUILD/dnsprobe" "$DIR/dnsprobe.c"

# Probe app: no code, debuggable so that run-as can run the probe as the app, signed with a throwaway key
KEYSTORE="$BUILD/dnsprobe.keystore"
[ -f "$KEYSTORE" ] || keytool -genkeypair -keystore "$KEYSTORE" -storepass dnsprobe -keypass dnsprobe -alias dnsprobe \
    -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=dnsprobe" >/dev/null 2>&1
"$BUILD_TOOLS/aapt2" link -o "$BUILD/unsigned.apk" --manifest "$DIR/AndroidManifest.xml" -I "$PLATFORM/android.jar"
"$BUILD_TOOLS/zipalign" -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:dnsprobe --out "$BUILD/dnsprobe.apk" "$BUILD/aligned.apk"

adb install -r "$BUILD/dnsprobe.apk" >/dev/null || {
    adb uninstall $PKG >/dev/null 2>&1 || true
    adb install "$BUILD/dnsprobe.apk" >/dev/null
}
# A new app that was never opened starts in the most restricted standby bucket, which blocks its network
adb shell am set-standby-bucket $PKG active

# The app must be covered by AppTP's VPN
APP_UID=$(adb shell dumpsys package $PKG | grep -m1 -oE "userId=[0-9]+" | cut -d= -f2)
VPN_UIDS=$(adb shell dumpsys connectivity | grep "VPN CONNECTED" | grep -oE "Uids: <[^>]*>" | head -1)
if [ -z "$VPN_UIDS" ]; then
    echo "== No VPN running: the probe runs without App Tracking Protection"
elif echo "$VPN_UIDS" | grep -oE "[0-9]+-[0-9]+" | awk -F- -v uid="$APP_UID" '$1 <= uid && uid <= $2 {found = 1} END {exit !found}'; then
    echo "== VPN running, and it covers the probe app (uid $APP_UID)"
else
    fail "== VPN running, but it doesn't cover the probe app (uid $APP_UID): protect it in App Tracking Protection"
fi
echo

adb push "$BUILD/dnsprobe" /data/local/tmp/dnsprobe >/dev/null
adb shell "run-as $PKG sh -c 'cat /data/local/tmp/dnsprobe > dnsprobe && chmod 700 dnsprobe'"
adb shell "run-as $PKG ./dnsprobe $*"
