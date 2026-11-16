"""App steps shared by proofs: each handles an app quirk once. Add one when a second proof needs it."""
import time

from .core import APP_ID, Error


def fresh_start(android):
    """Clears the app's data: no onboarding done, AppTP off."""
    android.shell("pm", "clear", APP_ID)


def open_settings(android):
    """From the browser, the app's Settings screen."""
    # The browser opens with the omnibar focused and the keyboard up. Depending on the omnibar variant the menu button
    # is the browser toolbar's or the native input widget's.
    android.hide_keyboard()
    menu = r"id=/:id\/(browserMenuImageView|inputModeWidgetNavMenu)$/"
    # The app may first ask to be the default browser, e.g. after a snapshot load moves the clock forward.
    if android.wait_for(menu, "id=defaultBrowserBottomSheetDialogGhostButton", timeout=30) != menu:
        android.tap("id=defaultBrowserBottomSheetDialogGhostButton")
    android.tap(menu, wait=30)
    android.tap("text=/^Settings$/", first=True)


def enable_apptp(android):
    """Turns AppTP on through onboarding (wipes app data), with verbose AppTP and netguard logs."""
    android.shell("pm", "clear", APP_ID)
    android.launch()
    # 16 KB page-size emulators warn that the app's native libraries aren't 16 KB aligned.
    returning = r"id=/:id\/secondaryCta$/,text=been here before"
    if android.wait_for(returning, "text=16 KB compatible", timeout=30) == "text=16 KB compatible":
        android.tap("text=/^OK$/")
    # The returning user's path, not the debug build's Skip Onboarding button, which is sometimes missing.
    android.tap(returning, wait=30)
    android.tap(r"id=/:id\/primaryCta$/,text=Start Browsing", wait=30)
    open_settings(android)
    enable_apptp_from_settings(android)


def enable_apptp_from_settings(android):
    """From Settings, turns AppTP on through its onboarding, keeping the app's data (and NetP, if it's on)."""
    android.scroll_to("text=/^App Tracking Protection$/")
    android.tap("text=/^App Tracking Protection$/")
    # The onboarding pages share one call-to-action button: Continue, Continue, then Enable.
    for label in ("Continue", "Continue", "Enable App Tracking Protection"):
        android.tap(f"id=onboarding_next_cta,text=/^{label}$/")
        time.sleep(1)  # the pager animates: don't tap the next page's button before it's the one on screen
    # Android's VPN permission dialog, shown only the first time.
    if android.wait_for("text=/^OK$/", "text=Good news! App Tracking Protection is now enabled", timeout=30) == "text=/^OK$/":
        android.tap("text=/^OK$/")
    if not android.wait_for("text=Good news! App Tracking Protection is now enabled", timeout=30):
        raise Error("AppTP's onboarding didn't end on its enabled screen; see ui.log")
    android.tap("text=/^Got it!$/")
    android.broadcast("logging", turn="on")
    time.sleep(3)  # the broadcast restarts the VPN: let the old tunnel go down first
    _wait_for_tunnel(android, "AppTP's tunnel didn't come up")


def enable_netp(android):
    """Turns NetP on from its screen (Settings > VPN), ending back on Settings. Needs a signed-in subscription: a proof
    that calls it sets SNAPSHOT = "netp-signed-in"."""
    android.launch()
    open_settings(android)
    if not android.wait_for("text=/^VPN$/", timeout=10):
        raise Error("Settings has no VPN entry: the app isn't signed in to a subscription with the VPN. Sign in again "
                    "and save the snapshot (features/wireguard-netp.md)")
    android.tap("text=/^VPN$/")
    android.tap("id=trailingSwitch")   # the switch in the "VPN" row (netp_toggle)
    # Android's VPN permission dialog, shown only the first time any VPN of the app starts.
    if android.wait_for("text=/^OK$/", timeout=5):
        android.tap("text=/^OK$/")
    _wait_for_tunnel(android, "NetP's tunnel didn't come up")
    android.key("back")


def _wait_for_tunnel(android, why):
    deadline = time.time() + 30
    while not android.tunnel_up():
        if time.time() > deadline:
            raise Error(why)
        time.sleep(1)
