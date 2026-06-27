#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8", errors="replace")


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


driver = read("aw86937-y700.c")
helper = read("y700-haptic-test.c")
gui = read("y700-haptic-gui.py")
bind = read("y700-aw86937-bind")
overlay = read("make_rootfs_overlay.sh")

checks = [
    ("daily PWM mode is fixed to Android mode 0",
     r"#define\s+AW86937_PWM_MODE_DEFAULT\s+0\b", driver),
    ("daily gain ceiling is full-scale 0xff",
     r"#define\s+AW86937_GAIN_CEILING_DEFAULT\s+0xff\b", driver),
    ("standard FF magnitude still scales through gain ceiling",
     r"gain\s*=\s*level\s*\*\s*AW86937_GAIN_CEILING_DEFAULT\s*/\s*0xffffU", driver),
    ("helper default short test still drives full magnitude",
     r'"both",\s*"13",\s*"65535"', gui),
    ("helper still supports standard FF constant effects",
     r'!strcmp\(argv\[1\],\s*"constant"\)', helper),
    ("helper still supports standard FF periodic effects",
     r'!strcmp\(argv\[1\],\s*"periodic"\)', helper),
]

for label, pattern, text in checks:
    if not re.search(pattern, text):
        fail(label)

for forbidden in [
    "module_param_named(android_pwm_mode",
    "module_param_named(android_static_init",
    "module_param_named(gain_ceiling",
    "module_param_named(lra_trim",
    "module_param_cb(android_protected_misc",
    "module_param_string(click_rtp_name",
    "module_param_string(long_rtp_name",
    "aw86937_y700_android_pwm_mode",
    "aw86937_y700_android_static_init",
    "aw86937_y700_gain_ceiling",
    "aw86937_y700_lra_trim",
    "aw86937_y700_android_protected_misc",
    "aw86937_y700_click_rtp_name",
    "aw86937_y700_long_rtp_name",
    "protected_misc",
    "AW86937_LRA_TRIM",
]:
    if forbidden in driver:
        fail(f"driver still exposes debug/state knob: {forbidden}")

for forbidden in [
    "android_pwm_mode",
    "android_static_init",
    "android_protected_misc",
    "gain_ceiling",
    "lra_trim",
    "click_rtp_name",
    "long_rtp_name",
    "android-candidate-sweep",
    "android_candidate_sweep",
    "android-protected",
    "gain-ceiling",
    "lra-trim",
    "pwm-sweep",
    "asset-sweep",
    "android-feel-sweep",
    "android-rtp-hold",
]:
    for name, text in {
        "helper": helper,
        "gui": gui,
        "bind": bind,
    }.items():
        if forbidden in text:
            fail(f"{name} still exposes debug command/parameter: {forbidden}")

for forbidden in [
    "haptic_click_hihat.bin",
    "haptic_click_kick.bin",
    "haptic_click_snare.bin",
    "haptic_click_auto_sin.bin",
    "haptic_rtp_osc_24K_5s.bin",
]:
    if forbidden in overlay:
        fail(f"overlay still packages debug comparison asset: {forbidden}")

print("AB026 daily haptics source checks passed")
