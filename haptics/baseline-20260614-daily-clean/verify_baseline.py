#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from pathlib import Path
import hashlib
import re
import sys


ROOT = Path(__file__).resolve().parent


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def sha256(rel: str) -> str:
    h = hashlib.sha256()
    with (ROOT / rel).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


required = [
    "README.md",
    "MAINLINE-DELTA.md",
    "source-integration/aw86937-y700.c",
    "source-integration/Kconfig.snippet",
    "source-integration/Makefile.snippet",
    "source-integration/sm8650-lenovo-tb321fu-haptics.dts.snippet",
    "source-integration/haptic_ram.bin",
    "source-integration/haptic_click.bin",
    "source-integration/y700-aw86937-bind",
    "source-integration/y700-aw86937-haptics.service",
    "source-integration/90-y700-haptics.rules",
    "source-integration/make_rootfs_overlay.sh",
    "testing-tools/y700-haptic-test.c",
    "testing-tools/y700-haptic-test.aarch64",
    "testing-tools/y700-haptic-gui.py",
    "testing-tools/remote_install_overlay.sh",
    "testing-tools/verify_daily_haptics_source.py",
    "rootfs-overlay.tar.gz",
    "rootfs-overlay-SHA256SUMS.txt",
    "SOURCE-SHA256SUMS.txt",
    "validation-20260614-221646/y700-vibration-ab026-install-20260614-221646.tar.gz",
]

for rel in required:
    if not (ROOT / rel).exists():
        fail(f"missing required baseline file: {rel}")

driver = read("source-integration/aw86937-y700.c")
helper = read("testing-tools/y700-haptic-test.c")
gui = read("testing-tools/y700-haptic-gui.py")
bind = read("source-integration/y700-aw86937-bind")
overlay = read("source-integration/make_rootfs_overlay.sh")
kconfig = read("source-integration/Kconfig.snippet")
makefile = read("source-integration/Makefile.snippet")
dts = read("source-integration/sm8650-lenovo-tb321fu-haptics.dts.snippet")

checks = [
    ("daily PWM mode is fixed to Android mode 0", r"#define\s+AW86937_PWM_MODE_DEFAULT\s+0\b", driver),
    ("daily gain ceiling is full-scale 0xff", r"#define\s+AW86937_GAIN_CEILING_DEFAULT\s+0xff\b", driver),
    ("standard FF magnitude scales through gain ceiling", r"gain\s*=\s*level\s*\*\s*AW86937_GAIN_CEILING_DEFAULT\s*/\s*0xffffU", driver),
    ("driver exposes FF_RUMBLE", r"FF_RUMBLE", driver),
    ("helper supports standard constant effects", r'!strcmp\(argv\[1\],\s*"constant"\)', helper),
    ("helper supports standard periodic effects", r'!strcmp\(argv\[1\],\s*"periodic"\)', helper),
    ("GUI default short click drives full magnitude", r'"both",\s*"13",\s*"65535"', gui),
    ("Kconfig defines driver symbol", r"config\s+INPUT_AW86937_Y700", kconfig),
    ("Makefile builds driver object", r"aw86937-y700\.o", makefile),
    ("DTS includes right motor", r"haptics-right@5a", dts),
    ("DTS includes left motor", r"haptics-left@5b", dts),
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
    for name, text in {"helper": helper, "gui": gui, "bind": bind}.items():
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

expected_hashes = {
    "source-integration/aw86937-y700.c": "e7b8998c2863649411c767d055a5e13e00cbbe061d3044d779370a5133403485",
    "rootfs-overlay.tar.gz": "22af41fb74ba8553916d5ea23ad42f004c449712649fcb940aa81e6e197d0a42",
    "source-integration/y700-aw86937-bind": "104b7a8ce11e5a47fc71c8ce486dbb204922b84ca1cfad703915d9239f9d730f",
    "testing-tools/y700-haptic-gui.py": "e8c7cf756b0818ae0b9c94da48e018d29fccc47d8620b9502db36a702432e819",
    "testing-tools/y700-haptic-test.aarch64": "14deaffb71559388bdaf105f3938c1674efd42fdcd794cb413a6c34cce5cd7a8",
}

for rel, expected in expected_hashes.items():
    actual = sha256(rel)
    if actual != expected:
        fail(f"hash mismatch for {rel}: {actual} != {expected}")

print("AB026 daily haptics baseline checks passed")
