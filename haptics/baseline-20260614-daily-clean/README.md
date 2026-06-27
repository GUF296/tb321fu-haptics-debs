# Y700 AW86937 Daily Haptics Baseline 20260614-2220

Status: accepted daily haptics baseline.

This baseline records the complete source-level delta needed to reproduce the
current Y700 vibration support from a mainline-style kernel/rootfs state. It is
not only a live overlay backup.

## Accepted Runtime

- Driver: `aw86937-y700`
- Public API: standard Linux evdev force feedback
- Devices:
  - `/dev/input/y700-haptics-left`
  - `/dev/input/y700-haptics-right`
- Daily haptic profile:
  - PWM mode fixed internally to Android mode `0`
  - gain ceiling fixed internally to `0xff`
  - standard FF magnitude maps through that full gain ceiling
- User result: accepted as good enough for daily use after AB026.

## Mainline Delta Saved Here

Kernel/DT source integration is in `source-integration/`:

- `aw86937-y700.c`
  - new Linux-native AW86937 haptics driver;
  - exposes standard input FF devices;
  - loads Android-derived `haptic_ram.bin` and short-click RTP asset;
  - keeps daily profile internal, with no runtime tuning module parameters.
- `Kconfig.snippet`
  - adds `CONFIG_INPUT_AW86937_Y700`.
- `Makefile.snippet`
  - builds `aw86937-y700.o`.
- `sm8650-lenovo-tb321fu-haptics.dts.snippet`
  - adds the two AW86937 I2C child nodes under the Y700 haptics bus.
- `haptic_ram.bin` and `haptic_click.bin`
  - firmware/effect assets used by the driver.
- `y700-aw86937-bind`, `y700-aw86937-haptics.service`, and
  `90-y700-haptics.rules`
  - rootfs integration to bind the I2C clients and create stable input links.
- `make_rootfs_overlay.sh`
  - regenerates `rootfs-overlay.tar.gz`.
- `build_daily_haptics_module.sh`
  - reproduces the external module build used for this baseline.

Testing helpers are in `testing-tools/`.

## Deliberately Removed From Daily Code

AB026 removed the runtime/debug surfaces used during tuning:

- `android_pwm_mode`
- `android_static_init`
- `android_protected_misc`
- `gain_ceiling`
- `lra_trim`
- `click_rtp_name`
- `long_rtp_name`
- sweep/debug commands for Android candidate comparisons

The daily version keeps the accepted profile as normal driver logic rather than
exposing tuning knobs in `/sys/module/aw86937_y700/parameters`.

## Rootfs Overlay

- File: `rootfs-overlay.tar.gz`
- SHA256: `22af41fb74ba8553916d5ea23ad42f004c449712649fcb940aa81e6e197d0a42`

Installed paths:

- `/usr/lib/modules/7.1.0-rc1-g66edb901bf87-dirty/extra/aw86937-y700.ko`
- `/usr/lib/firmware/haptic_ram.bin`
- `/usr/lib/firmware/haptic_click.bin`
- `/usr/local/bin/y700-haptic-test`
- `/usr/local/bin/y700-haptic-gui`
- `/usr/local/share/applications/y700-haptic-test.desktop`
- `/usr/local/sbin/y700-aw86937-bind`
- `/etc/udev/rules.d/90-y700-haptics.rules`
- `/etc/systemd/system/y700-aw86937-haptics.service`

## Validation

Runtime validation archive:

- `validation-20260614-221646/y700-vibration-ab026-install-20260614-221646.tar.gz`

Known accepted hashes:

- module: `19870de97babde92dc75f81e470a7a2407057b6a27fb459adb539e8bd45b4377`
- driver source: `e7b8998c2863649411c767d055a5e13e00cbbe061d3044d779370a5133403485`
- overlay: `22af41fb74ba8553916d5ea23ad42f004c449712649fcb940aa81e6e197d0a42`
- helper: `14deaffb71559388bdaf105f3938c1674efd42fdcd794cb413a6c34cce5cd7a8`
- GUI: `e8c7cf756b0818ae0b9c94da48e018d29fccc47d8620b9502db36a702432e819`
- bind script: `104b7a8ce11e5a47fc71c8ce486dbb204922b84ca1cfad703915d9239f9d730f`

Run:

```sh
python verify_baseline.py
```

## Reproduction Summary

1. Apply `source-integration/aw86937-y700.c` to `drivers/input/misc/`.
2. Apply the Kconfig and Makefile snippets near the other input misc haptic
   drivers.
3. Apply the DTS haptic child node snippet to the Y700 DTS.
4. Build with `CONFIG_INPUT_AW86937_Y700=m`.
5. Install firmware/effect assets and the rootfs helper/service from this
   baseline, or unpack `rootfs-overlay.tar.gz`.
6. Enable/start `y700-aw86937-haptics.service`.
7. Confirm `/dev/input/y700-haptics-left` and `/dev/input/y700-haptics-right`
   exist, then test through evdev FF.

## Notes

- The current rawdump/DT baseline used during bring-up was AB003b minimal
  haptic I2C child nodes. This baseline stores the source DTS snippet instead
  of requiring a rawdump image.
- RichTap private Android misc devices are intentionally not implemented.
- LED-class vibrator aliases are intentionally not used; the Linux-facing
  interface is evdev force feedback.
