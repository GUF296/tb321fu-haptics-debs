# Mainline Delta

This baseline assumes a mainline-style Y700 kernel that does not already have
AW86937 tablet haptics support.

## Kernel

Add a new driver:

```text
drivers/input/misc/aw86937-y700.c
```

Add a Kconfig entry equivalent to `source-integration/Kconfig.snippet` and a
Makefile object line equivalent to `source-integration/Makefile.snippet`.

Expected config:

```text
CONFIG_INPUT_AW86937_Y700=m
```

## Device Tree

Add the two AW86937 I2C child nodes from:

```text
source-integration/sm8650-lenovo-tb321fu-haptics.dts.snippet
```

The current known-good bus rate is 1 MHz, matching the AB003a/AB003b bring-up
state.

## Rootfs

Install these normal runtime assets:

```text
/usr/lib/firmware/haptic_ram.bin
/usr/lib/firmware/haptic_click.bin
/usr/local/sbin/y700-aw86937-bind
/etc/systemd/system/y700-aw86937-haptics.service
/etc/udev/rules.d/90-y700-haptics.rules
```

Install the optional user test tools:

```text
/usr/local/bin/y700-haptic-test
/usr/local/bin/y700-haptic-gui
/usr/local/share/applications/y700-haptic-test.desktop
```

## Daily Policy

The daily profile is hard-coded as normal behavior:

- PWM mode `0`
- gain ceiling `0xff`
- standard evdev FF as the public app interface

The driver intentionally does not expose the temporary bring-up module
parameters used in earlier AB tests.

## Patch/Artifact Layout

- `source-integration/` contains the files and snippets to apply to source.
- `testing-tools/` contains helpers and verification scripts.
- `rootfs-overlay.tar.gz` is the tested deployable overlay.
- `BASELINE-SHA256SUMS.txt` pins the entire baseline tree.
