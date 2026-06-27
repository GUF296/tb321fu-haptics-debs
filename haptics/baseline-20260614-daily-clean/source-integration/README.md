# Source Integration

Use this directory as the source-level delta against mainline.

## Kernel Driver

Copy:

```text
aw86937-y700.c
```

to:

```text
drivers/input/misc/aw86937-y700.c
```

Then add the contents of:

```text
Kconfig.snippet
Makefile.snippet
```

to the corresponding `drivers/input/misc/Kconfig` and
`drivers/input/misc/Makefile` locations.

Enable:

```text
CONFIG_INPUT_AW86937_Y700=m
```

## Device Tree

Apply:

```text
sm8650-lenovo-tb321fu-haptics.dts.snippet
```

to the Y700 DTS. It creates the right and left AW86937 I2C child nodes on the
known haptics bus and keeps the bus at the tested 1 MHz rate.

## Firmware and Rootfs Assets

Install:

```text
haptic_ram.bin
haptic_click.bin
```

to:

```text
/usr/lib/firmware/
```

`make_rootfs_overlay.sh` packages the module, firmware, service, udev rule,
stable input links, and user test tools into `rootfs-overlay.tar.gz`.

## Daily Cleanup State

The driver in this baseline keeps only the accepted daily behavior. Temporary
tuning controls from earlier AB runs are removed, including PWM mode, gain
ceiling, trim, protected misc, alternate RTP asset names, and sweep commands.
