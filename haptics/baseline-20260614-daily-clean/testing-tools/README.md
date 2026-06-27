# Testing Tools

These tools use the standard Linux evdev force-feedback API.

## CLI

```sh
/usr/local/bin/y700-haptic-test both 13 65535
/usr/local/bin/y700-haptic-test both constant 120 65535
/usr/local/bin/y700-haptic-test both periodic 120 65535 8
```

The helper discovers `aw86937-haptics-left` and `aw86937-haptics-right`
dynamically and does not depend on fixed `/dev/input/eventX` numbers.

## GUI

```sh
/usr/local/bin/y700-haptic-gui
```

The daily GUI is intentionally small:

- short clicks
- long hold
- custom duration/strength

It no longer exposes Android candidate sweeps or driver debug parameters.

## Verification

`verify_daily_haptics_source.py` checks that the daily source keeps the accepted
profile and does not reintroduce the removed tuning interfaces.

`remote_install_overlay.sh` is the tested install/smoke script used during
AB026 validation.
