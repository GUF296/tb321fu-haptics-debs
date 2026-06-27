# Findings

## Baseline state
- Accepted daily state is AB026.
- Runtime is fixed to `android_pwm_mode=0` and `gain_ceiling=0xff`.
- Public interface is standard Linux input force feedback.
- Removed debug/runtime knobs are not exposed in the daily build.

## Repro assets available
- `aw86937-y700.c`
- `y700-haptic-test.c`
- `y700-haptic-gui.py`
- `y700-aw86937-bind`
- `make_rootfs_overlay.sh`
- `remote_ab025_install_overlay.sh`
- `build_ab008_firmware_ram_module.sh`
- `verify_ab026_daily_haptics_source.py`
- `y700-aw86937-haptics.service`
- `90-y700-haptics.rules`
- `y700-haptic-test.desktop`
- `rootfs-overlay.tar.gz`
- validation tarball from the accepted install

## Baseline requirement
- The saved baseline must preserve the source-level delta relative to mainline, not only the installed overlay.

## Final status
- The baseline-save task is complete.
- The preserved tree includes source delta, rootfs overlay, validation archive, hashes, and readable mainline delta records.
