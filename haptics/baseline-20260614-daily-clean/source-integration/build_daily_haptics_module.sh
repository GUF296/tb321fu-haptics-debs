#!/usr/bin/env bash
set -euo pipefail

SRC=${SRC:-/home/guf296/y700-original12-source-repro-20260602/linux}
OUT=${OUT:-/home/guf296/y700-original12-source-repro-20260602/build}
ARCH=${ARCH:-arm64}
MODDIR=${MODDIR:-$(pwd)}

make -C "$SRC" O="$OUT" ARCH="$ARCH" CROSS_COMPILE=aarch64-linux-gnu- \
	KBUILD_BUILD_USER=guf296 \
	KBUILD_BUILD_HOST=WIN-GKD27BKUBEL \
	KBUILD_BUILD_TIMESTAMP='Mon Jun 1 16:41:03 CST 2026' \
	KBUILD_BUILD_VERSION=12 \
	M="$MODDIR" modules

/usr/sbin/modinfo "$MODDIR/aw86937-y700.ko" > "$MODDIR/aw86937-y700.modinfo.txt" 2>/dev/null || modinfo "$MODDIR/aw86937-y700.ko" > "$MODDIR/aw86937-y700.modinfo.txt"
sha256sum "$MODDIR/aw86937-y700.ko" \
	"$MODDIR/aw86937-y700.c" \
	"$MODDIR/Makefile" \
	"$MODDIR/build_ab008_firmware_ram_module.sh" \
	"$MODDIR/y700-aw86937-bind" \
	"$MODDIR/haptic_ram.bin" \
	"$MODDIR/haptic_click.bin" \
	> "$MODDIR/SHA256SUMS.txt"
cat "$MODDIR/aw86937-y700.modinfo.txt"
cat "$MODDIR/SHA256SUMS.txt"
