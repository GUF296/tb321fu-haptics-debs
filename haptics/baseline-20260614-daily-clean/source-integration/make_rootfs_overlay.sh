#!/bin/sh
set -eu

krel=${KREL:-7.1.0-rc1-g66edb901bf87-dirty}
out=${OUT:-rootfs-overlay}

rm -rf "$out" "$out.tar.gz"
mkdir -p "$out/usr/lib/modules/$krel/extra"
mkdir -p "$out/usr/lib/firmware"
mkdir -p "$out/usr/local/bin"
mkdir -p "$out/usr/local/share/applications"
mkdir -p "$out/usr/local/sbin"
mkdir -p "$out/etc/udev/rules.d"
mkdir -p "$out/etc/systemd/system/multi-user.target.wants"

cr=$(printf '\r')
if LC_ALL=C grep -q "$cr" y700-haptic-gui.py y700-haptic-test.desktop; then
	echo "error: GUI/desktop text files must use Unix LF line endings" >&2
	exit 1
fi

install -m 0644 aw86937-y700.ko "$out/usr/lib/modules/$krel/extra/aw86937-y700.ko"
install -m 0644 haptic_ram.bin "$out/usr/lib/firmware/haptic_ram.bin"
install -m 0644 haptic_click.bin "$out/usr/lib/firmware/haptic_click.bin"
install -m 0755 y700-haptic-test "$out/usr/local/bin/y700-haptic-test"
install -m 0755 y700-haptic-gui.py "$out/usr/local/bin/y700-haptic-gui"
install -m 0644 y700-haptic-test.desktop "$out/usr/local/share/applications/y700-haptic-test.desktop"
install -m 0755 y700-aw86937-bind "$out/usr/local/sbin/y700-aw86937-bind"
install -m 0644 y700-aw86937-haptics.service "$out/etc/systemd/system/y700-aw86937-haptics.service"
install -m 0644 90-y700-haptics.rules "$out/etc/udev/rules.d/90-y700-haptics.rules"
ln -s ../y700-aw86937-haptics.service \
	"$out/etc/systemd/system/multi-user.target.wants/y700-aw86937-haptics.service"

tar --owner=0 --group=0 --numeric-owner -czf "$out.tar.gz" -C "$out" .
sha256sum "$out.tar.gz" \
	"$out/usr/lib/modules/$krel/extra/aw86937-y700.ko" \
	"$out/usr/lib/firmware/haptic_ram.bin" \
	"$out/usr/lib/firmware/haptic_click.bin" \
	"$out/usr/local/bin/y700-haptic-test" \
	"$out/usr/local/bin/y700-haptic-gui" \
	"$out/usr/local/share/applications/y700-haptic-test.desktop" \
	"$out/usr/local/sbin/y700-aw86937-bind" \
	"$out/etc/udev/rules.d/90-y700-haptics.rules" \
	"$out/etc/systemd/system/y700-aw86937-haptics.service" \
	> rootfs-overlay-SHA256SUMS.txt
