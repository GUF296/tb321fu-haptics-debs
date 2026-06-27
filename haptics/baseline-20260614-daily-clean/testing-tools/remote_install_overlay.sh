#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

overlay=${1:-/tmp/rootfs-overlay.tar.gz}
ts=$(date +%Y%m%d-%H%M%S)
out=/tmp/y700-vibration-ab026-install-$ts
mkdir -p "$out"

log()
{
	printf '%s\n' "$*" | tee -a "$out/run.log"
}

{
	echo "== preflight =="
	uname -a
	df -h / /tmp
	ls -l "$overlay"
	sha256sum "$overlay"
	ls -ld /lib /usr/lib
	if [ ! -L /lib ]; then
		echo "refusing to install: /lib is not a symlink"
		exit 1
	fi
	if tar -tzf "$overlay" | grep -E '^(\./)?lib(/|$)'; then
		echo "refusing to install: overlay contains top-level lib/"
		exit 1
	fi
	systemctl is-active y700-aw86937-haptics.service || true
	lsmod | awk '$1 ~ /aw86937/ { print }' || true
} > "$out/preflight.txt" 2>&1

systemctl stop y700-aw86937-haptics.service > "$out/systemctl-stop.txt" 2>&1 || true

if [ -d /sys/bus/i2c/drivers/aw86937-y700 ]; then
	for dev in /sys/bus/i2c/devices/*-005a /sys/bus/i2c/devices/*-005b; do
		[ -e "$dev/name" ] || continue
		if [ -e "$dev/driver" ] &&
		   [ "$(basename "$(readlink -f "$dev/driver")")" = "aw86937-y700" ]; then
			echo "$(basename "$dev")" > /sys/bus/i2c/drivers/aw86937-y700/unbind
		fi
	done
fi

if lsmod | awk '{print $1}' | grep -qx aw86937_y700; then
	modprobe -r aw86937_y700 > "$out/modprobe-r.txt" 2>&1 ||
		rmmod aw86937_y700 >> "$out/modprobe-r.txt" 2>&1 || true
fi

if lsmod | awk '{print $1}' | grep -qx aw86937_y700; then
	echo "aw86937_y700 still loaded after unbind/unload" > "$out/module-unload.failed"
	exit 1
fi

krel=$(uname -r)
backup_dir="/root/y700-haptic-ab026-backup-$ts"
mkdir -p "$backup_dir"
for path in \
	"/lib/modules/$krel/extra/aw86937-y700.ko" \
	"/lib/firmware/haptic_ram.bin" \
	"/lib/firmware/haptic_click.bin" \
	"/usr/local/bin/y700-haptic-test" \
	"/usr/local/bin/y700-haptic-gui" \
	"/usr/local/share/applications/y700-haptic-test.desktop" \
	"/usr/local/sbin/y700-aw86937-bind" \
	"/etc/systemd/system/y700-aw86937-haptics.service" \
	"/etc/udev/rules.d/90-y700-haptics.rules"
do
	if [ -e "$path" ]; then
		mkdir -p "$backup_dir$(dirname "$path")"
		cp -a "$path" "$backup_dir$path"
	fi
done

tar --keep-directory-symlink --no-overwrite-dir -xzf "$overlay" -C /

chown root:root \
	"/lib/modules/$krel/extra/aw86937-y700.ko" \
	/lib/firmware/haptic_ram.bin \
	/lib/firmware/haptic_click.bin \
	/usr/local/bin/y700-haptic-test \
	/usr/local/bin/y700-haptic-gui \
	/usr/local/share/applications/y700-haptic-test.desktop \
	/usr/local/sbin/y700-aw86937-bind \
	/etc/udev/rules.d/90-y700-haptics.rules \
	/etc/systemd/system/y700-aw86937-haptics.service
chmod 0644 \
	"/lib/modules/$krel/extra/aw86937-y700.ko" \
	/lib/firmware/haptic_ram.bin \
	/lib/firmware/haptic_click.bin \
	/usr/local/share/applications/y700-haptic-test.desktop \
	/etc/udev/rules.d/90-y700-haptics.rules \
	/etc/systemd/system/y700-aw86937-haptics.service
chmod 0755 \
	/usr/local/bin/y700-haptic-test \
	/usr/local/bin/y700-haptic-gui \
	/usr/local/sbin/y700-aw86937-bind

depmod -a "$krel" 2>"$out/depmod.err" || true
udevadm control --reload-rules 2>"$out/udev-reload.err" || true
systemctl daemon-reload
systemctl enable y700-aw86937-haptics.service > "$out/systemctl-enable.txt" 2>&1
systemctl restart y700-aw86937-haptics.service > "$out/systemctl-restart.txt" 2>&1
udevadm trigger -s input 2>>"$out/udev-trigger.err" || true
udevadm settle --timeout=10 2>>"$out/udev-settle.err" || true

{
	echo "== state =="
	systemctl --no-pager --full status y700-aw86937-haptics.service || true
	sha256sum "/lib/modules/$krel/extra/aw86937-y700.ko" \
		/lib/firmware/haptic_ram.bin \
		/lib/firmware/haptic_click.bin \
		/usr/local/bin/y700-haptic-test \
		/usr/local/bin/y700-haptic-gui \
		/usr/local/sbin/y700-aw86937-bind \
		/etc/udev/rules.d/90-y700-haptics.rules \
		/etc/systemd/system/y700-aw86937-haptics.service
	echo "== module params =="
	for param in android_pwm_mode android_static_init android_protected_misc gain_ceiling lra_trim click_rtp_name long_rtp_name; do
		if [ -e "/sys/module/aw86937_y700/parameters/$param" ]; then
			echo "unexpected parameter still present: $param"
			exit 1
		fi
	done
	echo "== standard ff smoke =="
	/usr/local/bin/y700-haptic-test both 13 65535 2 65
	/usr/local/bin/y700-haptic-test both 13 32000 2 65
	/usr/local/bin/y700-haptic-test constant 18 65535 1 65
	/usr/local/bin/y700-haptic-test periodic 45 65535 6 1 65
	echo "== haptic events =="
	ls -l /dev/input/y700-haptics-left /dev/input/y700-haptics-right 2>/dev/null || true
} > "$out/post-start.txt" 2>&1

dmesg | grep -i -E 'aw869|haptic|vib|005a|005b|a9c000|force feedback|ff' | tail -180 > "$out/dmesg-tail.txt" || true
tar -czf "$out.tar.gz" -C "$(dirname "$out")" "$(basename "$out")"
log "OK $out.tar.gz"
