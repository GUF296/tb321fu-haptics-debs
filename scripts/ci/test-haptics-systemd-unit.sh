#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
builder="$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-systemd-unit.XXXXXX")

cleanup() {
  case "$tmp" in
    /tmp/tb321fu-haptics-systemd-unit.*) rm -rf -- "$tmp" ;;
  esac
}
trap cleanup EXIT INT TERM

command -v python3 >/dev/null
command -v systemctl >/dev/null
command -v systemd-analyze >/dev/null

unit="$tmp/tb321fu-haptics.service"
python3 - "$builder" "$unit" <<'PY'
from pathlib import Path
import sys

builder = Path(sys.argv[1]).read_text(encoding="utf-8")
start = builder.index("write_systemd_unit() {\n")
marker = "  cat > \"$dest\" <<'EOF_SERVICE'\n"
payload_start = builder.index(marker, start) + len(marker)
payload_end = builder.index("\nEOF_SERVICE\n", payload_start)
unit = builder[payload_start:payload_end] + "\n"
expected = """[Unit]
Description=Bind Lenovo TB321FU AW86937 haptics
DefaultDependencies=no
After=systemd-udevd.service local-fs.target
Wants=systemd-udevd.service
Conflicts=y700-aw86937-haptics.service

[Service]
Type=oneshot
ExecStart=/usr/libexec/tb321fu-haptics/bind-aw86937
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
if unit != expected:
    raise SystemExit("haptics unit content changed without updating its lifecycle contract")
Path(sys.argv[2]).write_text(unit, encoding="utf-8")
PY

root="$tmp/root"
install -d -m 0755 \
  "$root/usr/lib/systemd/system" \
  "$root/usr/libexec/tb321fu-haptics" \
  "$root/bin" \
  "$root/etc/systemd/system"
install -m 0644 "$unit" "$root/usr/lib/systemd/system/tb321fu-haptics.service"
printf '#!/bin/sh\nexit 0\n' > "$root/usr/libexec/tb321fu-haptics/bind-aw86937"
chmod 0755 "$root/usr/libexec/tb321fu-haptics/bind-aw86937"
printf '#!/bin/sh\nexit 0\n' > "$root/bin/true"
chmod 0755 "$root/bin/true"
printf '[Service]\nType=oneshot\nExecStart=/bin/true\n' > "$root/usr/lib/systemd/system/systemd-udevd.service"
printf '[Unit]\nDescription=Fixture local filesystems\n' > "$root/usr/lib/systemd/system/local-fs.target"
printf '[Unit]\nDescription=Fixture multi-user target\n' > "$root/usr/lib/systemd/system/multi-user.target"

systemd-analyze verify --root="$root" "$root/usr/lib/systemd/system/tb321fu-haptics.service"
systemctl --root="$root" enable tb321fu-haptics.service
systemctl --root="$root" is-enabled --quiet tb321fu-haptics.service
want="$root/etc/systemd/system/multi-user.target.wants/tb321fu-haptics.service"
[ -L "$want" ]
[ "$(readlink "$want")" = /usr/lib/systemd/system/tb321fu-haptics.service ]
systemctl --root="$root" disable tb321fu-haptics.service
if systemctl --root="$root" is-enabled --quiet tb321fu-haptics.service; then
  printf 'systemctl --root did not disable the haptics unit\n' >&2
  exit 1
fi

printf 'HAPTICS_SYSTEMD_UNIT=PASS\n'
