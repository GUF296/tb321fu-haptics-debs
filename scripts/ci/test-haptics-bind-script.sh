#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
builder="$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-bind.XXXXXX")

cleanup() {
  rm -rf -- "$tmp"
}
trap cleanup EXIT

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

require_failure() {
  local expected=$1 output status
  shift

  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "fixture unexpectedly succeeded"
  grep -Fq -- "$expected" <<<"$output" ||
    fail "fixture failed at the wrong boundary: $output"
}

bind_script="$tmp/bind-aw86937"
udev_rules="$tmp/90-tb321fu-haptics.rules"
modprobe_rules="$tmp/tb321fu-haptics.conf"
python3 - "$builder" "$bind_script" "$udev_rules" "$modprobe_rules" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
for marker, destination in (
    ("EOF_BIND", sys.argv[2]),
    ("EOF_UDEV", sys.argv[3]),
    ("EOF_MODPROBE", sys.argv[4]),
):
    start_token = f"<<'{marker}'\n"
    start = source.index(start_token) + len(start_token)
    end = source.index(f"\n{marker}\n", start)
    Path(destination).write_text(source[start:end] + "\n")
PY
chmod 0755 "$bind_script"
dash -n "$bind_script"

for token in \
  'lenovo,tb321fu-aw86937' \
  'awinic,aw86937' \
  005a \
  005b \
  'aw86937-haptics'; do
  grep -Fq -- "$token" "$bind_script" ||
    fail "bind helper omits current TB321FU contract token: $token"
done
for token in a9c000 new_device 'modprobe aw86937_y700' aw86937-y700; do
  if grep -Fq -- "$token" "$bind_script"; then
    fail "bind helper retains legacy fallback token: $token"
  fi
done
grep -Fq 'legacy aw86937_y700 module is already loaded' "$bind_script" ||
  fail 'bind helper does not reject an already-loaded legacy module'
for token in 'GROUP="input"' 'MODE="0660"' 'TAG+="uaccess"'; do
  grep -Fq -- "$token" "$udev_rules" ||
    fail "udev rules omit restricted local-user access token: $token"
done
if grep -Fq 'MODE="0666"' "$udev_rules"; then
  fail 'udev rules retain world-writable haptics events'
fi
grep -Fxq 'blacklist aw86937_y700' "$modprobe_rules" ||
  fail 'package generator does not blacklist the legacy AW86937 module'
grep -Fq 'write_legacy_module_blacklist "$pkg/etc/modprobe.d/tb321fu-haptics.conf"' \
  "$builder" ||
  fail 'package generator does not install its legacy-module blacklist'
for token in \
  'missing TB321FU AW86937 OF alias' \
  'missing Awinic AW86937 OF alias'; do
  grep -Fq -- "$token" "$builder" ||
    fail "package generator omits module alias contract: $token"
done

sysfs="$tmp/sys"
mockbin="$tmp/mockbin"
modprobe_log="$tmp/modprobe.log"
bind_log="$tmp/bind.log"
install -d -m 0755 "$mockbin" "$sysfs/bus/i2c/devices" \
  "$sysfs/bus/i2c/drivers/aw86937-haptics"
: > "$modprobe_log"
: > "$bind_log"
: > "$sysfs/bus/i2c/drivers/aw86937-haptics/bind"

cat > "$mockbin/lsmod" <<'EOF_LSMOD'
#!/bin/sh
set -eu
printf 'Module Size Used by\n'
if [ "${MOCK_LEGACY_MODULE:-0}" = 1 ]; then
  printf 'aw86937_y700 1 0\n'
fi
EOF_LSMOD
cat > "$mockbin/modprobe" <<'EOF_MODPROBE'
#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = aw86937_haptics ] || exit 70
printf '%s\n' "$1" >> "$MOCK_MODPROBE_LOG"
EOF_MODPROBE
cat > "$mockbin/sleep" <<'EOF_SLEEP'
#!/bin/sh
set -eu
bind="$TB321FU_HAPTICS_SYSFS_ROOT/bus/i2c/drivers/aw86937-haptics/bind"
driver="$TB321FU_HAPTICS_SYSFS_ROOT/bus/i2c/drivers/aw86937-haptics"
if [ -s "$bind" ]; then
  device=$(cat "$bind")
  printf '%s\n' "$device" >> "$MOCK_BIND_LOG"
  [ -e "$TB321FU_HAPTICS_SYSFS_ROOT/bus/i2c/devices/$device/driver" ] ||
    ln -s "$driver" "$TB321FU_HAPTICS_SYSFS_ROOT/bus/i2c/devices/$device/driver"
fi
EOF_SLEEP
chmod 0755 "$mockbin/lsmod" "$mockbin/modprobe" "$mockbin/sleep"

write_client() {
  local name=$1 compatible_a=$2 compatible_b=$3

  install -d -m 0755 "$sysfs/bus/i2c/devices/$name/of_node"
  printf '%s\0%s\0' "$compatible_a" "$compatible_b" > \
    "$sysfs/bus/i2c/devices/$name/of_node/compatible"
}

remove_client_drivers() {
  rm -f -- "$sysfs"/bus/i2c/devices/*/driver
}

run_bind() {
  env \
    PATH="$mockbin:$PATH" \
    TB321FU_HAPTICS_SYSFS_ROOT="$sysfs" \
    MOCK_MODPROBE_LOG="$modprobe_log" \
    MOCK_BIND_LOG="$bind_log" \
    MOCK_LEGACY_MODULE="${MOCK_LEGACY_MODULE:-0}" \
    "$bind_script"
}

write_client 42-005a lenovo,tb321fu-aw86937 awinic,aw86937
write_client 42-005b lenovo,tb321fu-aw86937 awinic,aw86937
ln -s "$sysfs/bus/i2c/drivers/aw86937-haptics" \
  "$sysfs/bus/i2c/devices/42-005a/driver"
ln -s "$sysfs/bus/i2c/drivers/aw86937-haptics" \
  "$sysfs/bus/i2c/devices/42-005b/driver"
run_bind
grep -Fxq aw86937_haptics "$modprobe_log" ||
  fail 'valid DT pair did not explicitly load the current module'
[ "$(wc -l < "$modprobe_log")" -eq 1 ] ||
  fail 'valid DT pair loaded an unexpected number of modules'

remove_client_drivers
: > "$modprobe_log"
: > "$bind_log"
: > "$sysfs/bus/i2c/drivers/aw86937-haptics/bind"
run_bind
grep -Fxq 42-005a "$bind_log" || fail 'unbound right client did not reach current bind path'
grep -Fxq 42-005b "$bind_log" || fail 'unbound left client did not reach current bind path'
[ -L "$sysfs/bus/i2c/devices/42-005a/driver" ] ||
  fail 'right client was not bound by the current driver fixture'
[ -L "$sysfs/bus/i2c/devices/42-005b/driver" ] ||
  fail 'left client was not bound by the current driver fixture'

remove_client_drivers
: > "$modprobe_log"
write_client 42-005a example,wrong-haptics awinic,aw86937
require_failure 'is not a current TB321FU AW86937 DT client' run_bind
[ ! -s "$modprobe_log" ] ||
  fail 'wrong-compatible DT fixture loaded a module before rejecting the client'

write_client 42-005a lenovo,tb321fu-aw86937 awinic,aw86937
: > "$modprobe_log"
MOCK_LEGACY_MODULE=1 require_failure 'legacy aw86937_y700 module is already loaded' run_bind
[ ! -s "$modprobe_log" ] ||
  fail 'loaded legacy module fixture invoked a fallback module load'

require_failure 'TB321FU_HAPTICS_SYSFS_ROOT must be an absolute path' \
  env PATH="$mockbin:$PATH" TB321FU_HAPTICS_SYSFS_ROOT=relative "$bind_script"

printf 'HAPTICS_BIND_SCRIPT=PASS\n'
