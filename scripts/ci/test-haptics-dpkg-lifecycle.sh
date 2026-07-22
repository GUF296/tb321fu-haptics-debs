#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/haptics-maintainer-scripts.sh"

for command in dpkg dpkg-deb grep install ln; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done

kernel_release=7.1.1-00009-g570b90203d97
package=tb321fu-haptics-dpkg-fixture
service=tb321fu-haptics.service
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-dpkg-lifecycle.XXXXXX")
root="$tmp/root"
mockbin="$tmp/mockbin"
log="$tmp/mock.log"

cleanup() {
  rm -rf -- "$tmp"
}
trap cleanup EXIT

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

assert_log_contains() {
  grep -Fq -- "$1" "$log" || fail "missing mock invocation: $1"
}

assert_log_absent() {
  if grep -Fq -- "$1" "$log"; then
    fail "unexpected mock invocation: $1"
  fi
}

clear_log() {
  : > "$log"
}

write_mock_commands() {
  install -d -m 0755 "$mockbin"

  cat > "$mockbin/depmod" <<'EOF_DEPMOD'
#!/bin/sh
set -eu
{
  printf 'depmod'
  for argument in "$@"; do printf ' <%s>' "$argument"; done
  printf '\n'
} >> "$MOCK_LOG"
[ "$#" -eq 4 ] || exit 41
[ "$1" = -b ] && [ "$2" = "$EXPECTED_ROOT" ] && [ "$3" = -a ] &&
  [ "$4" = "$EXPECTED_KERNEL_RELEASE" ] || exit 42
EOF_DEPMOD

  cat > "$mockbin/modinfo" <<'EOF_MODINFO'
#!/bin/sh
set -eu
{
  printf 'modinfo'
  for argument in "$@"; do printf ' <%s>' "$argument"; done
  printf '\n'
} >> "$MOCK_LOG"
[ "$#" -eq 3 ] && [ "$1" = -F ] && [ "$2" = vermagic ] &&
  [ "$3" = "$EXPECTED_MODULE_PATH" ] || exit 43
printf '%s SMP preempt\n' "$EXPECTED_KERNEL_RELEASE"
EOF_MODINFO

  cat > "$mockbin/systemctl" <<'EOF_SYSTEMCTL'
#!/bin/sh
set -eu
root=
case "${1:-}" in
  --root=*) root=${1#--root=}; shift ;;
esac
{
  printf 'systemctl'
  [ -n "$root" ] && printf ' <--root=%s>' "$root"
  for argument in "$@"; do printf ' <%s>' "$argument"; done
  printf '\n'
} >> "$MOCK_LOG"
[ "$root" = "$EXPECTED_ROOT" ] || exit 44
command=${1:-}
shift || true
case "$command" in
  enable)
    [ "${1:-}" = tb321fu-haptics.service ] || exit 45
    install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
    ln -sfn /usr/lib/systemd/system/tb321fu-haptics.service \
      "$root/etc/systemd/system/multi-user.target.wants/tb321fu-haptics.service"
    ;;
  is-enabled)
    [ "${1:-}" = --quiet ] && [ "${2:-}" = tb321fu-haptics.service ] || exit 46
    [ -L "$root/etc/systemd/system/multi-user.target.wants/tb321fu-haptics.service" ] || exit 47
    ;;
  *) exit 48 ;;
esac
EOF_SYSTEMCTL

  chmod 0755 "$mockbin/depmod" "$mockbin/modinfo" "$mockbin/systemctl"
}

create_package() {
  local version=$1 destination=$2 package_root

  package_root="$tmp/package-$version"

  rm -rf -- "$package_root"
  install -d -m 0755 \
    "$package_root/DEBIAN" \
    "$package_root/etc/skel/.config" \
    "$package_root/usr/bin" \
    "$package_root/usr/lib/firmware" \
    "$package_root/usr/lib/modules/$kernel_release/extra" \
    "$package_root/usr/lib/systemd/system" \
    "$package_root/usr/lib/udev/rules.d" \
    "$package_root/usr/libexec/tb321fu-haptics"
  printf '%s\n' \
    "Package: $package" \
    "Version: $version" \
    'Architecture: all' \
    'Maintainer: fixture <fixture@example.invalid>' \
    'Description: disposable haptics dpkg lifecycle fixture' \
    > "$package_root/DEBIAN/control"
  haptics_write_maintainer_scripts "$package_root" "$kernel_release"
  printf 'keyboard fixture\n' > "$package_root/etc/skel/.config/plasmakeyboardrc"
  printf '#!/bin/sh\nexit 0\n' > "$package_root/usr/bin/tb321fu-haptic-test"
  printf 'click fixture\n' > "$package_root/usr/lib/firmware/haptic_click.bin"
  printf 'ram fixture\n' > "$package_root/usr/lib/firmware/haptic_ram.bin"
  printf 'module fixture\n' > \
    "$package_root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  printf '[Service]\nType=oneshot\n' > \
    "$package_root/usr/lib/systemd/system/$service"
  printf 'SUBSYSTEM=="input"\n' > \
    "$package_root/usr/lib/udev/rules.d/90-tb321fu-haptics.rules"
  printf '#!/bin/sh\nexit 0\n' > \
    "$package_root/usr/libexec/tb321fu-haptics/bind-aw86937"
  find "$package_root" -type d -exec chmod 0755 {} +
  find "$package_root" -type f \
    ! -path '*/DEBIAN/postinst' \
    ! -path '*/DEBIAN/prerm' \
    ! -path '*/DEBIAN/postrm' \
    ! -path '*/usr/bin/tb321fu-haptic-test' \
    ! -path '*/usr/libexec/tb321fu-haptics/bind-aw86937' -exec chmod 0644 {} +
  chmod 0755 \
    "$package_root/DEBIAN/postinst" \
    "$package_root/DEBIAN/prerm" \
    "$package_root/DEBIAN/postrm" \
    "$package_root/usr/bin/tb321fu-haptic-test" \
    "$package_root/usr/libexec/tb321fu-haptics/bind-aw86937"
  dpkg-deb --build --root-owner-group "$package_root" "$destination" >/dev/null
}

run_dpkg() {
  env -i \
    PATH="$mockbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME="$tmp/home" \
    LC_ALL=C \
    MOCK_LOG="$log" \
    EXPECTED_ROOT="$root" \
    EXPECTED_KERNEL_RELEASE="$kernel_release" \
    EXPECTED_MODULE_PATH="$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko" \
    dpkg \
      --root="$root" \
      --log="$root/var/log/dpkg.log" \
      --force-not-root \
      --force-script-chrootless \
      "$@"
}

write_mock_commands
install -d -m 0755 \
  "$root/var/lib/dpkg" \
  "$root/var/log" \
  "$root/usr/lib/modules/$kernel_release/kernel" \
  "$tmp/home"
: > "$root/var/lib/dpkg/status"
printf 'kernel tree sentinel\n' > "$root/usr/lib/modules/$kernel_release/kernel/sentinel"

deb_v1="$tmp/$package-1_all.deb"
deb_v2="$tmp/$package-2_all.deb"
create_package 1 "$deb_v1"
create_package 2 "$deb_v2"

clear_log
run_dpkg --install "$deb_v1"
assert_log_contains "modinfo <-F> <vermagic> <$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko>"
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
want="$root/etc/systemd/system/multi-user.target.wants/$service"
[ -L "$want" ] || fail 'real dpkg install did not enable the service in the disposable root'
dpkg --root="$root" --status "$package" | grep -Fq 'Status: install ok installed'

clear_log
run_dpkg --install "$deb_v2"
assert_log_contains "modinfo <-F> <vermagic> <$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko>"
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
[ -L "$want" ] || fail 'real dpkg upgrade lost service enablement'

clear_log
run_dpkg --remove "$package"
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_absent "<stop> <$service>"
[ ! -L "$want" ] || fail 'real dpkg removal left service enablement behind'
dpkg --root="$root" --status "$package" | grep -Fq 'Status: deinstall ok config-files'

clear_log
run_dpkg --purge "$package"
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
[ ! -e "$root/var/lib/dpkg/info/$package.postrm" ] ||
  fail 'real dpkg purge left the haptics postrm registration behind'

printf 'HAPTICS_DPKG_LIFECYCLE=PASS\n'
