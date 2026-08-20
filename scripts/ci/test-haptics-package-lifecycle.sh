#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/haptics-maintainer-scripts.sh"

kernel_release=test-kernel-release
service=tb321fu-haptics.service
legacy_service=y700-aw86937-haptics.service
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-package-lifecycle.XXXXXX")
mockbin="$tmp/mockbin"
log="$tmp/mock.log"

cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local label=$1 output status
  shift

  set +e
  "$@" >"$tmp/$label.out" 2>&1
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "$label unexpectedly succeeded"
  output=$(<"$tmp/$label.out")
  [ -n "$output" ] || fail "$label failed without a diagnostic"
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
[ "${MOCK_DEPMOD_FAIL:-0}" = 1 ] && {
  printf 'mock depmod failure\n' >&2
  exit 41
}
[ "$#" -eq 4 ] || exit 42
[ "$1" = -b ] && [ "$2" = "$EXPECTED_ROOT" ] && [ "$3" = -a ] &&
  [ "$4" = "$EXPECTED_KERNEL_RELEASE" ] || exit 43
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
  [ "$3" = "$EXPECTED_MODULE_PATH" ] || exit 44
printf '%s\n' "${MOCK_VERMAGIC:-$EXPECTED_KERNEL_RELEASE SMP preempt}"
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
[ "$root" = "$EXPECTED_ROOT" ] || exit 45
command=${1:-}
shift || true
case "$command" in
  enable)
    [ "${MOCK_SYSTEMCTL_ENABLE_FAIL:-0}" = 1 ] && {
      printf 'mock systemctl enable failure\n' >&2
      exit 46
    }
    [ "${1:-}" = tb321fu-haptics.service ] || exit 47
    install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
    ln -sfn /usr/lib/systemd/system/tb321fu-haptics.service \
      "$root/etc/systemd/system/multi-user.target.wants/tb321fu-haptics.service"
    if [ "${MOCK_SYSTEMCTL_ENABLE_FAIL_AFTER_CREATE:-0}" = 1 ]; then
      printf 'mock systemctl enable failure after creating want\n' >&2
      exit 52
    fi
    ;;
  disable)
    [ "${1:-}" = y700-aw86937-haptics.service ] || exit 48
    rm -f -- "$root/etc/systemd/system/multi-user.target.wants/y700-aw86937-haptics.service"
    ;;
  is-enabled)
    [ "${1:-}" = --quiet ] && [ "${2:-}" = tb321fu-haptics.service ] || exit 50
    [ -L "$root/etc/systemd/system/multi-user.target.wants/tb321fu-haptics.service" ] || exit 51
    if [ "${MOCK_SYSTEMCTL_IS_ENABLED_FAIL:-0}" = 1 ]; then
      printf 'mock systemctl is-enabled failure\n' >&2
      exit 53
    fi
    ;;
  is-active) exit 3 ;;
  *) exit 49 ;;
esac
EOF_SYSTEMCTL

  cat > "$mockbin/uname" <<'EOF_UNAME'
#!/bin/sh
printf 'uname\n' >> "$MOCK_LOG"
exit 99
EOF_UNAME

  chmod 0755 "$mockbin/depmod" "$mockbin/modinfo" "$mockbin/systemctl" "$mockbin/uname"
}

create_package_tree() {
  local package_root=$1

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
    'Package: tb321fu-haptics' \
    'Version: 1' \
    'Architecture: arm64' \
    'Maintainer: fixture <fixture@example.invalid>' \
    'Depends: kmod, systemd, udev' \
    'Description: fixture' \
    > "$package_root/DEBIAN/control"
  haptics_write_maintainer_scripts "$package_root" "$kernel_release"
  printf 'keyboard\n' > "$package_root/etc/skel/.config/plasmakeyboardrc"
  printf '#!/bin/sh\nexit 0\n' > "$package_root/usr/bin/tb321fu-haptic-test"
  printf 'click firmware\n' > "$package_root/usr/lib/firmware/haptic_click.bin"
  printf 'ram firmware\n' > "$package_root/usr/lib/firmware/haptic_ram.bin"
  printf 'module fixture bytes\n' > \
    "$package_root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  printf '[Service]\nType=oneshot\n' > "$package_root/usr/lib/systemd/system/$service"
  printf 'rules\n' > "$package_root/usr/lib/udev/rules.d/90-tb321fu-haptics.rules"
  printf '#!/bin/sh\nexit 0\n' > "$package_root/usr/libexec/tb321fu-haptics/bind-aw86937"
  find "$package_root" -type d -exec chmod 0755 {} +
  find "$package_root" -type f ! -path '*/DEBIAN/postinst' ! -path '*/DEBIAN/postrm' \
    ! -path '*/DEBIAN/prerm' \
    ! -path '*/usr/bin/tb321fu-haptic-test' \
    ! -path '*/usr/libexec/tb321fu-haptics/bind-aw86937' -exec chmod 0644 {} +
  chmod 0755 \
    "$package_root/DEBIAN/postinst" \
    "$package_root/DEBIAN/prerm" \
    "$package_root/DEBIAN/postrm" \
    "$package_root/usr/bin/tb321fu-haptic-test" \
    "$package_root/usr/libexec/tb321fu-haptics/bind-aw86937"
}

prepare_fixture() {
  local name=$1 package_root

  root="$tmp/root-$name"
  control="$tmp/control-$name"
  package_root="$tmp/package-$name"
  deb="$tmp/$name.deb"
  create_package_tree "$package_root"
  dpkg-deb --build --root-owner-group "$package_root" "$deb" >/dev/null
  dpkg-deb -x "$deb" "$root"
  dpkg-deb -e "$deb" "$control"
  dash -n "$control/postinst" "$control/prerm" "$control/postrm"
  ln -s usr/lib "$root/lib"
  export EXPECTED_ROOT="$root"
  export EXPECTED_MODULE_PATH="$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
}

install_legacy_payload() {
  install -d -m 0755 \
    "$root/etc/systemd/system/multi-user.target.wants" \
    "$root/etc/udev/rules.d" \
    "$root/usr/local/sbin"
  printf '[Service]\nType=oneshot\n' > "$root/etc/systemd/system/$legacy_service"
  printf 'legacy rules\n' > "$root/etc/udev/rules.d/90-y700-haptics.rules"
  printf '#!/bin/sh\nexit 0\n' > "$root/usr/local/sbin/y700-aw86937-bind"
  chmod 0755 "$root/usr/local/sbin/y700-aw86937-bind"
  ln -s "/etc/systemd/system/$legacy_service" \
    "$root/etc/systemd/system/multi-user.target.wants/$legacy_service"
}

run_postinst() {
  env \
    PATH="$mockbin:$PATH" \
    DPKG_ROOT="$root" \
    MOCK_LOG="$log" \
    EXPECTED_ROOT="$EXPECTED_ROOT" \
    EXPECTED_MODULE_PATH="$EXPECTED_MODULE_PATH" \
    EXPECTED_KERNEL_RELEASE="$kernel_release" \
    MOCK_DEPMOD_FAIL="${MOCK_DEPMOD_FAIL:-0}" \
    MOCK_SYSTEMCTL_ENABLE_FAIL="${MOCK_SYSTEMCTL_ENABLE_FAIL:-0}" \
    MOCK_SYSTEMCTL_ENABLE_FAIL_AFTER_CREATE="${MOCK_SYSTEMCTL_ENABLE_FAIL_AFTER_CREATE:-0}" \
    MOCK_SYSTEMCTL_IS_ENABLED_FAIL="${MOCK_SYSTEMCTL_IS_ENABLED_FAIL:-0}" \
    MOCK_VERMAGIC="${MOCK_VERMAGIC:-}" \
    "$control/postinst" "$@"
}

run_postrm() {
  env \
    PATH="$mockbin:$PATH" \
    DPKG_ROOT="$root" \
    MOCK_LOG="$log" \
    EXPECTED_ROOT="$EXPECTED_ROOT" \
    EXPECTED_MODULE_PATH="$EXPECTED_MODULE_PATH" \
    EXPECTED_KERNEL_RELEASE="$kernel_release" \
    MOCK_DEPMOD_FAIL="${MOCK_DEPMOD_FAIL:-0}" \
    "$control/postrm" "$@"
}

run_prerm() {
  env \
    PATH="$mockbin:$PATH" \
    DPKG_ROOT="$root" \
    MOCK_LOG="$log" \
    EXPECTED_ROOT="$EXPECTED_ROOT" \
    EXPECTED_MODULE_PATH="$EXPECTED_MODULE_PATH" \
    EXPECTED_KERNEL_RELEASE="$kernel_release" \
    "$control/prerm" "$@"
}

write_mock_commands
export MOCK_LOG="$log" EXPECTED_KERNEL_RELEASE="$kernel_release"

bad_root="$tmp/bad-release"
install -d -m 0755 "$bad_root"
if haptics_write_maintainer_scripts "$bad_root" '../unsafe-release' >/dev/null 2>&1; then
  fail 'unsafe kernel release was accepted by maintainer-script generator'
fi

hostile_templates="$tmp/hostile-templates"
hostile_output="$tmp/hostile-template-output"
install -d -m 0755 "$hostile_templates" "$hostile_output"
for script in postinst prerm postrm; do
  printf '#!/bin/sh\necho hostile-template\n' > "$hostile_templates/$script.in"
done
env HAPTICS_MAINTAINER_TEMPLATE_DIR="$hostile_templates" \
  bash -c '
    set -euo pipefail
    helper=$1
    package_root=$2
    kernel_release=$3
    . "$helper"
    haptics_write_maintainer_scripts "$package_root" "$kernel_release"
  ' bash "$SCRIPT_DIR/haptics-maintainer-scripts.sh" "$hostile_output" "$kernel_release"
grep -Fq hostile-template "$hostile_output/DEBIAN/postinst" &&
  fail 'inherited template directory changed generated postinst bytes'
grep -Fxq "KERNEL_RELEASE=$kernel_release" "$hostile_output/DEBIAN/postinst" ||
  fail 'generated postinst did not embed the verified kernel release'
grep -Fq 'tb321fu-haptics postinst:' "$hostile_output/DEBIAN/postinst" ||
  fail 'generated postinst did not come from the producer-owned template'

prepare_fixture install
clear_log
run_postinst configure
assert_log_contains "modinfo <-F> <vermagic> <$EXPECTED_MODULE_PATH>"
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
assert_log_absent uname
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'postinst did not enable the TB321FU unit'
[ -f "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'postinst did not record ownership of the service want it created'
[ "$(cat "$root/var/lib/tb321fu-haptics/managed-want")" = \
  /usr/lib/systemd/system/tb321fu-haptics.service ] ||
  fail 'postinst recorded an unexpected service want target'

prepare_fixture preexisting-state-directory
install -d -m 0755 "$root/var/lib/tb321fu-haptics"
clear_log
run_postinst configure
[ -f "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'postinst did not record ownership in a pre-existing state directory'
clear_log
run_postrm remove
[ -d "$root/var/lib/tb321fu-haptics" ] ||
  fail 'postrm removed a pre-existing administrator-owned state directory'
[ ! -e "$root/var/lib/tb321fu-haptics/managed-want" ] && \
  [ ! -L "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'postrm left package-owned state in the pre-existing directory'

prepare_fixture preexisting-user-want
install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
ln -s /usr/lib/systemd/system/tb321fu-haptics.service \
  "$root/etc/systemd/system/multi-user.target.wants/$service"
clear_log
run_postinst configure
assert_log_absent "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
[ ! -e "$root/var/lib/tb321fu-haptics/managed-want" ] && \
  [ ! -L "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'postinst claimed ownership of a pre-existing service want'
clear_log
run_postrm remove
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'postrm removed a pre-existing user-owned service want'

for hostile_spec in \
  'foreign:/usr/lib/systemd/system/foreign.service' \
  'dangling:/nonexistent/tb321fu-haptics.service' \
  'relative:../../../usr/lib/systemd/system/tb321fu-haptics.service'; do
  hostile_name=${hostile_spec%%:*}
  hostile_target=${hostile_spec#*:}
  prepare_fixture "hostile-$hostile_name-want"
  install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
  ln -s "$hostile_target" "$root/etc/systemd/system/multi-user.target.wants/$service"
  clear_log
  expect_failure "hostile-$hostile_name-want" run_postinst configure
  [ "$(readlink "$root/etc/systemd/system/multi-user.target.wants/$service")" = "$hostile_target" ] ||
    fail "postinst modified a hostile $hostile_name systemd want"
  [ ! -e "$root/var/lib/tb321fu-haptics/managed-want" ] && \
    [ ! -L "$root/var/lib/tb321fu-haptics/managed-want" ] ||
    fail "postinst claimed a hostile $hostile_name systemd want"
  assert_log_absent "systemctl <--root=$root> <enable> <$service>"
done

prepare_fixture hostile-managed-state
install -d -m 0755 \
  "$root/etc/systemd/system/multi-user.target.wants" \
  "$root/var/lib/tb321fu-haptics"
ln -s /usr/lib/systemd/system/foreign.service \
  "$root/etc/systemd/system/multi-user.target.wants/$service"
printf '%s\n' /usr/lib/systemd/system/foreign.service > \
  "$root/var/lib/tb321fu-haptics/managed-want"
clear_log
expect_failure hostile-managed-state run_postinst configure
[ "$(cat "$root/var/lib/tb321fu-haptics/managed-want")" = \
  /usr/lib/systemd/system/foreign.service ] ||
  fail 'postinst modified hostile managed-want state'
[ "$(readlink "$root/etc/systemd/system/multi-user.target.wants/$service")" = \
  /usr/lib/systemd/system/foreign.service ] ||
  fail 'postinst modified a hostile state-owned systemd want'
clear_log
expect_failure hostile-managed-state-postrm run_postrm remove
[ -f "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'postrm removed hostile managed-want state'
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'postrm removed a hostile state-owned systemd want'

prepare_fixture oversized-managed-state
install -d -m 0755 \
  "$root/etc/systemd/system/multi-user.target.wants" \
  "$root/var/lib/tb321fu-haptics"
ln -s /usr/lib/systemd/system/tb321fu-haptics.service \
  "$root/etc/systemd/system/multi-user.target.wants/$service"
dd if=/dev/zero bs=512 count=2 2>/dev/null | tr '\000' x > \
  "$root/var/lib/tb321fu-haptics/managed-want"
clear_log
expect_failure oversized-managed-state run_postinst configure
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'postinst modified an oversized managed-want state fixture'
clear_log
expect_failure oversized-managed-state-postrm run_postrm remove
[ -f "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'postrm removed an oversized managed-want state fixture'
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'postrm modified a want after rejecting oversized state'

prepare_fixture legacy-payload
install_legacy_payload
install -d -m 0755 "$root/usr/local/bin" "$root/usr/lib/udev/rules.d"
printf '#!/bin/sh\nexit 0\n' > "$root/usr/local/bin/y700-aw86937-bind"
printf 'legacy vendor rules\n' > "$root/usr/lib/udev/rules.d/90-y700-haptics.rules"
chmod 0755 "$root/usr/local/bin/y700-aw86937-bind"
clear_log
expect_failure legacy-payload run_postinst configure
assert_log_contains "modinfo <-F> <vermagic> <$EXPECTED_MODULE_PATH>"
assert_log_absent "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_absent "systemctl <--root=$root> <enable> <$service>"
[ -e "$root/etc/systemd/system/$legacy_service" ] ||
  fail 'legacy service was modified after rejected migration'
[ -L "$root/etc/systemd/system/multi-user.target.wants/$legacy_service" ] ||
  fail 'legacy service want was modified after rejected migration'
[ -f "$root/etc/udev/rules.d/90-y700-haptics.rules" ] ||
  fail 'legacy udev rule was modified after rejected migration'
[ -f "$root/usr/lib/udev/rules.d/90-y700-haptics.rules" ] ||
  fail 'legacy vendor udev rule was modified after rejected migration'
[ -f "$root/usr/local/bin/y700-aw86937-bind" ] ||
  fail 'legacy bin helper was modified after rejected migration'
[ -f "$root/usr/local/sbin/y700-aw86937-bind" ] ||
  fail 'legacy sbin helper was modified after rejected migration'

prepare_fixture dangling-legacy-want
install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
ln -s /usr/lib/systemd/system/y700-aw86937-haptics.service \
  "$root/etc/systemd/system/multi-user.target.wants/$legacy_service"
clear_log
expect_failure dangling-legacy-want run_postinst configure
assert_log_contains "modinfo <-F> <vermagic> <$EXPECTED_MODULE_PATH>"
assert_log_absent "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_absent "systemctl <--root=$root> <enable> <$service>"
[ -L "$root/etc/systemd/system/multi-user.target.wants/$legacy_service" ] ||
  fail 'dangling legacy service want was modified after rejected migration'

clear_log
run_prerm upgrade 2
[ ! -s "$log" ] || fail 'upgrade prerm performed lifecycle actions'
clear_log
run_postrm upgrade 2
[ ! -s "$log" ] || fail 'upgrade postrm performed removal actions'

prepare_fixture upgrade
clear_log
run_postinst configure 1
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'upgrade postrm removed existing service enablement'
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"

clear_log
run_prerm remove
[ ! -s "$log" ] || fail 'offline prerm contacted a systemd manager'

rm -f -- \
  "$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko" \
  "$root/usr/lib/systemd/system/$service"
clear_log
run_postrm remove
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
[ ! -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'remove postrm left service enablement behind'
[ ! -e "$root/var/lib/tb321fu-haptics/managed-want" ] && \
  [ ! -L "$root/var/lib/tb321fu-haptics/managed-want" ] ||
  fail 'remove postrm left package-owned service-want state behind'

install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
ln -s /usr/lib/systemd/system/tb321fu-haptics.service \
  "$root/etc/systemd/system/multi-user.target.wants/$service"
clear_log
run_postrm purge
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'purge postrm removed a user-owned service want'

prepare_fixture depmod-failure
clear_log
export MOCK_DEPMOD_FAIL=1
expect_failure depmod-failure run_postinst configure
unset MOCK_DEPMOD_FAIL
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_absent "systemctl <--root=$root> <enable> <$service>"

prepare_fixture enable-failure
clear_log
export MOCK_SYSTEMCTL_ENABLE_FAIL=1
expect_failure enable-failure run_postinst configure
unset MOCK_SYSTEMCTL_ENABLE_FAIL
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
[ ! -e "$root/etc/systemd/system/multi-user.target.wants/$service" ] &&
  [ ! -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'enable failure left a newly created service want behind'

prepare_fixture partial-enable-failure
clear_log
export MOCK_SYSTEMCTL_ENABLE_FAIL_AFTER_CREATE=1
expect_failure partial-enable-failure run_postinst configure
unset MOCK_SYSTEMCTL_ENABLE_FAIL_AFTER_CREATE
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
assert_log_absent "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
[ ! -e "$root/etc/systemd/system/multi-user.target.wants/$service" ] &&
  [ ! -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'partial enable failure left a newly created service want behind'

prepare_fixture state-persistence-failure
install -d -m 0755 "$root/var/lib"
printf 'state directory blocker\n' > "$root/var/lib/tb321fu-haptics"
clear_log
expect_failure state-persistence-failure run_postinst configure
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
[ ! -e "$root/etc/systemd/system/multi-user.target.wants/$service" ] &&
  [ ! -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'state persistence failure left a newly created service want behind'
[ -f "$root/var/lib/tb321fu-haptics" ] ||
  fail 'state persistence failure removed the state-directory blocker'

prepare_fixture enable-verification-failure
clear_log
export MOCK_SYSTEMCTL_IS_ENABLED_FAIL=1
expect_failure enable-verification-failure run_postinst configure
unset MOCK_SYSTEMCTL_IS_ENABLED_FAIL
assert_log_contains "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
[ ! -e "$root/etc/systemd/system/multi-user.target.wants/$service" ] &&
  [ ! -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'enablement verification failure left a newly created service want behind'

prepare_fixture preexisting-enable-verification-failure
install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
ln -s /usr/lib/systemd/system/tb321fu-haptics.service \
  "$root/etc/systemd/system/multi-user.target.wants/$service"
clear_log
export MOCK_SYSTEMCTL_IS_ENABLED_FAIL=1
expect_failure preexisting-enable-verification-failure run_postinst configure
unset MOCK_SYSTEMCTL_IS_ENABLED_FAIL
assert_log_absent "systemctl <--root=$root> <enable> <$service>"
assert_log_contains "systemctl <--root=$root> <is-enabled> <--quiet> <$service>"
[ -L "$root/etc/systemd/system/multi-user.target.wants/$service" ] ||
  fail 'enablement verification failure removed a pre-existing service want'

prepare_fixture vermagic-failure
clear_log
export MOCK_VERMAGIC=wrong-kernel-release
expect_failure vermagic-failure run_postinst configure
unset MOCK_VERMAGIC
assert_log_contains "modinfo <-F> <vermagic> <$EXPECTED_MODULE_PATH>"
assert_log_absent depmod

prepare_fixture remove-depmod-failure
rm -f -- "$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
clear_log
export MOCK_DEPMOD_FAIL=1
expect_failure remove-depmod-failure run_postrm remove
unset MOCK_DEPMOD_FAIL
assert_log_contains "depmod <-b> <$root> <-a> <$kernel_release>"

prepare_fixture legacy-path-safety
install -d -m 0755 "$root/etc/udev/rules.d/90-y700-haptics.rules"
printf 'preserve me\n' > "$root/etc/udev/rules.d/90-y700-haptics.rules/sentinel"
clear_log
expect_failure legacy-path-safety run_postinst configure
[ -f "$root/etc/udev/rules.d/90-y700-haptics.rules/sentinel" ] ||
  fail 'legacy migration rejection modified an unexpected directory'

printf 'HAPTICS_PACKAGE_LIFECYCLE=PASS\n'
