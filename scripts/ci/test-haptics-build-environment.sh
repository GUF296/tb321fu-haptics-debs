#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-build-environment.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-build-env.XXXXXX")
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

require_failure() {
  local expected=$1
  shift
  local output status

  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "hostile build-environment fixture unexpectedly passed"
  grep -Fq -- "$expected" <<<"$output" ||
    fail "hostile build-environment fixture failed at the wrong boundary: $output"
}

probe="$tmp/producer-environment-probe.sh"
cat > "$probe" <<EOF_PROBE
#!/bin/bash
SCRIPT_DIR='$SCRIPT_DIR'
. "\$SCRIPT_DIR/common.sh"
. "\$SCRIPT_DIR/haptics-build-environment.sh"
haptics_enter_clean_environment HAPTICS_ENV_FIXTURE_CLEAN "\${BASH_SOURCE[0]}" \
  OUTPUT_DIR SOURCE_DATE_EPOCH -- "\$@"
set -euo pipefail
for name in \
  ARCH CROSS_COMPILE CC HOSTCC KCFLAGS KBUILD_OUTPUT KCONFIG_CONFIG LLVM LLVM_IAS \
  MAKEFLAGS MFLAGS MAKEFILES GNUMAKEFLAGS \
  TAR_OPTIONS GZIP GZIP_OPT XZ XZ_OPT \
  DPKG_ROOT DPKG_ADMINDIR DPKG_DEB_COMPRESSOR_TYPE DPKG_DEB_THREADS_MAX \
  COMPILER_PATH GCC_EXEC_PREFIX LIBRARY_PATH; do
  if [[ -v \$name ]]; then
    printf 'hostile environment survived: %s\n' "\$name" >&2
    exit 1
  fi
done
printf 'PATH=%s\n' "\$PATH"
printf 'LANG=%s\n' "\$LANG"
printf 'LC_ALL=%s\n' "\$LC_ALL"
printf 'TZ=%s\n' "\$TZ"
printf 'HOME=%s\n' "\$HOME"
printf 'TMPDIR=%s\n' "\$TMPDIR"
printf 'OUTPUT_DIR=%s\n' "\${OUTPUT_DIR-}"
printf 'SOURCE_DATE_EPOCH=%s\n' "\${SOURCE_DATE_EPOCH-}"
printf 'http_proxy=%s\n' "\${http_proxy-}"
printf 'https_proxy=%s\n' "\${https_proxy-}"
printf 'no_proxy=%s\n' "\${no_proxy-}"
EOF_PROBE
chmod 0755 "$probe"

probe_output=$(
  env \
    PATH=/hostile/bin:/usr/bin:/bin \
    LANG=en_US.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=Pacific/Honolulu \
    HOME="$tmp/hostile-home" \
    TMPDIR="$tmp" \
    OUTPUT_DIR="$tmp/output" \
    SOURCE_DATE_EPOCH=1234567890 \
    HTTP_PROXY=https://proxy.example.invalid:8443 \
    HTTPS_PROXY=https://proxy.example.invalid:8443 \
    NO_PROXY=localhost,127.0.0.1 \
    ARCH=x86_64 \
    CROSS_COMPILE=/tmp/hostile- \
    CC=/tmp/cc \
    HOSTCC=/tmp/hostcc \
    KCFLAGS=-include-hostile \
    KBUILD_OUTPUT=/tmp/kbuild \
    KCONFIG_CONFIG=/tmp/config \
    LLVM=1 \
    LLVM_IAS=1 \
    MAKEFLAGS=--eval=hostile \
    MFLAGS=--eval=hostile \
    MAKEFILES=/tmp/hostile.mk \
    GNUMAKEFLAGS=--eval=hostile \
    TAR_OPTIONS=--checkpoint-action=exec=hostile \
    GZIP=-9 \
    GZIP_OPT=-9 \
    XZ=/tmp/xz \
    XZ_OPT=-T0 \
    DPKG_ROOT=/tmp/dpkg-root \
    DPKG_ADMINDIR=/tmp/dpkg-admin \
    DPKG_DEB_COMPRESSOR_TYPE=gzip \
    DPKG_DEB_THREADS_MAX=99 \
    COMPILER_PATH=/tmp/compiler \
    GCC_EXEC_PREFIX=/tmp/gcc \
    LIBRARY_PATH=/tmp/library \
    /bin/bash "$probe"
)

for expected in \
  "PATH=$HAPTICS_BUILD_PATH" \
  LANG=C \
  LC_ALL=C \
  TZ=UTC \
  "HOME=$HAPTICS_BUILD_HOME" \
  "TMPDIR=$HAPTICS_BUILD_TMPDIR" \
  "OUTPUT_DIR=$tmp/output" \
  SOURCE_DATE_EPOCH=1234567890 \
  http_proxy=https://proxy.example.invalid:8443 \
  https_proxy=https://proxy.example.invalid:8443 \
  no_proxy=localhost,127.0.0.1; do
  grep -Fxq -- "$expected" <<<"$probe_output" ||
    fail "canonical producer environment omitted: $expected"
done

require_failure 'unsupported ARCH=x86_64' \
  env ARCH=x86_64 /bin/bash "$REPO_ROOT/scripts/ci/build-tb321fu-haptics-deb.sh" --help
require_failure 'conflicting transport proxy values' \
  env http_proxy=https://one.invalid HTTP_PROXY=https://two.invalid \
    /bin/bash "$probe"

shadow_bin="$tmp/shadow-bin"
shadow_marker="$tmp/shadow-bash-ran"
bash_env_marker="$tmp/hostile-bash-env-ran"
hostile_bash_env="$tmp/hostile-bash-env.sh"
mkdir -p "$shadow_bin"
cat > "$shadow_bin/bash" <<EOF_SHADOW
#!/usr/bin/bash
printf 'shadow\n' > '$shadow_marker'
exit 97
EOF_SHADOW
cat > "$hostile_bash_env" <<EOF_BASH_ENV
printf 'bash-env\n' > '$bash_env_marker'
EOF_BASH_ENV
chmod 0755 "$shadow_bin/bash"
PATH="$shadow_bin:/usr/bin:/bin" BASH_ENV="$hostile_bash_env" \
  "$REPO_ROOT/scripts/ci/build-tb321fu-haptics-deb.sh" --help >/dev/null
[ ! -e "$shadow_marker" ] || fail "hostile PATH replaced the direct-builder interpreter"
[ ! -e "$bash_env_marker" ] || fail "direct-builder entry sourced hostile BASH_ENV"
require_failure 'invalid HAPTICS_PRODUCER_COMMIT' \
  env PATH="$shadow_bin:/usr/bin:/bin" BASH_ENV="$hostile_bash_env" \
    "$REPO_ROOT/scripts/ci/build-tb321fu-haptics-deb-from-kernel-sdk.sh"
[ ! -e "$shadow_marker" ] || fail "hostile PATH replaced the SDK-wrapper interpreter"
[ ! -e "$bash_env_marker" ] || fail "SDK-wrapper entry sourced hostile BASH_ENV"

haptics_capture_build_tools
[ "$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256" = \
  4ff7d79a3d0f3513ccb2a58ee6ba68a066c5c75079b17235721be911cf7fcfb5 ] ||
  fail "environment-policy digest does not bind the reviewed metadata contract"
policy_output=$(haptics_build_environment_policy)
for policy_line in \
  'source-date-epoch=explicit,range=0..15032385535,filesystem-roundtrip-required' \
  'tool-metadata=target:regular-file,mode-0755,nlink-1;command:regular-file-mode-0755-or-symlink-mode-0777,nlink-1;under-/usr-or-/bin-or-/sbin:uid-0,gid-0' \
  'tool-identity=absolute-command-path,absolute-realpath,sha256,version,target-and-command-mode-uid-gid-nlink-type,pre-and-post-use-verification'; do
  [ "$(grep -Fxc -- "$policy_line" <<<"$policy_output")" -eq 1 ] ||
    fail "environment policy omits the exact metadata contract: $policy_line"
done
[[ $HAPTICS_BUILD_TOOLSET_SHA256 =~ ^[0-9a-f]{64}$ ]] ||
  fail "build-toolset digest is not SHA-256"
expected_build_tool_count=${#HAPTICS_REQUIRED_BUILD_TOOLS[@]}
[ "$expected_build_tool_count" -eq 69 ] ||
  fail "build-tool inventory does not contain the exact 69-tool contract"
[ "${#HAPTICS_BUILD_TOOL_RECORDS[@]}" -eq "${#HAPTICS_REQUIRED_BUILD_TOOLS[@]}" ] ||
  fail "build-tool inventory is incomplete"
for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
  command_path=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[$name]}
  path=${HAPTICS_BUILD_TOOL_PATHS[$name]}
  case "$command_path" in /*) ;; *) fail "build-tool command path is not absolute: $name" ;; esac
  [ -e "$command_path" ] && [ -x "$command_path" ] ||
    fail "build-tool command path is not executable: $name"
  case "$path" in /*) ;; *) fail "build tool path is not absolute: $name" ;; esac
  [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] ||
    fail "build tool path is not a regular executable: $name"
  [ "$(readlink -f -- "$command_path")" = "$path" ] ||
    fail "build-tool command does not resolve to recorded target: $name"
  [[ ${HAPTICS_BUILD_TOOL_SHA256[$name]} =~ ^[0-9a-f]{64}$ ]] ||
    fail "build tool lacks a captured digest: $name"
done
tools_manifest="$tmp/HAPTICS-BUILD-TOOLS.tsv"
haptics_write_build_tools_manifest "$tools_manifest"
haptics_verify_build_tools_manifest "$tools_manifest"
cp -- "$tools_manifest" "$tmp/HAPTICS-BUILD-TOOLS.mutated.tsv"
printf 'tool\tforged\t/usr/bin/false\t/usr/bin/false\t%s\tforged\n' \
  0000000000000000000000000000000000000000000000000000000000000000 >> \
  "$tmp/HAPTICS-BUILD-TOOLS.mutated.tsv"
require_failure 'build-tools manifest has an unexpected line count' \
  haptics_verify_build_tools_manifest "$tmp/HAPTICS-BUILD-TOOLS.mutated.tsv"

kbuild_tool_path_fixture="$tmp/kbuild-tool-path"
haptics_prepare_kbuild_tool_path "$kbuild_tool_path_fixture"
haptics_verify_kbuild_tool_path "$kbuild_tool_path_fixture"
[ "$(stat -c '%a' -- "$kbuild_tool_path_fixture")" = 700 ] ||
  fail "private Kbuild tool path fixture is not mode 0700"
[ "$(find "$kbuild_tool_path_fixture" -mindepth 1 -maxdepth 1 -type l -printf '.\n' | wc -l)" \
  -eq "$expected_build_tool_count" ] ||
  fail "private Kbuild tool path fixture does not match the captured tool count"
for generator in flex bison m4; do
  [ "$(PATH="$kbuild_tool_path_fixture" command -v -- "$generator")" = \
    "$kbuild_tool_path_fixture/$generator" ] ||
    fail "private Kbuild tool path does not resolve required generator: $generator"
done
[ "$(basename -- "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[modinfo]}")" = modinfo ] ||
  fail "captured modinfo invocation path does not preserve argv0"
haptics_run_isolated_tool modinfo --version >/dev/null ||
  fail "captured modinfo invocation path is not executable"

tampered_tool=xargs
rm -- "$kbuild_tool_path_fixture/$tampered_tool"
ln -s -- "${HAPTICS_BUILD_TOOL_PATHS[bash]}" "$kbuild_tool_path_fixture/$tampered_tool"
require_failure "private haptics Kbuild tool link target changed: $tampered_tool" \
  haptics_verify_kbuild_tool_path "$kbuild_tool_path_fixture"
rm -- "$kbuild_tool_path_fixture/$tampered_tool"
ln -s -- "${HAPTICS_BUILD_TOOL_PATHS[$tampered_tool]}" "$kbuild_tool_path_fixture/$tampered_tool"
haptics_verify_kbuild_tool_path "$kbuild_tool_path_fixture"

export MAKEFILES=/tmp/hostile.mk
export GNUMAKEFLAGS=--eval=hostile
export TAR_OPTIONS=--checkpoint-action=exec=hostile
export GZIP=-9
export XZ_OPT=-T0
export DPKG_ROOT=/tmp/dpkg-root
isolated_environment=$(haptics_run_isolated_tool env)
for forbidden in MAKEFILES GNUMAKEFLAGS TAR_OPTIONS GZIP XZ_OPT DPKG_ROOT; do
  if grep -q "^$forbidden=" <<<"$isolated_environment"; then
    fail "isolated external-tool invocation inherited $forbidden"
  fi
done
for expected in \
  "PATH=$HAPTICS_BUILD_PATH" \
  LANG=C \
  LC_ALL=C \
  TZ=UTC \
  "HOME=$HAPTICS_BUILD_HOME" \
  "TMPDIR=$HAPTICS_BUILD_TMPDIR"; do
  grep -Fxq -- "$expected" <<<"$isolated_environment" ||
    fail "isolated external-tool invocation omitted: $expected"
done

kernel_make_fixture="$tmp/kernel-make-function.sh"
awk '
  /^kernel_make\(\)/ { emit = 1 }
  emit { print }
  emit && /^}$/ { exit }
' "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" > "$kernel_make_fixture"
[ -s "$kernel_make_fixture" ] || fail "could not extract isolated kernel_make"
fake_make="$tmp/fake-make"
cat > "$fake_make" <<'EOF_FAKE_MAKE'
#!/bin/sh
out=
args=
status=0
for argument in "$@"; do
  case "$argument" in
    PROBE_OUTPUT=*) out=${argument#PROBE_OUTPUT=} ;;
    PROBE_ARGS=*) args=${argument#PROBE_ARGS=} ;;
    PROBE_STATUS=*) status=${argument#PROBE_STATUS=} ;;
  esac
done
[ -n "$out" ] && [ -n "$args" ] || exit 91
/usr/bin/env > "$out"
printf '%s\n' "$@" > "$args"
exit "$status"
EOF_FAKE_MAKE
chmod 0755 "$fake_make"
original_haptics_verify_build_tools_unchanged=$(
  declare -f haptics_verify_build_tools_unchanged
)
build_tool_verification_log="$tmp/kernel-make.build-tool-verifications"
: > "$build_tool_verification_log"
haptics_verify_build_tools_unchanged() {
  [ "$#" -eq 1 ] ||
    fail "kernel_make called build-tool verification with an invalid phase"
  printf '%s\n' "$1" >> "$build_tool_verification_log"
}
. "$kernel_make_fixture"
HAPTICS_BUILD_TOOL_PATHS[make]=$fake_make
HAPTICS_BUILD_TOOL_COMMAND_PATHS[make]=$fake_make
haptics_kbuild_path="$tmp/kernel-make-kbuild-tools"
haptics_prepare_kbuild_tool_path "$haptics_kbuild_path"
kernel_source_root="$tmp/kernel-source"
KERNEL_GIT_DIR=
SOURCE_DATE_EPOCH=13579
kernel_release=7.1.1-00009-g570b90203d97
kernel_kbuild_timestamp='2026-07-22 20:36:37 UTC'
kernel_kbuild_user=tb321fu-ci
kernel_kbuild_host=tb321fu-builder
kernel_kbuild_version=1
kernel_bundle_id=3333333333333333333333333333333333333333333333333333333333333333
kernel_toolchain_manifest_path=
mkdir -p "$kernel_source_root"
export ARCH=x86_64
export CROSS_COMPILE=/tmp/hostile-
export CC=/tmp/hostile-cc
export HOSTCC=/tmp/hostile-hostcc
export KBUILD_OUTPUT=/tmp/hostile-output
export KCONFIG_CONFIG=/tmp/hostile-config
export KERNELRELEASE=hostile-environment-release
export KBUILD_BUILD_TIMESTAMP='hostile environment timestamp'
export KBUILD_BUILD_USER=hostile-environment-user
export KBUILD_BUILD_HOST=hostile-environment-host
export KBUILD_BUILD_VERSION=999
kernel_make \
  "PROBE_OUTPUT=$tmp/kernel-make.environment" \
  "PROBE_ARGS=$tmp/kernel-make.arguments" \
  KERNELRELEASE=hostile-caller-release \
  KBUILD_BUILD_TIMESTAMP='hostile caller timestamp' \
  KBUILD_BUILD_USER=hostile-caller-user \
  KBUILD_BUILD_HOST=hostile-caller-host \
  KBUILD_BUILD_VERSION=998 \
  ARCH=x86_64 \
  CROSS_COMPILE=/tmp/hostile-caller- \
  CONFIG_SHELL=/tmp/hostile-caller-config-shell \
  SHELL=/tmp/hostile-caller-shell \
  HOSTCC=/tmp/hostile-caller-hostcc \
  HOSTAS=/tmp/hostile-caller-hostas \
  HOSTLD=/tmp/hostile-caller-hostld \
  HOSTAR=/tmp/hostile-caller-hostar \
  CC=/tmp/hostile-caller-cc \
  CPP=/tmp/hostile-caller-cpp \
  AS=/tmp/hostile-caller-as \
  LD=/tmp/hostile-caller-ld \
  AR=/tmp/hostile-caller-ar \
  NM=/tmp/hostile-caller-nm \
  OBJCOPY=/tmp/hostile-caller-objcopy \
  OBJDUMP=/tmp/hostile-caller-objdump \
  READELF=/tmp/hostile-caller-readelf \
  STRIP=/tmp/hostile-caller-strip
set +e
kernel_make \
  "PROBE_OUTPUT=$tmp/kernel-make-failure.environment" \
  "PROBE_ARGS=$tmp/kernel-make-failure.arguments" \
  PROBE_STATUS=37
kernel_make_failure_status=$?
set -e
[ "$kernel_make_failure_status" -eq 37 ] ||
  fail "kernel_make did not preserve the simulated make failure"
mapfile -t build_tool_verification_phases < "$build_tool_verification_log"
[ "${#build_tool_verification_phases[@]}" -eq 4 ] ||
  fail "kernel_make did not verify recorded build tools before and after every make"
for index in 0 2; do
  case "${build_tool_verification_phases[$index]}" in
    before*) ;;
    *) fail "kernel_make build-tool verification is missing before make" ;;
  esac
done
for index in 1 3; do
  case "${build_tool_verification_phases[$index]}" in
    after*) ;;
    *) fail "kernel_make build-tool verification is missing after make" ;;
  esac
done
eval "$original_haptics_verify_build_tools_unchanged"
for forbidden in \
  ARCH CROSS_COMPILE CC HOSTCC KBUILD_OUTPUT KCONFIG_CONFIG \
  KERNELRELEASE KBUILD_BUILD_TIMESTAMP KBUILD_BUILD_USER \
  KBUILD_BUILD_HOST KBUILD_BUILD_VERSION \
  MAKEFILES GNUMAKEFLAGS TAR_OPTIONS GZIP XZ_OPT DPKG_ROOT; do
  if grep -q "^$forbidden=" "$tmp/kernel-make.environment"; then
    fail "isolated kernel_make inherited $forbidden"
  fi
done
locked_dash=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[dash]}
case "$locked_dash" in
  /*) ;;
  *) fail "recorded dash path is not absolute: $locked_dash" ;;
esac
for expected in \
  "PATH=$haptics_kbuild_path" \
  LANG=C \
  LC_ALL=C \
  TZ=UTC \
  SOURCE_DATE_EPOCH=13579 \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  "CONFIG_SHELL=$locked_dash" \
  "SHELL=$locked_dash"; do
  grep -Fxq -- "$expected" "$tmp/kernel-make.environment" ||
    fail "isolated kernel_make omitted environment contract: $expected"
done
expected_make_arguments=(
  "KERNELRELEASE=$kernel_release" \
  "KBUILD_BUILD_TIMESTAMP=$kernel_kbuild_timestamp" \
  "KBUILD_BUILD_USER=$kernel_kbuild_user" \
  "KBUILD_BUILD_HOST=$kernel_kbuild_host" \
  "KBUILD_BUILD_VERSION=$kernel_kbuild_version" \
  ARCH=arm64 \
  CROSS_COMPILE= \
  "CONFIG_SHELL=$locked_dash" \
  "SHELL=$locked_dash" \
  "HOSTCC=$haptics_kbuild_path/gcc" \
  "HOSTAS=$haptics_kbuild_path/as" \
  "HOSTLD=$haptics_kbuild_path/ld" \
  "HOSTAR=$haptics_kbuild_path/ar" \
  "CC=$haptics_kbuild_path/aarch64-linux-gnu-gcc" \
  "CPP=$haptics_kbuild_path/aarch64-linux-gnu-gcc -E" \
  "AS=$haptics_kbuild_path/aarch64-linux-gnu-as" \
  "LD=$haptics_kbuild_path/aarch64-linux-gnu-ld" \
  "AR=$haptics_kbuild_path/aarch64-linux-gnu-ar" \
  "NM=$haptics_kbuild_path/aarch64-linux-gnu-nm" \
  "OBJCOPY=$haptics_kbuild_path/aarch64-linux-gnu-objcopy" \
  "OBJDUMP=$haptics_kbuild_path/aarch64-linux-gnu-objdump" \
  "READELF=$haptics_kbuild_path/aarch64-linux-gnu-readelf" \
  "STRIP=$haptics_kbuild_path/aarch64-linux-gnu-strip"
)
for expected in "${expected_make_arguments[@]}"; do
  grep -Fxq -- "$expected" "$tmp/kernel-make.arguments" ||
    fail "isolated kernel_make omitted fixed command argument: $expected"
done
for expected in "${expected_make_arguments[@]}"; do
  key=${expected%%=*}
  read -r count actual < <(
    awk -F= -v key="$key" \
      '$1 == key { count++; value = $0 } END { print count + 0, value }' \
      "$tmp/kernel-make.arguments"
  )
  [ "$count" -eq 2 ] ||
    fail "fixed make assignment does not have exactly one caller and one canonical value: $key"
  [ "$actual" = "$expected" ] ||
    fail "caller-controlled make assignment overrode verified value: $key"
done
HAPTICS_BUILD_TOOL_COMMAND_PATHS[make]=$(haptics_resolve_build_tool_command make)
HAPTICS_BUILD_TOOL_PATHS[make]=$(haptics_resolve_build_tool make)

deb_fixture="$tmp/deb-fixture"
mkdir -p "$deb_fixture/DEBIAN" "$deb_fixture/usr/share/tb321fu-fixture"
cat > "$deb_fixture/DEBIAN/control" <<'EOF_DEB_CONTROL'
Package: tb321fu-build-env-fixture
Version: 1
Architecture: all
Maintainer: TB321FU fixture <fixture@example.invalid>
Description: deterministic build-environment fixture
EOF_DEB_CONTROL
printf 'fixture\n' > "$deb_fixture/usr/share/tb321fu-fixture/payload"
find "$deb_fixture" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
for output in "$tmp/fixture-a.deb" "$tmp/fixture-b.deb"; do
  haptics_run_isolated_tool dpkg-deb \
    --build --root-owner-group --uniform-compression --threads-max=1 \
    -Zxz -z6 "$deb_fixture" "$output" >/dev/null
done
cmp -s "$tmp/fixture-a.deb" "$tmp/fixture-b.deb" ||
  fail "fixed dpkg-deb policy did not produce byte-identical fixture packages"

(
  fixture_target="$tmp/fixture-initial-target-mode"
  cp -- /usr/bin/true "$fixture_target"
  chmod 0750 "$fixture_target"
  require_failure 'build-tool target metadata is unsafe: fixture' \
    haptics_record_build_tool fixture "$fixture_target"
)
(
  fixture_target="$tmp/fixture-initial-target-type"
  mkdir -m 0755 -- "$fixture_target"
  require_failure 'build tool is not an absolute regular executable: fixture' \
    haptics_record_build_tool fixture "$fixture_target"
)
(
  fixture_target="$tmp/fixture-initial-target-nlink"
  fixture_target_link="$tmp/fixture-initial-target-nlink-copy"
  cp -- /usr/bin/true "$fixture_target"
  chmod 0755 "$fixture_target"
  ln -- "$fixture_target" "$fixture_target_link"
  require_failure 'build-tool target metadata is unsafe: fixture' \
    haptics_record_build_tool fixture "$fixture_target"
)
(
  fixture_target="$tmp/fixture-initial-command-nlink-target"
  fixture_command="$tmp/fixture-initial-command-nlink"
  fixture_command_link="$tmp/fixture-initial-command-nlink-copy"
  cp -- /usr/bin/true "$fixture_target"
  chmod 0755 "$fixture_target"
  ln -s -- "$fixture_target" "$fixture_command"
  ln -P -- "$fixture_command" "$fixture_command_link"
  require_failure 'build-tool command metadata is unsafe: fixture' \
    haptics_record_build_tool fixture "$fixture_command"
)

require_failure 'build-tool command metadata is unsafe: fixture' \
  haptics_require_build_tool_metadata fixture command "$tmp/fixture-command-mode" \
  '1:2:3:4:755:1000:1000:1:symbolic link'
require_failure 'build-tool command metadata is unsafe: fixture' \
  haptics_require_build_tool_metadata fixture command "$tmp/fixture-command-type" \
  '1:2:3:4:777:1000:1000:1:directory'
require_failure 'build-tool command metadata is unsafe: fixture' \
  haptics_require_build_tool_metadata fixture command "$tmp/fixture-command-nlink" \
  '1:2:3:4:777:1000:1000:2:symbolic link'

for role in target command; do
  case "$role" in
    target) safe_mode=755; safe_type='regular file' ;;
    command) safe_mode=777; safe_type='symbolic link' ;;
  esac
  for system_path in /usr/bin/fixture /bin/fixture /sbin/fixture; do
    require_failure "system build-tool $role is not root-owned: fixture" \
      haptics_require_build_tool_metadata fixture "$role" "$system_path" \
      "1:2:3:4:$safe_mode:1:0:1:$safe_type"
    require_failure "system build-tool $role is not root-owned: fixture" \
      haptics_require_build_tool_metadata fixture "$role" "$system_path" \
      "1:2:3:4:$safe_mode:0:1:1:$safe_type"
  done
done

(
  fixture_target="$tmp/fixture-target"
  fixture_command="$tmp/fixture-command"
  cp -- /usr/bin/true "$fixture_target"
  chmod 0755 "$fixture_target"
  ln -s -- "$fixture_target" "$fixture_command"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  haptics_record_build_tool fixture "$fixture_command"
  printf 'drift\n' >> "$fixture_target"
  require_failure 'build-tool target state changed after fixture use: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after fixture use'
)
(
  fixture_true="$tmp/fixture-command-true"
  fixture_false="$tmp/fixture-command-false"
  fixture_command="$tmp/fixture-retarget-command"
  cp -- /usr/bin/true "$fixture_true"
  cp -- /usr/bin/false "$fixture_false"
  chmod 0755 "$fixture_true" "$fixture_false"
  ln -s -- "$fixture_true" "$fixture_command"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  haptics_record_build_tool fixture "$fixture_command"
  rm -- "$fixture_command"
  ln -s -- "$fixture_false" "$fixture_command"
  require_failure 'build-tool command path changed after fixture retarget: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after fixture retarget'
)
(
  fixture_target="$tmp/fixture-metadata-target"
  fixture_command="$tmp/fixture-metadata-command"
  fixture_target_link="$tmp/fixture-metadata-target-link"
  fixture_command_link="$tmp/fixture-metadata-command-link"
  cp -- /usr/bin/true "$fixture_target"
  chmod 0755 "$fixture_target"
  ln -s -- "$fixture_target" "$fixture_command"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  haptics_record_build_tool fixture "$fixture_command"

  chmod 4755 "$fixture_target"
  require_failure 'build-tool target state changed after setuid drift: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after setuid drift'
  chmod 0755 "$fixture_target"

  chmod 0775 "$fixture_target"
  require_failure 'build-tool target state changed after writable-mode drift: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after writable-mode drift'
  chmod 0755 "$fixture_target"

  ln -- "$fixture_target" "$fixture_target_link"
  require_failure 'build-tool target state changed after target link-count drift: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after target link-count drift'
  rm -- "$fixture_target_link"

  ln -P -- "$fixture_command" "$fixture_command_link"
  require_failure 'build-tool command path changed after command link-count drift: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after command link-count drift'
)
(
  fixture_target="$tmp/fixture-capture-target"
  cat > "$fixture_target" <<'EOF_MUTATING_TARGET'
#!/bin/bash
if [ "${1:-}" = --version ]; then
  printf '\n# capture drift\n' >> "$0"
fi
printf 'fixture target 1.0\n'
EOF_MUTATING_TARGET
  chmod 0755 "$fixture_target"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  require_failure 'build-tool target changed while it was captured: fixture' \
    haptics_record_build_tool fixture "$fixture_target"
)
(
  fixture_target="$tmp/fixture-capture-same-state-target"
  cat > "$fixture_target" <<'EOF_SAME_STATE_TARGET'
#!/bin/bash
if [ "${1:-}" = --version ]; then
  original_mtime=$(/usr/bin/stat -c '%Y' -- "$0")
  original_size=$(/usr/bin/stat -c '%s' -- "$0")
  printf 'B' | /usr/bin/dd of="$0" bs=1 seek=$((original_size - 2)) \
    conv=notrunc status=none
  /usr/bin/touch -d "@$original_mtime" -- "$0"
fi
printf 'fixture target 1.0\n'
# A
EOF_SAME_STATE_TARGET
  chmod 0755 "$fixture_target"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  require_failure 'build-tool target bytes changed while it was captured: fixture' \
    haptics_record_build_tool fixture "$fixture_target"
)
(
  fixture_original="$tmp/fixture-capture-command-original"
  fixture_next="$tmp/fixture-capture-command-next"
  fixture_command="$tmp/fixture-capture-command"
  cat > "$fixture_original" <<EOF_MUTATING_COMMAND
#!/bin/bash
if [ "\${1:-}" = --version ]; then
  /usr/bin/rm -- "\$0"
  /usr/bin/ln -s -- "$fixture_next" "\$0"
fi
printf 'fixture command 1.0\n'
EOF_MUTATING_COMMAND
  printf '#!/bin/bash\nprintf "fixture next 1.0\\n"\n' > "$fixture_next"
  chmod 0755 "$fixture_original" "$fixture_next"
  ln -s -- "$fixture_original" "$fixture_command"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  require_failure 'build-tool command changed while it was captured: fixture' \
    haptics_record_build_tool fixture "$fixture_command"
)
(
  fixture_target="$tmp/fixture-disappear-target"
  fixture_command="$tmp/fixture-disappear-command"
  cp -- /usr/bin/true "$fixture_target"
  chmod 0755 "$fixture_target"
  ln -s -- "$fixture_target" "$fixture_command"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  haptics_record_build_tool fixture "$fixture_command"
  rm -- "$fixture_command"
  require_failure 'build-tool command is no longer executable after fixture disappearance: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_command" 'after fixture disappearance'
)

promotion_source="$tmp/promotion-source"
promotion_target="$tmp/promotion-target"
mkdir -p "$promotion_source"
printf 'candidate\n' > "$promotion_source/payload"
haptics_promote_directory_no_clobber "$promotion_source" "$promotion_target"
[ ! -e "$promotion_source" ] && [ ! -L "$promotion_source" ] &&
  [ "$(cat "$promotion_target/payload")" = candidate ] ||
  fail "haptics no-clobber promotion did not move the exact candidate"

blocked_source="$tmp/blocked-source"
blocked_target="$tmp/blocked-target"
mkdir -p "$blocked_source" "$blocked_target"
printf 'candidate\n' > "$blocked_source/payload"
printf 'foreign\n' > "$blocked_target/payload"
require_failure 'refusing existing haptics output target' \
  haptics_promote_directory_no_clobber "$blocked_source" "$blocked_target"
[ "$(cat "$blocked_source/payload")" = candidate ] &&
  [ "$(cat "$blocked_target/payload")" = foreign ] ||
  fail "blocked haptics promotion modified the candidate or foreign target"

build_module_path_fixture() {
  local root=$1
  local map_module=$2
  local map_kernel_source=$3
  local map_kernel_build=$4
  local module_src="$root/module-src"
  local kernel_source="$root/kernel-source"
  local kernel_build="$root/kernel-build"
  local -a path_maps=()

  mkdir -p "$module_src" "$kernel_source" "$kernel_build"
  printf '%s\n' \
    '#define SOURCE_VALUE 17' \
    'static const char fixture_source_path[] __attribute__((used)) = __FILE__;' \
    > "$kernel_source/source-value.h"
  printf '%s\n' \
    '#define BUILD_VALUE 25' \
    'static const char fixture_build_path[] __attribute__((used)) = __FILE__;' \
    > "$kernel_build/build-value.h"
  cat > "$module_src/module.c" <<EOF_MODULE_PATH_FIXTURE
#include "$kernel_source/source-value.h"
#include "$kernel_build/build-value.h"
int fixture_value(void) { return SOURCE_VALUE + BUILD_VALUE; }
EOF_MODULE_PATH_FIXTURE
  if [ "$map_module" = 1 ]; then
    path_maps+=(
      "-fdebug-prefix-map=$module_src=/usr/src/tb321fu-haptics"
      "-ffile-prefix-map=$module_src=/usr/src/tb321fu-haptics"
      "-fmacro-prefix-map=$module_src=/usr/src/tb321fu-haptics"
    )
  fi
  if [ "$map_kernel_source" = 1 ]; then
    path_maps+=(
      "-fdebug-prefix-map=$kernel_source=/usr/src/linux"
      "-ffile-prefix-map=$kernel_source=/usr/src/linux"
      "-fmacro-prefix-map=$kernel_source=/usr/src/linux"
    )
  fi
  if [ "$map_kernel_build" = 1 ]; then
    path_maps+=(
      "-fdebug-prefix-map=$kernel_build=/usr/lib/linux-kbuild"
      "-ffile-prefix-map=$kernel_build=/usr/lib/linux-kbuild"
      "-fmacro-prefix-map=$kernel_build=/usr/lib/linux-kbuild"
    )
  fi
  (
    cd "$module_src"
    "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[aarch64-linux-gnu-gcc]}" \
      -g -O0 "${path_maps[@]}" -c module.c -o module.o
  )
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[aarch64-linux-gnu-ld]}" \
    -r --build-id=sha1 -o "$module_src/module.ko" "$module_src/module.o"
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[aarch64-linux-gnu-strip]}" \
    --strip-unneeded "$module_src/module.ko"
}

require_distinct_module_path_fixtures() {
  local label=$1 left=$2 right=$3

  if cmp -s "$left/module-src/module.ko" "$right/module-src/module.ko"; then
    fail "external-module build-id fixture is insensitive to $label"
  fi
}

build_module_path_fixture "$tmp/build-id-unmapped-a" 0 0 0
build_module_path_fixture "$tmp/build-id-unmapped-b" 0 0 0
require_distinct_module_path_fixtures \
  'distinct unmapped roots' \
  "$tmp/build-id-unmapped-a" "$tmp/build-id-unmapped-b"

build_module_path_fixture "$tmp/build-id-mapped-a" 1 1 1
build_module_path_fixture "$tmp/build-id-mapped-b" 1 1 1
cmp -s \
  "$tmp/build-id-mapped-a/module-src/module.ko" \
  "$tmp/build-id-mapped-b/module-src/module.ko" ||
  fail "external-module path maps do not produce a stable stripped build-id"
for fixture_root in "$tmp/build-id-mapped-a" "$tmp/build-id-mapped-b"; do
  for random_root in \
    "$fixture_root/module-src" \
    "$fixture_root/kernel-source" \
    "$fixture_root/kernel-build"; do
    if grep -aFq -- "$random_root" "$fixture_root/module-src/module.o" ||
        grep -aFq -- "$random_root" "$fixture_root/module-src/module.ko"; then
      fail "mapped external-module fixture retains a random root: $random_root"
    fi
  done
  for fixed_root in \
    /usr/src/tb321fu-haptics \
    /usr/src/linux/source-value.h \
    /usr/lib/linux-kbuild/build-value.h; do
    grep -aFq -- "$fixed_root" "$fixture_root/module-src/module.o" ||
      fail "mapped external-module fixture omits fixed path evidence: $fixed_root"
  done
done

build_module_path_fixture "$tmp/build-id-missing-module-a" 0 1 1
build_module_path_fixture "$tmp/build-id-missing-module-b" 0 1 1
require_distinct_module_path_fixtures \
  'a missing module-source mapping group' \
  "$tmp/build-id-missing-module-a" "$tmp/build-id-missing-module-b"

build_module_path_fixture "$tmp/build-id-missing-kernel-source-a" 1 0 1
build_module_path_fixture "$tmp/build-id-missing-kernel-source-b" 1 0 1
require_distinct_module_path_fixtures \
  'a missing kernel-source mapping group' \
  "$tmp/build-id-missing-kernel-source-a" "$tmp/build-id-missing-kernel-source-b"

build_module_path_fixture "$tmp/build-id-missing-kernel-build-a" 1 1 0
build_module_path_fixture "$tmp/build-id-missing-kernel-build-b" 1 1 0
require_distinct_module_path_fixtures \
  'a missing kernel-build mapping group' \
  "$tmp/build-id-missing-kernel-build-a" "$tmp/build-id-missing-kernel-build-b"

for source in \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh"; do
  grep -Fq 'haptics_enter_clean_environment' "$source" ||
    fail "producer does not enter the clean environment: $source"
  grep -Fq 'haptics_verify_build_tools_unchanged' "$source" ||
    fail "producer does not reject post-use tool drift: $source"
done
for token in \
  '"SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"' \
  '"PATH=$haptics_kbuild_path"' \
  '"CONFIG_SHELL=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[dash]}"' \
  '"SHELL=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[dash]}"' \
  'GIT_CONFIG_NOSYSTEM=1' \
  'CROSS_COMPILE=' \
  'HOSTCC="$haptics_kbuild_path/gcc"' \
  'CC="$haptics_kbuild_path/aarch64-linux-gnu-gcc"' \
  'LD="$haptics_kbuild_path/aarch64-linux-gnu-ld"' \
  'OBJCOPY="$haptics_kbuild_path/aarch64-linux-gnu-objcopy"'; do
  grep -Fq -- "$token" "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
    fail "isolated Kbuild contract omits: $token"
done
grep -Fq -- '--build --root-owner-group --uniform-compression --threads-max=1' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
  fail "DEB packaging does not fix compressor, level, and thread count"
grep -Fq -- '-Zxz -z6' "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
  fail "DEB packaging does not fix xz level 6"
grep -Fq 'debian-compression=xz,level=6,threads=1,uniform=yes' \
  "$SCRIPT_DIR/haptics-build-environment.sh" ||
  fail "environment policy does not bind the effective DEB compression policy"
grep -Fq 'kbuild-tool-invocation=private-canonical-command-symlink-v1' \
  "$SCRIPT_DIR/haptics-build-environment.sh" ||
  fail "environment policy does not bind canonical Kbuild command names"
grep -Fq 'external-module-path-mapping=module-source,kernel-source,kernel-build-to-fixed-prefixes-v1' \
  "$SCRIPT_DIR/haptics-build-environment.sh" ||
  fail "environment policy does not bind all external-module path mappings"
grep -Fq 'command-invocation=locked-command-path-resolved-target-v1' \
  "$SCRIPT_DIR/haptics-build-environment.sh" ||
  fail "environment policy does not bind command paths separately from tool targets"
grep -Fq 'HAPTICS_BUILD_TOOLS_SCHEMA=tb321fu.haptics-build-tools/v2' \
  "$SCRIPT_DIR/haptics-build-environment.sh" ||
  fail "build-tools evidence does not use the invocation-path v2 schema"
grep -Fq 'haptics_run_isolated_tool modinfo "$module"' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
  fail "module verification does not invoke the locked modinfo command"
for token in \
  '-fdebug-prefix-map=$src=$module_prefix' \
  '-ffile-prefix-map=$src=$module_prefix' \
  '-fmacro-prefix-map=$src=$module_prefix' \
  '-fdebug-prefix-map=$kernel_source_root=$kernel_source_prefix' \
  '-ffile-prefix-map=$kernel_source_root=$kernel_source_prefix' \
  '-fmacro-prefix-map=$kernel_source_root=$kernel_source_prefix' \
  '-fdebug-prefix-map=$kernel_build_root=$kernel_build_prefix' \
  '-ffile-prefix-map=$kernel_build_root=$kernel_build_prefix' \
  '-fmacro-prefix-map=$kernel_build_root=$kernel_build_prefix' \
  'KCFLAGS="$module_path_maps"'; do
  grep -Fq -- "$token" "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
    fail "external-module path mapping omits: $token"
done
for token in \
  record_kernel_host_tools \
  'verify_kernel_host_tools_unchanged "before external module build"' \
  'verify_kernel_host_tools_unchanged "after external module build"'; do
  grep -Fq -- "$token" "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
    fail "producer omits generated kernel host-tool evidence: $token"
done
for token in \
  '/usr/bin/env -i' \
  'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
  '/bin/bash scripts/ci/build-tb321fu-haptics-deb-from-kernel-sdk.sh'; do
  grep -Fq -- "$token" "$REPO_ROOT/.github/workflows/build.yml" ||
    fail "workflow omits canonical producer boundary: $token"
done

printf 'HAPTICS_BUILD_ENVIRONMENT=PASS\n'
