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
[[ $HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256 =~ ^[0-9a-f]{64}$ ]] ||
  fail "environment-policy digest is not SHA-256"
[[ $HAPTICS_BUILD_TOOLSET_SHA256 =~ ^[0-9a-f]{64}$ ]] ||
  fail "build-toolset digest is not SHA-256"
expected_build_tool_count=${#HAPTICS_REQUIRED_BUILD_TOOLS[@]}
[ "$expected_build_tool_count" -eq 67 ] ||
  fail "build-tool inventory does not contain the exact 67-tool contract"
[ "${#HAPTICS_BUILD_TOOL_RECORDS[@]}" -eq "${#HAPTICS_REQUIRED_BUILD_TOOLS[@]}" ] ||
  fail "build-tool inventory is incomplete"
for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
  path=${HAPTICS_BUILD_TOOL_PATHS[$name]}
  case "$path" in /*) ;; *) fail "build tool path is not absolute: $name" ;; esac
  [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] ||
    fail "build tool path is not a regular executable: $name"
  [[ ${HAPTICS_BUILD_TOOL_SHA256[$name]} =~ ^[0-9a-f]{64}$ ]] ||
    fail "build tool lacks a captured digest: $name"
done
tools_manifest="$tmp/HAPTICS-BUILD-TOOLS.tsv"
haptics_write_build_tools_manifest "$tools_manifest"
haptics_verify_build_tools_manifest "$tools_manifest"
cp -- "$tools_manifest" "$tmp/HAPTICS-BUILD-TOOLS.mutated.tsv"
printf 'tool\tforged\t/usr/bin/false\t%s\tforged\n' \
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
haptics_kbuild_path="$tmp/kernel-make-kbuild-tools"
haptics_prepare_kbuild_tool_path "$haptics_kbuild_path"
kernel_source_root="$tmp/kernel-source"
KERNEL_GIT_DIR=
SOURCE_DATE_EPOCH=13579
mkdir -p "$kernel_source_root"
export ARCH=x86_64
export CROSS_COMPILE=/tmp/hostile-
export CC=/tmp/hostile-cc
export HOSTCC=/tmp/hostile-hostcc
export KBUILD_OUTPUT=/tmp/hostile-output
export KCONFIG_CONFIG=/tmp/hostile-config
kernel_make \
  "PROBE_OUTPUT=$tmp/kernel-make.environment" \
  "PROBE_ARGS=$tmp/kernel-make.arguments"
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
  MAKEFILES GNUMAKEFLAGS TAR_OPTIONS GZIP XZ_OPT DPKG_ROOT; do
  if grep -q "^$forbidden=" "$tmp/kernel-make.environment"; then
    fail "isolated kernel_make inherited $forbidden"
  fi
done
locked_dash=${HAPTICS_BUILD_TOOL_PATHS[dash]}
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
for expected in \
  ARCH=arm64 \
  CROSS_COMPILE= \
  "CONFIG_SHELL=$locked_dash" \
  "SHELL=$locked_dash" \
  "CC=${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-gcc]}" \
  "LD=${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-ld]}" \
  "STRIP=${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-strip]}"; do
  grep -Fxq -- "$expected" "$tmp/kernel-make.arguments" ||
    fail "isolated kernel_make omitted fixed command argument: $expected"
done
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
  fixture_tool="$tmp/fixture-tool"
  cp -- /usr/bin/true "$fixture_tool"
  chmod 0755 "$fixture_tool"
  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  haptics_record_build_tool fixture "$fixture_tool"
  printf 'drift\n' >> "$fixture_tool"
  require_failure 'build tool bytes changed after fixture use: fixture' \
    haptics_verify_recorded_build_tool fixture "$fixture_tool" 'after fixture use'
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
  '"CONFIG_SHELL=${HAPTICS_BUILD_TOOL_PATHS[dash]}"' \
  '"SHELL=${HAPTICS_BUILD_TOOL_PATHS[dash]}"' \
  'GIT_CONFIG_NOSYSTEM=1' \
  'CROSS_COMPILE=' \
  'CC="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-gcc]}"' \
  'LD="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-ld]}"' \
  'OBJCOPY="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-objcopy]}"'; do
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
