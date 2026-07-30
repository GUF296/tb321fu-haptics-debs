#!/usr/bin/env bash
# Canonical producer environment and build-tool identity helpers.

HAPTICS_BUILD_ENVIRONMENT_POLICY=isolated-allowlist-v1
HAPTICS_BUILD_ENVIRONMENT_SCHEMA=tb321fu.haptics-build-environment/v1
HAPTICS_BUILD_TOOLS_SCHEMA=tb321fu.haptics-build-tools/v2
HAPTICS_BUILD_PATH=/usr/sbin:/usr/bin:/sbin:/bin
HAPTICS_BUILD_HOME=/nonexistent
HAPTICS_BUILD_TMPDIR=/tmp

HAPTICS_REQUIRED_BUILD_TOOLS=(
  bash
  dash
  env
  readlink
  realpath
  basename
  dirname
  date
  sleep
  timeout
  mktemp
  mkdir
  rm
  chmod
  cp
  mv
  ln
  cat
  find
  install
  touch
  stat
  awk
  grep
  sed
  sort
  cut
  cmp
  tee
  tr
  wc
  git
  curl
  python3
  make
  flex
  bison
  m4
  gcc
  as
  ld
  ar
  rsync
  dpkg
  dpkg-deb
  sha256sum
  aarch64-linux-gnu-gcc
  aarch64-linux-gnu-cpp
  aarch64-linux-gnu-as
  aarch64-linux-gnu-ld
  aarch64-linux-gnu-ar
  aarch64-linux-gnu-nm
  aarch64-linux-gnu-objcopy
  aarch64-linux-gnu-objdump
  aarch64-linux-gnu-readelf
  aarch64-linux-gnu-strip
  modinfo
  tar
  gzip
  xz
  sh
  bc
  getconf
  sha1sum
  uname
  head
  expr
  uniq
  xargs
)

declare -gA HAPTICS_BUILD_TOOL_PATHS=()
declare -gA HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
declare -gA HAPTICS_BUILD_TOOL_SHA256=()
declare -gA HAPTICS_BUILD_TOOL_VERSIONS=()
declare -gA HAPTICS_BUILD_TOOL_STATES=()
declare -gA HAPTICS_BUILD_TOOL_COMMAND_STATES=()
declare -ga HAPTICS_BUILD_TOOL_RECORDS=()
declare -ga HAPTICS_TRANSPORT_ENVIRONMENT=()
HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256=
HAPTICS_BUILD_TOOLSET_SHA256=

haptics_build_environment_policy() {
  printf '%s\n' \
    "schema=$HAPTICS_BUILD_ENVIRONMENT_SCHEMA" \
    "policy=$HAPTICS_BUILD_ENVIRONMENT_POLICY" \
    "path=$HAPTICS_BUILD_PATH" \
    'lang=C' \
    'lc-all=C' \
    'timezone=UTC' \
    "home=$HAPTICS_BUILD_HOME" \
    "tmpdir=$HAPTICS_BUILD_TMPDIR" \
    'producer-environment=env-i-script-allowlist' \
    'transport-environment=http_proxy,https_proxy,no_proxy' \
    'dynamic-kbuild-environment=discarded' \
    'source-date-epoch=explicit' \
    'debian-compression=xz,level=6,threads=1,uniform=yes' \
    'kbuild-path=private-locked-tool-directory-v1' \
    'kbuild-shell=absolute-locked-dash-v1' \
    'kbuild-tool-invocation=private-canonical-command-symlink-v1' \
    'kbuild-kernelrelease=verified-sdk-command-line-v1' \
    'kbuild-compile-identity=verified-bundle-or-epoch-command-line-v1' \
    'external-module-path-mapping=module-source,kernel-source,kernel-build-to-fixed-prefixes-v1' \
    'command-invocation=locked-command-path-resolved-target-v1' \
    'generated-kernel-host-tools=absolute-private-path,sha256,pre-and-post-use-verification' \
    'tool-identity=absolute-command-path,absolute-realpath,sha256,version,pre-and-post-use-verification'
}

haptics_validate_clean_input() {
  local name=$1 value=${!1-}

  [ "${#value}" -le 4096 ] || ci_die "producer input is too long: $name"
  case "$value" in
    *$'\n'*|*$'\r'*|*$'\t'*) ci_die "producer input contains control whitespace: $name" ;;
  esac
  case "$name" in
    ARCH)
      [ -z "$value" ] || [ "$value" = arm64 ] || ci_die "unsupported ARCH=$value"
      ;;
    HAPTICS_STRIP|HAPTICS_RELEASE_MODE)
      [ -z "$value" ] || [ "$value" = 0 ] || [ "$value" = 1 ] ||
        ci_die "$name must be exactly 0 or 1"
      ;;
    HAPTICS_DEB_VERSION)
      [ -z "$value" ] || [[ $value =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]] ||
        ci_die "unsafe HAPTICS_DEB_VERSION"
      ;;
    HAPTICS_PRODUCER_COMMIT|EXPECTED_HAPTICS_PRODUCER_COMMIT|KERNEL_SOURCE_COMMIT|EXPECTED_KERNEL_SOURCE_COMMIT)
      [ -z "$value" ] || [[ $value =~ ^[0-9a-f]{40}$ ]] ||
        ci_die "invalid commit input: $name"
      ;;
    HAPTICS_SOURCE_ARCHIVE_SHA256|KERNEL_SOURCE_ARCHIVE_SHA256|KERNEL_BUILD_ARCHIVE_SHA256|KERNEL_BUNDLE_METADATA_SHA256|EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256|EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256)
      [ -z "$value" ] || [[ $value =~ ^[0-9A-Fa-f]{64}$ ]] ||
        ci_die "invalid SHA-256 input: $name"
      ;;
    SOURCE_DATE_EPOCH)
      [ -z "$value" ] || [[ $value =~ ^[0-9]{1,10}$ ]] ||
        ci_die "invalid SOURCE_DATE_EPOCH"
      ;;
    KERNEL_SOURCE_REPO)
      [ -z "$value" ] || [[ $value =~ ^https://[^[:space:]]{1,2048}$ ]] ||
        ci_die "KERNEL_SOURCE_REPO must be a bounded HTTPS URL"
      ;;
    OUTPUT_DIR|HAPTICS_SOURCE_ARCHIVE|HAPTICS_SOURCE_DIR|HAPTICS_GIT_DIR|KERNEL_SOURCE_ARCHIVE|KERNEL_SOURCE_DIR|KERNEL_BUILD_ARCHIVE|KERNEL_BUILD_DIR|KERNEL_GIT_DIR|KERNEL_BUNDLE_METADATA|KERNEL_SDK_MANIFEST)
      :
      ;;
    *)
      ci_die "internal error: producer clean-environment input is not declared: $name"
      ;;
  esac
}

haptics_validate_proxy() {
  local name=$1 value=$2

  [ "${#value}" -le 2048 ] || ci_die "transport proxy is too long: $name"
  case "$value" in
    *$'\n'*|*$'\r'*|*$'\t'*|*' '*) ci_die "transport proxy contains whitespace: $name" ;;
  esac
  case "$name" in
    http_proxy|https_proxy)
      [ -z "$value" ] || [[ $value =~ ^(http|https|socks4|socks4a|socks5|socks5h)://[^[:space:]]{1,2048}$ ]] ||
        ci_die "invalid transport proxy URL: $name"
      ;;
    no_proxy)
      :
      ;;
    *) ci_die "internal error: unknown transport proxy: $name" ;;
  esac
}

haptics_collect_transport_environment() {
  local lower upper lower_value upper_value value

  HAPTICS_TRANSPORT_ENVIRONMENT=()
  for lower in http_proxy https_proxy no_proxy; do
    case "$lower" in
      http_proxy) upper=HTTP_PROXY ;;
      https_proxy) upper=HTTPS_PROXY ;;
      no_proxy) upper=NO_PROXY ;;
    esac
    lower_value=${!lower-}
    upper_value=${!upper-}
    if [ -n "$lower_value" ] && [ -n "$upper_value" ] && [ "$lower_value" != "$upper_value" ]; then
      ci_die "conflicting transport proxy values: $lower and $upper"
    fi
    value=${lower_value:-$upper_value}
    haptics_validate_proxy "$lower" "$value"
    if [ -n "$value" ]; then
      HAPTICS_TRANSPORT_ENVIRONMENT+=("$lower=$value")
    fi
  done
}

haptics_environment_is_canonical() {
  local marker=$1
  shift
  local name assignment
  local -A allowed=(
    [PATH]=1 [LANG]=1 [LC_ALL]=1 [TZ]=1 [HOME]=1 [TMPDIR]=1
    [PWD]=1 [SHLVL]=1 [_]=1
  )

  [ "${!marker-}" = 1 ] || return 1
  [ "${PATH-}" = "$HAPTICS_BUILD_PATH" ] || return 1
  [ "${LANG-}" = C ] || return 1
  [ "${LC_ALL-}" = C ] || return 1
  [ "${TZ-}" = UTC ] || return 1
  [ "${HOME-}" = "$HAPTICS_BUILD_HOME" ] || return 1
  [ "${TMPDIR-}" = "$HAPTICS_BUILD_TMPDIR" ] || return 1
  allowed[$marker]=1
  for name in "$@"; do
    allowed[$name]=1
  done
  for assignment in "${HAPTICS_TRANSPORT_ENVIRONMENT[@]}"; do
    allowed[${assignment%%=*}]=1
  done
  while IFS= read -r name; do
    [ -n "${allowed[$name]+x}" ] || return 1
  done < <(compgen -e)
}

haptics_enter_clean_environment() {
  local marker=$1 script=$2
  shift 2
  local -a input_names=() command_args=() clean_env
  local name bash_path

  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
    input_names+=("$1")
    shift
  done
  [ "$#" -gt 0 ] || ci_die "internal error: clean-environment delimiter is missing"
  shift
  command_args=("$@")

  for name in "${input_names[@]}"; do
    haptics_validate_clean_input "$name"
  done
  haptics_collect_transport_environment
  if haptics_environment_is_canonical "$marker" "${input_names[@]}"; then
    return 0
  fi

  [ -f /usr/bin/env ] && [ -x /usr/bin/env ] && [ ! -L /usr/bin/env ] ||
    ci_die "canonical /usr/bin/env is not a regular executable"
  [ -f /usr/bin/readlink ] && [ -x /usr/bin/readlink ] && [ ! -L /usr/bin/readlink ] ||
    ci_die "canonical /usr/bin/readlink is not a regular executable"
  bash_path=$(/usr/bin/readlink -f -- /bin/bash) || ci_die "cannot resolve canonical Bash"
  [ -f "$bash_path" ] && [ -x "$bash_path" ] && [ ! -L "$bash_path" ] ||
    ci_die "canonical Bash is not a regular executable"

  clean_env=(
    "PATH=$HAPTICS_BUILD_PATH"
    LANG=C
    LC_ALL=C
    TZ=UTC
    "HOME=$HAPTICS_BUILD_HOME"
    "TMPDIR=$HAPTICS_BUILD_TMPDIR"
    "$marker=1"
  )
  clean_env+=("${HAPTICS_TRANSPORT_ENVIRONMENT[@]}")
  for name in "${input_names[@]}"; do
    if [[ -v $name ]]; then
      clean_env+=("$name=${!name}")
    fi
  done
  exec /usr/bin/env -i "${clean_env[@]}" \
    "$bash_path" --noprofile --norc "$script" "${command_args[@]}"
}

haptics_resolve_build_tool_command() {
  local name=$1 candidate command_directory command_path

  candidate=$(PATH="$HAPTICS_BUILD_PATH" command -v -- "$name") ||
    ci_die "required build tool not found: $name"
  case "$candidate" in
    /*) ;;
    *) ci_die "build tool did not resolve to an absolute path: $name -> $candidate" ;;
  esac
  command_directory=$(/usr/bin/readlink -f -- "$(/usr/bin/dirname -- "$candidate")") ||
    ci_die "cannot resolve build-tool command directory: $name -> $candidate"
  command_path="$command_directory/$(/usr/bin/basename -- "$candidate")"
  case "$command_path" in
    /usr/sbin/*|/usr/bin/*|/sbin/*|/bin/*) ;;
    *) ci_die "build-tool command is outside the canonical PATH: $name -> $command_path" ;;
  esac
  [ -e "$command_path" ] && [ -x "$command_path" ] ||
    ci_die "build-tool command is not executable: $name -> $command_path"
  printf '%s\n' "$command_path"
}

haptics_resolve_build_tool() {
  local name=$1 command_path resolved

  command_path=$(haptics_resolve_build_tool_command "$name")
  resolved=$(/usr/bin/readlink -f -- "$command_path") ||
    ci_die "cannot resolve build tool: $name -> $command_path"
  case "$resolved" in
    /usr/sbin/*|/usr/bin/*|/sbin/*|/bin/*) ;;
    *) ci_die "build tool resolved outside the canonical PATH: $name -> $resolved" ;;
  esac
  [ -f "$resolved" ] && [ -x "$resolved" ] && [ ! -L "$resolved" ] ||
    ci_die "build tool is not an absolute regular executable: $name -> $resolved"
  printf '%s\n' "$resolved"
}

haptics_build_tool_version() {
  local command_path=$1 version

  version=$(/usr/bin/env -i \
    "PATH=$HAPTICS_BUILD_PATH" LANG=C LC_ALL=C TZ=UTC \
    "HOME=$HAPTICS_BUILD_HOME" "TMPDIR=$HAPTICS_BUILD_TMPDIR" \
    "$command_path" --version 2>&1 || :)
  version=${version%%$'\n'*}
  version=${version//$'\t'/ }
  version=${version//$'\r'/ }
  printf '%.240s\n' "${version:-version-unreported}"
}

haptics_record_build_tool() {
  local name=$1 command_path=$2 path digest version state command_state

  case "$command_path" in /*) ;; *) ci_die "tool fixture path is not absolute: $name" ;; esac
  [ -e "$command_path" ] && [ -x "$command_path" ] ||
    ci_die "build-tool command is not executable: $name -> $command_path"
  path=$(/usr/bin/readlink -f -- "$command_path") || ci_die "cannot resolve build tool: $name"
  [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] ||
    ci_die "build tool is not an absolute regular executable: $name -> $path"
  digest=$(/usr/bin/sha256sum -- "$path") || ci_die "cannot hash build tool: $name"
  digest=${digest%% *}
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || ci_die "invalid build-tool digest: $name"
  version=$(haptics_build_tool_version "$command_path")
  state=$(/usr/bin/stat -Lc '%d:%i:%s:%Y' -- "$path") ||
    ci_die "cannot stat build-tool target: $name"
  command_state=$(/usr/bin/stat -c '%d:%i:%s:%Y:%F' -- "$command_path") ||
    ci_die "cannot stat build-tool command: $name"
  HAPTICS_BUILD_TOOL_PATHS[$name]=$path
  HAPTICS_BUILD_TOOL_COMMAND_PATHS[$name]=$command_path
  HAPTICS_BUILD_TOOL_SHA256[$name]=$digest
  HAPTICS_BUILD_TOOL_VERSIONS[$name]=$version
  HAPTICS_BUILD_TOOL_STATES[$name]=$state
  HAPTICS_BUILD_TOOL_COMMAND_STATES[$name]=$command_state
  HAPTICS_BUILD_TOOL_RECORDS+=("tool"$'\t'"$name"$'\t'"$command_path"$'\t'"$path"$'\t'"$digest"$'\t'"$version")
}

haptics_capture_build_tools() {
  local name command_path digest_record

  HAPTICS_BUILD_TOOL_PATHS=()
  HAPTICS_BUILD_TOOL_COMMAND_PATHS=()
  HAPTICS_BUILD_TOOL_SHA256=()
  HAPTICS_BUILD_TOOL_VERSIONS=()
  HAPTICS_BUILD_TOOL_STATES=()
  HAPTICS_BUILD_TOOL_COMMAND_STATES=()
  HAPTICS_BUILD_TOOL_RECORDS=()
  for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
    command_path=$(haptics_resolve_build_tool_command "$name")
    haptics_record_build_tool "$name" "$command_path"
  done
  hash -r
  for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
    hash -p "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[$name]}" "$name"
  done
  read -r HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256 _ < <(
    haptics_build_environment_policy | /usr/bin/sha256sum
  )
  read -r HAPTICS_BUILD_TOOLSET_SHA256 _ < <(
    printf '%s\n' "${HAPTICS_BUILD_TOOL_RECORDS[@]}" | /usr/bin/sha256sum
  )
  [[ $HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256 =~ ^[0-9a-f]{64}$ ]] ||
    ci_die "cannot hash the build-environment policy"
  [[ $HAPTICS_BUILD_TOOLSET_SHA256 =~ ^[0-9a-f]{64}$ ]] ||
    ci_die "cannot hash the build-tool set"

  CI_ENV_BIN=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[env]}
  CI_GIT_BIN=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[git]}
  CI_CURL_BIN=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[curl]}
  CI_PYTHON3_BIN=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[python3]}
  CI_SHA256SUM_BIN=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[sha256sum]}
  export CI_ENV_BIN CI_GIT_BIN CI_CURL_BIN CI_PYTHON3_BIN CI_SHA256SUM_BIN

  ci_log "build environment policy: $HAPTICS_BUILD_ENVIRONMENT_POLICY ($HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256)"
  ci_log "build toolset SHA-256: $HAPTICS_BUILD_TOOLSET_SHA256"
  for digest_record in "${HAPTICS_BUILD_TOOL_RECORDS[@]}"; do
    ci_log "build tool: $digest_record"
  done
}

haptics_verify_expected_build_environment() {
  local expected_toolset=${EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256:-}
  local expected_policy=${EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256:-}

  if [ -n "$expected_toolset" ]; then
    [ "$HAPTICS_BUILD_TOOLSET_SHA256" = "${expected_toolset,,}" ] ||
      ci_die "build toolset differs from the wrapper evidence"
  fi
  if [ -n "$expected_policy" ]; then
    [ "$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256" = "${expected_policy,,}" ] ||
      ci_die "build-environment policy differs from the wrapper evidence"
  fi
}

haptics_verify_recorded_build_tool() {
  local name=$1 actual_command_path=$2 phase=$3
  local expected_command_path expected_path actual_path actual_digest
  local command_state target_state

  expected_command_path=${HAPTICS_BUILD_TOOL_COMMAND_PATHS[$name]}
  expected_path=${HAPTICS_BUILD_TOOL_PATHS[$name]}
  [ "$actual_command_path" = "$expected_command_path" ] ||
    ci_die "build-tool command path changed $phase: $name"
  [ -e "$expected_command_path" ] && [ -x "$expected_command_path" ] ||
    ci_die "build-tool command is no longer executable $phase: $name"
  command_state=$(/usr/bin/stat -c '%d:%i:%s:%Y:%F' -- "$expected_command_path") ||
    ci_die "cannot restat build-tool command $phase: $name"
  [ "$command_state" = "${HAPTICS_BUILD_TOOL_COMMAND_STATES[$name]}" ] ||
    ci_die "build-tool command path changed $phase: $name"
  actual_path=$(/usr/bin/readlink -f -- "$expected_command_path") ||
    ci_die "cannot resolve build-tool command $phase: $name"
  [ "$actual_path" = "$expected_path" ] ||
    ci_die "build-tool command target changed $phase: $name"
  [ -f "$expected_path" ] && [ -x "$expected_path" ] && [ ! -L "$expected_path" ] ||
    ci_die "build tool is no longer a regular executable $phase: $name"
  target_state=$(/usr/bin/stat -Lc '%d:%i:%s:%Y' -- "$expected_path") ||
    ci_die "cannot restat build-tool target $phase: $name"
  [ "$target_state" = "${HAPTICS_BUILD_TOOL_STATES[$name]}" ] ||
    ci_die "build-tool target state changed $phase: $name"
  actual_digest=$(/usr/bin/sha256sum -- "$expected_path") ||
    ci_die "cannot rehash build tool $phase: $name"
  actual_digest=${actual_digest%% *}
  [ "$actual_digest" = "${HAPTICS_BUILD_TOOL_SHA256[$name]}" ] ||
    ci_die "build tool bytes changed $phase: $name"
}

haptics_verify_build_tools_unchanged() {
  local phase=$1 name actual_command_path

  for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
    actual_command_path=$(haptics_resolve_build_tool_command "$name")
    haptics_verify_recorded_build_tool "$name" "$actual_command_path" "$phase"
  done
  ci_log "build tools unchanged $phase"
}

haptics_prepare_kbuild_tool_path() {
  local destination=$1 name link target

  [ ! -e "$destination" ] && [ ! -L "$destination" ] ||
    ci_die "private haptics Kbuild tool path already exists: $destination"
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[mkdir]}" -m 0700 -- "$destination"
  for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
    target=${HAPTICS_BUILD_TOOL_PATHS[$name]}
    link="$destination/$name"
    "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[ln]}" -s -- "$target" "$link"
  done
  haptics_verify_kbuild_tool_path "$destination"
}

haptics_verify_kbuild_tool_path() {
  local destination=$1 name link target resolved actual_count

  [ -d "$destination" ] && [ ! -L "$destination" ] &&
    [ "$("${HAPTICS_BUILD_TOOL_COMMAND_PATHS[stat]}" -c '%a' -- "$destination")" = 700 ] ||
    ci_die "private haptics Kbuild tool path is not a real mode-0700 directory"
  for name in "${HAPTICS_REQUIRED_BUILD_TOOLS[@]}"; do
    target=${HAPTICS_BUILD_TOOL_PATHS[$name]}
    link="$destination/$name"
    [ -L "$link" ] || ci_die "private haptics Kbuild tool link disappeared: $name"
    [ "$("${HAPTICS_BUILD_TOOL_COMMAND_PATHS[readlink]}" -- "$link")" = "$target" ] ||
      ci_die "private haptics Kbuild tool link target changed: $name"
    resolved=$("${HAPTICS_BUILD_TOOL_COMMAND_PATHS[realpath]}" -e -- "$link") ||
      ci_die "private haptics Kbuild tool link became dangling: $name"
    [ "$resolved" = "$target" ] ||
      ci_die "private haptics Kbuild tool link resolves to unexpected bytes: $name"
  done
  [ -z "$("${HAPTICS_BUILD_TOOL_COMMAND_PATHS[find]}" "$destination" \
    -mindepth 1 -maxdepth 1 ! -type l -print -quit)" ] ||
    ci_die "private haptics Kbuild tool path contains a non-symlink entry"
  actual_count=$("${HAPTICS_BUILD_TOOL_COMMAND_PATHS[find]}" "$destination" \
    -mindepth 1 -maxdepth 1 -type l -printf '.\n' | "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[wc]}" -l)
  [ "$actual_count" -eq "${#HAPTICS_REQUIRED_BUILD_TOOLS[@]}" ] ||
    ci_die "private haptics Kbuild tool path contains an unexpected entry"
}

haptics_write_build_tools_manifest() {
  local destination=$1

  [ ! -e "$destination" ] || ci_die "refusing stale build-tools manifest: $destination"
  {
    printf 'schema\t%s\n' "$HAPTICS_BUILD_TOOLS_SCHEMA"
    printf 'environment-policy\t%s\n' "$HAPTICS_BUILD_ENVIRONMENT_POLICY"
    printf 'environment-policy-sha256\t%s\n' "$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256"
    printf 'build-toolset-sha256\t%s\n' "$HAPTICS_BUILD_TOOLSET_SHA256"
    printf '%s\n' "${HAPTICS_BUILD_TOOL_RECORDS[@]}"
  } > "$destination"
  chmod 0644 "$destination"
}

haptics_promote_directory_no_clobber() {
  local source=$1 destination=$2

  [ -d "$source" ] && [ ! -L "$source" ] ||
    ci_die "haptics promotion source is not a real directory: $source"
  [ ! -e "$destination" ] && [ ! -L "$destination" ] ||
    ci_die "refusing existing haptics output target: $destination"
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[mv]}" --no-clobber -T -- "$source" "$destination" ||
    ci_die "haptics no-clobber promotion failed: $destination"
  [ ! -e "$source" ] && [ ! -L "$source" ] &&
    [ -d "$destination" ] && [ ! -L "$destination" ] ||
    ci_die "haptics no-clobber promotion did not move the exact source directory"
}

haptics_verify_build_tools_manifest() {
  local manifest=$1 index
  local -a expected=(
    "schema"$'\t'"$HAPTICS_BUILD_TOOLS_SCHEMA"
    "environment-policy"$'\t'"$HAPTICS_BUILD_ENVIRONMENT_POLICY"
    "environment-policy-sha256"$'\t'"$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256"
    "build-toolset-sha256"$'\t'"$HAPTICS_BUILD_TOOLSET_SHA256"
  ) actual=()

  [ -f "$manifest" ] && [ ! -L "$manifest" ] ||
    ci_die "build-tools manifest is not a regular file: $manifest"
  expected+=("${HAPTICS_BUILD_TOOL_RECORDS[@]}")
  mapfile -t actual < "$manifest"
  [ "${#actual[@]}" -eq "${#expected[@]}" ] ||
    ci_die "build-tools manifest has an unexpected line count"
  for index in "${!expected[@]}"; do
    [ "${actual[$index]}" = "${expected[$index]}" ] ||
      ci_die "build-tools manifest differs from captured tool evidence at line $((index + 1))"
  done
}

haptics_run_isolated_tool() {
  local name=$1
  shift
  local epoch=${SOURCE_DATE_EPOCH:-0}

  [[ $epoch =~ ^[0-9]{1,10}$ ]] || ci_die "invalid SOURCE_DATE_EPOCH for isolated tool"
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[env]}" -i \
    "PATH=$HAPTICS_BUILD_PATH" \
    LANG=C LC_ALL=C TZ=UTC \
    "HOME=$HAPTICS_BUILD_HOME" \
    "TMPDIR=$HAPTICS_BUILD_TMPDIR" \
    "SOURCE_DATE_EPOCH=$epoch" \
    "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[$name]}" "$@"
}

haptics_sha256_file() {
  local digest

  digest=$("${HAPTICS_BUILD_TOOL_COMMAND_PATHS[sha256sum]}" -- "$1") ||
    ci_die "cannot hash file: $1"
  digest=${digest%% *}
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || ci_die "invalid SHA-256 output for $1"
  printf '%s\n' "$digest"
}
