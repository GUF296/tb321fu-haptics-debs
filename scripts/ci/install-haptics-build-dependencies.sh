#!/bin/bash -p
clean_environment=1
[ "${HAPTICS_APT_CLEAN_ENV:-}" = 1 ] &&
  [ "${PATH:-}" = /usr/sbin:/usr/bin:/sbin:/bin ] &&
  [ "${LANG:-}" = C ] && [ "${LC_ALL:-}" = C ] &&
  [ "${TZ:-}" = UTC ] && [ "${HOME:-}" = /root ] &&
  [ "${TMPDIR:-}" = /tmp ] || clean_environment=0
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  case "$name" in
    PATH|LANG|LC_ALL|TZ|HOME|TMPDIR|HAPTICS_APT_CLEAN_ENV|PWD|SHLVL|_) ;;
    *) clean_environment=0 ;;
  esac
done < <(/usr/bin/env -0)
if [ "$clean_environment" != 1 ]; then
  script_path=$(/usr/bin/realpath -e -- "$0") || exit 1
  exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/root TMPDIR=/tmp \
    HAPTICS_APT_CLEAN_ENV=1 \
    /bin/bash -p "$script_path" "$@"
fi
case $- in
  *p*) ;;
  *) echo 'dependency installation requires privileged Bash mode' >&2; exit 1 ;;
esac
set -euo pipefail
umask 077

work_dir=
cleanup() {
  if [ -n "$work_dir" ] && [ -d "$work_dir" ]; then
    /usr/bin/rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

prepare_reviewed_dpkg_config() {
  local config_root="$work_dir/reviewed-dpkg"

  /usr/bin/mkdir -m 0755 -p -- "$config_root/etc" \
    "$config_root/etc/dpkg.cfg.d"
  /usr/bin/chmod 0755 -- "$config_root" "$config_root/etc"
  /usr/bin/tee "$config_root/etc/dpkg.cfg" >/dev/null <<'DPKG_CFG'
# dpkg configuration file
#
# This file can contain default options for dpkg.  All command-line
# options are allowed.  Values can be specified by putting them after
# the option, separated by whitespace and/or an `=' sign.
#

# Do not enable debsig-verify by default; since the distribution is not using
# embedded signatures, debsig-verify would reject all packages.
no-debsig

# Log status changes and actions to a file.
log /var/log/dpkg.log
DPKG_CFG
  /usr/bin/chmod 0644 -- "$config_root/etc/dpkg.cfg"
  printf '%s\n' "$config_root/etc"
}

verify_private_apt_source() {
  local digest

  [ -f "$sources_file" ] && [ ! -L "$sources_file" ] &&
    [ "$(/usr/bin/stat -c '%a' -- "$sources_file")" = 644 ] || {
      echo 'private apt source is not a mode-0644 regular file' >&2
      return 1
    }
  digest=$(/usr/bin/sha256sum -- "$sources_file" | /usr/bin/cut -d' ' -f1)
  [ "$digest" = 96379d39707e38712509e7db3197cd13663a1486c0401347cbac75ffcc181f0b ] || {
    echo 'private apt source differs from the reviewed snapshot contract' >&2
    return 1
  }
}

verify_private_apt_permissions() {
  local path

  for path in \
    "$work_dir" "$source_parts" "$config_parts" "$auth_parts" \
    "$preferences_parts" "$trusted_parts" \
    "$lists" "$archives" "$cache" "$compat_dir" "$state" "$logs"; do
    [ -d "$path" ] && [ ! -L "$path" ] &&
      [ "$(/usr/bin/stat -c '%a' -- "$path")" = 755 ] || {
        echo "private apt public directory is not a real mode-0755 directory: $path" >&2
        return 1
      }
  done
  for path in "$lists/partial" "$archives/partial"; do
    [ -d "$path" ] && [ ! -L "$path" ] &&
      [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$path")" = \
        "700:$apt_partial_uid:$apt_partial_gid" ] || {
        echo "private apt partial directory has unsafe ownership or mode: $path" >&2
        return 1
      }
  done
  [ -d "$compat_private_dir" ] && [ ! -L "$compat_private_dir" ] &&
    [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$compat_private_dir")" = \
      "700:$private_uid:$private_gid" ] || {
      echo 'private compatibility-package directory has unsafe ownership or mode' >&2
      return 1
    }
}

verify_no_apt_sandbox_fallback() {
  local log=$1

  [ -f "$log" ] && [ ! -L "$log" ] &&
    [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$log")" = \
      "600:$private_uid:$private_gid" ] &&
    [ "$(/usr/bin/stat -c '%s' -- "$log")" -le 4194304 ] || {
      echo 'apt compatibility-package diagnostic log is unsafe' >&2
      return 1
    }
  if /usr/bin/grep -Fq -- 'Download is performed unsandboxed as root' "$log" ||
    /usr/bin/grep -Fq -- "couldn't be accessed by user '_apt'" "$log"; then
    echo 'apt fell back to unsandboxed root access for a compatibility package' >&2
    return 1
  fi
}

configure_private_apt_hook() {
  local hook_command=$1
  local expected_hook_script=${2:-}
  local hook_tool hook_rest hook_script

  [ -n "$hook_command" ] &&
    [ "${#hook_command}" -le 12288 ] &&
    [[ "$hook_command" != *[$'\n\r\t"\\']* ]] &&
    [[ "$hook_command" == /usr/bin/python3\ -I\ -B\ /*\ --verify-hook\ /*\ /* ]] || {
      echo 'private APT hook command is not canonical' >&2
      return 1
    }
  hook_tool=${hook_command%% *}
  [ -n "$hook_tool" ] || {
    echo 'private APT hook executable is missing' >&2
    return 1
  }
  if [ -n "$expected_hook_script" ]; then
    hook_rest=${hook_command#"/usr/bin/python3 -I -B "}
    hook_script=${hook_rest%% --verify-hook *}
    [ "$hook_script" = "$expected_hook_script" ] || {
      echo 'private APT hook is not bound to the reviewed verifier' >&2
      return 1
    }
  fi
  [ -f "$apt_config" ] && [ ! -L "$apt_config" ] &&
    [ "$(/usr/bin/stat -c '%a' -- "$apt_config")" = 600 ] || {
      echo 'private apt configuration is not a mode-0600 regular file' >&2
      return 1
    }
  if /usr/bin/grep -Eq '^(DPkg::Pre-Install-Pkgs|DPkg::Tools)' "$apt_config"; then
    echo 'private apt configuration already contains a package hook' >&2
    return 1
  fi
  {
    printf 'DPkg::Pre-Install-Pkgs { "%s"; };\n' "$hook_command"
    printf 'DPkg::Tools::options { "%s" { InfoFD "21"; Version "3"; }; };\n' \
      "$hook_tool"
  } >> "$apt_config"
  /usr/bin/chmod 0600 "$apt_config"
}

verify_private_apt_configuration() {
  local hook_command=${1:-}
  local expected_hook_script=${2:-}
  local resolved_config="$work_dir/resolved-apt-config.txt"
  local expected count hook_key hook_rest hook_script
  local -a expected_lines=(
    "Dir::State::lists \"$lists\";"
    "Dir::State::extended_states \"$extended_states\";"
    'Dir::State::status "/var/lib/dpkg/status";'
    "Dir::Cache \"$cache\";"
    "Dir::Cache::archives \"$archives\";"
    "Dir::Cache::srcpkgcache \"$srcpkgcache\";"
    "Dir::Cache::pkgcache \"$pkgcache\";"
    "Dir::Etc::sourcelist \"$sources_file\";"
    "Dir::Etc::sourceparts \"$source_parts\";"
    "Dir::Etc::main \"$empty_config\";"
    "Dir::Etc::parts \"$config_parts\";"
    "Dir::Etc::netrc \"$empty_config\";"
    "Dir::Etc::netrcparts \"$auth_parts\";"
    "Dir::Etc::preferences \"$empty_config\";"
    "Dir::Etc::preferencesparts \"$preferences_parts\";"
    'Dir::Etc::trusted "/dev/null";'
    "Dir::Etc::trustedparts \"$trusted_parts\";"
    "Dir::Log \"$logs\";"
    'Acquire::AllowInsecureRepositories "0";'
    'Acquire::AllowWeakRepositories "0";'
    'Acquire::AllowDowngradeToInsecureRepositories "0";'
    'Acquire::https::Verify-Peer "1";'
    'Acquire::https::Verify-Host "1";'
    'APT::Get::AllowUnauthenticated "0";'
    'APT::Sandbox::User "_apt";'
    'APT::Architecture "amd64";'
    'APT::Architectures:: "amd64";'
    'Dir::Bin::dpkg "/usr/bin/dpkg";'
    'Dir::Bin::planners "";'
    'Dir::Bin::planners:: "/usr/lib/apt/planners";'
    'Dir::Bin::solvers "";'
    'Dir::Bin::solvers:: "/usr/lib/apt/solvers";'
    'DPkg::ConfigurePending "1";'
    'DPkg::Path "/usr/sbin:/usr/bin:/sbin:/bin";'
    'DPkg::Run-Directory "/";'
  )
  if [ -n "$hook_command" ]; then
    if [ -n "$expected_hook_script" ]; then
      hook_rest=${hook_command#"/usr/bin/python3 -I -B "}
      hook_script=${hook_rest%% --verify-hook *}
      [ "$hook_script" = "$expected_hook_script" ] || {
        echo 'resolved APT hook is not bound to the reviewed verifier' >&2
        return 1
      }
    fi
    hook_key=${hook_command%% *}
    expected_lines+=(
      'DPkg::Pre-Install-Pkgs "";'
      "DPkg::Pre-Install-Pkgs:: \"$hook_command\";"
      'DPkg::Tools "";'
      'DPkg::Tools::options "";'
      "DPkg::Tools::options::$hook_key \"\";"
      "DPkg::Tools::options::$hook_key::InfoFD \"21\";"
      "DPkg::Tools::options::$hook_key::Version \"3\";"
    )
  fi

  [ -f "$apt_config" ] && [ ! -L "$apt_config" ] &&
    [ "$(/usr/bin/stat -c '%a' -- "$apt_config")" = 600 ] || {
      echo 'private apt configuration is not a mode-0600 regular file' >&2
      return 1
    }
  /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/root TMPDIR=/tmp \
    APT_CONFIG="$apt_config" \
    /usr/bin/apt-config dump > "$resolved_config"
  /usr/bin/chmod 0600 "$resolved_config"
  for expected in "${expected_lines[@]}"; do
    count=$(/usr/bin/grep -Fxc -- "$expected" "$resolved_config" || true)
    [ "$count" -eq 1 ] || {
      echo "private apt configuration did not resolve exactly: $expected" >&2
      /usr/bin/grep -E '^DPkg::(Pre-Install-Pkgs|Tools)' \
        "$resolved_config" >&2 || true
      return 1
    }
  done
  count=$(/usr/bin/grep -c '^APT::Architectures:: ' "$resolved_config" || true)
  [ "$count" -eq 1 ] || {
    echo 'private apt configuration did not isolate the native architecture' >&2
    return 1
  }
  count=$(/usr/bin/grep -Ec \
    '^(Dir::Bin::(dpkg|planners|solvers)(::)?|DPkg::(ConfigurePending|Path|Run-Directory)) ' \
    "$resolved_config" || true)
  [ "$count" -eq 8 ] || {
    echo 'private apt execution binary/configuration namespace is not exact' >&2
    return 1
  }
  if /usr/bin/grep -Eq \
    '^(APT::Update::[^ ]*Invoke[^ ]*|DPkg::(Pre|Post)-Invoke|DPkg::Options|Acquire::(http|https)::Proxy)(::| )' \
    "$resolved_config" ||
    { [ -z "$hook_command" ] && /usr/bin/grep -Eq \
      '^(DPkg::Pre-Install-Pkgs|DPkg::Tools)(::| )' "$resolved_config"; }; then
    echo 'private apt configuration inherited a host hook or proxy' >&2
    return 1
  fi
  if [ -n "$hook_command" ]; then
    count=$(/usr/bin/grep -Ec '^DPkg::Pre-Install-Pkgs(::)? ' "$resolved_config" || true)
    [ "$count" -eq 2 ] || {
      echo 'private apt configuration has an inexact pre-install hook set' >&2
      return 1
    }
    count=$(/usr/bin/grep -c '^DPkg::Tools' "$resolved_config" || true)
    [ "$count" -eq 5 ] || {
      echo 'private apt configuration has an inexact hook protocol set' >&2
      return 1
    }
  fi
}

prepare_private_apt_state() {
  local enable_apt_downloads=$1
  case "$enable_apt_downloads" in
    0|1) ;;
    *) echo 'invalid private apt state mode' >&2; exit 1 ;;
  esac
  sources_file="$work_dir/ubuntu-snapshot.sources"
  apt_config="$work_dir/apt.conf"
  empty_config="$work_dir/empty.conf"
  source_parts="$work_dir/source-parts"
  config_parts="$work_dir/config-parts"
  auth_parts="$work_dir/auth-parts"
  preferences_parts="$work_dir/preferences-parts"
  trusted_parts="$work_dir/trusted-parts"
  lists="$work_dir/lists"
  archives="$work_dir/cache/archives"
  cache="$work_dir/cache"
  compat_dir="$work_dir/compat"
  compat_private_dir="$work_dir/compat-private"
  state="$work_dir/state"
  logs="$work_dir/log"
  extended_states="$state/extended_states"
  srcpkgcache="$cache/srcpkgcache.bin"
  pkgcache="$cache/pkgcache.bin"

  /usr/bin/chmod 0755 "$work_dir"
  /usr/bin/mkdir -p \
    "$source_parts" "$config_parts" "$auth_parts" \
    "$preferences_parts" "$trusted_parts" \
    "$lists/partial" "$archives/partial" "$compat_dir" \
    "$compat_private_dir" "$state" "$logs"
  /usr/bin/chmod 0755 \
    "$source_parts" "$config_parts" "$auth_parts" \
    "$preferences_parts" "$trusted_parts" \
    "$lists" "$archives" "$cache" "$compat_dir" "$state" "$logs"
  /usr/bin/chmod 0700 \
    "$lists/partial" "$archives/partial" "$compat_private_dir"
  private_uid=$(/usr/bin/id -u)
  private_gid=$(/usr/bin/id -g)
  if [ "$enable_apt_downloads" = 1 ]; then
    /usr/bin/chown _apt:root "$lists/partial" "$archives/partial"
    apt_partial_uid=$(/usr/bin/id -u _apt)
    apt_partial_gid=0
  else
    apt_partial_uid=$private_uid
    apt_partial_gid=$private_gid
  fi
  verify_private_apt_permissions
  : > "$empty_config"
  /usr/bin/chmod 0644 "$empty_config"
  {
    echo 'Types: deb'
    printf 'URIs: %s\n' "$snapshot"
    echo 'Suites: noble noble-updates noble-security'
    echo 'Components: main'
    echo 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg'
    echo 'Check-Valid-Until: no'
  } > "$sources_file"
  /usr/bin/chmod 0644 "$sources_file"
  verify_private_apt_source
  {
    printf 'Dir::State::lists "%s";\n' "$lists"
    printf 'Dir::State::extended_states "%s";\n' "$extended_states"
    echo 'Dir::State::status "/var/lib/dpkg/status";'
    printf 'Dir::Cache "%s";\n' "$cache"
    printf 'Dir::Cache::archives "%s";\n' "$archives"
    printf 'Dir::Cache::srcpkgcache "%s";\n' "$srcpkgcache"
    printf 'Dir::Cache::pkgcache "%s";\n' "$pkgcache"
    printf 'Dir::Etc::sourcelist "%s";\n' "$sources_file"
    printf 'Dir::Etc::sourceparts "%s";\n' "$source_parts"
    printf 'Dir::Etc::main "%s";\n' "$empty_config"
    printf 'Dir::Etc::parts "%s";\n' "$config_parts"
    printf 'Dir::Etc::netrc "%s";\n' "$empty_config"
    printf 'Dir::Etc::netrcparts "%s";\n' "$auth_parts"
    printf 'Dir::Etc::preferences "%s";\n' "$empty_config"
    printf 'Dir::Etc::preferencesparts "%s";\n' "$preferences_parts"
    echo 'Dir::Etc::trusted "/dev/null";'
    printf 'Dir::Etc::trustedparts "%s";\n' "$trusted_parts"
    printf 'Dir::Log "%s";\n' "$logs"
    echo 'Acquire::Languages "none";'
    echo 'Acquire::Check-Valid-Until "0";'
    echo 'Acquire::AllowInsecureRepositories "0";'
    echo 'Acquire::AllowWeakRepositories "0";'
    echo 'Acquire::AllowDowngradeToInsecureRepositories "0";'
    echo 'Acquire::https::Verify-Peer "1";'
    echo 'Acquire::https::Verify-Host "1";'
    echo 'APT::Get::AllowUnauthenticated "0";'
    echo 'APT::Get::List-Cleanup "0";'
    echo 'APT::Sandbox::User "_apt";'
    echo '#clear APT::Architectures;'
    echo 'APT::Architecture "amd64";'
    echo 'APT::Architectures { "amd64"; };'
    echo 'DPkg::ConfigurePending "1";'
    echo 'DPkg::Path "/usr/sbin:/usr/bin:/sbin:/bin";'
    echo 'DPkg::Run-Directory "/";'
  } > "$apt_config"
  /usr/bin/chmod 0600 "$apt_config"
  verify_private_apt_configuration
}

if [ "${1:-}" = --check-clean-environment ]; then
  [ "$#" -eq 1 ] || exit 1
  echo 'HAPTICS_APT_CLEAN_ENVIRONMENT=PASS'
  exit 0
fi

if [ "${1:-}" = --check-apt-isolation ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260730T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-check.XXXXXX)
  prepare_private_apt_state 0
  echo 'HAPTICS_APT_CONFIGURATION=PASS'
  exit 0
fi

if [ "${1:-}" = --check-dpkg-isolation ]; then
  [ "$#" -eq 1 ] || exit 1
  mode_script_path=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
  mode_script_dir=${mode_script_path%/*}
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-dpkg-check.XXXXXX)
  private_home="$work_dir/home"
  reviewed_dpkg_config=$(prepare_reviewed_dpkg_config)
  /usr/bin/mkdir -- "$private_home"
  /usr/bin/chmod 0700 "$private_home"
  /usr/bin/python3 -I -B \
    "$mode_script_dir/verify-haptics-dpkg-configuration.py" \
    --expected-owner 0 --expected-group 0 \
    --expected-home-owner "$(/usr/bin/id -u)" \
    --expected-home-group "$(/usr/bin/id -g)" \
    "$reviewed_dpkg_config" "$private_home" >/dev/null
  echo 'HAPTICS_DPKG_CONFIGURATION_CHECK=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-source ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260730T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-source-test.XXXXXX)
  prepare_private_apt_state 0
  printf 'Trusted: yes\n' >> "$sources_file"
  if verify_private_apt_source >/dev/null 2>&1; then
    echo 'private apt source verifier accepted a trusted=yes mutation' >&2
    exit 1
  fi
  echo 'HAPTICS_APT_SOURCE_FIXTURE=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-config ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260730T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-config-test.XXXXXX)
  prepare_private_apt_state 0
  echo 'DPkg::Pre-Invoke { "/bin/false"; };' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a root hook' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::Options:: "--force-all";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a dpkg option' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'Dir::Bin::dpkg "/bin/true";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a substituted dpkg binary' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::ConfigurePending "0";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted disabled pending configuration' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::Run-Directory "/tmp";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a substituted dpkg run directory' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'APT::Update::Post-Invoke-Success:: "/bin/true";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an update success hook' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'Dir::Bin::solvers:: "/tmp/evil-solver";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an additional solver' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::Tools::options::/bin/true::Version "2";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an unbound tool protocol' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  mode_script_path=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
  mode_script_dir=${mode_script_path%/*}
  hook_private="$work_dir/hook-private"
  /usr/bin/mkdir -- "$hook_private"
  /usr/bin/chmod 0700 "$hook_private"
  hook_manifest="$hook_private/expected.tsv"
  hook_marker="$hook_private/hook.ok"
  hook_command="/usr/bin/python3 -I -B $mode_script_dir/verify-haptics-apt-transaction.py --verify-hook $hook_manifest $hook_marker"
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  verify_private_apt_configuration "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Tools::options { "%s" { InfoFD "22"; }; };\n' \
    "${hook_command%% *}" >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted the wrong hook InfoFD' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Tools::options { "%s" { Version "2"; }; };\n' \
    "${hook_command%% *}" >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted the wrong hook version' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Pre-Install-Pkgs { "/bin/true"; };\n' >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an extra package hook' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Tools::options { "%s" { Unknown "1"; }; };\n' \
    "${hook_command%% *}" >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an unknown hook option' >&2
    exit 1
  fi
  echo 'HAPTICS_APT_CONFIGURATION_FIXTURE=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-permissions ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260730T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-permission-test.XXXXXX)
  prepare_private_apt_state 0
  /usr/bin/chmod 0700 "$work_dir"
  if verify_private_apt_permissions >/dev/null 2>&1; then
    echo 'private apt permission verifier accepted a non-traversable root' >&2
    exit 1
  fi
  echo 'HAPTICS_APT_PERMISSION_FIXTURE=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-sandbox-log ]; then
  [ "$#" -eq 1 ] || exit 1
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-sandbox-test.XXXXXX)
  private_uid=$(/usr/bin/id -u)
  private_gid=$(/usr/bin/id -g)
  benign_log="$work_dir/benign.log"
  hostile_log="$work_dir/hostile.log"
  : > "$benign_log"
  /usr/bin/chmod 0600 "$benign_log"
  verify_no_apt_sandbox_fallback "$benign_log"
  printf '%s\n' \
    "N: Download is performed unsandboxed as root as file '/private/pkg.deb' couldn't be accessed by user '_apt'." \
    > "$hostile_log"
  /usr/bin/chmod 0600 "$hostile_log"
  if verify_no_apt_sandbox_fallback "$hostile_log" >/dev/null 2>&1; then
    echo 'apt sandbox-log verifier accepted an unsandboxed-root fallback' >&2
    exit 1
  fi
  echo 'HAPTICS_APT_SANDBOX_LOG_FIXTURE=PASS'
  exit 0
fi

[ "$#" -eq 4 ] || {
  echo 'usage: install-haptics-build-dependencies.sh PACKAGE_LOCK BUILD_TOOLS_REFERENCE RELEASE_REFERENCE DPKG_HOST_REFERENCE' >&2
  exit 1
}
[ "$(/usr/bin/id -u)" -eq 0 ] || {
  echo 'dependency installation must run as root' >&2
  exit 1
}

SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=${SCRIPT_PATH%/*}
  [ -f "$1" ] && [ ! -L "$1" ] &&
  [ -f "$2" ] && [ ! -L "$2" ] &&
  [ -f "$3" ] && [ ! -L "$3" ] &&
  [ -f "$4" ] && [ ! -L "$4" ] || {
  echo 'dependency evidence inputs must be regular non-symlink files' >&2
  exit 1
}
PACKAGE_LOCK=$(/usr/bin/realpath -e -- "$1")
BUILD_TOOLS_REFERENCE=$(/usr/bin/realpath -e -- "$2")
RELEASE_REFERENCE=$(/usr/bin/realpath -e -- "$3")
DPKG_HOST_REFERENCE=$(/usr/bin/realpath -e -- "$4")
PACKAGE_VERIFIER="$SCRIPT_DIR/verify-haptics-build-packages.py"
COMPAT_VERIFIER="$SCRIPT_DIR/verify-haptics-compat-package.sh"
DPKG_CONFIG_VERIFIER="$SCRIPT_DIR/verify-haptics-dpkg-configuration.py"
DPKG_STATE_VERIFIER="$SCRIPT_DIR/verify-haptics-dpkg-state.py"
APT_TRANSACTION_VERIFIER="$SCRIPT_DIR/verify-haptics-apt-transaction.py"
SNAPSHOT_VERIFIER="$SCRIPT_DIR/snapshot-bounded-regular-file.py"
LIVE_TOOLS_VERIFIER="$SCRIPT_DIR/verify-haptics-live-build-tools.sh"

work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt.XXXXXX)
dpkg_home=/root
reviewed_dpkg_config=$(prepare_reviewed_dpkg_config)
/usr/bin/python3 -I -B "$DPKG_CONFIG_VERIFIER" \
  --expected-owner 0 --expected-group 0 \
  "$reviewed_dpkg_config" "$dpkg_home" >/dev/null
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --self-test
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" "$PACKAGE_LOCK"
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --verify-bootstrap "$PACKAGE_LOCK"
[ "$(/usr/bin/sha256sum -- /usr/share/keyrings/ubuntu-archive-keyring.gpg | /usr/bin/cut -d' ' -f1)" = \
  80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31 ] || {
  echo 'Ubuntu archive keyring differs from the reviewed trust anchor' >&2
  exit 1
}

mapfile -d '' -t snapshots < <(
  /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --emit-snapshot-urls "$PACKAGE_LOCK"
)
[ "${#snapshots[@]}" -eq 1 ] || {
  echo 'package lock must emit exactly one apt snapshot' >&2
  exit 1
}
snapshot=${snapshots[0]}
prepare_private_apt_state 1
transaction_dir="$work_dir/transaction"
/usr/bin/mkdir -- "$transaction_dir"
/usr/bin/chmod 0700 "$transaction_dir"
runtime_package_lock="$work_dir/package-lock.tsv"
private_package_lock="$transaction_dir/package-lock.tsv"
private_host_reference="$transaction_dir/dpkg-host-reference.tsv"
/usr/bin/python3 -I -B "$SNAPSHOT_VERIFIER" \
  "$PACKAGE_LOCK" "$runtime_package_lock" 32768 --mode 0644
/usr/bin/python3 -I -B "$SNAPSHOT_VERIFIER" \
  "$runtime_package_lock" "$private_package_lock" 32768 --mode 0644
/usr/bin/chmod 0600 "$private_package_lock"
/usr/bin/python3 -I -B "$SNAPSHOT_VERIFIER" \
  "$DPKG_HOST_REFERENCE" "$private_host_reference" 33554432 --mode 0644
/usr/bin/chmod 0600 "$private_host_reference"
/usr/bin/python3 -I -B "$DPKG_STATE_VERIFIER" \
  --verify-host-reference /var/lib/dpkg 0 0 "$private_host_reference" >/dev/null
apt_command=(
  /usr/bin/env -i
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  LANG=C LC_ALL=C TZ=UTC HOME="$dpkg_home" TMPDIR=/tmp
  DEBIAN_FRONTEND=noninteractive
  APT_CONFIG="$apt_config"
  /usr/bin/apt-get
)
before_state="$transaction_dir/package-state.before.tsv"
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --capture-system-state "$runtime_package_lock" > "$before_state"
/usr/bin/chmod 0600 "$before_state"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-baseline-state "$runtime_package_lock" "$before_state"
before_dpkg_state="$transaction_dir/dpkg-state.before.tsv"
/usr/bin/python3 -I -B "$DPKG_STATE_VERIFIER" \
  --capture-state /var/lib/dpkg 0 0 > "$before_dpkg_state"
/usr/bin/chmod 0600 "$before_dpkg_state"
before_audit="$work_dir/dpkg-audit.before.txt"
HOME="$dpkg_home" /usr/bin/dpkg --audit > "$before_audit"
/usr/bin/chmod 0600 "$before_audit"
[ ! -s "$before_audit" ] || {
  echo 'dpkg reports an inconsistent pre-transaction state' >&2
  /usr/bin/cat -- "$before_audit" >&2
  exit 1
}

"${apt_command[@]}" update
mapfile -d '' -t package_arguments < <(
  /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --emit-apt-arguments "$runtime_package_lock"
)
[ "${#package_arguments[@]}" -gt 0 ] || {
  echo 'package lock emitted no apt arguments' >&2
  exit 1
}
mapfile -d '' -t compat_records < <(
  /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --emit-compat-records "$runtime_package_lock"
)
[ "${#compat_records[@]}" -eq 10 ] || {
  echo 'package lock emitted an unexpected compatibility-package count' >&2
  exit 1
}
compat_debs=()
for record in "${compat_records[@]}"; do
  IFS=$'\t' read -r name architecture version url digest extra <<< "$record"
  [ -n "$name" ] && [ -n "$architecture" ] && [ -n "$version" ] &&
    [ -n "$url" ] && [ -n "$digest" ] && [ -z "${extra:-}" ] || {
      echo 'invalid compatibility-package record emitted by verifier' >&2
      exit 1
    }
  destination="$compat_dir/${name}_${version}_${architecture}.deb"
  partial="$compat_private_dir/${name}_${version}_${architecture}.deb.part"
  /usr/bin/curl --disable --fail --location --silent --show-error \
    --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --max-time 300 --max-filesize 67108864 \
    --retry 3 --retry-all-errors --retry-delay 2 \
    --output "$partial" -- "$url"
  /bin/bash -p "$COMPAT_VERIFIER" "$partial" "$destination" \
    "$name" "$version" "$architecture" "$digest" >/dev/null
  compat_debs+=("$destination")
done

transaction_arguments=("${package_arguments[@]}" "${compat_debs[@]}")
[ "${#transaction_arguments[@]}" -eq 209 ] || {
  echo 'package lock emitted an unexpected transaction argument count' >&2
  exit 1
}
empty_status="$work_dir/empty-status"
: > "$empty_status"
/usr/bin/chmod 0600 "$empty_status"
closure_plan="$work_dir/apt-closure.plan"
"${apt_command[@]}" -s -qq \
  -o APT::Get::Show-User-Simulation-Note=0 \
  -o "Dir::State::status=$empty_status" \
  install --no-install-recommends --allow-downgrades --no-remove -- \
  "${transaction_arguments[@]}" > "$closure_plan"
/usr/bin/chmod 0600 "$closure_plan"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-closure-plan "$runtime_package_lock" "$closure_plan"

host_plan="$transaction_dir/apt-host.plan"
"${apt_command[@]}" -s -qq \
  -o APT::Get::Show-User-Simulation-Note=0 \
  install --no-install-recommends --allow-downgrades --no-remove -- \
  "${transaction_arguments[@]}" > "$host_plan"
/usr/bin/chmod 0600 "$host_plan"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-host-plan "$runtime_package_lock" "$before_state" "$host_plan"

download_stderr="$work_dir/package-download.stderr"
if ! "${apt_command[@]}" -y --download-only \
  install --no-install-recommends --allow-downgrades --no-remove -- \
  "${transaction_arguments[@]}" 2> "$download_stderr"; then
  /usr/bin/cat -- "$download_stderr" >&2
  exit 1
fi
if ! verify_no_apt_sandbox_fallback "$download_stderr"; then
  /usr/bin/cat -- "$download_stderr" >&2
  exit 1
fi
/usr/bin/cat -- "$download_stderr" >&2
hook_manifest="$transaction_dir/expected.tsv"
hook_marker="$transaction_dir/hook.ok"
hook_command="/usr/bin/python3 -I -B $APT_TRANSACTION_VERIFIER --verify-hook $hook_manifest $hook_marker"
[ ! -e "$hook_manifest" ] && [ ! -L "$hook_manifest" ] &&
  [ ! -e "$hook_marker" ] && [ ! -L "$hook_marker" ] || {
    echo 'APT transaction manifest or marker path already exists' >&2
    exit 1
  }
/usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER" \
  --prepare-manifest-runtime-reference "$hook_command" \
  "$private_package_lock" "$before_state" "$host_plan" \
  "$before_dpkg_state" "$private_host_reference" \
  "$archives" "$compat_dir" "$hook_manifest"
configure_private_apt_hook "$hook_command" "$APT_TRANSACTION_VERIFIER"
verify_private_apt_configuration "$hook_command" "$APT_TRANSACTION_VERIFIER"
compat_apt_stderr="$work_dir/package-install.stderr"
if "${apt_command[@]}" install -y \
  --no-install-recommends --allow-downgrades --no-remove -- \
  "${transaction_arguments[@]}" 2> "$compat_apt_stderr"; then
  apt_install_status=0
else
  apt_install_status=$?
fi
if /usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER" \
  --verify-marker "$hook_manifest" "$hook_marker"; then
  marker_status=0
else
  marker_status=$?
fi
if /usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER" \
  --verify-post "$hook_manifest" "$before_dpkg_state"; then
  post_status=0
else
  post_status=$?
fi
if [ "$marker_status" -ne 0 ] || [ "$post_status" -ne 0 ]; then
  /usr/bin/cat -- "$compat_apt_stderr" >&2
  exit 1
fi
if [ "$apt_install_status" -ne 0 ]; then
  /usr/bin/cat -- "$compat_apt_stderr" >&2
  exit "$apt_install_status"
fi
if ! verify_no_apt_sandbox_fallback "$compat_apt_stderr"; then
  /usr/bin/cat -- "$compat_apt_stderr" >&2
  exit 1
fi
/usr/bin/cat -- "$compat_apt_stderr" >&2
/usr/bin/update-alternatives --set awk /usr/bin/gawk
after_state="$work_dir/package-state.after.tsv"
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --capture-system-state "$runtime_package_lock" > "$after_state"
/usr/bin/chmod 0600 "$after_state"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-state-transition "$runtime_package_lock" "$before_state" "$after_state"
after_audit="$work_dir/dpkg-audit.after.txt"
HOME="$dpkg_home" /usr/bin/dpkg --audit > "$after_audit"
/usr/bin/chmod 0600 "$after_audit"
[ ! -s "$after_audit" ] || {
  echo 'dpkg reports an inconsistent post-transaction state' >&2
  /usr/bin/cat -- "$after_audit" >&2
  exit 1
}
"${apt_command[@]}" -qq check
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --verify-installed "$runtime_package_lock"
/bin/bash -p "$LIVE_TOOLS_VERIFIER" \
  "$BUILD_TOOLS_REFERENCE" "$RELEASE_REFERENCE"
echo 'HAPTICS_BUILD_DEPENDENCIES=PASS'
