#!/usr/bin/env bash
set -euo pipefail

ci_log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

ci_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

ci_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || ci_die "required command not found: $1"
}

ci_bool() {
  case "${1:-}" in
    1|yes|true|on) return 0 ;;
    *) return 1 ;;
  esac
}

ci_abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$(pwd -P)" "$1" ;;
  esac
}

ci_sanitized_git_env() {
  env \
    -u GIT_DIR \
    -u GIT_WORK_TREE \
    -u GIT_COMMON_DIR \
    -u GIT_INDEX_FILE \
    -u GIT_OBJECT_DIRECTORY \
    -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
    -u GIT_REPLACE_REF_BASE \
    -u GIT_NAMESPACE \
    -u GIT_SHALLOW_FILE \
    -u GIT_GRAFT_FILE \
    -u GIT_CONFIG_PARAMETERS \
    -u GIT_CONFIG_COUNT \
    -u GIT_CONFIG_SYSTEM \
    -u GIT_CONFIG_GLOBAL \
    -u GIT_EXEC_PATH \
    -u GIT_TEMPLATE_DIR \
    -u GIT_CEILING_DIRECTORIES \
    -u GIT_DISCOVERY_ACROSS_FILESYSTEM \
    -u GIT_IMPLICIT_WORK_TREE \
    -u GIT_PREFIX \
    -u GIT_INTERNAL_SUPER_PREFIX \
    -u GIT_QUARANTINE_PATH \
    -u GIT_SSH \
    -u GIT_SSH_COMMAND \
    -u GIT_SSH_VARIANT \
    -u GIT_PROXY_COMMAND \
    -u GIT_ASKPASS \
    -u GIT_ALLOW_PROTOCOL \
    -u GIT_PROTOCOL_FROM_USER \
    -u GIT_NO_REPLACE_OBJECTS \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_ATTR_NOSYSTEM=1 \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=core.fsmonitor \
    GIT_CONFIG_VALUE_0=false \
    GIT_CONFIG_KEY_1=core.untrackedCache \
    GIT_CONFIG_VALUE_1=false \
    GIT_CONFIG_KEY_2=core.excludesFile \
    GIT_CONFIG_VALUE_2=/dev/null \
    "$@"
}

ci_git() {
  ci_sanitized_git_env \
    git --no-replace-objects \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.excludesFile=/dev/null \
    "$@"
}

ci_verify_clean_git_commit() {
  local root=$1
  local expected_commit=$2
  local external_git_dir=${3:-}
  local resolved_root actual_commit top_level status index_flags
  local -a git_cmd

  [[ $expected_commit =~ ^[0-9a-f]{40}$ ]] ||
    ci_die "expected source commit must be 40 lowercase hex characters"
  ci_require_cmd git
  resolved_root=$(realpath -e -- "$root")
  [ -d "$resolved_root" ] || ci_die "source root is not a directory: $root"

  if [ -n "$external_git_dir" ]; then
    external_git_dir=$(realpath -e -- "$external_git_dir")
    [ -d "$external_git_dir/objects" ] ||
      ci_die "external Git directory is not an object database: $external_git_dir"
    git_cmd=(ci_git --git-dir="$external_git_dir" --work-tree="$resolved_root")
  else
    git_cmd=(ci_git -C "$resolved_root")
  fi

  top_level=$("${git_cmd[@]}" rev-parse --show-toplevel 2>/dev/null) ||
    ci_die "source root lacks Git metadata: $resolved_root"
  [ "$(realpath -e -- "$top_level")" = "$resolved_root" ] ||
    ci_die "source root is not the Git worktree root: $resolved_root"
  actual_commit=$("${git_cmd[@]}" rev-parse HEAD^{commit}) ||
    ci_die "cannot resolve source HEAD: $resolved_root"
  [ "$actual_commit" = "$expected_commit" ] ||
    ci_die "source commit mismatch: expected $expected_commit, got $actual_commit"
  index_flags=$("${git_cmd[@]}" ls-files -v) ||
    ci_die "cannot inspect source index flags: $resolved_root"
  if grep -Eq '^[a-zS] ' <<<"$index_flags"; then
    ci_die "source worktree has unsafe assume-unchanged/skip-worktree index flags: $resolved_root"
  fi
  status=$("${git_cmd[@]}" status --porcelain=v1 --untracked-files=all) ||
    ci_die "cannot inspect source worktree state: $resolved_root"
  [ -z "$status" ] || ci_die "source worktree must be clean: $resolved_root"
  printf '%s\n' "$actual_commit"
}

ci_export_git_file() {
  local root=$1
  local commit=$2
  local relative_path=$3
  local destination=$4
  local external_git_dir=${5:-}
  local resolved_root entry mode tmp
  local -a git_cmd

  [[ $commit =~ ^[0-9a-f]{40}$ ]] ||
    ci_die "source commit must be 40 lowercase hex characters"
  case "$relative_path" in
    ''|/*|../*|*/../*|*/..|*\\*)
      ci_die "unsafe Git source path: $relative_path"
      ;;
  esac
  ci_require_cmd git
  resolved_root=$(realpath -e -- "$root")
  [ -d "$resolved_root" ] || ci_die "source root is not a directory: $root"
  if [ -n "$external_git_dir" ]; then
    external_git_dir=$(realpath -e -- "$external_git_dir")
    [ -d "$external_git_dir/objects" ] ||
      ci_die "external Git directory is not an object database: $external_git_dir"
    git_cmd=(ci_git --git-dir="$external_git_dir" --work-tree="$resolved_root")
  else
    git_cmd=(ci_git -C "$resolved_root")
  fi

  entry=$("${git_cmd[@]}" ls-tree "$commit" -- "$relative_path") ||
    ci_die "cannot inspect Git source path: $relative_path"
  [ "$(wc -l <<<"$entry")" -eq 1 ] && [ -n "$entry" ] ||
    ci_die "Git source path must resolve exactly once: $relative_path"
  mode=${entry%% *}
  [ "$mode" = 100644 ] ||
    ci_die "Git source path must be a regular 100644 blob: $relative_path"

  mkdir -p "$(dirname -- "$destination")"
  tmp="${destination}.part.$$"
  rm -f -- "$tmp"
  if ! "${git_cmd[@]}" cat-file blob "$commit:$relative_path" > "$tmp"; then
    rm -f -- "$tmp"
    ci_die "cannot export Git source blob: $relative_path"
  fi
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$destination"
}

ci_create_exact_git_bundle() (
  set -euo pipefail

  local root=$1
  local commit=$2
  local destination=$3
  local bundle_ref=$4
  local external_git_dir=${5:-}
  local resolved_root common_dir object_dir heads tmp tmp_bundle
  local -a source_git

  [[ $commit =~ ^[0-9a-f]{40}$ ]] ||
    ci_die "bundle commit must be 40 lowercase hex characters"
  [[ $bundle_ref =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$ ]] ||
    ci_die "unsafe bundle ref: $bundle_ref"
  ci_require_cmd git
  resolved_root=$(realpath -e -- "$root")
  [ -d "$resolved_root" ] || ci_die "bundle source root is not a directory: $root"
  [ ! -e "$destination" ] || ci_die "refusing stale bundle destination: $destination"
  mkdir -p "$(dirname -- "$destination")"

  if [ -n "$external_git_dir" ]; then
    external_git_dir=$(realpath -e -- "$external_git_dir")
    [ -d "$external_git_dir/objects" ] ||
      ci_die "external Git directory is not an object database: $external_git_dir"
    source_git=(ci_git --git-dir="$external_git_dir" --work-tree="$resolved_root")
  else
    source_git=(ci_git -C "$resolved_root")
  fi
  common_dir=$("${source_git[@]}" rev-parse --path-format=absolute --git-common-dir) ||
    ci_die "cannot resolve bundle source Git common directory"
  object_dir=$(realpath -e -- "$common_dir/objects")
  [ -d "$object_dir" ] || ci_die "bundle source Git object directory is missing"

  tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-git-bundle.XXXXXX")
  trap 'rm -rf -- "$tmp"' EXIT
  tmp_bundle="$tmp/output.bundle"
  ci_git init -q --bare "$tmp/source.git"
  mkdir -p "$tmp/source.git/objects/info"
  printf '%s\n' "$object_dir" > "$tmp/source.git/objects/info/alternates"
  ci_git --git-dir="$tmp/source.git" cat-file -e "$commit^{commit}" ||
    ci_die "bundle commit is absent from the source object database"
  ci_git --git-dir="$tmp/source.git" update-ref "$bundle_ref" "$commit"
  if ! ci_git --git-dir="$tmp/source.git" bundle create "$tmp_bundle" "$bundle_ref"; then
    ci_die "cannot create a self-contained Git bundle from the available history"
  fi

  ci_git init -q --bare "$tmp/verify.git"
  if ! ci_git --git-dir="$tmp/verify.git" bundle verify "$tmp_bundle" >/dev/null 2>&1; then
    ci_die "Git bundle has prerequisites or is not independently verifiable"
  fi
  heads=$(ci_git --git-dir="$tmp/verify.git" bundle list-heads "$tmp_bundle")
  [ "$heads" = "$commit $bundle_ref" ] ||
    ci_die "Git bundle must expose only $bundle_ref at the expected commit"

  chmod 0644 "$tmp_bundle"
  mv -- "$tmp_bundle" "$destination"
)

ci_verify_download() {
  local file=$1
  local expected=$2
  local actual

  [[ $expected =~ ^[A-Fa-f0-9]{64}$ ]] || ci_die "invalid SHA-256 verifier for $file"
  actual=$(sha256sum "$file" | awk '{print $1}')
  [ "$actual" = "${expected,,}" ] ||
    ci_die "SHA-256 mismatch for $file: expected ${expected,,}, got $actual"
}

ci_download() {
  local src=$1
  local dst=$2
  local verifier=${3:-}
  local tmp="${dst}.part.$$"

  rm -f -- "$tmp"
  case "$src" in
    https://*)
      [ -n "$verifier" ] || ci_die "remote download requires an explicit SHA-256: $src"
      ci_require_cmd curl
      if ! curl --proto '=https' --tlsv1.2 -fL --retry 3 --retry-delay 2 -o "$tmp" "$src"; then
        rm -f -- "$tmp"
        ci_die "download failed: $src"
      fi
      ;;
    http://*)
      ci_die "refusing insecure HTTP download: $src"
      ;;
    '')
      ci_die "empty download source for $dst"
      ;;
    *)
      [ -f "$src" ] || ci_die "local download source is not a regular file: $src"
      cp -- "$src" "$tmp"
      ;;
  esac
  if [ -n "$verifier" ]; then
    if ! (ci_verify_download "$tmp" "$verifier"); then
      rm -f -- "$tmp"
      ci_die "download verification failed: $src"
    fi
  fi
  mv -f -- "$tmp" "$dst"
}

ci_extract_archive() {
  local archive=$1
  local dest=$2
  local helper

  helper=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/safe-extract-archive.py
  ci_require_cmd python3
  [ -f "$archive" ] || ci_die "archive not found: $archive"
  python3 "$helper" "$archive" "$dest" || ci_die "safe archive extraction failed: $archive"
}
