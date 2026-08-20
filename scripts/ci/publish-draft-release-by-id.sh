#!/bin/bash -p
if ! [[ -o privileged ]]; then
  builtin exit 126
fi
set -euo pipefail
set +x

release_id=${1:?usage: publish-draft-release-by-id.sh RELEASE_ID RELEASE_TAG RELEASE_DIR NOTES_FILE}
release_tag=${2:?usage: publish-draft-release-by-id.sh RELEASE_ID RELEASE_TAG RELEASE_DIR NOTES_FILE}
release_dir=${3:?usage: publish-draft-release-by-id.sh RELEASE_ID RELEASE_TAG RELEASE_DIR NOTES_FILE}
notes_file=${4:?usage: publish-draft-release-by-id.sh RELEASE_ID RELEASE_TAG RELEASE_DIR NOTES_FILE}

[ "${GH_ALLOW_PUBLISH:-}" = 1 ] || {
  printf 'GH_ALLOW_PUBLISH must be exactly 1 for draft publication\n' >&2
  exit 1
}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
[ "${#GH_TOKEN}" -le 4096 ] || {
  printf 'GH_TOKEN exceeds the supported length\n' >&2
  exit 1
}
case $GH_TOKEN in
  *$'\r'*|*$'\n'*)
    printf 'GH_TOKEN contains a forbidden line break\n' >&2
    exit 1
    ;;
esac
github_token=$GH_TOKEN
export -n github_token
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN GH_DEBUG GH_HOST
export GH_PROMPT_DISABLED=1
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(/usr/bin/realpath -e -- "$SCRIPT_DIR/../..")
REFERENCE="$SCRIPT_DIR/HAPTICS-RELEASE-REFERENCE.tsv"
STAGE_VERIFIER="$SCRIPT_DIR/verify-haptics-publication-stage.sh"
SNAPSHOTTER="$SCRIPT_DIR/snapshot-haptics-publication-stage.py"

publisher_git() {
  /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent \
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
    /usr/bin/git --no-replace-objects \
      -c core.fsmonitor=false \
      -c core.untrackedCache=false \
      -c core.excludesFile=/dev/null \
      "$@"
}

publisher_verify_trusted_checkout() {
  local fixed_tool top_level actual_commit index_flags status index_record

  [[ $GITHUB_SHA =~ ^[0-9a-f]{40}$ ]] || {
    printf 'GITHUB_SHA is not a full lowercase commit id: %s\n' \
      "$GITHUB_SHA" >&2
    return 1
  }
  for fixed_tool in /usr/bin/env /usr/bin/git /usr/bin/realpath; do
    [ -x "$fixed_tool" ] && [ -f "$fixed_tool" ] && [ ! -L "$fixed_tool" ] || {
      printf 'fixed publisher bootstrap tool is missing or unsafe: %s\n' \
        "$fixed_tool" >&2
      return 1
    }
  done
  top_level=$(publisher_git -C "$REPO_ROOT" rev-parse --show-toplevel) || {
    printf 'cannot establish the publisher Git worktree root\n' >&2
    return 1
  }
  [ "$(/usr/bin/realpath -e -- "$top_level")" = "$REPO_ROOT" ] || {
    printf 'publisher source is not the Git worktree root\n' >&2
    return 1
  }
  actual_commit=$(publisher_git -C "$REPO_ROOT" rev-parse 'HEAD^{commit}') || {
    printf 'cannot resolve publisher source HEAD\n' >&2
    return 1
  }
  [ "$actual_commit" = "$GITHUB_SHA" ] || {
    printf 'publisher source commit mismatch: expected %s, got %s\n' \
      "$GITHUB_SHA" "$actual_commit" >&2
    return 1
  }
  index_flags=$(publisher_git -C "$REPO_ROOT" ls-files -v) || {
    printf 'cannot inspect publisher source index flags\n' >&2
    return 1
  }
  while IFS= read -r index_record; do
    case $index_record in
      [a-zS]\ *)
        printf 'publisher source has unsafe index flags\n' >&2
        return 1
        ;;
    esac
  done <<<"$index_flags"
  status=$(publisher_git -C "$REPO_ROOT" status --porcelain=v1 \
    --untracked-files=all) || {
    printf 'cannot inspect publisher source worktree state\n' >&2
    return 1
  }
  [ -z "$status" ] || {
    printf 'publisher source worktree must be clean\n' >&2
    return 1
  }
}

publisher_verify_trusted_checkout
. "$SCRIPT_DIR/common.sh"
unset CI_CURL_BIN CI_ENV_BIN CI_GIT_BIN CI_PYTHON3_BIN CI_SHA256SUM_BIN
CI_GIT_BIN=/usr/bin/git
CI_ENV_BIN=/usr/bin/env
CI_CURL_BIN=/usr/bin/curl
CI_PYTHON3_BIN=/usr/bin/python3
CI_SHA256SUM_BIN=/usr/bin/sha256sum

[[ $release_id =~ ^[1-9][0-9]{0,19}$ ]] || {
  printf 'release ID must be a canonical positive decimal integer: %s\n' "$release_id" >&2
  exit 1
}
[[ $release_tag =~ ^tb321fu-haptics-debs-([0-9][0-9A-Za-z._-]{0,63})$ ]] || {
  printf 'release tag must equal tb321fu-haptics-debs-<safe-version>: %s\n' "$release_tag" >&2
  exit 1
}
package_version=${BASH_REMATCH[1]}
[[ $GITHUB_REPOSITORY =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  printf 'unsafe repository name: %s\n' "$GITHUB_REPOSITORY" >&2
  exit 1
}
[ "$GITHUB_REPOSITORY" = GUF296/tb321fu-haptics-debs ] || {
  printf 'numeric haptics publication is restricted to GUF296/tb321fu-haptics-debs\n' >&2
  exit 1
}
[ -d "$release_dir" ] || { printf 'release directory not found: %s\n' "$release_dir" >&2; exit 1; }
[ -f "$notes_file" ] || { printf 'release notes not found: %s\n' "$notes_file" >&2; exit 1; }
for command_name in gh git python3 bash sha256sum stat find sort awk grep uniq wc base64 cmp seq sleep mktemp rm realpath env; do
  command -v "$command_name" >/dev/null || {
    printf 'required command not found: %s\n' "$command_name" >&2
    exit 1
  }
done
gh_path=/usr/bin/gh
publisher_shell_pid=$BASHPID
[ -x "$gh_path" ] && [ -f "$gh_path" ] && [ ! -L "$gh_path" ] || {
  printf 'fixed GitHub CLI is missing or unsafe: %s\n' "$gh_path" >&2
  exit 1
}

publisher_fixture_environment() {
  local tool_path=$1 output_name=$2 variable_name
  local -n output=$output_name

  output=()
  [ "$tool_path" != /usr/bin/gh ] || return 0
  while IFS= read -r variable_name; do
    case $variable_name in
      GH_TOKEN|GH_ENTERPRISE_TOKEN|GH_HOST|GH_DEBUG) continue ;;
      AUTH_SENTINEL_FILE|EXPECTED_PRODUCER_SHA|FAKE_NUMERIC_PUBLISHER|GH_*)
        output+=("$variable_name=${!variable_name}")
        ;;
    esac
  done < <(builtin compgen -e)
}

github_api() (
  local -a fixture_environment=()

  set +x
  publisher_fixture_environment "$gh_path" fixture_environment
  exec 3<<<"$github_token"
  exec /usr/bin/env -i "${fixture_environment[@]}" \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent GH_CONFIG_DIR=/nonexistent \
    GH_PROMPT_DISABLED=1 \
    TB321FU_PUBLICATION_PARENT_PID="$publisher_shell_pid" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 60s \
    /bin/bash -p -c '
      IFS= read -r GH_TOKEN <&3 || exit 125
      exec 3<&-
      export GH_TOKEN
      exec "$@"
    ' tb321fu-github-api "$gh_path" api "$@" --hostname github.com
)

ci_verify_clean_git_commit "$REPO_ROOT" "$GITHUB_SHA" >/dev/null
[ -x "$STAGE_VERIFIER" ] && [ ! -L "$STAGE_VERIFIER" ] &&
  [ -f "$SNAPSHOTTER" ] && [ ! -L "$SNAPSHOTTER" ] || {
  printf 'committed haptics publication verifier is missing\n' >&2
  exit 1
}

source_release_dir=$release_dir
source_notes_file=$notes_file
publication_verify_parent=$(mktemp -d \
  "${TMPDIR:-/tmp}/tb321fu-haptics-publication.XXXXXX")
cleanup() {
  case $publication_verify_parent in
    "${TMPDIR:-/tmp}"/tb321fu-haptics-publication.*)
      rm -rf -- "$publication_verify_parent"
      ;;
  esac
}
cancel_now() {
  local status=$1 signal_name=$2

  trap - INT TERM EXIT
  printf 'publication cancelled by %s outside an active remote write\n' \
    "$signal_name" >&2
  cleanup
  exit "$status"
}

remote_write_active=false
remote_write_kind=
remote_write_sequence=0
remote_write_child=
remote_write_stdout=
remote_write_stderr=
remote_write_status_file=
pending_cancel_status=0
pending_cancel_name=

record_cancel() {
  local status=$1 signal_name=$2

  if $remote_write_active; then
    if [ "$pending_cancel_status" -eq 0 ]; then
      pending_cancel_status=$status
      pending_cancel_name=$signal_name
    fi
    return 0
  fi
  cancel_now "$status" "$signal_name"
}

cancel_int() {
  record_cancel 130 INT
}

cancel_term() {
  record_cancel 143 TERM
}

begin_remote_write() {
  [ "$remote_write_active" = false ] || {
    printf 'nested remote write transaction is not allowed\n' >&2
    return 1
  }
  remote_write_kind=$1
  remote_write_sequence=$((remote_write_sequence + 1))
  remote_write_child=
  remote_write_stdout="$publication_verify_parent/remote-write-${remote_write_sequence}.stdout"
  remote_write_stderr="$publication_verify_parent/remote-write-${remote_write_sequence}.stderr"
  remote_write_status_file="$publication_verify_parent/remote-write-${remote_write_sequence}.status"
  rm -f -- "$remote_write_stdout" "$remote_write_stderr" \
    "$remote_write_status_file"
  : > "$remote_write_stdout"
  : > "$remote_write_stderr"
  remote_write_active=true
}

finish_remote_write() {
  local reconciled_state=$1
  local cancel_status cancel_name

  remote_write_active=false
  cancel_status=$pending_cancel_status
  cancel_name=$pending_cancel_name
  remote_write_child=
  pending_cancel_status=0
  pending_cancel_name=
  if [ "$cancel_status" -ne 0 ]; then
    printf '%s remote write reconciled as %s; honoring deferred %s\n' \
      "$remote_write_kind" "$reconciled_state" "$cancel_name" >&2
    exit "$cancel_status"
  fi
}

fail_remote_write() {
  local reconciled_state=$1

  finish_remote_write "$reconciled_state"
  exit 1
}

wait_remote_write_child() {
  local wait_status request_status

  while :; do
    if wait "$remote_write_child"; then
      wait_status=0
    else
      wait_status=$?
    fi
    if [ -s "$remote_write_status_file" ] &&
       ! kill -0 "$remote_write_child" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$remote_write_child" 2>/dev/null; then
      printf '%s remote write child ended without a status record (wait=%s)\n' \
        "$remote_write_kind" "$wait_status" >&2
      return 125
    fi
  done
  IFS= read -r request_status < "$remote_write_status_file" || return 125
  [[ $request_status =~ ^[0-9]+$ ]] && [ "$request_status" -le 255 ] || {
    printf '%s remote write child returned an invalid status record\n' \
      "$remote_write_kind" >&2
    return 125
  }
  remote_write_child=
  return "$request_status"
}

run_github_remote_write() {
  (
    set +e
    github_api "$@" > "$remote_write_stdout" 2> "$remote_write_stderr"
    request_status=$?
    printf '%s\n' "$request_status" > "$remote_write_status_file"
    exit 0
  ) &
  remote_write_child=$!
  wait_remote_write_child
}
trap cleanup EXIT
trap cancel_int INT
trap cancel_term TERM

reference_snapshot="$publication_verify_parent/committed-reference.tsv"
ci_export_git_file "$REPO_ROOT" "$GITHUB_SHA" \
  scripts/ci/HAPTICS-RELEASE-REFERENCE.tsv "$reference_snapshot"
release_snapshot="$publication_verify_parent/assets"
/usr/bin/python3 -I "$SNAPSHOTTER" \
  "$source_release_dir" "$source_notes_file" "$package_version" \
  "$release_snapshot" || {
  printf 'cannot create a stable haptics publication snapshot\n' >&2
  exit 1
}
release_dir=$release_snapshot
notes_file="$release_snapshot/BUILD-PARAMETERS.md"
REFERENCE=$reference_snapshot

[ -f "$notes_file" ] || {
  printf 'release asset BUILD-PARAMETERS.md is required\n' >&2
  exit 1
}
release_title=$release_tag
notes_body_b64=$(base64 -w 0 "$notes_file")

expected_asset_names=$(printf '%s\n' \
  BUILD-PARAMETERS.md \
  HAPTICS-SOURCE-LOCK.tsv \
  SHA256SUMS-tb321fu-haptics-debs.txt \
  SHA256SUMS.txt \
  "tb321fu-haptics-debs_${package_version}_arm64.tar.gz" | sort)

load_local_assets() {
  local output_name=$1 entry_count regular_count actual_asset_names asset asset_name
  local -n output=$output_name

  entry_count=$(find "$release_dir" -mindepth 1 -maxdepth 1 -printf . | wc -c) || return 1
  regular_count=$(find "$release_dir" -mindepth 1 -maxdepth 1 -type f -printf . | wc -c) || return 1
  [ "$entry_count" -eq "$regular_count" ] || {
    printf 'release directory contains a directory, symlink, or special file\n' >&2
    return 1
  }
  mapfile -d '' -t output < <(
    find "$release_dir" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z
  )
  actual_asset_names=$(
    for asset in "${output[@]}"; do
      printf '%s\n' "${asset##*/}"
    done | sort
  )
  [ "$actual_asset_names" = "$expected_asset_names" ] || {
    printf 'release directory does not contain the exact five haptics assets\n' >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected_asset_names" "$actual_asset_names" >&2
    return 1
  }
  for asset in "${output[@]}"; do
    asset_name=${asset##*/}
    [[ $asset_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
      printf 'unsafe release asset name: %s\n' "$asset_name" >&2
      return 1
    }
    [ -f "$asset" ] && [ ! -L "$asset" ] || {
      printf 'release asset is not a regular file: %s\n' "$asset_name" >&2
      return 1
    }
  done
}

assets=()
load_local_assets assets
[ -f "$release_dir/SHA256SUMS.txt" ] || { printf 'SHA256SUMS.txt is required\n' >&2; exit 1; }

manifest_names=$(awk '
  length($1) != 64 || $1 !~ /^[0-9a-fA-F]+$/ { exit 2 }
  {
    name = substr($0, 67)
    sub(/^\\*/, "", name)
    if (name == "" || name == "SHA256SUMS.txt") exit 3
    print name
  }
' "$release_dir/SHA256SUMS.txt") || {
  printf 'invalid SHA256SUMS.txt format\n' >&2
  exit 1
}
[ -n "$manifest_names" ] || { printf 'empty SHA256SUMS.txt\n' >&2; exit 1; }
[ "$(printf '%s\n' "$manifest_names" | wc -l)" -eq "$((${#assets[@]} - 1))" ] || {
  printf 'SHA256SUMS.txt does not cover every non-manifest asset exactly once\n' >&2
  exit 1
}
[ -z "$(printf '%s\n' "$manifest_names" | sort | uniq -d)" ] || {
  printf 'SHA256SUMS.txt contains duplicate asset names\n' >&2
  exit 1
}
for asset in "${assets[@]}"; do
  asset_name=${asset##*/}
  [ "$asset_name" = SHA256SUMS.txt ] && continue
  printf '%s\n' "$manifest_names" | grep -Fxq -- "$asset_name" || {
    printf 'asset is missing from SHA256SUMS.txt: %s\n' "$asset_name" >&2
    exit 1
  }
done
(cd "$release_dir" && sha256sum --strict -c SHA256SUMS.txt)

snapshot_local_assets() {
  local asset asset_name local_size local_digest
  local -a current_assets=()

  load_local_assets current_assets || return 1
  (cd "$release_dir" && sha256sum --strict -c SHA256SUMS.txt >/dev/null) || return 1
  for asset in "${current_assets[@]}"; do
    asset_name=${asset##*/}
    local_size=$(stat -c '%s' "$asset") || return 1
    local_digest=sha256:$(sha256sum "$asset" | awk '{print $1}') || return 1
    printf '%s\t%s\t%s\n' "$asset_name" "$local_size" "$local_digest"
  done
}

local_asset_records=$(snapshot_local_assets) || {
  printf 'cannot create the local release asset snapshot\n' >&2
  exit 1
}

/bin/bash -p "$STAGE_VERIFIER" "$release_dir" "$REFERENCE" "$GITHUB_SHA" \
  "$publication_verify_parent/archive" >/dev/null || {
  printf 'local haptics publication stage does not match the trusted reference\n' >&2
  exit 1
}

fetch_release_snapshot() {
  github_api "repos/$GITHUB_REPOSITORY/releases/$release_id" --jq \
    '(["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv'
}

verify_release_snapshot() {
  local snapshot=$1
  local expected_draft=$2
  local expected_immutable=$3
  local expected_target=$4
  local metadata actual_kind actual_id actual_draft actual_immutable actual_tag actual_target actual_prerelease actual_title actual_body_b64
  local remote_assets remote_count expected_count expected_record
  local expected_name expected_size expected_digest remote_record

  metadata=$(printf '%s\n' "$snapshot" | awk -F '\t' \
    '$1 == "release" { print; found++ } END { if (found != 1) exit 1 }') || return 1
  IFS=$'\t' read -r actual_kind actual_id actual_draft actual_immutable actual_tag actual_target actual_prerelease actual_title actual_body_b64 <<< "$metadata"
  [ "$actual_kind" = release ] || return 1
  [ "$actual_id" = "$release_id" ] || return 1
  [ "$actual_draft" = "$expected_draft" ] || return 1
  [ "$actual_immutable" = "$expected_immutable" ] || return 1
  [ "$actual_tag" = "$release_tag" ] || return 1
  [ "$actual_target" = "$expected_target" ] || return 1
  [ "$actual_prerelease" = true ] || return 1
  [ "$actual_title" = "$release_title" ] || return 1
  [ "$actual_body_b64" = "$notes_body_b64" ] || return 1

  remote_assets=$(printf '%s\n' "$snapshot" | awk -F '\t' 'BEGIN { OFS="\t" }
    $1 == "asset" {
      if (NF != 5 || $5 != "uploaded") exit 1
      print $2, $3, $4
    }
  ') || return 1
  remote_count=$(printf '%s\n' "$remote_assets" | awk 'NF { count++ } END { print count + 0 }')
  expected_count=$(printf '%s\n' "$local_asset_records" | awk 'NF { count++ } END { print count + 0 }')
  [ "$remote_count" -eq "$expected_count" ] || return 1

  while IFS=$'\t' read -r expected_name expected_size expected_digest; do
    [ -n "$expected_name" ] || continue
    expected_record=$(printf '%s\t%s\t%s' "$expected_name" "$expected_size" "$expected_digest")
    remote_record=$(printf '%s\n' "$remote_assets" | awk -F '\t' -v name="$expected_name" \
      '$1 == name { print; found++ } END { if (found != 1) exit 1 }') || return 1
    [ "$remote_record" = "$expected_record" ] || return 1
  done <<< "$local_asset_records"
}

fetch_latest_snapshot() {
  local snapshot regular_release_ids

  if snapshot=$(github_api "repos/$GITHUB_REPOSITORY/releases/latest" --jq \
      '(["latest", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["latest-asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv'); then
    printf '%s\n' "$snapshot"
    return 0
  fi
  regular_release_ids=$(github_api \
    "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --jq \
    '.[] | select(.draft == false and .prerelease == false) | .id') || return 1
  [ -z "$regular_release_ids" ] || return 1
  printf 'latest-none\n'
}

verify_latest_snapshot() {
  local snapshot=$1

  [ "$snapshot" = latest-none ] && return 0
  printf '%s\n' "$snapshot" | awk -F '\t' -v candidate="$release_id" '
    $1 == "latest" {
      if (NF != 9 || $2 !~ /^[1-9][0-9]*$/ || length($2) > 20 || $2 == candidate ||
          $3 != "false" || ($4 != "true" && $4 != "false") ||
          $7 != "false" || $9 !~ /^[A-Za-z0-9+\/=]*$/) exit 1
      metadata++
      next
    }
    $1 == "latest-asset" {
      if (NF != 5 || $2 == "" || $3 !~ /^[0-9]+$/ ||
          ($4 != "" && ($4 !~ /^sha256:[0-9a-f]+$/ || length($4) != 71)) ||
          $5 != "uploaded") exit 1
      next
    }
    { exit 1 }
    END { if (metadata != 1) exit 1 }
  '
}

fetch_immutability_policy() {
  github_api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq \
    '[(.enabled | tostring), (.enforced_by_owner | tostring)] | @tsv'
}

verify_immutability_policy() {
  [ "$1" = $'true\tfalse' ] || [ "$1" = $'true\ttrue' ]
}

resolve_tag_commit() {
  local object_type object_sha record
  local depth

  record=$(github_api "repos/$GITHUB_REPOSITORY/git/ref/tags/$release_tag" --jq \
    '[.object.type, .object.sha] | @tsv') || return 1
  for depth in $(seq 1 8); do
    IFS=$'\t' read -r object_type object_sha <<< "$record"
    [[ $object_sha =~ ^[0-9a-f]{40}$ ]] || return 1
    case "$object_type" in
      commit)
        printf '%s\n' "$object_sha"
        return 0
        ;;
      tag)
        record=$(github_api "repos/$GITHUB_REPOSITORY/git/tags/$object_sha" --jq \
          '[.object.type, .object.sha] | @tsv') || return 1
        ;;
      *)
        return 1
        ;;
    esac
  done
  return 1
}

verify_tag_target() {
  local resolved

  resolved=$(resolve_tag_commit) || {
    printf 'release tag cannot be resolved to a commit: %s\n' "$release_tag" >&2
    return 1
  }
  [ "$resolved" = "$GITHUB_SHA" ] || {
    printf 'release tag target differs from the expected commit: %s != %s\n' \
      "$resolved" "$GITHUB_SHA" >&2
    return 1
  }
}

immutability_policy=$(fetch_immutability_policy) || {
  printf 'cannot establish the repository immutable-release policy\n' >&2
  exit 1
}
verify_immutability_policy "$immutability_policy" || {
  printf 'repository immutable releases must be enabled before publication\n' >&2
  exit 1
}

draft_snapshot=$(fetch_release_snapshot) || {
  printf 'cannot fetch draft release ID %s\n' "$release_id" >&2
  exit 1
}
release_target_commitish=$(printf '%s\n' "$draft_snapshot" | awk -F '\t' \
  '$1 == "release" { print $6; found++ } END { if (found != 1) exit 1 }') || {
  printf 'draft release snapshot has invalid metadata framing\n' >&2
  exit 1
}
[ -n "$release_target_commitish" ] || {
  printf 'draft release has an empty target_commitish\n' >&2
  exit 1
}
verify_release_snapshot "$draft_snapshot" true false "$release_target_commitish" || {
  printf 'draft release ID/tag/metadata/state/assets do not match the local release set\n' >&2
  printf '%s\n' "$draft_snapshot" >&2
  exit 1
}
verify_tag_target || exit 1

latest_snapshot=$(fetch_latest_snapshot) || {
  printf 'cannot establish the current latest-release state before publication\n' >&2
  exit 1
}
verify_latest_snapshot "$latest_snapshot" || {
  printf 'current latest release snapshot is invalid\n' >&2
  printf '%s\n' "$latest_snapshot" >&2
  exit 1
}

current_local_asset_records=$(snapshot_local_assets) || {
  printf 'cannot repeat the local release asset snapshot before publication\n' >&2
  exit 1
}
[ "$current_local_asset_records" = "$local_asset_records" ] || {
  printf 'local release assets changed before publication\n' >&2
  exit 1
}
second_immutability_policy=$(fetch_immutability_policy) || {
  printf 'cannot repeat the immutable-release policy before publication\n' >&2
  exit 1
}
[ "$second_immutability_policy" = "$immutability_policy" ] || {
  printf 'repository immutable-release policy changed before publication\n' >&2
  exit 1
}
second_latest_snapshot=$(fetch_latest_snapshot) || {
  printf 'cannot repeat the latest-release state before publication\n' >&2
  exit 1
}
[ "$second_latest_snapshot" = "$latest_snapshot" ] || {
  printf 'latest release changed concurrently before publication\n' >&2
  exit 1
}
verify_tag_target || exit 1
second_draft_snapshot=$(fetch_release_snapshot) || {
  printf 'cannot repeat the draft release snapshot before publication\n' >&2
  exit 1
}
[ "$second_draft_snapshot" = "$draft_snapshot" ] || {
  printf 'draft release changed concurrently before publication\n' >&2
  exit 1
}

patch_query='(["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv'
begin_remote_write "release PATCH ID $release_id"
set +e
run_github_remote_write -X PATCH \
  "repos/$GITHUB_REPOSITORY/releases/$release_id" \
  -F draft=false -F prerelease=true -f make_latest=false --jq \
  "$patch_query"
patch_status=$?
set -e
patch_snapshot=$(< "$remote_write_stdout")
patch_failed=false
if [ "$patch_status" -ne 0 ]; then
  patch_failed=true
  printf 'release PATCH transport failed; reconciling numeric release ID %s\n' \
    "$release_id" >&2
  [ ! -s "$remote_write_stderr" ] || /usr/bin/cat "$remote_write_stderr" >&2
else
  if ! verify_release_snapshot "$patch_snapshot" false true \
      "$release_target_commitish"; then
    patch_failed=true
    printf 'release PATCH response is not yet the verified immutable prerelease; reconciling numeric release ID %s\n' \
      "$release_id" >&2
    printf '%s\n' "$patch_snapshot" >&2
  fi
fi

published_snapshot=
for attempt in $(seq 1 6); do
  candidate_snapshot=$(fetch_release_snapshot 2>/dev/null || :)
  if [ -n "$candidate_snapshot" ] &&
      verify_release_snapshot "$candidate_snapshot" false true \
        "$release_target_commitish"; then
    published_snapshot=$candidate_snapshot
    break
  fi
  if [ -n "$candidate_snapshot" ] &&
      verify_release_snapshot "$candidate_snapshot" true false \
        "$release_target_commitish" &&
      [ "$candidate_snapshot" = "$draft_snapshot" ]; then
    [ "$attempt" -eq 6 ] || sleep "$attempt" || :
    continue
  fi
  if [ -n "$candidate_snapshot" ]; then
    printf 'release PATCH produced an unknown or concurrently changed state\n' >&2
    printf '%s\n' "$candidate_snapshot" >&2
    fail_remote_write 'unknown or concurrently changed numeric release state'
  fi
  [ "$attempt" -eq 6 ] || sleep "$attempt" || :
done
[ -n "$published_snapshot" ] || {
  printf 'release PATCH outcome remains indeterminate after bounded reconciliation of ID %s\n' \
    "$release_id" >&2
  fail_remote_write 'indeterminate after bounded numeric-ID reconciliation'
}
verify_tag_target || {
  printf 'release tag changed after publication\n' >&2
  fail_remote_write 'published ID has a changed tag target'
}
published_latest_snapshot=$(fetch_latest_snapshot) || {
  printf 'publication returned but the current latest release cannot be re-read\n' >&2
  fail_remote_write 'published ID verified but latest state is indeterminate'
}
[ "$published_latest_snapshot" = "$latest_snapshot" ] || {
  printf 'latest release changed during prerelease publication\n' >&2
  printf '%s\n' "$published_latest_snapshot" >&2
  fail_remote_write 'published ID verified but latest release changed'
}
verify_latest_snapshot "$published_latest_snapshot" || {
  printf 'latest release snapshot became invalid after publication\n' >&2
  fail_remote_write 'published ID verified but latest snapshot is invalid'
}
published_immutability_policy=$(fetch_immutability_policy) || {
  printf 'published release cannot re-read the immutable-release policy\n' >&2
  fail_remote_write 'published ID verified but immutable policy is indeterminate'
}
[ "$published_immutability_policy" = "$immutability_policy" ] || {
  printf 'repository immutable-release policy changed during publication\n' >&2
  fail_remote_write 'published ID verified but immutable policy changed'
}
current_local_asset_records=$(snapshot_local_assets) || {
  printf 'cannot repeat the local release asset snapshot after publication\n' >&2
  fail_remote_write 'published ID verified but local source snapshot is indeterminate'
}
[ "$current_local_asset_records" = "$local_asset_records" ] || {
  printf 'local release assets changed during publication\n' >&2
  fail_remote_write 'published ID verified but local source snapshot changed'
}

finish_remote_write "verified immutable prerelease ID $release_id with latest unchanged"

if $patch_failed; then
  printf 'Published and reconciled verified immutable prerelease %s as release ID %s; latest release is unchanged.\n' \
    "$release_tag" "$release_id"
else
  printf 'Published verified immutable prerelease %s as release ID %s; latest release is unchanged.\n' \
    "$release_tag" "$release_id"
fi
