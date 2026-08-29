#!/bin/bash -p
if ! [[ -o privileged ]]; then
  builtin exit 126
fi
set -euo pipefail
set +x

release_tag=${1:?usage: publish-release.sh RELEASE_TAG RELEASE_DIR NOTES_FILE}
release_dir=${2:?usage: publish-release.sh RELEASE_TAG RELEASE_DIR NOTES_FILE}
notes_file=${3:?usage: publish-release.sh RELEASE_TAG RELEASE_DIR NOTES_FILE}

: "${GH_TOKEN:?RELEASE_TOKEN must be exposed as GH_TOKEN only for this step}"
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

[ "${PRERELEASE:-}" = 1 ] || {
  printf 'PRERELEASE must be exactly 1 for immutable remediation publication\n' >&2
  exit 1
}
publish_prerelease=true
release_kind='prerelease draft'

[[ $release_tag =~ ^tb321fu-haptics-debs-([0-9][0-9A-Za-z._-]{0,63})$ ]] || {
  printf 'release tag must equal tb321fu-haptics-debs-<safe-version>: %s\n' \
    "$release_tag" >&2
  exit 1
}
package_version=${BASH_REMATCH[1]}
[[ $GITHUB_REPOSITORY =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  printf 'unsafe repository name: %s\n' "$GITHUB_REPOSITORY" >&2
  exit 1
}
[ "$GITHUB_REPOSITORY" = GUF296/tb321fu-haptics-debs ] || {
  printf 'haptics draft creation is restricted to GUF296/tb321fu-haptics-debs\n' >&2
  exit 1
}
[ -d "$release_dir" ] || { printf 'release directory not found: %s\n' "$release_dir" >&2; exit 1; }
[ -f "$notes_file" ] || { printf 'release notes not found: %s\n' "$notes_file" >&2; exit 1; }
for command_name in \
  gh git curl python3 bash sha256sum stat find sort awk grep uniq wc seq sleep \
  base64 cmp env mktemp rm realpath; do
  command -v "$command_name" >/dev/null || {
    printf 'required command not found: %s\n' "$command_name" >&2
    exit 1
  }
done
gh_path=/usr/bin/gh
curl_path=/usr/bin/curl
publisher_shell_pid=$BASHPID
[ -x "$gh_path" ] && [ -f "$gh_path" ] && [ ! -L "$gh_path" ] || {
  printf 'fixed GitHub CLI is missing or unsafe: %s\n' "$gh_path" >&2
  exit 1
}
[ -x "$curl_path" ] && [ -f "$curl_path" ] && [ ! -L "$curl_path" ] || {
  printf 'fixed curl is missing or unsafe: %s\n' "$curl_path" >&2
  exit 1
}

publisher_fixture_environment() {
  local tool_path=$1 output_name=$2 variable_name
  local -n output=$output_name

  output=()
  case $tool_path in
    /usr/bin/gh|/usr/bin/curl) return 0 ;;
  esac
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
  "${TMPDIR:-/tmp}/tb321fu-haptics-draft-verification.XXXXXX")
cleanup() {
  case $publication_verify_parent in
    "${TMPDIR:-/tmp}"/tb321fu-haptics-draft-verification.*)
      rm -rf -- "$publication_verify_parent"
      ;;
  esac
}
cancel_now() {
  local status=$1

  trap - INT TERM EXIT
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
  cancel_now "$status"
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

upload_asset_request() {
  local asset=$1 asset_name=$2

  printf 'Authorization: Bearer %s\n' "$github_token" |
    publisher_curl_upload \
    --disable --fail-with-body --silent --show-error --request POST \
    --connect-timeout 15 --max-time 300 \
    --header 'Accept: application/vnd.github+json' \
    --header '@-' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    --header 'Content-Type: application/octet-stream' \
    --data-binary "@$asset" \
    "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$asset_name"
}

publisher_curl_upload() (
  local -a fixture_environment=()

  set +x
  publisher_fixture_environment "$curl_path" fixture_environment
  exec /usr/bin/env -i "${fixture_environment[@]}" \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C TZ=UTC \
    TB321FU_PUBLICATION_PARENT_PID="$publisher_shell_pid" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 310s \
    "$curl_path" "$@"
)

run_asset_remote_write() {
  local asset=$1 asset_name=$2

  (
    set +e
    upload_asset_request "$asset" "$asset_name" \
      > "$remote_write_stdout" 2> "$remote_write_stderr"
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

entry_count=$(find "$release_dir" -mindepth 1 -maxdepth 1 -printf . | wc -c)
regular_count=$(find "$release_dir" -mindepth 1 -maxdepth 1 -type f -printf . | wc -c)
[ "$entry_count" -eq "$regular_count" ] || {
  printf 'release directory contains a directory, symlink, or special file\n' >&2
  exit 1
}

mapfile -d '' -t assets < <(find "$release_dir" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z)
actual_asset_names=$(
  for asset in "${assets[@]}"; do
    printf '%s\n' "${asset##*/}"
  done | sort
)
[ "$actual_asset_names" = "$expected_asset_names" ] || {
  printf 'release directory does not contain the exact five haptics assets\n' >&2
  printf 'expected:\n%s\nactual:\n%s\n' \
    "$expected_asset_names" "$actual_asset_names" >&2
  exit 1
}
[ -f "$release_dir/SHA256SUMS.txt" ] || { printf 'SHA256SUMS.txt is required\n' >&2; exit 1; }

for asset in "${assets[@]}"; do
  asset_name=${asset##*/}
  [[ $asset_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
    printf 'unsafe release asset name: %s\n' "$asset_name" >&2
    exit 1
  }
done

manifest_names=$(awk '
  length($1) != 64 || $1 !~ /^[0-9a-fA-F]+$/ { exit 2 }
  {
    name = substr($0, 67)
    sub(/^\*/, "", name)
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
  grep -Fxq -- "$asset_name" <<< "$manifest_names" || {
    printf 'asset is missing from SHA256SUMS.txt: %s\n' "$asset_name" >&2
    exit 1
  }
done
(cd "$release_dir" && sha256sum --strict -c SHA256SUMS.txt)

local_asset_records=$(
total_asset_bytes=0
for asset in "${assets[@]}"; do
  local_size=$(stat -c '%s' -- "$asset")
  [[ $local_size =~ ^[0-9]+$ ]] || {
    printf 'invalid release asset size: %s\n' "${asset##*/}" >&2
    exit 1
  }
  total_asset_bytes=$((total_asset_bytes + local_size))
  [ "$total_asset_bytes" -le $((128 * 1024 * 1024)) ] || {
    printf 'haptics release asset payload exceeds the 128 MiB aggregate limit\n' >&2
    exit 1
  }
done

  for asset in "${assets[@]}"; do
    asset_name=${asset##*/}
    local_size=$(stat -c '%s' "$asset")
    local_digest=sha256:$(sha256sum "$asset" | awk '{print $1}')
    printf '%s\t%s\t%s\n' "$asset_name" "$local_size" "$local_digest"
  done
)

/bin/bash -p "$STAGE_VERIFIER" "$release_dir" "$REFERENCE" "$GITHUB_SHA" \
  "$publication_verify_parent/archive" >/dev/null || {
  printf 'local haptics draft stage does not match the trusted reference\n' >&2
  exit 1
}

fetch_release_snapshot() {
  local release_id=$1

  github_api "repos/$GITHUB_REPOSITORY/releases/$release_id" --jq \
    '["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)] | @tsv'
  github_api "repos/$GITHUB_REPOSITORY/releases/$release_id/assets?per_page=100" \
    --paginate --jq '.[] | ["asset", .name, (.size | tostring), (.digest // ""), .state] | @tsv'
}

fetch_release_snapshots_by_tag() {
  local query release_list

  printf -v query \
    '.[] | select(.tag_name == "%s") | .id' \
    "$release_tag"
  release_list=$(github_api "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --paginate --jq "$query") || return 1
  matching_release_ids=()
  if [ -n "$release_list" ]; then
    mapfile -t matching_release_ids <<< "$release_list"
  fi
  local release_id
  for release_id in "${matching_release_ids[@]}"; do
    [[ $release_id =~ ^[1-9][0-9]{0,19}$ ]] || return 1
    fetch_release_snapshot "$release_id"
  done
}

verify_release_snapshot() {
  local snapshot=$1
  local expected_release_id=$2
  local expected_draft=$3
  local expected_immutable=$4
  local expected_target=$5
  local expected_prerelease=$6
  local expected_title=$7
  local expected_body_b64=$8
  local metadata actual_kind actual_id actual_draft actual_immutable actual_tag actual_target actual_prerelease actual_title actual_body_b64

  metadata=$(printf '%s\n' "$snapshot" | awk -F '\t' \
    '$1 == "release" { print; found++ } END { if (found != 1) exit 1 }') || return 1
  IFS=$'\t' read -r actual_kind actual_id actual_draft actual_immutable actual_tag actual_target actual_prerelease actual_title actual_body_b64 <<< "$metadata"
  [ "$actual_kind" = release ] || return 1
  [ "$actual_id" = "$expected_release_id" ] || return 1
  [ "$actual_draft" = "$expected_draft" ] || return 1
  [ "$actual_immutable" = "$expected_immutable" ] || return 1
  [ "$actual_tag" = "$release_tag" ] || return 1
  [ "$actual_target" = "$expected_target" ] || return 1
  [ "$actual_prerelease" = "$expected_prerelease" ] || return 1
  [ "$actual_title" = "$expected_title" ] || return 1
  [ "$actual_body_b64" = "$expected_body_b64" ] || return 1
}

verify_release_assets() {
  local snapshot=$1 expected_assets=$2
  local remote_assets remote_count expected_count expected_record
  local expected_name expected_size expected_digest remote_record

  remote_assets=$(printf '%s\n' "$snapshot" | awk -F '\t' 'BEGIN { OFS="\t" }
    $1 == "asset" {
      if (NF != 5 || $5 != "uploaded") exit 1
      print $2, $3, $4
    }
  ') || return 1
  remote_count=$(printf '%s\n' "$remote_assets" | awk 'NF { count++ } END { print count + 0 }')
  expected_count=$(printf '%s\n' "$expected_assets" | awk 'NF { count++ } END { print count + 0 }')
  [ "$remote_count" -eq "$expected_count" ] || return 1

  while IFS=$'\t' read -r expected_name expected_size expected_digest; do
    [ -n "$expected_name" ] || continue
    expected_record=$(printf '%s\t%s\t%s' "$expected_name" "$expected_size" "$expected_digest")
    remote_record=$(printf '%s\n' "$remote_assets" | awk -F '\t' -v name="$expected_name" \
      '$1 == name { print; found++ } END { if (found != 1) exit 1 }') || return 1
    [ "$remote_record" = "$expected_record" ] || return 1
  done <<< "$expected_assets"
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
    printf 'release tag target differs from this workflow commit: %s != %s\n' \
      "$resolved" "$GITHUB_SHA" >&2
    return 1
  }
}

immutability_policy=$(github_api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq \
  '[(.enabled | tostring), (.enforced_by_owner | tostring)] | @tsv') || {
  printf 'cannot establish the repository immutable-release policy\n' >&2
  exit 1
}
case $immutability_policy in
  $'true\tfalse'|$'true\ttrue') ;;
  *)
    printf 'repository immutable releases must be enabled before draft creation\n' >&2
    exit 1
    ;;
esac

existing_release_tags=$(github_api "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
  --paginate --jq '.[].tag_name') || {
  printf 'cannot establish the existing release set\n' >&2
  exit 1
}
if grep -Fxq -- "$release_tag" <<< "$existing_release_tags"; then
  printf 'refusing to modify an existing release or draft: %s\n' "$release_tag" >&2
  exit 1
fi
matching_tag_refs=$(github_api \
  "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$release_tag" \
  --jq '.[].ref') || {
  printf 'cannot establish the existing tag set\n' >&2
  exit 1
}
if grep -Fxq -- "refs/tags/$release_tag" <<< "$matching_tag_refs"; then
  printf 'refusing to publish through an existing tag: %s\n' "$release_tag" >&2
  exit 1
fi

create_response_query='[.id, .tag_name, (.draft | tostring), (.immutable | tostring), .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)] | @tsv'
begin_remote_write 'draft-create POST'
set +e
run_github_remote_write -X POST "repos/$GITHUB_REPOSITORY/releases" \
  -f "tag_name=$release_tag" \
  -f "target_commitish=$GITHUB_SHA" \
  -f "name=$release_title" \
  -F "body=@$notes_file" \
  -F draft=true -F prerelease="$publish_prerelease" --jq \
  "$create_response_query"
create_status=$?
set -e
release_record=$(< "$remote_write_stdout")
create_response_valid=false
release_target_commitish=$GITHUB_SHA
response_release_id=
if [ "$create_status" -eq 0 ] &&
   [ "$(printf '%s\n' "$release_record" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ]; then
  IFS=$'\t' read -r parsed_response_release_id created_tag created_draft created_immutable \
    response_target created_prerelease created_title created_body_b64 <<< "$release_record"
  if [[ $parsed_response_release_id =~ ^[1-9][0-9]{0,19}$ ]] &&
     [ "$created_tag" = "$release_tag" ] &&
     [ "$created_draft" = true ] && [ "$created_immutable" = false ] &&
     [ -n "$response_target" ] &&
     [ "$created_prerelease" = "$publish_prerelease" ] &&
     [ "$created_title" = "$release_title" ] &&
     [ "$created_body_b64" = "$notes_body_b64" ]; then
    create_response_valid=true
    response_release_id=$parsed_response_release_id
    release_target_commitish=$response_target
  fi
fi
if [ "$create_status" -ne 0 ] || ! $create_response_valid; then
  printf 'draft-create POST returned status %s for tag %s or an unusable response; refusing to take over an unowned remote object\n' \
    "$create_status" "$release_tag" >&2
  [ ! -s "$remote_write_stderr" ] || /usr/bin/cat "$remote_write_stderr" >&2
  fail_remote_write 'draft-create ownership proof failed; no takeover'
fi

create_reconciled=false
tag_snapshot=
initial_snapshot=
release_id=
for attempt in $(seq 1 4); do
  if tag_snapshot=$(fetch_release_snapshots_by_tag 2>/dev/null); then
    candidate_release_id=$(printf '%s\n' "$tag_snapshot" | awk -F '\t' \
      '$1 == "release" { print $2; found++ } END { if (found != 1) exit 1 }') ||
      candidate_release_id=
    if [[ $candidate_release_id =~ ^[1-9][0-9]{0,19}$ ]] &&
       [ "$candidate_release_id" = "$response_release_id" ] &&
       verify_release_snapshot "$tag_snapshot" "$candidate_release_id" true false \
         "$release_target_commitish" "$publish_prerelease" "$release_title" \
         "$notes_body_b64" &&
       verify_release_assets "$tag_snapshot" '' &&
       initial_snapshot=$(fetch_release_snapshot "$candidate_release_id" 2>/dev/null) &&
       [ "$initial_snapshot" = "$tag_snapshot" ] &&
       verify_tag_target &&
       current_immutability_policy=$(github_api \
         "repos/$GITHUB_REPOSITORY/immutable-releases" --jq \
         '[(.enabled | tostring), (.enforced_by_owner | tostring)] | @tsv' \
         2>/dev/null) &&
       [ "$current_immutability_policy" = "$immutability_policy" ]; then
      release_id=$candidate_release_id
      create_reconciled=true
      break
    fi
    if [ -n "$tag_snapshot" ]; then
      printf 'exact tag resolved to a non-unique or incomplete draft during create reconciliation\n' >&2
      printf '%s\n' "$tag_snapshot" >&2
      fail_remote_write 'non-unique or incomplete exact-tag object; no takeover'
    fi
  fi
  [ "$attempt" -eq 4 ] || sleep 1 || :
done

if ! $create_reconciled; then
  printf 'draft-create outcome is not a unique complete empty draft for exact tag %s; no remote object is taken over\n' \
    "$release_tag" >&2
  [ ! -s "$remote_write_stderr" ] || /usr/bin/cat "$remote_write_stderr" >&2
  [ -z "$tag_snapshot" ] || printf '%s\n' "$tag_snapshot" >&2
  fail_remote_write 'indeterminate or non-matching; failed closed'
fi
finish_remote_write "unique complete empty draft ID $release_id"

uploaded_asset_records=
for asset in "${assets[@]}"; do
  asset_name=${asset##*/}
  asset_record=$(printf '%s\n' "$local_asset_records" | awk -F '\t' \
    -v name="$asset_name" '$1 == name { print; found++ } END { if (found != 1) exit 1 }') || {
    printf 'cannot locate local asset record for %s\n' "$asset_name" >&2
    exit 1
  }
  if [ -n "$uploaded_asset_records" ]; then
    expected_uploaded_asset_records=$(printf '%s\n%s' \
      "$uploaded_asset_records" "$asset_record")
  else
    expected_uploaded_asset_records=$asset_record
  fi

  begin_remote_write "asset-upload POST $asset_name"
  set +e
  run_asset_remote_write "$asset" "$asset_name"
  upload_status=$?
  set -e
  upload_reconciled=false
  remote_snapshot=
  for attempt in $(seq 1 6); do
    if remote_snapshot=$(fetch_release_snapshot "$release_id" 2>/dev/null) &&
       verify_release_snapshot "$remote_snapshot" "$release_id" true false \
         "$release_target_commitish" "$publish_prerelease" "$release_title" \
         "$notes_body_b64" &&
       verify_release_assets "$remote_snapshot" \
         "$expected_uploaded_asset_records" &&
       verify_tag_target &&
       current_immutability_policy=$(github_api \
         "repos/$GITHUB_REPOSITORY/immutable-releases" --jq \
         '[(.enabled | tostring), (.enforced_by_owner | tostring)] | @tsv' \
         2>/dev/null) &&
       [ "$current_immutability_policy" = "$immutability_policy" ]; then
      upload_reconciled=true
      break
    fi
    if [ -n "$remote_snapshot" ] &&
       { ! verify_release_snapshot "$remote_snapshot" "$release_id" true false \
           "$release_target_commitish" "$publish_prerelease" "$release_title" \
           "$notes_body_b64" ||
         ! verify_release_assets "$remote_snapshot" "$uploaded_asset_records"; }; then
      printf 'asset upload reconciliation observed an unknown or concurrently changed release state\n' >&2
      printf '%s\n' "$remote_snapshot" >&2
      fail_remote_write 'unknown or concurrently changed numeric release state'
    fi
    [ "$attempt" -eq 6 ] || sleep 1 || :
  done
  if ! $upload_reconciled; then
    printf 'asset upload outcome for %s is not the exact expected draft state (request status %s); no retry or takeover is attempted\n' \
      "$asset_name" "$upload_status" >&2
    [ ! -s "$remote_write_stderr" ] || /usr/bin/cat "$remote_write_stderr" >&2
    [ -z "$remote_snapshot" ] || printf '%s\n' "$remote_snapshot" >&2
    fail_remote_write 'indeterminate or non-matching; draft retained'
  fi
  if [ "$upload_status" -ne 0 ]; then
    printf 'asset upload transport failure for %s reconciled by release ID %s\n' \
      "$asset_name" "$release_id" >&2
  fi
  uploaded_asset_records=$expected_uploaded_asset_records
  finish_remote_write "exact draft with $asset_name uploaded"
done

final_snapshot=$(fetch_release_snapshot "$release_id") || {
  printf 'cannot fetch the final verified draft release snapshot\n' >&2
  exit 1
}
if ! verify_release_snapshot "$final_snapshot" "$release_id" true false \
     "$release_target_commitish" "$publish_prerelease" "$release_title" \
     "$notes_body_b64" ||
   ! verify_release_assets "$final_snapshot" "$local_asset_records"; then
  printf 'release changed concurrently after upload verification; release remains draft\n' >&2
  printf '%s\n' "$final_snapshot" >&2
  exit 1
fi
verify_tag_target || {
  printf 'release tag changed after draft verification; release remains draft\n' >&2
  exit 1
}
final_immutability_policy=$(github_api \
  "repos/$GITHUB_REPOSITORY/immutable-releases" --jq \
  '[(.enabled | tostring), (.enforced_by_owner | tostring)] | @tsv') || {
  printf 'cannot re-read the immutable-release policy after draft verification\n' >&2
  exit 1
}
[ "$final_immutability_policy" = "$immutability_policy" ] || {
  printf 'repository immutable-release policy changed during draft creation\n' >&2
  exit 1
}
printf 'Created verified %s %s with %d assets; draft remains private for manual publication.\n' \
  "$release_kind" "$release_tag" "${#assets[@]}"
