#!/usr/bin/env bash
if ! [[ -o privileged ]]; then
  builtin exit 126
fi
if [ "${HAPTICS_STAGE_CLEAN_ENV:-}" = 1 ]; then
  [[ ${PATH:-} = /usr/sbin:/usr/bin:/sbin:/bin ]] &&
    [[ ${LANG:-} = C ]] && [[ ${LC_ALL:-} = C ]] &&
    [[ ${TZ:-} = UTC ]] && [[ ${HOME:-} = /nonexistent ]] &&
    [[ ${TMPDIR:-} = /tmp ]] && [[ ${PWD:-} = /* ]] &&
    [[ ${SHLVL:-} =~ ^[0-9]+$ ]] || builtin exit 126
  stage_clean_environment=1
  while IFS= read -r -d '' stage_environment_entry; do
    stage_environment_name=${stage_environment_entry%%=*}
    case $stage_environment_name in
      HOME|HAPTICS_STAGE_CLEAN_ENV|LANG|LC_ALL|PATH|PWD|SHLVL|TMPDIR|TZ|_)
        ;;
      *)
        stage_clean_environment=0
        ;;
    esac
  done < <(/usr/bin/env -0)
  [ "$stage_clean_environment" = 1 ] || builtin exit 126
else
  stage_script=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}") || builtin exit 1
  builtin exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent TMPDIR=/tmp \
    HAPTICS_STAGE_CLEAN_ENV=1 \
    /bin/bash -p "$stage_script" "$@"
fi
set -euo pipefail
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
SCRIPT_DIR=$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(/usr/bin/realpath -e -- "$SCRIPT_DIR")
unset CI_CURL_BIN CI_ENV_BIN CI_GIT_BIN CI_PYTHON3_BIN CI_SHA256SUM_BIN
. "$SCRIPT_DIR/common.sh"
CI_GIT_BIN=/usr/bin/git
CI_ENV_BIN=/usr/bin/env
CI_CURL_BIN=/usr/bin/curl
CI_PYTHON3_BIN=/usr/bin/python3
CI_SHA256SUM_BIN=/usr/bin/sha256sum

[ "$#" -eq 12 ] ||
  ci_die "usage: stage-haptics-release-assets.sh PRODUCER_OUTPUT RELEASE_STAGE VERSION KERNEL_SOURCE_COMMIT KERNEL_ARCHIVE_URL KERNEL_ARCHIVE_SHA256 KERNEL_METADATA_URL KERNEL_METADATA_SHA256 KERNEL_SDK_MANIFEST_URL KERNEL_TOOLCHAIN_MANIFEST_URL PRODUCER_COMMIT WORKFLOW_RUN_ID"

producer_output=$1
release_stage=$2
haptics_version=$3
kernel_source_commit=$4
kernel_archive_url=$5
kernel_archive_sha256=$6
kernel_metadata_url=$7
kernel_metadata_sha256=$8
kernel_sdk_manifest_url=$9
kernel_toolchain_manifest_url=${10}
producer_commit=${11}
workflow_run_id=${12}

[[ $haptics_version =~ ^[0-9][0-9A-Za-z._-]{0,63}$ ]] ||
  ci_die "haptics release version is invalid"
/usr/bin/dpkg --validate-version "$haptics_version" >/dev/null ||
  ci_die "haptics release version is not a valid Debian version"
[[ $kernel_source_commit =~ ^[0-9a-f]{40}$ ]] ||
  ci_die "kernel source commit is invalid"
[[ $producer_commit =~ ^[0-9a-f]{40}$ ]] ||
  ci_die "haptics producer commit is invalid"
[[ $kernel_archive_sha256 =~ ^[0-9a-f]{64}$ ]] ||
  ci_die "kernel archive digest is invalid"
[[ $kernel_metadata_sha256 =~ ^[0-9a-f]{64}$ ]] ||
  ci_die "kernel metadata digest is invalid"
[[ $workflow_run_id =~ ^[1-9][0-9]{0,19}$ ]] ||
  ci_die "workflow run ID is invalid"
for url in \
  "$kernel_archive_url" "$kernel_metadata_url" \
  "$kernel_sdk_manifest_url" "$kernel_toolchain_manifest_url"; do
  [[ $url =~ ^https://[^[:space:]]{1,2048}$ ]] ||
    ci_die "haptics release input contains an invalid URL"
done

[ -d "$producer_output" ] && [ ! -L "$producer_output" ] ||
  ci_die "haptics producer output is not a real directory"
producer_output=$(/usr/bin/realpath -e -- "$producer_output")

[ ! -e "$release_stage" ] && [ ! -L "$release_stage" ] ||
  ci_die "haptics release stage already exists"
release_parent=$(/usr/bin/dirname -- "$release_stage")
/usr/bin/mkdir -p -- "$release_parent"
release_parent=$(/usr/bin/realpath -e -- "$release_parent")
release_stage="$release_parent/$(/usr/bin/basename -- "$release_stage")"

working_stage=
verification_root=
cleanup() {
  local rc=$?

  trap - EXIT INT TERM
  case $verification_root in
    "$release_parent"/.release-verification.*)
      [ ! -e "$verification_root" ] || /usr/bin/rm -rf -- "$verification_root"
      ;;
  esac
  case $working_stage in
    "$release_parent"/.release-staging.*)
      [ ! -e "$working_stage" ] || /usr/bin/rm -rf -- "$working_stage"
      ;;
  esac
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
working_stage=$(/usr/bin/mktemp -d "$release_parent/.release-staging.XXXXXX")
verification_root=$(/usr/bin/mktemp -d "$release_parent/.release-verification.XXXXXX")

release_dir="$working_stage/assets"
notes="$release_dir/BUILD-PARAMETERS.md"
compiled="$producer_output/HAPTICS-COMPILED-DIGESTS.env"
source_lock="$producer_output/HAPTICS-SOURCE-LOCK.tsv"
reference="$SCRIPT_DIR/HAPTICS-RELEASE-REFERENCE.tsv"
package_checksums="$producer_output/SHA256SUMS-tb321fu-haptics-debs.txt"
haptics_archive="$producer_output/tb321fu-haptics-debs_${haptics_version}_arm64.tar.gz"
sibling_deb="$producer_output/tb321fu-haptics_${haptics_version}_arm64.deb"
archive_extract="$verification_root/archive"
payload_extract="$verification_root/payload"

"$CI_PYTHON3_BIN" -I "$SCRIPT_DIR/verify-haptics-release-reference.py" "$reference"
haptics_deb=$(/bin/bash -p "$SCRIPT_DIR/verify-haptics-release-archive.sh" \
  "$haptics_archive" "$producer_output" "$haptics_version" "$archive_extract")
[ "$haptics_deb" = "$archive_extract/tb321fu-haptics_${haptics_version}_arm64.deb" ] ||
  ci_die "haptics archive verifier returned an unexpected DEB path"
for evidence in \
  "$compiled" "$source_lock" "$package_checksums" \
  "$haptics_archive" "$sibling_deb" "$haptics_deb"; do
  [ -f "$evidence" ] && [ ! -L "$evidence" ] ||
    ci_die "haptics release evidence is missing or unsafe: ${evidence##*/}"
done

env_value() {
  local key=$1 count

  count=$(/usr/bin/awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$compiled")
  [ "$count" -eq 1 ] || ci_die "compiled digest key is not unique: $key"
  /usr/bin/awk -F= -v key="$key" '$1 == key { print $2 }' "$compiled"
}

lock_value() {
  local key=$1 count

  count=$(/usr/bin/awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$source_lock")
  [ "$count" -eq 1 ] || ci_die "source-lock key is not unique: $key"
  /usr/bin/awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$source_lock"
}

reference_value() {
  local key=$1 count

  count=$(/usr/bin/awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$reference")
  [ "$count" -eq 1 ] || ci_die "release-reference key is not unique: $key"
  /usr/bin/awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$reference"
}

module_sha256=$(env_value HAPTICS_MODULE_SHA256)
helper_sha256=$(env_value HAPTICS_HELPER_BINARY_SHA256)
archive_sha256=$(env_value HAPTICS_ARCHIVE_SHA256)
compiled_deb_sha256=$(env_value HAPTICS_DEB_SHA256)
compiled_producer=$(env_value HAPTICS_PRODUCER_COMMIT)
kernel_bundle_id=$(lock_value kernel-bundle-id)
kernel_release=$(lock_value kernel-release)
source_lock_producer=$(lock_value haptics-producer-commit)
kernel_toolchain_manifest_sha256=$(lock_value kernel-toolchain-manifest-sha256)
manifest_deb_sha256=$(/usr/bin/awk \
  -v name="./tb321fu-haptics_${haptics_version}_arm64.deb" \
  '$2 == name { count++; digest=$1 } END { if (count == 1) print digest }' \
  "$package_checksums")
haptics_deb_sha256=$("$CI_SHA256SUM_BIN" -- "$haptics_deb" | /usr/bin/awk '{ print $1 }')
haptics_archive_sha256=$("$CI_SHA256SUM_BIN" -- "$haptics_archive" | /usr/bin/awk '{ print $1 }')
source_lock_sha256=$("$CI_SHA256SUM_BIN" -- "$source_lock" | /usr/bin/awk '{ print $1 }')
reference_producer=$(reference_value reference-producer-commit)
reference_archive_sha256=$(reference_value reference-archive-sha256)
reference_version=$(reference_value package-version)
reference_bundle_id=$(reference_value kernel-bundle-id)
reference_deb_sha256=$(reference_value haptics-deb-sha256)
reference_module_sha256=$(reference_value haptics-module-sha256)
reference_helper_sha256=$(reference_value haptics-helper-sha256)

for digest in \
  "$module_sha256" "$helper_sha256" "$archive_sha256" \
  "$compiled_deb_sha256" "$kernel_bundle_id" \
  "$kernel_toolchain_manifest_sha256" "$manifest_deb_sha256" \
  "$haptics_deb_sha256" "$haptics_archive_sha256" \
  "$source_lock_sha256" "$reference_archive_sha256" \
  "$reference_deb_sha256" "$reference_module_sha256" \
  "$reference_helper_sha256"; do
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || ci_die "haptics release digest is invalid"
done
[[ $compiled_producer =~ ^[0-9a-f]{40}$ ]] || ci_die "compiled producer is invalid"
[[ $reference_producer =~ ^[0-9a-f]{40}$ ]] || ci_die "reference producer is invalid"
[[ $source_lock_producer =~ ^[0-9a-f]{40}$ ]] || ci_die "source-lock producer is invalid"
[[ $kernel_release =~ ^[0-9A-Za-z][0-9A-Za-z._+~-]{0,127}$ ]] ||
  ci_die "kernel release is invalid"

[ "$compiled_producer" = "$producer_commit" ] ||
  ci_die "compiled producer differs from the workflow producer"
[ "$source_lock_producer" = "$producer_commit" ] ||
  ci_die "source-lock producer differs from the workflow producer"
ci_git cat-file -e "$reference_producer^{commit}" ||
  ci_die "trusted reference producer is absent from the checked-out history"
ci_git merge-base --is-ancestor "$reference_producer" "$producer_commit" ||
  ci_die "trusted reference producer is not an ancestor of the release producer"
[ "$reference_version" = "$haptics_version" ] ||
  ci_die "trusted reference version differs from the candidate"
[ "$reference_bundle_id" = "$kernel_bundle_id" ] ||
  ci_die "trusted kernel bundle differs from the candidate"
[ "$compiled_deb_sha256" = "$haptics_deb_sha256" ] ||
  ci_die "compiled DEB digest differs from the archive"
[ "$archive_sha256" = "$haptics_archive_sha256" ] ||
  ci_die "compiled archive digest differs from the archive"
[ "$manifest_deb_sha256" = "$haptics_deb_sha256" ] ||
  ci_die "package manifest DEB digest differs from the archive"
[ "$reference_deb_sha256" = "$haptics_deb_sha256" ] ||
  ci_die "candidate DEB differs from the trusted reference"

/usr/bin/mkdir -p -- "$payload_extract"
/usr/bin/dpkg-deb -x "$haptics_deb" "$payload_extract"
extracted_module="$payload_extract/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
extracted_helper="$payload_extract/usr/bin/tb321fu-haptic-test"
[ -f "$extracted_module" ] && [ ! -L "$extracted_module" ] ||
  ci_die "candidate haptics module is missing or unsafe"
[ -f "$extracted_helper" ] && [ ! -L "$extracted_helper" ] ||
  ci_die "candidate haptics helper is missing or unsafe"
extracted_module_sha256=$("$CI_SHA256SUM_BIN" -- "$extracted_module" | /usr/bin/awk '{ print $1 }')
extracted_helper_sha256=$("$CI_SHA256SUM_BIN" -- "$extracted_helper" | /usr/bin/awk '{ print $1 }')
[ "$module_sha256" = "$extracted_module_sha256" ] ||
  ci_die "compiled module digest differs from the DEB payload"
[ "$helper_sha256" = "$extracted_helper_sha256" ] ||
  ci_die "compiled helper digest differs from the DEB payload"
[ "$reference_module_sha256" = "$extracted_module_sha256" ] ||
  ci_die "candidate module differs from the trusted reference"
[ "$reference_helper_sha256" = "$extracted_helper_sha256" ] ||
  ci_die "candidate helper differs from the trusted reference"

/usr/bin/mkdir -m 0700 -- "$release_dir"
{
  echo '# TB321FU Haptics Debs'
  echo
  echo "- Package version: $haptics_version"
  echo "- Kernel source commit: $kernel_source_commit"
  echo "- Kernel SDK: $kernel_archive_url"
  echo "- Kernel SDK SHA-256: $kernel_archive_sha256"
  echo "- Kernel bundle metadata: $kernel_metadata_url"
  echo "- Kernel bundle metadata SHA-256: $kernel_metadata_sha256"
  echo "- Kernel bundle ID: $kernel_bundle_id"
  echo "- Kernel SDK manifest: $kernel_sdk_manifest_url"
  echo "- Kernel toolchain manifest: $kernel_toolchain_manifest_url"
  echo "- Kernel toolchain manifest SHA-256: $kernel_toolchain_manifest_sha256"
  echo "- Commit: $producer_commit"
  echo "- Workflow run: $workflow_run_id"
  echo "- Haptics archive SHA-256: $haptics_archive_sha256"
  echo "- Haptics DEB SHA-256: $haptics_deb_sha256"
  echo "- Haptics source lock SHA-256: $source_lock_sha256"
  echo "- Trusted reference producer: $reference_producer"
  echo "- Trusted reference archive SHA-256: $reference_archive_sha256"
  echo "- Trusted reference DEB SHA-256: $reference_deb_sha256"
  echo "- Candidate HAPTICS_MODULE_SHA256: $module_sha256"
  echo "- Candidate HAPTICS_HELPER_BINARY_SHA256: $helper_sha256"
  echo
  echo 'Static CI verifies package/lifecycle behavior; stop/suspend/resume remains a device gate.'
  echo 'Compiled digests require a byte-identical second trusted build and independent consumer pinning.'
} > "$notes"
/usr/bin/chmod 0644 "$notes"
/usr/bin/install -m 0644 \
  "$haptics_archive" \
  "$source_lock" \
  "$package_checksums" \
  "$release_dir/"
(
  cd "$release_dir"
  "$CI_SHA256SUM_BIN" -- \
    "tb321fu-haptics-debs_${haptics_version}_arm64.tar.gz" \
    HAPTICS-SOURCE-LOCK.tsv \
    SHA256SUMS-tb321fu-haptics-debs.txt \
    BUILD-PARAMETERS.md > SHA256SUMS.txt
  /usr/bin/chmod 0644 SHA256SUMS.txt
)
/bin/bash -p "$SCRIPT_DIR/verify-haptics-publication-stage.sh" \
  "$release_dir" "$reference" "$producer_commit" \
  "$verification_root/publication" >/dev/null

/usr/bin/mv --no-clobber -T -- "$working_stage" "$release_stage"
[ ! -e "$working_stage" ] && [ ! -L "$working_stage" ] ||
  ci_die "haptics release stage appeared during no-clobber promotion"
working_stage=
