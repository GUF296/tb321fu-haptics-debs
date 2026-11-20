#!/bin/bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo 'usage: run-in-haptics-toolchain.sh IMAGE_ID_FILE MODE' >&2
  exit 2
fi
iid_file=$1
mode=$2
[[ -f $iid_file && ! -L $iid_file && $(/usr/bin/stat -c %s -- "$iid_file") == 72 ]]
IFS= read -r iid < "$iid_file"
[[ $iid =~ ^sha256:[0-9a-f]{64}$ ]]
[[ $(/usr/bin/docker image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$iid") == "$iid linux amd64" ]]

repo=$(pwd -P)
[[ -d $repo/.git && ! -L $repo/.git && $repo != *,* ]]
uid=$(/usr/bin/id -u)
gid=$(/usr/bin/id -g)
[[ $uid != 0 && $gid != 0 ]]
scratch=$(/usr/bin/mktemp -d -- "${iid_file%/*}/haptics-container.XXXXXXXX")
trap '/usr/bin/rm -rf -- "$scratch"' EXIT
[[ $scratch != *,* ]]
opts=(--rm --init --pull=never --platform=linux/amd64 --read-only
      --cap-drop=ALL --security-opt=no-new-privileges
      --user "$uid:$gid" --workdir /workspace
      --mount "type=bind,src=$repo,dst=/workspace,readonly"
      --mount "type=bind,src=$scratch,dst=/tmp"
      --env PATH=/usr/sbin:/usr/bin:/sbin:/bin --env HOME=/nonexistent
      --env LANG=C --env LC_ALL=C --env TZ=UTC --env TMPDIR=/tmp)
if [[ $mode == cross-link ]]; then
  /usr/bin/docker run "${opts[@]}" --network=none "$iid" /bin/bash -p \
    scripts/ci/test-haptics-cross-link-closure.sh scripts/ci/HAPTICS-BUILD-PACKAGES.tsv
elif [[ $mode == kernel-metadata ]]; then
  /usr/bin/docker run "${opts[@]}" --network=none "$iid" /usr/bin/python3 -I -B \
    scripts/ci/test-kernel-bundle-metadata.py
elif [[ $mode == build-environment ]]; then
  /usr/bin/docker run "${opts[@]}" --network=none "$iid" /bin/bash -p \
    scripts/ci/test-haptics-build-environment.sh
elif [[ $mode == build ]]; then
  [[ ${OUTPUT_DIR:-} == out/tb321fu-haptics-debs ]]
  # The SDK wrapper creates its own output tree by atomic rename within out/.
  /usr/bin/mkdir -p -- "$repo/out"
  [[ -d $repo/out && ! -L $repo/out ]]
  opts+=(--mount "type=bind,src=$repo/out,dst=/workspace/out")
  for name in http_proxy https_proxy no_proxy OUTPUT_DIR ARCH HAPTICS_DEB_VERSION \
      HAPTICS_STRIP HAPTICS_RELEASE_MODE HAPTICS_PRODUCER_COMMIT KERNEL_SOURCE_COMMIT \
      KERNEL_BUILD_ARCHIVE KERNEL_BUILD_ARCHIVE_SHA256 KERNEL_BUNDLE_METADATA \
      KERNEL_BUNDLE_METADATA_SHA256 KERNEL_SDK_MANIFEST KERNEL_TOOLCHAIN_MANIFEST \
      SOURCE_DATE_EPOCH; do
    opts+=(--env "$name")
  done
  /usr/bin/docker run "${opts[@]}" "$iid" /bin/bash -p \
    scripts/ci/build-tb321fu-haptics-deb-from-kernel-sdk.sh
else
  echo "unknown toolchain mode: $mode" >&2
  exit 2
fi
