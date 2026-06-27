#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
. "$SCRIPT_DIR/common.sh"

OUTPUT_DIR=${OUTPUT_DIR:-out/tb321fu-haptics-debs}
ARCH=${ARCH:-arm64}
HAPTICS_DEB_VERSION=${HAPTICS_DEB_VERSION:-20260627.1}
HAPTICS_STRIP=${HAPTICS_STRIP:-1}
KERNEL_SOURCE_REPO=${KERNEL_SOURCE_REPO:-https://github.com/GUF296/linux.git}
KERNEL_SOURCE_REF=${KERNEL_SOURCE_REF:-TB321FU-7.1.1}
KERNEL_BUILD_ARCHIVE=${KERNEL_BUILD_ARCHIVE:-https://github.com/GUF296/tb321fu-haptics-debs/releases/download/kernel-sdk-7.1.1-g5df8e852ea72/tb321fu-kernel-build-sdk-7.1.1-g5df8e852ea72.tar.gz}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-kernel.XXXXXX")
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

kernel_source="$work_dir/linux"
ci_log "cloning kernel source: $KERNEL_SOURCE_REPO $KERNEL_SOURCE_REF"
git clone --depth 1 --branch "$KERNEL_SOURCE_REF" "$KERNEL_SOURCE_REPO" "$kernel_source" 2>/dev/null || {
  git clone "$KERNEL_SOURCE_REPO" "$kernel_source"
  git -C "$kernel_source" checkout "$KERNEL_SOURCE_REF"
}

env \
  OUTPUT_DIR="$OUTPUT_DIR" \
  ARCH="$ARCH" \
  HAPTICS_DEB_VERSION="$HAPTICS_DEB_VERSION" \
  HAPTICS_SOURCE_DIR="$REPO_ROOT" \
  KERNEL_SOURCE_DIR="$kernel_source" \
  KERNEL_BUILD_ARCHIVE="$KERNEL_BUILD_ARCHIVE" \
  HAPTICS_STRIP="$HAPTICS_STRIP" \
  bash "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"

archive_dir=$(cd -- "$OUTPUT_DIR" && pwd -P)
(cd "$archive_dir" && tar -czf "tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz" ./*.deb SHA256SUMS-tb321fu-haptics-debs.txt)
sha256sum "$archive_dir/tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz" > "$archive_dir/SHA256SUMS-archive.txt"
ci_log "haptics deb archive ready: $archive_dir/tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz"
