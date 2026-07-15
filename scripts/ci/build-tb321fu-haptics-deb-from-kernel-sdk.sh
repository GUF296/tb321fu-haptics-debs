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
KERNEL_SOURCE_COMMIT=${KERNEL_SOURCE_COMMIT:-5df8e852ea722929f5359a5ef28ebcec0c4443fd}
KERNEL_BUILD_ARCHIVE=${KERNEL_BUILD_ARCHIVE:-https://github.com/GUF296/tb321fu-haptics-debs/releases/download/kernel-sdk-7.1.1-g5df8e852ea72/tb321fu-kernel-build-sdk-7.1.1-g5df8e852ea72.tar.gz}
KERNEL_BUILD_ARCHIVE_SHA256=${KERNEL_BUILD_ARCHIVE_SHA256:-75703c4cf2ed10777905d79c57103ce1a9e50a02d09507c4aa15eb81b27c845a}
KERNEL_BUNDLE_METADATA=${KERNEL_BUNDLE_METADATA:-}
KERNEL_BUNDLE_METADATA_SHA256=${KERNEL_BUNDLE_METADATA_SHA256:-}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}

[[ $KERNEL_SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || ci_die "invalid KERNEL_SOURCE_COMMIT"
[[ $KERNEL_BUILD_ARCHIVE_SHA256 =~ ^[0-9A-Fa-f]{64}$ ]] || ci_die "invalid KERNEL_BUILD_ARCHIVE_SHA256"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{1,10}$ ]] || ci_die "invalid SOURCE_DATE_EPOCH"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-kernel.XXXXXX")
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

kernel_source="$work_dir/linux"
ci_log "fetching exact kernel source: $KERNEL_SOURCE_REPO $KERNEL_SOURCE_COMMIT"
git init -q "$kernel_source"
git -C "$kernel_source" remote add origin "$KERNEL_SOURCE_REPO"
git -C "$kernel_source" fetch --depth 1 origin "$KERNEL_SOURCE_COMMIT"
git -C "$kernel_source" checkout -q --detach FETCH_HEAD
actual_kernel_commit=$(git -C "$kernel_source" rev-parse HEAD)
[ "$actual_kernel_commit" = "$KERNEL_SOURCE_COMMIT" ] ||
  ci_die "kernel fetch returned $actual_kernel_commit instead of $KERNEL_SOURCE_COMMIT"

env \
  OUTPUT_DIR="$OUTPUT_DIR" \
  ARCH="$ARCH" \
  HAPTICS_DEB_VERSION="$HAPTICS_DEB_VERSION" \
  HAPTICS_SOURCE_DIR="$REPO_ROOT" \
  KERNEL_SOURCE_DIR="$kernel_source" \
  KERNEL_BUILD_ARCHIVE="$KERNEL_BUILD_ARCHIVE" \
  KERNEL_BUILD_ARCHIVE_SHA256="$KERNEL_BUILD_ARCHIVE_SHA256" \
  KERNEL_BUNDLE_METADATA="$KERNEL_BUNDLE_METADATA" \
  KERNEL_BUNDLE_METADATA_SHA256="$KERNEL_BUNDLE_METADATA_SHA256" \
  EXPECTED_KERNEL_SOURCE_COMMIT="$KERNEL_SOURCE_COMMIT" \
  HAPTICS_STRIP="$HAPTICS_STRIP" \
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  bash "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"

archive_dir=$(cd -- "$OUTPUT_DIR" && pwd -P)
(cd "$archive_dir" && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -czf "tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz" \
  ./*.deb HAPTICS-SOURCE-LOCK.tsv SHA256SUMS-tb321fu-haptics-debs.txt)
(cd "$archive_dir" && \
  sha256sum "tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz" > SHA256SUMS-archive.txt)
ci_log "haptics deb archive ready: $archive_dir/tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz"
