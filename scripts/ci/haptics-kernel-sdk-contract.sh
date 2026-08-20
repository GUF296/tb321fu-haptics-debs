#!/usr/bin/env bash
# Shared input and binding checks for portable haptics release candidates.

haptics_validate_kernel_build_input_contract() {
  local release_mode=$1 kernel_build_archive=$2 kernel_build_archive_sha256=$3
  local kernel_build_dir=$4 kernel_bundle_metadata=$5 kernel_bundle_metadata_sha256=$6
  local kernel_sdk_manifest=$7 kernel_toolchain_manifest=$8

  case "$release_mode" in
    0|1) ;;
    *) ci_die "HAPTICS_RELEASE_MODE must be exactly 0 or 1" ;;
  esac

  if [ -n "$kernel_build_archive" ] && [ -n "$kernel_build_dir" ]; then
    ci_die "set exactly one of KERNEL_BUILD_ARCHIVE or KERNEL_BUILD_DIR"
  fi
  if [ -n "$kernel_build_archive" ]; then
    [[ $kernel_build_archive_sha256 =~ ^[0-9A-Fa-f]{64}$ ]] ||
      ci_die "invalid KERNEL_BUILD_ARCHIVE_SHA256"
  elif [ -n "$kernel_build_archive_sha256" ]; then
    ci_die "KERNEL_BUILD_ARCHIVE_SHA256 requires KERNEL_BUILD_ARCHIVE"
  fi
  if [ -n "$kernel_bundle_metadata" ] || [ -n "$kernel_bundle_metadata_sha256" ]; then
    [ -n "$kernel_bundle_metadata" ] && [ -n "$kernel_bundle_metadata_sha256" ] ||
      ci_die "KERNEL_BUNDLE_METADATA and KERNEL_BUNDLE_METADATA_SHA256 must be provided together"
    [[ $kernel_bundle_metadata_sha256 =~ ^[0-9A-Fa-f]{64}$ ]] ||
      ci_die "invalid KERNEL_BUNDLE_METADATA_SHA256"
  fi
  if [ "$release_mode" = 1 ]; then
    [ -n "$kernel_build_archive" ] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires KERNEL_BUILD_ARCHIVE"
    [ -z "$kernel_build_dir" ] ||
      ci_die "HAPTICS_RELEASE_MODE=1 forbids KERNEL_BUILD_DIR"
    [ -n "$kernel_bundle_metadata" ] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires KERNEL_BUNDLE_METADATA"
    [ -n "$kernel_sdk_manifest" ] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires KERNEL_SDK_MANIFEST"
    [ -n "$kernel_toolchain_manifest" ] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires KERNEL_TOOLCHAIN_MANIFEST"
    [[ $kernel_build_archive =~ ^https://[^[:space:]]{1,2048}$ ]] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires an HTTPS KERNEL_BUILD_ARCHIVE"
    [[ $kernel_bundle_metadata =~ ^https://[^[:space:]]{1,2048}$ ]] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires HTTPS KERNEL_BUNDLE_METADATA"
    [[ $kernel_sdk_manifest =~ ^https://[^[:space:]]{1,2048}$ ]] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires HTTPS KERNEL_SDK_MANIFEST"
    [[ $kernel_toolchain_manifest =~ ^https://[^[:space:]]{1,2048}$ ]] ||
      ci_die "HAPTICS_RELEASE_MODE=1 requires HTTPS KERNEL_TOOLCHAIN_MANIFEST"
  else
    [ -z "$kernel_build_archive" ] ||
      ci_die "HAPTICS_RELEASE_MODE=0 forbids KERNEL_BUILD_ARCHIVE"
    [ -z "$kernel_sdk_manifest" ] ||
      ci_die "HAPTICS_RELEASE_MODE=0 forbids KERNEL_SDK_MANIFEST"
    [ -z "$kernel_toolchain_manifest" ] ||
      ci_die "HAPTICS_RELEASE_MODE=0 forbids KERNEL_TOOLCHAIN_MANIFEST"
    [ -n "$kernel_build_dir" ] ||
      ci_die "HAPTICS_RELEASE_MODE=0 requires KERNEL_BUILD_DIR"
  fi
}

haptics_validate_kernel_sdk_binding() {
  local release_mode=$1 kernel_build_input=$2 kernel_build_archive_sha256=$3
  local kernel_bundle_id=$4 kernel_bundle_sdk_archive_sha256=$5

  if [ "$kernel_build_input" = kernel-sdk-archive ] && [ "$kernel_bundle_id" != unbound ]; then
    [[ $kernel_build_archive_sha256 =~ ^[0-9a-f]{64}$ ]] ||
      ci_die "kernel SDK archive identity is not a lowercase SHA-256"
    [[ $kernel_bundle_sdk_archive_sha256 =~ ^[0-9a-f]{64}$ ]] ||
      ci_die "KERNEL-BUNDLE.tsv lacks a valid kernel-sdk-archive-sha256"
    [ "$kernel_build_archive_sha256" = "$kernel_bundle_sdk_archive_sha256" ] ||
      ci_die "kernel SDK archive SHA-256 differs from KERNEL-BUNDLE.tsv"
  fi

  [ "$release_mode" = 1 ] || return 0
  [ "$kernel_build_input" = kernel-sdk-archive ] ||
    ci_die "HAPTICS_RELEASE_MODE=1 requires a kernel SDK archive input"
  [[ $kernel_build_archive_sha256 =~ ^[0-9a-f]{64}$ ]] ||
    ci_die "release kernel SDK archive identity is not a lowercase SHA-256"
  [[ $kernel_bundle_sdk_archive_sha256 =~ ^[0-9a-f]{64}$ ]] ||
    ci_die "KERNEL-BUNDLE.tsv lacks a valid kernel-sdk-archive-sha256"
  [[ $kernel_bundle_id =~ ^[0-9a-f]{64}$ ]] ||
    ci_die "KERNEL-BUNDLE.tsv lacks a valid kernel-bundle-id"
  [ "$kernel_build_archive_sha256" = "$kernel_bundle_sdk_archive_sha256" ] ||
    ci_die "kernel SDK archive SHA-256 differs from KERNEL-BUNDLE.tsv"
}
