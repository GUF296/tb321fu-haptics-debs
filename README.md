# TB321FU Haptics Debs

Builds the verified AW86937 haptics Debian package for Lenovo Legion Y700 (2025) / TB321FU.

Output:

- `tb321fu-haptics_<version>_arm64.deb`
- `tb321fu-haptics-debs_<version>_arm64.tar.gz`
- `HAPTICS-PRODUCER.bundle`
- `HAPTICS-SOURCE-SNAPSHOT/`
- `HAPTICS-SOURCE-LOCK.tsv` and portable SHA-256 manifests
- `HAPTICS-COMPILED-DIGESTS.env` (local workflow evidence, outside the tar)

`HAPTICS-SOURCE-LOCK.tsv` uses the ordered
`tb321fu.haptics-source-lock/v1` schema. It records the exact clean producer
commit, canonical and patched driver hashes, both firmware hashes, the
test-helper source hash, final module/helper binary hashes, and the paired
kernel bundle identity. `HAPTICS-SOURCE-SNAPSHOT/` carries those five source
inputs at fixed paths. The builder exports the original inputs from the
expected commit's Git objects into a private snapshot; it never compiles or
installs the mutable worktree copies. Assume-unchanged and skip-worktree index
flags are rejected in addition to ordinary dirty-worktree state.

`HAPTICS-PRODUCER.bundle` is a self-contained Git bundle with no prerequisites.
It exposes exactly one ref, `refs/heads/tb321fu-haptics-producer`, whose tip is
the producer commit recorded in the lock. The outer tar has exactly five root
entries: the versioned DEB, `HAPTICS-SOURCE-LOCK.tsv`,
`SHA256SUMS-tb321fu-haptics-debs.txt`, `HAPTICS-PRODUCER.bundle`, and
`HAPTICS-SOURCE-SNAPSHOT/`. The tar command names the DEB and all five snapshot
files explicitly; it uses neither a DEB glob nor recursive directory selection.

Both builders treat `OUTPUT_DIR` as a new publication target. They reject a
pre-existing target, work in private sibling staging directories, validate
exact root/member lists and portable checksums, and use one `mv -T` promotion.
The outer archive is streamed once into its final staging filesystem, avoiding
a second full archive copy before promotion.
Before publication, the final DEB is unpacked and checked against a closed
eight-data-file/three-control-file contract, including member types, paths,
modes, bytes, and final firmware/module/helper digests.

The workflow builds an external module from a paired kernel source commit and
kernel build SDK. Release dispatches must provide all five locked inputs:

- `kernel_source_commit`: exact 40-hex `GUF296/linux` commit
- `kernel_build_archive`: HTTPS SDK archive URL
- `kernel_build_archive_sha256`: SHA-256 of that exact archive
- `kernel_bundle_metadata`: HTTPS URL of the paired `KERNEL-BUNDLE.tsv`
- `kernel_bundle_metadata_sha256`: SHA-256 of that exact metadata file

The checked-in defaults reconstruct the tested `7.1.1-g5df8e852ea72`
baseline. A remediation release must override all five fields with the new
commit-bound SDK and bundle. The release tag defaults to empty; when explicitly set,
publication uses a prerelease by default and refuses to modify an existing
public release.

The SDK wrapper also emits deterministic `HAPTICS-COMPILED-DIGESTS.env` lines
for `HAPTICS_PRODUCER_COMMIT`, `HAPTICS_DEB_SHA256`,
`HAPTICS_ARCHIVE_SHA256`, `HAPTICS_MODULE_SHA256`, and
`HAPTICS_HELPER_BINARY_SHA256`. This file is outside the five-root tar and is
not an additional bootstrap release asset. Its values are evidence/input
material only: the record is not self-authenticating when obtained from the
same untrusted build. A release consumer must receive the module/helper values
through separately trusted dispatcher configuration and require them to equal
both the lock and actual DEB bytes.

The haptics tar does not carry the kernel SDK or a pinned compiler/binutils
toolchain, so it cannot independently reproduce compiled bytes. Final trusted
values therefore require two byte-identical trusted builds, comparing at least
the final archive digest, plus independent pinning of the module and helper
digests. The source bundle proves source/recipe identity; it does not by itself
prove that compiled bytes were derived from that source.

The package provides `tb321fu-haptics.service`, `/usr/libexec/tb321fu-haptics/bind-aw86937`, firmware, udev feedbackd integration, and `/dev/input/tb321fu-haptics-left/right` symlinks.

For the remediation bootstrap, do not create a duplicate kernel SDK. Invoke
`build-tb321fu-haptics-deb.sh` directly with the clean local kernel source,
external kernel Git database, existing build directory, generated
`KERNEL-BUNDLE.tsv`, and `EXPECTED_HAPTICS_PRODUCER_COMMIT`. The standalone
GitHub workflow remains the remote-SDK reconstruction path. Any archive handed
to a rootfs builder must keep `HAPTICS-SOURCE-LOCK.tsv`,
`HAPTICS-PRODUCER.bundle`, `HAPTICS-SOURCE-SNAPSHOT/`, the DEB, and the portable
checksum manifest together.
