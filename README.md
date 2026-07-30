# TB321FU Haptics Debs

Builds the verified AW86937 haptics Debian package for Lenovo Legion Y700 (2025) / TB321FU.

Output:

- `tb321fu-haptics_<version>_arm64.deb`
- `tb321fu-haptics-debs_<version>_arm64.tar.gz`
- `HAPTICS-PRODUCER.bundle`
- `HAPTICS-BUILD-TOOLS.tsv`
- `HAPTICS-SOURCE-SNAPSHOT/`
- `HAPTICS-SOURCE-LOCK.tsv` and portable SHA-256 manifests
- `HAPTICS-COMPILED-DIGESTS.env` (local workflow evidence, outside the tar)

`HAPTICS-SOURCE-LOCK.tsv` uses the ordered
`tb321fu.haptics-source-lock/v3` schema only for release candidates. Its
second field is `haptics-output-mode=release-candidate`; its kernel fields end
with `kernel-build-input=kernel-sdk-archive` and
`kernel-build-archive-sha256`. That digest must exactly equal the paired
KERNEL-BUNDLE v2 `kernel-sdk-archive-sha256`. A direct local directory build
instead emits `tb321fu.haptics-source-lock/v3-local`,
`haptics-output-mode=local`, `kernel-build-input=local-directory`, and the
non-digest `local-build-directory` sentinel. Consumers must reject that local
schema and sentinel. Both schemas otherwise record the exact clean producer
commit, canonical and patched driver hashes, both firmware hashes, test-helper
source hash, final module/helper binary hashes, and paired kernel bundle
identity. `HAPTICS-SOURCE-SNAPSHOT/` carries those five source inputs at fixed
paths. The builder exports the original inputs from the expected commit's Git
objects into a private snapshot; it never compiles or installs mutable
worktree copies. Assume-unchanged and skip-worktree index flags are rejected in
addition to ordinary dirty-worktree state.

Both producer layers run with the `isolated-allowlist-v1` environment policy:
`env -i`, `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, C locale, UTC, an explicit
`SOURCE_DATE_EPOCH`, declared producer inputs, and only normalized
`http_proxy`, `https_proxy`, and `no_proxy` transport settings. Dynamic Make,
Kbuild, compiler, tar, gzip, xz, and dpkg environment variables are discarded.
The SDK wrapper fetches the exact kernel commit with at most four HTTP/1.1
attempts, discards the complete private repository after each failed attempt,
applies bounded 1/2/3-second retry delays, limits each network attempt to ten
minutes plus a 30-second forced-termination window, and rechecks the detached
`HEAD` before any SDK or build step.
Every external build/packaging tool is resolved to an absolute regular
executable before use; its path, SHA-256, and version line are recorded in
`HAPTICS-BUILD-TOOLS.tsv`, then rechecked before atomic promotion. The v3 lock
binds the policy name/digest, toolset digest, fixed manifest name, and manifest
digest. DEB compression is explicitly xz level 6 with one thread, independent
of runner CPU count and dpkg defaults. The build-tools manifest is itself named by the portable checksum
manifest.

`HAPTICS-PRODUCER.bundle` is a self-contained Git bundle with no prerequisites.
It exposes exactly one ref, `refs/heads/tb321fu-haptics-producer`, whose tip is
the producer commit recorded in the lock. The outer tar has exactly six root
entries: the versioned DEB, `HAPTICS-SOURCE-LOCK.tsv`,
`HAPTICS-BUILD-TOOLS.tsv`,
`SHA256SUMS-tb321fu-haptics-debs.txt`, `HAPTICS-PRODUCER.bundle`, and
`HAPTICS-SOURCE-SNAPSHOT/`. The tar command names the DEB and all five snapshot
files explicitly; it uses neither a DEB glob nor recursive directory selection.

Both builders treat `OUTPUT_DIR` as a new publication target. They reject a
pre-existing target, work in private sibling staging directories, validate
exact root/member lists and portable checksums, and use one `mv -T` promotion.
The outer archive is streamed once into its final staging filesystem, avoiding
a second full archive copy before promotion.
Before publication, the final DEB is unpacked and checked against a closed
nine-data-file/four-control-file contract, including member types, paths,
modes, bytes, and final firmware/module/helper digests.

The workflow builds a release candidate external module only from a paired
kernel source commit and kernel SDK archive. It explicitly sets
`HAPTICS_RELEASE_MODE=1`, which requires all six locked inputs:

- `kernel_source_commit`: exact 40-hex `GUF296/linux` commit
- `kernel_build_archive`: HTTPS SDK archive URL
- `kernel_build_archive_sha256`: SHA-256 of that exact archive
- `kernel_bundle_metadata`: HTTPS URL of the paired `KERNEL-BUNDLE.tsv` v2
- `kernel_bundle_metadata_sha256`: SHA-256 of that exact metadata file
- `kernel_sdk_manifest`: HTTPS URL of the paired `KERNEL-SDK-MANIFEST.tsv`; its
  SHA-256 must equal the `kernel-sdk-manifest-sha256` field in that bundle

The SDK archive, its digest, and the KERNEL-BUNDLE v2 digest are checked before
the archive is extracted or the module is compiled. A mismatch, an old schema,
or a missing metadata field fails the build. The release tag defaults to empty;
when explicitly set, the publisher creates and verifies a prerelease draft,
then leaves it private for manual publication. It refuses to modify an existing
release or draft.

Each prerelease also includes `BUILD-PARAMETERS.md` as a checksum-covered
release asset. The publisher uses those exact bytes as the release body and
verifies the release title and body before upload, before publication, and after
publication.

The SDK wrapper also emits deterministic `HAPTICS-COMPILED-DIGESTS.env` lines
for `HAPTICS_PRODUCER_COMMIT`, `HAPTICS_DEB_SHA256`,
`HAPTICS_ARCHIVE_SHA256`, `HAPTICS_MODULE_SHA256`, and
`HAPTICS_HELPER_BINARY_SHA256`. This file is outside the six-root tar and is
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
`KERNEL-BUNDLE.tsv`, and `EXPECTED_HAPTICS_PRODUCER_COMMIT` with
`HAPTICS_RELEASE_MODE=0`. That output is intentionally nonportable and must
not be passed to a rootfs builder. The standalone GitHub workflow remains the
remote-SDK reconstruction path. Any archive handed to a rootfs builder must
keep `HAPTICS-SOURCE-LOCK.tsv`, `HAPTICS-PRODUCER.bundle`,
`HAPTICS-SOURCE-SNAPSHOT/`, the DEB, and the portable checksum manifest
together.
