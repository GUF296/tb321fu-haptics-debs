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
`tb321fu.haptics-source-lock/v4` schema only for release candidates. Its
second field is `haptics-output-mode=release-candidate`; its kernel fields end
with `kernel-build-input=kernel-sdk-archive` and
`kernel-build-archive-sha256`. That digest must exactly equal the paired
KERNEL-BUNDLE v2 `kernel-sdk-archive-sha256`. A direct local directory build
instead emits `tb321fu.haptics-source-lock/v4-local`,
`haptics-output-mode=local`, `kernel-build-input=local-directory`, and the
non-digest `local-build-directory` sentinel. Consumers must reject that local
schema and sentinel. Both schemas otherwise record the exact clean producer
commit, canonical and patched driver hashes, both firmware hashes, test-helper
source hash, final module/helper binary hashes, and paired kernel bundle
identity. The v4 release schema also records the bundle-bound
`kernel-toolchain-manifest-sha256`; the local schema records the explicit
`unbound` sentinel. `HAPTICS-SOURCE-SNAPSHOT/` carries those five source inputs at fixed
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
`HEAD` before any SDK or build step. Redirects, automatic tag following, and
submodule recursion are disabled for this exact-commit fetch.
Every external build/packaging tool is resolved to an absolute regular
executable before use; its path, SHA-256, and version line are recorded in
`HAPTICS-BUILD-TOOLS.tsv`, then rechecked before atomic promotion. The v4 lock
binds the policy name/digest, toolset digest, fixed manifest name, and manifest
digest. DEB compression is explicitly xz level 6 with one thread, independent
of runner CPU count and dpkg defaults. The build-tools manifest is itself named by the portable checksum
manifest.

The release workflow uses the x86_64 `ubuntu-24.04` runner with the ARM64 cross
toolchain, matching the host architecture used to produce and validate the
canonical kernel SDK. An ARM64 host runner is not interchangeable: regenerating
Kbuild host tools there changes compiler-probed configuration, and the
post-regeneration config identity gate rejects that drift before packaging.
`HAPTICS-BUILD-PACKAGES.tsv` v2 locks 109 A12 command-provider/runtime roots and
their complete 100-package selected dependency closure. All 209 package records
carry exact `amd64`/`all` architecture, version, and
`bootstrap`/`requested`/`closure` role. The only general apt source is Ubuntu's signed
`20260730T000000Z` snapshot, restricted to `main`; runner sources, lists and
package caches are excluded through private apt directories. A first-stage
private `APT_CONFIG` also excludes runner apt configuration, hooks, preferences,
authentication files and global trust directories before apt parses them, and
restricts index resolution to the native `amd64` architecture. All private apt
state is removed after the transaction. Native dpkg must itself match the locked
bootstrap version before package mutation. `/etc/dpkg/dpkg.cfg` is bound to the
reviewed Ubuntu digest and ownership/mode/link contract, `dpkg.cfg.d` must be
empty, and `/root/.dpkg.cfg` must not exist; appended native dpkg hooks or path
filters therefore fail before apt update. The glibc 2.39 `.8`,
OpenLDAP 2.6.7, and systemd 255.4 `.17` packages that are absent from the
primary snapshot are ten explicit compatibility records, each bound
to one immutable Ubuntu snapshot URL, SHA-256, Package, Version and
Architecture. Downloads remain private through verification, then the same
verified inode is atomically exposed root-owned and read-only through an
`_apt`-traversable directory. Their older snapshots are never exposed as general apt sources.
Unsigned repositories, `trusted=yes`, unauthenticated installation and mutable
fallback sources are prohibited.

The installer verifies the apt/dpkg/keyring bootstrap before network access and
authenticates and inspects each compatibility DEB before package mutation. It
then runs an empty-status apt simulation whose exact `Inst`/`Conf` tuples must
equal the 209-package lock, and a second simulation whose old/new tuples must
equal the delta from a captured runner state. One apt transaction consumes the
same exact repository arguments and verified local DEBs. Complete dpkg package
status, selections, foreign architectures, and alternatives are compared before
and after; no package or alternative outside policy may change, removals are
forbidden, dpkg audit and apt dependency checks must remain clean, and apt's
unsandboxed-root local-file fallback is fatal. The installer sets `awk`
explicitly to manual `/usr/bin/gawk`; command paths for `sh`, GCC/CPP, binutils and `modinfo` are covered by
the full manifest comparison. A fresh 69-tool `HAPTICS-BUILD-TOOLS.tsv` must be
byte-identical to committed `HAPTICS-BUILD-TOOLS-REFERENCE.tsv`, whose digest is
authenticated by `HAPTICS-RELEASE-REFERENCE.tsv`, before any kernel source or
large SDK download. The bundle-bound `KERNEL-TOOLCHAIN.tsv` then independently
checks Kbuild compiler, binutils, generator, shell and Bison data-tree
identities. Kbuild uses the manifest-bound GCC driver for `CPP=$(CC) -E`; it
does not depend on the v2 manifest's omitted standalone CPP.

These older packages are a compatibility lock for A12, not a permanent update
policy. They temporarily replace newer runner security packages and therefore
belong only in this isolated producer job. The long-term replacement is a
reviewed digest-pinned producer image. Any future canonical image or kernel
SDK/toolchain refresh must update the package lock, build-tools reference,
`KERNEL-TOOLCHAIN.tsv` and haptics release reference together, then complete
fresh byte-identical producer builds before the A12 pins are removed.

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
`HAPTICS_RELEASE_MODE=1`, which requires all seven locked inputs:

- `kernel_source_commit`: exact 40-hex `GUF296/linux` commit
- `kernel_build_archive`: HTTPS SDK archive URL
- `kernel_build_archive_sha256`: SHA-256 of that exact archive
- `kernel_bundle_metadata`: HTTPS URL of the paired `KERNEL-BUNDLE.tsv` v2
- `kernel_bundle_metadata_sha256`: SHA-256 of that exact metadata file
- `kernel_sdk_manifest`: HTTPS URL of the paired `KERNEL-SDK-MANIFEST.tsv`; its
  SHA-256 must equal the `kernel-sdk-manifest-sha256` field in that bundle
- `kernel_toolchain_manifest`: HTTPS URL of the paired `KERNEL-TOOLCHAIN.tsv`
  v2; its SHA-256 must equal the `kernel-toolchain-manifest-sha256` field in
  that bundle

The SDK archive, its digest, and the KERNEL-BUNDLE v2 digest are checked before
the archive is extracted or the module is compiled. A mismatch, an old schema,
or a missing metadata field fails the build. The release tag defaults to empty;
when explicitly set, the read-only Actions job validates the release contract
and uploads one attempt-unique staging artifact. Actions never receives a
release credential, creates a tag, or mutates a release. Draft creation and the
final prerelease transition are explicit operator-local steps from the exact
clean producer checkout and downloaded staging artifact.
An empty-tag run exposes only an attempt-specific `diagnostic-*` build artifact;
a tagged run exposes only the five-asset staging artifact after the complete
publication gate. The workflow and its validator reject every additional
artifact-upload action.

The candidate deliberately uses a clean pushed isolated remediation ref rather
than the default branch. Remote dispatch accepts only a candidate commit `C`
whose sole parent is the reviewed trusted commit `P` and whose Git tree is
byte-identical to `P`'s tree. Thus `C` changes commit identity only: it cannot
change the workflow, builder, package input, validator, or any other checked-out
byte. A workspace-external launcher rendered only after both commits exist pins
the repository, `P`, `C`, the exact `codex-dispatch/<C>` ref, and the SHA-256 of
the gate, workflow, and both workflow validators. It independently rehashes the
complete commit/tree/blob SHA-1 chains, privately exports and executes only the
gate blob from `P`, retains its authenticated read-only inode through
`/proc/self/fd`, and then passes those same fixed identities to the gate. One
absolute monotonic deadline is propagated inside the launcher's own cleanup
deadline. The launcher is a Linux child subreaper and kills/reaps escaped
sessions as well as its primary process group on every exit path. Mutable
worktree, private-path replacements, or candidate scripts are never
authorization roots.

The launcher's private root is owned by its initial `(device,inode)` identity
and an authenticated directory descriptor held through mode and namespace
verification. Descriptor creation is recovered across applied-before-return
failures. Cleanup is non-recursive: it removes only recorded empty directories
and exact owned inodes. An unidentifiable path or replacement is preserved and
causes failure; it is never adopted as launcher-owned state or recursively
removed.

The renderer's success boundary is deliberately finite: it retains authenticated
output and parent descriptors in a terminal custody object, rechecks complete
metadata, namespace identity, and the fd-derived SHA-256 after every earlier
close/callback boundary, and emits its evidence while that custody remains live.
Process teardown releases the final credentials after the transcript; the
reported pathname is not claimed to remain immutable afterward. The sole
verify/dispatch entry is the production runner below. `BOOTSTRAP_OUTPUT` and
`BOOTSTRAP_SHA256` must be the exact `output` and `sha256` fields from one
successful renderer transcript; do not execute the rendered pathname directly
or manually reproduce the descriptor handoff.

```sh
repo="$(pwd -P)"
runner="$repo/scripts/ci/run-haptics-workflow-dispatch-bootstrap.py"

/usr/bin/python3 -I -B "$runner" \
  --launcher "$BOOTSTRAP_OUTPUT" \
  --launcher-sha256 "$BOOTSTRAP_SHA256" \
  --repo-dir "$repo" \
  --timeout-seconds 330 \
  --verify-only

/usr/bin/python3 -I -B "$runner" \
  --launcher "$BOOTSTRAP_OUTPUT" \
  --launcher-sha256 "$BOOTSTRAP_SHA256" \
  --repo-dir "$repo" \
  --timeout-seconds 330 \
  --profile diagnostic

/usr/bin/python3 -I -B "$runner" \
  --launcher "$BOOTSTRAP_OUTPUT" \
  --launcher-sha256 "$BOOTSTRAP_SHA256" \
  --repo-dir "$repo" \
  --timeout-seconds 330 \
  --profile release
```

The runner alone reopens the launcher with `O_NOFOLLOW`, revalidates its
metadata and SHA-256, copies those authenticated bytes into a
`MFD_ALLOW_SEALING` memfd, requires
`F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`, and executes only
`/proc/self/fd/<sealed-fd>`. A verify-only PASS is required before the diagnostic
profile, and the diagnostic profile must reconcile successfully before release.

The launcher atomically captures and blocks its cancellation signals before it
installs the outer guard. It buffers all evidence until descendant cleanup,
descriptor closure, pending-signal consumption, handler restoration and signal-
mask handoff have succeeded; a cancellation or cleanup failure before that
point emits no evidence or PASS marker. A signal arriving after the final
pending-signal boundary belongs to the restored caller policy. Consumers must
therefore require exit status zero, the complete exact evidence transcript and
the final `HAPTICS_WORKFLOW_BOOTSTRAP=PASS` line together; a marker or partial
transcript on a nonzero process result is never authorization.
The runner also forwards the bounded transcript through nonblocking writes with
a five-second caller-backpressure deadline. A parent that stops reading cannot
hold the verification process indefinitely; the runner fails closed instead of
claiming a complete transcript.
Both the gate and bootstrap transcripts are strict UTF-8 byte contracts with
one fixed field order, one occurrence of each terminal marker, and a final LF.
Replacement decoding, CRLF, a missing final LF, duplicate markers, extra lines,
or trailing bytes all fail closed and cannot authorize a release dispatch.

Before dispatch, the candidate-derived ref must point to `C` and have branch
protection with updates and deletion disabled, `lock_branch=true`, and fork
syncing disabled. The gate rechecks that state immediately before its sole POST
and again afterward. Its at-most-once ledger lives only under the canonical
passwd account home and is bound to `P`, `C`, all reviewed path/mode/digests,
the complete input set, and either the `diagnostic` or `release` profile. The
diagnostic profile uses an empty tag; only after it reconciles successfully may
the separate release profile request the new prerelease tag. These client-side
checks cannot make an administrator ref/protection change atomic with GitHub's
POST, so all other repository administrators must leave that unique ref and its
protection unchanged through final reconciliation.

This policy keeps default and tested refs untouched: only a never-used dispatch
ref, a never-used tag, and a new prerelease may be created, and no tested tag,
asset, release or default branch may be replaced or retargeted.
The dedicated GitHub repository must have immutable releases enabled before a
tag or draft is created. The publisher checks that policy before and after draft
creation, requires every uploaded asset to reach `uploaded`, and leaves the
draft itself non-immutable until the reviewed publication transition.
For a tagged run, `release_tag` must be exactly
`tb321fu-haptics-debs-<haptics_deb_version>` and the version must equal the
committed trusted release reference; this gate runs before the SDK download.
`HAPTICS-RELEASE-REFERENCE.tsv` uses the exact
`tb321fu.haptics-release-reference/v3` schema and authenticates the accepted
source, build-tool, kernel-profile, DEB, module, and helper identities.

Each prerelease also includes `BUILD-PARAMETERS.md` as a checksum-covered
release asset. The publisher uses those exact bytes as the release body and
verifies the release title and body before upload and again on the completed
draft. Manual publication is a separate release-ID operation with before/after
tag, metadata, asset, prerelease, and latest-state checks.

After a tagged staging run succeeds, download only its exact run/attempt
artifact, keep the producer checkout at that run's committed SHA, and create the
private draft locally:

```bash
gh run download <run-id> \
  --repo GUF296/tb321fu-haptics-debs \
  --name release-staging-<run-id>-<run-attempt> \
  --dir <verified-staging-directory>

GH_TOKEN="$(gh auth token)" \
GITHUB_REPOSITORY=GUF296/tb321fu-haptics-debs \
GITHUB_SHA=<exact-producer-commit> \
PRERELEASE=1 \
PATH=/usr/bin:/bin \
/usr/bin/env -u BASH_ENV /bin/bash -p scripts/ci/publish-release.sh \
  tb321fu-haptics-debs-<haptics_deb_version> \
  <verified-staging-directory>/assets \
  <verified-staging-directory>/assets/BUILD-PARAMETERS.md
```

The draft creator accepts exactly the five release assets and no other entry.
Before its first API request it requires a clean tracked producer checkout at
`GITHUB_SHA`, the fixed repository, committed trusted reference and ancestry,
the v4 source lock, exact archive layout, and the trusted embedded DEB/module/
helper identities. One release-create POST owns both private-draft and public-tag
creation through `target_commitish`; there is no separate `git/refs` mutation.
That POST occurs before asset upload and final draft verification. A failed
operation can therefore leave the new public tag plus a private empty or
partially uploaded draft. It refuses to modify an existing release or tag, so
that identity must be preserved and never reused. Inspect it read-only by exact
tag, then continue only with the reported numeric release ID after its target,
draft/prerelease state, title, body and complete asset set have been reconciled:

```bash
gh api repos/GUF296/tb321fu-haptics-debs/git/ref/tags/<exact-tag>
gh api repos/GUF296/tb321fu-haptics-debs/releases/tags/<exact-tag> \
  --jq '{id,tag_name,target_commitish,draft,prerelease,immutable,name,assets}'
```

After reviewing the private draft, publish only by its numeric release ID from
the exact producer checkout and the unchanged staged asset directory:

```bash
GH_TOKEN="$(gh auth token)" \
GH_ALLOW_PUBLISH=1 \
GITHUB_REPOSITORY=GUF296/tb321fu-haptics-debs \
GITHUB_SHA=<exact-producer-commit> \
PATH=/usr/bin:/bin \
/usr/bin/env -u BASH_ENV /bin/bash -p scripts/ci/publish-draft-release-by-id.sh \
  <numeric-release-id> \
  tb321fu-haptics-debs-<haptics_deb_version> \
  <verified-release-assets-directory> \
  <verified-release-assets-directory>/BUILD-PARAMETERS.md
```

The operation requires the script to come from a tracked-clean producer checkout
whose `HEAD` equals `GITHUB_SHA`. Before any API request it validates the fixed
committed reference, the v4 release source lock, producer ancestry, bundle,
module/helper identities, exact outer-tar contract, and the embedded DEB's A12
SHA-256. It then requires the existing release to remain a non-immutable draft
prerelease, resolves its tag to `GITHUB_SHA`, compares every remote asset name,
size, SHA-256 digest and `uploaded` state with a freshly re-enumerated local
five-asset set, and snapshots the current latest release twice. A repository
with no current non-prerelease latest release is a valid, explicitly represented
state.

The only mutation PATCHes `draft=false`, retains `prerelease=true`, and sends
`make_latest=false`. The public result must report `immutable=true`; the script
then repeats release, tag, asset, local-file, immutable-policy and latest-state
checks. A transport failure after GitHub applies the PATCH is reconciled by
re-reading the numeric ID and classified as verified public, exactly unchanged
draft, or unknown/mutated; never retry an unknown result blindly. The token is
removed from ordinary child environments and exposed only to fixed-host
`gh api --hostname github.com` processes.

GitHub does not document compare-and-swap semantics for this draft transition.
Stop every other owner-token release writer during the final policy/latest/tag/
draft/PATCH sequence. Postchecks detect a concurrent change but cannot make that
small server-side interval atomic. A failed post-publication check does not roll
back or reuse the now-public identity; inspect the numeric ID and treat the
failure as publication evidence requiring review.

The SDK wrapper also emits deterministic `HAPTICS-COMPILED-DIGESTS.env` lines
for `HAPTICS_PRODUCER_COMMIT`, `HAPTICS_DEB_SHA256`,
`HAPTICS_ARCHIVE_SHA256`, `HAPTICS_MODULE_SHA256`, and
`HAPTICS_HELPER_BINARY_SHA256`. This file is outside the six-root tar and is
not an additional bootstrap release asset. Its values are evidence/input
material only: the record is not self-authenticating when obtained from the
same untrusted build. A release consumer must receive the module/helper values
through separately trusted dispatcher configuration and require them to equal
both the lock and actual DEB bytes.

The haptics tar does not carry the kernel SDK or toolchain binaries, so it cannot
independently reproduce compiled bytes. Two canonical reference builds must be
byte-identical across their complete output trees. A GitHub-hosted publisher
build may differ only in commit/epoch-bound provenance members such as the
source lock, Git bundle, notes, and outer archive. Before staging a tagged
release it must exactly match the commit-bound
`HAPTICS-RELEASE-REFERENCE.tsv` source, build-tool manifest, kernel profile,
DEB, module, and helper digests, with module/helper recomputed from the actual
DEB. The source lock and compiled ledger must both identify the exact workflow
commit, and the reference producer must be an available ancestor of that
commit. The source bundle is checked semantically for its one exact ref; it is
not by itself proof that compiled bytes came from that source. A digest-pinned
amd64 builder image is the long-term route to complete local/Actions archive
identity.

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
