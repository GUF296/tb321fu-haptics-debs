# TB321FU Haptics Debs

Builds the verified AW86937 haptics Debian package for Lenovo Legion Y700 (2025) / TB321FU.

Output:

- `tb321fu-haptics_<version>_arm64.deb`
- `tb321fu-haptics-debs_<version>_arm64.tar.gz`
- `HAPTICS-SOURCE-LOCK.tsv` and portable SHA-256 manifests

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

The package provides `tb321fu-haptics.service`, `/usr/libexec/tb321fu-haptics/bind-aw86937`, firmware, udev feedbackd integration, and `/dev/input/tb321fu-haptics-left/right` symlinks.
