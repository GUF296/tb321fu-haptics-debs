#!/usr/bin/env python3
"""Verify every non-Git member of a haptics release provenance archive."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import stat
import sys


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9][0-9A-Za-z._-]{0,63}")
KERNEL_RELEASE = re.compile(r"[0-9][0-9A-Za-z.+~-]{0,63}")
HTTPS = re.compile(r"https://[^\x00-\x20\x7f]{1,2040}")
PRINTABLE_240 = re.compile(r"[ -~]{1,240}")
POLICY_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
MAX_METADATA_BYTES = 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024

SOURCE_LOCK_FIELDS = (
    ("schema", re.compile(r"tb321fu\.haptics-source-lock/v4")),
    ("haptics-output-mode", re.compile(r"release-candidate")),
    ("haptics-producer-commit", HEX40),
    ("haptics-producer-state", re.compile(r"clean")),
    ("environment-policy", POLICY_NAME),
    ("environment-policy-sha256", HEX64),
    ("build-toolset-sha256", HEX64),
    ("build-tools-manifest", re.compile(r"HAPTICS-BUILD-TOOLS\.tsv")),
    ("build-tools-manifest-sha256", HEX64),
    ("aw86937-driver-sha256", HEX64),
    ("aw86937-build-source-sha256", HEX64),
    ("haptic-ram-firmware-sha256", HEX64),
    ("haptic-click-firmware-sha256", HEX64),
    ("haptic-test-helper-sha256", HEX64),
    ("aw86937-module-sha256", HEX64),
    ("haptic-test-helper-binary-sha256", HEX64),
    ("kernel-bundle-id", HEX64),
    ("kernel-toolchain-manifest-sha256", HEX64),
    ("kernel-release", KERNEL_RELEASE),
    ("kernel-source-commit", HEX40),
    ("kernel-config-sha256", HEX64),
    ("kernel-build-input", re.compile(r"kernel-sdk-archive")),
    ("kernel-build-archive-sha256", HEX64),
    ("source-date-epoch", re.compile(r"[0-9]{1,12}")),
)

REFERENCE_FIELDS = (
    ("schema", re.compile(r"tb321fu\.haptics-release-reference/v3")),
    ("reference-producer-commit", HEX40),
    ("reference-archive-sha256", HEX64),
    ("package-version", VERSION),
    ("kernel-bundle-id", HEX64),
    ("kernel-toolchain-manifest-sha256", HEX64),
    ("kernel-build-archive-url", HTTPS),
    ("kernel-bundle-metadata-url", HTTPS),
    ("kernel-bundle-metadata-sha256", HEX64),
    ("kernel-sdk-manifest-url", HTTPS),
    ("kernel-toolchain-manifest-url", HTTPS),
    ("build-toolset-sha256", HEX64),
    ("build-tools-manifest-sha256", HEX64),
    ("aw86937-driver-sha256", HEX64),
    ("aw86937-build-source-sha256", HEX64),
    ("haptic-ram-firmware-sha256", HEX64),
    ("haptic-click-firmware-sha256", HEX64),
    ("haptic-test-helper-sha256", HEX64),
    ("kernel-release", KERNEL_RELEASE),
    ("kernel-source-commit", HEX40),
    ("kernel-config-sha256", HEX64),
    ("kernel-build-archive-sha256", HEX64),
    ("haptics-deb-sha256", HEX64),
    ("haptics-module-sha256", HEX64),
    ("haptics-helper-sha256", HEX64),
)

REFERENCE_LOCK_BINDINGS = (
    ("kernel-bundle-id", "kernel-bundle-id"),
    ("kernel-toolchain-manifest-sha256", "kernel-toolchain-manifest-sha256"),
    ("build-toolset-sha256", "build-toolset-sha256"),
    ("build-tools-manifest-sha256", "build-tools-manifest-sha256"),
    ("aw86937-driver-sha256", "aw86937-driver-sha256"),
    ("aw86937-build-source-sha256", "aw86937-build-source-sha256"),
    ("haptic-ram-firmware-sha256", "haptic-ram-firmware-sha256"),
    ("haptic-click-firmware-sha256", "haptic-click-firmware-sha256"),
    ("haptic-test-helper-sha256", "haptic-test-helper-sha256"),
    ("kernel-release", "kernel-release"),
    ("kernel-source-commit", "kernel-source-commit"),
    ("kernel-config-sha256", "kernel-config-sha256"),
    ("kernel-build-archive-sha256", "kernel-build-archive-sha256"),
    ("aw86937-module-sha256", "haptics-module-sha256"),
    ("haptic-test-helper-binary-sha256", "haptics-helper-sha256"),
)

TOOL_NAMES = (
    "bash", "dash", "env", "readlink", "realpath", "basename", "dirname",
    "date", "sleep", "timeout", "mktemp", "mkdir", "rm", "chmod", "cp",
    "mv", "ln", "cat", "find", "install", "touch", "stat", "awk", "grep",
    "sed", "sort", "cut", "cmp", "tee", "tr", "wc", "git", "curl",
    "python3", "make", "flex", "bison", "m4", "gcc", "as", "ld", "ar",
    "rsync", "dpkg", "dpkg-deb", "sha256sum", "aarch64-linux-gnu-gcc",
    "aarch64-linux-gnu-cpp", "aarch64-linux-gnu-as", "aarch64-linux-gnu-ld",
    "aarch64-linux-gnu-ar", "aarch64-linux-gnu-nm",
    "aarch64-linux-gnu-objcopy", "aarch64-linux-gnu-objdump",
    "aarch64-linux-gnu-readelf", "aarch64-linux-gnu-strip", "modinfo", "tar",
    "gzip", "xz", "sh", "bc", "getconf", "sha1sum", "uname", "head",
    "expr", "uniq", "xargs",
)

SNAPSHOT_DIGEST_FIELDS = (
    (
        "aw86937-driver-sha256",
        "HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c",
    ),
    ("aw86937-build-source-sha256", "HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c"),
    (
        "haptic-ram-firmware-sha256",
        "HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin",
    ),
    (
        "haptic-click-firmware-sha256",
        "HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin",
    ),
    (
        "haptic-test-helper-sha256",
        "HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c",
    ),
)


class ProvenanceError(ValueError):
    pass


def read_regular(root: pathlib.Path, relative: str, maximum: int) -> bytes:
    path = root / relative
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProvenanceError(f"cannot inspect provenance member {relative}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o644:
        raise ProvenanceError(f"provenance member is not regular mode 0644: {relative}")
    if before.st_size > maximum:
        raise ProvenanceError(f"provenance member is oversized: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(after):
        raise ProvenanceError(f"provenance member changed while reading: {relative}")
    if len(raw) != opened.st_size or len(raw) > maximum:
        raise ProvenanceError(f"provenance member size changed while reading: {relative}")
    return bytes(raw)


def read_reference(path: pathlib.Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProvenanceError(f"cannot inspect trusted release reference: {exc}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) not in (0o400, 0o644)
        or before.st_size > MAX_METADATA_BYTES
    ):
        raise ProvenanceError("trusted release reference is not a bounded regular file")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_METADATA_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_METADATA_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if (
        identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or len(raw) != opened.st_size
        or len(raw) > MAX_METADATA_BYTES
    ):
        raise ProvenanceError("trusted release reference changed while reading")
    return bytes(raw)


def parse_exact_tsv(raw: bytes, fields: tuple[tuple[str, re.Pattern[str]], ...], label: str) -> dict[str, str]:
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ProvenanceError(f"{label} must be NUL/CR-free and end with LF")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ProvenanceError(f"{label} must contain ASCII only") from exc
    if len(lines) != len(fields):
        raise ProvenanceError(f"{label} has {len(lines)} fields, expected {len(fields)}")
    values: dict[str, str] = {}
    for index, ((expected_key, validator), line) in enumerate(zip(fields, lines, strict=True), 1):
        if line.count("\t") != 1:
            raise ProvenanceError(f"{label} field {index} must contain exactly one tab")
        key, value = line.split("\t", 1)
        if key != expected_key or validator.fullmatch(value) is None:
            raise ProvenanceError(f"invalid {label} field {index}: {expected_key}")
        values[key] = value
    return values


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_build_tools(root: pathlib.Path, lock: dict[str, str]) -> None:
    raw = read_regular(root, "HAPTICS-BUILD-TOOLS.tsv", MAX_METADATA_BYTES)
    if sha256(raw) != lock["build-tools-manifest-sha256"]:
        raise ProvenanceError("build-tools manifest SHA-256 mismatch")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ProvenanceError("build-tools manifest has invalid framing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ProvenanceError("build-tools manifest must contain ASCII only") from exc
    if len(lines) != 4 + len(TOOL_NAMES):
        raise ProvenanceError("build-tools manifest has an unexpected line count")
    headers = (
        "schema\ttb321fu.haptics-build-tools/v2",
        f"environment-policy\t{lock['environment-policy']}",
        f"environment-policy-sha256\t{lock['environment-policy-sha256']}",
        f"build-toolset-sha256\t{lock['build-toolset-sha256']}",
    )
    if tuple(lines[:4]) != headers:
        raise ProvenanceError("build-tools manifest headers differ from the source lock")
    tool_lines = lines[4:]
    for index, (expected_name, line) in enumerate(zip(TOOL_NAMES, tool_lines, strict=True), 5):
        if line.count("\t") != 5:
            raise ProvenanceError(f"build-tool record {index} must contain six fields")
        kind, name, command_path, resolved_path, digest, version = line.split("\t")
        if kind != "tool" or name != expected_name:
            raise ProvenanceError(f"unexpected build-tool order at line {index}")
        for value in (command_path, resolved_path):
            if not value.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
                raise ProvenanceError(f"unsafe build-tool path at line {index}")
            if "//" in value or "/../" in value or value.endswith(("/..", "/.")) or "\\" in value:
                raise ProvenanceError(f"unsafe build-tool path at line {index}")
        if HEX64.fullmatch(digest) is None or PRINTABLE_240.fullmatch(version) is None:
            raise ProvenanceError(f"invalid build-tool identity at line {index}")
    toolset_raw = "".join(f"{line}\n" for line in tool_lines).encode("ascii")
    if sha256(toolset_raw) != lock["build-toolset-sha256"]:
        raise ProvenanceError("build-toolset SHA-256 mismatch")


def verify_checksums(root: pathlib.Path, version: str, lock: dict[str, str]) -> None:
    deb_name = f"tb321fu-haptics_{version}_arm64.deb"
    expected = (
        deb_name,
        "HAPTICS-SOURCE-LOCK.tsv",
        "HAPTICS-BUILD-TOOLS.tsv",
        "HAPTICS-PRODUCER.bundle",
        SNAPSHOT_DIGEST_FIELDS[0][1],
        SNAPSHOT_DIGEST_FIELDS[1][1],
        SNAPSHOT_DIGEST_FIELDS[2][1],
        SNAPSHOT_DIGEST_FIELDS[3][1],
        SNAPSHOT_DIGEST_FIELDS[4][1],
    )
    raw = read_regular(root, "SHA256SUMS-tb321fu-haptics-debs.txt", MAX_METADATA_BYTES)
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ProvenanceError("inner checksum manifest has invalid framing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ProvenanceError("inner checksum manifest must contain ASCII only") from exc
    if len(lines) != len(expected):
        raise ProvenanceError("inner checksum manifest must contain exactly nine records")
    for index, (relative, line) in enumerate(zip(expected, lines, strict=True), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        if match is None or match.group(2) != relative:
            raise ProvenanceError(f"invalid inner checksum record {index}")
        maximum = (
            MAX_PAYLOAD_BYTES
            if relative in (deb_name, "HAPTICS-PRODUCER.bundle")
            else MAX_METADATA_BYTES
        )
        actual = sha256(read_regular(root, relative, maximum))
        if actual != match.group(1):
            raise ProvenanceError(f"inner checksum mismatch: {relative}")
    if sha256(read_regular(root, deb_name, MAX_PAYLOAD_BYTES)) != lock["__expected_deb"]:
        raise ProvenanceError("embedded haptics DEB differs from the trusted reference")
    for field, relative in SNAPSHOT_DIGEST_FIELDS:
        if sha256(read_regular(root, relative, MAX_METADATA_BYTES)) != lock[field]:
            raise ProvenanceError(f"source snapshot differs from source-lock field: {field}")


def verify(args: argparse.Namespace) -> None:
    if VERSION.fullmatch(args.version) is None:
        raise ProvenanceError("unsafe haptics package version")
    if HEX40.fullmatch(args.expected_producer) is None:
        raise ProvenanceError("invalid expected producer commit")
    reference = parse_exact_tsv(
        read_reference(args.reference), REFERENCE_FIELDS, "trusted release reference"
    )
    if reference["package-version"] != args.version:
        raise ProvenanceError("package version differs from the trusted release reference")
    lock_raw = read_regular(args.root, "HAPTICS-SOURCE-LOCK.tsv", MAX_METADATA_BYTES)
    lock = parse_exact_tsv(lock_raw, SOURCE_LOCK_FIELDS, "haptics source lock")
    if lock["haptics-producer-commit"] != args.expected_producer:
        raise ProvenanceError("haptics producer commit mismatch")
    for lock_field, reference_field in REFERENCE_LOCK_BINDINGS:
        if lock[lock_field] != reference[reference_field]:
            raise ProvenanceError(
                f"haptics source lock differs from trusted reference: {lock_field}"
            )
    lock["__expected_deb"] = reference["haptics-deb-sha256"]
    verify_build_tools(args.root, lock)
    verify_checksums(args.root, args.version, lock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("version")
    parser.add_argument("expected_producer")
    parser.add_argument("reference", type=pathlib.Path)
    args = parser.parse_args()
    try:
        verify(args)
    except (ProvenanceError, OSError, ValueError) as exc:
        print(f"haptics release provenance verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
