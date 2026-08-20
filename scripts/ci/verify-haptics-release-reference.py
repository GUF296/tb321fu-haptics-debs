#!/usr/bin/env python3
"""Validate the commit-bound haptics payload reference profile."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import sys


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HTTPS = re.compile(r"https://[^\x00-\x20\x7f]{1,2040}")
FIELDS = (
    ("schema", re.compile(r"tb321fu\.haptics-release-reference/v3")),
    ("reference-producer-commit", HEX40),
    ("reference-archive-sha256", HEX64),
    ("package-version", re.compile(r"[0-9][0-9A-Za-z.+~_-]{0,63}")),
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
    ("kernel-release", re.compile(r"[0-9][0-9A-Za-z.+~-]{0,63}")),
    ("kernel-source-commit", HEX40),
    ("kernel-config-sha256", HEX64),
    ("kernel-build-archive-sha256", HEX64),
    ("haptics-deb-sha256", HEX64),
    ("haptics-module-sha256", HEX64),
    ("haptics-helper-sha256", HEX64),
)
MAX_BYTES = 8192


class ReferenceError(ValueError):
    pass


def parse_reference(path: pathlib.Path) -> tuple[dict[str, str], bytes]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReferenceError(f"cannot open reference: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise ReferenceError("reference must be a bounded regular file")
        raw = os.read(descriptor, MAX_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_id = (before.st_dev, before.st_ino, before.st_mode, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns)
    after_id = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)
    if before_id != after_id or len(raw) != before.st_size:
        raise ReferenceError("reference changed while it was read")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ReferenceError("reference must be NUL/CR-free and end with LF")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ReferenceError("reference must contain ASCII only") from exc
    if len(lines) != len(FIELDS):
        raise ReferenceError(
            f"reference has {len(lines)} fields, expected {len(FIELDS)}"
        )
    values: dict[str, str] = {}
    for index, ((expected_key, validator), line) in enumerate(
        zip(FIELDS, lines, strict=True), start=1
    ):
        if line.count("\t") != 1:
            raise ReferenceError(f"reference field {index} must contain one tab")
        key, value = line.split("\t", 1)
        if key != expected_key or validator.fullmatch(value) is None:
            raise ReferenceError(f"invalid reference field {index}: {expected_key}")
        values[key] = value
    return values, raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("--emit-tsv", action="store_true")
    args = parser.parse_args()
    try:
        _, raw = parse_reference(args.reference)
    except (ReferenceError, OSError) as exc:
        print(f"haptics release reference verification failed: {exc}", file=sys.stderr)
        return 1
    if args.emit_tsv:
        sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
