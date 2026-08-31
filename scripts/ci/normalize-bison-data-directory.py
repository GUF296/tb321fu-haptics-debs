#!/usr/bin/env python3
"""Normalize the hosted Bison data-directory mode without following races."""

from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile


CANONICAL_PATH = pathlib.Path("/usr/share/bison")
EXPECTED_MODE = 0o755


class NormalizationError(RuntimeError):
    """Raised when the Bison data directory cannot be authenticated."""


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
    )


def _require_directory(path: pathlib.Path, expected_uid: int, expected_gid: int) -> os.stat_result:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise NormalizationError(f"cannot inspect Bison data directory: {exc}") from exc
    if resolved != path:
        raise NormalizationError("Bison data directory is not the canonical path")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
    ):
        raise NormalizationError("Bison data directory has an unsafe type or owner")
    return metadata


def normalize(path: pathlib.Path = CANONICAL_PATH, *, expected_uid: int = 0, expected_gid: int = 0) -> None:
    """Set only the authenticated directory's mode and verify the namespace."""
    before = _require_directory(path, expected_uid, expected_gid)
    descriptor = -1
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise NormalizationError("Bison data directory changed while it was opened")
        if opened.st_uid != expected_uid or opened.st_gid != expected_gid:
            raise NormalizationError("Bison data directory owner changed while it was opened")
        try:
            os.fchmod(descriptor, EXPECTED_MODE)
        except OSError as exc:
            raise NormalizationError(f"cannot normalize Bison data directory mode: {exc}") from exc
        after = os.fstat(descriptor)
        path_after = path.lstat()
        resolved_after = path.resolve(strict=True)
        if (
            resolved_after != path
            or _identity(path_after)[:2] != _identity(before)[:2]
            or stat.S_IFMT(after.st_mode) != stat.S_IFDIR
            or stat.S_IMODE(after.st_mode) != EXPECTED_MODE
            or after.st_uid != expected_uid
            or after.st_gid != expected_gid
            or _identity(after)[:2] != _identity(opened)[:2]
        ):
            raise NormalizationError("Bison data directory changed during normalization")
    except OSError as exc:
        raise NormalizationError(f"cannot open Bison data directory: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _expect_failure(path: pathlib.Path, *, expected_uid: int, expected_gid: int) -> None:
    try:
        normalize(path, expected_uid=expected_uid, expected_gid=expected_gid)
    except NormalizationError:
        return
    raise SystemExit(f"unsafe Bison fixture was accepted: {path}")


def self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    with tempfile.TemporaryDirectory(prefix="tb321fu-bison-normalize-") as temporary:
        root = pathlib.Path(temporary)
        good = root / "good"
        good.mkdir(mode=0o755)
        good.chmod(0o775)
        normalize(good, expected_uid=uid, expected_gid=gid)
        if stat.S_IMODE(good.stat().st_mode) != EXPECTED_MODE:
            raise SystemExit("Bison mode normalization did not produce 0755")

        regular = root / "regular"
        regular.write_bytes(b"not a directory\n")
        _expect_failure(regular, expected_uid=uid, expected_gid=gid)

        target = root / "target"
        target.mkdir(mode=0o755)
        link = root / "link"
        link.symlink_to(target, target_is_directory=True)
        _expect_failure(link, expected_uid=uid, expected_gid=gid)

        if uid == 0:
            nobody = root / "wrong-owner"
            nobody.mkdir(mode=0o755)
            os.chown(nobody, 65534, 65534)
            _expect_failure(nobody, expected_uid=0, expected_gid=0)

    print("HAPTICS_BISON_NORMALIZATION_FIXTURE=PASS")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if sys.argv[1:]:
        raise SystemExit("usage: normalize-bison-data-directory.py [--self-test]")
    if os.geteuid() != 0:
        raise SystemExit("Bison data-directory normalization must run as root")
    normalize()
    print("HAPTICS_BISON_DATA_DIRECTORY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
