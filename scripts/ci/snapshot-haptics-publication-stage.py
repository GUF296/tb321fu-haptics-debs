#!/usr/bin/env python3
"""Copy one immutable, checksum-closed haptics publication stage."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import stat
import sys


VERSION = re.compile(r"[0-9][0-9A-Za-z._-]{0,63}")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024


class SnapshotError(ValueError):
    pass


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def list_exact_directory(descriptor: int, expected: tuple[str, ...]) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) == len(expected):
                    raise SnapshotError("publication directory contains more than five entries")
                names.append(entry.name)
    except SnapshotError:
        raise
    except OSError as exc:
        raise SnapshotError(f"cannot enumerate publication directory: {exc}") from exc
    actual = tuple(sorted(names))
    if actual != tuple(sorted(expected)):
        raise SnapshotError("publication directory does not contain the exact five assets")
    return actual


def copy_regular(
    source_dir_fd: int,
    name: str,
    destination_dir_fd: int,
    maximum: int,
) -> tuple[int, tuple[int, ...]]:
    try:
        source_fd = os.open(name, open_flags(), dir_fd=source_dir_fd)
    except OSError as exc:
        raise SnapshotError(f"cannot open publication asset {name}: {exc}") from exc
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotError(f"publication asset is not regular: {name}")
        if stat.S_IMODE(before.st_mode) != 0o644:
            raise SnapshotError(f"publication asset mode is not 0644: {name}")
        if before.st_size > maximum:
            raise SnapshotError(f"publication asset exceeds its size limit: {name}")
        destination_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_dir_fd,
        )
        copied = 0
        try:
            while copied < before.st_size:
                chunk = os.read(source_fd, min(1024 * 1024, before.st_size - copied))
                if not chunk:
                    raise SnapshotError(f"publication asset ended while copying: {name}")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise SnapshotError(f"cannot write publication snapshot: {name}")
                    view = view[written:]
                copied += len(chunk)
            if os.read(source_fd, 1):
                raise SnapshotError(f"publication asset grew while copying: {name}")
            os.fchmod(destination_fd, 0o644)
        finally:
            os.close(destination_fd)
        after = os.fstat(source_fd)
        if identity(before) != identity(after) or copied != before.st_size:
            raise SnapshotError(f"publication asset changed while copying: {name}")
        return copied, identity(before)
    finally:
        os.close(source_fd)


def snapshot(source: pathlib.Path, notes: pathlib.Path, version: str, destination: pathlib.Path) -> None:
    if VERSION.fullmatch(version) is None:
        raise SnapshotError("unsafe haptics package version")
    archive_name = f"tb321fu-haptics-debs_{version}_arm64.tar.gz"
    expected = (
        "BUILD-PARAMETERS.md",
        "HAPTICS-SOURCE-LOCK.tsv",
        "SHA256SUMS-tb321fu-haptics-debs.txt",
        "SHA256SUMS.txt",
        archive_name,
    )
    maximum = {name: MAX_METADATA_BYTES for name in expected}
    maximum[archive_name] = MAX_ARCHIVE_BYTES

    try:
        source_fd = os.open(source, open_flags(directory=True))
    except OSError as exc:
        raise SnapshotError(f"cannot open publication directory: {exc}") from exc
    destination_created = False
    try:
        source_before = os.fstat(source_fd)
        if not stat.S_ISDIR(source_before.st_mode):
            raise SnapshotError("publication source is not a directory")
        list_exact_directory(source_fd, expected)

        try:
            notes_fd = os.open(notes, open_flags())
        except OSError as exc:
            raise SnapshotError(f"cannot open publication notes: {exc}") from exc
        try:
            notes_stat = os.fstat(notes_fd)
            asset_notes_fd = os.open("BUILD-PARAMETERS.md", open_flags(), dir_fd=source_fd)
            try:
                asset_notes_stat = os.fstat(asset_notes_fd)
            finally:
                os.close(asset_notes_fd)
            if identity(notes_stat) != identity(asset_notes_stat):
                raise SnapshotError("publication notes are not the stage BUILD-PARAMETERS.md inode")
        finally:
            os.close(notes_fd)

        try:
            os.mkdir(destination, mode=0o700)
            destination_created = True
        except OSError as exc:
            raise SnapshotError(f"cannot create publication snapshot: {exc}") from exc
        destination_fd = os.open(destination, open_flags(directory=True))
        try:
            total = 0
            for name in sorted(expected):
                copied, _ = copy_regular(source_fd, name, destination_fd, maximum[name])
                total += copied
                if total > MAX_TOTAL_BYTES:
                    raise SnapshotError("publication assets exceed the total size limit")
        finally:
            os.close(destination_fd)

        try:
            list_exact_directory(source_fd, expected)
        except SnapshotError as exc:
            raise SnapshotError("publication directory changed while it was copied") from exc
        source_after = os.fstat(source_fd)
        if identity(source_before) != identity(source_after):
            raise SnapshotError("publication directory changed while it was copied")
        path_after = os.lstat(source)
        if not stat.S_ISDIR(path_after.st_mode) or (
            path_after.st_dev,
            path_after.st_ino,
        ) != (source_before.st_dev, source_before.st_ino):
            raise SnapshotError("publication directory path changed while it was copied")
    except Exception:
        if destination_created:
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        os.close(source_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("notes", type=pathlib.Path)
    parser.add_argument("version")
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    try:
        snapshot(args.source, args.notes, args.version, args.destination)
    except (SnapshotError, OSError, ValueError) as exc:
        print(f"haptics publication snapshot failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
