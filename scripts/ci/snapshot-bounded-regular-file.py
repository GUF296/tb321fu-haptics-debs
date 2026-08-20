#!/usr/bin/env python3
"""Copy one no-follow regular file after stable descriptor verification."""

from __future__ import annotations

import argparse
import os
import pathlib
import stat
import sys


class SnapshotError(ValueError):
    pass


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def snapshot(source: pathlib.Path, destination: pathlib.Path, maximum: int, mode: int) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise SnapshotError(f"cannot open source: {exc}") from exc
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode:
            raise SnapshotError(f"source must be a regular mode-{mode:04o} file")
        if before.st_size > maximum:
            raise SnapshotError("source exceeds the snapshot size limit")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        copied = 0
        try:
            while copied < before.st_size:
                chunk = os.read(source_fd, min(1024 * 1024, before.st_size - copied))
                if not chunk:
                    raise SnapshotError("source ended while it was copied")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise SnapshotError("cannot write snapshot")
                    view = view[written:]
                copied += len(chunk)
            if os.read(source_fd, 1):
                raise SnapshotError("source grew while it was copied")
            os.fchmod(destination_fd, mode)
        finally:
            os.close(destination_fd)
        after = os.fstat(source_fd)
        path_after = os.lstat(source)
        if identity(before) != identity(after) or identity(after) != identity(path_after):
            raise SnapshotError("source changed while it was copied")
        if copied != before.st_size:
            raise SnapshotError("snapshot byte count differs from the source")
    except Exception:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    parser.add_argument("maximum", type=int)
    parser.add_argument("--mode", type=lambda value: int(value, 8), default=0o644)
    args = parser.parse_args()
    if args.maximum < 0 or args.maximum > 1024 * 1024 * 1024:
        print("bounded file snapshot failed: invalid maximum", file=sys.stderr)
        return 1
    try:
        snapshot(args.source, args.destination, args.maximum, args.mode)
    except (SnapshotError, OSError, ValueError) as exc:
        print(f"bounded file snapshot failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
