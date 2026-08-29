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


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _open_parent(path: pathlib.Path) -> tuple[int, str, pathlib.Path]:
    """Open every parent directory without following replaceable symlinks."""
    try:
        absolute = pathlib.Path(os.path.abspath(path))
    except (OSError, ValueError) as exc:
        raise SnapshotError(f"invalid snapshot path: {path}") from exc
    if not absolute.is_absolute() or absolute.parts[0] != os.sep:
        raise SnapshotError(f"snapshot path is not absolute: {absolute}")
    components = absolute.parts[1:]
    if not components:
        raise SnapshotError(f"snapshot path has no file component: {path}")
    current = -1
    try:
        current = os.open(os.sep, _directory_flags())
        for component in components[:-1]:
            child = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = child
        return current, components[-1], absolute
    except OSError as exc:
        if current >= 0:
            os.close(current)
        if exc.errno == getattr(os, "ELOOP", 40):
            raise SnapshotError(
                f"snapshot path contains a symlink component: {path}"
            ) from exc
        raise SnapshotError(f"cannot open snapshot path parent: {path}: {exc}") from exc


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def snapshot(source: pathlib.Path, destination: pathlib.Path, maximum: int, mode: int) -> None:
    source_parent_fd = -1
    source_fd = -1
    destination_parent_fd = -1
    destination_fd = -1
    destination_name = ""
    destination_created = False
    try:
        source_parent_fd, source_name, source_absolute = _open_parent(source)
        source_fd = os.open(source_name, _file_flags(), dir_fd=source_parent_fd)
    except OSError as exc:
        if source_fd >= 0:
            os.close(source_fd)
            source_fd = -1
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
            source_parent_fd = -1
        raise SnapshotError(f"cannot open source: {exc}") from exc
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode:
            raise SnapshotError(f"source must be a regular mode-{mode:04o} file")
        if before.st_size > maximum:
            raise SnapshotError("source exceeds the snapshot size limit")
        destination_parent_fd, destination_name, destination_absolute = _open_parent(
            destination
        )
        destination_fd = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_parent_fd,
        )
        destination_created = True
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
        destination_fd = -1
        after = os.fstat(source_fd)
        path_after = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
        if identity(before) != identity(after) or identity(after) != identity(path_after):
            raise SnapshotError(f"source changed while it was copied: {source_absolute}")
        if copied != before.st_size:
            raise SnapshotError("snapshot byte count differs from the source")
    except Exception:
        if destination_fd >= 0:
            try:
                os.close(destination_fd)
            except OSError:
                pass
            destination_fd = -1
        if destination_created and destination_parent_fd >= 0:
            try:
                os.unlink(destination_name, dir_fd=destination_parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        for descriptor in (source_fd, source_parent_fd, destination_parent_fd):
            if descriptor >= 0:
                os.close(descriptor)


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
