#!/usr/bin/env python3
"""Safely merge a tar or ZIP archive into a destination directory."""

from __future__ import annotations

import bz2
import errno
import io
import lzma
import os
import shutil
import stat
import struct
import sys
import tarfile
import zipfile
import zlib
from collections import deque
from collections.abc import Callable
from pathlib import Path, PurePosixPath


MIB = 1024 * 1024
GIB = 1024 * MIB


def positive_limit(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise ValueError(f"{name} must be a decimal integer: {raw!r}") from error
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


MAX_MEMBERS = positive_limit("SAFE_EXTRACT_MAX_MEMBERS", 200_000)
MAX_FILE_BYTES = positive_limit("SAFE_EXTRACT_MAX_FILE_BYTES", 8 * GIB)
MAX_TOTAL_BYTES = positive_limit("SAFE_EXTRACT_MAX_TOTAL_BYTES", 32 * GIB)
MAX_COMPRESSION_RATIO = positive_limit("SAFE_EXTRACT_MAX_COMPRESSION_RATIO", 1_000)
MIN_FREE_BYTES = positive_limit("SAFE_EXTRACT_MIN_FREE_BYTES", 64 * MIB)
MAX_ARCHIVE_BYTES = positive_limit("SAFE_EXTRACT_MAX_ARCHIVE_BYTES", 2 * GIB)
# tarfile and zipfile normally materialize metadata before returning it. Keep
# extension records and ZIP central-directory bytes bounded before that happens.
MAX_EXTENSION_BYTES = positive_limit("SAFE_EXTRACT_MAX_EXTENSION_BYTES", 1 * MIB)
MAX_ZIP_CENTRAL_BYTES = positive_limit("SAFE_EXTRACT_MAX_ZIP_CENTRAL_BYTES", 32 * MIB)
# liblzma accepts the dictionary size advertised by an input stream. Keep the
# decoder below a bounded allocation before tarfile gets a chance to open it.
MAX_LZMA_MEMORY = positive_limit("SAFE_EXTRACT_MAX_LZMA_MEMORY", 256 * MIB)
MAX_PATH_BYTES = 4_096
MAX_COMPONENT_BYTES = 255
MAX_PATH_COMPONENTS = 128
MAX_LINK_TARGET_BYTES = 4_096
MAX_DECOMPRESSED_CHUNK = 1 * MIB


def _close_resources(
    resources: tuple[tuple[str, Callable[[], None]], ...],
    primary: BaseException | None,
) -> None:
    """Close every owned resource while preserving any active primary error."""
    cleanup_error: ValueError | None = None
    for label, close in resources:
        try:
            close()
        except BaseException as error:
            note = f"{label} close failed ({type(error).__name__})"
            if primary is not None:
                primary.add_note(note)
                continue
            if cleanup_error is None:
                cleanup_error = ValueError("archive resource cleanup failed")
                cleanup_error.__cause__ = error
            cleanup_error.add_note(note)
    if primary is None and cleanup_error is not None:
        raise cleanup_error


def _owned_fd_resources(
    archive_fd: int,
    destination_fd: int,
    own_archive: bool,
    own_destination: bool,
) -> tuple[tuple[str, Callable[[], None]], ...]:
    resources: list[tuple[str, Callable[[], None]]] = []
    if own_archive:
        resources.append(("archive descriptor", lambda fd=archive_fd: os.close(fd)))
    if own_destination:
        resources.append(
            ("destination descriptor", lambda fd=destination_fd: os.close(fd))
        )
    return tuple(resources)


def clean_name(value: str) -> PurePosixPath:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError(f"unsafe empty/NUL/backslash path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or (path.parts and ":" in path.parts[0]):
        raise ValueError(f"unsafe absolute/drive path: {value!r}")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if ".." in parts:
        raise ValueError(f"unsafe parent traversal: {value!r}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"path is not UTF-8: {value!r}") from error
    if len(encoded) > MAX_PATH_BYTES or len(parts) > MAX_PATH_COMPONENTS:
        raise ValueError(f"path is too long or deep: {value!r}")
    for part in parts:
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise ValueError(f"path component is too long: {value!r}")
    return PurePosixPath(*parts)


def link_is_contained(member: PurePosixPath, target: str, *, hardlink: bool) -> bool:
    if not target or "\x00" in target or "\\" in target:
        return False
    link = PurePosixPath(target)
    if link.is_absolute() or (link.parts and ":" in link.parts[0]):
        return False
    base = PurePosixPath() if hardlink else member.parent
    try:
        if len(target.encode("utf-8")) > MAX_LINK_TARGET_BYTES:
            return False
    except UnicodeEncodeError:
        return False
    if len(link.parts) > MAX_PATH_COMPONENTS:
        return False
    if any(len(part.encode("utf-8")) > MAX_COMPONENT_BYTES for part in link.parts):
        return False
    stack: list[str] = []
    for part in (base / link).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return False
            stack.pop()
        else:
            stack.append(part)
    return True


def _open_regular_archive(path: Path) -> tuple[int, int]:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or absolute.parts[0] != os.sep:
        raise ValueError(f"archive path is not absolute: {absolute}")
    components = absolute.parts[1:]
    if not components:
        raise ValueError(f"archive path has no regular-file component: {path}")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd = -1
    previous_fd = -1
    descriptor = -1
    try:
        parent_fd = os.open(os.sep, directory_flags)
        for component in components[:-1]:
            child = os.open(component, directory_flags, dir_fd=parent_fd)
            previous_fd = parent_fd
            parent_fd = child
            _close_resources(
                (("archive parent descriptor", lambda fd=previous_fd: os.close(fd)),),
                None,
            )
            previous_fd = -1
        descriptor = os.open(components[-1], file_flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"archive is not a regular file: {path}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
            raise ValueError(f"archive exceeds compressed size limit: {path}")
        previous_fd = parent_fd
        _close_resources(
            (("archive parent descriptor", lambda fd=previous_fd: os.close(fd)),),
            None,
        )
        parent_fd = -1
        previous_fd = -1
        result = (descriptor, metadata.st_size)
        descriptor = -1
        return result
    except OSError as error:
        raise ValueError(
            f"cannot open archive without following symlinks: {path}: {error}"
        ) from error
    except BaseException:
        raise
    finally:
        resources: list[tuple[str, Callable[[], None]]] = []
        if descriptor >= 0:
            resources.append(
                ("archive descriptor", lambda fd=descriptor: os.close(fd))
            )
        if parent_fd >= 0:
            resources.append(
                ("archive parent descriptor", lambda fd=parent_fd: os.close(fd))
            )
        if previous_fd >= 0 and previous_fd != parent_fd:
            resources.append(
                ("archive previous parent descriptor", lambda fd=previous_fd: os.close(fd))
            )
        _close_resources(tuple(resources), sys.exception())


def _validate_archive_fd(archive_fd: int, archive_size: int) -> None:
    """Bind a caller-supplied archive size to a bounded regular-file FD."""
    if isinstance(archive_fd, bool) or not isinstance(archive_fd, int) or archive_fd < 0:
        raise ValueError("archive_fd must be a non-negative integer file descriptor")
    if isinstance(archive_size, bool) or not isinstance(archive_size, int):
        raise ValueError("archive_size must be an integer")
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds compressed size limit")
    try:
        metadata = os.fstat(archive_fd)
    except OSError as error:
        raise ValueError(f"cannot inspect archive descriptor: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("archive descriptor is not a regular file")
    if metadata.st_size != archive_size:
        raise ValueError(
            "archive descriptor size does not match archive_size "
            f"({metadata.st_size} != {archive_size})"
        )


def _validate_destination_fd(destination_fd: int) -> None:
    if (
        isinstance(destination_fd, bool)
        or not isinstance(destination_fd, int)
        or destination_fd < 0
    ):
        raise ValueError(
            "destination_fd must be a non-negative integer file descriptor"
        )
    try:
        metadata = os.fstat(destination_fd)
    except OSError as error:
        raise ValueError(f"cannot inspect destination descriptor: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("destination descriptor is not a directory")


def _rewind(descriptor: int) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise ValueError(f"archive descriptor is not seekable: {error}") from error


class _BoundedArchiveStream(io.RawIOBase):
    """Expose only the immutable byte range captured for an archive FD."""

    def __init__(self, stream, size: int) -> None:
        super().__init__()
        self._stream = stream
        self._size = size
        self._position = 0

    @property
    def mode(self) -> str:
        return "rb"

    @property
    def name(self):
        return getattr(self._stream, "name", None)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._position

    def _target(self, offset: int, whence: int) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self._position + offset
        elif whence == os.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError(f"unsupported archive seek origin: {whence}")
        if target < 0 or target > self._size:
            raise ValueError("archive seek exceeds the authenticated byte range")
        return target

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        target = self._target(offset, whence)
        self._stream.seek(target, os.SEEK_SET)
        self._position = target
        return target

    def read(self, size: int = -1) -> bytes:
        remaining = self._size - self._position
        if size is None or size < 0:
            size = remaining
        else:
            size = min(size, remaining)
        if size <= 0:
            return b""
        data = self._stream.read(size)
        if len(data) > size:
            data = data[:size]
        self._position += len(data)
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def readline(self, size: int = -1) -> bytes:
        remaining = self._size - self._position
        if size is None or size < 0:
            size = remaining
        else:
            size = min(size, remaining)
        if size <= 0:
            return b""
        data = self._stream.readline(size)
        if len(data) > size:
            data = data[:size]
        self._position += len(data)
        return data

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)

    def fileno(self) -> int:
        return self._stream.fileno()

    def close(self) -> None:
        if not self.closed:
            try:
                self._stream.close()
            finally:
                super().close()


def _dup_binary_stream(descriptor: int, *, limit: int | None = None):
    """Open a binary stream on a duplicate FD without leaking it on failure."""
    duplicate = os.dup(descriptor)
    stream = None
    try:
        stream = os.fdopen(duplicate, "rb")
        if limit is None:
            return stream
        return _BoundedArchiveStream(stream, limit)
    except BaseException:
        close = stream.close if stream is not None else lambda: os.close(duplicate)
        _close_resources(
            (("duplicate binary stream", close),),
            sys.exception(),
        )
        raise


def _open_destination(path: Path) -> tuple[Path, int]:
    absolute = Path(os.path.abspath(path))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    # Walk from a pinned root descriptor. Pathname lstat/mkdir sequences leave
    # a replaceable component between the check and the write; openat/mkdirat
    # keeps every component bound to the descriptor we just validated.
    if not absolute.is_absolute() or absolute.parts[0] != os.sep:
        raise ValueError(f"destination path is not absolute: {absolute}")
    current = os.open(os.sep, flags)
    previous = -1
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=current)
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise ValueError(
                        f"destination contains a symlink component: {component}"
                    ) from error
                raise ValueError(
                    f"cannot open destination component {component}: {error}"
                ) from error
            previous = current
            current = child
            _close_resources(
                (("destination parent descriptor", lambda fd=previous: os.close(fd)),),
                None,
            )
            previous = -1
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise ValueError(f"destination is not a directory: {absolute}")
        return absolute, current
    except BaseException:
        resources: list[tuple[str, Callable[[], None]]] = []
        if current >= 0:
            resources.append(("destination path descriptor", lambda fd=current: os.close(fd)))
        if previous >= 0 and previous != current:
            resources.append(
                ("destination parent descriptor", lambda fd=previous: os.close(fd))
            )
        _close_resources(
            tuple(resources),
            sys.exception(),
        )
        raise


class DestinationTree:
    """Descriptor-relative operations rooted at one checked directory FD."""

    def __init__(self, root: Path, descriptor: int) -> None:
        self.root = root
        self.fd = descriptor
        self.regular_identities: dict[PurePosixPath, tuple[int, int]] = {}

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    @staticmethod
    def _parts(path: PurePosixPath) -> tuple[str, ...]:
        return tuple(path.parts)

    def directory(self, parts: tuple[str, ...], *, create: bool = True) -> int:
        current = os.dup(self.fd)
        previous = -1
        try:
            for part in parts:
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current,
                    )
                except FileNotFoundError:
                    if not create:
                        raise ValueError(f"destination directory does not exist: {'/'.join(parts)}")
                    try:
                        os.mkdir(part, 0o755, dir_fd=current)
                    except FileExistsError:
                        pass
                    child = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current,
                    )
                except OSError as error:
                    if error.errno == errno.ELOOP:
                        raise ValueError(f"destination directory is a symlink: {part}") from error
                    raise
                previous = current
                current = child
                _close_resources(
                    (("destination parent descriptor", lambda fd=previous: os.close(fd)),),
                    None,
                )
                previous = -1
            return current
        except BaseException:
            resources: list[tuple[str, Callable[[], None]]] = []
            if current >= 0:
                resources.append(("destination tree descriptor", lambda fd=current: os.close(fd)))
            if previous >= 0 and previous != current:
                resources.append(
                    ("destination parent descriptor", lambda fd=previous: os.close(fd))
                )
            _close_resources(
                tuple(resources),
                sys.exception(),
            )
            raise

    def parent(self, name: PurePosixPath) -> tuple[int, str]:
        parts = self._parts(name)
        if not parts:
            raise ValueError("archive member has an empty path")
        return self.directory(parts[:-1]), parts[-1]

    @staticmethod
    def _lstat(parent_fd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def remove_non_directory(self, parent_fd: int, name: str) -> None:
        metadata = self._lstat(parent_fd, name)
        if metadata is None:
            return
        if stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"refusing to replace destination directory: {name}")
        os.unlink(name, dir_fd=parent_fd)

    def write_regular(self, name: PurePosixPath, source, size: int, mode: int) -> None:
        parent_fd, basename = self.parent(name)
        descriptor = -1
        identity: tuple[int, int] | None = None
        try:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            # Never truncate an existing inode: a destination regular file may
            # be a hardlink to a path outside the extraction root.
            for _ in range(4):
                existing = self._lstat(parent_fd, basename)
                if existing is not None:
                    if stat.S_ISDIR(existing.st_mode) or not (
                        stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
                    ):
                        raise ValueError(
                            f"refusing to replace special destination member: {name}"
                        )
                    try:
                        os.unlink(basename, dir_fd=parent_fd)
                    except FileNotFoundError:
                        continue
                try:
                    descriptor = os.open(
                        basename, flags, mode & 0o777, dir_fd=parent_fd
                    )
                    break
                except FileExistsError:
                    continue
            if descriptor < 0:
                raise ValueError(f"destination member changed during replacement: {name}")
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError(f"destination member is not a regular file: {name}")
            identity = (opened.st_dev, opened.st_ino)
            copied = 0
            while copied < size:
                chunk = source.read(min(1024 * 1024, size - copied))
                if not chunk:
                    raise ValueError(f"archive member ended early: {name}")
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ValueError(f"cannot write archive member: {name}")
                    view = view[written:]
                copied += len(chunk)
            if source.read(1):
                raise ValueError(f"archive member grew while extracting: {name}")
            os.fchmod(descriptor, mode & 0o777)
            os.close(descriptor)
            descriptor = -1
            self.regular_identities[name] = identity
        except BaseException:
            primary = sys.exception()
            if descriptor >= 0:
                _close_resources(
                    (("regular file descriptor", lambda fd=descriptor: os.close(fd)),),
                    primary,
                )
            if identity is not None:
                try:
                    current = self._lstat(parent_fd, basename)
                    if current is not None and (
                        current.st_dev,
                        current.st_ino,
                    ) == identity:
                        try:
                            os.unlink(basename, dir_fd=parent_fd)
                        except FileNotFoundError:
                            pass
                except BaseException as cleanup_error:
                    primary.add_note(
                        "regular file rollback failed "
                        f"({type(cleanup_error).__name__})"
                    )
            raise
        finally:
            _close_resources(
                (("regular file parent descriptor", lambda fd=parent_fd: os.close(fd)),),
                sys.exception(),
            )

    def make_directory(self, name: PurePosixPath) -> None:
        descriptor = self.directory(self._parts(name))
        _close_resources(
            (("created directory descriptor", lambda fd=descriptor: os.close(fd)),),
            None,
        )

    def set_directory_mode(self, name: PurePosixPath, mode: int) -> None:
        descriptor = self.directory(self._parts(name), create=False)
        try:
            os.fchmod(descriptor, mode & 0o777)
        finally:
            _close_resources(
                (("mode directory descriptor", lambda fd=descriptor: os.close(fd)),),
                sys.exception(),
            )

    def make_symlink(self, name: PurePosixPath, target: str) -> None:
        parent_fd, basename = self.parent(name)
        try:
            self.remove_non_directory(parent_fd, basename)
            os.symlink(target, basename, dir_fd=parent_fd)
        finally:
            _close_resources(
                (("symlink parent descriptor", lambda fd=parent_fd: os.close(fd)),),
                sys.exception(),
            )

    def make_hardlink(self, name: PurePosixPath, target: PurePosixPath) -> None:
        expected = self.regular_identities.get(target)
        if expected is None:
            raise ValueError(
                f"hardlink target is not a materialized archive regular file: {target}"
            )
        destination_fd = -1
        source_fd = -1
        try:
            destination_fd, basename = self.parent(name)
            source_fd, source_basename = self.parent(target)
            source = self._lstat(source_fd, source_basename)
            if source is None or not stat.S_ISREG(source.st_mode):
                raise ValueError(f"hardlink target is not a regular file: {target}")
            source_identity = (source.st_dev, source.st_ino)
            if source_identity != expected:
                raise ValueError(f"hardlink target changed during extraction: {target}")
            self.remove_non_directory(destination_fd, basename)
            os.link(
                source_basename,
                basename,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
                follow_symlinks=False,
            )
            linked = self._lstat(destination_fd, basename)
            source_after = self._lstat(source_fd, source_basename)
            if (
                linked is None
                or source_after is None
                or (linked.st_dev, linked.st_ino) != source_identity
                or (source_after.st_dev, source_after.st_ino) != expected
            ):
                self.remove_non_directory(destination_fd, basename)
                raise ValueError(f"hardlink target changed during extraction: {target}")
            self.regular_identities[name] = source_identity
        finally:
            resources: list[tuple[str, Callable[[], None]]] = []
            if source_fd >= 0:
                resources.append(("hardlink source directory", lambda fd=source_fd: os.close(fd)))
            if destination_fd >= 0:
                resources.append(("hardlink destination directory", lambda fd=destination_fd: os.close(fd)))
            _close_resources(tuple(resources), sys.exception())


def _new_destination_tree(root: Path, descriptor: int) -> DestinationTree:
    """Construct a descriptor-rooted tree without leaking its duplicate FD."""
    duplicate = os.dup(descriptor)
    try:
        return DestinationTree(root, duplicate)
    except BaseException:
        _close_resources(
            (("destination tree", lambda fd=duplicate: os.close(fd)),),
            sys.exception(),
        )
        raise


def validate_resource_budget(
    archive_size: int,
    destination: Path,
    members: int,
    total_bytes: int,
    *,
    destination_fd: int | None = None,
) -> None:
    if members > MAX_MEMBERS:
        raise ValueError(f"archive has too many members: {members} > {MAX_MEMBERS}")
    if total_bytes > MAX_TOTAL_BYTES:
        raise ValueError(
            f"archive expands beyond total limit: {total_bytes} > {MAX_TOTAL_BYTES}"
        )
    archive_bytes = archive_size
    if total_bytes and archive_bytes == 0:
        raise ValueError("non-empty archive has zero compressed bytes")
    if archive_bytes and total_bytes > archive_bytes * MAX_COMPRESSION_RATIO:
        raise ValueError(
            "archive compression ratio exceeds limit: "
            f"{total_bytes}/{archive_bytes} > {MAX_COMPRESSION_RATIO}"
        )
    if destination_fd is None:
        free_bytes = shutil.disk_usage(destination).free
    else:
        filesystem = os.fstatvfs(destination_fd)
        free_bytes = filesystem.f_bavail * filesystem.f_frsize
    if total_bytes > max(0, free_bytes - MIN_FREE_BYTES):
        raise ValueError(
            f"archive needs {total_bytes} bytes but destination has only "
            f"{free_bytes} bytes free with a {MIN_FREE_BYTES}-byte reserve"
        )


class BoundedTarInfo(tarfile.TarInfo):
    """Bound hidden GNU/PAX extension records before tarfile reads them."""

    @staticmethod
    def _account_extension(handle: tarfile.TarFile, size: int) -> None:
        if size < 0 or size > MAX_EXTENSION_BYTES:
            raise ValueError(f"tar extension record exceeds {MAX_EXTENSION_BYTES} bytes")
        count = getattr(handle, "_haptics_extension_count", 0) + 1
        total = getattr(handle, "_haptics_extension_bytes", 0) + size
        if count > MAX_MEMBERS:
            raise ValueError("tar archive has too many extension records")
        if total > MAX_TOTAL_BYTES:
            raise ValueError("tar extension records exceed total size limit")
        handle._haptics_extension_count = count
        handle._haptics_extension_bytes = total

    def _proc_pax(self, handle: tarfile.TarFile):
        self._account_extension(handle, self.size)
        return super()._proc_pax(handle)

    def _proc_gnulong(self, handle: tarfile.TarFile):
        self._account_extension(handle, self.size)
        return super()._proc_gnulong(handle)


def validate_archive_link_graph(
    members: list[tarfile.TarInfo] | None = None,
    *,
    zip_entries: list[tuple[zipfile.ZipInfo, PurePosixPath, str | None]] | None = None,
) -> None:
    """Prove that every archive link resolves inside the archive namespace."""
    if (members is None) == (zip_entries is None):
        raise ValueError("exactly one archive link namespace is required")
    kinds: dict[PurePosixPath, str] = {}
    targets: dict[PurePosixPath, str] = {}
    if members is not None:
        for member in members:
            name = clean_name(member.name)
            if member.isdir():
                kind = "directory"
            elif member.isreg() or member.islnk():
                kind = "file"
            elif member.issym():
                kind = "symlink"
                targets[name] = member.linkname
            else:
                continue
            previous = kinds.get(name)
            if previous is not None and previous != kind:
                raise ValueError(f"archive member type collision: {member.name!r}")
            kinds[name] = kind
    else:
        assert zip_entries is not None
        for info, name, link_target in zip_entries:
            mode = zip_mode(info)
            if info.is_dir() or stat.S_ISDIR(mode):
                kind = "directory"
            elif link_target is None:
                kind = "file"
            else:
                kind = "symlink"
                targets[name] = link_target
            previous = kinds.get(name)
            if previous is not None and previous != kind:
                raise ValueError(f"ZIP member type collision: {info.filename!r}")
            kinds[name] = kind

    # Tar permits omitted directory headers; extraction creates those parents,
    # so include them in the namespace used for link resolution.
    for name in tuple(kinds):
        parts = name.parts
        for depth in range(1, len(parts)):
            parent = PurePosixPath(*parts[:depth])
            previous = kinds.get(parent)
            if previous is not None and previous != "directory":
                raise ValueError(f"archive link path has a non-directory parent: {parent}")
            kinds[parent] = "directory"

    def target_parts(target: str) -> tuple[str, ...]:
        if not target or "\x00" in target or "\\" in target:
            raise ValueError(f"unsafe archive link target: {target!r}")
        parsed = PurePosixPath(target)
        if parsed.is_absolute() or (parsed.parts and ":" in parsed.parts[0]):
            raise ValueError(f"unsafe absolute archive link target: {target!r}")
        try:
            encoded = target.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError(f"archive link target is not UTF-8: {target!r}") from error
        if len(encoded) > MAX_LINK_TARGET_BYTES or len(parsed.parts) > MAX_PATH_COMPONENTS:
            raise ValueError(f"archive link target is too long: {target!r}")
        for part in parsed.parts:
            if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
                raise ValueError(f"archive link target component is too long: {target!r}")
        return parsed.parts

    def resolve(base: tuple[str, ...], components: tuple[str, ...], chain: tuple[PurePosixPath, ...]) -> None:
        resolved = list(base)
        pending = deque(components)
        expansions = 0
        while pending:
            part = pending.popleft()
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved:
                    raise ValueError("archive link escapes destination root")
                current = PurePosixPath(*resolved)
                if kinds.get(current) not in (None, "directory"):
                    raise ValueError(f"archive link traverses a non-directory: {current}")
                resolved.pop()
                continue
            resolved.append(part)
            current = PurePosixPath(*resolved)
            kind = kinds.get(current)
            if kind is None:
                raise ValueError(f"archive link has an unresolved target: {current}")
            if kind == "symlink":
                if current in chain:
                    raise ValueError(f"archive link has a symlink cycle: {current}")
                resolved.pop()
                pending.extendleft(reversed(target_parts(targets[current])))
                chain = chain + (current,)
                expansions += 1
                if expansions > MAX_PATH_COMPONENTS:
                    raise ValueError("archive link expansion is too deep")
            elif kind == "file" and pending:
                raise ValueError(f"archive link traverses a regular file: {current}")

    for link, target in targets.items():
        resolve(link.parent.parts, target_parts(target), (link,))


class _TarTailScanner:
    """Consume a decompressed tar stream and reject bytes after its end marker."""

    _PAX_TYPES = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE)
    _EXTENSION_TYPES = _PAX_TYPES + (
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    )

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.remaining = 0
        self.extension_remaining = 0
        self.extension_payload = bytearray()
        self.extension_is_pax = False
        self.zero_blocks = 0
        self.ended = False
        self.total = 0

    def _finish_extension(self) -> None:
        if not self.extension_payload or not self.extension_is_pax:
            self.extension_payload.clear()
            return
        # Parse only the record key. A sparse PAX key can make tarfile read an
        # attacker-controlled number of sparse extents before normal member
        # validation runs; reject it while the extension is still bounded.
        payload = bytes(self.extension_payload)
        offset = 0
        while offset < len(payload):
            separator = payload.find(b" ", offset)
            if separator <= offset or not payload[offset:separator].isdigit():
                break
            declared_length = int(payload[offset:separator], 10)
            record_end = offset + declared_length
            if declared_length <= 0 or record_end > len(payload):
                break
            record = payload[separator + 1 : record_end]
            if not record.endswith(b"\n"):
                break
            key = record[:-1].split(b"=", 1)[0]
            if key.startswith(b"GNU.sparse."):
                raise ValueError("sparse TAR metadata is unsupported")
            offset = record_end
        self.extension_payload.clear()

    def feed(self, data: bytes) -> None:
        self.total += len(data)
        if self.total > MAX_TOTAL_BYTES + MAX_MEMBERS * 1024 + MIB:
            raise ValueError("tar decompressed stream exceeds the safety limit")
        if self.ended:
            if data.strip(b"\0"):
                raise ValueError("tar archive contains trailing data after the end marker")
            return
        self.buffer.extend(data)
        while True:
            if self.remaining:
                amount = min(self.remaining, len(self.buffer))
                if self.extension_remaining:
                    extension_amount = min(amount, self.extension_remaining)
                    self.extension_payload.extend(
                        self.buffer[:extension_amount]
                    )
                    self.extension_remaining -= extension_amount
                del self.buffer[:amount]
                self.remaining -= amount
                if self.remaining:
                    return
                self._finish_extension()
                continue
            if len(self.buffer) < 512:
                return
            block = bytes(self.buffer[:512])
            del self.buffer[:512]
            if block == bytes(512):
                self.zero_blocks += 1
                if self.zero_blocks >= 2:
                    self.ended = True
                    if self.buffer and self.buffer.strip(b"\0"):
                        raise ValueError("tar archive contains trailing data after the end marker")
                    self.buffer.clear()
                continue
            self.zero_blocks = 0
            member_type = block[156:157]
            if member_type == tarfile.GNUTYPE_SPARSE:
                raise ValueError("sparse TAR members are unsupported")
            try:
                size = tarfile.nti(block[124:136])
            except (TypeError, ValueError) as error:
                raise ValueError("tar archive has an invalid member size") from error
            if size < 0:
                raise ValueError("tar archive has a negative member size")
            if member_type in self._EXTENSION_TYPES:
                if size > MAX_EXTENSION_BYTES:
                    raise ValueError(
                        f"tar extension record exceeds {MAX_EXTENSION_BYTES} bytes"
                    )
                self.extension_remaining = size
                self.extension_payload.clear()
                self.extension_is_pax = member_type in self._PAX_TYPES
            else:
                self.extension_remaining = 0
                self.extension_payload.clear()
                self.extension_is_pax = False
            self.remaining = ((size + 511) // 512) * 512

    def finish(self) -> None:
        if not self.ended or self.remaining or self.buffer:
            raise ValueError("tar archive ended before its complete end marker")


def _feed_decompressed(
    decompressor, compressed: bytes, scanner: _TarTailScanner
) -> None:
    """Emit bounded output while draining decoder-internal buffered bytes."""
    pending = compressed
    while True:
        try:
            output = decompressor.decompress(pending, MAX_DECOMPRESSED_CHUNK)
        except TypeError:
            # All supported stdlib decoders accept max_length. Keep a clear
            # rejection if a replacement object violates that contract.
            raise ValueError("tar decompressor does not support bounded output")
        scanner.feed(output)
        if getattr(decompressor, "eof", False):
            if getattr(decompressor, "unused_data", b""):
                raise ValueError("archive contains trailing compressed bytes")
            return
        unconsumed = getattr(decompressor, "unconsumed_tail", b"")
        if unconsumed:
            if unconsumed == pending and not output:
                raise ValueError("tar decompressor made no progress")
            pending = unconsumed
            continue
        if not getattr(decompressor, "needs_input", True):
            pending = b""
            if not output:
                raise ValueError("tar decompressor made no progress")
            continue
        return


def strict_tar_stream(descriptor: int, archive_bytes: int) -> str:
    """Validate compression termination and tar trailing bytes on a pinned FD."""
    if isinstance(archive_bytes, bool) or not isinstance(archive_bytes, int):
        raise ValueError("archive size must be an integer")
    if archive_bytes <= 0 or archive_bytes > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds compressed size limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = _dup_binary_stream(descriptor)
    scanner = _TarTailScanner()
    try:
        prefix = raw.read(512)
        raw.seek(0)
        try:
            # Compression signatures live at the same offset as a plain TAR
            # member name. Prefer a checksum-valid raw header so legitimate
            # names such as ``BZh9payload`` are not mistaken for compression.
            tarfile.TarInfo.frombuf(prefix, "utf-8", "surrogateescape")
            plain_tar = True
        except (tarfile.HeaderError, ValueError):
            plain_tar = False
        if plain_tar:
            decompressor = None
            tar_mode = "r:"
        elif prefix.startswith(b"\x1f\x8b"):
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            tar_mode = "r:gz"
        elif prefix.startswith(b"BZh"):
            decompressor = bz2.BZ2Decompressor()
            tar_mode = "r:bz2"
        elif prefix.startswith(b"\xfd7zXZ\x00"):
            decompressor = lzma.LZMADecompressor(memlimit=MAX_LZMA_MEMORY)
            tar_mode = "r:xz"
        else:
            decompressor = None
            tar_mode = "r:"
        compression_done = False
        remaining = archive_bytes
        while remaining:
            chunk = raw.read(min(MIB, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            if decompressor is None:
                scanner.feed(chunk)
                continue
            if compression_done:
                raise ValueError("archive contains trailing compressed bytes")
            try:
                _feed_decompressed(decompressor, chunk, scanner)
            except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError) as error:
                raise ValueError(f"tar compression stream is corrupt: {error}") from error
            if getattr(decompressor, "eof", False):
                if getattr(decompressor, "unused_data", b""):
                    raise ValueError("archive contains trailing compressed bytes")
                compression_done = True
        if remaining:
            raise ValueError("archive changed or was truncated while scanning")
        if raw.read(1):
            raise ValueError("archive grew while scanning")
        if decompressor is not None and not getattr(decompressor, "eof", False):
            raise ValueError("tar compression stream is truncated")
        scanner.finish()
        return tar_mode
    finally:
        _close_resources((("tar stream", raw.close),), sys.exception())


def validate_tar(handle: tarfile.TarFile) -> tuple[list[tarfile.TarInfo], int]:
    result: list[tarfile.TarInfo] = []
    seen: set[PurePosixPath] = set()
    total_bytes = 0
    by_name: dict[PurePosixPath, tarfile.TarInfo] = {}
    for member in handle:
        name = clean_name(member.name)
        if not name.parts:
            continue
        if name in seen:
            raise ValueError(f"duplicate archive member: {member.name!r}")
        seen.add(name)
        by_name[name] = member
        if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
            raise ValueError(f"unsupported special member: {member.name!r}")
        if not (member.isdir() or member.isreg() or member.issym() or member.islnk()):
            raise ValueError(f"unsupported member type: {member.name!r}")
        if member.size < 0 or member.size > MAX_FILE_BYTES:
            raise ValueError(f"archive member exceeds file limit: {member.name!r}")
        if member.isreg():
            total_bytes += member.size
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("archive expands beyond total size limit")
        if member.issym() and not link_is_contained(name, member.linkname, hardlink=False):
            raise ValueError(f"unsafe symlink: {member.name!r} -> {member.linkname!r}")
        if member.islnk() and not link_is_contained(name, member.linkname, hardlink=True):
            raise ValueError(f"unsafe hardlink: {member.name!r} -> {member.linkname!r}")
        result.append(member)
        if len(result) + getattr(handle, "_haptics_extension_count", 0) > MAX_MEMBERS:
            raise ValueError("archive has too many members")
    for member in result:
        if member.islnk():
            target = clean_name(member.linkname)
            target_member = by_name.get(target)
            if target_member is None or not target_member.isreg():
                raise ValueError(
                    f"hardlink target is not an archive regular file: {member.name!r} -> {member.linkname!r}"
                )
    validate_archive_link_graph(result)
    return result, total_bytes


def extract_tar(
    archive: Path,
    destination: Path,
    *,
    archive_fd: int | None = None,
    archive_size: int | None = None,
    destination_fd: int | None = None,
) -> int:
    owned_archive_fd = archive_fd is None
    owned_destination_fd = destination_fd is None
    if archive_fd is None:
        archive_fd, archive_size = _open_regular_archive(archive)
    elif archive_size is None:
        raise ValueError("archive_size is required when archive_fd is supplied")
    else:
        _validate_archive_fd(archive_fd, archive_size)
    if destination_fd is None:
        try:
            _, destination_fd = _open_destination(destination)
        except BaseException:
            _close_resources(
                _owned_fd_resources(archive_fd, -1, owned_archive_fd, False),
                sys.exception(),
            )
            raise
    else:
        try:
            _validate_destination_fd(destination_fd)
        except BaseException:
            _close_resources(
                _owned_fd_resources(archive_fd, -1, owned_archive_fd, False),
                sys.exception(),
            )
            raise
    try:
        _rewind(archive_fd)
        tar_mode = strict_tar_stream(archive_fd, archive_size)
        _rewind(archive_fd)
        archive_stream = _dup_binary_stream(archive_fd, limit=archive_size)
    except BaseException:
        _close_resources(
            _owned_fd_resources(
                archive_fd,
                destination_fd,
                owned_archive_fd,
                owned_destination_fd,
            ),
            sys.exception(),
        )
        raise
    try:
        with tarfile.open(
            fileobj=archive_stream, mode=tar_mode, tarinfo=BoundedTarInfo
        ) as handle:
            members, total_bytes = validate_tar(handle)
            validate_resource_budget(
                archive_size,
                destination,
                len(members),
                total_bytes,
                destination_fd=destination_fd,
            )
            tree = _new_destination_tree(destination, destination_fd)
            try:
                # Materialize directories and regular files first. Links are delayed
                # so an archive cannot make a later member traverse a new link.
                links: list[tarfile.TarInfo] = []
                hardlinks: list[tarfile.TarInfo] = []
                directory_modes: list[tuple[PurePosixPath, int]] = []
                for member in members:
                    name = clean_name(member.name)
                    if member.isdir():
                        tree.make_directory(name)
                        directory_modes.append((name, member.mode & 0o777))
                    elif member.isreg():
                        source = handle.extractfile(member)
                        if source is None:
                            raise ValueError(
                                f"cannot read archive member: {member.name!r}"
                            )
                        with source:
                            tree.write_regular(name, source, member.size, member.mode)
                    elif member.issym():
                        links.append(member)
                    elif member.islnk():
                        hardlinks.append(member)
                for member in hardlinks:
                    name = clean_name(member.name)
                    target = clean_name(member.linkname)
                    tree.make_hardlink(name, target)
                for member in links:
                    name = clean_name(member.name)
                    tree.make_symlink(name, member.linkname)
                for name, mode in sorted(
                    directory_modes, key=lambda item: len(item[0].parts), reverse=True
                ):
                    tree.set_directory_mode(name, mode)
            finally:
                _close_resources(
                    (("destination tree", tree.close),),
                    sys.exception(),
                )
        _validate_archive_fd(archive_fd, archive_size)
        return len(members)
    finally:
        resources = [("archive stream", archive_stream.close)]
        resources.extend(
            _owned_fd_resources(
                archive_fd,
                destination_fd,
                owned_archive_fd,
                owned_destination_fd,
            )
        )
        _close_resources(tuple(resources), sys.exception())


def zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def _read_exact(descriptor: int, size: int) -> bytes:
    """Read a bounded regular-file range despite POSIX short reads."""
    if size < 0:
        raise ValueError("cannot read a negative archive range")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        if len(chunk) > remaining:
            raise ValueError("archive descriptor returned an oversized read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining:
        raise ValueError("ZIP archive ended while reading its central-directory tail")
    return b"".join(chunks)


def validate_zip_central_directory(archive_fd: int, archive_size: int) -> None:
    """Reject oversized/malformed ZIP metadata before ZipFile materializes it."""
    # The classic EOCD is at most 65,557 bytes from EOF (22-byte record plus a
    # 65,535-byte comment). ZIP64 is deliberately rejected here: the producer
    # archives are far below the ZIP64 threshold and accepting it would require
    # allocating an unbounded central-directory representation first.
    read_size = min(archive_size, 65_557)
    os.lseek(archive_fd, archive_size - read_size, os.SEEK_SET)
    tail = _read_exact(archive_fd, read_size)
    marker = b"PK\x05\x06"
    position = tail.rfind(marker)
    if position < 0 or position + 22 > len(tail):
        raise ValueError("ZIP archive is missing its end-of-central-directory record")
    fields = struct.unpack_from("<4s4H2LH", tail, position)
    comment_length = fields[7]
    if position + 22 + comment_length != len(tail):
        raise ValueError("ZIP end-of-central-directory comment is malformed")
    eocd_position = archive_size - read_size + position
    entries = fields[4]
    central_size = fields[5]
    central_offset = fields[6]
    if fields[1] != 0 or fields[2] != 0 or fields[3] != entries:
        raise ValueError("multi-disk ZIP archives are unsupported")
    if entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ValueError("ZIP64 archives are unsupported by the bounded extractor")
    if entries > MAX_MEMBERS:
        raise ValueError("ZIP archive has too many members")
    if central_size > MAX_ZIP_CENTRAL_BYTES:
        raise ValueError("ZIP central directory exceeds its resource limit")
    if central_size > archive_size or central_offset > archive_size - central_size:
        raise ValueError("ZIP central directory is outside the archive")
    if entries and central_size < entries * 46:
        raise ValueError("ZIP central directory is too small for its member count")
    if central_offset + central_size > eocd_position:
        raise ValueError("ZIP central directory overlaps its end record")


def extract_zip(
    archive: Path,
    destination: Path,
    *,
    archive_fd: int | None = None,
    archive_size: int | None = None,
    destination_fd: int | None = None,
) -> int:
    owned_archive_fd = archive_fd is None
    owned_destination_fd = destination_fd is None
    if archive_fd is None:
        archive_fd, archive_size = _open_regular_archive(archive)
    elif archive_size is None:
        raise ValueError("archive_size is required when archive_fd is supplied")
    else:
        _validate_archive_fd(archive_fd, archive_size)
    if destination_fd is None:
        try:
            _, destination_fd = _open_destination(destination)
        except BaseException:
            _close_resources(
                _owned_fd_resources(archive_fd, -1, owned_archive_fd, False),
                sys.exception(),
            )
            raise
    else:
        try:
            _validate_destination_fd(destination_fd)
        except BaseException:
            _close_resources(
                _owned_fd_resources(archive_fd, -1, owned_archive_fd, False),
                sys.exception(),
            )
            raise
    try:
        _rewind(archive_fd)
        validate_zip_central_directory(archive_fd, archive_size)
        _rewind(archive_fd)
        archive_stream = _dup_binary_stream(archive_fd, limit=archive_size)
    except BaseException:
        _close_resources(
            _owned_fd_resources(
                archive_fd,
                destination_fd,
                owned_archive_fd,
                owned_destination_fd,
            ),
            sys.exception(),
        )
        raise
    try:
        with zipfile.ZipFile(archive_stream) as handle:
            entries: list[tuple[zipfile.ZipInfo, PurePosixPath, str | None]] = []
            seen: set[PurePosixPath] = set()
            total_bytes = 0
            for info in handle.infolist():
                if info.flag_bits & 0x1:
                    raise ValueError(f"encrypted ZIP member is unsupported: {info.filename!r}")
                name = clean_name(info.filename)
                if not name.parts:
                    continue
                if name in seen:
                    raise ValueError(f"duplicate ZIP member: {info.filename!r}")
                seen.add(name)
                mode = zip_mode(info)
                kind = stat.S_IFMT(mode)
                link_target: str | None = None
                if info.file_size < 0 or info.file_size > MAX_FILE_BYTES:
                    raise ValueError(f"ZIP member exceeds file limit: {info.filename!r}")
                if info.file_size and info.compress_size == 0:
                    raise ValueError(f"ZIP member has impossible zero compressed size: {info.filename!r}")
                if info.compress_size and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO:
                    raise ValueError(f"ZIP member compression ratio exceeds limit: {info.filename!r}")
                if kind == stat.S_IFLNK:
                    if info.file_size > MAX_LINK_TARGET_BYTES:
                        raise ValueError(f"ZIP symlink target is too large: {info.filename!r}")
                    try:
                        link_target = handle.read(info).decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise ValueError(f"ZIP symlink target is not UTF-8: {info.filename!r}") from error
                    if not link_is_contained(name, link_target, hardlink=False):
                        raise ValueError(f"unsafe ZIP symlink: {info.filename!r} -> {link_target!r}")
                elif kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError(f"unsupported ZIP member type: {info.filename!r}")
                entries.append((info, name, link_target))
                if not info.is_dir() and not stat.S_ISDIR(mode):
                    total_bytes += info.file_size
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise ValueError("ZIP archive expands beyond total size limit")
                if len(entries) > MAX_MEMBERS:
                    raise ValueError("ZIP archive has too many members")

            validate_archive_link_graph(zip_entries=entries)
            validate_resource_budget(
                archive_size,
                destination,
                len(entries),
                total_bytes,
                destination_fd=destination_fd,
            )

            tree = _new_destination_tree(destination, destination_fd)
            try:
                directory_modes: list[tuple[PurePosixPath, int]] = []
                for info, name, link_target in entries:
                    if info.is_dir() or stat.S_ISDIR(zip_mode(info)):
                        mode = zip_mode(info) & 0o777 or 0o755
                        tree.make_directory(name)
                        directory_modes.append((name, mode))
                    elif link_target is None:
                        with handle.open(info) as source:
                            tree.write_regular(
                                name,
                                source,
                                info.file_size,
                                (zip_mode(info) & 0o777) or 0o644,
                            )

                # Create links only after all directories and regular files,
                # preventing a later member from traversing a new link.
                for _, name, link_target in entries:
                    if link_target is not None:
                        tree.make_symlink(name, link_target)
                for name, mode in sorted(
                    directory_modes, key=lambda item: len(item[0].parts), reverse=True
                ):
                    tree.set_directory_mode(name, mode)
            finally:
                _close_resources(
                    (("destination tree", tree.close),),
                    sys.exception(),
                )
        _validate_archive_fd(archive_fd, archive_size)
        return len(entries)
    finally:
        resources = [("archive stream", archive_stream.close)]
        resources.extend(
            _owned_fd_resources(
                archive_fd,
                destination_fd,
                owned_archive_fd,
                owned_destination_fd,
            )
        )
        _close_resources(tuple(resources), sys.exception())


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: safe-extract-archive.py ARCHIVE DESTINATION", file=sys.stderr)
        return 2
    archive = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    archive_fd, archive_size = _open_regular_archive(archive)
    destination_fd = -1
    try:
        destination, destination_fd = _open_destination(destination)
        # Keep format detection ahead of tarfile metadata parsing. In
        # particular, a plain TAR can carry PAX sparse metadata; letting
        # tarfile inspect it first would defeat the bounded raw-stream guard.
        # First prefer a checksum-valid raw TAR header so a TAR filename that
        # begins with ``PK`` cannot be confused with a ZIP. Only inputs that
        # are not plainly TAR go through the bounded ZIP EOCD probe.
        probe = _dup_binary_stream(archive_fd, limit=archive_size)
        try:
            prefix = probe.read(512)
        finally:
            _close_resources((("archive probe", probe.close),), sys.exception())
        kind: str | None = None
        try:
            tarfile.TarInfo.frombuf(prefix, "utf-8", "surrogateescape")
        except (tarfile.HeaderError, ValueError):
            raw_tar_header = False
        else:
            raw_tar_header = True
        if raw_tar_header or prefix.startswith(
            (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
        ):
            kind = "tar"
        elif prefix.startswith(b"PK"):
            try:
                _rewind(archive_fd)
                validate_zip_central_directory(archive_fd, archive_size)
            except (
                OSError,
                ValueError,
                struct.error,
            ):
                pass
            else:
                kind = "zip"
        if kind is None:
            try:
                strict_tar_stream(archive_fd, archive_size)
            except (
                OSError,
                tarfile.TarError,
                EOFError,
                ValueError,
                zlib.error,
                lzma.LZMAError,
            ):
                # A non-TAR input may still be a self-extracting/prepended
                # ZIP whose signature is not at offset zero. Validate that
                # bounded ZIP structure before handing it to ZipFile.
                _rewind(archive_fd)
                validate_zip_central_directory(archive_fd, archive_size)
                kind = "zip"
            else:
                kind = "tar"
        _rewind(archive_fd)
        if kind == "tar":
            count = extract_tar(
                archive,
                destination,
                archive_fd=archive_fd,
                archive_size=archive_size,
                destination_fd=destination_fd,
            )
        else:
            validate_zip_central_directory(archive_fd, archive_size)
            count = extract_zip(
                archive,
                destination,
                archive_fd=archive_fd,
                archive_size=archive_size,
                destination_fd=destination_fd,
            )
    finally:
        resources = [("archive descriptor", lambda fd=archive_fd: os.close(fd))]
        if destination_fd >= 0:
            resources.append(
                (
                    "destination descriptor",
                    lambda fd=destination_fd: os.close(fd),
                )
            )
        _close_resources(tuple(resources), sys.exception())
    print(f"PASS safely extracted {count} members: {archive} -> {destination}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"archive rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
