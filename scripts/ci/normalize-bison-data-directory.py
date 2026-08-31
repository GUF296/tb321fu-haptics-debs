#!/usr/bin/env python3
"""Normalize the hosted Bison data-directory mode without following races."""

from __future__ import annotations

import contextlib
import os
import pathlib
import stat
import sys
import tempfile
from collections.abc import Iterator


CANONICAL_PATH = pathlib.Path("/usr/share/bison")
EXPECTED_MODE = 0o755
EXPECTED_FILE_MODE = 0o644
MAX_ENTRIES = 4096
MAX_LOGICAL_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64

# Descriptor, pre-normalization metadata, expected post-normalization mode,
# and a human-readable path.  Keeping the expected mode lets rollback reject
# an external mode update instead of overwriting it with stale metadata.
ModeChange = tuple[int, os.stat_result, int, str]


class NormalizationError(RuntimeError):
    """Raised when the Bison data directory cannot be authenticated."""


@contextlib.contextmanager
def _owned_descriptor(descriptor: int, label: str) -> Iterator[int]:
    primary: BaseException | None = None
    try:
        yield descriptor
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            message = f"cannot close Bison descriptor: {label}"
            if primary is not None:
                primary.add_note(message)
            else:
                raise NormalizationError(message) from exc


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare identity fields unaffected by an intentional mode change."""
    return _identity(left)[:-1] == _identity(right)[:-1]


def _same_descriptor_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _close_mode_changes(
    changes: list[ModeChange], primary: BaseException | None
) -> None:
    close_failure: NormalizationError | None = None
    for descriptor, _, _, label in reversed(changes):
        try:
            os.close(descriptor)
        except OSError as exc:
            message = f"cannot close Bison rollback descriptor: {label}"
            if primary is not None:
                primary.add_note(message)
            elif close_failure is None:
                close_failure = NormalizationError(message)
                close_failure.__cause__ = exc
            else:
                close_failure.add_note(message)
    if close_failure is not None:
        raise close_failure


def _rollback_mode_changes(changes: list[ModeChange], primary: BaseException) -> None:
    for descriptor, before, expected_mode, label in reversed(changes):
        try:
            current = os.fstat(descriptor)
            if not _same_descriptor_object(current, before):
                raise OSError("rollback descriptor identity changed")
            # A descriptor pins the inode, but not its metadata.  Do not
            # restore stale permissions over an owner/link/content/timestamp
            # update made by another actor after normalization.
            if not _same_object(current, before):
                raise OSError("rollback metadata changed concurrently")
            before_mode = stat.S_IMODE(before.st_mode)
            current_mode = stat.S_IMODE(current.st_mode)
            if current_mode not in (before_mode, expected_mode):
                raise OSError("rollback mode changed concurrently")
            if current_mode == before_mode:
                continue
            os.fchmod(descriptor, stat.S_IMODE(before.st_mode))
            restored = os.fstat(descriptor)
            if (
                not _same_descriptor_object(restored, before)
                or not _same_object(restored, before)
                or stat.S_IMODE(restored.st_mode) != before_mode
            ):
                raise OSError("rollback mode verification failed")
        except OSError as exc:
            primary.add_note(f"cannot roll back Bison mode: {label}: {exc}")


@contextlib.contextmanager
def _mode_transaction() -> Iterator[list[ModeChange]]:
    changes: list[ModeChange] = []
    primary: BaseException | None = None
    try:
        yield changes
    except BaseException as exc:
        primary = exc
        _rollback_mode_changes(changes, exc)
        raise
    finally:
        _close_mode_changes(changes, primary)


def _normalize_descriptor_mode(
    descriptor: int,
    opened: os.stat_result,
    expected_mode: int,
    label: str,
    changes: list[ModeChange],
) -> os.stat_result:
    if stat.S_IMODE(opened.st_mode) == expected_mode:
        return opened
    try:
        rollback_descriptor = os.dup(descriptor)
    except OSError as exc:
        raise NormalizationError(
            f"cannot retain Bison rollback descriptor: {label}: {exc}"
        ) from exc
    try:
        rollback_opened = os.fstat(rollback_descriptor)
        if _identity(rollback_opened) != _identity(opened):
            raise NormalizationError(
                f"Bison rollback descriptor changed while it was opened: {label}"
            )
    except BaseException as exc:
        try:
            os.close(rollback_descriptor)
        except OSError:
            exc.add_note(f"cannot close rejected Bison rollback descriptor: {label}")
        raise

    # Publish rollback ownership before fchmod: a fault may be raised after the
    # kernel has already applied the requested mode.
    changes.append((rollback_descriptor, opened, expected_mode, label))
    try:
        os.fchmod(descriptor, expected_mode)
    except OSError as exc:
        raise NormalizationError(
            f"cannot normalize Bison mode: {label}: {exc}"
        ) from exc
    after = os.fstat(descriptor)
    if not _same_object(after, opened) or stat.S_IMODE(after.st_mode) != expected_mode:
        raise NormalizationError(f"Bison entry changed during normalization: {label}")
    return after


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


def _open_flags(*, directory: bool = False) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _check_common_metadata(
    metadata: os.stat_result,
    *,
    root_device: int,
    expected_uid: int,
    expected_gid: int,
    label: str,
) -> None:
    if metadata.st_dev != root_device:
        raise NormalizationError(f"Bison data tree contains a cross-device entry: {label}")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise NormalizationError(f"Bison data tree contains an unexpected owner: {label}")
    if stat.S_ISLNK(metadata.st_mode):
        raise NormalizationError(f"Bison data tree contains a symlink: {label}")


def _inspect_regular(
    parent_descriptor: int,
    name: str,
    entry_metadata: os.stat_result,
    *,
    root_device: int,
    expected_uid: int,
    expected_gid: int,
    label: str,
    normalize_mode: bool,
    mode_changes: list[ModeChange] | None,
) -> int:
    if entry_metadata.st_nlink != 1:
        raise NormalizationError(f"Bison data tree contains a hard-linked file: {label}")
    try:
        descriptor = os.open(name, _open_flags(), dir_fd=parent_descriptor)
        with _owned_descriptor(descriptor, label):
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(entry_metadata):
                raise NormalizationError(f"Bison file changed while it was opened: {label}")
            _check_common_metadata(
                opened,
                root_device=root_device,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                label=label,
            )
            if not stat.S_ISREG(opened.st_mode):
                raise NormalizationError(
                    f"Bison data tree contains a non-regular entry: {label}"
                )
            if opened.st_size > MAX_LOGICAL_BYTES:
                raise NormalizationError(
                    f"Bison data tree exceeds its logical size limit: {label}"
                )
            if normalize_mode:
                if mode_changes is None:
                    raise AssertionError("missing Bison mode transaction")
                after = _normalize_descriptor_mode(
                    descriptor,
                    opened,
                    EXPECTED_FILE_MODE,
                    label,
                    mode_changes,
                )
                if (
                    after.st_uid != expected_uid
                    or after.st_gid != expected_gid
                    or after.st_nlink != 1
                ):
                    raise NormalizationError(
                        f"Bison file changed during normalization: {label}"
                    )
            else:
                after = os.fstat(descriptor)
                if _identity(after) != _identity(opened):
                    raise NormalizationError(
                        f"Bison file changed during preflight: {label}"
                    )
            return after.st_size
    except OSError as exc:
        raise NormalizationError(f"cannot open Bison file {label}: {exc}") from exc


def _walk_directory(
    descriptor: int,
    *,
    depth: int,
    root_device: int,
    expected_uid: int,
    expected_gid: int,
    counters: list[int],
    label: str,
    normalize_modes: bool,
    mode_changes: list[ModeChange] | None,
) -> None:
    if depth > MAX_DEPTH:
        raise NormalizationError("Bison data tree exceeds its depth limit")
    opened = os.fstat(descriptor)
    _check_common_metadata(
        opened,
        root_device=root_device,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        label=label,
    )
    if not stat.S_ISDIR(opened.st_mode):
        raise NormalizationError(f"Bison data tree contains a non-directory: {label}")
    if normalize_modes:
        if mode_changes is None:
            raise AssertionError("missing Bison mode transaction")
        after_mode = _normalize_descriptor_mode(
            descriptor,
            opened,
            EXPECTED_MODE,
            label,
            mode_changes,
        )
        if (
            after_mode.st_uid != expected_uid
            or after_mode.st_gid != expected_gid
        ):
            raise NormalizationError(
                f"Bison directory changed during normalization: {label}"
            )
    else:
        after_mode = opened
    try:
        iterator = os.scandir(descriptor)
        with iterator:
            for entry in iterator:
                counters[0] += 1
                if counters[0] > MAX_ENTRIES:
                    raise NormalizationError("Bison data tree has an unsafe entry count")
                child_label = f"{label}/{entry.name}"
                try:
                    entry_metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise NormalizationError(
                        f"cannot inspect Bison entry {child_label}: {exc}"
                    ) from exc
                _check_common_metadata(
                    entry_metadata,
                    root_device=root_device,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                    label=child_label,
                )
                if stat.S_ISDIR(entry_metadata.st_mode):
                    try:
                        child_descriptor = os.open(
                            entry.name,
                            _open_flags(directory=True),
                            dir_fd=descriptor,
                        )
                        with _owned_descriptor(child_descriptor, child_label):
                            child_opened = os.fstat(child_descriptor)
                            if _identity(child_opened) != _identity(entry_metadata):
                                raise NormalizationError(
                                    "Bison directory changed while it was opened: "
                                    f"{child_label}"
                                )
                            _walk_directory(
                                child_descriptor,
                                depth=depth + 1,
                                root_device=root_device,
                                expected_uid=expected_uid,
                                expected_gid=expected_gid,
                                counters=counters,
                                label=child_label,
                                normalize_modes=normalize_modes,
                                mode_changes=mode_changes,
                            )
                    except OSError as exc:
                        raise NormalizationError(
                            f"cannot open Bison directory {child_label}: {exc}"
                        ) from exc
                elif stat.S_ISREG(entry_metadata.st_mode):
                    counters[1] += _inspect_regular(
                        descriptor,
                        entry.name,
                        entry_metadata,
                        root_device=root_device,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                        label=child_label,
                        normalize_mode=normalize_modes,
                        mode_changes=mode_changes,
                    )
                    if counters[1] > MAX_LOGICAL_BYTES:
                        raise NormalizationError("Bison data tree has an unsafe logical size")
                else:
                    raise NormalizationError(
                        f"Bison data tree contains an unsupported entry: {child_label}"
                    )
    except NormalizationError:
        raise
    except OSError as exc:
        raise NormalizationError(f"cannot scan Bison data tree {label}: {exc}") from exc
    final = os.fstat(descriptor)
    if _identity(final) != _identity(after_mode):
        phase = "normalization" if normalize_modes else "preflight"
        raise NormalizationError(
            f"Bison directory changed during {phase}: {label}"
        )


def _require_nonempty_bounded_tree(counters: list[int]) -> None:
    if counters[0] < 2 or counters[1] <= 0:
        raise NormalizationError("Bison data tree has an unsafe logical size or entry count")


def _require_root_identity(
    path: pathlib.Path,
    descriptor: int,
    expected: os.stat_result,
    *,
    phase: str,
) -> os.stat_result:
    current = os.fstat(descriptor)
    try:
        path_current = path.lstat()
        resolved_current = path.resolve(strict=True)
    except OSError as exc:
        raise NormalizationError(
            f"cannot revalidate Bison data directory after {phase}: {exc}"
        ) from exc
    if (
        resolved_current != path
        or _identity(path_current) != _identity(current)
        or not _same_object(current, expected)
    ):
        raise NormalizationError(f"Bison data directory changed during {phase}")
    return current


def normalize(path: pathlib.Path = CANONICAL_PATH, *, expected_uid: int = 0, expected_gid: int = 0) -> None:
    """Recursively normalize an authenticated Bison tree without following links."""
    before = _require_directory(path, expected_uid, expected_gid)
    try:
        descriptor = os.open(path, _open_flags(directory=True))
        with _owned_descriptor(descriptor, str(path)):
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(before):
                raise NormalizationError("Bison data directory changed while it was opened")
            preflight_counters = [1, 0]
            _walk_directory(
                descriptor,
                depth=0,
                root_device=opened.st_dev,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                counters=preflight_counters,
                label=str(path),
                normalize_modes=False,
                mode_changes=None,
            )
            _require_nonempty_bounded_tree(preflight_counters)
            preflight = _require_root_identity(
                path, descriptor, opened, phase="preflight"
            )

            with _mode_transaction() as mode_changes:
                counters = [1, 0]
                _walk_directory(
                    descriptor,
                    depth=0,
                    root_device=opened.st_dev,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                    counters=counters,
                    label=str(path),
                    normalize_modes=True,
                    mode_changes=mode_changes,
                )
                _require_nonempty_bounded_tree(counters)
                final = _require_root_identity(
                    path, descriptor, preflight, phase="normalization"
                )
                if (
                    stat.S_IMODE(final.st_mode) != EXPECTED_MODE
                    or final.st_uid != expected_uid
                    or final.st_gid != expected_gid
                ):
                    raise NormalizationError(
                        "Bison data directory changed during normalization"
                    )
    except OSError as exc:
        raise NormalizationError(f"cannot open Bison data directory: {exc}") from exc


def _expect_failure(path: pathlib.Path, *, expected_uid: int, expected_gid: int) -> None:
    try:
        normalize(path, expected_uid=expected_uid, expected_gid=expected_gid)
    except NormalizationError:
        return
    raise SystemExit(f"unsafe Bison fixture was accepted: {path}")


def _expect_failure_without_mode_changes(
    path: pathlib.Path,
    protected: tuple[pathlib.Path, ...],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    before = tuple(stat.S_IMODE(item.lstat().st_mode) for item in protected)
    _expect_failure(path, expected_uid=expected_uid, expected_gid=expected_gid)
    after = tuple(stat.S_IMODE(item.lstat().st_mode) for item in protected)
    if after != before:
        raise SystemExit(f"Bison preflight failure changed modes: {path}")


def self_test() -> None:
    global MAX_DEPTH, MAX_ENTRIES, MAX_LOGICAL_BYTES

    uid = os.getuid()
    gid = os.getgid()
    with tempfile.TemporaryDirectory(prefix="tb321fu-bison-normalize-") as temporary:
        root = pathlib.Path(temporary)
        good = root / "good"
        good.mkdir(mode=0o755)
        good.chmod(0o775)
        nested = good / "nested"
        nested.mkdir(mode=0o700)
        payload = nested / "payload"
        payload.write_bytes(b"nested bison data\n")
        payload.chmod(0o600)
        deeper = nested / "deeper"
        deeper.mkdir(mode=0o711)
        deep_payload = deeper / "deep-payload"
        deep_payload.write_bytes(b"more data\n")
        deep_payload.chmod(0o640)
        normalize(good, expected_uid=uid, expected_gid=gid)
        for directory in (good, nested, deeper):
            if stat.S_IMODE(directory.stat().st_mode) != EXPECTED_MODE:
                raise SystemExit(f"Bison directory mode normalization failed: {directory}")
        for regular_file in (payload, deep_payload):
            if stat.S_IMODE(regular_file.stat().st_mode) != EXPECTED_FILE_MODE:
                raise SystemExit(f"Bison file mode normalization failed: {regular_file}")

        transactional_tree = root / "transactional-tree"
        transactional_tree.mkdir(mode=0o770)
        transactional_tree.chmod(0o770)
        transactional_payload = transactional_tree / "payload"
        transactional_payload.write_bytes(b"transactional payload\n")
        transactional_payload.chmod(0o600)
        original_fchmod = os.fchmod
        fchmod_calls = 0

        def apply_then_fail_once(descriptor: int, mode: int) -> None:
            nonlocal fchmod_calls
            fchmod_calls += 1
            original_fchmod(descriptor, mode)
            if fchmod_calls == 2:
                raise OSError("fixture applied-before-raise")

        os.fchmod = apply_then_fail_once
        try:
            _expect_failure_without_mode_changes(
                transactional_tree,
                (transactional_tree, transactional_payload),
                expected_uid=uid,
                expected_gid=gid,
            )
        finally:
            os.fchmod = original_fchmod
        if fchmod_calls < 2:
            raise SystemExit("Bison transaction fixture did not fail during mutation")

        rollback_race_tree = root / "rollback-race-tree"
        rollback_race_tree.mkdir(mode=0o770)
        rollback_race_tree.chmod(0o770)
        rollback_race_payload = rollback_race_tree / "payload"
        rollback_race_payload.write_bytes(b"rollback race payload\n")
        rollback_race_payload.chmod(0o600)
        rollback_race_calls = 0

        def mutate_previous_entry_then_fail(descriptor: int, mode: int) -> None:
            nonlocal rollback_race_calls
            rollback_race_calls += 1
            original_fchmod(descriptor, mode)
            if rollback_race_calls == 2:
                # The root was already normalized successfully.  Change it
                # before injecting a later failure; rollback must preserve this
                # concurrent mode instead of restoring stale 0770 metadata.
                rollback_race_tree.chmod(0o711)
                raise OSError("fixture concurrent mode update")

        os.fchmod = mutate_previous_entry_then_fail
        try:
            _expect_failure(
                rollback_race_tree,
                expected_uid=uid,
                expected_gid=gid,
            )
        finally:
            os.fchmod = original_fchmod
        if rollback_race_calls < 2:
            raise SystemExit("Bison rollback-race fixture did not reach the later failure")
        if stat.S_IMODE(rollback_race_tree.stat().st_mode) != 0o711:
            raise SystemExit("Bison rollback overwrote a concurrent root mode update")
        if stat.S_IMODE(rollback_race_payload.stat().st_mode) != 0o600:
            raise SystemExit("Bison rollback did not restore the later entry")

        regular = root / "regular"
        regular.write_bytes(b"not a directory\n")
        _expect_failure(regular, expected_uid=uid, expected_gid=gid)

        target = root / "target"
        target.mkdir(mode=0o755)
        link = root / "link"
        link.symlink_to(target, target_is_directory=True)
        _expect_failure(link, expected_uid=uid, expected_gid=gid)

        nested_link_tree = root / "nested-link-tree"
        nested_link_tree.mkdir(mode=0o755)
        nested_link_tree.chmod(0o770)
        nested_link_payload = nested_link_tree / "payload"
        nested_link_payload.write_bytes(b"payload\n")
        nested_link_payload.chmod(0o600)
        (nested_link_tree / "nested-link").symlink_to(target, target_is_directory=True)
        _expect_failure_without_mode_changes(
            nested_link_tree,
            (nested_link_tree, nested_link_payload),
            expected_uid=uid,
            expected_gid=gid,
        )

        hard_tree = root / "hard-tree"
        hard_tree.mkdir(mode=0o755)
        hard_tree.chmod(0o770)
        hard_target = root / "hard-target"
        hard_target.write_bytes(b"hard-linked payload\n")
        hard_alias = hard_tree / "alias"
        os.link(hard_target, hard_alias)
        _expect_failure_without_mode_changes(
            hard_tree,
            (hard_tree, hard_alias),
            expected_uid=uid,
            expected_gid=gid,
        )

        fifo_tree = root / "fifo-tree"
        fifo_tree.mkdir(mode=0o755)
        fifo_tree.chmod(0o770)
        fifo_payload = fifo_tree / "payload"
        fifo_payload.write_bytes(b"payload\n")
        fifo_payload.chmod(0o600)
        os.mkfifo(fifo_tree / "unsupported", mode=0o600)
        _expect_failure_without_mode_changes(
            fifo_tree,
            (fifo_tree, fifo_payload),
            expected_uid=uid,
            expected_gid=gid,
        )

        empty_tree = root / "empty-tree"
        empty_tree.mkdir(mode=0o755)
        empty_tree.chmod(0o770)
        _expect_failure_without_mode_changes(
            empty_tree,
            (empty_tree,),
            expected_uid=uid,
            expected_gid=gid,
        )

        original_limits = (MAX_ENTRIES, MAX_LOGICAL_BYTES, MAX_DEPTH)
        try:
            count_tree = root / "count-tree"
            count_tree.mkdir(mode=0o755)
            count_tree.chmod(0o770)
            count_payloads = tuple(count_tree / f"payload-{index}" for index in range(2))
            for count_payload in count_payloads:
                count_payload.write_bytes(b"x")
                count_payload.chmod(0o600)
            MAX_ENTRIES = 2
            _expect_failure_without_mode_changes(
                count_tree,
                (count_tree, *count_payloads),
                expected_uid=uid,
                expected_gid=gid,
            )

            size_tree = root / "size-tree"
            size_tree.mkdir(mode=0o755)
            size_tree.chmod(0o770)
            size_payloads = tuple(size_tree / f"payload-{index}" for index in range(2))
            for size_payload in size_payloads:
                size_payload.write_bytes(b"12345")
                size_payload.chmod(0o600)
            MAX_ENTRIES = original_limits[0]
            MAX_LOGICAL_BYTES = 8
            _expect_failure_without_mode_changes(
                size_tree,
                (size_tree, *size_payloads),
                expected_uid=uid,
                expected_gid=gid,
            )

            depth_tree = root / "depth-tree"
            depth_tree.mkdir(mode=0o755)
            depth_tree.chmod(0o770)
            depth_child = depth_tree / "child"
            depth_child.mkdir(mode=0o700)
            depth_grandchild = depth_child / "grandchild"
            depth_grandchild.mkdir(mode=0o710)
            (depth_grandchild / "payload").write_bytes(b"payload\n")
            MAX_LOGICAL_BYTES = original_limits[1]
            MAX_DEPTH = 1
            _expect_failure_without_mode_changes(
                depth_tree,
                (depth_tree, depth_child, depth_grandchild),
                expected_uid=uid,
                expected_gid=gid,
            )
        finally:
            MAX_ENTRIES, MAX_LOGICAL_BYTES, MAX_DEPTH = original_limits

        cross_device_tree = root / "cross-device-tree"
        cross_device_tree.mkdir(mode=0o755)
        cross_device_tree.chmod(0o770)
        cross_device_payload = cross_device_tree / "payload"
        cross_device_payload.write_bytes(b"payload\n")
        cross_device_payload.chmod(0o600)
        original_scandir = os.scandir
        cross_device_checked = False

        class CrossDeviceEntry:
            def __init__(self, wrapped: os.DirEntry[str]) -> None:
                self.wrapped = wrapped
                self.name = wrapped.name

            def stat(self, *, follow_symlinks: bool) -> os.stat_result:
                nonlocal cross_device_checked
                metadata = self.wrapped.stat(follow_symlinks=follow_symlinks)
                values = list(metadata)
                values[2] = metadata.st_dev + 1
                cross_device_checked = True
                return os.stat_result(values)

        class CrossDeviceScandir:
            def __init__(self, wrapped: os.ScandirIterator[str]) -> None:
                self.wrapped = wrapped

            def __enter__(self) -> CrossDeviceScandir:
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args: object) -> object:
                return self.wrapped.__exit__(*args)

            def __iter__(self) -> CrossDeviceScandir:
                return self

            def __next__(self) -> CrossDeviceEntry:
                return CrossDeviceEntry(next(self.wrapped))

        os.scandir = lambda descriptor: CrossDeviceScandir(original_scandir(descriptor))
        try:
            _expect_failure_without_mode_changes(
                cross_device_tree,
                (cross_device_tree, cross_device_payload),
                expected_uid=uid,
                expected_gid=gid,
            )
        finally:
            os.scandir = original_scandir
        if not cross_device_checked:
            raise SystemExit("Bison cross-device fixture did not execute")

        child_race_tree = root / "child-race-tree"
        child_race_tree.mkdir(mode=0o755)
        child_race_tree.chmod(0o770)
        child_race_payload = child_race_tree / "payload"
        child_race_payload.write_bytes(b"authenticated\n")
        child_race_payload.chmod(0o600)
        child_race_replacement = root / "child-race-replacement"
        child_race_replacement.write_bytes(b"replacement\n")
        child_race_replacement.chmod(0o640)
        child_race_authenticated = child_race_tree / "authenticated"
        original_open = os.open
        child_swapped = False

        def swap_child_before_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal child_swapped
            if path == "payload" and dir_fd is not None and not child_swapped:
                child_race_payload.rename(child_race_authenticated)
                child_race_replacement.rename(child_race_payload)
                child_swapped = True
            return original_open(path, flags, mode, dir_fd=dir_fd)

        os.open = swap_child_before_open
        try:
            _expect_failure(child_race_tree, expected_uid=uid, expected_gid=gid)
        finally:
            os.open = original_open
        if not child_swapped:
            raise SystemExit("Bison child-replacement fixture did not execute")
        if (
            stat.S_IMODE(child_race_tree.stat().st_mode) != 0o770
            or stat.S_IMODE(child_race_authenticated.stat().st_mode) != 0o600
            or stat.S_IMODE(child_race_payload.stat().st_mode) != 0o640
        ):
            raise SystemExit("Bison child-replacement preflight changed modes")

        child_fifo_tree = root / "child-fifo-tree"
        child_fifo_tree.mkdir(mode=0o755)
        child_fifo_tree.chmod(0o770)
        child_fifo_payload = child_fifo_tree / "payload"
        child_fifo_payload.write_bytes(b"authenticated FIFO race input\n")
        child_fifo_payload.chmod(0o600)
        child_fifo_authenticated = child_fifo_tree / "authenticated"
        child_fifo_swapped = False

        def swap_child_to_fifo_before_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal child_fifo_swapped
            if path == "payload" and dir_fd is not None and not child_fifo_swapped:
                nonblock = getattr(os, "O_NONBLOCK", 0)
                if not nonblock or not flags & nonblock:
                    raise SystemExit("Bison FIFO race open omitted O_NONBLOCK")
                child_fifo_payload.rename(child_fifo_authenticated)
                os.mkfifo(child_fifo_payload, mode=0o600)
                child_fifo_swapped = True
            return original_open(path, flags, mode, dir_fd=dir_fd)

        os.open = swap_child_to_fifo_before_open
        try:
            _expect_failure(child_fifo_tree, expected_uid=uid, expected_gid=gid)
        finally:
            os.open = original_open
        if not child_fifo_swapped:
            raise SystemExit("Bison regular-to-FIFO fixture did not execute")
        if (
            stat.S_IMODE(child_fifo_tree.stat().st_mode) != 0o770
            or stat.S_IMODE(child_fifo_authenticated.stat().st_mode) != 0o600
            or not stat.S_ISFIFO(child_fifo_payload.lstat().st_mode)
        ):
            raise SystemExit("Bison regular-to-FIFO preflight changed authenticated state")

        close_fixture = root / "close-fixture"
        close_fixture.write_bytes(b"close fixture\n")
        original_close = os.close

        def close_then_fail(descriptor: int) -> None:
            original_close(descriptor)
            raise OSError("fixture close failure")

        close_descriptor = original_open(close_fixture, _open_flags())
        os.close = close_then_fail
        try:
            try:
                with _owned_descriptor(close_descriptor, "close fixture"):
                    pass
            except NormalizationError as exc:
                if str(exc) != "cannot close Bison descriptor: close fixture":
                    raise SystemExit(f"wrong Bison close failure: {exc}") from exc
            else:
                raise SystemExit("Bison close failure was accepted")
        finally:
            os.close = original_close

        primary_close_descriptor = original_open(close_fixture, _open_flags())
        os.close = close_then_fail
        try:
            try:
                with _owned_descriptor(primary_close_descriptor, "primary fixture"):
                    raise NormalizationError("primary fixture failure")
            except NormalizationError as exc:
                if str(exc) != "primary fixture failure":
                    raise SystemExit("Bison close failure replaced the primary error") from exc
                if "cannot close Bison descriptor: primary fixture" not in getattr(
                    exc, "__notes__", ()
                ):
                    raise SystemExit("Bison close failure note was not retained") from exc
            else:
                raise SystemExit("Bison primary close fixture was accepted")
        finally:
            os.close = original_close

        race = root / "race"
        race.mkdir(mode=0o770)
        race.chmod(0o770)
        race_payload = race / "payload"
        race_payload.write_bytes(b"race payload\n")
        race_payload.chmod(0o600)
        replacement = root / "race-replacement"
        replacement.mkdir(mode=0o711)
        (replacement / "replacement").write_bytes(b"replacement\n")
        swapped = False

        def swap_root_after_chmod(descriptor: int, mode: int) -> None:
            nonlocal swapped
            original_fchmod(descriptor, mode)
            if not swapped:
                race.rename(root / "race-authenticated")
                replacement.rename(race)
                swapped = True

        os.fchmod = swap_root_after_chmod
        try:
            _expect_failure(race, expected_uid=uid, expected_gid=gid)
        finally:
            os.fchmod = original_fchmod
        if not swapped:
            raise SystemExit("Bison path-replacement fixture did not execute")
        race_authenticated = root / "race-authenticated"
        if (
            stat.S_IMODE(race_authenticated.stat().st_mode) != 0o770
            or stat.S_IMODE((race_authenticated / "payload").stat().st_mode) != 0o600
        ):
            raise SystemExit("Bison path-replacement rollback changed modes")

        if uid == 0:
            nobody = root / "wrong-owner"
            nobody.mkdir(mode=0o755)
            os.chown(nobody, 65534, 65534)
            _expect_failure(nobody, expected_uid=0, expected_gid=0)

            nested_owner_tree = root / "nested-wrong-owner"
            nested_owner_tree.mkdir(mode=0o755)
            nested_owner_tree.chmod(0o770)
            nested_owner_payload = nested_owner_tree / "payload"
            nested_owner_payload.write_bytes(b"payload\n")
            os.chown(nested_owner_payload, 65534, 65534)
            _expect_failure_without_mode_changes(
                nested_owner_tree,
                (nested_owner_tree,),
                expected_uid=0,
                expected_gid=0,
            )

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
