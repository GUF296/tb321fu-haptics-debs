#!/usr/bin/env python3
"""Render one candidate-specific workflow-dispatch trust bootstrap."""

from __future__ import annotations

import argparse
import errno
import hashlib
import os
import pathlib
import re
import stat
import sys


_ORIGINAL_SCANDIR = os.scandir


COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_TEMPLATE_BYTES = 256 * 1024
MAX_FD_SNAPSHOT_ENTRIES = 4096
TEMPLATE_NAME = "haptics-workflow-dispatch-bootstrap.py.in"
PLACEHOLDERS = {
    "@@TRUSTED_COMMIT@@": COMMIT,
    "@@CANDIDATE_COMMIT@@": COMMIT,
    "@@GATE_SHA256@@": SHA256,
    "@@WORKFLOW_SHA256@@": SHA256,
    "@@BOUNDARY_VALIDATOR_SHA256@@": SHA256,
    "@@ISOLATION_VALIDATOR_SHA256@@": SHA256,
}


class RenderError(ValueError):
    pass


def choose_failure(
    current: BaseException | None,
    new: BaseException,
    note: str,
) -> BaseException:
    if current is None:
        return new
    if not isinstance(new, Exception) and isinstance(current, Exception):
        new.add_note(note)
        if new.__cause__ is None:
            new.__cause__ = current
        return new
    if new is not current:
        current.add_note(note)
    return current


def settle_owned_descriptor(
    descriptor: int,
    label: str,
) -> tuple[BaseException | None, bool]:
    primary: BaseException | None = None
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                f"{label} close also failed",
            )
            try:
                os.fstat(descriptor)
            except BaseException as probe:
                if isinstance(probe, OSError) and probe.errno == errno.EBADF:
                    return primary, True
                primary = choose_failure(
                    primary,
                    probe,
                    f"{label} descriptor custody probe also failed",
                )
            continue
        return primary, True
    try:
        os.fstat(descriptor)
    except BaseException as probe:
        if isinstance(probe, OSError) and probe.errno == errno.EBADF:
            return primary, True
        primary = choose_failure(
            primary,
            probe,
            f"{label} final descriptor custody probe also failed",
        )
    return primary, False


def descriptor_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def renderer_cleanup_candidate(exc: BaseException, message: str) -> BaseException:
    if not isinstance(exc, Exception) or isinstance(exc, RenderError):
        return exc
    failure = RenderError(message)
    failure.__cause__ = exc
    return failure


def settle_scandir_iterator(
    entries,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    closed = False
    for _ in range(3):
        try:
            entries.close()
        except BaseException as exc:
            primary = choose_failure(
                primary,
                renderer_cleanup_candidate(exc, f"{label} close failed"),
                f"{label} close also failed",
            )
            continue
        closed = True
        break
    if not closed:
        primary = choose_failure(
            primary,
            RenderError(f"{label} close did not converge"),
            f"{label} custody also did not converge",
        )
    return primary


def trusted_fd_snapshot(
    partial_descriptors: set[int] | None = None,
) -> frozenset[int]:
    descriptors: set[int] = set()
    entries = None
    primary: BaseException | None = None
    try:
        entries = _ORIGINAL_SCANDIR("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > MAX_FD_SNAPSHOT_ENTRIES:
                raise RenderError("renderer descriptor table exceeds its bound")
            if entry.name.isascii() and entry.name.isdecimal():
                descriptor = int(entry.name, 10)
                descriptors.add(descriptor)
                if partial_descriptors is not None:
                    partial_descriptors.add(descriptor)
    except BaseException as exc:
        primary = renderer_cleanup_candidate(
            exc,
            "cannot inspect trusted renderer descriptor table",
        )
    if entries is not None:
        primary = settle_scandir_iterator(
            entries,
            primary,
            "trusted renderer descriptor-table iterator",
        )
    if primary is not None:
        raise primary
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise RenderError(
                    "cannot inspect trusted renderer descriptor table entry"
                ) from exc
        else:
            live.add(descriptor)
    return frozenset(live)


def recover_scandir_acquisition(
    before: frozenset[int],
    identity: tuple[int, int],
    label: str,
    primary: BaseException,
) -> BaseException:
    partial_descriptors: set[int] = set()
    try:
        after = trusted_fd_snapshot(partial_descriptors)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            exc,
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    for descriptor in sorted(after - before):
        identity_matches: bool | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                f"{label} recovery probe also failed",
            )
        else:
            identity_matches = descriptor_identity(metadata) == identity
        failure, closed = settle_owned_descriptor(descriptor, label)
        if failure is not None:
            primary = choose_failure(
                primary,
                failure,
                f"{label} recovery close also failed",
            )
        if not closed:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovery did not converge"),
                f"{label} recovery also did not converge",
            )
        if identity_matches is None:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovered descriptor identity is unknown"),
                f"{label} recovery identity also became unknown",
            )
        elif not identity_matches:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovered an unexpected descriptor"),
                f"{label} recovery identity also differed",
            )
    return primary


def bounded_fd_snapshot(
    partial_descriptors: set[int] | None = None,
) -> frozenset[int]:
    descriptors: set[int] = set()
    entries = None
    primary: BaseException | None = None
    table_metadata = os.stat("/proc/self/fd", follow_symlinks=False)
    acquisition_before = trusted_fd_snapshot(partial_descriptors)
    try:
        entries = os.scandir("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > MAX_FD_SNAPSHOT_ENTRIES:
                raise RenderError("renderer descriptor table exceeds its bound")
            if entry.name.isascii() and entry.name.isdecimal():
                descriptor = int(entry.name, 10)
                descriptors.add(descriptor)
                if partial_descriptors is not None:
                    partial_descriptors.add(descriptor)
    except BaseException as exc:
        primary = renderer_cleanup_candidate(
            exc,
            "cannot inspect renderer descriptor table",
        )
        if entries is None:
            primary = recover_scandir_acquisition(
                acquisition_before,
                descriptor_identity(table_metadata),
                "renderer descriptor-table acquisition",
                primary,
            )
    if entries is not None:
        primary = settle_scandir_iterator(
            entries,
            primary,
            "renderer descriptor-table iterator",
        )
    if primary is not None:
        raise primary
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise RenderError(
                    "cannot inspect renderer descriptor table entry"
                ) from exc
        else:
            live.add(descriptor)
    return frozenset(live)


def recover_descriptor_handoff(
    before: frozenset[int],
    identity: tuple[int, int],
    label: str,
    primary: BaseException,
) -> tuple[BaseException, bool]:
    recovered = False
    partial_descriptors: set[int] = set()
    try:
        after = bounded_fd_snapshot(partial_descriptors)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            exc,
            f"{label} descriptor recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    for descriptor in sorted(after - before):
        identity_matches: bool | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                f"{label} descriptor recovery inspection also failed",
            )
        else:
            identity_matches = descriptor_identity(metadata) == identity
        failure, closed = settle_owned_descriptor(descriptor, label)
        if failure is not None:
            primary = choose_failure(
                primary,
                failure,
                f"{label} descriptor recovery close also failed",
            )
        if identity_matches is None:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovered descriptor identity is unknown"),
                f"{label} descriptor recovery identity also became unknown",
            )
        elif not identity_matches:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovered an unexpected descriptor"),
                f"{label} descriptor recovery identity also differed",
            )
        if not closed:
            primary = choose_failure(
                primary,
                RenderError(f"{label} descriptor recovery did not converge"),
                f"{label} descriptor recovery also did not converge",
            )
        elif identity_matches:
            recovered = True
    return primary, recovered


def recover_created_output_handoff(
    before: frozenset[int],
    parent_device: int,
    label: str,
    primary: BaseException,
) -> tuple[BaseException, tuple[int, int] | None]:
    partial_descriptors: set[int] = set()
    try:
        after = bounded_fd_snapshot(partial_descriptors)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            exc,
            f"{label} descriptor recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    candidates: list[tuple[int, os.stat_result | None, bool]] = []
    for descriptor in sorted(after - before):
        metadata: os.stat_result | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                f"{label} descriptor recovery inspection also failed",
            )
        policy_matches = metadata is not None and (
            stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o500
            and metadata.st_uid == os.geteuid()
            and metadata.st_gid == os.getegid()
            and metadata.st_nlink == 1
            and metadata.st_size == 0
            and metadata.st_dev == parent_device
        )
        candidates.append((descriptor, metadata, policy_matches))
    recovered_identity: tuple[int, int] | None = None
    if len(candidates) > 1:
        primary = choose_failure(
            primary,
            RenderError(f"{label} descriptor recovery is ambiguous"),
            f"{label} descriptor recovery also became ambiguous",
        )
    for descriptor, metadata, policy_matches in candidates:
        failure, closed = settle_owned_descriptor(descriptor, label)
        if failure is not None:
            primary = choose_failure(
                primary,
                failure,
                f"{label} descriptor recovery close also failed",
            )
        if metadata is None:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovered descriptor identity is unknown"),
                f"{label} descriptor recovery identity also became unknown",
            )
        elif not policy_matches:
            primary = choose_failure(
                primary,
                RenderError(f"{label} recovered descriptor differs from policy"),
                f"{label} descriptor recovery metadata also differed",
            )
        if not closed:
            primary = choose_failure(
                primary,
                RenderError(f"{label} descriptor recovery did not converge"),
                f"{label} descriptor recovery also did not converge",
            )
            continue
        if metadata is None:
            continue
        identity = descriptor_identity(metadata)
        if recovered_identity is None:
            recovered_identity = identity
        elif recovered_identity != identity:
            recovered_identity = None
    if len(candidates) != 1:
        recovered_identity = None
    return primary, recovered_identity


def read_template(path: pathlib.Path) -> str:
    descriptor = -1
    try:
        namespace_metadata = os.stat(path, follow_symlinks=False)
        descriptor_baseline = bounded_fd_snapshot()
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except BaseException as exc:
            selected, _ = recover_descriptor_handoff(
                descriptor_baseline,
                descriptor_identity(namespace_metadata),
                "bootstrap template open handoff",
                exc,
            )
            if selected is not exc:
                raise selected
            raise
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or descriptor_identity(metadata) != descriptor_identity(namespace_metadata)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_TEMPLATE_BYTES
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RenderError("bootstrap template metadata differs from policy")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise RenderError("bootstrap template ended before its bound")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RenderError("bootstrap template exceeds its bound")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise RenderError("bootstrap template changed while it was read")
    except OSError as exc:
        raise RenderError("cannot read bootstrap template") from exc
    finally:
        if descriptor >= 0:
            active = sys.exception()
            failure, closed = settle_owned_descriptor(
                descriptor,
                "bootstrap template descriptor",
            )
            selected = active
            if failure is not None:
                selected = choose_failure(
                    selected,
                    failure,
                    "bootstrap template descriptor close also failed",
                )
            if not closed:
                selected = choose_failure(
                    selected,
                    RenderError(
                        "bootstrap template descriptor close did not converge"
                    ),
                    "bootstrap template descriptor custody also did not converge",
                )
            if selected is not None and selected is not active:
                raise selected
    raw = b"".join(chunks)
    if b"\0" in raw or b"\r" in raw:
        raise RenderError("bootstrap template framing differs from policy")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RenderError("bootstrap template must be UTF-8") from exc


def require_output(path: pathlib.Path) -> tuple[pathlib.Path, int]:
    if type(path) is not pathlib.PosixPath or not path.is_absolute():
        raise RenderError("bootstrap output path must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
        metadata = path.parent.lstat()
    except OSError as exc:
        raise RenderError("cannot inspect bootstrap output parent") from exc
    if (
        parent != path.parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", path.name)
    ):
        raise RenderError("bootstrap output parent or name differs from policy")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor_baseline = bounded_fd_snapshot()
    try:
        parent_descriptor = os.open(parent, flags)
    except BaseException as exc:
        selected, _ = recover_descriptor_handoff(
            descriptor_baseline,
            descriptor_identity(metadata),
            "bootstrap output parent open handoff",
            exc,
        )
        if not isinstance(selected, Exception):
            raise selected
        if selected is not exc:
            raise RenderError("cannot open bootstrap output parent") from selected
        if isinstance(exc, OSError):
            raise RenderError("cannot open bootstrap output parent") from exc
        raise
    try:
        opened = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
                opened.st_nlink,
            )
            != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
            )
        ):
            raise RenderError("bootstrap output parent changed before open")
    except BaseException as exc:
        failure, closed = settle_owned_descriptor(
            parent_descriptor,
            "bootstrap output parent",
        )
        selected = exc
        if failure is not None:
            selected = choose_failure(
                selected,
                failure,
                "bootstrap output parent close cleanup failed",
            )
        if not closed:
            selected = choose_failure(
                selected,
                RenderError("bootstrap output parent close did not converge"),
                "bootstrap output parent custody also did not converge",
            )
        if selected is not exc:
            raise selected
        raise
    return parent, parent_descriptor


def recheck_output_parent(parent: pathlib.Path, descriptor: int) -> None:
    try:
        opened = os.fstat(descriptor)
        namespace = os.stat(parent, follow_symlinks=False)
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise RenderError("bootstrap output parent changed during publication") from exc
    if (
        resolved != parent
        or not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(namespace.st_mode)
        or (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_nlink,
        )
        != (
            namespace.st_dev,
            namespace.st_ino,
            namespace.st_mode,
            namespace.st_uid,
            namespace.st_gid,
            namespace.st_nlink,
        )
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & 0o022
    ):
        raise RenderError("bootstrap output parent changed during publication")


def output_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def attest_published_output(
    output: pathlib.Path,
    parent: pathlib.Path,
    parent_descriptor: int,
    output_descriptor: int,
    expected_fingerprint: tuple[int, ...],
    expected_digest: str,
) -> None:
    try:
        recheck_output_parent(parent, parent_descriptor)
        before = os.fstat(output_descriptor)
        namespace = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            output_fingerprint(before) != expected_fingerprint
            or output_fingerprint(namespace) != expected_fingerprint
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o500
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
            or before.st_nlink != 1
        ):
            raise RenderError("bootstrap output terminal metadata changed")
        os.lseek(output_descriptor, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(output_descriptor, min(65536, remaining))
            if not chunk:
                raise RenderError("bootstrap output terminal content is truncated")
            hasher.update(chunk)
            remaining -= len(chunk)
        if os.read(output_descriptor, 1):
            raise RenderError("bootstrap output terminal content exceeds its bound")
        after = os.fstat(output_descriptor)
        if output_fingerprint(after) != expected_fingerprint:
            raise RenderError("bootstrap output changed during terminal attestation")
        if hasher.hexdigest() != expected_digest:
            raise RenderError("bootstrap output terminal content changed")
    except RenderError:
        raise
    except OSError as exc:
        raise RenderError("cannot attest bootstrap output terminal evidence") from exc


class RenderCustody:
    __slots__ = (
        "output",
        "digest",
        "_parent",
        "_parent_descriptor",
        "_output_descriptor",
        "_fingerprint",
    )

    def __init__(
        self,
        output: pathlib.Path,
        digest: str,
        parent: pathlib.Path,
        parent_descriptor: int,
        output_descriptor: int,
        fingerprint: tuple[int, ...],
    ) -> None:
        self.output = output
        self.digest = digest
        self._parent = parent
        self._parent_descriptor = parent_descriptor
        self._output_descriptor = output_descriptor
        self._fingerprint = fingerprint

    def evidence(self) -> tuple[pathlib.Path, str]:
        if self._parent_descriptor < 0 or self._output_descriptor < 0:
            raise RenderError("bootstrap output terminal custody was released")
        attest_published_output(
            self.output,
            self._parent,
            self._parent_descriptor,
            self._output_descriptor,
            self._fingerprint,
            self.digest,
        )
        return self.output, self.digest

    def release(self) -> None:
        primary: BaseException | None = None
        for attribute in ("_output_descriptor", "_parent_descriptor"):
            descriptor = getattr(self, attribute)
            if descriptor < 0:
                continue
            failure, closed = settle_owned_descriptor(
                descriptor,
                "bootstrap output custody",
            )
            if closed:
                setattr(self, attribute, -1)
            if failure is not None:
                primary = choose_failure(
                    primary,
                    failure,
                    "bootstrap output custody release also failed",
                )
            if not closed:
                primary = choose_failure(
                    primary,
                    RenderError("bootstrap output custody release did not converge"),
                    "bootstrap output custody release also did not converge",
                )
        if primary is not None:
            if not isinstance(primary, Exception):
                raise primary
            failure = RenderError("bootstrap output custody release failed")
            failure.__cause__ = primary
            raise failure
        if self._parent_descriptor >= 0 or self._output_descriptor >= 0:
            raise RenderError("bootstrap output custody release did not complete")


def render(arguments: argparse.Namespace) -> RenderCustody:
    values = {
        "@@TRUSTED_COMMIT@@": arguments.trusted_commit,
        "@@CANDIDATE_COMMIT@@": arguments.candidate_commit,
        "@@GATE_SHA256@@": arguments.gate_sha256,
        "@@WORKFLOW_SHA256@@": arguments.workflow_sha256,
        "@@BOUNDARY_VALIDATOR_SHA256@@": arguments.boundary_validator_sha256,
        "@@ISOLATION_VALIDATOR_SHA256@@": arguments.isolation_validator_sha256,
    }
    if any(
        type(value) is not str or pattern.fullmatch(value) is None
        for token, pattern in PLACEHOLDERS.items()
        for value in (values[token],)
    ):
        raise RenderError("bootstrap identities are not canonical")
    if values["@@TRUSTED_COMMIT@@"] == values["@@CANDIDATE_COMMIT@@"]:
        raise RenderError("bootstrap trusted and candidate commits must differ")
    template_path = pathlib.Path(__file__).resolve().with_name(TEMPLATE_NAME)
    source = read_template(template_path)
    for token, value in values.items():
        if source.count(token) != 1:
            raise RenderError(f"bootstrap template placeholder drifted: {token}")
        source = source.replace(token, value)
    if "@@" in source:
        raise RenderError("bootstrap template retains an unresolved placeholder")
    raw = source.encode("utf-8")
    raw_output = arguments.output
    if (
        type(raw_output) is not str
        or not raw_output.startswith("/")
        or "\0" in raw_output
        or pathlib.PurePosixPath(raw_output).as_posix() != raw_output
    ):
        raise RenderError("bootstrap output path is not canonical")
    output = pathlib.Path(raw_output)
    parent, parent_descriptor = require_output(output)
    cleanup_parent_descriptor = -1
    descriptor = -1
    custody_descriptor = -1
    created_identity: tuple[int, int] | None = None
    expected_fingerprint: tuple[int, ...] | None = None
    published_digest: str | None = None
    completed = False
    primary: BaseException | None = None
    cleanup_notes: list[str] = []

    def remember_cleanup(
        note: str,
        failure: BaseException | None = None,
    ) -> None:
        nonlocal primary
        if failure is not None and not isinstance(failure, Exception):
            candidate = failure
        else:
            candidate = RenderError("bootstrap output cleanup failed")
            if failure is not None:
                candidate.__cause__ = failure
        primary = choose_failure(
            primary,
            candidate,
            "bootstrap output cleanup also failed",
        )
        cleanup_notes.append(note)

    def close_owned_descriptor(value: int, role: str) -> tuple[bool, bool]:
        failure, closed = settle_owned_descriptor(value, role)
        cancellation = (
            failure
            if failure is not None and not isinstance(failure, Exception)
            else None
        )
        if cancellation is not None:
            remember_cleanup(f"{role} close cleanup failed", cancellation)
            return False, closed
        if closed:
            return True, True
        remember_cleanup(f"{role} close cleanup failed", failure)
        return False, False

    try:
        recheck_output_parent(parent, parent_descriptor)
        parent_metadata = os.fstat(parent_descriptor)
        cleanup_parent_baseline = bounded_fd_snapshot()
        try:
            cleanup_parent_descriptor = os.dup(parent_descriptor)
        except BaseException as exc:
            selected, _ = recover_descriptor_handoff(
                cleanup_parent_baseline,
                descriptor_identity(parent_metadata),
                "bootstrap output cleanup parent dup handoff",
                exc,
            )
            raise selected
        cleanup_parent_metadata = os.fstat(cleanup_parent_descriptor)
        if (
            not stat.S_ISDIR(cleanup_parent_metadata.st_mode)
            or (
                cleanup_parent_metadata.st_dev,
                cleanup_parent_metadata.st_ino,
                cleanup_parent_metadata.st_mode,
                cleanup_parent_metadata.st_uid,
                cleanup_parent_metadata.st_gid,
                cleanup_parent_metadata.st_nlink,
            )
            != (
                parent_metadata.st_dev,
                parent_metadata.st_ino,
                parent_metadata.st_mode,
                parent_metadata.st_uid,
                parent_metadata.st_gid,
                parent_metadata.st_nlink,
            )
            or os.get_inheritable(cleanup_parent_descriptor)
        ):
            raise RenderError("bootstrap output cleanup parent differs from policy")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RenderError("bootstrap output already exists")
        output_baseline = bounded_fd_snapshot()
        try:
            descriptor = os.open(
                output.name,
                flags,
                0o500,
                dir_fd=parent_descriptor,
            )
        except BaseException as exc:
            selected, recovered_identity = recover_created_output_handoff(
                output_baseline,
                parent_metadata.st_dev,
                "bootstrap output open handoff",
                exc,
            )
            if recovered_identity is not None:
                created_identity = recovered_identity
            try:
                recovered_namespace = os.stat(
                    output.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                recovered_namespace = None
            except BaseException as inspect_exc:
                selected = choose_failure(
                    selected,
                    inspect_exc,
                    "bootstrap output open handoff inspection also failed",
                )
                raise selected
            if recovered_namespace is not None:
                namespace_identity = descriptor_identity(recovered_namespace)
                if recovered_identity is None:
                    selected, recovered = recover_descriptor_handoff(
                        output_baseline,
                        namespace_identity,
                        "bootstrap output open handoff",
                        selected,
                    )
                    if recovered:
                        created_identity = namespace_identity
                elif namespace_identity != recovered_identity:
                    selected = choose_failure(
                        selected,
                        RenderError(
                            "bootstrap output namespace changed during open handoff"
                        ),
                        "bootstrap output open handoff namespace also changed",
                    )
                raise selected
            raise selected
        created = os.fstat(descriptor)
        if (
            not stat.S_ISREG(created.st_mode)
            or stat.S_IMODE(created.st_mode) != 0o500
            or created.st_uid != os.geteuid()
            or created.st_gid != os.getegid()
            or created.st_nlink != 1
            or created.st_size != 0
        ):
            raise RenderError("bootstrap output creation metadata differs from policy")
        created_identity = (created.st_dev, created.st_ino)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RenderError("bootstrap output write made no progress")
            offset += written
        os.fchmod(descriptor, 0o500)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        namespace = os.stat(
            output.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(final.st_mode)
            or stat.S_IMODE(final.st_mode) != 0o500
            or final.st_uid != os.geteuid()
            or final.st_nlink != 1
            or final.st_size != len(raw)
            or (final.st_dev, final.st_ino) != created_identity
            or (namespace.st_dev, namespace.st_ino) != created_identity
        ):
            raise RenderError("bootstrap output metadata differs from policy")
        os.lseek(descriptor, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        remaining = len(raw)
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise RenderError("bootstrap output content is truncated")
            hasher.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RenderError("bootstrap output content exceeds its bound")
        published_digest = hasher.hexdigest()
        if published_digest != hashlib.sha256(raw).hexdigest():
            raise RenderError("bootstrap output content differs from policy")
        expected_fingerprint = output_fingerprint(final)
        custody_baseline = bounded_fd_snapshot()
        try:
            custody_descriptor = os.dup(descriptor)
        except BaseException as exc:
            selected, _ = recover_descriptor_handoff(
                custody_baseline,
                descriptor_identity(final),
                "bootstrap output custody dup handoff",
                exc,
            )
            raise selected
        custody_metadata = os.fstat(custody_descriptor)
        if (
            output_fingerprint(custody_metadata) != expected_fingerprint
            or os.get_inheritable(custody_descriptor)
        ):
            raise RenderError("bootstrap output custody descriptor differs from policy")
        os.fsync(parent_descriptor)
        recheck_output_parent(parent, parent_descriptor)
        absolute_namespace = os.stat(output, follow_symlinks=False)
        if (
            absolute_namespace.st_dev,
            absolute_namespace.st_ino,
        ) != created_identity:
            raise RenderError("bootstrap output path changed during publication")
        attest_published_output(
            output,
            parent,
            parent_descriptor,
            custody_descriptor,
            expected_fingerprint,
            published_digest,
        )
        completed = True
    except OSError as exc:
        primary = RenderError("cannot publish bootstrap output")
        primary.__cause__ = exc
    except BaseException as exc:
        primary = exc
    finally:
        if descriptor >= 0 and created_identity is None and not completed:
            try:
                recovered = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(recovered.st_mode)
                    or stat.S_IMODE(recovered.st_mode) != 0o500
                    or recovered.st_uid != os.geteuid()
                    or recovered.st_gid != os.getegid()
                    or recovered.st_nlink != 1
                    or recovered.st_size != 0
                ):
                    raise RenderError(
                        "bootstrap output recovery metadata differs from policy"
                    )
                created_identity = (recovered.st_dev, recovered.st_ino)
            except BaseException as exc:
                remember_cleanup(
                    "bootstrap output identity recovery failed",
                    exc,
                )
        if descriptor >= 0:
            clean, closed = close_owned_descriptor(
                descriptor,
                "bootstrap output descriptor",
            )
            if closed:
                descriptor = -1
            if not clean:
                completed = False
        if completed:
            try:
                if expected_fingerprint is None or published_digest is None:
                    raise RenderError("bootstrap output terminal evidence is incomplete")
                attest_published_output(
                    output,
                    parent,
                    parent_descriptor,
                    custody_descriptor,
                    expected_fingerprint,
                    published_digest,
                )
            except BaseException as exc:
                completed = False
                if primary is None:
                    primary = exc
                else:
                    primary.add_note("bootstrap output final custody recheck failed")
        if completed and parent_descriptor >= 0:
            clean, closed = close_owned_descriptor(
                parent_descriptor,
                "bootstrap output parent",
            )
            if closed:
                parent_descriptor = -1
            if not clean:
                completed = False
        if completed:
            try:
                if expected_fingerprint is None or published_digest is None:
                    raise RenderError("bootstrap output terminal evidence is incomplete")
                attest_published_output(
                    output,
                    parent,
                    cleanup_parent_descriptor,
                    custody_descriptor,
                    expected_fingerprint,
                    published_digest,
                )
            except BaseException as exc:
                completed = False
                if primary is None:
                    primary = exc
                else:
                    primary.add_note("bootstrap output terminal handoff failed")
        cleanup_descriptor = (
            cleanup_parent_descriptor
            if cleanup_parent_descriptor >= 0
            else parent_descriptor
        )
        if created_identity is not None and not completed and cleanup_descriptor >= 0:
            try:
                current = os.stat(
                    output.name, dir_fd=cleanup_descriptor, follow_symlinks=False
                )
            except FileNotFoundError:
                current = None
            except BaseException as exc:
                current = None
                remember_cleanup(
                    "bootstrap output cleanup inspection failed",
                    exc,
                )
            if current is not None:
                if (current.st_dev, current.st_ino) == created_identity:
                    try:
                        os.unlink(output.name, dir_fd=cleanup_descriptor)
                    except FileNotFoundError:
                        pass
                    except BaseException as exc:
                        remember_cleanup(
                            "bootstrap output cleanup unlink failed",
                            exc,
                        )
                else:
                    remember_cleanup("bootstrap output cleanup namespace changed")
            try:
                os.fsync(cleanup_descriptor)
            except BaseException as exc:
                remember_cleanup(
                    "bootstrap output cleanup directory sync failed",
                    exc,
                )
            try:
                remaining = os.stat(
                    output.name,
                    dir_fd=cleanup_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                remaining = None
            except BaseException as exc:
                remaining = None
                remember_cleanup(
                    "bootstrap output cleanup recheck failed",
                    exc,
                )
            if (
                remaining is not None
                and (remaining.st_dev, remaining.st_ino) == created_identity
            ):
                remember_cleanup("bootstrap output cleanup left owned inode present")
        elif created_identity is not None and not completed:
            remember_cleanup("bootstrap output cleanup lost its parent descriptor")
        if not completed:
            for value, role in (
                (descriptor, "bootstrap output descriptor"),
                (custody_descriptor, "bootstrap output custody descriptor"),
                (parent_descriptor, "bootstrap output parent"),
                (cleanup_parent_descriptor, "bootstrap output cleanup parent"),
            ):
                if value >= 0:
                    close_owned_descriptor(value, role)
        if primary is not None:
            for note in dict.fromkeys(cleanup_notes):
                primary.add_note(note)
    if primary is not None:
        raise primary
    if not completed:
        raise RenderError("bootstrap output publication did not complete")
    if published_digest is None:
        raise RenderError("bootstrap output digest is missing")
    if expected_fingerprint is None:
        raise RenderError("bootstrap output metadata evidence is missing")
    if custody_descriptor < 0 or cleanup_parent_descriptor < 0:
        raise RenderError("bootstrap output terminal custody is missing")
    return RenderCustody(
        output,
        published_digest,
        parent,
        cleanup_parent_descriptor,
        custody_descriptor,
        expected_fingerprint,
    )


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--gate-sha256", required=True)
    parser.add_argument("--workflow-sha256", required=True)
    parser.add_argument("--boundary-validator-sha256", required=True)
    parser.add_argument("--isolation-validator-sha256", required=True)
    try:
        publication = render(parser.parse_args())
        output, digest = publication.evidence()
    except (OSError, RenderError) as exc:
        raise SystemExit(f"haptics bootstrap render failed: {exc}") from exc
    print("schema\ttb321fu.haptics-workflow-bootstrap-render/v1")
    print(f"output\t{output}")
    print(f"sha256\t{digest}")
    print("HAPTICS_WORKFLOW_BOOTSTRAP_RENDER=PASS")


if __name__ == "__main__":
    main()
