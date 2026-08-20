#!/usr/bin/env python3
"""Validate a candidate workflow from a trusted commit before dispatch."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
import errno
import hashlib
import json
import math
import os
import pathlib
import pwd
import re
import secrets
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import urllib.parse


_ORIGINAL_SCANDIR = os.scandir


COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
REMOTE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
DISPATCH_ID = re.compile(r"[0-9a-f]{32}")
MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_VALIDATOR_BYTES = 2 * 1024 * 1024
MAX_GH_OUTPUT_BYTES = 1024 * 1024
MAX_GH_DIAGNOSTIC_BYTES = 4096
MAX_GH_JSON_INTEGER_DIGITS = 64
MAX_GH_JSON_NESTING_DEPTH = 16
MAX_GITHUB_DATABASE_ID = 2**63 - 1
MAX_DISPATCH_STATE_BYTES = 4096
MAX_PROCESS_INPUT_BYTES = 1024 * 1024
MAX_PROCESS_STREAM_BYTES = 4 * 1024 * 1024
PROCESS_IO_CHUNK_BYTES = 64 * 1024
PROCESS_TERM_GRACE_SECONDS = 0.2
PROCESS_KILL_GRACE_SECONDS = 1.0
MAX_GIT_DIAGNOSTIC_BYTES = 64 * 1024
MAX_COMMIT_OBJECT_BYTES = 64 * 1024
MAX_TREE_OBJECT_BYTES = 2 * 1024 * 1024
MAX_VALIDATOR_OUTPUT_BYTES = 1024 * 1024
MAX_GATE_BYTES = 2 * 1024 * 1024
MAX_GATE_FD_SNAPSHOT_ENTRIES = 4096
VERIFY_TIMEOUT_SECONDS = 60.0
GATE_TIMEOUT_SECONDS = 300.0
WORKFLOW_PATH = ".github/workflows/build.yml"
WORKFLOW_NAME = "Build TB321FU Haptics Debs"
VALIDATOR_MODE = "trusted-commit-blobs/v1"
DISPATCH_STATE_RELATIVE_DIRECTORY = pathlib.PurePosixPath(
    ".local/state/tb321fu-haptics-workflow-dispatch"
)
VALIDATOR_PATHS = (
    "scripts/ci/check-workflow-input-boundaries.py",
    "scripts/ci/test-haptics-release-job-isolation.py",
)
REVIEWED_BLOB_MODES = {
    WORKFLOW_PATH: "100644",
    VALIDATOR_PATHS[0]: "100755",
    VALIDATOR_PATHS[1]: "100644",
}
CANONICAL_INPUTS: dict[str, object] = {
    "dispatch_id": "",
    "release_tag": "",
    "prerelease": True,
    "haptics_deb_version": "20260730.2",
    "kernel_source_commit": "570b90203d97f67321fa0fb2d0af73c31d7111af",
    "kernel_build_archive": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/"
        "tb321fu-kernel-build-sdk-7.1.1-00009-g570b90203d97.tar.gz"
    ),
    "kernel_build_archive_sha256": (
        "7f9b12bd02c1155c9900a33c823d088e1a9f72689dea28c8ee582a31304c7c49"
    ),
    "kernel_bundle_metadata": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/KERNEL-BUNDLE.tsv"
    ),
    "kernel_bundle_metadata_sha256": (
        "9b11d12fab79eb4f10acb7eddf9c5e11e3f4242f2877658627ff3b11dd231998"
    ),
    "kernel_sdk_manifest": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/"
        "KERNEL-SDK-MANIFEST.tsv"
    ),
    "kernel_toolchain_manifest": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/KERNEL-TOOLCHAIN.tsv"
    ),
}


class WorkflowGateError(ValueError):
    pass


@dataclass(frozen=True)
class DispatchRecord:
    run_id: int
    display_title: str
    head_branch: str
    head_sha: str
    url: str


@dataclass(frozen=True)
class DispatchResult:
    record: DispatchRecord
    dispatch_id: str
    input_sha256: str
    state_sha256: str
    validator_mode: str

    @property
    def run_id(self) -> int:
        return self.record.run_id

    @property
    def display_title(self) -> str:
        return self.record.display_title

    @property
    def head_branch(self) -> str:
        return self.record.head_branch

    @property
    def head_sha(self) -> str:
        return self.record.head_sha

    @property
    def url(self) -> str:
        return self.record.url


@dataclass(frozen=True)
class VerificationEvidence:
    trusted_commit: str
    gate_sha256: str
    workflow_sha256: str
    validators: tuple[tuple[str, str, str], ...]


def require_verification_evidence(value: object) -> VerificationEvidence:
    if type(value) is not VerificationEvidence:
        raise WorkflowGateError("workflow verification evidence is not canonical")
    if (
        not COMMIT.fullmatch(value.trusted_commit)
        or not SHA256.fullmatch(value.gate_sha256)
        or not SHA256.fullmatch(value.workflow_sha256)
        or type(value.validators) is not tuple
        or any(
            type(record) is not tuple or len(record) != 3
            for record in value.validators
        )
    ):
        raise WorkflowGateError("workflow verification evidence is not canonical")
    if tuple(record[0] for record in value.validators) != VALIDATOR_PATHS or any(
        type(path) is not str
        or type(mode) is not str
        or type(digest) is not str
        or mode != REVIEWED_BLOB_MODES[path]
        or not SHA256.fullmatch(digest)
        for path, mode, digest in value.validators
    ):
        raise WorkflowGateError("workflow verification evidence is not canonical")
    return value


def dispatch_input_digest(release_tag: str, dispatch_id: str) -> str:
    expected_tag = f"tb321fu-haptics-debs-{CANONICAL_INPUTS['haptics_deb_version']}"
    if (
        type(release_tag) is not str
        or release_tag not in {"", expected_tag}
        or type(dispatch_id) is not str
        or not DISPATCH_ID.fullmatch(dispatch_id)
    ):
        raise WorkflowGateError("workflow dispatch input identity is not canonical")
    inputs = dict(CANONICAL_INPUTS)
    inputs["release_tag"] = release_tag
    inputs["dispatch_id"] = dispatch_id
    return hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def serialize_dispatch_state(
    repository: str,
    remote_ref: str,
    candidate_commit: str,
    release_tag: str,
    dispatch_id: str,
    evidence: VerificationEvidence,
) -> bytes:
    evidence = require_verification_evidence(evidence)
    require_repository_and_ref(repository, remote_ref)
    if (
        type(candidate_commit) is not str
        or not COMMIT.fullmatch(candidate_commit)
        or evidence.trusted_commit == candidate_commit
    ):
        raise WorkflowGateError("workflow dispatch commit identities are not canonical")
    lines = (
        "schema\ttb321fu.haptics-workflow-dispatch/v2",
        f"repository\t{repository}",
        f"remote-ref\t{remote_ref}",
        f"trusted-commit\t{evidence.trusted_commit}",
        f"candidate-commit\t{candidate_commit}",
        f"gate-sha256\t{evidence.gate_sha256}",
        f"workflow-sha256\t{evidence.workflow_sha256}",
        *(
            f"validator-sha256\t{path}\t{mode}\t{digest}"
            for path, mode, digest in evidence.validators
        ),
        f"release-tag\t{release_tag or '-'}",
        f"input-sha256\t{dispatch_input_digest(release_tag, dispatch_id)}",
        f"dispatch-id\t{dispatch_id}",
    )
    raw = ("\n".join(lines) + "\n").encode("ascii")
    if len(raw) > MAX_DISPATCH_STATE_BYTES:
        raise WorkflowGateError("workflow dispatch state exceeds its size bound")
    return raw


def parse_dispatch_state(
    raw: bytes,
    repository: str,
    remote_ref: str,
    candidate_commit: str,
    release_tag: str,
    evidence: VerificationEvidence,
) -> str:
    if (
        not raw
        or len(raw) > MAX_DISPATCH_STATE_BYTES
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\0" in raw
    ):
        raise WorkflowGateError("workflow dispatch state has invalid framing or size")
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as exc:
        raise WorkflowGateError("workflow dispatch state must contain ASCII only") from exc
    key, separator, dispatch_id = lines[-1].partition("\t")
    if key != "dispatch-id" or not separator or not DISPATCH_ID.fullmatch(dispatch_id):
        raise WorkflowGateError("workflow dispatch state contains an invalid id")
    if serialize_dispatch_state(
        repository,
        remote_ref,
        candidate_commit,
        release_tag,
        dispatch_id,
        evidence,
    ) != raw:
        raise WorkflowGateError(
            "workflow dispatch state is not canonical or differs from this request"
        )
    return dispatch_id


def dispatch_state_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def dispatch_state_content_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def require_dispatch_state_path(path: object) -> pathlib.PosixPath:
    if (
        type(path) is not pathlib.PosixPath
        or not path.is_absolute()
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", path.name)
    ):
        raise WorkflowGateError("workflow dispatch state path is not canonical")
    return path


def require_operator_home() -> pathlib.PosixPath:
    try:
        account_home = pwd.getpwuid(os.geteuid()).pw_dir
    except (KeyError, OSError) as exc:
        raise WorkflowGateError(
            "cannot resolve workflow dispatch operator account"
        ) from exc
    if (
        type(account_home) is not str
        or not account_home
        or "\0" in account_home
        or os.environ.get("HOME") != account_home
    ):
        raise WorkflowGateError(
            "workflow dispatch HOME differs from the account database"
        )
    home = pathlib.Path(account_home)
    try:
        resolved = home.resolve(strict=True)
        metadata = home.lstat()
    except OSError as exc:
        raise WorkflowGateError("cannot inspect workflow dispatch operator home") from exc
    if (
        type(home) is not pathlib.PosixPath
        or not home.is_absolute()
        or str(home) != account_home
        or home != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise WorkflowGateError("workflow dispatch operator home differs from policy")
    return home


def require_dispatch_state_ancestry(
    home: pathlib.PosixPath,
    parent: pathlib.PosixPath,
) -> None:
    expected_parent = home / DISPATCH_STATE_RELATIVE_DIRECTORY
    if (
        type(home) is not pathlib.PosixPath
        or type(parent) is not pathlib.PosixPath
        or parent != expected_parent
    ):
        raise WorkflowGateError(
            "workflow dispatch state directory ancestry differs from policy"
        )
    paths = [home]
    current = home
    for component in DISPATCH_STATE_RELATIVE_DIRECTORY.parts:
        current /= component
        paths.append(current)
    for path in paths:
        try:
            resolved = path.resolve(strict=True)
            metadata = path.lstat()
        except OSError as exc:
            raise WorkflowGateError(
                "cannot inspect workflow dispatch state directory ancestry"
            ) from exc
        if (
            resolved != path
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise WorkflowGateError(
                "workflow dispatch state directory ancestry differs from policy"
            )


def canonical_dispatch_state_path(
    home: pathlib.PosixPath,
    candidate_commit: str,
    release_tag: str,
) -> pathlib.PosixPath:
    expected_tag = f"tb321fu-haptics-debs-{CANONICAL_INPUTS['haptics_deb_version']}"
    if (
        type(home) is not pathlib.PosixPath
        or not home.is_absolute()
        or type(candidate_commit) is not str
        or not COMMIT.fullmatch(candidate_commit)
        or type(release_tag) is not str
        or release_tag not in {"", expected_tag}
    ):
        raise WorkflowGateError("workflow dispatch state identity is not canonical")
    profile = "diagnostic" if not release_tag else "release"
    return (
        home
        / DISPATCH_STATE_RELATIVE_DIRECTORY
        / f"{candidate_commit}.{profile}.tsv"
    )


def reserve_dispatch_state(
    path: pathlib.Path,
    repository: str,
    remote_ref: str,
    candidate_commit: str,
    release_tag: str,
    evidence: VerificationEvidence,
    dispatch_id_factory: Callable[[], str],
) -> tuple[str, bool]:
    path = require_dispatch_state_path(path)
    evidence = require_verification_evidence(evidence)
    if not callable(dispatch_id_factory):
        raise WorkflowGateError("workflow dispatch id generator is not callable")
    try:
        parent = path.parent.resolve(strict=True)
        parent_namespace = os.stat(path.parent, follow_symlinks=False)
    except OSError as exc:
        raise WorkflowGateError(f"cannot inspect workflow dispatch state parent: {exc}") from exc
    if parent != path.parent:
        raise WorkflowGateError("workflow dispatch state parent is not canonical")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor = -1
    temporary_descriptor = -1
    temporary_name: str | None = None
    created_identity: tuple[int, int] | None = None
    completed = False
    primary: BaseException | None = None
    cleanup_notes: list[str] = []
    reservation_result: tuple[str, bool] | None = None

    class ReservationReady(Exception):
        pass

    def remember_state_cleanup(exc: BaseException, note: str) -> None:
        nonlocal primary
        primary = choose_running_gate_failure(
            primary,
            running_gate_cleanup_candidate(
                exc,
                "workflow dispatch state cleanup failed",
            ),
            note,
        )
        cleanup_notes.append(note)

    def parent_guard(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
        )

    def verify_parent_metadata() -> None:
        current = os.fstat(parent_descriptor)
        namespace = os.stat(path.parent, follow_symlinks=False)
        if (
            parent_guard(current) != parent_guard(parent_metadata)
            or parent_guard(namespace) != parent_guard(parent_metadata)
            or path.parent.resolve(strict=True) != path.parent
        ):
            raise WorkflowGateError(
                "workflow dispatch state parent changed during reservation"
            )

    def read_existing_state() -> str:
        descriptor = -1
        read_primary: BaseException | None = None
        result: str | None = None
        try:
            read_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
            if hasattr(os, "O_NOFOLLOW"):
                read_flags |= os.O_NOFOLLOW
            existing_namespace = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            existing_baseline = bounded_gate_descriptor_set()
            try:
                descriptor = os.open(
                    path.name,
                    read_flags,
                    dir_fd=parent_descriptor,
                )
            except BaseException as exc:
                selected, _ = recover_gate_descriptor_handoff(
                    existing_baseline,
                    (existing_namespace.st_dev, existing_namespace.st_ino),
                    "workflow dispatch existing-state open handoff",
                    exc,
                )
                raise selected
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid()
                or before.st_gid != os.getegid()
                or before.st_nlink not in {1, 2}
                or before.st_size <= 0
                or before.st_size > MAX_DISPATCH_STATE_BYTES
            ):
                raise WorkflowGateError(
                    "workflow dispatch state metadata differs from policy"
                )
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_DISPATCH_STATE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(65536, MAX_DISPATCH_STATE_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            namespace = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            stable_identity = dispatch_state_content_identity(before)
            if (
                dispatch_state_content_identity(after) == stable_identity
                and dispatch_state_content_identity(namespace) == stable_identity
                and after.st_nlink != namespace.st_nlink
            ):
                after = os.fstat(descriptor)
                namespace = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            if (
                total > MAX_DISPATCH_STATE_BYTES
                or total != before.st_size
                or dispatch_state_content_identity(after) != stable_identity
                or dispatch_state_content_identity(namespace) != stable_identity
                or after.st_nlink not in {1, 2}
                or namespace.st_nlink != after.st_nlink
                or namespace.st_ctime_ns != after.st_ctime_ns
                or (
                    before.st_nlink == after.st_nlink
                    and before.st_ctime_ns != after.st_ctime_ns
                )
                or (before.st_nlink == 1 and after.st_nlink != 1)
            ):
                raise WorkflowGateError(
                    "workflow dispatch state changed during verification"
                )
            result = parse_dispatch_state(
                raw,
                repository,
                remote_ref,
                candidate_commit,
                release_tag,
                evidence,
            )
            if after.st_nlink == 2:
                recovery_name = f".{path.name}.{result}.tmp"
                try:
                    recovery = os.stat(
                        recovery_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    recovery = None
                if recovery is not None:
                    if (
                        dispatch_state_content_identity(recovery)
                        != stable_identity
                        or recovery.st_nlink != 2
                    ):
                        raise WorkflowGateError(
                            "workflow dispatch state hardlink differs from recovery policy"
                        )
                    try:
                        os.unlink(recovery_name, dir_fd=parent_descriptor)
                    except FileNotFoundError:
                        pass
                os.fsync(parent_descriptor)
                recovered = os.fstat(descriptor)
                recovered_namespace = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    recovered.st_nlink != 1
                    or recovered_namespace.st_nlink != 1
                    or dispatch_state_content_identity(recovered)
                    != stable_identity
                    or dispatch_state_content_identity(recovered_namespace)
                    != stable_identity
                    or recovered.st_ctime_ns != recovered_namespace.st_ctime_ns
                    or recovered.st_size != len(raw)
                ):
                    raise WorkflowGateError(
                        "workflow dispatch state recovery did not converge"
                    )
            verify_parent_metadata()
        except OSError as exc:
            read_primary = WorkflowGateError(
                f"cannot read workflow dispatch state: {exc}"
            )
            read_primary.__cause__ = exc
        except BaseException as exc:
            read_primary = exc
        finally:
            if descriptor >= 0:
                read_primary, _ = close_owned_gate_descriptor(
                    descriptor,
                    "workflow dispatch state descriptor",
                    read_primary,
                )
        if read_primary is not None:
            raise read_primary
        if result is None:
            raise WorkflowGateError("workflow dispatch state read produced no result")
        return result

    try:
        parent_baseline = bounded_gate_descriptor_set()
        try:
            parent_descriptor = os.open(parent, flags)
        except BaseException as exc:
            selected, _ = recover_gate_descriptor_handoff(
                parent_baseline,
                (parent_namespace.st_dev, parent_namespace.st_ino),
                "workflow dispatch state-parent open handoff",
                exc,
            )
            raise selected
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or parent_metadata.st_uid != os.geteuid()
            or parent_metadata.st_gid != os.getegid()
            or parent_guard(parent_metadata) != parent_guard(parent_namespace)
        ):
            raise WorkflowGateError(
                "workflow dispatch state parent metadata differs from policy"
            )
        try:
            os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            reservation_result = (read_existing_state(), False)
            completed = True
            raise ReservationReady
        dispatch_id = dispatch_id_factory()
        if type(dispatch_id) is not str or not DISPATCH_ID.fullmatch(dispatch_id):
            raise WorkflowGateError("workflow dispatch id generator returned unsafe data")
        raw = serialize_dispatch_state(
            repository,
            remote_ref,
            candidate_commit,
            release_tag,
            dispatch_id,
            evidence,
        )
        temporary_name = f".{path.name}.{dispatch_id}.tmp"
        if len(os.fsencode(temporary_name)) > 240:
            raise WorkflowGateError("workflow dispatch temporary name is too long")
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        temporary_baseline = bounded_gate_descriptor_set()
        try:
            temporary_descriptor = os.open(
                temporary_name, create_flags, 0o600, dir_fd=parent_descriptor
            )
        except BaseException as exc:
            selected, recovered_identity = recover_created_state_handoff(
                temporary_baseline,
                parent_metadata.st_dev,
                "workflow dispatch temporary-state open handoff",
                exc,
            )
            if recovered_identity is not None:
                created_identity = recovered_identity
            if isinstance(exc, FileExistsError) and recovered_identity is None:
                failure = WorkflowGateError(
                    "workflow dispatch temporary state already exists"
                )
                failure.__cause__ = exc
                selected = choose_running_gate_failure(
                    selected if selected is not exc else None,
                    failure,
                    "workflow dispatch temporary-state open also failed",
                )
            raise selected
        before = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
            or before.st_nlink != 1
            or before.st_size != 0
        ):
            raise WorkflowGateError(
                "workflow dispatch temporary state metadata differs from policy"
            )
        created_identity = (before.st_dev, before.st_ino)
        offset = 0
        while offset < len(raw):
            written = os.write(temporary_descriptor, raw[offset:])
            if written <= 0:
                raise WorkflowGateError(
                    "workflow dispatch state write made no progress"
                )
            offset += written
        os.fchmod(temporary_descriptor, 0o600)
        os.fsync(temporary_descriptor)
        after = os.fstat(temporary_descriptor)
        temporary_namespace = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            dispatch_state_identity(after)
            != dispatch_state_identity(temporary_namespace)
            or (after.st_dev, after.st_ino) != created_identity
            or after.st_nlink != 1
            or after.st_size != len(raw)
        ):
            raise WorkflowGateError(
                "workflow dispatch temporary state changed before publication"
            )
        primary, temporary_closed = close_owned_gate_descriptor(
            temporary_descriptor,
            "workflow dispatch temporary state descriptor",
            primary,
        )
        if temporary_closed:
            temporary_descriptor = -1
        if primary is not None:
            raise primary
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            current = os.stat(
                temporary_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != created_identity:
                raise WorkflowGateError(
                    "workflow dispatch temporary namespace changed during race"
                )
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            created_identity = None
            temporary_name = None
            os.fsync(parent_descriptor)
            existing_id = read_existing_state()
            reservation_result = (existing_id, False)
            completed = True
            raise ReservationReady
        if reservation_result is None:
            os.fsync(parent_descriptor)
            published_state = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                (published_state.st_dev, published_state.st_ino) != created_identity
                or published_state.st_nlink not in {1, 2}
                or published_state.st_size != len(raw)
            ):
                raise WorkflowGateError(
                    "workflow dispatch state publication differs from policy"
                )
            if published_state.st_nlink == 2:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
            temporary_name = None
            os.fsync(parent_descriptor)
            verify_parent_metadata()
            if read_existing_state() != dispatch_id:
                raise WorkflowGateError(
                    "workflow dispatch state changed after publication"
                )
            reservation_result = (dispatch_id, True)
            completed = True
    except ReservationReady:
        pass
    except OSError as exc:
        primary = WorkflowGateError(f"cannot reserve workflow dispatch state: {exc}")
        primary.__cause__ = exc
    except BaseException as exc:
        primary = exc
    finally:
        if (
            temporary_descriptor >= 0
            and created_identity is None
            and not completed
        ):
            try:
                recovered = os.fstat(temporary_descriptor)
                if (
                    not stat.S_ISREG(recovered.st_mode)
                    or stat.S_IMODE(recovered.st_mode) != 0o600
                    or recovered.st_uid != os.geteuid()
                    or recovered.st_gid != os.getegid()
                    or recovered.st_nlink != 1
                    or recovered.st_size != 0
                ):
                    raise WorkflowGateError(
                        "workflow dispatch temporary state recovery metadata "
                        "differs from policy"
                    )
                created_identity = (recovered.st_dev, recovered.st_ino)
            except BaseException as exc:
                remember_state_cleanup(
                    exc,
                    "workflow dispatch temporary identity recovery failed",
                )
        if temporary_descriptor >= 0:
            primary, temporary_closed = close_owned_gate_descriptor(
                temporary_descriptor,
                "workflow dispatch temporary state descriptor",
                primary,
            )
            if temporary_closed:
                temporary_descriptor = -1
        if (
            created_identity is not None
            and not completed
            and parent_descriptor >= 0
        ):
            names = tuple(
                dict.fromkeys(
                    name
                    for name in (path.name, temporary_name)
                    if name is not None
                )
            )
            for name in names:
                try:
                    current = os.stat(
                        name, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    continue
                except BaseException as exc:
                    remember_state_cleanup(
                        exc, "workflow dispatch state cleanup inspection failed"
                    )
                    continue
                if (current.st_dev, current.st_ino) != created_identity:
                    remember_state_cleanup(
                        WorkflowGateError(
                            "workflow dispatch state cleanup namespace changed"
                        ),
                        "workflow dispatch state cleanup namespace changed",
                    )
                    continue
                try:
                    os.unlink(name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
                except BaseException as exc:
                    remember_state_cleanup(
                        exc, "workflow dispatch state cleanup unlink failed"
                    )
            try:
                os.fsync(parent_descriptor)
            except BaseException as exc:
                remember_state_cleanup(
                    exc, "workflow dispatch state cleanup directory sync failed"
                )
            for name in names:
                try:
                    current = os.stat(
                        name, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    continue
                except BaseException as exc:
                    remember_state_cleanup(
                        exc, "workflow dispatch state cleanup recheck failed"
                    )
                    continue
                note = (
                    "workflow dispatch state cleanup left owned inode present"
                    if (current.st_dev, current.st_ino) == created_identity
                    else "workflow dispatch state cleanup namespace changed"
                )
                remember_state_cleanup(WorkflowGateError(note), note)
        if parent_descriptor >= 0:
            primary, parent_closed = close_owned_gate_descriptor(
                parent_descriptor,
                "workflow dispatch state parent descriptor",
                primary,
            )
            if parent_closed:
                parent_descriptor = -1
        if cleanup_notes:
            if primary is None:
                primary = WorkflowGateError(
                    "workflow dispatch state cleanup failed"
                )
            for note in dict.fromkeys(cleanup_notes):
                primary.add_note(note)
    if primary is not None:
        raise primary
    if reservation_result is None:
        raise WorkflowGateError("workflow dispatch state reservation produced no result")
    return reservation_result


def clean_environment(home: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_OPTIONAL_LOCKS": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def choose_running_gate_failure(
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


def running_gate_cleanup_candidate(
    exc: BaseException,
    message: str,
) -> BaseException:
    if not isinstance(exc, Exception):
        return exc
    failure = WorkflowGateError(message)
    failure.__cause__ = exc
    return failure


def close_owned_gate_descriptor(
    descriptor: int,
    label: str,
    primary: BaseException | None,
) -> tuple[BaseException | None, bool]:
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            primary = choose_running_gate_failure(
                primary,
                running_gate_cleanup_candidate(
                    exc,
                    f"cannot close {label}",
                ),
                f"{label} close cleanup also failed",
            )
            try:
                os.fstat(descriptor)
            except BaseException as probe:
                if isinstance(probe, OSError) and probe.errno == errno.EBADF:
                    return primary, True
                primary = choose_running_gate_failure(
                    primary,
                    running_gate_cleanup_candidate(
                        probe,
                        f"cannot determine {label} custody",
                    ),
                    f"{label} custody probe also failed",
                )
            continue
        return primary, True
    try:
        os.fstat(descriptor)
    except BaseException as probe:
        if isinstance(probe, OSError) and probe.errno == errno.EBADF:
            return primary, True
        primary = choose_running_gate_failure(
            primary,
            running_gate_cleanup_candidate(
                probe,
                f"cannot determine final {label} custody",
            ),
            f"final {label} custody probe also failed",
        )
    return (
        choose_running_gate_failure(
            primary,
            WorkflowGateError(f"{label} close did not converge"),
            f"{label} custody also did not converge",
        ),
        False,
    )


def trusted_gate_descriptor_set(
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
            if count > MAX_GATE_FD_SNAPSHOT_ENTRIES:
                raise WorkflowGateError(
                    "workflow gate descriptor table exceeds its bound"
                )
            if entry.name.isascii() and entry.name.isdecimal():
                descriptor = int(entry.name, 10)
                descriptors.add(descriptor)
                if partial_descriptors is not None:
                    partial_descriptors.add(descriptor)
    except BaseException as exc:
        primary = running_gate_cleanup_candidate(
            exc,
            "cannot inspect trusted workflow gate descriptor table",
        )
    if entries is not None:
        closed = False
        for _ in range(3):
            try:
                entries.close()
            except BaseException as exc:
                primary = choose_running_gate_failure(
                    primary,
                    running_gate_cleanup_candidate(
                        exc,
                        "cannot close trusted workflow gate descriptor iterator",
                    ),
                    "trusted workflow gate descriptor iterator close also failed",
                )
                continue
            closed = True
            break
        if not closed:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(
                    "trusted workflow gate descriptor iterator close did not converge"
                ),
                "trusted workflow gate descriptor iterator custody also failed",
            )
    if primary is not None:
        raise primary
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise WorkflowGateError(
                    "cannot inspect trusted workflow gate descriptor entry"
                ) from exc
        else:
            live.add(descriptor)
    return frozenset(live)


def recover_gate_scandir_acquisition(
    before: frozenset[int],
    identity: tuple[int, int],
    primary: BaseException,
) -> BaseException:
    partial_descriptors: set[int] = set()
    try:
        after = trusted_gate_descriptor_set(partial_descriptors)
    except BaseException as exc:
        primary = choose_running_gate_failure(
            primary,
            running_gate_cleanup_candidate(
                exc,
                "cannot recover workflow gate descriptor-table acquisition",
            ),
            "workflow gate descriptor-table recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    for descriptor in sorted(after - before):
        identity_matches: bool | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_running_gate_failure(
                primary,
                running_gate_cleanup_candidate(
                    exc,
                    "cannot inspect workflow gate descriptor-table recovery",
                ),
                "workflow gate descriptor-table recovery probe also failed",
            )
        else:
            identity_matches = (metadata.st_dev, metadata.st_ino) == identity
        primary, closed = close_owned_gate_descriptor(
            descriptor,
            "workflow gate descriptor-table acquisition",
            primary,
        )
        if identity_matches is None:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(
                    "workflow gate descriptor-table acquisition recovered "
                    "a descriptor with unknown identity"
                ),
                "workflow gate descriptor-table recovery identity also "
                "became unknown",
            )
        elif not identity_matches:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(
                    "workflow gate descriptor-table acquisition recovered an "
                    "unexpected descriptor"
                ),
                "workflow gate descriptor-table recovery identity also differed",
            )
        if not closed:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(
                    "workflow gate descriptor-table recovery did not converge"
                ),
                "workflow gate descriptor-table recovery also did not converge",
            )
    return primary


def bounded_gate_descriptor_set(
    partial_descriptors: set[int] | None = None,
) -> frozenset[int]:
    descriptors: set[int] = set()
    entries = None
    primary: BaseException | None = None
    table_metadata = os.stat("/proc/self/fd", follow_symlinks=False)
    acquisition_before = trusted_gate_descriptor_set(partial_descriptors)
    try:
        entries = os.scandir("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > MAX_GATE_FD_SNAPSHOT_ENTRIES:
                raise WorkflowGateError(
                    "workflow gate descriptor table exceeds its bound"
                )
            if entry.name.isascii() and entry.name.isdecimal():
                descriptor = int(entry.name, 10)
                descriptors.add(descriptor)
                if partial_descriptors is not None:
                    partial_descriptors.add(descriptor)
    except BaseException as exc:
        primary = running_gate_cleanup_candidate(
            exc,
            "cannot inspect workflow gate descriptor table",
        )
        if entries is None:
            primary = recover_gate_scandir_acquisition(
                acquisition_before,
                (table_metadata.st_dev, table_metadata.st_ino),
                primary,
            )
    if entries is not None:
        closed = False
        for _ in range(3):
            try:
                entries.close()
            except BaseException as exc:
                primary = choose_running_gate_failure(
                    primary,
                    running_gate_cleanup_candidate(
                        exc,
                        "cannot close workflow gate descriptor-table iterator",
                    ),
                    "workflow gate descriptor-table iterator close also failed",
                )
                continue
            closed = True
            break
        if not closed:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(
                    "workflow gate descriptor-table iterator close did not converge"
                ),
                "workflow gate descriptor-table iterator custody also failed",
            )
    if primary is not None:
        raise primary
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise WorkflowGateError(
                    "cannot inspect workflow gate descriptor-table entry"
                ) from exc
        else:
            live.add(descriptor)
    return frozenset(live)


def recover_gate_descriptor_handoff(
    before: frozenset[int],
    identity: tuple[int, int],
    label: str,
    primary: BaseException,
) -> tuple[BaseException, bool]:
    recovered = False
    partial_descriptors: set[int] = set()
    try:
        after = bounded_gate_descriptor_set(partial_descriptors)
    except BaseException as exc:
        primary = choose_running_gate_failure(
            primary,
            running_gate_cleanup_candidate(
                exc,
                f"cannot recover {label}",
            ),
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    for descriptor in sorted(after - before):
        identity_matches: bool | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_running_gate_failure(
                primary,
                running_gate_cleanup_candidate(
                    exc,
                    f"cannot inspect {label}",
                ),
                f"{label} recovery inspection also failed",
            )
        else:
            identity_matches = (metadata.st_dev, metadata.st_ino) == identity
        primary, closed = close_owned_gate_descriptor(
            descriptor,
            label,
            primary,
        )
        if identity_matches is None:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(f"{label} recovered descriptor identity is unknown"),
                f"{label} recovery identity also became unknown",
            )
        elif not identity_matches:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(f"{label} recovered an unexpected descriptor"),
                f"{label} recovery identity also differed",
            )
        elif closed:
            recovered = True
        if not closed:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(f"{label} recovery did not converge"),
                f"{label} recovery also did not converge",
            )
    return primary, recovered


def recover_created_state_handoff(
    before: frozenset[int],
    parent_device: int,
    label: str,
    primary: BaseException,
) -> tuple[BaseException, tuple[int, int] | None]:
    partial_descriptors: set[int] = set()
    try:
        after = bounded_gate_descriptor_set(partial_descriptors)
    except BaseException as exc:
        primary = choose_running_gate_failure(
            primary,
            running_gate_cleanup_candidate(
                exc,
                f"cannot recover {label}",
            ),
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    candidates: list[tuple[int, os.stat_result | None, bool]] = []
    for descriptor in sorted(after - before):
        metadata: os.stat_result | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_running_gate_failure(
                primary,
                running_gate_cleanup_candidate(
                    exc,
                    f"cannot inspect {label}",
                ),
                f"{label} recovery inspection also failed",
            )
        policy_matches = metadata is not None and (
            stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid == os.geteuid()
            and metadata.st_gid == os.getegid()
            and metadata.st_nlink == 1
            and metadata.st_size == 0
            and metadata.st_dev == parent_device
        )
        candidates.append((descriptor, metadata, policy_matches))
    recovered_identity: tuple[int, int] | None = None
    if len(candidates) > 1:
        primary = choose_running_gate_failure(
            primary,
            WorkflowGateError(f"{label} recovery is ambiguous"),
            f"{label} recovery also became ambiguous",
        )
    for descriptor, metadata, policy_matches in candidates:
        primary, closed = close_owned_gate_descriptor(
            descriptor,
            label,
            primary,
        )
        if metadata is None:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(f"{label} recovered descriptor identity is unknown"),
                f"{label} recovery identity also became unknown",
            )
        elif not policy_matches:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(f"{label} recovered descriptor differs from policy"),
                f"{label} recovery metadata also differed",
            )
        if not closed:
            primary = choose_running_gate_failure(
                primary,
                WorkflowGateError(f"{label} recovery did not converge"),
                f"{label} recovery also did not converge",
            )
            continue
        if metadata is None:
            continue
        identity = (metadata.st_dev, metadata.st_ino)
        if recovered_identity is None:
            recovered_identity = identity
        elif recovered_identity != identity:
            recovered_identity = None
    if len(candidates) != 1:
        recovered_identity = None
    return primary, recovered_identity


def close_running_gate_descriptor(
    descriptor: int,
    primary: BaseException | None,
) -> BaseException | None:
    primary, _ = close_owned_gate_descriptor(
        descriptor,
        "running gate descriptor",
        primary,
    )
    return primary


def attest_running_gate(expected_digest: str | None) -> str:
    if expected_digest is not None and (
        type(expected_digest) is not str or not SHA256.fullmatch(expected_digest)
    ):
        raise WorkflowGateError("trusted gate digest is not canonical")
    descriptor = -1
    source_namespace: os.stat_result | None = None
    try:
        path = pathlib.Path(__file__)
        descriptor_match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", str(path))
        descriptor_execution = descriptor_match is not None
        if descriptor_execution:
            if expected_digest is None:
                raise WorkflowGateError(
                    "descriptor-executed gate requires a trusted digest"
                )
            inherited_descriptor = int(descriptor_match.group(1), 10)
            if inherited_descriptor < 3 or inherited_descriptor > 1_000_000:
                raise WorkflowGateError("running gate descriptor is not canonical")
            inherited_metadata = os.fstat(inherited_descriptor)
            duplicate_baseline = bounded_gate_descriptor_set()
            try:
                descriptor = os.dup(inherited_descriptor)
            except BaseException as exc:
                selected, _ = recover_gate_descriptor_handoff(
                    duplicate_baseline,
                    (inherited_metadata.st_dev, inherited_metadata.st_ino),
                    "running gate dup handoff",
                    exc,
                )
                raise selected
        else:
            if type(path) is not pathlib.PosixPath or path.resolve(strict=True) != path:
                raise WorkflowGateError("running gate path is not canonical")
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            source_namespace = os.stat(path, follow_symlinks=False)
            open_baseline = bounded_gate_descriptor_set()
            try:
                descriptor = os.open(path, flags)
            except BaseException as exc:
                selected, _ = recover_gate_descriptor_handoff(
                    open_baseline,
                    (source_namespace.st_dev, source_namespace.st_ino),
                    "running gate open handoff",
                    exc,
                )
                raise selected
    except WorkflowGateError:
        raise
    except OSError as exc:
        raise WorkflowGateError(f"cannot open running gate source: {exc}") from exc
    primary: BaseException | None = None
    digest: str | None = None
    try:
        before = os.fstat(descriptor)
        namespace = (
            None
            if descriptor_execution
            else os.stat(path, follow_symlinks=False)
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > MAX_GATE_BYTES
            or (
                namespace is not None
                and dispatch_state_identity(before)
                != dispatch_state_identity(namespace)
            )
            or (
                namespace is not None
                and source_namespace is not None
                and dispatch_state_identity(namespace)
                != dispatch_state_identity(source_namespace)
            )
        ):
            raise WorkflowGateError("running gate source metadata differs from policy")
        hasher = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise WorkflowGateError("running gate source ended before its bound")
            hasher.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise WorkflowGateError("running gate source exceeds its bound")
        after = os.fstat(descriptor)
        if dispatch_state_identity(after) != dispatch_state_identity(before):
            raise WorkflowGateError("running gate source changed while it was read")
        digest = hasher.hexdigest()
        if expected_digest is not None and not secrets.compare_digest(
            digest, expected_digest
        ):
            raise WorkflowGateError("running gate source differs from its trusted digest")
    except BaseException as exc:
        primary = exc
    finally:
        primary = close_running_gate_descriptor(descriptor, primary)
    if primary is not None:
        raise primary
    if digest is None:
        raise WorkflowGateError("running gate digest was not produced")
    return digest


def run_bounded_process(
    arguments: list[str],
    *,
    input_bytes: bytes | None,
    environment: dict[str, str],
    deadline: float,
    stdout_limit: int,
    stderr_limit: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    if (
        type(arguments) is not list
        or not arguments
        or len(arguments) > 128
        or any(
            type(argument) is not str
            or not argument
            or len(argument) > 4096
            or "\0" in argument
            for argument in arguments
        )
        or not pathlib.PurePosixPath(arguments[0]).is_absolute()
    ):
        raise WorkflowGateError(f"{label} arguments are not canonical")
    if type(input_bytes) not in {bytes, type(None)} or (
        input_bytes is not None and len(input_bytes) > MAX_PROCESS_INPUT_BYTES
    ):
        raise WorkflowGateError(f"{label} input exceeds its size bound")
    if type(environment) is not dict or any(
        type(name) is not str
        or type(value) is not str
        or not name
        or "=" in name
        or "\0" in name
        or "\0" in value
        for name, value in environment.items()
    ):
        raise WorkflowGateError(f"{label} environment is not canonical")
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
        or deadline <= time.monotonic()
    ):
        raise WorkflowGateError(f"{label} exceeded its deadline")
    if any(
        isinstance(limit, bool)
        or type(limit) is not int
        or limit < 0
        or limit > MAX_PROCESS_STREAM_BYTES
        for limit in (stdout_limit, stderr_limit)
    ):
        raise WorkflowGateError(f"{label} output limit is outside policy")
    if type(label) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._/-]{0,199}", label):
        raise WorkflowGateError("bounded process label is not canonical")
    try:
        sigchld_policy = signal.getsignal(signal.SIGCHLD)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise WorkflowGateError(f"cannot inspect {label} SIGCHLD policy") from exc
    if sigchld_policy != signal.SIG_DFL:
        raise WorkflowGateError(f"{label} requires default SIGCHLD policy")
    try:
        previous_sigchld_policy = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise WorkflowGateError(f"cannot normalize {label} SIGCHLD policy") from exc
    if previous_sigchld_policy != signal.SIG_DFL:
        try:
            signal.signal(signal.SIGCHLD, previous_sigchld_policy)
        except BaseException as restore_exc:
            failure = WorkflowGateError(
                f"{label} SIGCHLD policy changed during setup"
            )
            failure.add_note(
                f"SIGCHLD policy restoration also failed: {restore_exc}"
            )
            raise failure
        raise WorkflowGateError(f"{label} SIGCHLD policy changed during setup")

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    streams: dict[int, tuple[object, str]] = {}
    input_offset = 0
    leader_ownership = "owned"
    cleanup_notes: list[str] = []
    primary: BaseException | None = None
    normal_completion = False
    returncode = -signal.SIGKILL

    def require_process() -> subprocess.Popen[bytes]:
        if process is None:
            raise WorkflowGateError("bounded process is unavailable")
        return process

    def remember_cleanup_failure(exc: BaseException, note: str) -> None:
        nonlocal primary
        if isinstance(exc, Exception):
            candidate: BaseException = WorkflowGateError(f"{label} cleanup failed")
            candidate.__cause__ = exc
        else:
            candidate = exc
        primary = choose_running_gate_failure(primary, candidate, note)
        cleanup_notes.append(note)

    def register_stream(stream, events: int, name: str) -> None:
        if selector is None:
            raise WorkflowGateError("bounded process selector is unavailable")
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, events, name)
        streams[stream.fileno()] = (stream, name)

    def close_stream(stream) -> None:
        try:
            already_closed = stream.closed
        except BaseException as exc:
            remember_cleanup_failure(
                exc, "process stream state cleanup failed"
            )
            already_closed = False
        if already_closed:
            try:
                for key, value in tuple(streams.items()):
                    if value[0] is stream:
                        streams.pop(key, None)
            except BaseException as exc:
                remember_cleanup_failure(
                    exc, "process stream registry cleanup failed"
                )
            return
        descriptor: int | None = None
        try:
            descriptor = stream.fileno()
        except BaseException as exc:
            remember_cleanup_failure(
                exc, "process stream descriptor cleanup failed"
            )
        if selector is not None:
            for _ in range(2):
                try:
                    selector.unregister(stream)
                    break
                except (KeyError, ValueError):
                    break
                except BaseException as exc:
                    remember_cleanup_failure(
                        exc, "process stream unregister cleanup failed"
                    )
        try:
            if descriptor is not None:
                streams.pop(descriptor, None)
            else:
                for key, value in tuple(streams.items()):
                    if value[0] is stream:
                        streams.pop(key, None)
        except BaseException as exc:
            remember_cleanup_failure(
                exc, "process stream registry cleanup failed"
            )
        for _ in range(2):
            try:
                stream.close()
                return
            except BaseException as exc:
                remember_cleanup_failure(exc, "process stream close cleanup failed")
                try:
                    closed = getattr(stream, "closed", False)
                except BaseException as state_exc:
                    remember_cleanup_failure(
                        state_exc, "process stream state cleanup failed"
                    )
                    closed = False
                if closed:
                    return

    def leader_exited_without_reaping() -> bool:
        nonlocal leader_ownership
        current_process = require_process()
        if leader_ownership != "owned":
            return True
        try:
            result = os.waitid(
                os.P_PID,
                current_process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            leader_ownership = "lost"
            return True
        except BaseException:
            leader_ownership = "uncertain"
            raise
        return result is not None and result.si_pid == current_process.pid

    def signal_owned_group(signal_number: int, signal_name: str) -> None:
        current_process = require_process()
        for _ in range(2):
            if leader_ownership != "owned":
                return
            try:
                leader_exited_without_reaping()
            except BaseException as exc:
                remember_cleanup_failure(
                    exc, "process leader ownership check cleanup failed"
                )
                return
            if leader_ownership != "owned":
                return
            try:
                os.killpg(current_process.pid, signal_number)
                return
            except ProcessLookupError:
                return
            except BaseException as exc:
                remember_cleanup_failure(
                    exc, f"process-group {signal_name} cleanup failed"
                )
                if isinstance(exc, Exception):
                    return

    def drain_ready(timeout: float, *, discard: bool) -> None:
        nonlocal input_offset
        if selector is None:
            raise WorkflowGateError("bounded process selector is unavailable")
        for key, mask in selector.select(timeout):
            stream = key.fileobj
            name = key.data
            if name == "stdin":
                if not (mask & selectors.EVENT_WRITE):
                    continue
                try:
                    written = os.write(
                        stream.fileno(),
                        input_bytes[input_offset : input_offset + PROCESS_IO_CHUNK_BYTES],
                    )
                except BlockingIOError:
                    continue
                except BrokenPipeError:
                    close_stream(stream)
                    continue
                if written <= 0:
                    close_stream(stream)
                    continue
                input_offset += written
                if input_offset >= len(input_bytes):
                    close_stream(stream)
                continue
            if not (mask & selectors.EVENT_READ):
                continue
            target = stdout if name == "stdout" else stderr
            limit = stdout_limit if name == "stdout" else stderr_limit
            read_bound = PROCESS_IO_CHUNK_BYTES if discard else min(
                PROCESS_IO_CHUNK_BYTES,
                max(1, limit - len(target) + 1),
            )
            try:
                chunk = os.read(stream.fileno(), read_bound)
            except BlockingIOError:
                continue
            if not chunk:
                close_stream(stream)
                continue
            if not discard:
                target.extend(chunk)

    def output_error() -> WorkflowGateError | None:
        if len(stdout) > stdout_limit:
            return WorkflowGateError(f"{label} stdout exceeds its size bound")
        if len(stderr) > stderr_limit:
            return WorkflowGateError(f"{label} stderr exceeds its size bound")
        return None

    try:
        try:
            process = subprocess.Popen(
                arguments,
                stdin=(
                    subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
                text=False,
                bufsize=0,
                env=environment,
            )
        except OSError as exc:
            raise WorkflowGateError(f"cannot start {label}") from exc
        if process.stdout is None or process.stderr is None:
            raise WorkflowGateError(f"cannot capture {label} output")
        selector = selectors.DefaultSelector()
        register_stream(process.stdout, selectors.EVENT_READ, "stdout")
        register_stream(process.stderr, selectors.EVENT_READ, "stderr")
        if process.stdin is not None:
            if input_bytes:
                register_stream(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                primary = WorkflowGateError(f"{label} exceeded its deadline")
                break
            drain_ready(min(remaining, 0.05), discard=False)
            primary = output_error()
            if primary is not None:
                break
            output_open = any(
                name in {"stdout", "stderr"} for _, name in streams.values()
            )
            if not output_open and leader_exited_without_reaping():
                normal_completion = True
                break
    except BaseException as exc:
        primary = exc
    finally:
        if process is not None:
            if process.stdin is not None:
                close_stream(process.stdin)
            try:
                leader_exited_without_reaping()
            except BaseException as exc:
                remember_cleanup_failure(
                    exc, "process leader ownership check cleanup failed"
                )
            if normal_completion:
                signal_owned_group(signal.SIGKILL, "KILL")
            else:
                signal_owned_group(signal.SIGTERM, "TERM")
                grace_deadline = time.monotonic() + PROCESS_TERM_GRACE_SECONDS
                while selector is not None and time.monotonic() < grace_deadline:
                    try:
                        drain_ready(0.02, discard=True)
                    except BaseException as exc:
                        remember_cleanup_failure(
                            exc, "process TERM drain cleanup failed"
                        )
                        break
                signal_owned_group(signal.SIGKILL, "KILL")
            kill_deadline = time.monotonic() + PROCESS_KILL_GRACE_SECONDS
            while selector is not None and time.monotonic() < kill_deadline:
                try:
                    drain_ready(0.02, discard=True)
                except BaseException as exc:
                    remember_cleanup_failure(
                        exc, "process KILL drain cleanup failed"
                    )
                    break
                output_open = any(
                    name in {"stdout", "stderr"} for _, name in streams.values()
                )
                if not output_open:
                    try:
                        if leader_exited_without_reaping():
                            break
                    except BaseException as exc:
                        remember_cleanup_failure(
                            exc, "process leader ownership check cleanup failed"
                        )
                        break
            for stream, _ in tuple(streams.values()):
                close_stream(stream)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    close_stream(stream)
            if selector is not None:
                for _ in range(2):
                    try:
                        selector.close()
                        break
                    except BaseException as exc:
                        remember_cleanup_failure(
                            exc, "process selector close cleanup failed"
                        )
            while True:
                try:
                    returncode = process.wait(
                        timeout=max(0.0, kill_deadline - time.monotonic())
                    )
                    break
                except subprocess.TimeoutExpired:
                    if primary is None:
                        primary = WorkflowGateError(
                            f"{label} could not reap its process leader"
                        )
                    cleanup_notes.append(
                        "process leader did not exit after the final group signal"
                    )
                    returncode = -signal.SIGKILL
                    break
                except ChildProcessError as exc:
                    leader_ownership = "lost"
                    remember_cleanup_failure(
                        exc, "process leader reap cleanup failed"
                    )
                    returncode = -signal.SIGKILL
                    break
                except BaseException as exc:
                    remember_cleanup_failure(
                        exc, "process leader reap cleanup failed"
                    )
                    if time.monotonic() >= kill_deadline:
                        returncode = -signal.SIGKILL
                        break
            if leader_ownership == "lost" and primary is None:
                primary = WorkflowGateError(
                    f"{label} process leader was reaped outside the runner"
                )
            elif leader_ownership == "uncertain" and primary is None:
                primary = WorkflowGateError(
                    f"{label} process leader ownership is uncertain"
                )
        if cleanup_notes:
            if primary is None:
                primary = WorkflowGateError(f"{label} cleanup failed")
            for note in dict.fromkeys(cleanup_notes):
                primary.add_note(note)

    if primary is not None:
        raise primary
    return subprocess.CompletedProcess(arguments, returncode, bytes(stdout), bytes(stderr))


def run_git(
    repo: pathlib.Path,
    home: pathlib.Path,
    arguments: list[str],
    *,
    deadline: float,
    stdout_limit: int = MAX_GIT_DIAGNOSTIC_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    return run_bounded_process(
        [
            "/usr/bin/git",
            "--no-replace-objects",
            "-c",
            "core.pager=cat",
            "-C",
            str(repo),
            *arguments,
        ],
        input_bytes=None,
        environment=clean_environment(home),
        deadline=deadline,
        stdout_limit=stdout_limit,
        stderr_limit=MAX_GIT_DIAGNOSTIC_BYTES,
        label="git command",
    )


def require_commit(
    repo: pathlib.Path,
    home: pathlib.Path,
    commit: str,
    label: str,
    deadline: float,
) -> bytes:
    if not COMMIT.fullmatch(commit):
        raise WorkflowGateError(f"{label} is not a full lowercase commit id")
    result = run_git(
        repo,
        home,
        ["cat-file", "-t", commit],
        deadline=deadline,
        stdout_limit=16,
    )
    if result.returncode:
        raise WorkflowGateError(f"{label} is absent from the local object database")
    if result.stdout != b"commit\n":
        raise WorkflowGateError(f"{label} object is not an exact commit")
    size = run_git(
        repo,
        home,
        ["cat-file", "-s", commit],
        deadline=deadline,
        stdout_limit=32,
    )
    if size.returncode or not re.fullmatch(rb"[1-9][0-9]*\n", size.stdout):
        raise WorkflowGateError(f"{label} size is not canonical")
    object_size = int(size.stdout[:-1], 10)
    if object_size > MAX_COMMIT_OBJECT_BYTES:
        raise WorkflowGateError(f"{label} exceeds its size bound")
    content = run_git(
        repo,
        home,
        ["cat-file", "commit", commit],
        deadline=deadline,
        stdout_limit=object_size + 1,
    )
    if content.returncode or len(content.stdout) != object_size:
        raise WorkflowGateError(f"cannot export exact {label} bytes")
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(b"commit " + str(object_size).encode("ascii") + b"\0")
    digest.update(content.stdout)
    if not secrets.compare_digest(digest.hexdigest(), commit):
        raise WorkflowGateError(f"{label} bytes differ from their object id")
    return content.stdout


def require_sha1_repository(
    repo: pathlib.Path,
    home: pathlib.Path,
    deadline: float,
) -> None:
    result = run_git(
        repo,
        home,
        ["rev-parse", "--show-object-format"],
        deadline=deadline,
        stdout_limit=16,
    )
    if result.returncode or result.stdout != b"sha1\n":
        raise WorkflowGateError("repository object format must be exactly sha1")


def require_direct_unchanged_candidate(
    trusted_raw: bytes,
    candidate_raw: bytes,
    trusted_commit: str,
) -> None:
    def relation(raw: bytes, label: str) -> tuple[bytes, tuple[bytes, ...]]:
        header, separator, _ = raw.partition(b"\n\n")
        lines = header.split(b"\n")
        if (
            not separator
            or not lines
            or not re.fullmatch(rb"tree [0-9a-f]{40}", lines[0])
        ):
            raise WorkflowGateError(f"{label} header is not canonical")
        parents: list[bytes] = []
        for line in lines[1:]:
            if not line.startswith(b"parent "):
                break
            if not re.fullmatch(rb"parent [0-9a-f]{40}", line):
                raise WorkflowGateError(f"{label} parent header is not canonical")
            parents.append(line[7:])
        identity_offset = 1 + len(parents)
        if (
            len(lines) <= identity_offset + 1
            or not lines[identity_offset].startswith(b"author ")
            or not lines[identity_offset + 1].startswith(b"committer ")
        ):
            raise WorkflowGateError(f"{label} identity headers are not canonical")
        return lines[0][5:], tuple(parents)

    trusted_tree, _ = relation(trusted_raw, "trusted commit")
    candidate_tree, candidate_parents = relation(candidate_raw, "candidate commit")
    if len(candidate_parents) != 1:
        raise WorkflowGateError("candidate is not a canonical single-parent commit")
    if candidate_parents[0].decode("ascii") != trusted_commit:
        raise WorkflowGateError(
            "candidate is not the direct child of the trusted commit"
        )
    if not secrets.compare_digest(candidate_tree, trusted_tree):
        raise WorkflowGateError("candidate tree differs from the trusted commit")


def commit_root_tree(raw: bytes, label: str) -> str:
    header, separator, _ = raw.partition(b"\n\n")
    first, _, _ = header.partition(b"\n")
    if not separator or not re.fullmatch(rb"tree [0-9a-f]{40}", first):
        raise WorkflowGateError(f"{label} header is not canonical")
    return first[5:].decode("ascii")


def export_tree_object(
    repo: pathlib.Path,
    home: pathlib.Path,
    object_id: str,
    label: str,
    deadline: float,
) -> bytes:
    if not COMMIT.fullmatch(object_id):
        raise WorkflowGateError(f"{label} object id is not canonical")
    object_type = run_git(
        repo,
        home,
        ["cat-file", "-t", object_id],
        deadline=deadline,
        stdout_limit=16,
    )
    if object_type.returncode or object_type.stdout != b"tree\n":
        raise WorkflowGateError(f"{label} is not an exact tree")
    size = run_git(
        repo,
        home,
        ["cat-file", "-s", object_id],
        deadline=deadline,
        stdout_limit=64,
    )
    if size.returncode or not re.fullmatch(rb"[1-9][0-9]*\n", size.stdout):
        raise WorkflowGateError(f"{label} size is not canonical")
    object_size = int(size.stdout[:-1], 10)
    if object_size > MAX_TREE_OBJECT_BYTES:
        raise WorkflowGateError(f"{label} exceeds its size bound")
    content = run_git(
        repo,
        home,
        ["cat-file", "tree", object_id],
        deadline=deadline,
        stdout_limit=object_size + 1,
    )
    if content.returncode or len(content.stdout) != object_size:
        raise WorkflowGateError(f"cannot export exact {label} bytes")
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(b"tree " + str(object_size).encode("ascii") + b"\0")
    digest.update(content.stdout)
    if not secrets.compare_digest(digest.hexdigest(), object_id):
        raise WorkflowGateError(f"{label} bytes differ from its object id")
    return content.stdout


def tree_entry(
    raw: bytes,
    component: str,
    label: str,
) -> tuple[str, str]:
    try:
        component_bytes = component.encode("ascii")
    except UnicodeEncodeError as exc:
        raise WorkflowGateError(f"{label} path component is not canonical") from exc
    if (
        not component_bytes
        or component_bytes in {b".", b".."}
        or b"/" in component_bytes
        or b"\0" in component_bytes
    ):
        raise WorkflowGateError(f"{label} path component is not canonical")
    offset = 0
    match: tuple[str, str] | None = None
    while offset < len(raw):
        space = raw.find(b" ", offset)
        nul = raw.find(b"\0", space + 1) if space > offset else -1
        object_end = nul + 21
        if (
            space <= offset
            or nul <= space + 1
            or object_end > len(raw)
        ):
            raise WorkflowGateError(f"{label} bytes are not canonically framed")
        mode = raw[offset:space]
        name = raw[space + 1:nul]
        if (
            not re.fullmatch(rb"(?:40000|100644|100755|120000|160000)", mode)
            or name in {b".", b".."}
            or b"/" in name
        ):
            raise WorkflowGateError(f"{label} entry is not canonical")
        if name == component_bytes:
            if match is not None:
                raise WorkflowGateError(f"{label} path entry is not unique")
            match = (mode.decode("ascii"), raw[nul + 1:object_end].hex())
        offset = object_end
    if match is None:
        raise WorkflowGateError(f"{label} lacks its reviewed path entry")
    return match


def reviewed_blob_identity(
    repo: pathlib.Path,
    home: pathlib.Path,
    root_tree: str,
    commit_label: str,
    relative: str,
    expected_mode: str,
    deadline: float,
) -> str:
    components = pathlib.PurePosixPath(relative).parts
    if not components or "/".join(components) != relative:
        raise WorkflowGateError(f"{relative} export policy is not canonical")
    current_tree = root_tree
    traversed: list[str] = []
    for index, component in enumerate(components):
        tree_label = (
            f"{commit_label} root tree"
            if not traversed
            else f"{commit_label} tree {'/'.join(traversed)}"
        )
        raw = export_tree_object(
            repo,
            home,
            current_tree,
            tree_label,
            deadline,
        )
        mode, object_id = tree_entry(raw, component, tree_label)
        if index + 1 == len(components):
            if mode != expected_mode:
                raise WorkflowGateError(
                    f"{relative} tree mode or object id differs from policy"
                )
            return object_id
        if mode != "40000":
            raise WorkflowGateError(
                f"{relative} tree path differs from policy"
            )
        traversed.append(component)
        current_tree = object_id
    raise WorkflowGateError(f"{relative} reviewed object identity was not produced")


def export_blob(
    repo: pathlib.Path,
    home: pathlib.Path,
    root_tree: str,
    commit_label: str,
    relative: str,
    expected_mode: str,
    size_bound: int,
    deadline: float,
) -> bytes:
    if (
        REVIEWED_BLOB_MODES.get(relative) != expected_mode
        or not re.fullmatch(r"100(?:644|755)", expected_mode)
        or isinstance(size_bound, bool)
        or type(size_bound) is not int
        or size_bound <= 0
        or size_bound >= MAX_PROCESS_STREAM_BYTES
    ):
        raise WorkflowGateError(f"{relative} export policy is not canonical")
    object_id = reviewed_blob_identity(
        repo,
        home,
        root_tree,
        commit_label,
        relative,
        expected_mode,
        deadline,
    )
    object_type = run_git(
        repo,
        home,
        ["cat-file", "-t", object_id],
        deadline=deadline,
        stdout_limit=16,
    )
    if object_type.returncode or object_type.stdout != b"blob\n":
        raise WorkflowGateError(f"{relative} object is not an exact blob")
    size_result = run_git(
        repo,
        home,
        ["cat-file", "-s", object_id],
        deadline=deadline,
        stdout_limit=64,
    )
    if size_result.returncode or not re.fullmatch(rb"(?:0|[1-9][0-9]*)\n", size_result.stdout):
        raise WorkflowGateError(f"{relative} blob size is not canonical")
    blob_size = int(size_result.stdout[:-1], 10)
    if blob_size <= 0 or blob_size > size_bound:
        raise WorkflowGateError(f"{relative} is empty or exceeds its size bound")
    result = run_git(
        repo,
        home,
        ["cat-file", "blob", object_id],
        deadline=deadline,
        stdout_limit=blob_size + 1,
    )
    if result.returncode or len(result.stdout) != blob_size:
        raise WorkflowGateError(f"cannot export exact {relative} blob bytes")
    raw = result.stdout
    object_digest = hashlib.sha1(usedforsecurity=False)
    object_digest.update(b"blob " + str(blob_size).encode("ascii") + b"\0")
    object_digest.update(raw)
    if not secrets.compare_digest(object_digest.hexdigest(), object_id):
        raise WorkflowGateError(f"{relative} blob bytes differ from their object id")
    if b"\0" in raw:
        raise WorkflowGateError(f"{relative} contains a NUL byte")
    return raw


def require_canonical_repo(path: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute():
        raise WorkflowGateError("repository path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise WorkflowGateError(f"cannot inspect repository path: {exc}") from exc
    if resolved != path or not stat.S_ISDIR(metadata.st_mode):
        raise WorkflowGateError("repository path must be a canonical real directory")
    return path


def verify_candidate(
    repo: pathlib.Path,
    trusted_commit: str,
    candidate_commit: str,
    *,
    deadline: float | None = None,
    require_unchanged_candidate: bool = False,
) -> tuple[str, tuple[tuple[str, str], ...]]:
    if type(require_unchanged_candidate) is not bool:
        raise WorkflowGateError("candidate relation policy is not canonical")
    if deadline is None:
        deadline = time.monotonic() + VERIFY_TIMEOUT_SECONDS
    elif (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
        or deadline <= time.monotonic()
    ):
        raise WorkflowGateError("workflow verification exceeded its deadline")
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-workflow-gate.") as raw:
        private = pathlib.Path(raw)
        private.chmod(0o700)
        home = private / "home"
        home.mkdir(mode=0o700)
        require_sha1_repository(repo, home, deadline)
        trusted_raw = require_commit(
            repo, home, trusted_commit, "trusted validator commit", deadline
        )
        candidate_raw = require_commit(
            repo, home, candidate_commit, "candidate commit", deadline
        )
        trusted_tree = commit_root_tree(trusted_raw, "trusted validator commit")
        candidate_tree = commit_root_tree(candidate_raw, "candidate commit")
        if require_unchanged_candidate:
            require_direct_unchanged_candidate(
                trusted_raw,
                candidate_raw,
                trusted_commit,
            )
        ancestry = run_git(
            repo,
            home,
            ["merge-base", "--is-ancestor", trusted_commit, candidate_commit],
            deadline=deadline,
        )
        if ancestry.returncode:
            raise WorkflowGateError("trusted validator commit is not a candidate ancestor")

        workflow = export_blob(
            repo,
            home,
            candidate_tree,
            "candidate commit",
            WORKFLOW_PATH,
            REVIEWED_BLOB_MODES[WORKFLOW_PATH],
            MAX_WORKFLOW_BYTES,
            deadline,
        )
        workflow_path = private / "candidate-build.yml"
        workflow_path.write_bytes(workflow)
        workflow_path.chmod(0o600)
        validator_digests: list[tuple[str, str]] = []
        for index, relative in enumerate(VALIDATOR_PATHS):
            validator = export_blob(
                repo,
                home,
                trusted_tree,
                "trusted validator commit",
                relative,
                REVIEWED_BLOB_MODES[relative],
                MAX_VALIDATOR_BYTES,
                deadline,
            )
            validator_path = private / f"validator-{index}.py"
            validator_path.write_bytes(validator)
            validator_path.chmod(0o500)
            validator_digests.append((relative, hashlib.sha256(validator).hexdigest()))
            result = run_bounded_process(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(validator_path),
                    str(workflow_path),
                ],
                input_bytes=None,
                environment=clean_environment(home),
                deadline=deadline,
                stdout_limit=MAX_VALIDATOR_OUTPUT_BYTES,
                stderr_limit=MAX_VALIDATOR_OUTPUT_BYTES,
                label="trusted workflow validator",
            )
            if result.returncode:
                diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
                raise WorkflowGateError(
                    f"trusted validator rejected candidate workflow: {relative}: "
                    f"{diagnostic}"
                )
        return hashlib.sha256(workflow).hexdigest(), tuple(validator_digests)


GhRunner = Callable[[list[str], str | None, float], subprocess.CompletedProcess[str]]


def safe_remote_ref(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and REMOTE_REF.fullmatch(value)
        and ".." not in value
        and "//" not in value
        and "@{" not in value
        and not value.endswith(("/", ".", ".lock"))
        and all(not part.startswith(".") for part in value.split("/"))
    )


def require_repository_and_ref(repository: str, remote_ref: str) -> None:
    if not REPOSITORY.fullmatch(repository):
        raise WorkflowGateError("GitHub repository is not canonical")
    if not safe_remote_ref(remote_ref):
        raise WorkflowGateError("remote workflow ref is not a safe branch name")


def require_gh_result(
    result: object,
    label: str,
) -> subprocess.CompletedProcess[str]:
    if (
        type(result) is not subprocess.CompletedProcess
        or type(result.returncode) is not int
        or type(result.stdout) is not str
        or type(result.stderr) is not str
    ):
        raise WorkflowGateError(f"{label} result is not canonical")
    try:
        stdout_bytes = result.stdout.encode("utf-8")
        stderr_bytes = result.stderr.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WorkflowGateError(f"{label} result is not valid UTF-8") from exc
    if len(stdout_bytes) > MAX_GH_OUTPUT_BYTES:
        raise WorkflowGateError(f"{label} output exceeds its size bound")
    if len(stderr_bytes) > MAX_GH_OUTPUT_BYTES:
        raise WorkflowGateError(f"{label} error output exceeds its size bound")
    return result


def gh_failure_message(
    result: subprocess.CompletedProcess[str],
    label: str,
) -> str:
    diagnostic = result.stderr.strip()
    if not diagnostic:
        return f"{label} failed"
    if len(diagnostic.encode("utf-8")) > MAX_GH_DIAGNOSTIC_BYTES:
        return f"{label} failed with an oversized diagnostic"
    if any(
        ord(character) < 0x20 or ord(character) > 0x7E
        for character in diagnostic
    ):
        return f"{label} failed with a noncanonical diagnostic"
    return f"{label} failed: {diagnostic}"


def require_gh_json_resource_bounds(source: str, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in source:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_GH_JSON_NESTING_DEPTH:
                raise WorkflowGateError(f"{label} returned over-nested JSON")
        elif character in "]}":
            depth = max(0, depth - 1)


def parse_gh_json_integer(source: str) -> int:
    digits = source[1:] if source.startswith("-") else source
    if len(digits) > MAX_GH_JSON_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds the reviewed digit limit")
    return int(source, 10)


def reject_gh_json_number(source: str) -> object:
    del source
    raise ValueError("non-integer JSON numbers are not allowed")


def unique_gh_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def gh_json(
    runner: GhRunner,
    arguments: list[str],
    label: str,
    deadline: float,
    input_text: str | None = None,
) -> object:
    result = require_gh_result(runner(arguments, input_text, deadline), label)
    if result.returncode:
        raise WorkflowGateError(gh_failure_message(result, label))
    require_gh_json_resource_bounds(result.stdout, label)
    try:
        return json.loads(
            result.stdout,
            parse_int=parse_gh_json_integer,
            parse_float=reject_gh_json_number,
            parse_constant=reject_gh_json_number,
            object_pairs_hook=unique_gh_json_object,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise WorkflowGateError(f"{label} returned invalid JSON") from exc


def query_remote_ref(
    runner: GhRunner,
    repository: str,
    remote_ref: str,
    deadline: float,
) -> str:
    encoded_ref = urllib.parse.quote(remote_ref, safe="")
    value = gh_json(
        runner,
        [
            "/usr/bin/gh",
            "api",
            "--method",
            "GET",
            f"repos/{repository}/git/ref/heads/{encoded_ref}",
            "--jq",
            "{object:{sha:.object.sha}}",
        ],
        "remote workflow-ref query",
        deadline,
    )
    if not isinstance(value, dict) or set(value) != {"object"}:
        raise WorkflowGateError("remote workflow-ref response has unexpected fields")
    target = value.get("object")
    if not isinstance(target, dict) or set(target) != {"sha"}:
        raise WorkflowGateError("remote workflow-ref object has unexpected fields")
    sha = target.get("sha")
    if not isinstance(sha, str) or not COMMIT.fullmatch(sha):
        raise WorkflowGateError("remote workflow-ref target is not a full commit id")
    return sha


def require_locked_remote_ref(
    runner: GhRunner,
    repository: str,
    remote_ref: str,
    deadline: float,
) -> None:
    encoded_ref = urllib.parse.quote(remote_ref, safe="")
    value = gh_json(
        runner,
        [
            "/usr/bin/gh",
            "api",
            "--method",
            "GET",
            f"repos/{repository}/branches/{encoded_ref}/protection",
            "--jq",
            (
                "{lockBranch:.lock_branch.enabled,"
                "allowForcePushes:.allow_force_pushes.enabled,"
                "allowDeletions:.allow_deletions.enabled,"
                "allowForkSyncing:(.allow_fork_syncing.enabled // false)}"
            ),
        ],
        "remote dispatch branch protection query",
        deadline,
    )
    if value != {
        "lockBranch": True,
        "allowForcePushes": False,
        "allowDeletions": False,
        "allowForkSyncing": False,
    }:
        raise WorkflowGateError(
            "remote dispatch branch is not locked against updates and deletion"
        )


def list_workflow_runs(
    runner: GhRunner,
    repository: str,
    remote_ref: str,
    candidate_commit: str,
    deadline: float,
) -> tuple[DispatchRecord, ...]:
    value = gh_json(
        runner,
        [
            "/usr/bin/gh",
            "run",
            "list",
            "--repo",
            repository,
            "--workflow",
            "build.yml",
            "--event",
            "workflow_dispatch",
            "--branch",
            remote_ref,
            "--commit",
            candidate_commit,
            "--limit",
            "100",
            "--json",
            "databaseId,displayTitle,headBranch,headSha,event,status,url,workflowName",
        ],
        "workflow-run inventory",
        deadline,
    )
    if not isinstance(value, list) or len(value) > 100:
        raise WorkflowGateError("workflow-run inventory is not a bounded list")
    records: list[DispatchRecord] = []
    seen_ids: set[int] = set()
    expected_keys = {
        "databaseId",
        "displayTitle",
        "headBranch",
        "headSha",
        "event",
        "status",
        "url",
        "workflowName",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise WorkflowGateError("workflow-run record has unexpected fields")
        run_id = item.get("databaseId")
        display_title = item.get("displayTitle")
        head_branch = item.get("headBranch")
        head_sha = item.get("headSha")
        url = item.get("url")
        if (
            not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or run_id <= 0
            or run_id > MAX_GITHUB_DATABASE_ID
            or run_id in seen_ids
            or not isinstance(display_title, str)
            or not 1 <= len(display_title) <= 256
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in display_title)
            or not safe_remote_ref(head_branch)
            or not isinstance(head_sha, str)
            or not COMMIT.fullmatch(head_sha)
            or item.get("event") != "workflow_dispatch"
            or item.get("workflowName") != WORKFLOW_NAME
            or item.get("status")
            not in {"queued", "in_progress", "completed", "requested", "waiting", "pending"}
            or not isinstance(url, str)
            or url != f"https://github.com/{repository}/actions/runs/{run_id}"
        ):
            raise WorkflowGateError("workflow-run record is not canonical")
        seen_ids.add(run_id)
        records.append(
            DispatchRecord(run_id, display_title, head_branch, head_sha, url)
        )
    return tuple(records)


def dispatch_candidate(
    repository: str,
    remote_ref: str,
    candidate_commit: str,
    release_tag: str,
    dispatch_state_path: pathlib.Path,
    gh_runner: GhRunner,
    *,
    evidence: VerificationEvidence,
    deadline: float | None = None,
    dispatch_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    timeout_seconds: float = 120.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> DispatchResult:
    require_repository_and_ref(repository, remote_ref)
    evidence = require_verification_evidence(evidence)
    if evidence.trusted_commit == candidate_commit:
        raise WorkflowGateError("trusted commit must differ from the candidate commit")
    if not COMMIT.fullmatch(candidate_commit):
        raise WorkflowGateError("candidate commit is not a full lowercase commit id")
    if remote_ref != f"codex-dispatch/{candidate_commit}":
        raise WorkflowGateError(
            "remote workflow ref is not the unique candidate dispatch branch"
        )
    expected_tag = f"tb321fu-haptics-debs-{CANONICAL_INPUTS['haptics_deb_version']}"
    if release_tag not in {"", expected_tag}:
        raise WorkflowGateError("release tag differs from the canonical profile")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 300
    ):
        raise WorkflowGateError("dispatch reconciliation timeout is outside its bound")
    started = monotonic()
    if (
        isinstance(started, bool)
        or not isinstance(started, (int, float))
        or not math.isfinite(started)
    ):
        raise WorkflowGateError("dispatch monotonic clock returned an invalid value")
    if deadline is None:
        deadline = started + timeout_seconds
    elif (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
        or deadline <= started
        or deadline - started > GATE_TIMEOUT_SECONDS
    ):
        raise WorkflowGateError("dispatch absolute deadline is outside its bound")
    if query_remote_ref(gh_runner, repository, remote_ref, deadline) != candidate_commit:
        raise WorkflowGateError("remote ref does not target the candidate commit before dispatch")
    require_locked_remote_ref(gh_runner, repository, remote_ref, deadline)
    before = list_workflow_runs(
        gh_runner, repository, remote_ref, candidate_commit, deadline
    )
    if query_remote_ref(gh_runner, repository, remote_ref, deadline) != candidate_commit:
        raise WorkflowGateError(
            "remote ref changed immediately before workflow dispatch"
        )
    require_locked_remote_ref(gh_runner, repository, remote_ref, deadline)
    dispatch_id, should_submit = reserve_dispatch_state(
        dispatch_state_path,
        repository,
        remote_ref,
        candidate_commit,
        release_tag,
        evidence,
        dispatch_id_factory,
    )
    before_ids = {record.run_id for record in before} if should_submit else set()
    inputs = dict(CANONICAL_INPUTS)
    inputs["dispatch_id"] = dispatch_id
    inputs["release_tag"] = release_tag
    dispatch_error = ""
    if should_submit:
        dispatch = require_gh_result(
            gh_runner(
            [
                "/usr/bin/gh",
                "workflow",
                "run",
                "build.yml",
                "--repo",
                repository,
                "--ref",
                remote_ref,
                "--json",
            ],
            json.dumps(inputs, sort_keys=True, separators=(",", ":")),
            deadline,
            ),
            "workflow dispatch",
        )
        dispatch_error = (
            gh_failure_message(dispatch, "workflow dispatch")
            if dispatch.returncode
            else ""
        )

    selected: DispatchRecord | None = None
    while selected is None:
        current = list_workflow_runs(
            gh_runner, repository, remote_ref, candidate_commit, deadline
        )
        candidate_runs = [
            record
            for record in current
            if record.run_id not in before_ids and record.head_sha == candidate_commit
        ]
        if any(record.head_branch != remote_ref for record in candidate_runs):
            raise WorkflowGateError(
                "workflow dispatch produced a run on an unexpected branch"
            )
        matching = [
            record
            for record in candidate_runs
            if record.head_branch == remote_ref
            and record.display_title == f"haptics-dispatch-{dispatch_id}"
        ]
        if len(matching) > 1:
            raise WorkflowGateError("workflow dispatch produced an ambiguous run set")
        if matching:
            selected = matching[0]
            break
        current_time = monotonic()
        if (
            isinstance(current_time, bool)
            or not isinstance(current_time, (int, float))
            or not math.isfinite(current_time)
        ):
            raise WorkflowGateError("dispatch monotonic clock returned an invalid value")
        if current_time >= deadline:
            if dispatch_error:
                raise WorkflowGateError(
                    "workflow dispatch failed and no applied run appeared: "
                    f"{dispatch_error}"
                )
            raise WorkflowGateError("workflow dispatch run did not appear before the timeout")
        sleeper(min(2.0, deadline - current_time))
    if query_remote_ref(gh_runner, repository, remote_ref, deadline) != candidate_commit:
        raise WorkflowGateError("remote ref changed during workflow dispatch")
    require_locked_remote_ref(gh_runner, repository, remote_ref, deadline)
    state_raw = serialize_dispatch_state(
        repository,
        remote_ref,
        candidate_commit,
        release_tag,
        dispatch_id,
        evidence,
    )
    return DispatchResult(
        selected,
        dispatch_id,
        dispatch_input_digest(release_tag, dispatch_id),
        hashlib.sha256(state_raw).hexdigest(),
        VALIDATOR_MODE,
    )


def operator_environment(home: pathlib.Path) -> dict[str, str]:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(home),
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
    }
    for name in ("http_proxy", "https_proxy", "no_proxy"):
        value = os.environ.get(name, "")
        if value and len(value) <= 2048 and "\n" not in value and "\r" not in value:
            environment[name] = value
    return environment


def real_gh_runner(home: pathlib.Path) -> GhRunner:
    environment = operator_environment(home)

    def invoke(
        arguments: list[str], input_text: str | None, deadline: float
    ) -> subprocess.CompletedProcess[str]:
        if not arguments or arguments[0] != "/usr/bin/gh":
            return subprocess.CompletedProcess(
                arguments, 126, "", "workflow gate refused a noncanonical gh path"
            )
        try:
            encoded_input = input_text.encode("utf-8") if input_text is not None else None
        except UnicodeEncodeError:
            return subprocess.CompletedProcess(
                arguments,
                65,
                "",
                "workflow gate refused non-UTF-8 gh input",
            )
        result = run_bounded_process(
            arguments,
            input_bytes=encoded_input,
            environment=environment,
            deadline=deadline,
            stdout_limit=MAX_GH_OUTPUT_BYTES,
            stderr_limit=MAX_GH_OUTPUT_BYTES,
            label="GitHub CLI command",
        )
        try:
            stdout = result.stdout.decode("utf-8")
            stderr = result.stderr.decode("utf-8")
        except UnicodeDecodeError:
            return subprocess.CompletedProcess(
                arguments,
                65,
                "",
                "workflow gate received non-UTF-8 gh output",
            )
        return subprocess.CompletedProcess(arguments, result.returncode, stdout, stderr)

    return invoke


def format_gate_failure(exc: BaseException) -> str:
    lines = [f"haptics workflow gate failed: {exc}"]
    notes = getattr(exc, "__notes__", ())
    for note in dict.fromkeys(notes):
        if type(note) is not str or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}", note
        ):
            rendered = "noncanonical cleanup evidence omitted"
        else:
            rendered = note
        lines.append(f"haptics workflow gate cleanup: {rendered}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--dispatch", action="store_true")
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--repository")
    parser.add_argument("--remote-ref")
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--dispatch-state")
    try:
        arguments = parser.parse_args()
        if arguments.verify_only == arguments.dispatch:
            raise WorkflowGateError("select exactly one of --verify-only or --dispatch")
        if arguments.dispatch and arguments.dispatch_state is None:
            raise WorkflowGateError("remote dispatch requires a private dispatch state path")
        if arguments.verify_only and arguments.dispatch_state is not None:
            raise WorkflowGateError("verify-only mode does not accept a dispatch state path")
        dispatch_state_path = (
            require_dispatch_state_path(pathlib.Path(arguments.dispatch_state))
            if arguments.dispatch
            else None
        )
        operator_home: pathlib.PosixPath | None = None
        if arguments.dispatch:
            operator_home = require_operator_home()
            expected_state_path = canonical_dispatch_state_path(
                operator_home,
                arguments.candidate_commit,
                arguments.release_tag,
            )
            if dispatch_state_path != expected_state_path:
                raise WorkflowGateError(
                    "workflow dispatch state path is not the unique candidate ledger"
                )
            require_dispatch_state_ancestry(
                operator_home,
                dispatch_state_path.parent,
            )
        gate_started = time.monotonic()
        if not math.isfinite(gate_started):
            raise WorkflowGateError("workflow gate monotonic clock returned an invalid value")
        external_deadline_text = os.environ.get("HAPTICS_WORKFLOW_DEADLINE_NS")
        descriptor_execution = re.fullmatch(
            r"/proc/self/fd/[1-9][0-9]*", __file__
        ) is not None
        if descriptor_execution and external_deadline_text is None:
            raise WorkflowGateError(
                "descriptor-executed gate requires the bootstrap deadline"
            )
        if external_deadline_text is None:
            gate_deadline = gate_started + GATE_TIMEOUT_SECONDS
        else:
            if re.fullmatch(r"[1-9][0-9]{0,18}", external_deadline_text) is None:
                raise WorkflowGateError("bootstrap deadline is not canonical")
            gate_deadline = int(external_deadline_text, 10) / 1_000_000_000
            if (
                not math.isfinite(gate_deadline)
                or gate_deadline <= gate_started
                or gate_deadline - gate_started > GATE_TIMEOUT_SECONDS
            ):
                raise WorkflowGateError("bootstrap deadline is outside gate policy")
        repo = require_canonical_repo(pathlib.Path(arguments.repo_dir))
        expected_gate_digest = os.environ.get("HAPTICS_TRUSTED_GATE_SHA256")
        if not arguments.dispatch and not descriptor_execution:
            expected_gate_digest = None
        if arguments.dispatch and expected_gate_digest is None:
            raise WorkflowGateError(
                "remote dispatch requires HAPTICS_TRUSTED_GATE_SHA256"
            )
        gate_digest = attest_running_gate(expected_gate_digest)
        workflow_digest, validator_digests = verify_candidate(
            repo,
            arguments.trusted_commit,
            arguments.candidate_commit,
            deadline=gate_deadline,
            require_unchanged_candidate=arguments.dispatch,
        )
        dispatch_result: DispatchResult | None = None
        if arguments.dispatch:
            if os.environ.get("GH_ALLOW_DISPATCH") != "1":
                raise WorkflowGateError("remote dispatch requires GH_ALLOW_DISPATCH=1")
            if arguments.repository is None or arguments.remote_ref is None:
                raise WorkflowGateError("remote dispatch requires repository and branch ref")
            if operator_home is None:
                raise WorkflowGateError("workflow dispatch operator home is unavailable")
            evidence = VerificationEvidence(
                arguments.trusted_commit,
                gate_digest,
                workflow_digest,
                tuple(
                    (relative, REVIEWED_BLOB_MODES[relative], digest)
                    for relative, digest in validator_digests
                ),
            )
            dispatch_result = dispatch_candidate(
                arguments.repository,
                arguments.remote_ref,
                arguments.candidate_commit,
                arguments.release_tag,
                dispatch_state_path,
                real_gh_runner(operator_home),
                evidence=evidence,
                deadline=gate_deadline,
            )
    except (OSError, WorkflowGateError) as exc:
        raise SystemExit(format_gate_failure(exc)) from exc
    print("schema\ttb321fu.haptics-workflow-gate/v1")
    print(f"trusted-commit\t{arguments.trusted_commit}")
    print(f"candidate-commit\t{arguments.candidate_commit}")
    print(f"gate-sha256\t{gate_digest}")
    print(f"workflow-sha256\t{workflow_digest}")
    for relative, digest in validator_digests:
        print(f"validator-sha256\t{relative}\t{digest}")
    validator_mode = (
        VALIDATOR_MODE
        if dispatch_result is None
        else dispatch_result.validator_mode
    )
    print(f"validator-mode\t{validator_mode}")
    if dispatch_result is None:
        print("HAPTICS_WORKFLOW_GATE_VERIFY=PASS")
    else:
        dispatch_record = dispatch_result.record
        print(f"repository\t{arguments.repository}")
        print(f"remote-ref\t{arguments.remote_ref}")
        print(f"release-tag\t{arguments.release_tag or '-'}")
        print(f"run-id\t{dispatch_record.run_id}")
        print(f"run-display-title\t{dispatch_record.display_title}")
        print(f"run-head-branch\t{dispatch_record.head_branch}")
        print(f"run-head-sha\t{dispatch_record.head_sha}")
        print(f"run-url\t{dispatch_record.url}")
        print(f"dispatch-id\t{dispatch_result.dispatch_id}")
        print(f"input-sha256\t{dispatch_result.input_sha256}")
        print(f"dispatch-state-sha256\t{dispatch_result.state_sha256}")
        print("HAPTICS_WORKFLOW_DISPATCH=PASS")


if __name__ == "__main__":
    main()
