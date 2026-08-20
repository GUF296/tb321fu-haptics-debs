#!/usr/bin/env python3
"""Verify the exact APT EIPP v3 transaction immediately before dpkg."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import argparse
import errno
import hashlib
import hmac
import importlib.util
import math
import os
import pathlib
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time


MAX_EIPP_BYTES = 4 * 1024 * 1024
EIPP_READ_TIMEOUT_SECONDS = 30.0
PREPARATION_TIMEOUT_SECONDS = 300.0
HOOK_VERIFICATION_TIMEOUT_SECONDS = 300.0
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
ARCHITECTURE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+:~\-]{0,254}")
EIPP_MULTIARCH = {"same", "foreign", "allowed", "none"}
DEBIAN_MULTIARCH = {"same", "foreign", "allowed", "no"}
HEX_BYTE = re.compile(r"[0-9A-Fa-f]{2}")
SHA256 = re.compile(r"[0-9a-f]{64}")
EXPECTED_HOST_REFERENCE_SHA256 = (
    "59b743bc1fc980f06f86dab9f122255b55b09010c844e32e44342d5bd87e3823"
)
UNSIGNED = re.compile(r"0|[1-9][0-9]{0,19}")
CONTROL_FIELD_NAME = re.compile(r"(?!#)[\x21-\x39\x3b-\x7e]+")
HOOK_PATH_COMPONENT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,254}")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_CONTROL_BYTES = 64 * 1024
MAX_CONTROL_STDERR_BYTES = 8192
CONTROL_QUERY_TIMEOUT_SECONDS = 30.0
COMMAND_TERM_GRACE_SECONDS = 0.25
COMMAND_CLEANUP_SECONDS = 1.0
APT_READABLE_TIMEOUT_SECONDS = 30.0
CHILD_CLEANUP_SECONDS = 1.0
MAX_TRANSACTION_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PRIVATE_PATH_BYTES = 4096
MAX_ARCHIVE_COUNT = 512
MAX_PACKAGE_LOCK_BYTES = 32768
MAX_PACKAGE_STATE_BYTES = 16 * 1024 * 1024
MAX_HOST_PLAN_BYTES = 4 * 1024 * 1024
MAX_DPKG_STATE_BYTES = 32 * 1024 * 1024
FORK_CANCELLATION_SIGNALS = frozenset((signal.SIGINT, signal.SIGTERM))
MAX_FD_SNAPSHOT_ENTRIES = 4096


class AptTransactionError(ValueError):
    pass


def choose_cleanup_failure(
    current: BaseException | None,
    new: BaseException,
    note: str,
) -> BaseException:
    if current is None:
        return new

    def priority(failure: BaseException) -> int:
        if isinstance(failure, KeyboardInterrupt):
            return 2
        if not isinstance(failure, Exception):
            return 1
        return 0

    if priority(new) > priority(current):
        new.add_note(note)
        if new.__cause__ is None and isinstance(current, Exception):
            new.__cause__ = current
        return new
    if new is not current:
        current.add_note(note)
    return current


def fixed_cleanup_candidate(exc: BaseException, message: str) -> BaseException:
    if not isinstance(exc, Exception):
        return exc
    failure = AptTransactionError(message)
    failure.__cause__ = exc
    return failure


def close_owned_descriptor(
    descriptor: int,
    label: str,
) -> tuple[BaseException | None, bool]:
    failure: BaseException | None = None
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(exc, f"cannot close {label} descriptor"),
                f"{label} descriptor close also failed",
            )
        try:
            os.fstat(descriptor)
        except OSError as probe:
            if probe.errno == errno.EBADF:
                return failure, True
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(
                    probe,
                    f"cannot determine {label} descriptor custody",
                ),
                f"{label} descriptor custody inspection also failed",
            )
        except BaseException as probe:
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(
                    probe,
                    f"cannot determine {label} descriptor custody",
                ),
                f"{label} descriptor custody inspection also failed",
            )
    failure = choose_cleanup_failure(
        failure,
        AptTransactionError(f"{label} descriptor close did not converge"),
        f"{label} descriptor cleanup also did not converge",
    )
    return failure, False


def snapshot_descriptor_numbers(label: str) -> frozenset[int]:
    descriptors: set[int] = set()
    try:
        with os.scandir("/proc/self/fd") as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_FD_SNAPSHOT_ENTRIES:
                    raise AptTransactionError(
                        f"{label} descriptor snapshot exceeds its entry bound"
                    )
                if not entry.name.isascii() or not entry.name.isdecimal():
                    raise AptTransactionError(
                        f"{label} descriptor snapshot is malformed"
                    )
                descriptor = int(entry.name, 10)
                if str(descriptor) != entry.name:
                    raise AptTransactionError(
                        f"{label} descriptor snapshot is not canonical"
                    )
                descriptors.add(descriptor)
    except AptTransactionError:
        raise
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise AptTransactionError(f"cannot enumerate {label} descriptors") from exc
    return frozenset(descriptors)


def snapshot_live_descriptors(label: str) -> frozenset[int]:
    live: set[int] = set()
    for descriptor in snapshot_descriptor_numbers(label):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise AptTransactionError(
                f"cannot inspect {label} descriptor snapshot"
            ) from exc
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            raise AptTransactionError(
                f"cannot inspect {label} descriptor snapshot"
            ) from exc
        live.add(descriptor)
    return frozenset(live)


def duplicate_owned_descriptor(source: int, label: str) -> int:
    before = snapshot_live_descriptors(label)
    try:
        source_state = os.fstat(source)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise AptTransactionError(f"cannot inspect {label} source descriptor") from exc
    source_identity = (
        source_state.st_dev,
        source_state.st_ino,
        source_state.st_mode,
        source_state.st_rdev,
    )
    try:
        duplicated = os.dup(source)
    except BaseException as exc:
        primary = fixed_cleanup_candidate(exc, f"cannot duplicate {label} descriptor")
        try:
            after = snapshot_descriptor_numbers(label)
        except BaseException as snapshot_exc:
            primary = choose_cleanup_failure(
                primary,
                fixed_cleanup_candidate(
                    snapshot_exc,
                    f"cannot recover applied {label} descriptor duplication",
                ),
                f"{label} applied-duplication recovery also failed",
            )
        else:
            for candidate in sorted(after - before):
                candidate_is_closed = False
                try:
                    candidate_state = os.fstat(candidate)
                except OSError as candidate_exc:
                    if candidate_exc.errno == errno.EBADF:
                        candidate_is_closed = True
                    else:
                        primary = choose_cleanup_failure(
                            primary,
                            fixed_cleanup_candidate(
                                candidate_exc,
                                f"cannot inspect applied {label} descriptor duplication",
                            ),
                            f"{label} applied-duplication inspection also failed",
                        )
                except BaseException as candidate_exc:
                    primary = choose_cleanup_failure(
                        primary,
                        fixed_cleanup_candidate(
                            candidate_exc,
                            f"cannot inspect applied {label} descriptor duplication",
                        ),
                        f"{label} applied-duplication inspection also failed",
                    )
                else:
                    candidate_identity = (
                        candidate_state.st_dev,
                        candidate_state.st_ino,
                        candidate_state.st_mode,
                        candidate_state.st_rdev,
                    )
                    if candidate_identity != source_identity:
                        primary = choose_cleanup_failure(
                            primary,
                            AptTransactionError(
                                f"unexpected descriptor appeared while recovering "
                                f"applied {label} duplication"
                            ),
                            f"{label} applied-duplication identity also changed",
                        )
                if candidate_is_closed:
                    continue
                close_failure, _ = close_owned_descriptor(
                    candidate,
                    f"applied {label} duplicate",
                )
                if close_failure is not None:
                    primary = choose_cleanup_failure(
                        primary,
                        close_failure,
                        f"applied {label} duplicate cleanup also failed",
                    )
        raise primary
    try:
        duplicated_state = os.fstat(duplicated)
        if (
            duplicated in before
            or (
                duplicated_state.st_dev,
                duplicated_state.st_ino,
                duplicated_state.st_mode,
                duplicated_state.st_rdev,
            )
            != source_identity
            or os.get_inheritable(duplicated)
        ):
            raise AptTransactionError(f"{label} duplicate descriptor changed")
    except BaseException as exc:
        primary = fixed_cleanup_candidate(
            exc,
            f"cannot verify {label} duplicate descriptor",
        )
        close_failure, _ = close_owned_descriptor(
            duplicated,
            f"invalid {label} duplicate",
        )
        if close_failure is not None:
            primary = choose_cleanup_failure(
                primary,
                close_failure,
                f"invalid {label} duplicate cleanup also failed",
            )
        raise primary
    return duplicated


def open_owned_directory(
    path: pathlib.Path,
    expected_identity: tuple[int, ...],
    label: str,
) -> int:
    before = snapshot_live_descriptors(label)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except BaseException as exc:
        primary = fixed_cleanup_candidate(exc, f"cannot open {label}")
        try:
            after = snapshot_live_descriptors(label)
        except BaseException as snapshot_exc:
            primary = choose_cleanup_failure(
                primary,
                fixed_cleanup_candidate(
                    snapshot_exc,
                    f"cannot recover applied {label} open",
                ),
                f"{label} applied-open recovery also failed",
            )
        else:
            for candidate in sorted(after - before):
                try:
                    candidate_identity = private_file_identity(os.fstat(candidate))
                except BaseException as candidate_exc:
                    primary = choose_cleanup_failure(
                        primary,
                        fixed_cleanup_candidate(
                            candidate_exc,
                            f"cannot inspect applied {label} open",
                        ),
                        f"{label} applied-open inspection also failed",
                    )
                    continue
                if candidate_identity != expected_identity:
                    continue
                close_failure, _ = close_owned_descriptor(
                    candidate,
                    f"applied {label}",
                )
                if close_failure is not None:
                    primary = choose_cleanup_failure(
                        primary,
                        close_failure,
                        f"applied {label} cleanup also failed",
                    )
        raise primary
    try:
        if (
            descriptor in before
            or private_file_identity(os.fstat(descriptor)) != expected_identity
            or private_file_identity(os.stat(path, follow_symlinks=False))
            != expected_identity
            or os.get_inheritable(descriptor)
        ):
            raise AptTransactionError(f"{label} directory identity changed")
    except BaseException as exc:
        primary = fixed_cleanup_candidate(exc, f"cannot verify {label}")
        close_failure, _ = close_owned_descriptor(
            descriptor,
            f"invalid {label}",
        )
        if close_failure is not None:
            primary = choose_cleanup_failure(
                primary,
                close_failure,
                f"invalid {label} cleanup also failed",
            )
        raise primary
    return descriptor


def close_descriptors(
    descriptors: tuple[int, ...],
    label: str,
    primary_exception: BaseException | None,
) -> None:
    if (
        type(descriptors) is not tuple
        or any(type(descriptor) is not int or descriptor < 0 for descriptor in descriptors)
        or len(set(descriptors)) != len(descriptors)
        or type(label) is not str
        or not label
        or (
            primary_exception is not None
            and not isinstance(primary_exception, BaseException)
        )
    ):
        raise AptTransactionError("descriptor cleanup inputs are invalid")
    selected = primary_exception
    for descriptor in descriptors:
        failure, _ = close_owned_descriptor(descriptor, label)
        if failure is None:
            continue
        reported = (
            failure.__cause__
            if isinstance(failure, AptTransactionError)
            and isinstance(failure.__cause__, BaseException)
            else failure
        )
        note = (
            f"{label} cleanup failed for descriptor {descriptor}: "
            f"{type(reported).__name__}: {reported}"
        )
        if selected is None and isinstance(failure, Exception):
            selected = AptTransactionError(f"cannot close {label} descriptors")
            selected.__cause__ = failure
            selected.add_note(note)
            continue
        selected = choose_cleanup_failure(
            selected,
            failure,
            note,
        )
    if selected is not None and selected is not primary_exception:
        raise selected


def require_operation_deadline(deadline: float, label: str) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise AptTransactionError(f"{label} deadline is invalid")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AptTransactionError(f"{label} exceeded its deadline")
    return remaining


def verify_host_reference_trust_anchor(raw: bytes) -> None:
    if type(raw) is not bytes or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(), EXPECTED_HOST_REFERENCE_SHA256
    ):
        raise AptTransactionError(
            "dpkg host reference differs from the committed trust anchor"
        )


@dataclass(frozen=True)
class PackageAction:
    package: str
    old_version: str | None
    old_architecture: str | None
    old_multiarch: str | None
    direction: str
    new_version: str | None
    new_architecture: str | None
    new_multiarch: str | None
    action: str


@dataclass(frozen=True)
class PlannedChange:
    package: str
    architecture: str
    old_version: str | None
    new_version: str


@dataclass(frozen=True)
class EippDocument:
    configuration: tuple[tuple[str, str], ...]
    actions: tuple[PackageAction, ...]


@dataclass(frozen=True)
class ArchiveRecord:
    path: str
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    sha256: str
    package: str
    version: str
    architecture: str
    multiarch: str


def action_sort_key(action: PackageAction) -> tuple[str, ...]:
    return (
        action.package,
        action.new_architecture or "-",
        action.new_version or "-",
        "1" if action.action == "**CONFIGURE**" else "0",
        action.action,
        action.old_architecture or "-",
        action.old_version or "-",
    )


@dataclass(frozen=True)
class ExpectedTransaction:
    package_state_sha256: str
    dpkg_state_sha256: str
    host_reference_sha256: str
    configuration: tuple[tuple[str, str], ...]
    actions: tuple[PackageAction, ...]
    archives: tuple[ArchiveRecord, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "configuration", tuple(sorted(self.configuration)))
        object.__setattr__(self, "actions", tuple(sorted(self.actions, key=action_sort_key)))
        object.__setattr__(self, "archives", tuple(sorted(self.archives, key=lambda item: item.path)))


@dataclass(frozen=True)
class PublishedFileOwnership:
    descriptor: int
    device: int
    inode: int
    parent_descriptor: int | None


@dataclass
class PublicationOwnershipSlot:
    """Caller-owned handoff slot established before publication starts."""

    ownership: PublishedFileOwnership | None = None

    def accept(self, ownership: PublishedFileOwnership) -> None:
        if (
            type(ownership) is not PublishedFileOwnership
            or self.ownership is not None
        ):
            raise AptTransactionError("publication ownership handoff is invalid")
        self.ownership = ownership


def canonical_hook_path(value: str) -> pathlib.PurePosixPath:
    if type(value) is not str or len(value.encode("ascii", errors="ignore")) != len(value):
        raise AptTransactionError("APT hook command is not canonical")
    path = pathlib.PurePosixPath(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or len(value.encode("ascii")) > MAX_PRIVATE_PATH_BYTES
        or len(path.parts) < 2
        or path.parts[0] != "/"
        or any(
            component in {"", ".", ".."}
            or HOOK_PATH_COMPONENT.fullmatch(component) is None
            for component in path.parts[1:]
        )
    ):
        raise AptTransactionError("APT hook command is not canonical")
    return path


def expected_hook_configuration(command: str) -> tuple[tuple[str, str], ...]:
    if type(command) is not str or len(command) > 3 * MAX_PRIVATE_PATH_BYTES:
        raise AptTransactionError("APT hook command is not canonical")
    fields = command.split(" ")
    if len(fields) != 7 or fields[:3] != ["/usr/bin/python3", "-I", "-B"]:
        raise AptTransactionError("APT hook command is not canonical")
    script = canonical_hook_path(fields[3])
    if fields[4] != "--verify-hook":
        raise AptTransactionError("APT hook command is not canonical")
    manifest = canonical_hook_path(fields[5])
    marker = canonical_hook_path(fields[6])
    if (
        script.name != "verify-haptics-apt-transaction.py"
        or manifest == marker
        or manifest.parent != marker.parent
    ):
        raise AptTransactionError("APT hook command is not canonical")
    return tuple(
        sorted(
            (
                ("APT::Architecture", "amd64"),
                ("APT::Architectures::", "amd64"),
                ("Dir::Bin::dpkg", "/usr/bin/dpkg"),
                ("DPkg::ConfigurePending", "1"),
                ("DPkg::Path", "/usr/sbin:/usr/bin:/sbin:/bin"),
                ("DPkg::Pre-Install-Pkgs::", command),
                ("DPkg::Run-Directory", "/"),
                (f"DPkg::Tools::options::{command}::InfoFD", "21"),
                (f"DPkg::Tools::options::{command}::Version", "3"),
            )
        )
    )


def decode_eipp_component(value: str, label: str, *, key: bool) -> str:
    source = value.encode("ascii")
    decoded = bytearray()
    position = 0
    while position < len(source):
        byte = source[position]
        if byte == ord("%"):
            if position + 2 >= len(source):
                raise AptTransactionError(f"{label} contains a truncated escape")
            encoded = source[position + 1 : position + 3].decode("ascii")
            if not HEX_BYTE.fullmatch(encoded):
                raise AptTransactionError(f"{label} contains an invalid escape")
            byte = int(encoded, 16)
            must_encode = (
                byte < 0x20
                or byte >= 0x7F
                or byte == ord("%")
                or byte == ord(" ")
                or (key and byte in {ord('"'), ord("=")})
            )
            if not must_encode:
                raise AptTransactionError(f"{label} contains an unnecessary escape")
            decoded.append(byte)
            position += 3
            continue
        if (
            byte < 0x20
            or byte >= 0x7F
            or byte == ord(" ")
            or (key and byte == ord('"'))
        ):
            raise AptTransactionError(f"{label} contains an unescaped special byte")
        decoded.append(byte)
        position += 1
    if not decoded or 0 in decoded:
        raise AptTransactionError(f"{label} is empty or contains NUL")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AptTransactionError(f"{label} is not valid UTF-8") from exc


def parse_version_identity(
    version: str,
    architecture: str,
    multiarch: str,
    label: str,
) -> tuple[str | None, str | None, str | None]:
    if version == "-":
        if architecture != "-" or multiarch != "none":
            raise AptTransactionError(f"missing {label} version has metadata")
        return None, None, None
    if (
        not VERSION.fullmatch(version)
        or not ARCHITECTURE.fullmatch(architecture)
        or multiarch not in EIPP_MULTIARCH
    ):
        raise AptTransactionError(f"invalid {label} package identity")
    return version, architecture, "no" if multiarch == "none" else multiarch


def validate_archive_path(value: str) -> str:
    components = value.split("/")
    if (
        len(value) > 4096
        or not value.startswith("/")
        or not value.endswith(".deb")
        or components[0] != ""
        or len(components) < 3
        or any(component in {"", ".", ".."} for component in components[1:])
    ):
        raise AptTransactionError("EIPP archive path is not canonical")
    return value


def _bounded_command(
    args: list[str],
    label: str,
    *,
    env: dict[str, str],
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    pass_fds: tuple[int, ...] = (),
) -> tuple[int, bytes, bytes]:
    if (
        type(args) is not list
        or not args
        or any(type(value) is not str or not value for value in args)
        or type(label) is not str
        or not label
        or type(env) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in env.items())
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or type(max_stdout) is not int
        or max_stdout < 0
        or type(max_stderr) is not int
        or max_stderr < 0
        or type(pass_fds) is not tuple
        or any(type(descriptor) is not int or descriptor < 0 for descriptor in pass_fds)
        or len(set(pass_fds)) != len(pass_fds)
    ):
        raise AptTransactionError("bounded command received invalid runtime inputs")
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
        close_fds=True,
        pass_fds=pass_fds,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    streams = {
        process.stdout.fileno(): (process.stdout, stdout, max_stdout, "stdout"),
        process.stderr.fileno(): (process.stderr, stderr, max_stderr, "stderr"),
    }
    all_streams = (process.stdout, process.stderr)
    deadline = time.monotonic() + timeout
    leader_reaped_early = False

    def leader_exited_without_reaping() -> bool:
        nonlocal leader_reaped_early
        try:
            result = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            leader_reaped_early = True
            return True
        return result is not None and result.si_pid == process.pid

    def signal_group(signum: int) -> None:
        if leader_reaped_early:
            return
        try:
            os.killpg(process.pid, signum)
        except (ProcessLookupError, PermissionError):
            pass

    def wait_for_leader_exit(limit: float) -> bool:
        while not leader_exited_without_reaping():
            remaining = limit - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))
        return True

    def terminate_group(*, normal_completion: bool) -> None:
        cleanup_deadline = time.monotonic() + COMMAND_CLEANUP_SECONDS
        leader_exited_without_reaping()
        if leader_reaped_early:
            raise AptTransactionError(f"cannot retain {label} process ownership")
        if normal_completion:
            signal_group(signal.SIGKILL)
        else:
            signal_group(signal.SIGTERM)
            term_deadline = min(
                cleanup_deadline,
                time.monotonic() + COMMAND_TERM_GRACE_SECONDS,
            )
            wait_for_leader_exit(term_deadline)
            signal_group(signal.SIGKILL)
        remaining = max(0.0, cleanup_deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise AptTransactionError(f"cannot terminate {label}")
        except ChildProcessError as exc:
            raise AptTransactionError(f"cannot retain {label} process ownership") from exc

    completed = False
    try:
        while streams:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            ready, _, _ = select.select(tuple(streams), (), (), remaining_time)
            if not ready:
                raise subprocess.TimeoutExpired(args, timeout)
            for descriptor in ready:
                stream, output, maximum, stream_name = streams[descriptor]
                remaining_output = maximum - len(output)
                chunk = os.read(descriptor, min(65536, remaining_output + 1))
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                output.extend(chunk)
                if len(output) > maximum:
                    raise AptTransactionError(
                        f"{label} {stream_name} exceeds its size bound"
                    )
        if not wait_for_leader_exit(deadline):
            raise subprocess.TimeoutExpired(args, timeout)
        completed = True
    except BaseException as exc:
        try:
            terminate_group(normal_completion=False)
        except BaseException as cleanup_exc:
            exc.add_note(
                "bounded command cleanup failed: "
                f"{type(cleanup_exc).__name__}: {cleanup_exc}"
            )
        raise
    finally:
        try:
            if completed:
                terminate_group(normal_completion=True)
        finally:
            for stream in all_streams:
                if not stream.closed:
                    stream.close()
    assert process.returncode is not None
    return process.returncode, bytes(stdout), bytes(stderr)


def archive_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def hash_archive_descriptor(
    descriptor: int,
    expected_uid: int,
    expected_gid: int,
    *,
    deadline: float | None = None,
) -> tuple[tuple[int, ...], str]:
    if type(descriptor) is not int or descriptor < 0:
        raise AptTransactionError("APT archive descriptor is invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o644
        or before.st_uid != expected_uid
        or before.st_gid != expected_gid
        or before.st_nlink != 1
        or before.st_size > MAX_ARCHIVE_BYTES
    ):
        raise AptTransactionError("APT archive metadata differs from policy")
    digest = hashlib.sha256()
    remaining = MAX_ARCHIVE_BYTES + 1
    size = 0
    while remaining:
        if deadline is not None:
            require_operation_deadline(deadline, "APT archive hashing")
        chunk = os.read(descriptor, min(remaining, 65536))
        if not chunk:
            break
        remaining -= len(chunk)
        size += len(chunk)
        digest.update(chunk)
    after = os.fstat(descriptor)
    identity = archive_file_identity(before)
    if archive_file_identity(after) != identity or size != before.st_size:
        raise AptTransactionError("APT archive changed while it was hashed")
    return identity, digest.hexdigest()


def open_archive_descriptor(path: pathlib.Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise AptTransactionError(f"cannot open APT archive: {exc}") from exc


def parse_control_fields(raw: bytes) -> tuple[str, str, str, str]:
    if not raw or len(raw) > MAX_CONTROL_BYTES or not raw.endswith(b"\n"):
        raise AptTransactionError("DEB control output has invalid size or framing")
    if (
        b"\r" in raw
        or b"\0" in raw
        or any(byte < 0x20 and byte not in {0x09, 0x0A} for byte in raw)
        or b"\x7f" in raw
    ):
        raise AptTransactionError("DEB control output has invalid framing")
    try:
        lines = raw.decode("utf-8")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise AptTransactionError("DEB control output is not UTF-8") from exc
    fields: dict[str, str] = {}
    current: str | None = None
    simple_fields = {"package", "version", "architecture", "multi-arch"}
    for line in lines:
        if line.startswith((" ", "\t")):
            if current is None:
                raise AptTransactionError("DEB control has an orphan continuation")
            if current in simple_fields:
                raise AptTransactionError(
                    "DEB control simple identity field must not be folded"
                )
            continue
        name, found, value = line.partition(": ")
        canonical_name = name.lower()
        if (
            not found
            or CONTROL_FIELD_NAME.fullmatch(name) is None
            or canonical_name in fields
        ):
            raise AptTransactionError("DEB control contains a malformed field")
        if canonical_name not in simple_fields:
            raise AptTransactionError("DEB control contains an unexpected field set")
        fields[canonical_name] = value
        current = canonical_name
    if tuple(fields) not in (
        ("package", "version", "architecture"),
        ("package", "version", "architecture", "multi-arch"),
    ):
        raise AptTransactionError("DEB control contains an unexpected field set")
    try:
        package = fields["package"]
        version = fields["version"]
        architecture = fields["architecture"]
    except KeyError as exc:
        raise AptTransactionError("DEB control lacks package identity") from exc
    multiarch = fields.get("multi-arch", "no")
    if (
        not PACKAGE_NAME.fullmatch(package)
        or not VERSION.fullmatch(version)
        or not ARCHITECTURE.fullmatch(architecture)
        or multiarch not in DEBIAN_MULTIARCH
    ):
        raise AptTransactionError("DEB control package identity is unsafe")
    return package, version, architecture, multiarch


def capture_deb_archive(
    path: pathlib.Path,
    expected_uid: int,
    expected_gid: int,
    *,
    deadline: float | None = None,
) -> ArchiveRecord:
    if not path.is_absolute():
        raise AptTransactionError("APT archive path is not absolute")
    validate_archive_path(str(path))
    descriptor = open_archive_descriptor(path)
    try:
        before_identity, before_digest = hash_archive_descriptor(
            descriptor,
            expected_uid,
            expected_gid,
            deadline=deadline,
        )
        control_path = f"/proc/self/fd/{descriptor}"
        query_timeout = CONTROL_QUERY_TIMEOUT_SECONDS
        if deadline is not None:
            query_timeout = min(
                query_timeout,
                require_operation_deadline(deadline, "APT archive capture"),
            )
        try:
            returncode, control_stdout, control_stderr = _bounded_command(
                [
                    "/usr/bin/dpkg-deb",
                    "-f",
                    control_path,
                    "Package",
                    "Version",
                    "Architecture",
                    "Multi-Arch",
                ],
                "dpkg-deb control query",
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": "/nonexistent",
                },
                timeout=query_timeout,
                max_stdout=MAX_CONTROL_BYTES,
                max_stderr=MAX_CONTROL_STDERR_BYTES,
                pass_fds=(descriptor,),
            )
        except subprocess.TimeoutExpired as exc:
            raise AptTransactionError("dpkg-deb control query timed out") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise AptTransactionError("dpkg-deb control query failed") from exc
        if returncode:
            error = control_stderr[:4096].decode(
                "utf-8", errors="replace"
            ).strip()
            raise AptTransactionError(f"dpkg-deb rejected APT archive: {error}")
        package, version, architecture, multiarch = parse_control_fields(
            control_stdout
        )
        after_identity, after_digest = hash_archive_descriptor(
            descriptor,
            expected_uid,
            expected_gid,
            deadline=deadline,
        )
        try:
            namespace_identity = archive_file_identity(
                os.stat(path, follow_symlinks=False)
            )
        except OSError as exc:
            raise AptTransactionError(
                f"cannot recheck APT archive namespace: {exc}"
            ) from exc
        if (
            before_identity != after_identity
            or before_digest != after_digest
            or namespace_identity != before_identity
        ):
            raise AptTransactionError("APT archive changed during its control query")
        device, inode, mode, uid, gid, nlink, size, _, _ = before_identity
        return ArchiveRecord(
            str(path),
            device,
            inode,
            mode,
            uid,
            gid,
            nlink,
            size,
            before_digest,
            package,
            version,
            architecture,
            multiarch,
        )
    except subprocess.TimeoutExpired as exc:
        raise AptTransactionError("dpkg-deb control query timed out") from exc
    finally:
        close_descriptors((descriptor,), "APT archive", sys.exception())


def verify_archive_actions(
    archives: tuple[ArchiveRecord, ...],
    actions: tuple[PackageAction, ...],
) -> None:
    if (
        type(archives) is not tuple
        or type(actions) is not tuple
        or any(type(record) is not ArchiveRecord for record in archives)
        or any(type(action) is not PackageAction for action in actions)
        or len({record.path for record in archives}) != len(archives)
        or len(
            {(record.package, record.version, record.architecture) for record in archives}
        )
        != len(archives)
    ):
        raise AptTransactionError("APT archive/action closure is not canonical")
    if (
        len(archives) > MAX_ARCHIVE_COUNT
        or any(
            type(record.size) is not int
            or record.size < 0
            or record.size > MAX_ARCHIVE_BYTES
            for record in archives
        )
        or sum(record.size for record in archives) > MAX_ARCHIVE_TOTAL_BYTES
    ):
        raise AptTransactionError(
            "expected transaction archive set exceeds its aggregate size bound"
        )
    unpack_actions = tuple(action for action in actions if action.action.startswith("/"))
    configure_actions = tuple(
        action for action in actions if action.action == "**CONFIGURE**"
    )
    if len(unpack_actions) != len(archives) or len(configure_actions) != len(archives):
        raise AptTransactionError("APT archive/action counts differ")
    for archive in archives:
        identity = (
            archive.package,
            archive.version,
            archive.architecture,
            archive.multiarch,
        )
        unpack_matches = [
            action
            for action in unpack_actions
            if action.action == archive.path
            and (
                action.package,
                action.new_version,
                action.new_architecture,
                action.new_multiarch,
            )
            == identity
        ]
        configure_matches = [
            action
            for action in configure_actions
            if (
                action.package,
                action.new_version,
                action.new_architecture,
                action.new_multiarch,
            )
            == identity
        ]
        if len(unpack_matches) != 1 or len(configure_matches) != 1:
            raise AptTransactionError("APT archive differs from its exact EIPP actions")


def optional_field(value: str | None) -> str:
    return value if value is not None else "-"


def serialize_expected_transaction(transaction: ExpectedTransaction) -> bytes:
    if (
        type(transaction) is not ExpectedTransaction
        or not SHA256.fullmatch(transaction.package_state_sha256)
        or not SHA256.fullmatch(transaction.dpkg_state_sha256)
        or not SHA256.fullmatch(transaction.host_reference_sha256)
        or any(
            "\t" in key
            or "\n" in key
            or "\r" in key
            or "\t" in value
            or "\n" in value
            or "\r" in value
            for key, value in transaction.configuration
        )
    ):
        raise AptTransactionError("expected transaction cannot be serialized canonically")
    verify_eipp_configuration(transaction.configuration, transaction.configuration)
    verify_eipp_actions(transaction.actions, transaction.actions)
    verify_archive_actions(transaction.archives, transaction.actions)
    lines = [
        "schema\ttb321fu.haptics-apt-transaction/v1",
        f"package-state-sha256\t{transaction.package_state_sha256}",
        f"dpkg-state-sha256\t{transaction.dpkg_state_sha256}",
        f"host-reference-sha256\t{transaction.host_reference_sha256}",
    ]
    lines.extend(f"configuration\t{key}\t{value}" for key, value in transaction.configuration)
    lines.extend(
        "\t".join(
            (
                "action",
                action.package,
                optional_field(action.old_version),
                optional_field(action.old_architecture),
                "none" if action.old_version is None else optional_field(action.old_multiarch),
                action.direction,
                optional_field(action.new_version),
                optional_field(action.new_architecture),
                optional_field(action.new_multiarch),
                action.action,
            )
        )
        for action in transaction.actions
    )
    lines.extend(
        "\t".join(
            (
                "archive",
                archive.path,
                str(archive.device),
                str(archive.inode),
                f"{archive.mode:o}",
                str(archive.uid),
                str(archive.gid),
                str(archive.nlink),
                str(archive.size),
                archive.sha256,
                archive.package,
                archive.version,
                archive.architecture,
                archive.multiarch,
            )
        )
        for archive in transaction.archives
    )
    raw = ("\n".join(lines) + "\n").encode("ascii")
    if len(raw) > MAX_TRANSACTION_MANIFEST_BYTES:
        raise AptTransactionError("expected transaction manifest exceeds its size bound")
    return raw


def parse_expected_transaction_bytes(raw: bytes) -> ExpectedTransaction:
    if not raw or len(raw) > MAX_TRANSACTION_MANIFEST_BYTES:
        raise AptTransactionError("expected transaction manifest is empty or oversized")
    if (
        not raw.endswith(b"\n")
        or any(
            separator in raw
            for separator in (b"\r", b"\v", b"\f", b"\x1c", b"\x1d", b"\x1e")
        )
        or b"\0" in raw
    ):
        raise AptTransactionError("expected transaction manifest has invalid framing")
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as exc:
        raise AptTransactionError("expected transaction manifest must be ASCII") from exc
    if (
        len(lines) < 7
        or lines[0] != "schema\ttb321fu.haptics-apt-transaction/v1"
        or not lines[1].startswith("package-state-sha256\t")
        or not lines[2].startswith("dpkg-state-sha256\t")
        or not lines[3].startswith("host-reference-sha256\t")
    ):
        raise AptTransactionError("expected transaction manifest header is invalid")
    package_fields = lines[1].split("\t")
    dpkg_fields = lines[2].split("\t")
    host_fields = lines[3].split("\t")
    if (
        len(package_fields) != 2
        or len(dpkg_fields) != 2
        or len(host_fields) != 2
        or not SHA256.fullmatch(package_fields[1])
        or not SHA256.fullmatch(dpkg_fields[1])
        or not SHA256.fullmatch(host_fields[1])
    ):
        raise AptTransactionError("expected transaction manifest digest is invalid")
    configuration: list[tuple[str, str]] = []
    actions: list[PackageAction] = []
    archives: list[ArchiveRecord] = []
    section = 0
    for line in lines[4:]:
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        current = {"configuration": 0, "action": 1, "archive": 2}.get(kind)
        if current is None or current < section:
            raise AptTransactionError("expected transaction manifest section order is invalid")
        section = current
        if kind == "configuration" and len(fields) == 3:
            _, key, value = fields
            if not key:
                raise AptTransactionError("expected transaction has an empty config key")
            configuration.append((key, value))
        elif kind == "action" and len(fields) == 10:
            actions.append(parse_manifest_action_fields(fields[1:]))
        elif kind == "archive" and len(fields) == 14:
            (
                _,
                path,
                device_text,
                inode_text,
                mode_text,
                uid_text,
                gid_text,
                nlink_text,
                size_text,
                digest,
                package,
                version,
                architecture,
                multiarch,
            ) = fields
            numeric = (device_text, inode_text, uid_text, gid_text, nlink_text, size_text)
            if (
                any(not UNSIGNED.fullmatch(value) for value in numeric)
                or mode_text != "644"
                or not SHA256.fullmatch(digest)
                or not PACKAGE_NAME.fullmatch(package)
                or not VERSION.fullmatch(version)
                or not ARCHITECTURE.fullmatch(architecture)
                or multiarch not in {"same", "foreign", "allowed", "no"}
            ):
                raise AptTransactionError("expected transaction archive record is invalid")
            numbers = tuple(int(value) for value in numeric)
            device, inode, uid, gid, nlink, size = numbers
            if nlink != 1 or size > MAX_ARCHIVE_BYTES:
                raise AptTransactionError("expected archive resource metadata is invalid")
            archives.append(
                ArchiveRecord(
                    validate_archive_path(path),
                    device,
                    inode,
                    0o644,
                    uid,
                    gid,
                    nlink,
                    size,
                    digest,
                    package,
                    version,
                    architecture,
                    multiarch,
                )
            )
        else:
            raise AptTransactionError("expected transaction manifest record is malformed")
    transaction = ExpectedTransaction(
        package_fields[1],
        dpkg_fields[1],
        host_fields[1],
        tuple(configuration),
        tuple(actions),
        tuple(archives),
    )
    if serialize_expected_transaction(transaction) != raw:
        raise AptTransactionError("expected transaction manifest is noncanonical")
    return transaction


def verify_eipp_configuration(
    actual: tuple[tuple[str, str], ...],
    expected: tuple[tuple[str, str], ...],
) -> None:
    if (
        type(actual) is not tuple
        or type(expected) is not tuple
        or any(
            type(record) is not tuple
            or len(record) != 2
            or any(type(field) is not str for field in record)
            for record in (*actual, *expected)
        )
        or tuple(sorted(expected)) != expected
    ):
        raise AptTransactionError("expected EIPP configuration is not canonical")
    if actual != expected:
        raise AptTransactionError("effective APT configuration differs from the exact contract")


def validate_semantic_action(action: PackageAction) -> None:
    if (
        type(action) is not PackageAction
        or type(action.package) is not str
        or not PACKAGE_NAME.fullmatch(action.package)
    ):
        raise AptTransactionError("EIPP action closure contains an invalid package")
    for version, architecture, multiarch in (
        (action.old_version, action.old_architecture, action.old_multiarch),
        (action.new_version, action.new_architecture, action.new_multiarch),
    ):
        if version is None:
            if architecture is not None or multiarch is not None:
                raise AptTransactionError(
                    "EIPP semantic action has metadata for an absent version"
                )
        elif (
            type(version) is not str
            or type(architecture) is not str
            or type(multiarch) is not str
            or not VERSION.fullmatch(version)
            or not ARCHITECTURE.fullmatch(architecture)
            or multiarch not in DEBIAN_MULTIARCH
        ):
            raise AptTransactionError("EIPP semantic action identity is invalid")
    if type(action.direction) is not str or action.direction not in {"<", ">", "="}:
        raise AptTransactionError("EIPP semantic action direction is invalid")
    if action.old_version is None:
        valid_direction = action.new_version is not None and action.direction == "<"
    elif action.new_version is None:
        valid_direction = action.direction == ">"
    else:
        valid_direction = (action.old_version == action.new_version) == (
            action.direction == "="
        )
    if not valid_direction:
        raise AptTransactionError("EIPP semantic action direction is invalid")
    if type(action.action) is not str:
        raise AptTransactionError("EIPP semantic action target is invalid")
    if action.action == "**REMOVE**":
        raise AptTransactionError("package removal is forbidden by the transaction policy")
    if action.action != "**CONFIGURE**":
        validate_archive_path(action.action)


def verify_eipp_actions(
    actual: tuple[PackageAction, ...],
    expected: tuple[PackageAction, ...],
) -> None:
    if (
        type(actual) is not tuple
        or type(expected) is not tuple
        or any(type(action) is not PackageAction for action in (*actual, *expected))
    ):
        raise AptTransactionError("EIPP action closure is not canonical")
    for action in (*actual, *expected):
        validate_semantic_action(action)
    if len(actual) != len(set(actual)) or len(expected) != len(set(expected)):
        raise AptTransactionError("EIPP action closure is not canonical")
    if Counter(actual) != Counter(expected):
        raise AptTransactionError("EIPP actions differ from the exact transaction closure")


def debian_version_direction(
    old_version: str,
    new_version: str,
    *,
    deadline: float | None = None,
) -> str:
    if (
        type(old_version) is not str
        or type(new_version) is not str
        or not VERSION.fullmatch(old_version)
        or not VERSION.fullmatch(new_version)
    ):
        raise AptTransactionError("Debian version comparison input is invalid")
    if deadline is not None:
        require_operation_deadline(deadline, "APT transaction preparation")
    if old_version == new_version:
        return "="
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
    }
    for operator, direction in (("lt", "<"), ("gt", ">")):
        timeout = 10.0
        if deadline is not None:
            timeout = min(
                timeout,
                require_operation_deadline(deadline, "APT transaction preparation"),
            )
        try:
            returncode, stdout, stderr = _bounded_command(
                [
                    "/usr/bin/dpkg",
                    "--compare-versions",
                    old_version,
                    operator,
                    new_version,
                ],
                "dpkg version comparison",
                env=environment,
                timeout=timeout,
                max_stdout=0,
                max_stderr=MAX_CONTROL_STDERR_BYTES,
            )
        except subprocess.TimeoutExpired as exc:
            raise AptTransactionError("dpkg version comparison timed out") from exc
        if stdout or stderr or returncode not in {0, 1}:
            raise AptTransactionError("dpkg version comparison failed closed")
        if returncode == 0:
            return direction
    raise AptTransactionError("dpkg version comparison is inconsistent")


def build_expected_actions(
    changes: tuple[PlannedChange, ...],
    installed: dict[tuple[str, str], tuple[str, str, str]],
    archives: tuple[ArchiveRecord, ...],
    *,
    deadline: float | None = None,
) -> tuple[PackageAction, ...]:
    if (
        type(changes) is not tuple
        or type(installed) is not dict
        or type(archives) is not tuple
        or any(type(change) is not PlannedChange for change in changes)
        or any(type(record) is not ArchiveRecord for record in archives)
        or any(
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(field) is not str for field in identity)
            or type(record) is not tuple
            or len(record) != 3
            or any(type(field) is not str for field in record)
            or not PACKAGE_NAME.fullmatch(identity[0])
            or not ARCHITECTURE.fullmatch(identity[1])
            or not VERSION.fullmatch(record[0])
            or record[1] not in {"install ok installed", "hold ok installed"}
            or record[2] not in DEBIAN_MULTIARCH
            for identity, record in installed.items()
        )
    ):
        raise AptTransactionError("expected action builder received invalid inputs")
    change_key = lambda item: (item.package, item.architecture)
    if (
        tuple(sorted(changes, key=change_key)) != changes
        or len({change_key(change) for change in changes}) != len(changes)
    ):
        raise AptTransactionError("planned package changes are duplicate or noncanonical")
    archive_map = {
        (record.package, record.architecture): record for record in archives
    }
    if len(archive_map) != len(archives) or set(archive_map) != {
        change_key(change) for change in changes
    }:
        raise AptTransactionError("planned package changes differ from archive closure")
    actions: list[PackageAction] = []
    for change in changes:
        identity = change_key(change)
        if (
            type(change.package) is not str
            or type(change.architecture) is not str
            or not PACKAGE_NAME.fullmatch(change.package)
            or not ARCHITECTURE.fullmatch(change.architecture)
            or (
                change.old_version is not None
                and (
                    type(change.old_version) is not str
                    or not VERSION.fullmatch(change.old_version)
                )
            )
            or type(change.new_version) is not str
            or not VERSION.fullmatch(change.new_version)
        ):
            raise AptTransactionError("planned package change identity is invalid")
        archive = archive_map[identity]
        if archive.version != change.new_version:
            raise AptTransactionError("planned package version differs from its archive")
        installed_record = installed.get(identity)
        if change.old_version is None:
            if installed_record is not None:
                raise AptTransactionError("planned initial install already has an identity")
            old_version = None
            old_architecture = None
            old_multiarch = None
            direction = "<"
        else:
            if installed_record is None or installed_record[0] != change.old_version:
                raise AptTransactionError(
                    "planned prior version differs from installed status"
                )
            old_version = installed_record[0]
            old_architecture = identity[1]
            old_multiarch = installed_record[2]
            direction = debian_version_direction(
                old_version,
                archive.version,
                deadline=deadline,
            )
        base = (
            change.package,
            old_version,
            old_architecture,
            old_multiarch,
            direction,
            archive.version,
            archive.architecture,
            archive.multiarch,
        )
        actions.append(PackageAction(*base, archive.path))
        actions.append(PackageAction(*base, "**CONFIGURE**"))
    result = tuple(actions)
    verify_eipp_actions(result, result)
    verify_archive_actions(archives, result)
    return result


def prepare_expected_transaction(
    hook_command: str,
    package_lock_raw: bytes,
    package_state_raw: bytes,
    host_plan_raw: bytes,
    dpkg_state_raw: bytes,
    host_reference_raw: bytes,
    status_raw: bytes,
    archive_paths: tuple[pathlib.Path, ...],
    dpkg_admin: pathlib.Path,
    expected_uid: int,
    expected_gid: int,
    *,
    deadline: float | None = None,
) -> ExpectedTransaction:
    if (
        type(hook_command) is not str
        or any(
            type(raw) is not bytes
            for raw in (
                package_lock_raw,
                package_state_raw,
                host_plan_raw,
                dpkg_state_raw,
                host_reference_raw,
                status_raw,
            )
        )
        or type(archive_paths) is not tuple
        or not archive_paths
        or len(archive_paths) > MAX_ARCHIVE_COUNT
        or any(type(path) is not pathlib.PosixPath for path in archive_paths)
        or tuple(sorted(archive_paths, key=str)) != archive_paths
        or len(set(archive_paths)) != len(archive_paths)
        or type(dpkg_admin) is not pathlib.PosixPath
        or not dpkg_admin.is_absolute()
        or any(
            type(value) is not int or value < 0 or value > 2**32 - 1
            for value in (expected_uid, expected_gid)
        )
    ):
        raise AptTransactionError("APT transaction preparation inputs are invalid")
    if deadline is None:
        deadline = time.monotonic() + PREPARATION_TIMEOUT_SECONDS
    require_operation_deadline(deadline, "APT transaction preparation")
    package = load_package_verifier()
    dpkg = load_dpkg_state_verifier()
    try:
        policy = package.parse_lock_bytes(package_lock_raw)
        expected_package_state = package.parse_system_state_bytes(package_state_raw)
        plan = package.parse_apt_plan_bytes(host_plan_raw)
        package.verify_host_plan(
            policy.expected_versions(), expected_package_state, plan
        )
        expected_dpkg_state = dpkg.parse_dpkg_state_bytes(dpkg_state_raw)
        expected_host_reference = dpkg.parse_host_reference_bytes(host_reference_raw)
        installed_identities = dpkg.parse_status_identities(status_raw)
    except ValueError as exc:
        raise AptTransactionError(
            f"cannot parse APT transaction preparation evidence: {exc}"
        ) from exc

    def verify_live_package_state() -> None:
        require_operation_deadline(deadline, "APT transaction preparation")
        try:
            current_raw = package.serialize_system_state(
                package.capture_system_state(deadline=deadline)
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise AptTransactionError("cannot capture package preparation state") from exc
        if not hmac.compare_digest(current_raw, package_state_raw):
            raise AptTransactionError(
                "package state differs from the approved pre-transaction state"
            )
        require_operation_deadline(deadline, "APT transaction preparation")

    def verify_live_dpkg_state() -> None:
        require_operation_deadline(deadline, "APT transaction preparation")
        try:
            current = dpkg.capture_dpkg_state(
                dpkg_admin, expected_uid, expected_gid
            )
            dpkg.verify_dpkg_state(current, expected_dpkg_state)
            dpkg.verify_host_reference(current, expected_host_reference)
            current_host_raw = dpkg.serialize_host_reference(
                dpkg.host_reference_from_state(current)
            )
        except ValueError as exc:
            raise AptTransactionError(
                f"cannot verify dpkg preparation state: {exc}"
            ) from exc
        if not hmac.compare_digest(current_host_raw, host_reference_raw):
            raise AptTransactionError(
                "dpkg host reference bytes differ from the reviewed reference"
            )
        require_operation_deadline(deadline, "APT transaction preparation")

    verify_live_package_state()
    verify_live_dpkg_state()
    installed = {
        identity: record
        for identity, record in installed_identities.items()
        if record[1] in {"install ok installed", "hold ok installed"}
    }
    changes = tuple(
        PlannedChange(
            name,
            architecture,
            record.old_version,
            record.version,
        )
        for (name, architecture), record in sorted(plan.installs.items())
    )
    archive_records: list[ArchiveRecord] = []
    archive_total = 0
    for path in archive_paths:
        require_operation_deadline(deadline, "APT transaction preparation")
        record = capture_deb_archive(
            path,
            expected_uid,
            expected_gid,
            deadline=deadline,
        )
        require_operation_deadline(deadline, "APT transaction preparation")
        archive_total += record.size
        if archive_total > MAX_ARCHIVE_TOTAL_BYTES:
            raise AptTransactionError(
                "expected transaction archive set exceeds its aggregate size bound"
            )
        archive_records.append(record)
    archives = tuple(archive_records)
    actions = build_expected_actions(
        changes,
        installed,
        archives,
        deadline=deadline,
    )
    require_operation_deadline(deadline, "APT transaction preparation")
    verify_live_package_state()
    verify_live_dpkg_state()
    return ExpectedTransaction(
        hashlib.sha256(package_state_raw).hexdigest(),
        hashlib.sha256(dpkg_state_raw).hexdigest(),
        hashlib.sha256(host_reference_raw).hexdigest(),
        expected_hook_configuration(hook_command),
        actions,
        archives,
    )


def verify_post_transaction(
    manifest_raw: bytes,
    before_dpkg_state_raw: bytes,
    dpkg_admin: pathlib.Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if (
        type(manifest_raw) is not bytes
        or type(before_dpkg_state_raw) is not bytes
        or type(dpkg_admin) is not pathlib.PosixPath
        or not dpkg_admin.is_absolute()
        or any(
            type(value) is not int or value < 0 or value > 2**32 - 1
            for value in (expected_uid, expected_gid)
        )
    ):
        raise AptTransactionError("APT post-transaction inputs are invalid")
    transaction = parse_expected_transaction_bytes(manifest_raw)
    if not hmac.compare_digest(
        hashlib.sha256(before_dpkg_state_raw).hexdigest(),
        transaction.dpkg_state_sha256,
    ):
        raise AptTransactionError(
            "dpkg pre-state differs from the expected transaction"
        )
    dpkg = load_dpkg_state_verifier()
    try:
        before = dpkg.parse_dpkg_state_bytes(before_dpkg_state_raw)
        after = dpkg.capture_dpkg_state(
            dpkg_admin, expected_uid, expected_gid
        )
        approved = tuple(
            sorted(
                {
                    (archive.package, archive.architecture)
                    for archive in transaction.archives
                }
            )
        )
        dpkg.verify_post_dpkg_state(before, after, approved)
    except ValueError as exc:
        raise AptTransactionError(
            f"dpkg post-transaction state verification failed: {exc}"
        ) from exc


def enumerate_archive_paths(
    directories: tuple[pathlib.Path, ...],
    expected_uid: int,
    expected_gid: int,
    *,
    deadline: float | None = None,
) -> tuple[pathlib.Path, ...]:
    if (
        type(directories) is not tuple
        or not directories
        or len(directories) > 4
        or any(type(path) is not pathlib.PosixPath for path in directories)
        or len(set(directories)) != len(directories)
        or any(
            type(value) is not int or value < 0 or value > 2**32 - 1
            for value in (expected_uid, expected_gid)
        )
    ):
        raise AptTransactionError("APT archive directory inputs are invalid")

    def check_deadline() -> None:
        if deadline is not None:
            require_operation_deadline(deadline, "APT transaction preparation")

    check_deadline()

    def directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    paths: list[pathlib.Path] = []
    for directory in sorted(directories, key=str):
        check_deadline()
        try:
            directory_text = str(directory)
            directory_text.encode("ascii")
            check_deadline()
            before = directory.lstat()
            if (
                not directory.is_absolute()
                or len(os.fsencode(directory_text)) > MAX_PRIVATE_PATH_BYTES
                or directory.resolve(strict=True) != directory
                or not stat.S_ISDIR(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o755
                or before.st_uid != expected_uid
                or before.st_gid != expected_gid
            ):
                raise AptTransactionError(
                    "APT archive directory metadata differs from policy"
                )
            check_deadline()
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            check_deadline()
            names = tuple(entry.name for entry in entries if entry.name.endswith(".deb"))
            if len(paths) + len(names) > MAX_ARCHIVE_COUNT:
                raise AptTransactionError("APT archive set exceeds its count bound")
            for entry in entries:
                check_deadline()
                if not entry.name.endswith(".deb"):
                    continue
                archive = directory / entry.name
                metadata = entry.stat(follow_symlinks=False)
                check_deadline()
                try:
                    archive_text = str(archive)
                    archive_text.encode("ascii")
                except UnicodeEncodeError as exc:
                    raise AptTransactionError(
                        "APT archive directory contains an unsafe DEB entry"
                    ) from exc
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o644
                    or metadata.st_uid != expected_uid
                    or metadata.st_gid != expected_gid
                    or metadata.st_nlink != 1
                    or metadata.st_size > MAX_ARCHIVE_BYTES
                    or validate_archive_path(archive_text) != archive_text
                ):
                    raise AptTransactionError(
                        "APT archive directory contains an unsafe DEB entry"
                    )
                paths.append(archive)
            check_deadline()
            after = directory.lstat()
            after_names = tuple(
                sorted(
                    name
                    for name in os.listdir(directory)
                    if name.endswith(".deb")
                )
            )
            check_deadline()
            if directory_identity(after) != directory_identity(before) or after_names != names:
                raise AptTransactionError(
                    "APT archive directory changed while it was enumerated"
                )
        except AptTransactionError:
            raise
        except (OSError, UnicodeError) as exc:
            raise AptTransactionError(
                f"cannot enumerate APT archive directory: {exc}"
            ) from exc
    result = tuple(sorted(paths, key=str))
    if not result or len(set(result)) != len(result):
        raise AptTransactionError("APT archive path closure is empty or duplicate")
    check_deadline()
    return result


def write_private_manifest(
    path: pathlib.Path,
    raw: bytes,
    expected_uid: int,
    expected_gid: int,
    *,
    deadline: float | None = None,
    retain_ownership: bool = False,
    ownership_slot: PublicationOwnershipSlot | None = None,
) -> PublishedFileOwnership | None:
    if (
        type(path) is not pathlib.PosixPath
        or type(raw) is not bytes
        or type(retain_ownership) is not bool
        or (
            retain_ownership
            and (
                type(ownership_slot) is not PublicationOwnershipSlot
                or ownership_slot.ownership is not None
            )
        )
        or (not retain_ownership and ownership_slot is not None)
        or any(
            type(value) is not int or value < 0 or value > 2**32 - 1
            for value in (expected_uid, expected_gid)
        )
    ):
        raise AptTransactionError("private APT transaction manifest inputs are invalid")

    def check_deadline() -> None:
        if deadline is not None:
            require_operation_deadline(deadline, "APT transaction preparation")

    check_deadline()
    parse_expected_transaction_bytes(raw)
    check_deadline()
    canonical_hook_path(str(path))
    directory_descriptor = -1
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    publication: PublishedFileOwnership | None = None
    completed = False
    active_exception: BaseException | None = None
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        check_deadline()
        directory_descriptor = os.open(path.parent, flags)
        check_deadline()
        directory_metadata = os.fstat(directory_descriptor)
        directory_namespace = os.stat(path.parent, follow_symlinks=False)
        check_deadline()
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_uid != expected_uid
            or directory_metadata.st_gid != expected_gid
            or archive_file_identity(directory_metadata)
            != archive_file_identity(directory_namespace)
        ):
            raise AptTransactionError(
                "private APT transaction directory metadata differs from policy"
            )
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        check_deadline()
        descriptor = os.open(
            path.name,
            create_flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        check_deadline()
        offset = 0
        while offset < len(raw):
            check_deadline()
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise AptTransactionError(
                    "private APT transaction manifest write made no progress"
                )
            offset += written
            check_deadline()
        os.fchmod(descriptor, 0o600)
        check_deadline()
        os.fsync(descriptor)
        check_deadline()
        final = os.fstat(descriptor)
        namespace = os.stat(
            path.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        check_deadline()
        if (
            not stat.S_ISREG(final.st_mode)
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_uid != expected_uid
            or final.st_gid != expected_gid
            or final.st_nlink != 1
            or final.st_size != len(raw)
            or archive_file_identity(final) != archive_file_identity(namespace)
        ):
            raise AptTransactionError(
                "private APT transaction manifest metadata differs from policy"
            )
        check_deadline()
        os.fsync(directory_descriptor)
        check_deadline()
        if retain_ownership:
            publication = PublishedFileOwnership(
                descriptor,
                created_identity[0],
                created_identity[1],
                directory_descriptor,
            )
            assert ownership_slot is not None
            ownership_slot.accept(publication)
        completed = True
    except AptTransactionError as exc:
        active_exception = exc
        raise
    except OSError as exc:
        active_exception = AptTransactionError(
            f"cannot create private APT transaction manifest: {exc}"
        )
        raise active_exception from exc
    except BaseException as exc:
        active_exception = exc
        raise
    finally:
        cleanup_notes: list[str] = []
        cleanup_primary = active_exception
        transferred = (
            ownership_slot is not None
            and ownership_slot.ownership is not None
            and ownership_slot.ownership.descriptor == descriptor
            and ownership_slot.ownership.parent_descriptor == directory_descriptor
            and (
                ownership_slot.ownership.device,
                ownership_slot.ownership.inode,
            )
            == created_identity
        )
        if (
            descriptor >= 0
            and created_identity is None
            and not completed
            and not transferred
        ):
            try:
                recovered = os.fstat(descriptor)
            except BaseException:
                cleanup_notes.append(
                    "APT transaction manifest cleanup could not inspect owned "
                    "publication inode"
                )
            else:
                created_identity = (recovered.st_dev, recovered.st_ino)
        if descriptor >= 0 and not transferred:
            close_failure, _ = close_owned_descriptor(
                descriptor,
                "APT transaction manifest publication",
            )
            if close_failure is not None:
                note = (
                    "APT transaction manifest cleanup could not close publication "
                    "descriptor"
                )
                completed = False
                if cleanup_primary is None and isinstance(close_failure, Exception):
                    cleanup_primary = AptTransactionError(
                        "cannot finalize private APT transaction manifest cleanup"
                    )
                    cleanup_primary.__cause__ = close_failure
                    cleanup_primary.add_note(note)
                else:
                    cleanup_primary = choose_cleanup_failure(
                        cleanup_primary,
                        close_failure,
                        note,
                    )
            descriptor = -1
        if directory_descriptor >= 0 and not transferred:
            if created_identity is not None and not completed:
                try:
                    current = os.stat(
                        path.name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    current = None
                except BaseException:
                    current = None
                    cleanup_notes.append(
                        "APT transaction manifest cleanup could not inspect "
                        "published manifest"
                    )
                if current is not None and (
                    current.st_dev,
                    current.st_ino,
                ) == created_identity:
                    try:
                        os.unlink(path.name, dir_fd=directory_descriptor)
                    except FileNotFoundError:
                        pass
                    except BaseException:
                        cleanup_notes.append(
                            "APT transaction manifest cleanup could not remove "
                            "published manifest"
                        )
                elif current is not None:
                    cleanup_notes.append(
                        "APT transaction manifest cleanup found the published "
                        "manifest namespace changed"
                    )
                try:
                    os.fsync(directory_descriptor)
                except BaseException:
                    cleanup_notes.append(
                        "APT transaction manifest cleanup could not synchronize "
                        "manifest directory"
                    )
                try:
                    remaining = os.stat(
                        path.name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    remaining = None
                except BaseException:
                    remaining = None
                    cleanup_notes.append(
                        "APT transaction manifest cleanup could not confirm "
                        "published manifest removal"
                    )
                if remaining is not None:
                    if (
                        remaining.st_dev,
                        remaining.st_ino,
                    ) == created_identity:
                        cleanup_notes.append(
                            "APT transaction manifest cleanup left the published "
                            "manifest inode present"
                        )
                    else:
                        cleanup_notes.append(
                            "APT transaction manifest cleanup found the published "
                            "manifest namespace changed"
                        )
            close_failure, _ = close_owned_descriptor(
                directory_descriptor,
                "APT transaction manifest parent directory",
            )
            if close_failure is not None:
                note = (
                    "APT transaction manifest cleanup could not close parent "
                    "directory descriptor"
                )
                if cleanup_primary is None and isinstance(close_failure, Exception):
                    cleanup_primary = AptTransactionError(
                        "cannot finalize private APT transaction manifest cleanup"
                    )
                    cleanup_primary.__cause__ = close_failure
                    cleanup_primary.add_note(note)
                else:
                    cleanup_primary = choose_cleanup_failure(
                        cleanup_primary,
                        close_failure,
                        note,
                    )
            directory_descriptor = -1
        notes = tuple(dict.fromkeys(cleanup_notes))
        if cleanup_primary is not None:
            add_cleanup_notes(cleanup_primary, notes)
        elif notes:
            cleanup_primary = AptTransactionError(
                "cannot finalize private APT transaction manifest cleanup"
            )
            add_cleanup_notes(cleanup_primary, notes)
        if cleanup_primary is not None and cleanup_primary is not active_exception:
            raise cleanup_primary
    if (
        retain_ownership
        and (
            publication is None
            or ownership_slot is None
            or ownership_slot.ownership is not publication
        )
    ):
        raise AptTransactionError(
            "private APT transaction manifest publication ownership is missing"
        )
    return publication


def current_signal_mask() -> frozenset[signal.Signals]:
    return frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))


def restore_signal_mask(
    expected: frozenset[signal.Signals],
    label: str,
) -> tuple[BaseException | None, bool]:
    failure: BaseException | None = None
    for _ in range(3):
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, set(expected))
        except BaseException as exc:
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(exc, f"cannot restore {label}"),
                f"{label} restoration also failed",
            )
        try:
            current = current_signal_mask()
        except BaseException as exc:
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(exc, f"cannot inspect {label}"),
                f"{label} inspection also failed",
            )
            continue
        if current == expected:
            return failure, True
    failure = choose_cleanup_failure(
        failure,
        AptTransactionError(f"{label} restoration did not converge"),
        f"{label} restoration also did not converge",
    )
    return failure, False


def block_cleanup_signals(label: str) -> frozenset[signal.Signals]:
    try:
        original = current_signal_mask()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise AptTransactionError(f"cannot inspect {label} signal mask") from exc
    try:
        previous = frozenset(
            signal.pthread_sigmask(
                signal.SIG_BLOCK,
                set(FORK_CANCELLATION_SIGNALS),
            )
        )
    except BaseException as exc:
        primary = fixed_cleanup_candidate(exc, f"cannot block {label} signals")
        restore_failure, _ = restore_signal_mask(original, f"{label} signal mask")
        if restore_failure is not None:
            primary = choose_cleanup_failure(
                primary,
                restore_failure,
                f"{label} signal-mask recovery also failed",
            )
        raise primary
    try:
        current = current_signal_mask()
    except BaseException as exc:
        primary = fixed_cleanup_candidate(
            exc,
            f"cannot inspect blocked {label} signals",
        )
    else:
        if previous == original and FORK_CANCELLATION_SIGNALS <= current:
            return original
        primary = AptTransactionError(f"{label} signal block did not apply")
    restore_failure, _ = restore_signal_mask(original, f"{label} signal mask")
    if restore_failure is not None:
        primary = choose_cleanup_failure(
            primary,
            restore_failure,
            f"{label} signal-mask recovery also failed",
        )
    raise primary


def block_fork_cancellation() -> frozenset[signal.Signals]:
    try:
        original = current_signal_mask()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise AptTransactionError(
            "cannot inspect _apt archive proof fork signal mask"
        ) from exc
    try:
        previous = frozenset(
            signal.pthread_sigmask(
                signal.SIG_BLOCK,
                set(FORK_CANCELLATION_SIGNALS),
            )
        )
    except BaseException as exc:
        restore_failure, _ = restore_signal_mask(
            original,
            "_apt archive proof fork signal mask",
        )
        primary = fixed_cleanup_candidate(
            exc,
            "cannot block _apt archive proof fork signals",
        )
        if restore_failure is not None:
            primary = choose_cleanup_failure(
                primary,
                restore_failure,
                "_apt archive proof fork signal-mask recovery also failed",
            )
        raise primary
    if previous != original:
        restore_failure, _ = restore_signal_mask(
            original,
            "_apt archive proof fork signal mask",
        )
        primary: BaseException = AptTransactionError(
            "_apt archive proof fork signal mask changed unexpectedly"
        )
        if restore_failure is not None:
            primary = choose_cleanup_failure(
                primary,
                restore_failure,
                "_apt archive proof unexpected signal-mask recovery also failed",
            )
        raise primary
    try:
        current = current_signal_mask()
    except BaseException as exc:
        primary = fixed_cleanup_candidate(
            exc,
            "cannot inspect blocked _apt archive proof fork signals",
        )
    else:
        if FORK_CANCELLATION_SIGNALS <= current:
            return original
        primary = AptTransactionError(
            "_apt archive proof fork signal block did not apply"
        )
    restore_failure, _ = restore_signal_mask(
        original,
        "_apt archive proof fork signal mask",
    )
    if restore_failure is not None:
        primary = choose_cleanup_failure(
            primary,
            restore_failure,
            "_apt archive proof fork signal-mask recovery also failed",
        )
    raise primary


def cleanup_child_after_failure(
    child: int,
    primary: BaseException,
) -> BaseException:
    selected = primary
    live = False
    custody_failures = 0
    while custody_failures < 3:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return selected
        except BaseException as exc:
            custody_failures += 1
            selected = choose_cleanup_failure(
                selected,
                fixed_cleanup_candidate(
                    exc,
                    "cannot determine _apt archive proof child custody",
                ),
                "_apt archive proof child custody inspection also failed",
            )
            continue
        if waited == child:
            return selected
        if waited != 0:
            return choose_cleanup_failure(
                selected,
                AptTransactionError(
                    "child cleanup returned an unexpected process"
                ),
                "_apt archive proof child cleanup also failed",
            )
        live = True
        break
    if not live:
        return choose_cleanup_failure(
            selected,
            AptTransactionError(
                "_apt archive proof child custody did not converge"
            ),
            "_apt archive proof child cleanup also did not converge",
        )
    signal_applied = False
    for _ in range(3):
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            break
        except BaseException as exc:
            selected = choose_cleanup_failure(
                selected,
                fixed_cleanup_candidate(
                    exc,
                    "cannot signal _apt archive proof child",
                ),
                "_apt archive proof child signal cleanup also failed",
            )
            try:
                waited, _ = os.waitpid(child, os.WNOHANG)
            except InterruptedError:
                continue
            except ChildProcessError:
                return selected
            except BaseException as probe:
                selected = choose_cleanup_failure(
                    selected,
                    fixed_cleanup_candidate(
                        probe,
                        "cannot recheck _apt archive proof child custody",
                    ),
                    "_apt archive proof child custody recheck also failed",
                )
                continue
            if waited == child:
                return selected
            if waited != 0:
                return choose_cleanup_failure(
                    selected,
                    AptTransactionError(
                        "child cleanup returned an unexpected process"
                    ),
                    "_apt archive proof child cleanup also failed",
                )
            continue
        signal_applied = True
        break
    if not signal_applied:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            return selected
        except BaseException as exc:
            selected = choose_cleanup_failure(
                selected,
                fixed_cleanup_candidate(
                    exc,
                    "cannot confirm _apt archive proof child signal state",
                ),
                "_apt archive proof child signal-state confirmation also failed",
            )
        else:
            if waited == child:
                return selected
            if waited != 0:
                return choose_cleanup_failure(
                    selected,
                    AptTransactionError(
                        "child cleanup returned an unexpected process"
                    ),
                    "_apt archive proof child cleanup also failed",
                )
            selected = choose_cleanup_failure(
                selected,
                AptTransactionError(
                    "_apt archive proof child signal did not converge"
                ),
                "_apt archive proof child signal also did not converge",
            )
    cleanup_deadline = time.monotonic() + CHILD_CLEANUP_SECONDS
    while True:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return selected
        except BaseException as exc:
            selected = choose_cleanup_failure(
                selected,
                fixed_cleanup_candidate(
                    exc,
                    "cannot reap _apt archive proof child",
                ),
                "_apt archive proof child reap also failed",
            )
        else:
            if waited == child:
                return selected
            if waited != 0:
                return choose_cleanup_failure(
                    selected,
                    AptTransactionError(
                        "child cleanup returned an unexpected process"
                    ),
                    "_apt archive proof child cleanup also failed",
                )
        remaining = cleanup_deadline - time.monotonic()
        if remaining <= 0:
            return choose_cleanup_failure(
                selected,
                AptTransactionError(
                    "cannot reap _apt archive proof child"
                ),
                "_apt archive proof child reap did not converge",
            )
        try:
            time.sleep(min(0.01, remaining))
        except BaseException as exc:
            selected = choose_cleanup_failure(
                selected,
                fixed_cleanup_candidate(
                    exc,
                    "_apt archive proof child cleanup sleep failed",
                ),
                "_apt archive proof child cleanup sleep also failed",
            )


def _wait_for_child(
    child: int,
    timeout: float,
    *,
    deadline: float | None = None,
    deadline_label: str | None = None,
) -> int:
    if type(child) is not int or child <= 0:
        raise AptTransactionError("child wait received invalid runtime inputs")
    try:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
            or (deadline is None) != (deadline_label is None)
            or (
                deadline is not None
                and (
                    isinstance(deadline, bool)
                    or not isinstance(deadline, (int, float))
                    or not math.isfinite(deadline)
                    or type(deadline_label) is not str
                    or not deadline_label
                )
            )
        ):
            raise AptTransactionError("child wait received invalid runtime inputs")
        child_deadline = time.monotonic() + timeout
        while True:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise AptTransactionError(f"{deadline_label} exceeded its deadline")
            if now >= child_deadline:
                raise AptTransactionError("_apt archive proof timed out")
            try:
                waited, status_value = os.waitpid(child, os.WNOHANG)
            except InterruptedError:
                continue
            if waited == child:
                return status_value
            if waited != 0:
                raise AptTransactionError("child wait returned an unexpected process")
            remaining = child_deadline - now
            if deadline is not None:
                remaining = min(remaining, deadline - now)
            time.sleep(min(0.01, remaining))
    except BaseException as exc:
        selected = cleanup_child_after_failure(child, exc)
        if selected is exc:
            raise
        raise selected


def verify_apt_readable_archive(
    path: pathlib.Path,
    expected_sha256: str,
    expected_device: int,
    expected_inode: int,
    apt_uid: int,
    apt_gid: int,
    *,
    deadline: float | None = None,
) -> None:
    if os.geteuid() != 0:
        raise AptTransactionError("_apt archive proof requires root before privilege drop")
    if (
        not path.is_absolute()
        or not SHA256.fullmatch(expected_sha256)
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            or value > 2**64 - 1
            for value in (expected_device, expected_inode, apt_uid, apt_gid)
        )
    ):
        raise AptTransactionError("_apt archive proof received invalid identity metadata")
    if apt_uid == 0 or apt_gid == 0:
        raise AptTransactionError("_apt archive proof must use a non-root identity")
    if deadline is not None:
        require_operation_deadline(deadline, "APT hook verification")
    validate_archive_path(str(path))
    fork_mask = block_fork_cancellation()
    child = -1
    try:
        child = os.fork()
    except BaseException as exc:
        primary = fixed_cleanup_candidate(
            exc,
            "cannot fork _apt archive proof",
        )
        restore_failure, _ = restore_signal_mask(
            fork_mask,
            "_apt archive proof fork signal mask",
        )
        if restore_failure is not None:
            primary = choose_cleanup_failure(
                primary,
                restore_failure,
                "_apt archive proof fork signal-mask restoration also failed",
            )
        raise primary
    if child == 0:
        restore_failure, restored = restore_signal_mask(
            fork_mask,
            "_apt archive proof child signal mask",
        )
        if restore_failure is not None or not restored:
            os._exit(1)
        descriptor = -1
        try:
            os.setgroups([])
            os.setgid(apt_gid)
            os.setuid(apt_uid)
            if (
                os.getresuid() != (apt_uid, apt_uid, apt_uid)
                or os.getresgid() != (apt_gid, apt_gid, apt_gid)
                or os.getgroups()
            ):
                os._exit(1)
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o644
                or before.st_uid != 0
                or before.st_gid != 0
                or before.st_nlink != 1
                or before.st_dev != expected_device
                or before.st_ino != expected_inode
                or before.st_size > MAX_ARCHIVE_BYTES
            ):
                os._exit(1)
            digest = hashlib.sha256()
            remaining = MAX_ARCHIVE_BYTES + 1
            size = 0
            while remaining:
                if deadline is not None and time.monotonic() >= deadline:
                    os._exit(1)
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                size += len(chunk)
                remaining -= len(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            stable = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (
                not stable
                or size != before.st_size
                or digest.hexdigest() != expected_sha256
            ):
                os._exit(1)
            os._exit(0)
        except BaseException:
            os._exit(1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    try:
        restore_failure, restored = restore_signal_mask(
            fork_mask,
            "_apt archive proof fork signal mask",
        )
        if restore_failure is not None:
            raise restore_failure
        if not restored:
            raise AptTransactionError(
                "_apt archive proof fork signal-mask restoration did not converge"
            )
        status_value = _wait_for_child(
            child,
            APT_READABLE_TIMEOUT_SECONDS,
            deadline=deadline,
            deadline_label="APT hook verification" if deadline is not None else None,
        )
    except BaseException as exc:
        selected = cleanup_child_after_failure(child, exc)
        if selected is exc:
            raise
        raise selected
    if not os.WIFEXITED(status_value) or os.WEXITSTATUS(status_value):
        raise AptTransactionError("_apt could not open and hash the verified archive inode")


def parse_manifest_action_fields(fields: list[str]) -> PackageAction:
    if len(fields) != 9:
        raise AptTransactionError("expected transaction action is malformed")
    wire_fields = list(fields)
    for version_index, architecture_index, multiarch_index in (
        (1, 2, 3),
        (5, 6, 7),
    ):
        version = fields[version_index]
        architecture = fields[architecture_index]
        multiarch = fields[multiarch_index]
        if version == "-":
            if architecture != "-" or multiarch != "none":
                raise AptTransactionError(
                    "expected transaction absent identity has metadata"
                )
        elif multiarch not in DEBIAN_MULTIARCH:
            raise AptTransactionError(
                "expected transaction present Multi-Arch identity is invalid"
            )
        elif multiarch == "no":
            wire_fields[multiarch_index] = "none"
    return parse_action_line(" ".join(wire_fields))


def parse_action_line(line: str) -> PackageAction:
    fields = line.split(" ")
    if len(fields) != 9 or any(not field for field in fields):
        raise AptTransactionError("EIPP v3 action does not contain nine fields")
    (
        package,
        old_version_text,
        old_architecture_text,
        old_multiarch_text,
        direction,
        new_version_text,
        new_architecture_text,
        new_multiarch_text,
        action,
    ) = fields
    if not PACKAGE_NAME.fullmatch(package) or direction not in {"<", ">", "="}:
        raise AptTransactionError("EIPP v3 action contains invalid package metadata")
    old_version, old_architecture, old_multiarch = parse_version_identity(
        old_version_text, old_architecture_text, old_multiarch_text, "old"
    )
    new_version, new_architecture, new_multiarch = parse_version_identity(
        new_version_text, new_architecture_text, new_multiarch_text, "new"
    )
    if old_version is None:
        if new_version is None or direction != "<":
            raise AptTransactionError("initial-install action has an invalid direction")
    elif new_version is None:
        if direction != ">":
            raise AptTransactionError("removal action has an invalid direction")
    elif (old_version == new_version) != (direction == "="):
        raise AptTransactionError("version-change direction is inconsistent")
    if action == "**REMOVE**":
        raise AptTransactionError("package removal is forbidden by the transaction policy")
    if action != "**CONFIGURE**" and not action.startswith("/"):
        raise AptTransactionError("EIPP v3 action is not canonical")
    if action != "**CONFIGURE**":
        action = validate_archive_path(action)
    return PackageAction(
        package,
        old_version,
        old_architecture,
        old_multiarch,
        direction,
        new_version,
        new_architecture,
        new_multiarch,
        action,
    )


def parse_eipp_v3_bytes(raw: bytes) -> EippDocument:
    if not raw or len(raw) > MAX_EIPP_BYTES:
        raise AptTransactionError("EIPP stream is empty or exceeds its size bound")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise AptTransactionError("EIPP stream has invalid line framing")
    if any(byte != 0x0A and not 0x20 <= byte <= 0x7E for byte in raw):
        raise AptTransactionError("EIPP stream contains a noncanonical raw byte")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AptTransactionError("EIPP stream must contain ASCII only") from exc
    if not lines or lines[0] != "VERSION 3":
        raise AptTransactionError("EIPP protocol version is not exactly 3")
    try:
        separator = lines.index("", 1)
    except ValueError as exc:
        raise AptTransactionError("EIPP stream is missing its section separator") from exc
    if separator == 1 or separator == len(lines) - 1 or "" in lines[separator + 1 :]:
        raise AptTransactionError("EIPP stream has invalid section framing")

    configuration: list[tuple[str, str]] = []
    scalar_keys: set[str] = set()
    for line in lines[1:separator]:
        key, found, value = line.partition("=")
        if not found or not key:
            raise AptTransactionError("EIPP configuration record is malformed")
        decoded_key = decode_eipp_component(
            key, "EIPP configuration key", key=True
        )
        decoded_value = decode_eipp_component(
            value, "EIPP configuration value", key=False
        )
        if not decoded_key.endswith("::"):
            if decoded_key in scalar_keys:
                raise AptTransactionError("EIPP configuration repeats a scalar key")
            scalar_keys.add(decoded_key)
        configuration.append((decoded_key, decoded_value))
    actions = tuple(parse_action_line(line) for line in lines[separator + 1 :])
    if len(actions) != len(set(actions)):
        raise AptTransactionError("EIPP stream repeats a package action")
    return EippDocument(tuple(sorted(configuration)), actions)


def load_dpkg_state_verifier():
    module_path = pathlib.Path(__file__).resolve().with_name(
        "verify-haptics-dpkg-state.py"
    )
    module_name = "_haptics_dpkg_state_verifier"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise AptTransactionError("cannot load the dpkg state verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def load_package_verifier():
    module_path = pathlib.Path(__file__).resolve().with_name(
        "verify-haptics-build-packages.py"
    )
    module_name = "_haptics_build_package_verifier"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise AptTransactionError("cannot load the package state verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def verify_hook_inputs(
    eipp_raw: bytes,
    manifest_raw: bytes,
    dpkg_admin: pathlib.Path,
    expected_uid: int,
    expected_gid: int,
    apt_uid: int,
    apt_gid: int,
    *,
    deadline: float | None = None,
) -> str:
    if (
        type(eipp_raw) is not bytes
        or type(manifest_raw) is not bytes
        or type(dpkg_admin) is not pathlib.PosixPath
        or not dpkg_admin.is_absolute()
        or any(
            type(value) is not int or value < 0 or value > 2**32 - 1
            for value in (expected_uid, expected_gid, apt_uid, apt_gid)
        )
    ):
        raise AptTransactionError("APT hook verifier received invalid runtime inputs")
    if os.geteuid() != 0:
        raise AptTransactionError("APT hook verification requires root")
    if deadline is None:
        deadline = time.monotonic() + HOOK_VERIFICATION_TIMEOUT_SECONDS
    elif (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise AptTransactionError("APT hook verification deadline is invalid")
    else:
        deadline = float(deadline)
    require_operation_deadline(deadline, "APT hook verification")
    transaction = parse_expected_transaction_bytes(manifest_raw)
    document = parse_eipp_v3_bytes(eipp_raw)
    verify_eipp_configuration(document.configuration, transaction.configuration)
    verify_eipp_actions(document.actions, transaction.actions)
    package = load_package_verifier()
    dpkg = load_dpkg_state_verifier()

    def capture_and_verify_package_state() -> bytes:
        require_operation_deadline(deadline, "APT hook verification")
        try:
            state_raw = package.serialize_system_state(
                package.capture_system_state(deadline=deadline)
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise AptTransactionError(
                "cannot capture package state at the APT hook boundary"
            ) from exc
        state_digest = hashlib.sha256(state_raw).hexdigest()
        if not hmac.compare_digest(
            state_digest, transaction.package_state_sha256
        ):
            raise AptTransactionError(
                "package state differs from the expected transaction"
            )
        require_operation_deadline(deadline, "APT hook verification")
        return state_raw

    def capture_and_verify_state():
        require_operation_deadline(deadline, "APT hook verification")
        state = dpkg.capture_dpkg_state(dpkg_admin, expected_uid, expected_gid)
        state_digest = hashlib.sha256(dpkg.serialize_dpkg_state(state)).hexdigest()
        host_digest = hashlib.sha256(
            dpkg.serialize_host_reference(dpkg.host_reference_from_state(state))
        ).hexdigest()
        if not hmac.compare_digest(state_digest, transaction.dpkg_state_sha256):
            raise AptTransactionError("dpkg state differs from the expected transaction")
        if not hmac.compare_digest(
            host_digest, transaction.host_reference_sha256
        ):
            raise AptTransactionError(
                "dpkg host reference differs from the expected transaction"
            )
        require_operation_deadline(deadline, "APT hook verification")
        return state

    def capture_archive_set() -> tuple[ArchiveRecord, ...]:
        records: list[ArchiveRecord] = []
        for expected in transaction.archives:
            require_operation_deadline(deadline, "APT hook verification")
            records.append(
                capture_deb_archive(
                    pathlib.Path(expected.path),
                    expected.uid,
                    expected.gid,
                    deadline=deadline,
                )
            )
            require_operation_deadline(deadline, "APT hook verification")
        return tuple(records)

    initial_package_state = capture_and_verify_package_state()
    initial_state = capture_and_verify_state()
    actual_archives = capture_archive_set()
    if actual_archives != transaction.archives:
        raise AptTransactionError("APT archive identity differs from the manifest")
    verify_archive_actions(actual_archives, document.actions)
    for record in actual_archives:
        verify_apt_readable_archive(
            pathlib.Path(record.path),
            record.sha256,
            record.device,
            record.inode,
            apt_uid,
            apt_gid,
            deadline=deadline,
        )
    final_archives = capture_archive_set()
    if final_archives != actual_archives:
        raise AptTransactionError("APT archive changed during hook verification")
    final_package_state = capture_and_verify_package_state()
    if not hmac.compare_digest(final_package_state, initial_package_state):
        raise AptTransactionError("package state changed during hook verification")
    final_state = capture_and_verify_state()
    dpkg.verify_dpkg_state(final_state, initial_state)
    require_operation_deadline(deadline, "APT hook verification")
    return hashlib.sha256(manifest_raw).hexdigest()


def parse_numeric_id(value: str) -> int:
    if not UNSIGNED.fullmatch(value):
        raise AptTransactionError("hook owner/group id is not canonical")
    number = int(value)
    if number > 2**32 - 1:
        raise AptTransactionError("hook owner/group id exceeds its bound")
    return number


def read_eipp_hook_fd(
    descriptor: int = 21,
    *,
    timeout: float = EIPP_READ_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> bytes:
    if type(descriptor) is not int or descriptor != 21:
        raise AptTransactionError("APT hook descriptor is not exactly 21")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > EIPP_READ_TIMEOUT_SECONDS
    ):
        raise AptTransactionError("APT EIPP hook stream timeout is invalid")
    if deadline is not None and (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise AptTransactionError("APT EIPP hook stream deadline is invalid")
    chunks: list[bytes] = []
    remaining = MAX_EIPP_BYTES + 1
    local_deadline = time.monotonic() + timeout
    deadline = (
        local_deadline if deadline is None else min(local_deadline, float(deadline))
    )
    try:
        while remaining:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise AptTransactionError("APT EIPP hook stream read timed out")
            ready, _, _ = select.select((descriptor,), (), (), remaining_time)
            if not ready:
                raise AptTransactionError("APT EIPP hook stream read timed out")
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except AptTransactionError:
        raise
    except OSError as exc:
        raise AptTransactionError(f"cannot read the APT EIPP hook stream: {exc}") from exc
    raw = b"".join(chunks)
    if not raw or len(raw) > MAX_EIPP_BYTES:
        raise AptTransactionError("APT EIPP hook stream is empty or oversized")
    return raw


def private_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def cleanup_owned_publication(
    parent_descriptor: int,
    ownership: PublishedFileOwnership,
    names: tuple[tuple[str, str], ...],
    label: str,
    directory_role: str,
) -> tuple[str, ...]:
    cleanup_notes: list[str] = []
    created_identity = (ownership.device, ownership.inode)
    identity_is_pinned = False
    try:
        pinned = os.fstat(ownership.descriptor)
    except BaseException:
        cleanup_notes.append(
            f"{label} cleanup could not inspect owned publication inode"
        )
    else:
        if (pinned.st_dev, pinned.st_ino) == created_identity:
            identity_is_pinned = True
        else:
            cleanup_notes.append(
                f"{label} cleanup found the publication descriptor changed"
            )
    if identity_is_pinned:
        for role, name in names:
            try:
                current = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except BaseException:
                cleanup_notes.append(f"{label} cleanup could not inspect {role}")
                continue
            if (current.st_dev, current.st_ino) == created_identity:
                try:
                    os.unlink(name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
                except BaseException:
                    cleanup_notes.append(f"{label} cleanup could not remove {role}")
            else:
                cleanup_notes.append(
                    f"{label} cleanup found the {role} namespace changed"
                )
    try:
        os.fsync(parent_descriptor)
    except BaseException:
        cleanup_notes.append(
            f"{label} cleanup could not synchronize {directory_role}"
        )
    for role, name in names:
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except BaseException:
            cleanup_notes.append(f"{label} cleanup could not confirm {role} removal")
            continue
        if (current.st_dev, current.st_ino) == created_identity:
            cleanup_notes.append(f"{label} cleanup left the {role} inode present")
        else:
            cleanup_notes.append(f"{label} cleanup found the {role} namespace changed")
    return tuple(dict.fromkeys(cleanup_notes))


def cleanup_known_publication(
    parent_descriptor: int,
    device: int,
    inode: int,
    names: tuple[tuple[str, str], ...],
    label: str,
    directory_role: str,
) -> tuple[str, ...]:
    cleanup_notes: list[str] = []
    created_identity = (device, inode)
    for role, name in names:
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except BaseException:
            cleanup_notes.append(f"{label} cleanup could not inspect {role}")
            continue
        if (current.st_dev, current.st_ino) == created_identity:
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except BaseException:
                cleanup_notes.append(f"{label} cleanup could not remove {role}")
        else:
            cleanup_notes.append(
                f"{label} cleanup found the {role} namespace changed"
            )
    try:
        os.fsync(parent_descriptor)
    except BaseException:
        cleanup_notes.append(
            f"{label} cleanup could not synchronize {directory_role}"
        )
    for role, name in names:
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except BaseException:
            cleanup_notes.append(f"{label} cleanup could not confirm {role} removal")
            continue
        if (current.st_dev, current.st_ino) == created_identity:
            cleanup_notes.append(f"{label} cleanup left the {role} inode present")
        else:
            cleanup_notes.append(f"{label} cleanup found the {role} namespace changed")
    return tuple(dict.fromkeys(cleanup_notes))


def add_cleanup_notes(primary: BaseException, notes: tuple[str, ...]) -> None:
    for note in notes:
        primary.add_note(note)


FIXED_CLI_CLEANUP_NOTES = frozenset(
    {
        "APT transaction manifest cleanup lost the owned manifest directory",
        *(
            f"{label} cleanup could not inspect owned publication inode"
            for label in ("APT transaction manifest", "APT hook marker")
        ),
        *(
            f"{label} cleanup found the publication descriptor changed"
            for label in ("APT transaction manifest", "APT hook marker")
        ),
        *(
            note
            for label, roles in (
                ("APT transaction manifest", ("published manifest",)),
                (
                    "APT hook marker",
                    ("published marker", "temporary marker"),
                ),
            )
            for role in roles
            for note in (
                f"{label} cleanup could not inspect {role}",
                f"{label} cleanup could not remove {role}",
                f"{label} cleanup could not confirm {role} removal",
                f"{label} cleanup left the {role} inode present",
                f"{label} cleanup found the {role} namespace changed",
            )
        ),
        "APT transaction manifest cleanup could not synchronize manifest directory",
        "APT hook marker cleanup could not synchronize marker directory",
        "APT transaction manifest cleanup could not close publication descriptor",
        "APT transaction manifest cleanup could not close parent directory descriptor",
        "APT hook marker cleanup could not close publication descriptor",
        "APT hook marker cleanup could not close parent directory descriptor",
    }
)


def format_cli_failure(prefix: str, failure: BaseException) -> str:
    lines = [f"{prefix}: {failure}"]
    for note in dict.fromkeys(getattr(failure, "__notes__", ())):
        if type(note) is str and note in FIXED_CLI_CLEANUP_NOTES:
            lines.append(f"{prefix} cleanup: {note}")
    return "\n".join(lines)


def release_publication_ownership(
    ownership: PublishedFileOwnership,
    label: str,
    primary: BaseException | None,
    *,
    rollback_parent_descriptor: int,
    rollback_names: tuple[tuple[str, str], ...],
    rollback_directory_role: str,
) -> None:
    if (
        type(rollback_parent_descriptor) is not int
        or rollback_parent_descriptor < 0
        or not rollback_names
        or any(
            type(role) is not str
            or not role
            or type(name) is not str
            or not name
            for role, name in rollback_names
        )
        or type(rollback_directory_role) is not str
        or not rollback_directory_role
    ):
        raise AptTransactionError("publication release rollback inputs are invalid")

    rollback_descriptor = -1
    rollback_parent = -1
    rollback_ownership: PublishedFileOwnership | None = None
    cleanup_descriptor = -1
    cleanup_parent = -1
    terminal_parent = -1
    cleanup_ownership: PublishedFileOwnership | None = None
    terminal_parent_path: pathlib.Path | None = None
    terminal_parent_identity: tuple[int, ...] | None = None
    duplication_mask: frozenset[signal.Signals] | None = None
    duplication_mask_owned = False

    def close_release_descriptor(
        descriptor: int,
        role: str,
        current: BaseException | None,
    ) -> tuple[BaseException | None, bool]:
        close_failure, closed = close_owned_descriptor(
            descriptor,
            f"{label} {role}",
        )
        if close_failure is None:
            return current, closed
        note = f"{label} cleanup could not close {role} descriptor"
        if current is None:
            if isinstance(close_failure, Exception):
                current = AptTransactionError(f"cannot release {label} ownership")
                current.__cause__ = close_failure
                current.add_note(note)
                return current, closed
            close_failure.add_note(note)
            return close_failure, closed
        return (
            choose_cleanup_failure(current, close_failure, note),
            closed,
        )

    if primary is None:
        try:
            duplication_mask = block_cleanup_signals(
                f"{label} rollback duplication"
            )
            duplication_mask_owned = True
            rollback_descriptor = duplicate_owned_descriptor(
                ownership.descriptor,
                f"{label} rollback publication",
            )
            rollback_parent = duplicate_owned_descriptor(
                rollback_parent_descriptor,
                f"{label} rollback parent directory",
            )
            pinned = os.fstat(rollback_descriptor)
            if (pinned.st_dev, pinned.st_ino) != (
                ownership.device,
                ownership.inode,
            ):
                raise AptTransactionError(
                    f"{label} rollback publication descriptor changed"
                )
            rollback_ownership = PublishedFileOwnership(
                rollback_descriptor,
                ownership.device,
                ownership.inode,
                rollback_parent,
            )
            cleanup_descriptor = duplicate_owned_descriptor(
                rollback_descriptor,
                f"{label} cleanup publication",
            )
            cleanup_parent = duplicate_owned_descriptor(
                rollback_parent,
                f"{label} cleanup parent directory",
            )
            terminal_parent = duplicate_owned_descriptor(
                cleanup_parent,
                f"{label} terminal parent directory",
            )
            cleanup_pinned = os.fstat(cleanup_descriptor)
            if (cleanup_pinned.st_dev, cleanup_pinned.st_ino) != (
                ownership.device,
                ownership.inode,
            ):
                raise AptTransactionError(
                    f"{label} cleanup publication descriptor changed"
                )
            cleanup_ownership = PublishedFileOwnership(
                cleanup_descriptor,
                ownership.device,
                ownership.inode,
                cleanup_parent,
            )
            terminal_state = os.fstat(terminal_parent)
            terminal_parent_identity = private_file_identity(terminal_state)
            terminal_parent_path = pathlib.Path(
                os.readlink(f"/proc/self/fd/{terminal_parent}")
            )
            if (
                not terminal_parent_path.is_absolute()
                or len(os.fsencode(terminal_parent_path)) > MAX_PRIVATE_PATH_BYTES
                or private_file_identity(
                    os.stat(terminal_parent_path, follow_symlinks=False)
                )
                != terminal_parent_identity
            ):
                raise AptTransactionError(
                    f"{label} terminal rollback directory changed"
                )
            restore_failure, restored = restore_signal_mask(
                duplication_mask,
                f"{label} rollback duplication signal mask",
            )
            duplication_mask_owned = not restored
            if restore_failure is not None:
                raise restore_failure
            if not restored:
                raise AptTransactionError(
                    f"{label} rollback duplication signal-mask restoration "
                    "did not converge"
                )
        except BaseException as exc:
            if isinstance(exc, Exception):
                failure: BaseException = AptTransactionError(
                    f"cannot preserve {label} release rollback ownership"
                )
            else:
                failure = exc
            if duplication_mask_owned and duplication_mask is not None:
                restore_failure, restored = restore_signal_mask(
                    duplication_mask,
                    f"{label} rollback duplication signal mask",
                )
                duplication_mask_owned = not restored
                if restore_failure is not None:
                    failure = choose_cleanup_failure(
                        failure,
                        restore_failure,
                        f"{label} rollback duplication signal-mask cleanup "
                        "also failed",
                    )
                if not restored:
                    failure = choose_cleanup_failure(
                        failure,
                        AptTransactionError(
                            f"{label} rollback duplication signal-mask cleanup "
                            "did not converge"
                        ),
                        f"{label} rollback duplication signal-mask cleanup also "
                        "did not converge",
                    )
            notes = cleanup_owned_publication(
                rollback_parent_descriptor,
                ownership,
                rollback_names,
                label,
                rollback_directory_role,
            )
            add_cleanup_notes(failure, notes)
            selected: BaseException = failure
            try:
                release_publication_ownership(
                    ownership,
                    label,
                    failure,
                    rollback_parent_descriptor=rollback_parent_descriptor,
                    rollback_names=rollback_names,
                    rollback_directory_role=rollback_directory_role,
                )
            except BaseException as release_exc:
                selected = choose_cleanup_failure(
                    selected,
                    release_exc,
                    f"{label} release cleanup also failed",
                )
            for role, descriptor in (
                ("publication", rollback_descriptor),
                ("parent directory", rollback_parent),
                ("publication", cleanup_descriptor),
                ("parent directory", cleanup_parent),
                ("parent directory", terminal_parent),
            ):
                if descriptor < 0:
                    continue
                selected, _ = close_release_descriptor(
                    descriptor,
                    role,
                    selected,
                )
                assert selected is not None
            if selected is failure:
                if failure is exc:
                    raise
                raise failure from exc
            raise selected

    release_failure: BaseException | None = primary
    descriptors = [("publication", ownership.descriptor)]
    if ownership.parent_descriptor is not None:
        descriptors.append(("parent directory", ownership.parent_descriptor))
    for role, descriptor in descriptors:
        release_failure, _ = close_release_descriptor(
            descriptor,
            role,
            release_failure,
        )
    if primary is None and release_failure is not None:
        if rollback_ownership is not None:
            rollback_notes = cleanup_owned_publication(
                rollback_parent,
                rollback_ownership,
                rollback_names,
                label,
                rollback_directory_role,
            )
            add_cleanup_notes(release_failure, rollback_notes)

    rollback_failure_before_close = release_failure
    for role, descriptor in (
        ("publication", rollback_descriptor),
        ("parent directory", rollback_parent),
    ):
        if descriptor < 0:
            continue
        release_failure, _ = close_release_descriptor(
            descriptor,
            role,
            release_failure,
        )
    if (
        rollback_failure_before_close is None
        and release_failure is not None
        and cleanup_ownership is not None
    ):
        rollback_notes = cleanup_owned_publication(
            cleanup_parent,
            cleanup_ownership,
            rollback_names,
            label,
            rollback_directory_role,
        )
        add_cleanup_notes(release_failure, rollback_notes)

    for role, descriptor in (
        ("publication", cleanup_descriptor),
        ("parent directory", cleanup_parent),
    ):
        if descriptor < 0:
            continue
        cleanup_failure_before_close = release_failure
        release_failure, _ = close_release_descriptor(
            descriptor,
            role,
            release_failure,
        )
        if cleanup_failure_before_close is not None or release_failure is None:
            continue
        rollback_directory = (
            cleanup_parent
            if role == "publication"
            else terminal_parent
        )
        try:
            parent_state = os.fstat(rollback_directory)
        except BaseException as exc:
            release_failure = choose_cleanup_failure(
                release_failure,
                fixed_cleanup_candidate(
                    exc,
                    f"cannot retain {label} rollback directory custody",
                ),
                f"{label} rollback directory custody also failed",
            )
        else:
            if stat.S_ISDIR(parent_state.st_mode):
                rollback_notes = cleanup_known_publication(
                    rollback_directory,
                    ownership.device,
                    ownership.inode,
                    rollback_names,
                    label,
                    rollback_directory_role,
                )
                add_cleanup_notes(release_failure, rollback_notes)
    terminal_failure_before_close = release_failure
    if terminal_parent >= 0:
        release_failure, _ = close_release_descriptor(
            terminal_parent,
            "parent directory",
            release_failure,
        )
    if terminal_failure_before_close is None and release_failure is not None:
        if terminal_parent_path is None or terminal_parent_identity is None:
            release_failure = choose_cleanup_failure(
                release_failure,
                AptTransactionError(
                    f"{label} terminal rollback directory ownership is missing"
                ),
                f"{label} terminal rollback directory cleanup also failed",
            )
        else:
            reopen_descriptor = -1
            reopen_mask: frozenset[signal.Signals] | None = None
            reopen_mask_owned = False
            try:
                reopen_mask = block_cleanup_signals(
                    f"{label} terminal rollback reopen"
                )
                reopen_mask_owned = True
                reopen_descriptor = open_owned_directory(
                    terminal_parent_path,
                    terminal_parent_identity,
                    f"{label} terminal rollback directory",
                )
                rollback_notes = cleanup_known_publication(
                    reopen_descriptor,
                    ownership.device,
                    ownership.inode,
                    rollback_names,
                    label,
                    rollback_directory_role,
                )
                add_cleanup_notes(release_failure, rollback_notes)
            except BaseException as exc:
                release_failure = choose_cleanup_failure(
                    release_failure,
                    fixed_cleanup_candidate(
                        exc,
                        f"cannot complete {label} terminal rollback",
                    ),
                    f"{label} terminal rollback also failed",
                )
            if reopen_descriptor >= 0:
                release_failure, _ = close_release_descriptor(
                    reopen_descriptor,
                    "terminal rollback directory",
                    release_failure,
                )
            if reopen_mask_owned and reopen_mask is not None:
                restore_failure, restored = restore_signal_mask(
                    reopen_mask,
                    f"{label} terminal rollback reopen signal mask",
                )
                reopen_mask_owned = not restored
                if restore_failure is not None:
                    release_failure = choose_cleanup_failure(
                        release_failure,
                        restore_failure,
                        f"{label} terminal rollback signal-mask cleanup also failed",
                    )
                if not restored:
                    release_failure = choose_cleanup_failure(
                        release_failure,
                        AptTransactionError(
                            f"{label} terminal rollback signal-mask cleanup did not "
                            "converge"
                        ),
                        f"{label} terminal rollback signal-mask cleanup also did not "
                        "converge",
                    )
    if primary is None and release_failure is not None:
        raise release_failure


def cleanup_private_manifest_publication(
    path: pathlib.Path,
    ownership: PublishedFileOwnership,
    primary: BaseException,
) -> None:
    if ownership.parent_descriptor is None:
        primary.add_note(
            "APT transaction manifest cleanup lost the owned manifest directory"
        )
        return
    notes = cleanup_owned_publication(
        ownership.parent_descriptor,
        ownership,
        (("published manifest", path.name),),
        "APT transaction manifest",
        "manifest directory",
    )
    add_cleanup_notes(primary, notes)


def open_private_manifest(
    manifest_path: pathlib.Path,
    marker_path: pathlib.Path,
) -> tuple[int, int, bytes, tuple[int, ...], tuple[int, ...]]:
    if (
        type(manifest_path) is not pathlib.PosixPath
        or type(marker_path) is not pathlib.PosixPath
        or not manifest_path.is_absolute()
        or not marker_path.is_absolute()
        or manifest_path == marker_path
        or manifest_path.parent != marker_path.parent
        or len(os.fsencode(manifest_path)) > MAX_PRIVATE_PATH_BYTES
        or len(os.fsencode(marker_path)) > MAX_PRIVATE_PATH_BYTES
        or manifest_path.name in {"", ".", ".."}
        or marker_path.name in {"", ".", ".."}
    ):
        raise AptTransactionError("APT hook private paths are not canonical")
    parent = manifest_path.parent
    try:
        if parent.resolve(strict=True) != parent:
            raise AptTransactionError("APT hook private directory contains a symlink")
    except OSError as exc:
        raise AptTransactionError(f"cannot resolve APT hook private directory: {exc}") from exc
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(parent, flags)
    except OSError as exc:
        raise AptTransactionError(f"cannot open APT hook private directory: {exc}") from exc
    manifest_descriptor = -1
    try:
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or parent_metadata.st_uid != 0
            or parent_metadata.st_gid != 0
        ):
            raise AptTransactionError("APT hook private directory metadata differs from policy")
        parent_identity = private_file_identity(parent_metadata)
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        manifest_descriptor = os.open(
            manifest_path.name,
            file_flags,
            dir_fd=parent_descriptor,
        )
        before = os.fstat(manifest_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_TRANSACTION_MANIFEST_BYTES
        ):
            raise AptTransactionError("APT hook manifest metadata differs from policy")
        remaining = MAX_TRANSACTION_MANIFEST_BYTES + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(manifest_descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(manifest_descriptor)
        identity = private_file_identity(before)
        if (
            len(raw) != before.st_size
            or len(raw) > MAX_TRANSACTION_MANIFEST_BYTES
            or private_file_identity(after) != identity
        ):
            raise AptTransactionError("APT hook manifest changed while it was read")
        return (
            parent_descriptor,
            manifest_descriptor,
            raw,
            identity,
            parent_identity,
        )
    except BaseException as exc:
        descriptors = tuple(
            descriptor
            for descriptor in (manifest_descriptor, parent_descriptor)
            if descriptor >= 0
        )
        close_descriptors(descriptors, "APT hook manifest", exc)
        raise


def recheck_private_manifest(
    parent_descriptor: int,
    manifest_descriptor: int,
    manifest_path: pathlib.Path,
    expected_raw: bytes,
    expected_identity: tuple[int, ...],
    expected_parent_identity: tuple[int, ...],
) -> None:
    os.lseek(manifest_descriptor, 0, os.SEEK_SET)
    remaining = MAX_TRANSACTION_MANIFEST_BYTES + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(manifest_descriptor, min(remaining, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    current = os.fstat(manifest_descriptor)
    namespace = os.stat(
        manifest_path.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    parent_current = os.fstat(parent_descriptor)
    parent_namespace = os.stat(manifest_path.parent, follow_symlinks=False)
    if (
        b"".join(chunks) != expected_raw
        or private_file_identity(current) != expected_identity
        or private_file_identity(namespace) != expected_identity
    ):
        raise AptTransactionError("APT hook manifest changed before marker creation")
    if (
        private_file_identity(parent_current) != expected_parent_identity
        or private_file_identity(parent_namespace) != expected_parent_identity
        or stat.S_IMODE(parent_current.st_mode) != 0o700
        or parent_current.st_uid != 0
        or parent_current.st_gid != 0
        or manifest_path.parent.resolve(strict=True) != manifest_path.parent
    ):
        raise AptTransactionError(
            "APT hook private directory changed before marker creation"
        )


def write_hook_marker(
    parent_descriptor: int,
    marker_path: pathlib.Path,
    manifest_digest: str,
    *,
    deadline: float,
    retain_ownership: bool = False,
    ownership_slot: PublicationOwnershipSlot | None = None,
) -> PublishedFileOwnership | None:
    if (
        type(retain_ownership) is not bool
        or not SHA256.fullmatch(manifest_digest)
        or (
            retain_ownership
            and (
                type(ownership_slot) is not PublicationOwnershipSlot
                or ownership_slot.ownership is not None
            )
        )
        or (not retain_ownership and ownership_slot is not None)
    ):
        raise AptTransactionError("APT hook marker digest is invalid")

    def checkpoint() -> None:
        require_operation_deadline(deadline, "APT hook verification")

    checkpoint()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    temporary_name = f".{marker_path.name}.tmp"
    publication: PublishedFileOwnership | None = None
    active_exception: BaseException | None = None
    try:
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        checkpoint()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise AptTransactionError("APT hook marker metadata differs from policy")
        raw = (manifest_digest + "\n").encode("ascii")
        written = 0
        while written < len(raw):
            checkpoint()
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise AptTransactionError("APT hook marker write made no progress")
            written += count
            checkpoint()
        os.fsync(descriptor)
        checkpoint()
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != created_identity
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_uid != 0
            or final.st_gid != 0
            or final.st_nlink != 1
            or final.st_size != len(raw)
        ):
            raise AptTransactionError("APT hook marker changed while it was written")
        os.link(
            temporary_name,
            marker_path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        checkpoint()
        linked_marker = os.stat(
            marker_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            (linked_marker.st_dev, linked_marker.st_ino) != created_identity
            or stat.S_IMODE(linked_marker.st_mode) != 0o600
            or linked_marker.st_uid != 0
            or linked_marker.st_gid != 0
            or linked_marker.st_nlink != 2
            or linked_marker.st_size != len(raw)
        ):
            raise AptTransactionError("APT hook marker link differs from policy")
        os.fsync(parent_descriptor)
        checkpoint()
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        checkpoint()
        final_marker = os.stat(
            marker_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            (final_marker.st_dev, final_marker.st_ino) != created_identity
            or stat.S_IMODE(final_marker.st_mode) != 0o600
            or final_marker.st_uid != 0
            or final_marker.st_gid != 0
            or final_marker.st_nlink != 1
            or final_marker.st_size != len(raw)
        ):
            raise AptTransactionError("APT hook marker promotion differs from policy")
        os.fsync(parent_descriptor)
        checkpoint()
        if retain_ownership:
            publication = PublishedFileOwnership(
                descriptor,
                created_identity[0],
                created_identity[1],
                None,
            )
            assert ownership_slot is not None
            ownership_slot.accept(publication)
    except BaseException as exc:
        primary: BaseException
        if isinstance(exc, OSError):
            primary = AptTransactionError(
                f"cannot create or write APT hook marker: {exc}"
            )
        else:
            primary = exc
        active_exception = primary
        transferred = (
            ownership_slot is not None
            and ownership_slot.ownership is not None
            and ownership_slot.ownership.descriptor == descriptor
            and ownership_slot.ownership.parent_descriptor is None
            and (
                ownership_slot.ownership.device,
                ownership_slot.ownership.inode,
            )
            == created_identity
        )
        if created_identity is None and descriptor >= 0 and not transferred:
            try:
                recovered = os.fstat(descriptor)
            except BaseException:
                primary.add_note(
                    "APT hook marker cleanup could not inspect owned publication "
                    "inode"
                )
            else:
                created_identity = (recovered.st_dev, recovered.st_ino)
        if created_identity is not None and not transferred:
            marker_ownership = PublishedFileOwnership(
                descriptor,
                created_identity[0],
                created_identity[1],
                None,
            )
            notes = cleanup_owned_publication(
                parent_descriptor,
                marker_ownership,
                (
                    ("published marker", marker_path.name),
                    ("temporary marker", temporary_name),
                ),
                "APT hook marker",
                "marker directory",
            )
            add_cleanup_notes(primary, notes)
        if primary is exc:
            raise
        raise primary from exc
    finally:
        transferred = (
            ownership_slot is not None
            and ownership_slot.ownership is not None
            and ownership_slot.ownership.descriptor == descriptor
            and ownership_slot.ownership.parent_descriptor is None
            and (
                ownership_slot.ownership.device,
                ownership_slot.ownership.inode,
            )
            == created_identity
        )
        if descriptor >= 0 and not transferred:
            close_failure, _ = close_owned_descriptor(
                descriptor,
                "APT hook marker publication",
            )
            if close_failure is not None:
                note = (
                    "APT hook marker cleanup could not close publication descriptor"
                )
                if created_identity is not None:
                    notes = cleanup_known_publication(
                        parent_descriptor,
                        created_identity[0],
                        created_identity[1],
                        (
                            ("published marker", marker_path.name),
                            ("temporary marker", temporary_name),
                        ),
                        "APT hook marker",
                        "marker directory",
                    )
                else:
                    notes = ()
                if active_exception is None and isinstance(close_failure, Exception):
                    selected: BaseException = AptTransactionError(
                        "cannot close APT hook marker publication descriptor"
                    )
                    selected.__cause__ = close_failure
                    selected.add_note(note)
                else:
                    selected = choose_cleanup_failure(
                        active_exception,
                        close_failure,
                        note,
                    )
                add_cleanup_notes(selected, notes)
                if selected is not active_exception:
                    raise selected
            descriptor = -1
    if (
        retain_ownership
        and (
            publication is None
            or ownership_slot is None
            or ownership_slot.ownership is not publication
        )
    ):
        raise AptTransactionError("APT hook marker publication ownership is missing")
    return publication


def verify_hook_marker(
    manifest_path: pathlib.Path,
    marker_path: pathlib.Path,
) -> str:
    (
        parent_descriptor,
        manifest_descriptor,
        manifest_raw,
        manifest_identity,
        parent_identity,
    ) = open_private_manifest(manifest_path, marker_path)
    marker_descriptor = -1
    try:
        expected_digest = hashlib.sha256(manifest_raw).hexdigest()
        expected_raw = (expected_digest + "\n").encode("ascii")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            marker_descriptor = os.open(
                marker_path.name,
                flags,
                dir_fd=parent_descriptor,
            )
            before = os.fstat(marker_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != 0
                or before.st_gid != 0
                or before.st_nlink != 1
                or before.st_size != len(expected_raw)
            ):
                raise AptTransactionError(
                    "APT hook marker metadata differs from policy"
                )
            marker_raw = os.read(marker_descriptor, len(expected_raw) + 1)
            after = os.fstat(marker_descriptor)
            namespace = os.stat(
                marker_path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except AptTransactionError:
            raise
        except OSError as exc:
            raise AptTransactionError(f"cannot read APT hook marker: {exc}") from exc
        if (
            marker_raw != expected_raw
            or private_file_identity(before) != private_file_identity(after)
            or private_file_identity(after) != private_file_identity(namespace)
        ):
            raise AptTransactionError("APT hook marker differs from the manifest")
        recheck_private_manifest(
            parent_descriptor,
            manifest_descriptor,
            manifest_path,
            manifest_raw,
            manifest_identity,
            parent_identity,
        )
        return expected_digest
    finally:
        descriptors = tuple(
            descriptor
            for descriptor in (
                marker_descriptor,
                manifest_descriptor,
                parent_descriptor,
            )
            if descriptor >= 0
        )
        close_descriptors(descriptors, "APT hook marker verification", sys.exception())


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify-hook", nargs=2, metavar=("MANIFEST", "MARKER"))
    modes.add_argument(
        "--verify-hook-disposable",
        nargs=5,
        metavar=("ADMIN", "UID", "GID", "MANIFEST", "MARKER"),
    )
    modes.add_argument(
        "--prepare-manifest",
        nargs=9,
        metavar=(
            "COMMAND",
            "LOCK",
            "PACKAGE_STATE",
            "PLAN",
            "DPKG_STATE",
            "HOST_REFERENCE",
            "APT_ARCHIVES",
            "COMPAT_ARCHIVES",
            "MANIFEST",
        ),
    )
    modes.add_argument(
        "--prepare-manifest-runtime-reference",
        nargs=9,
        metavar=(
            "COMMAND",
            "LOCK",
            "PACKAGE_STATE",
            "PLAN",
            "DPKG_STATE",
            "HOST_REFERENCE",
            "APT_ARCHIVES",
            "COMPAT_ARCHIVES",
            "MANIFEST",
        ),
    )
    modes.add_argument(
        "--prepare-manifest-disposable",
        nargs=12,
        metavar=(
            "ADMIN",
            "UID",
            "GID",
            "COMMAND",
            "LOCK",
            "PACKAGE_STATE",
            "PLAN",
            "DPKG_STATE",
            "HOST_REFERENCE",
            "APT_ARCHIVES",
            "COMPAT_ARCHIVES",
            "MANIFEST",
        ),
    )
    modes.add_argument(
        "--verify-marker",
        nargs=2,
        metavar=("MANIFEST", "MARKER"),
    )
    modes.add_argument(
        "--verify-post",
        nargs=2,
        metavar=("MANIFEST", "DPKG_STATE"),
    )
    modes.add_argument(
        "--verify-post-disposable",
        nargs=5,
        metavar=("ADMIN", "UID", "GID", "MANIFEST", "DPKG_STATE"),
    )
    arguments = parser.parse_args()
    if arguments.verify_marker is not None:
        if os.geteuid() != 0:
            raise SystemExit("APT hook marker verification requires root")
        try:
            manifest_text, marker_text = arguments.verify_marker
            verify_hook_marker(
                pathlib.Path(manifest_text), pathlib.Path(marker_text)
            )
        except (OSError, ValueError) as exc:
            raise SystemExit(
                f"haptics APT hook marker verification failed: {exc}"
            ) from exc
        print("HAPTICS_APT_MARKER=PASS")
        return
    post = (
        arguments.verify_post
        if arguments.verify_post is not None
        else arguments.verify_post_disposable
    )
    if post is not None:
        try:
            if arguments.verify_post is not None:
                dpkg_admin = pathlib.Path("/var/lib/dpkg")
                expected_uid = 0
                expected_gid = 0
                manifest_text, dpkg_state_text = post
            else:
                (
                    admin_text,
                    uid_text,
                    gid_text,
                    manifest_text,
                    dpkg_state_text,
                ) = post
                dpkg_admin = pathlib.Path(admin_text)
                expected_uid = parse_numeric_id(uid_text)
                expected_gid = parse_numeric_id(gid_text)
            manifest_path = pathlib.Path(manifest_text)
            dpkg_state_path = pathlib.Path(dpkg_state_text)
            if (
                not dpkg_admin.is_absolute()
                or not manifest_path.is_absolute()
                or not dpkg_state_path.is_absolute()
            ):
                raise AptTransactionError(
                    "APT post-transaction paths must be absolute"
                )
            dpkg = load_dpkg_state_verifier()
            manifest_raw = dpkg.read_regular(
                manifest_path,
                0o600,
                expected_uid,
                expected_gid,
                MAX_TRANSACTION_MANIFEST_BYTES,
                "APT transaction manifest",
            )
            dpkg_state_raw = dpkg.read_regular(
                dpkg_state_path,
                0o600,
                expected_uid,
                expected_gid,
                MAX_DPKG_STATE_BYTES,
                "dpkg pre-transaction state",
            )
            verify_post_transaction(
                manifest_raw,
                dpkg_state_raw,
                dpkg_admin,
                expected_uid,
                expected_gid,
            )
        except (OSError, ValueError) as exc:
            raise SystemExit(
                f"haptics APT post-transaction verification failed: {exc}"
            ) from exc
        print("HAPTICS_APT_POST_STATE=PASS")
        return
    production_preparation = (
        arguments.prepare_manifest
        if arguments.prepare_manifest is not None
        else arguments.prepare_manifest_runtime_reference
    )
    preparation = (
        production_preparation
        if production_preparation is not None
        else arguments.prepare_manifest_disposable
    )
    if preparation is not None:
        preparation_deadline = time.monotonic() + PREPARATION_TIMEOUT_SECONDS
        try:
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            if production_preparation is not None:
                dpkg_admin = pathlib.Path("/var/lib/dpkg")
                expected_uid = 0
                expected_gid = 0
                (
                    hook_command,
                    package_lock_text,
                    package_state_text,
                    host_plan_text,
                    dpkg_state_text,
                    host_reference_text,
                    apt_archives_text,
                    compat_archives_text,
                    manifest_text,
                ) = preparation
            else:
                (
                    admin_text,
                    uid_text,
                    gid_text,
                    hook_command,
                    package_lock_text,
                    package_state_text,
                    host_plan_text,
                    dpkg_state_text,
                    host_reference_text,
                    apt_archives_text,
                    compat_archives_text,
                    manifest_text,
                ) = preparation
                dpkg_admin = pathlib.Path(admin_text)
                expected_uid = parse_numeric_id(uid_text)
                expected_gid = parse_numeric_id(gid_text)
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            evidence = tuple(
                pathlib.Path(value)
                for value in (
                    package_lock_text,
                    package_state_text,
                    host_plan_text,
                    dpkg_state_text,
                    host_reference_text,
                )
            )
            archive_directories = (
                pathlib.Path(apt_archives_text),
                pathlib.Path(compat_archives_text),
            )
            manifest_path = pathlib.Path(manifest_text)
            if (
                not dpkg_admin.is_absolute()
                or any(not path.is_absolute() for path in evidence)
                or any(not path.is_absolute() for path in archive_directories)
                or not manifest_path.is_absolute()
            ):
                raise AptTransactionError(
                    "APT transaction preparation paths must be absolute"
                )
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            dpkg = load_dpkg_state_verifier()
            bounds = (
                MAX_PACKAGE_LOCK_BYTES,
                MAX_PACKAGE_STATE_BYTES,
                MAX_HOST_PLAN_BYTES,
                MAX_DPKG_STATE_BYTES,
                MAX_DPKG_STATE_BYTES,
            )
            labels = (
                "package lock",
                "package pre-transaction state",
                "host APT plan",
                "dpkg pre-transaction state",
                "dpkg host reference",
            )
            raw_evidence_list: list[bytes] = []
            for path, maximum, label in zip(evidence, bounds, labels):
                require_operation_deadline(
                    preparation_deadline, "APT transaction preparation"
                )
                raw_evidence_list.append(
                    dpkg.read_regular(
                        path,
                        0o600,
                        expected_uid,
                        expected_gid,
                        maximum,
                        label,
                    )
                )
                require_operation_deadline(
                    preparation_deadline, "APT transaction preparation"
                )
            raw_evidence = tuple(raw_evidence_list)
            if arguments.prepare_manifest is not None:
                require_operation_deadline(
                    preparation_deadline, "APT transaction preparation"
                )
                verify_host_reference_trust_anchor(raw_evidence[4])
                require_operation_deadline(
                    preparation_deadline, "APT transaction preparation"
                )
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            status_raw = dpkg.read_regular(
                dpkg_admin / "status",
                0o644,
                expected_uid,
                expected_gid,
                MAX_DPKG_STATE_BYTES,
                "dpkg status",
            )
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            archive_paths = enumerate_archive_paths(
                archive_directories,
                expected_uid,
                expected_gid,
                deadline=preparation_deadline,
            )
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            transaction = prepare_expected_transaction(
                hook_command,
                *raw_evidence[:3],
                raw_evidence[3],
                raw_evidence[4],
                status_raw,
                archive_paths,
                dpkg_admin,
                expected_uid,
                expected_gid,
                deadline=preparation_deadline,
            )
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            if enumerate_archive_paths(
                archive_directories,
                expected_uid,
                expected_gid,
                deadline=preparation_deadline,
            ) != archive_paths:
                raise AptTransactionError(
                    "APT archive path closure changed during manifest preparation"
                )
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            manifest_raw = serialize_expected_transaction(transaction)
            require_operation_deadline(
                preparation_deadline, "APT transaction preparation"
            )
            manifest_slot = PublicationOwnershipSlot()
            try:
                try:
                    manifest_publication = write_private_manifest(
                        manifest_path,
                        manifest_raw,
                        expected_uid,
                        expected_gid,
                        deadline=preparation_deadline,
                        retain_ownership=True,
                        ownership_slot=manifest_slot,
                    )
                    if (
                        manifest_publication is None
                        or manifest_slot.ownership is not manifest_publication
                    ):
                        raise AptTransactionError(
                            "private APT transaction manifest publication ownership "
                            "is missing"
                        )
                    require_operation_deadline(
                        preparation_deadline, "APT transaction preparation"
                    )
                except BaseException as exc:
                    if manifest_slot.ownership is not None:
                        cleanup_private_manifest_publication(
                            manifest_path,
                            manifest_slot.ownership,
                            exc,
                        )
                    raise
            finally:
                if manifest_slot.ownership is not None:
                    if manifest_slot.ownership.parent_descriptor is None:
                        raise AptTransactionError(
                            "private APT transaction manifest publication ownership "
                            "lost its parent directory"
                        )
                    release_publication_ownership(
                        manifest_slot.ownership,
                        "APT transaction manifest",
                        sys.exception(),
                        rollback_parent_descriptor=(
                            manifest_slot.ownership.parent_descriptor
                        ),
                        rollback_names=(("published manifest", manifest_path.name),),
                        rollback_directory_role="manifest directory",
                    )
        except (OSError, ValueError) as exc:
            raise SystemExit(
                format_cli_failure(
                    "haptics APT manifest preparation failed", exc
                )
            ) from exc
        print("HAPTICS_APT_MANIFEST=PASS")
        return
    if os.environ.get("APT_HOOK_INFO_FD") != "21":
        raise SystemExit("APT_HOOK_INFO_FD must be exactly 21")
    try:
        if arguments.verify_hook is not None:
            dpkg_admin = pathlib.Path("/var/lib/dpkg")
            expected_uid = 0
            expected_gid = 0
            manifest_text, marker_text = arguments.verify_hook
        else:
            (
                admin_text,
                uid_text,
                gid_text,
                manifest_text,
                marker_text,
            ) = arguments.verify_hook_disposable
            dpkg_admin = pathlib.Path(admin_text)
            expected_uid = parse_numeric_id(uid_text)
            expected_gid = parse_numeric_id(gid_text)
        manifest_path = pathlib.Path(manifest_text)
        marker_path = pathlib.Path(marker_text)
        hook_deadline = time.monotonic() + HOOK_VERIFICATION_TIMEOUT_SECONDS
        eipp_raw = read_eipp_hook_fd(deadline=hook_deadline)
        require_operation_deadline(hook_deadline, "APT hook verification")
        (
            parent_descriptor,
            manifest_descriptor,
            manifest_raw,
            manifest_identity,
            parent_identity,
        ) = open_private_manifest(manifest_path, marker_path)
        try:
            apt_account = pwd.getpwnam("_apt")
            manifest_digest = verify_hook_inputs(
                eipp_raw,
                manifest_raw,
                dpkg_admin,
                expected_uid,
                expected_gid,
                apt_account.pw_uid,
                apt_account.pw_gid,
                deadline=hook_deadline,
            )
            require_operation_deadline(hook_deadline, "APT hook verification")
            recheck_private_manifest(
                parent_descriptor,
                manifest_descriptor,
                manifest_path,
                manifest_raw,
                manifest_identity,
                parent_identity,
            )
            marker_slot = PublicationOwnershipSlot()
            try:
                try:
                    marker_publication = write_hook_marker(
                        parent_descriptor,
                        marker_path,
                        manifest_digest,
                        deadline=hook_deadline,
                        retain_ownership=True,
                        ownership_slot=marker_slot,
                    )
                    if (
                        marker_publication is None
                        or marker_slot.ownership is not marker_publication
                    ):
                        raise AptTransactionError(
                            "APT hook marker publication ownership is missing"
                        )
                    require_operation_deadline(
                        hook_deadline, "APT hook verification"
                    )
                except BaseException as exc:
                    if marker_slot.ownership is not None:
                        notes = cleanup_owned_publication(
                            parent_descriptor,
                            marker_slot.ownership,
                            (("published marker", marker_path.name),),
                            "APT hook marker",
                            "marker directory",
                        )
                        add_cleanup_notes(exc, notes)
                    raise
            finally:
                if marker_slot.ownership is not None:
                    release_publication_ownership(
                        marker_slot.ownership,
                        "APT hook marker",
                        sys.exception(),
                        rollback_parent_descriptor=parent_descriptor,
                        rollback_names=(("published marker", marker_path.name),),
                        rollback_directory_role="marker directory",
                    )
        finally:
            close_descriptors(
                (manifest_descriptor, parent_descriptor),
                "APT hook verification",
                sys.exception(),
            )
    except (OSError, ValueError) as exc:
        raise SystemExit(
            format_cli_failure("haptics APT hook verification failed", exc)
        ) from exc
    print("HAPTICS_APT_HOOK=PASS")


if __name__ == "__main__":
    main()
