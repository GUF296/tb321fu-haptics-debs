#!/usr/bin/env python3
"""Authenticate, seal, and execute a rendered workflow-dispatch launcher.

The renderer publishes a mutable pathname plus a SHA-256 digest.  This
production consumer reopens and authenticates that inode, copies only those
bytes to a sealed memfd, and executes the memfd through an isolated Python
interpreter.  No launcher evidence is emitted until process and descriptor
custody, signal restoration, and descendant cleanup have converged.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import math
import os
import pathlib
import pwd
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import threading
import time


PYTHON = "/usr/bin/python3"
MAX_LAUNCHER_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_LAUNCHER_FILE_BYTES = 2 * 1024 * 1024
MAX_FD_ENTRIES = 4096
MAX_DIRECT_CHILDREN = 4096
MAX_CHILDREN_RECORD_BYTES = 128 * 1024
PIDFD_BATCH = 32
PIDFD_PREFLIGHT = PIDFD_BATCH + 4
WAIT_SLICE_SECONDS = 0.05
CLEANUP_SECONDS = 5.0
MAX_CLEANUP_PASSES = (MAX_DIRECT_CHILDREN // PIDFD_BATCH) + 64
MAX_PROCESS_WAIT_PASSES = math.ceil(CLEANUP_SECONDS / WAIT_SLICE_SECONDS)
MAX_IO_INTERRUPTS = 3
MAX_PENDING_SIGNAL_DRAIN = 16
DEFAULT_TIMEOUT_SECONDS = 330.0
OUTPUT_WRITE_SECONDS = 5.0
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
SA_NOCLDWAIT = 2
LINUX_SIGSET_BITS = 1024
NATIVE_WORD_BITS = 8 * ctypes.sizeof(ctypes.c_ulong)
KERNEL_SIGSET_BITS = int(signal.NSIG) - 1
KERNEL_SIGSET_WORDS = (
    KERNEL_SIGSET_BITS + NATIVE_WORD_BITS - 1
) // NATIVE_WORD_BITS
SHA256 = re.compile(r"[0-9a-f]{64}")
MEMFD_NAME = "tb321fu-haptics-workflow-bootstrap"
REQUIRED_SEALS = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)
_ORIGINAL_SCANDIR = os.scandir


class RunnerError(Exception):
    """A fixed-domain, fail-closed launcher-runner failure."""


@dataclass
class RunnerSignal(BaseException):
    signum: int


@dataclass(frozen=True)
class BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass
class DescriptorOwner:
    descriptor: int = -1


@dataclass
class PopenOwner:
    process: subprocess.Popen[bytes] | None = None


@dataclass
class SubreaperOwner:
    previous: bool | None = None
    restore_required: bool = False


class LinuxSigset(ctypes.Structure):
    _fields_ = [
        (
            "words",
            ctypes.c_ulong
            * (LINUX_SIGSET_BITS // (8 * ctypes.sizeof(ctypes.c_ulong))),
        ),
    ]


class LinuxSigaction(ctypes.Structure):
    _fields_ = [
        ("handler", ctypes.c_void_p),
        ("mask", LinuxSigset),
        ("flags", ctypes.c_int),
        ("restorer", ctypes.c_void_p),
    ]


class NativeSignalSet(ctypes.Structure):
    _fields_ = [("bits", ctypes.c_ulong * 16)]


def decode_native_signal_mask(mask: NativeSignalSet) -> frozenset[int]:
    libc = ctypes.CDLL(None, use_errno=True)
    decoded: set[int] = set()
    for signum in signal.valid_signals():
        member = libc.sigismember(ctypes.byref(mask), int(signum))
        if member == 1:
            decoded.add(int(signum))
        elif member != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    return frozenset(decoded)


def atomic_capture_and_block(
    signals: frozenset[signal.Signals],
    old_mask: NativeSignalSet,
    applied: list[bool],
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    new_mask = NativeSignalSet()
    if libc.sigemptyset(ctypes.byref(new_mask)) != 0:
        raise RunnerError("cannot initialize launcher-runner signal mask")
    for signum in signals:
        if libc.sigaddset(ctypes.byref(new_mask), int(signum)) != 0:
            raise RunnerError("cannot initialize launcher-runner signal mask")
    result = libc.pthread_sigmask(
        int(signal.SIG_BLOCK),
        ctypes.byref(new_mask),
        ctypes.byref(old_mask),
    )
    if result != 0:
        raise OSError(result, os.strerror(result))
    applied[0] = True


def add_evidence(target: BaseException, source: BaseException, note: str) -> None:
    target.add_note(f"{note}: {type(source).__name__}: {source}")
    for source_note in getattr(source, "__notes__", ()):
        target.add_note(f"{note}: earlier note: {source_note}")


def choose_failure(
    current: BaseException | None,
    new: BaseException,
    note: str,
) -> BaseException:
    if current is None:
        return new
    if not isinstance(new, Exception) and isinstance(current, Exception):
        add_evidence(new, current, note)
        if new.__cause__ is None:
            new.__cause__ = current
        return new
    if new is not current:
        add_evidence(current, new, note)
    return current


def runner_failure(exc: BaseException, message: str) -> BaseException:
    if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
        return exc
    failure = RunnerError(message)
    failure.__cause__ = exc
    return failure


def run_cleanup_stage(
    primary: BaseException | None,
    operation,
    message: str,
) -> BaseException | None:
    """Run one finalizer without allowing it to skip later finalizers."""
    try:
        updated = operation(primary)
    except BaseException as exc:
        return choose_failure(
            primary,
            runner_failure(exc, message),
            f"{message}; an earlier failure also occurred",
        )
    return updated


def inspect_sigchld_action() -> LinuxSigaction:
    action = LinuxSigaction()
    libc = ctypes.CDLL(None, use_errno=True)
    sigaction_fn = libc.sigaction
    sigaction_fn.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(LinuxSigaction),
        ctypes.POINTER(LinuxSigaction),
    ]
    sigaction_fn.restype = ctypes.c_int
    ctypes.set_errno(0)
    if sigaction_fn(signal.SIGCHLD, None, ctypes.byref(action)) != 0:
        error = OSError(ctypes.get_errno(), "cannot inspect SIGCHLD action")
        raise RunnerError("cannot inspect launcher-runner SIGCHLD policy") from error
    if KERNEL_SIGSET_WORDS <= 0 or KERNEL_SIGSET_WORDS > len(action.mask.words):
        raise RunnerError("launcher-runner kernel signal domain is invalid")
    remainder = KERNEL_SIGSET_BITS % NATIVE_WORD_BITS
    if remainder:
        action.mask.words[KERNEL_SIGSET_WORDS - 1] &= (1 << remainder) - 1
    for index in range(KERNEL_SIGSET_WORDS, len(action.mask.words)):
        action.mask.words[index] = 0
    return action


def require_waitable_sigchld() -> None:
    action = inspect_sigchld_action()
    if action.handler not in (None, 0) or action.flags & SA_NOCLDWAIT:
        raise RunnerError("launcher runner requires default waitable SIGCHLD policy")


def close_descriptor(
    descriptor: int,
    label: str,
) -> tuple[BaseException | None, bool]:
    primary: BaseException | None = None
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            primary = choose_failure(primary, exc, f"{label} close also failed")
            try:
                os.fstat(descriptor)
            except OSError as probe:
                if probe.errno == errno.EBADF:
                    return primary, True
                primary = choose_failure(
                    primary,
                    probe,
                    f"{label} close-state inspection also failed",
                )
            except BaseException as probe:
                primary = choose_failure(
                    primary,
                    probe,
                    f"{label} close-state inspection also failed",
                )
            continue
        return primary, True
    try:
        os.fstat(descriptor)
    except OSError as probe:
        if probe.errno == errno.EBADF:
            return primary, True
        primary = choose_failure(
            primary,
            probe,
            f"{label} terminal close-state inspection also failed",
        )
    except BaseException as probe:
        primary = choose_failure(
            primary,
            probe,
            f"{label} terminal close-state inspection also failed",
        )
    return primary, False


def settle_descriptor(
    owner: DescriptorOwner,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    if owner.descriptor < 0:
        return primary
    close_error, closed = close_descriptor(owner.descriptor, label)
    if close_error is not None:
        primary = choose_failure(
            primary,
            runner_failure(close_error, f"{label} cleanup failed"),
            f"{label} cleanup also failed",
        )
    if closed:
        owner.descriptor = -1
    else:
        primary = choose_failure(
            primary,
            RunnerError(f"{label} cleanup did not converge"),
            f"{label} cleanup also did not converge",
        )
    return primary


def settle_iterator(entries, primary: BaseException | None) -> BaseException | None:
    closed = False
    for _ in range(3):
        try:
            entries.close()
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                "descriptor-table iterator close also failed",
            )
            continue
        closed = True
        break
    if not closed:
        primary = choose_failure(
            primary,
            RunnerError("descriptor-table iterator close did not converge"),
            "descriptor-table iterator custody also failed",
        )
    return primary


def trusted_descriptor_snapshot(partial: set[int] | None = None) -> frozenset[int]:
    return descriptor_snapshot(partial, _trusted=True)


def descriptor_snapshot(
    partial: set[int] | None = None,
    *,
    _trusted: bool = False,
) -> frozenset[int]:
    """Return live fds, excluding the transient enumeration descriptor."""
    entries = None
    parsed: set[int] = set()
    primary: BaseException | None = None
    table_metadata = os.stat("/proc/self/fd", follow_symlinks=False)
    acquisition_before = (
        frozenset() if _trusted else trusted_descriptor_snapshot(partial)
    )
    try:
        scan = _ORIGINAL_SCANDIR if _trusted else os.scandir
        entries = scan("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > MAX_FD_ENTRIES:
                raise RunnerError("launcher-runner descriptor table exceeds its bound")
            if not entry.name.isascii() or not entry.name.isdecimal():
                raise RunnerError("launcher-runner descriptor table is malformed")
            descriptor = int(entry.name, 10)
            if str(descriptor) != entry.name:
                raise RunnerError("launcher-runner descriptor table is noncanonical")
            parsed.add(descriptor)
            if partial is not None:
                partial.add(descriptor)
    except BaseException as exc:
        primary = runner_failure(exc, "cannot inspect launcher-runner descriptors")
        if entries is None and not _trusted:
            primary = recover_scandir_acquisition(
                acquisition_before,
                (table_metadata.st_dev, table_metadata.st_ino),
                primary,
            )
    if entries is not None:
        primary = settle_iterator(entries, primary)
    candidates = set(parsed)
    if partial is not None:
        partial.clear()
        partial.update(candidates)
    live: set[int] = set()
    for descriptor in sorted(parsed):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                candidates.discard(descriptor)
                continue
            primary = choose_failure(
                primary,
                runner_failure(exc, "cannot inspect launcher-runner descriptor"),
                "descriptor entry inspection also failed",
            )
        except BaseException as exc:
            primary = choose_failure(
                primary,
                runner_failure(exc, "cannot inspect launcher-runner descriptor"),
                "descriptor entry inspection also failed",
            )
        else:
            live.add(descriptor)
    if partial is not None:
        partial.clear()
        partial.update(candidates)
    if primary is not None:
        raise primary
    return frozenset(live)


def recover_scandir_acquisition(
    before: frozenset[int],
    identity: tuple[int, int],
    primary: BaseException,
) -> BaseException:
    partial: set[int] = set()
    try:
        after = trusted_descriptor_snapshot(partial)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            runner_failure(exc, "descriptor iterator recovery scan failed"),
            "descriptor iterator recovery scan also failed",
        )
        after = frozenset(partial)
    for descriptor in sorted(after - before):
        matches = False
        try:
            metadata = os.fstat(descriptor)
            matches = (metadata.st_dev, metadata.st_ino) == identity
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                "descriptor iterator recovery identity failed",
            )
        close_error, closed = close_descriptor(
            descriptor,
            "descriptor-table iterator acquisition",
        )
        if close_error is not None:
            primary = choose_failure(
                primary,
                close_error,
                "descriptor iterator recovery close failed",
            )
        if not matches:
            primary = choose_failure(
                primary,
                RunnerError("descriptor iterator recovery identity differed"),
                "descriptor iterator recovery also differed",
            )
        if not closed:
            primary = choose_failure(
                primary,
                RunnerError("descriptor iterator recovery did not converge"),
                "descriptor iterator recovery close also did not converge",
            )
    return primary


def recover_descriptor_acquisition(
    before: frozenset[int],
    primary: BaseException,
    predicate,
    label: str,
) -> BaseException:
    """Close the complete observed fd diff even when identity inspection fails."""
    partial: set[int] = set()
    try:
        after = descriptor_snapshot(partial)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            runner_failure(exc, f"{label} recovery scan failed"),
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial)
    for descriptor in sorted(after - before):
        matches = False
        try:
            matches = bool(predicate(descriptor))
        except BaseException as exc:
            primary = choose_failure(
                primary,
                runner_failure(exc, f"{label} recovery identity failed"),
                f"{label} recovery identity also failed",
            )
        close_error, closed = close_descriptor(descriptor, label)
        if close_error is not None:
            primary = choose_failure(
                primary,
                close_error,
                f"{label} recovery close also failed",
            )
        if not matches:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovered an unexpected descriptor"),
                f"{label} recovery identity also differed",
            )
        if not closed:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovery did not converge"),
                f"{label} recovery close also did not converge",
            )
    return primary


def acquire_path_descriptor(
    owner: DescriptorOwner,
    path: str,
    flags: int,
    identity: tuple[int, int],
    label: str,
) -> None:
    if owner.descriptor >= 0:
        raise RunnerError(f"{label} owner is already populated")
    baseline = descriptor_snapshot()
    try:
        owner.descriptor = os.open(path, flags)
    except BaseException as exc:
        selected = exc
        if owner.descriptor >= 0:
            selected = settle_descriptor(owner, selected, label) or selected
        else:
            def matches(descriptor: int) -> bool:
                metadata = os.fstat(descriptor)
                return (metadata.st_dev, metadata.st_ino) == identity

            selected = recover_descriptor_acquisition(
                baseline,
                selected,
                matches,
                label,
            )
        raise selected


def memfd_identity(descriptor: int) -> bool:
    metadata = os.fstat(descriptor)
    target = os.readlink(f"/proc/self/fd/{descriptor}")
    return (
        stat.S_ISREG(metadata.st_mode)
        and target == f"/memfd:{MEMFD_NAME} (deleted)"
    )


def acquire_memfd(owner: DescriptorOwner) -> None:
    if owner.descriptor >= 0:
        raise RunnerError("execution memfd owner is already populated")
    baseline = descriptor_snapshot()
    try:
        owner.descriptor = os.memfd_create(
            MEMFD_NAME,
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
    except BaseException as exc:
        selected = exc
        if owner.descriptor >= 0:
            selected = settle_descriptor(
                owner,
                selected,
                "launcher execution memfd",
            ) or selected
        else:
            selected = recover_descriptor_acquisition(
                baseline,
                selected,
                memfd_identity,
                "launcher execution memfd acquisition",
            )
        raise selected


def read_bounded(descriptor: int, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    interruptions = 0
    while total <= limit:
        try:
            chunk = os.read(descriptor, min(65536, limit + 1 - total))
        except InterruptedError:
            interruptions += 1
            if interruptions > MAX_IO_INTERRUPTS:
                raise RunnerError(f"{label} read did not converge")
            continue
        interruptions = 0
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
    raise RunnerError(f"{label} exceeds its bound")


def pidfd_target(descriptor: int) -> int | None:
    path = f"/proc/self/fdinfo/{descriptor}"
    metadata = os.stat(path, follow_symlinks=False)
    owner = DescriptorOwner()
    acquire_path_descriptor(
        owner,
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        (metadata.st_dev, metadata.st_ino),
        "pidfd identity record",
    )
    primary: BaseException | None = None
    raw = b""
    try:
        raw = read_bounded(owner.descriptor, 4096, "pidfd identity record")
    except BaseException as exc:
        primary = exc
    primary = settle_descriptor(owner, primary, "pidfd identity record")
    if primary is not None:
        raise primary
    targets = [
        line[4:].strip()
        for line in raw.splitlines()
        if line.startswith(b"Pid:")
    ]
    if len(targets) != 1 or not raw.endswith(b"\n"):
        raise RunnerError("launcher-runner pidfd identity is malformed")
    if targets[0] == b"-1":
        return None
    if not targets[0].isascii() or not targets[0].isdigit():
        raise RunnerError("launcher-runner pidfd identity is malformed")
    return int(targets[0], 10)


def acquire_pidfd(owner: DescriptorOwner, pid: int, label: str) -> None:
    if owner.descriptor >= 0:
        raise RunnerError(f"{label} owner is already populated")
    baseline = descriptor_snapshot()
    try:
        owner.descriptor = os.pidfd_open(pid, 0)
    except BaseException as exc:
        selected = exc
        if owner.descriptor >= 0:
            selected = settle_descriptor(owner, selected, label) or selected
        else:
            def matches(descriptor: int) -> bool:
                return (
                    os.readlink(f"/proc/self/fd/{descriptor}")
                    == "anon_inode:[pidfd]"
                    and pidfd_target(descriptor) == pid
                )

            selected = recover_descriptor_acquisition(
                baseline,
                selected,
                matches,
                label,
            )
        raise selected


def metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
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


def authenticate_launcher(
    launcher: pathlib.Path,
    expected_digest: str,
    owner: DescriptorOwner,
) -> bytes:
    path = os.fspath(launcher)
    try:
        namespace_before = os.stat(path, follow_symlinks=False)
    except BaseException as exc:
        raise runner_failure(exc, "cannot inspect rendered launcher")
    acquire_path_descriptor(
        owner,
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        (namespace_before.st_dev, namespace_before.st_ino),
        "rendered launcher fd",
    )
    opened = os.fstat(owner.descriptor)
    namespace_opened = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o500
        or opened.st_uid != os.geteuid()
        or opened.st_gid != os.getegid()
        or opened.st_nlink != 1
        or opened.st_size <= 0
        or opened.st_size > MAX_LAUNCHER_BYTES
        or (opened.st_dev, opened.st_ino)
        != (namespace_before.st_dev, namespace_before.st_ino)
        or (opened.st_dev, opened.st_ino)
        != (namespace_opened.st_dev, namespace_opened.st_ino)
    ):
        raise RunnerError("rendered launcher metadata differs from policy")
    raw = read_bounded(owner.descriptor, MAX_LAUNCHER_BYTES, "rendered launcher")
    after = os.fstat(owner.descriptor)
    namespace_after = os.stat(path, follow_symlinks=False)
    if (
        len(raw) != opened.st_size
        or hashlib.sha256(raw).hexdigest() != expected_digest
        or metadata_signature(after) != metadata_signature(opened)
        or metadata_signature(namespace_after) != metadata_signature(opened)
    ):
        raise RunnerError("rendered launcher changed during authentication")
    return raw


def write_and_seal(raw: bytes, owner: DescriptorOwner) -> None:
    acquire_memfd(owner)
    descriptor = owner.descriptor
    if os.get_inheritable(descriptor):
        raise RunnerError("execution memfd was not created close-on-exec")
    offset = 0
    interruptions = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except InterruptedError:
            interruptions += 1
            if interruptions > MAX_IO_INTERRUPTS:
                raise RunnerError("execution memfd write did not converge")
            continue
        interruptions = 0
        if written <= 0:
            raise RunnerError("execution memfd write made no progress")
        offset += written
    if os.fstat(descriptor).st_size != len(raw):
        raise RunnerError("execution memfd size differs from authenticated bytes")
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
        raise RunnerError("execution memfd seal set differs from policy")
    if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
        raise RunnerError("cannot rewind execution memfd")
    sealed = read_bounded(descriptor, MAX_LAUNCHER_BYTES, "sealed execution memfd")
    if sealed != raw or hashlib.sha256(sealed).digest() != hashlib.sha256(raw).digest():
        raise RunnerError("sealed execution memfd differs from authenticated bytes")
    if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
        raise RunnerError("cannot rewind sealed execution memfd")
    if os.get_inheritable(descriptor):
        raise RunnerError("execution memfd lost close-on-exec policy")


class CancellationLatch:
    """Capture INT/TERM from before owner acquisition through final settlement."""

    def __init__(self) -> None:
        self.signals = frozenset((signal.SIGINT, signal.SIGTERM))
        self.original_mask: frozenset[int] | None = None
        self.native_original_mask = NativeSignalSet()
        self.atomic_block_applied = [False]
        self.previous_handlers: dict[signal.Signals, signal.Handlers] = {}
        self.signum: int | None = None

    def record(self, signum, _frame=None) -> None:
        if self.signum is None or signum == signal.SIGINT:
            self.signum = int(signum)

    def drain(self) -> None:
        for _ in range(MAX_PENDING_SIGNAL_DRAIN):
            try:
                pending = signal.sigtimedwait(self.signals, 0)
            except InterruptedError:
                continue
            except BaseException as exc:
                raise runner_failure(exc, "cannot consume pending runner signal")
            if pending is None:
                return
            self.record(pending.si_signo)
        raise RunnerError("pending launcher-runner signals did not converge")

    def enter(self) -> None:
        if not hasattr(signal, "sigtimedwait"):
            raise RunnerError("launcher runner requires bounded signal waits")
        primary: BaseException | None = None
        try:
            atomic_capture_and_block(
                self.signals,
                self.native_original_mask,
                self.atomic_block_applied,
            )
            self.original_mask = decode_native_signal_mask(
                self.native_original_mask
            )
            if self.original_mask & self.signals:
                raise RunnerError("launcher runner inherited blocked cancellation")
            for signum in self.signals:
                self.previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signal.SIGINT, self.record)
            signal.signal(signal.SIGTERM, self.record)
            self.drain()
            signal.pthread_sigmask(signal.SIG_SETMASK, self.original_mask)
            return
        except BaseException as exc:
            primary = runner_failure(exc, "cannot install launcher-runner signal latch")
            if self.atomic_block_applied[0] and self.original_mask is None:
                try:
                    self.original_mask = decode_native_signal_mask(
                        self.native_original_mask
                    )
                except BaseException as recovery:
                    primary = choose_failure(
                        primary,
                        recovery,
                        "original signal-mask recovery also failed",
                    )
        for signum in (signal.SIGTERM, signal.SIGINT):
            handler = self.previous_handlers.get(signum)
            if handler is None:
                continue
            try:
                signal.signal(signum, handler)
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    "signal handler rollback also failed",
                )
        if self.atomic_block_applied[0] and self.original_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, self.original_mask)
            except BaseException as exc:
                primary = choose_failure(primary, exc, "signal mask rollback also failed")
        assert primary is not None
        raise primary

    def checkpoint(self) -> None:
        if self.signum is not None:
            raise RunnerSignal(self.signum)

    def block_handoff(self) -> frozenset[signal.Signals]:
        if self.original_mask is None:
            raise RunnerError("launcher-runner signal latch is not installed")
        previous = frozenset(
            signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        )
        if previous != self.original_mask:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            except BaseException as exc:
                raise RunnerError("cannot restore unexpected handoff mask") from exc
            raise RunnerError("launcher-runner handoff mask changed unexpectedly")
        return previous

    def unblock_handoff(self, previous: frozenset[signal.Signals]) -> None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def restore_terminal_mask(
        self,
    ) -> tuple[BaseException | None, BaseException | None]:
        if self.original_mask is None:
            failure = RunnerError("launcher-runner original signal mask is missing")
            return failure, None
        failure: BaseException | None = None
        for _ in range(3):
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, self.original_mask)
            except BaseException as exc:
                try:
                    current = frozenset(
                        signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    )
                except BaseException as probe:
                    failure = choose_failure(
                        failure,
                        exc,
                        "terminal signal-mask restore failed",
                    )
                    failure = choose_failure(
                        failure,
                        probe,
                        "terminal signal-mask inspection also failed",
                    )
                    continue
                if current == self.original_mask:
                    if failure is not None and failure is not exc:
                        add_evidence(
                            exc,
                            failure,
                            "earlier terminal signal-mask restore failure",
                        )
                    return exc, exc
                failure = choose_failure(
                    failure,
                    exc,
                    "terminal signal-mask restore failed",
                )
                continue
            return failure, None
        failure = choose_failure(
            failure,
            RunnerError("terminal signal-mask restore did not converge"),
            "terminal signal-mask restoration also did not converge",
        )
        return failure, None

    def close(self, primary: BaseException | None) -> BaseException | None:
        failures: list[BaseException] = []
        handoff_failure: BaseException | None = None
        if self.original_mask is None:
            failures.append(RunnerError("launcher-runner signal latch was not installed"))
        else:
            blocked = False
            for _ in range(3):
                try:
                    signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
                    current = frozenset(
                        signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    )
                    if self.signals <= current:
                        blocked = True
                        break
                except BaseException as exc:
                    failures.append(exc)
            if not blocked:
                failures.append(RunnerError("terminal signal block did not converge"))
            else:
                try:
                    self.drain()
                except BaseException as exc:
                    failures.append(exc)
                for signum in (signal.SIGTERM, signal.SIGINT):
                    handler = self.previous_handlers.get(signum)
                    if handler is None:
                        continue
                    restored = False
                    for _ in range(3):
                        try:
                            signal.signal(signum, handler)
                        except BaseException as exc:
                            failures.append(exc)
                            continue
                        restored = True
                        break
                    if not restored:
                        failures.append(
                            RunnerError(f"{signum.name} handler restore did not converge")
                        )
                try:
                    self.drain()
                except BaseException as exc:
                    failures.append(exc)
                restore_failure, handoff_failure = self.restore_terminal_mask()
                if restore_failure is not None:
                    failures.append(restore_failure)
        if handoff_failure is not None:
            if primary is not None and primary is not handoff_failure:
                add_evidence(
                    handoff_failure,
                    primary,
                    "runner failed before caller signal-policy handoff",
                )
            for failure in failures:
                if failure is not handoff_failure:
                    add_evidence(
                        handoff_failure,
                        failure,
                        "signal restoration also failed",
                    )
            return handoff_failure
        caller_policy = (
            primary
            if (
                primary is not None
                and not isinstance(primary, Exception)
                and not isinstance(primary, RunnerSignal)
            )
            else next(
                (
                    failure
                    for failure in failures
                    if not isinstance(failure, Exception)
                    and not isinstance(failure, RunnerSignal)
                ),
                None,
            )
        )
        if caller_policy is not None:
            if primary is not None and primary is not caller_policy:
                add_evidence(
                    caller_policy,
                    primary,
                    "runner failed before caller signal policy was restored",
                )
            for failure in failures:
                if failure is not caller_policy:
                    add_evidence(
                        caller_policy,
                        failure,
                        "signal restoration also failed",
                    )
            return caller_policy
        if failures:
            containment = RunnerError("launcher-runner signal restoration failed")
            if primary is not None:
                add_evidence(
                    containment,
                    primary,
                    "runner failed before signal restoration",
                )
            for failure in failures:
                add_evidence(containment, failure, "signal restoration failed")
            return containment
        selected_signum = self.signum
        if isinstance(primary, RunnerSignal) and (
            selected_signum is None or primary.signum == signal.SIGINT
        ):
            selected_signum = primary.signum
        if selected_signum is not None:
            cancellation = RunnerSignal(selected_signum)
            if primary is not None and not isinstance(primary, RunnerSignal):
                add_evidence(
                    cancellation,
                    primary,
                    "runner failed before cancellation cleanup",
                )
            return cancellation
        return primary


def inspect_subreaper() -> bool:
    value = ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(value), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot inspect child-subreaper state")
    return bool(value.value)


def set_subreaper(enabled: bool) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, int(enabled), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot set child-subreaper state")


def enter_subreaper(owner: SubreaperOwner) -> None:
    """Publish restoration custody before the first subreaper mutation."""
    if owner.previous is not None or owner.restore_required:
        raise RunnerError("launcher-runner subreaper owner is already populated")
    try:
        owner.previous = inspect_subreaper()
        owner.restore_required = True
        set_subreaper(True)
        if not inspect_subreaper():
            raise RunnerError("launcher-runner subreaper state was not applied")
    except BaseException as exc:
        raise runner_failure(
            exc,
            "cannot enter launcher-runner subreaper custody",
        )


def restore_subreaper(
    owner: SubreaperOwner,
    primary: BaseException | None,
) -> BaseException | None:
    if not owner.restore_required:
        return primary
    if owner.previous is None:
        return choose_failure(
            primary,
            RunnerError("launcher-runner subreaper restoration identity is missing"),
            "child-subreaper restoration also failed",
        )
    failure: BaseException | None = None
    for _ in range(3):
        try:
            set_subreaper(owner.previous)
            if inspect_subreaper() != owner.previous:
                raise RunnerError("launcher-runner subreaper restore was not applied")
        except BaseException as exc:
            failure = choose_failure(failure, exc, "subreaper restore also failed")
            continue
        owner.restore_required = False
        owner.previous = None
        return primary
    assert failure is not None
    return choose_failure(
        primary,
        runner_failure(failure, "launcher-runner subreaper restore failed"),
        "launcher-runner subreaper restoration also failed",
    )


def direct_children() -> tuple[int, ...]:
    path = f"/proc/self/task/{os.getpid()}/children"
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except BaseException as exc:
        raise runner_failure(exc, "cannot inspect launcher-runner children")
    owner = DescriptorOwner()
    acquire_path_descriptor(
        owner,
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        (metadata.st_dev, metadata.st_ino),
        "launcher-runner children record",
    )
    raw = b""
    primary: BaseException | None = None
    try:
        opened = os.fstat(owner.descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RunnerError("launcher-runner children record changed")
        raw = read_bounded(
            owner.descriptor,
            MAX_CHILDREN_RECORD_BYTES,
            "launcher-runner children record",
        )
    except BaseException as exc:
        primary = exc
    primary = settle_descriptor(owner, primary, "launcher-runner children record")
    if primary is not None:
        raise primary
    fields = raw.split()
    if len(fields) > MAX_DIRECT_CHILDREN:
        raise RunnerError("launcher-runner direct-child set exceeds its bound")
    children: list[int] = []
    for field in fields:
        if not field.isascii() or not field.isdigit() or field.startswith(b"0"):
            raise RunnerError("launcher-runner children record is malformed")
        children.append(int(field, 10))
    if len(set(children)) != len(children):
        raise RunnerError("launcher-runner children record contains duplicates")
    return tuple(sorted(children))


def process_start_time(pid: int) -> int:
    path = f"/proc/{pid}/stat"
    metadata = os.stat(path, follow_symlinks=False)
    owner = DescriptorOwner()
    acquire_path_descriptor(
        owner,
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        (metadata.st_dev, metadata.st_ino),
        "launcher-runner process identity record",
    )
    primary: BaseException | None = None
    raw = b""
    try:
        opened = os.fstat(owner.descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RunnerError("launcher-runner process identity record changed")
        raw = read_bounded(
            owner.descriptor,
            4096,
            "launcher-runner process identity record",
        )
    except BaseException as exc:
        primary = exc
    primary = settle_descriptor(
        owner,
        primary,
        "launcher-runner process identity record",
    )
    if primary is not None:
        raise primary
    closing = raw.rfind(b") ")
    fields = raw[closing + 2:].split() if closing > 0 else []
    if (
        len(fields) < 20
        or not fields[1].isascii()
        or not fields[1].isdigit()
        or int(fields[1], 10) != os.getpid()
        or not fields[19].isascii()
        or not fields[19].isdigit()
    ):
        raise RunnerError("launcher-runner process identity record is malformed")
    return int(fields[19], 10)


def kill_numeric_after_identity(
    pid: int,
    expected_start_time: int,
    label: str,
) -> BaseException | None:
    """Use numeric SIGKILL only after direct-child identity was revalidated."""
    try:
        current_start_time = process_start_time(pid)
    except (FileNotFoundError, ProcessLookupError):
        return None
    except BaseException as exc:
        return runner_failure(exc, f"{label} identity probe failed")
    if current_start_time != expected_start_time:
        return RunnerError(f"{label} process identity changed before numeric kill")
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return None
    except BaseException as exc:
        return runner_failure(exc, f"{label} numeric kill failed")
    return None


def direct_child_snapshot() -> dict[int, int]:
    snapshot: dict[int, int] = {}
    for pid in direct_children():
        try:
            snapshot[pid] = process_start_time(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return snapshot


def preflight_pidfd_capacity() -> None:
    owners = [DescriptorOwner() for _ in range(PIDFD_PREFLIGHT)]
    primary: BaseException | None = None
    try:
        metadata = os.stat("/dev/null", follow_symlinks=False)
        for owner in owners:
            acquire_path_descriptor(
                owner,
                "/dev/null",
                os.O_RDONLY | os.O_CLOEXEC,
                (metadata.st_dev, metadata.st_ino),
                "launcher-runner descriptor-capacity preflight",
            )
    except BaseException as exc:
        primary = runner_failure(
            exc,
            "launcher runner has insufficient descriptor capacity",
        )
    for owner in reversed(owners):
        primary = settle_descriptor(
            owner,
            primary,
            "launcher-runner descriptor-capacity preflight",
        )
    if primary is not None:
        raise primary


def preflight_pidfd_capability() -> None:
    """Prove both pidfd syscalls work against a disposable direct child."""
    owner = DescriptorOwner()
    child_baseline = direct_child_snapshot()
    child_pid = -1
    primary: BaseException | None = None
    try:
        child_pid = os.fork()
        if child_pid == 0:
            # Keep the target alive until the parent has exercised both
            # syscalls.  The parent owns this child and will always reap it.
            try:
                while True:
                    signal.pause()
            finally:
                os._exit(0)
        acquire_pidfd(
            owner,
            child_pid,
            "launcher-runner pidfd capability preflight",
        )
        if pidfd_target(owner.descriptor) != child_pid:
            raise RunnerError("launcher-runner pidfd capability identity differed")
        # Signal zero exercises the kernel capability/permission path without
        # changing the disposable child. pidfd_open alone is insufficient
        # because cleanup relies on pidfd_send_signal for every owned child.
        signal.pidfd_send_signal(owner.descriptor, 0, None, 0)
    except BaseException as exc:
        primary = runner_failure(
            exc,
            "launcher runner requires operational Linux pidfd support",
        )
        if child_pid <= 0:
            # A wrapper can theoretically fork successfully and then raise
            # before returning its PID. Recover the one newly adopted child by
            # identity instead of allowing the capability probe to leak it.
            primary = recover_unassigned_child(child_baseline, primary)
    finally:
        if child_pid > 0:
            if owner.descriptor >= 0:
                try:
                    signal.pidfd_send_signal(owner.descriptor, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                except BaseException as exc:
                    primary = choose_failure(
                        primary,
                        exc,
                        "launcher-runner pidfd capability child kill failed",
                    )
            # Numeric fallback is safe for this freshly forked child and keeps
            # the probe itself from becoming a leaked descendant if the send
            # wrapper fails after opening the pidfd.
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    "launcher-runner pidfd capability numeric child kill failed",
                )
    primary = settle_descriptor(
        owner,
        primary,
        "launcher-runner pidfd capability preflight",
    )
    if child_pid > 0:
        reaped = False
        for _ in range(MAX_PROCESS_WAIT_PASSES):
            try:
                waited, _ = os.waitpid(child_pid, os.WNOHANG)
            except ChildProcessError:
                reaped = True
                break
            except InterruptedError:
                continue
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    "launcher-runner pidfd capability child reap failed",
                )
                continue
            if waited == child_pid:
                reaped = True
                break
            if waited != 0:
                primary = choose_failure(
                    primary,
                    RunnerError(
                        "launcher-runner pidfd capability child reap returned another pid"
                    ),
                    "launcher-runner pidfd capability child reap also failed",
                )
                break
            try:
                time.sleep(WAIT_SLICE_SECONDS)
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    "launcher-runner pidfd capability child reap delay failed",
                )
        if not reaped:
            primary = choose_failure(
                primary,
                RunnerError(
                    "launcher-runner pidfd capability child reap did not converge"
                ),
                "launcher-runner pidfd capability child custody also failed",
            )
    if primary is not None:
        raise primary


def cleanup_children() -> tuple[BaseException | None, bool]:
    """Kill and reap every direct child adopted by this child subreaper."""
    primary: BaseException | None = None
    found = False
    cursor = 0
    for _ in range(MAX_CLEANUP_PASSES):
        try:
            children = direct_children()
        except BaseException as exc:
            primary = choose_failure(primary, exc, "child snapshot also failed")
            try:
                time.sleep(0.01)
            except BaseException as delay:
                primary = choose_failure(primary, delay, "cleanup delay also failed")
            continue
        if not children:
            return primary, found
        found = True
        start = cursor % len(children)
        selected = tuple(
            children[(start + index) % len(children)]
            for index in range(min(PIDFD_BATCH, len(children)))
        )
        cursor += len(selected)
        owners: list[tuple[int, DescriptorOwner]] = []
        try:
            for pid in selected:
                # A zero WNOHANG result proves direct, unreaped custody.  Numeric
                # process-group signalling is permitted only under this proof.
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    continue
                except InterruptedError:
                    continue
                except BaseException as exc:
                    primary = choose_failure(primary, exc, "child custody probe failed")
                    continue
                if waited == pid:
                    continue
                if waited != 0:
                    primary = choose_failure(
                        primary,
                        RunnerError("child custody probe returned another pid"),
                        "child custody probe also failed",
                    )
                    continue
                try:
                    expected_start_time = process_start_time(pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except BaseException as exc:
                    primary = choose_failure(
                        primary,
                        exc,
                        "child identity probe failed",
                    )
                    continue
                owner = DescriptorOwner()
                owners.append((pid, owner))
                try:
                    acquire_pidfd(owner, pid, "descendant pidfd handoff")
                except ProcessLookupError:
                    owners.pop()
                    continue
                except BaseException as exc:
                    failed_owner = owners.pop()[1]
                    primary = settle_descriptor(
                        failed_owner,
                        choose_failure(primary, exc, "descendant pidfd also failed"),
                        "descendant pidfd",
                    )
                    numeric_failure = kill_numeric_after_identity(
                        pid,
                        expected_start_time,
                        "descendant fallback",
                    )
                    if numeric_failure is not None:
                        primary = choose_failure(
                            primary,
                            numeric_failure,
                            "descendant numeric fallback also failed",
                        )
                    continue
                try:
                    if os.getpgid(pid) == pid:
                        os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as exc:
                    primary = choose_failure(primary, exc, "process-group kill failed")
                try:
                    signal.pidfd_send_signal(owner.descriptor, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                except BaseException as exc:
                    primary = choose_failure(primary, exc, "descendant kill failed")
                    numeric_failure = kill_numeric_after_identity(
                        pid,
                        expected_start_time,
                        "descendant signal fallback",
                    )
                    if numeric_failure is not None:
                        primary = choose_failure(
                            primary,
                            numeric_failure,
                            "descendant numeric fallback also failed",
                        )
        finally:
            for _, owner in reversed(owners):
                primary = run_cleanup_stage(
                    primary,
                    lambda current, owner=owner: settle_descriptor(
                        owner,
                        current,
                        "descendant pidfd",
                    ),
                    "descendant pidfd settlement failed",
                )
        for pid in children:
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, InterruptedError):
                pass
            except BaseException as exc:
                primary = choose_failure(primary, exc, "direct-child reap failed")
        try:
            time.sleep(0.01)
        except BaseException as exc:
            primary = choose_failure(primary, exc, "cleanup delay failed")
    try:
        remaining = direct_children()
    except BaseException as exc:
        primary = choose_failure(primary, exc, "terminal child snapshot failed")
        remaining = (-1,)
    if remaining:
        primary = choose_failure(
            primary,
            RunnerError("launcher-runner descendant cleanup did not converge"),
            "descendant cleanup also did not converge",
        )
    return primary, found


def recover_popen_descriptors(
    baseline: frozenset[int],
    primary: BaseException,
) -> BaseException:
    def internal_popen_descriptor(descriptor: int) -> bool:
        target = os.readlink(f"/proc/self/fd/{descriptor}")
        return (
            target == "/dev/null"
            or (target.startswith("pipe:[") and target.endswith("]"))
        )

    return recover_descriptor_acquisition(
        baseline,
        primary,
        internal_popen_descriptor,
        "launcher subprocess handoff",
    )


def recover_unassigned_child(
    baseline: dict[int, int],
    primary: BaseException,
) -> BaseException:
    """Own, terminate, and exactly reap a Popen child whose return was lost."""
    try:
        after = direct_child_snapshot()
    except BaseException as exc:
        return choose_failure(
            primary,
            runner_failure(exc, "cannot recover launcher subprocess handoff"),
            "launcher subprocess recovery scan also failed",
        )
    introduced = [
        (pid, start_time)
        for pid, start_time in sorted(after.items())
        if baseline.get(pid) != start_time
    ]
    if len(introduced) != 1:
        return choose_failure(
            primary,
            RunnerError("launcher subprocess recovery identity is ambiguous"),
            "launcher subprocess recovery also failed",
        )
    pid, start_time = introduced[0]
    owner = DescriptorOwner()
    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
    except BaseException as exc:
        return choose_failure(primary, exc, "recovered child custody probe failed")
    if waited == pid:
        return primary
    if waited != 0:
        return choose_failure(
            primary,
            RunnerError("recovered child custody probe returned another pid"),
            "recovered child custody also failed",
        )
    try:
        acquire_pidfd(owner, pid, "recovered root pidfd handoff")
        if process_start_time(pid) != start_time:
            raise RunnerError("recovered launcher subprocess identity changed")
        try:
            signal.pidfd_send_signal(owner.descriptor, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
    except BaseException as exc:
        primary = choose_failure(primary, exc, "recovered child kill failed")
        numeric_failure = kill_numeric_after_identity(
            pid,
            start_time,
            "recovered child fallback",
        )
        if numeric_failure is not None:
            primary = choose_failure(
                primary,
                numeric_failure,
                "recovered numeric child fallback also failed",
            )
    finally:
        primary = settle_descriptor(owner, primary, "recovered root pidfd")
    reaped = False
    for _ in range(MAX_PROCESS_WAIT_PASSES):
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            reaped = True
            break
        except InterruptedError:
            continue
        except BaseException as exc:
            primary = choose_failure(primary, exc, "recovered child reap failed")
            continue
        if waited == pid:
            reaped = True
            break
        if waited != 0:
            primary = choose_failure(
                primary,
                RunnerError("recovered child reap returned another pid"),
                "recovered child reap also failed",
            )
            break
        try:
            time.sleep(WAIT_SLICE_SECONDS)
        except BaseException as exc:
            primary = choose_failure(primary, exc, "recovered child delay failed")
    if not reaped:
        primary = choose_failure(
            primary,
            RunnerError("recovered launcher subprocess reap did not converge"),
            "recovered child custody also did not converge",
        )
    return primary


def close_popen_streams(
    process: subprocess.Popen[bytes],
    primary: BaseException | None,
) -> BaseException | None:
    for stream, label in ((process.stderr, "stderr"), (process.stdout, "stdout")):
        if stream is None:
            continue
        descriptor: int | None = None
        try:
            descriptor = stream.fileno()
        except BaseException as exc:
            primary = choose_failure(primary, exc, f"child {label} fd inspection failed")
        try:
            already_closed = stream.closed
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                f"child {label} close-state inspection failed",
            )
            already_closed = False
        if already_closed:
            continue
        closed = False
        for _ in range(3):
            try:
                stream.close()
            except BaseException as exc:
                primary = choose_failure(primary, exc, f"child {label} close failed")
                try:
                    if stream.closed:
                        closed = True
                        break
                except BaseException as probe:
                    primary = choose_failure(
                        primary,
                        probe,
                        f"child {label} close-state probe also failed",
                    )
                continue
            closed = True
            break
        if descriptor is not None:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    closed = True
                else:
                    primary = choose_failure(
                        primary,
                        exc,
                        f"child {label} descriptor close-state probe failed",
                    )
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    f"child {label} descriptor close-state probe failed",
                )
            else:
                closed = False
        if not closed:
            primary = choose_failure(
                primary,
                RunnerError(f"child {label} close did not converge"),
                f"child {label} custody also failed",
            )
    return primary


def settle_popen(
    owner: PopenOwner,
    root_pidfd: DescriptorOwner,
    primary: BaseException | None,
) -> BaseException | None:
    process = owner.process
    if process is None:
        return primary
    running = True
    poll_known = False
    root_start_time: int | None = None
    try:
        running = process.poll() is None
        poll_known = True
        if running:
            try:
                root_start_time = process_start_time(process.pid)
            except (FileNotFoundError, ProcessLookupError):
                root_start_time = None
            except BaseException as exc:
                primary = choose_failure(primary, exc, "root process identity probe failed")
    except BaseException as exc:
        primary = choose_failure(primary, exc, "root process poll failed")
    if running:
        if root_pidfd.descriptor >= 0:
            try:
                signal.pidfd_send_signal(root_pidfd.descriptor, signal.SIGKILL, None, 0)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                primary = choose_failure(primary, exc, "root pidfd kill failed")
        if poll_known:
            try:
                still_running = process.poll() is None
            except BaseException as exc:
                primary = choose_failure(primary, exc, "root numeric custody poll failed")
                still_running = False
            if still_running:
                try:
                    waited, _ = os.waitpid(process.pid, os.WNOHANG)
                except (ChildProcessError, InterruptedError):
                    waited = -1
                except BaseException as exc:
                    primary = choose_failure(primary, exc, "root custody waitpid failed")
                    waited = -1
                if waited == 0:
                    if root_start_time is not None:
                        numeric_failure = kill_numeric_after_identity(
                            process.pid,
                            root_start_time,
                            "root process fallback",
                        )
                        if numeric_failure is not None:
                            primary = choose_failure(
                                primary,
                                numeric_failure,
                                "root numeric fallback also failed",
                            )
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except BaseException as exc:
                        primary = choose_failure(
                            primary,
                            exc,
                            "root process-group kill failed",
                        )
    for _ in range(MAX_PROCESS_WAIT_PASSES):
        if process.returncode is not None:
            break
        try:
            process.wait(timeout=WAIT_SLICE_SECONDS)
        except subprocess.TimeoutExpired:
            continue
        except BaseException as exc:
            primary = choose_failure(primary, exc, "root process wait failed")
            continue
    if process.returncode is None:
        primary = choose_failure(
            primary,
            RunnerError("root process reap did not converge"),
            "root process custody also failed",
        )
    primary = close_popen_streams(process, primary)
    if process.returncode is not None:
        owner.process = None
    return primary


def run_sealed_launcher(
    execution: DescriptorOwner,
    arguments: list[str],
    repo: pathlib.Path,
    environment: dict[str, str],
    deadline: float,
    cancellation: CancellationLatch,
) -> BoundedResult:
    if threading.active_count() != 1:
        raise RunnerError("launcher runner requires a single-threaded process")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RunnerError("launcher runner requires Linux pidfd support")
    require_waitable_sigchld()
    if direct_children():
        raise RunnerError("launcher runner inherited pre-existing children")
    subreaper_owner = SubreaperOwner()
    process_owner = PopenOwner()
    root_pidfd = DescriptorOwner()
    primary: BaseException | None = None
    timed_out = False
    overflow = False
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    returncode: int | None = None
    try:
        enter_subreaper(subreaper_owner)
        preflight_pidfd_capacity()
        preflight_pidfd_capability()
        cancellation.checkpoint()
        spawn_mask: frozenset[signal.Signals] | None = None
        popen_baseline = descriptor_snapshot()
        child_baseline = direct_child_snapshot()

        def child_setup() -> None:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            if cancellation.original_mask is None:
                os._exit(126)
            signal.pthread_sigmask(signal.SIG_SETMASK, cancellation.original_mask)
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (MAX_LAUNCHER_FILE_BYTES, MAX_LAUNCHER_FILE_BYTES),
            )

        try:
            spawn_mask = cancellation.block_handoff()
            cancellation.checkpoint()
            process_owner.process = subprocess.Popen(
                arguments,
                cwd=repo,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(execution.descriptor,),
                start_new_session=True,
                preexec_fn=child_setup,
            )
            acquire_pidfd(root_pidfd, process_owner.process.pid, "root pidfd handoff")
            if os.get_inheritable(execution.descriptor):
                raise RunnerError("parent execution memfd became inheritable")
        except BaseException as exc:
            primary = exc
            if process_owner.process is None:
                primary = recover_unassigned_child(child_baseline, primary)
                primary = recover_popen_descriptors(popen_baseline, primary)
        finally:
            if spawn_mask is not None:
                try:
                    cancellation.unblock_handoff(spawn_mask)
                except BaseException as exc:
                    primary = choose_failure(primary, exc, "spawn mask restore failed")
        if primary is None:
            process = process_owner.process
            assert process is not None
            assert process.stdout is not None and process.stderr is not None
            streams = {
                process.stdout.fileno(): (process.stdout, stdout_buffer),
                process.stderr.fileno(): (process.stderr, stderr_buffer),
            }
            for descriptor in streams:
                os.set_blocking(descriptor, False)
            while streams or process.returncode is None:
                if cancellation.signum is not None:
                    break
                remaining = deadline - time.monotonic()
                if not math.isfinite(remaining) or remaining <= 0:
                    timed_out = True
                    break
                try:
                    poller = select.poll()
                    for descriptor in streams:
                        poller.register(
                            descriptor,
                            select.POLLIN | select.POLLHUP | select.POLLERR,
                        )
                    poll_timeout = max(
                        1,
                        min(
                            2_147_483_647,
                            math.ceil(
                                min(remaining, WAIT_SLICE_SECONDS) * 1000
                            ),
                        ),
                    )
                    ready = poller.poll(poll_timeout)
                except InterruptedError:
                    continue
                readable = [
                    descriptor
                    for descriptor, events in ready
                    if events
                    & (select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
                ]
                for descriptor in readable:
                    _, target = streams[descriptor]
                    try:
                        chunk = os.read(descriptor, 65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not chunk:
                        del streams[descriptor]
                        continue
                    target.extend(chunk)
                    if len(target) > MAX_OUTPUT_BYTES:
                        overflow = True
                        break
                if overflow:
                    break
                process.poll()
            returncode = process.returncode
    except BaseException as exc:
        primary = choose_failure(primary, exc, "launcher execution failed")
    finally:
        primary = run_cleanup_stage(
            primary,
            lambda current: settle_popen(process_owner, root_pidfd, current),
            "root process settlement failed",
        )

        def settle_children(current: BaseException | None) -> BaseException | None:
            child_failure, leaked = cleanup_children()
            if child_failure is not None:
                current = choose_failure(
                    current,
                    child_failure,
                    "descendant cleanup failed",
                )
            if leaked:
                current = choose_failure(
                    current,
                    RunnerError("launcher subprocess left descendants"),
                    "launcher containment failed",
                )
            return current

        primary = run_cleanup_stage(
            primary,
            settle_children,
            "descendant settlement failed",
        )
        primary = run_cleanup_stage(
            primary,
            lambda current: settle_popen(process_owner, root_pidfd, current),
            "terminal root process reconciliation failed",
        )
        primary = run_cleanup_stage(
            primary,
            lambda current: settle_descriptor(root_pidfd, current, "root pidfd"),
            "root pidfd settlement failed",
        )
        primary = run_cleanup_stage(
            primary,
            lambda current: restore_subreaper(subreaper_owner, current),
            "child-subreaper restoration failed",
        )
    if primary is not None:
        raise primary
    cancellation.checkpoint()
    if timed_out:
        return BoundedResult(124, b"", b"launcher subprocess exceeded its deadline\n")
    if overflow:
        return BoundedResult(125, b"", b"launcher subprocess output exceeded its bound\n")
    if returncode is None:
        raise RunnerError("launcher subprocess return code is unavailable")
    stdout = bytes(stdout_buffer)
    stderr = bytes(stderr_buffer)
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        raise RunnerError("launcher subprocess output exceeded its bound")
    return BoundedResult(returncode, stdout, stderr)


def require_absolute_path(raw: str, label: str) -> pathlib.Path:
    path = pathlib.Path(raw)
    if not path.is_absolute() or "\x00" in raw or len(os.fsencode(raw)) > 4096:
        raise RunnerError(f"{label} is not a bounded absolute path")
    return path


def require_repo(raw: str) -> pathlib.Path:
    repo = require_absolute_path(raw, "repository path")
    try:
        resolved = repo.resolve(strict=True)
        metadata = repo.lstat()
    except BaseException as exc:
        raise runner_failure(exc, "cannot inspect repository path")
    if resolved != repo or not stat.S_ISDIR(metadata.st_mode):
        raise RunnerError("repository path is not one canonical direct directory")
    return repo


def require_launcher(raw: str) -> pathlib.Path:
    launcher = require_absolute_path(raw, "launcher path")
    try:
        resolved = launcher.resolve(strict=True)
        metadata = launcher.lstat()
    except BaseException as exc:
        raise runner_failure(exc, "cannot inspect launcher path")
    if resolved != launcher or not stat.S_ISREG(metadata.st_mode):
        raise RunnerError("launcher path is not one canonical direct regular file")
    return launcher


def clean_environment() -> dict[str, str]:
    home = os.environ.get("HOME")
    try:
        account_home = pwd.getpwuid(os.geteuid()).pw_dir
    except (KeyError, OSError) as exc:
        raise RunnerError("cannot resolve launcher-runner account") from exc
    if (
        type(home) is not str
        or type(account_home) is not str
        or home != account_home
        or not home.startswith("/")
        or "\x00" in home
        or len(os.fsencode(home)) > 4096
    ):
        raise RunnerError("operator HOME differs from the account database")
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": home,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONOPTIMIZE": "1",
    }
    for name in ("http_proxy", "https_proxy", "no_proxy"):
        value = os.environ.get(name, "")
        if value and len(value) <= 2048 and "\n" not in value and "\r" not in value:
            environment[name] = value
    return environment


def execute(arguments, cancellation: CancellationLatch) -> BoundedResult:
    launcher = require_launcher(arguments.launcher)
    repo = require_repo(arguments.repo_dir)
    if SHA256.fullmatch(arguments.launcher_sha256) is None:
        raise RunnerError("launcher SHA-256 is not canonical")
    if not math.isfinite(arguments.timeout_seconds) or not (
        1.0 <= arguments.timeout_seconds <= 600.0
    ):
        raise RunnerError("launcher timeout differs from policy")
    if arguments.verify_only == (arguments.profile is not None):
        raise RunnerError("select verify-only or one dispatch profile")
    launcher_owner = DescriptorOwner()
    execution_owner = DescriptorOwner()
    primary: BaseException | None = None
    result: BoundedResult | None = None
    try:
        cancellation.checkpoint()
        raw = authenticate_launcher(
            launcher,
            arguments.launcher_sha256,
            launcher_owner,
        )
        cancellation.checkpoint()
        write_and_seal(raw, execution_owner)
        cancellation.checkpoint()
        child_arguments = [
            PYTHON,
            "-I",
            "-B",
            f"/proc/self/fd/{execution_owner.descriptor}",
        ]
        if arguments.verify_only:
            child_arguments.append("--verify-only")
        else:
            child_arguments.extend(("--profile", arguments.profile))
        child_arguments.extend(("--repo-dir", os.fspath(repo)))
        result = run_sealed_launcher(
            execution_owner,
            child_arguments,
            repo,
            clean_environment(),
            time.monotonic() + arguments.timeout_seconds,
            cancellation,
        )
        cancellation.checkpoint()
    except BaseException as exc:
        primary = exc
    finally:
        primary = run_cleanup_stage(
            primary,
            lambda current: settle_descriptor(
                execution_owner,
                current,
                "sealed launcher execution memfd",
            ),
            "sealed launcher execution memfd settlement failed",
        )
        primary = run_cleanup_stage(
            primary,
            lambda current: settle_descriptor(
                launcher_owner,
                current,
                "authenticated launcher fd",
            ),
            "authenticated launcher fd settlement failed",
        )
    if primary is not None:
        raise primary
    assert result is not None
    return result


def write_all(descriptor: int, raw: bytes) -> None:
    """Forward bounded evidence without allowing a blocked caller to hang us."""
    try:
        was_blocking = os.get_blocking(descriptor)
    except BaseException as exc:
        raise RunnerError("cannot inspect runner output descriptor mode") from exc
    changed_mode = False
    deadline = time.monotonic() + OUTPUT_WRITE_SECONDS
    offset = 0
    interruptions = 0
    try:
        if was_blocking:
            os.set_blocking(descriptor, False)
            changed_mode = True
        while offset < len(raw):
            remaining = deadline - time.monotonic()
            if not math.isfinite(remaining) or remaining <= 0:
                raise RunnerError("runner output write exceeded its deadline")
            try:
                poller = select.poll()
                poller.register(
                    descriptor,
                    select.POLLOUT | select.POLLHUP | select.POLLERR,
                )
                poll_timeout = max(
                    1,
                    min(
                        2_147_483_647,
                        math.ceil(min(remaining, WAIT_SLICE_SECONDS) * 1000),
                    ),
                )
                ready = poller.poll(poll_timeout)
            except InterruptedError:
                interruptions += 1
                if interruptions > MAX_IO_INTERRUPTS:
                    raise RunnerError("runner output readiness wait did not converge")
                continue
            interruptions = 0
            writable = any(
                ready_descriptor == descriptor
                and events & (select.POLLOUT | select.POLLHUP | select.POLLERR)
                for ready_descriptor, events in ready
            )
            if not writable:
                continue
            try:
                written = os.write(descriptor, raw[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            if written <= 0:
                raise RunnerError("runner output write made no progress")
            offset += written
    finally:
        if changed_mode:
            try:
                os.set_blocking(descriptor, was_blocking)
            except BaseException as exc:
                raise RunnerError("cannot restore runner output descriptor mode") from exc


def best_effort_error(raw: bytes) -> None:
    """Never let a blocked caller turn a bounded failure into an unhandled traceback."""
    try:
        write_all(2, raw[:16 * 1024])
    except BaseException:
        pass


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunnerError(f"launcher-runner arguments are invalid: {message}")


def parse_arguments():
    parser = FailClosedParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--profile", choices=("diagnostic", "release"))
    return parser.parse_args()


def main() -> None:
    cancellation = CancellationLatch()
    primary: BaseException | None = None
    result: BoundedResult | None = None
    try:
        cancellation.enter()
        arguments = parse_arguments()
        cancellation.checkpoint()
        result = execute(arguments, cancellation)
        cancellation.checkpoint()
    except BaseException as exc:
        primary = exc
    primary = run_cleanup_stage(
        primary,
        lambda current: cancellation.close(current),
        "launcher-runner signal-latch settlement failed",
    )
    if primary is not None:
        raise primary
    assert result is not None
    write_all(2, result.stderr)
    write_all(1, result.stdout)
    if result.returncode:
        if result.returncode < 0:
            raise SystemExit(128 - result.returncode)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except RunnerSignal as exc:
        raise SystemExit(128 + exc.signum) from None
    except RunnerError as exc:
        best_effort_error(
            f"haptics workflow launcher runner failed: {exc}\n".encode("utf-8"),
        )
        os._exit(125)
    except Exception as exc:
        failure = runner_failure(exc, "unexpected launcher-runner failure")
        best_effort_error(
            f"haptics workflow launcher runner failed: {failure}\n".encode("utf-8"),
        )
        os._exit(125)
