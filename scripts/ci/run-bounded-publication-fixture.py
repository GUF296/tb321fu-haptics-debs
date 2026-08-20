#!/usr/bin/env python3
"""Run the privileged publication fixture with bounded Linux process custody."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import math
import os
import pathlib
import resource
import signal
import subprocess
import sys
import tempfile
import time


_ORIGINAL_SCANDIR = os.scandir


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PUBLICATION_FIXTURE = SCRIPT_DIR / "test-release-publication.sh"
PROCESS_TABLE_LIMIT = 131072
PROCESS_LIMIT = 4096
PROCESS_PASSES = 40
PIDFD_BATCH = 32
OUTPUT_LIMIT = 1024 * 1024
PUBLICATION_TIMEOUT_SECONDS = 300.0
SIGNAL_POLL_SECONDS = 0.05
MAX_PENDING_SIGNAL_DRAIN = 16
PUBLICATION_RESULT_MARKER = b"RESULT=PASS release-publication-regressions\n"
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
SA_NOCLDWAIT = 2
LINUX_SIGSET_BITS = 1024
NATIVE_WORD_BITS = 8 * ctypes.sizeof(ctypes.c_ulong)
KERNEL_SIGSET_BITS = int(signal.NSIG) - 1
KERNEL_SIGSET_WORDS = (
    KERNEL_SIGSET_BITS + NATIVE_WORD_BITS - 1
) // NATIVE_WORD_BITS
PROCESS_CHILDREN_LIMIT = PROCESS_TABLE_LIMIT * 16


class RunnerError(Exception):
    """Fixed-domain publication runner failure."""


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


def add_failure_evidence(
    target: BaseException,
    source: BaseException,
    note: str,
) -> None:
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
        new.add_note(
            f"{note}: earlier {type(current).__name__}: {current}"
        )
        for current_note in getattr(current, "__notes__", ()):
            new.add_note(f"{note}: earlier note: {current_note}")
        if new.__cause__ is None:
            new.__cause__ = current
        return new
    if new is not current:
        add_failure_evidence(current, new, note)
    return current


def inspect_sigchld_action() -> LinuxSigaction:
    action = LinuxSigaction()
    libc = ctypes.CDLL(None, use_errno=True)
    sigaction = libc.sigaction
    sigaction.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(LinuxSigaction),
        ctypes.POINTER(LinuxSigaction),
    ]
    sigaction.restype = ctypes.c_int
    ctypes.set_errno(0)
    if sigaction(signal.SIGCHLD, None, ctypes.byref(action)) != 0:
        error = OSError(
            ctypes.get_errno(),
            "cannot inspect publication runner SIGCHLD action",
        )
        raise RunnerError(
            "cannot inspect publication runner SIGCHLD policy"
        ) from error
    if KERNEL_SIGSET_WORDS <= 0 or KERNEL_SIGSET_WORDS > len(action.mask.words):
        raise RunnerError("publication runner kernel signal domain is invalid")
    remainder = KERNEL_SIGSET_BITS % NATIVE_WORD_BITS
    if remainder:
        action.mask.words[KERNEL_SIGSET_WORDS - 1] &= (1 << remainder) - 1
    for index in range(KERNEL_SIGSET_WORDS, len(action.mask.words)):
        action.mask.words[index] = 0
    return action


def apply_sigchld_action(action: LinuxSigaction) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    sigaction = libc.sigaction
    sigaction.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(LinuxSigaction),
        ctypes.POINTER(LinuxSigaction),
    ]
    sigaction.restype = ctypes.c_int
    ctypes.set_errno(0)
    if sigaction(signal.SIGCHLD, ctypes.byref(action), None) != 0:
        error = OSError(
            ctypes.get_errno(),
            "cannot set publication runner SIGCHLD action",
        )
        raise RunnerError(
            "cannot set publication runner SIGCHLD policy"
        ) from error


def copy_sigaction(action: LinuxSigaction) -> LinuxSigaction:
    copied = LinuxSigaction()
    ctypes.memmove(
        ctypes.byref(copied),
        ctypes.byref(action),
        ctypes.sizeof(LinuxSigaction),
    )
    return copied


def sigaction_complete_signature(
    action: LinuxSigaction,
) -> tuple[int, int, int, tuple[int, ...]]:
    mask_words = [
        int(action.mask.words[index])
        for index in range(KERNEL_SIGSET_WORDS)
    ]
    remainder = KERNEL_SIGSET_BITS % NATIVE_WORD_BITS
    if remainder:
        mask_words[-1] &= (1 << remainder) - 1
    return (
        int(action.handler or 0),
        int(action.flags),
        int(action.restorer or 0),
        tuple(mask_words),
    )


def require_waitable_sigchld_policy() -> None:
    action = inspect_sigchld_action()
    if action.handler not in (None, 0) or action.flags & SA_NOCLDWAIT:
        raise RunnerError("publication runner requires default SIGCHLD policy")


def close_owned_descriptor(
    descriptor: int,
    label: str,
) -> tuple[BaseException | None, bool]:
    failure: BaseException | None = None
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            failure = choose_failure(
                failure,
                exc,
                f"{label} close also failed",
            )
            try:
                os.fstat(descriptor)
            except OSError as probe:
                if probe.errno == errno.EBADF:
                    return failure, True
                failure = choose_failure(
                    failure,
                    probe,
                    f"{label} close-state inspection also failed",
                )
            except BaseException as probe:
                failure = choose_failure(
                    failure,
                    probe,
                    f"{label} close-state inspection also failed",
                )
            continue
        return failure, True
    try:
        os.fstat(descriptor)
    except OSError as probe:
        if probe.errno == errno.EBADF:
            return failure, True
        failure = choose_failure(
            failure,
            probe,
            f"{label} terminal close-state inspection also failed",
        )
    except BaseException as probe:
        failure = choose_failure(
            failure,
            probe,
            f"{label} terminal close-state inspection also failed",
        )
    return failure, False


def settle_owned_descriptor(
    descriptor: int,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    close_error, closed = close_owned_descriptor(descriptor, label)
    if close_error is not None:
        if not isinstance(close_error, Exception):
            candidate = close_error
        else:
            candidate = RunnerError(f"{label} cleanup failed")
            candidate.__cause__ = close_error
            add_failure_evidence(
                candidate,
                close_error,
                f"{label} cleanup failure",
            )
        primary = choose_failure(
            primary,
            candidate,
            f"{label} cleanup also failed",
        )
    if not closed:
        primary = choose_failure(
            primary,
            RunnerError(f"{label} cleanup did not converge"),
            f"{label} cleanup also did not converge",
        )
    return primary


def fixed_descriptor_failure(exc: BaseException, message: str) -> BaseException:
    if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
        return exc
    failure = RunnerError(message)
    failure.__cause__ = exc
    return failure


def finish_descriptor_snapshot(
    descriptors: set[int],
    partial: set[int] | None,
    label: str,
) -> frozenset[int]:
    candidates = set(descriptors)
    if partial is not None:
        partial.clear()
        partial.update(candidates)
    live: set[int] = set()
    primary: BaseException | None = None
    for descriptor in sorted(descriptors):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                candidates.discard(descriptor)
                continue
            primary = choose_failure(
                primary,
                fixed_descriptor_failure(exc, f"cannot inspect {label}"),
                f"{label} entry inspection also failed",
            )
        except BaseException as exc:
            primary = choose_failure(
                primary,
                fixed_descriptor_failure(exc, f"cannot inspect {label}"),
                f"{label} entry inspection also failed",
            )
        else:
            live.add(descriptor)
    if partial is not None:
        partial.clear()
        partial.update(candidates)
    if primary is not None:
        raise primary
    return frozenset(live)


def trusted_descriptor_set(
    partial: set[int] | None = None,
    _scandir=_ORIGINAL_SCANDIR,
) -> frozenset[int]:
    entries = None
    primary: BaseException | None = None
    descriptors: set[int] = set()
    try:
        entries = _scandir("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > PROCESS_TABLE_LIMIT:
                raise RunnerError(
                    "publication runner descriptor table exceeds its bound"
                )
            if entry.name.isascii() and entry.name.isdecimal():
                descriptors.add(int(entry.name, 10))
    except BaseException as exc:
        primary = fixed_descriptor_failure(
            exc,
            "cannot inspect trusted publication runner descriptor custody",
        )
    if entries is not None:
        primary = settle_scandir_iterator(
            entries,
            primary,
            "trusted publication runner descriptor-table iterator",
        )
    if partial is not None:
        partial.clear()
        partial.update(descriptors)
    if primary is not None:
        raise primary
    return finish_descriptor_snapshot(
        descriptors,
        partial,
        "trusted publication runner descriptor custody",
    )


def recover_scandir_acquisition(
    before: frozenset[int],
    identity: tuple[int, int],
    primary: BaseException,
    label: str,
) -> BaseException:
    after_partial: set[int] = set()
    try:
        after = trusted_descriptor_set(after_partial)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            fixed_descriptor_failure(exc, f"{label} recovery scan failed"),
            f"{label} recovery scan also failed",
        )
        after = frozenset(after_partial)
    for descriptor in sorted(after - before):
        metadata = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_failure(
                primary,
                fixed_descriptor_failure(exc, f"{label} recovery probe failed"),
                f"{label} recovery probe also failed",
            )
        identity_matches = (
            metadata is not None
            and (metadata.st_dev, metadata.st_ino) == identity
        )
        close_error, closed = close_owned_descriptor(descriptor, label)
        if close_error is not None:
            primary = choose_failure(
                primary,
                close_error,
                f"{label} recovery close also failed",
            )
        if not identity_matches:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovered an unexpected descriptor"),
                f"{label} recovery identity also differed",
            )
        if not closed:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovery did not converge"),
                f"{label} recovery also did not converge",
            )
    return primary


def open_descriptor_set(partial: set[int] | None = None) -> frozenset[int]:
    entries = None
    primary: BaseException | None = None
    descriptors: set[int] = set()
    table_metadata = os.stat("/proc/self/fd", follow_symlinks=False)
    acquisition_before = trusted_descriptor_set(partial)
    try:
        entries = os.scandir("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > PROCESS_TABLE_LIMIT:
                raise RunnerError(
                    "publication runner descriptor table exceeds its bound"
                )
            if entry.name.isascii() and entry.name.isdecimal():
                descriptors.add(int(entry.name, 10))
    except BaseException as exc:
        primary = fixed_descriptor_failure(
            exc,
            "cannot inspect publication runner descriptor custody",
        )
        if entries is None:
            primary = recover_scandir_acquisition(
                acquisition_before,
                (table_metadata.st_dev, table_metadata.st_ino),
                primary,
                "publication runner descriptor-table acquisition",
            )
    if entries is not None:
        primary = settle_scandir_iterator(
            entries,
            primary,
            "publication runner descriptor-table iterator",
        )
    if partial is not None:
        partial.clear()
        partial.update(descriptors)
    if primary is not None:
        raise primary
    return finish_descriptor_snapshot(
        descriptors,
        partial,
        "publication runner descriptor custody",
    )


def recover_descriptor_handoff(
    before: frozenset[int],
    identity: tuple[int, int],
    primary: BaseException,
    label: str,
) -> tuple[BaseException, bool]:
    recovery_failed = False
    after_partial: set[int] = set()
    try:
        after = open_descriptor_set(after_partial)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            fixed_descriptor_failure(exc, f"{label} recovery scan failed"),
            f"{label} recovery scan also failed",
        )
        after = frozenset(after_partial)
        recovery_failed = True
    for descriptor in sorted(after - before):
        metadata = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = choose_failure(
                primary,
                fixed_descriptor_failure(exc, f"{label} recovery probe failed"),
                f"{label} recovery probe also failed",
            )
            recovery_failed = True
        identity_matches = (
            metadata is not None
            and (metadata.st_dev, metadata.st_ino) == identity
        )
        close_error, closed = close_owned_descriptor(descriptor, label)
        if close_error is not None:
            primary = choose_failure(
                primary,
                close_error,
                f"{label} recovery close also failed",
            )
            recovery_failed = True
        if not identity_matches:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovered an unexpected descriptor"),
                f"{label} recovery identity also differed",
            )
            recovery_failed = True
        if not closed:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovery did not converge"),
                f"{label} recovery also did not converge",
            )
            recovery_failed = True
    return primary, recovery_failed


def pidfd_target_pid(descriptor: int) -> int | None:
    try:
        raw = pathlib.Path(f"/proc/self/fdinfo/{descriptor}").read_bytes()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise RunnerError("cannot inspect publication runner pidfd identity") from exc
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise RunnerError("publication runner pidfd identity is malformed")
    targets = [line[4:] for line in raw.splitlines() if line.startswith(b"Pid:")]
    if len(targets) != 1:
        raise RunnerError("publication runner pidfd identity is malformed")
    target = targets[0].strip()
    if target == b"-1":
        return None
    if not target.isdigit():
        raise RunnerError("publication runner pidfd identity is malformed")
    return int(target, 10)


def recover_pidfd_handoff(
    before: frozenset[int],
    pid: int,
    primary: BaseException,
    label: str,
) -> tuple[BaseException, bool]:
    matched = False
    recovery_failed = False
    after_partial: set[int] = set()
    try:
        after = open_descriptor_set(after_partial)
    except BaseException as exc:
        primary = choose_failure(
            primary,
            fixed_descriptor_failure(exc, f"{label} recovery scan failed"),
            f"{label} recovery scan also failed",
        )
        after = frozenset(after_partial)
        recovery_failed = True
    for descriptor in sorted(after - before):
        try:
            is_pidfd = (
                os.readlink(f"/proc/self/fd/{descriptor}")
                == "anon_inode:[pidfd]"
            )
            target = pidfd_target_pid(descriptor) if is_pidfd else None
        except BaseException as exc:
            primary = choose_failure(
                primary,
                exc,
                f"{label} recovery identity inspection also failed",
            )
            target = None
            recovery_failed = True
        close_error, closed = close_owned_descriptor(descriptor, label)
        if close_error is not None:
            primary = choose_failure(
                primary,
                close_error,
                f"{label} recovery close also failed",
            )
            recovery_failed = True
        if target == pid and closed:
            matched = True
        elif target != pid:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovered an unexpected descriptor"),
                f"{label} recovery identity also differed",
            )
            recovery_failed = True
        if not closed:
            primary = choose_failure(
                primary,
                RunnerError(f"{label} recovery did not converge"),
                f"{label} recovery also did not converge",
            )
            recovery_failed = True
    return primary, recovery_failed or (not matched and bool(after - before))


def acquire_pidfd(
    owner: DescriptorOwner,
    pid: int,
    label: str,
) -> None:
    if owner.descriptor >= 0:
        raise RunnerError(f"{label} owner is already populated")
    baseline = open_descriptor_set()
    try:
        owner.descriptor = os.pidfd_open(pid, 0)
    except BaseException as exc:
        selected = exc
        if owner.descriptor >= 0:
            selected = settle_owned_descriptor(
                owner.descriptor,
                selected,
                label,
            ) or selected
            owner.descriptor = -1
        else:
            selected, _ = recover_pidfd_handoff(
                baseline,
                pid,
                selected,
                label,
            )
        raise selected


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
                exc,
                f"{label} close also failed",
            )
            continue
        closed = True
        break
    if not closed:
        primary = choose_failure(
            primary,
            RunnerError(f"{label} close did not converge"),
            f"{label} custody also did not converge",
        )
    return primary


class CancellationLatch:
    def __init__(self) -> None:
        self.signals = {signal.SIGINT, signal.SIGTERM}
        self.original_mask: frozenset[signal.Signals] | None = None
        self.signum: int | None = None
        self.previous_int_handler = None
        self.previous_term_handler = None
        self.handlers_captured = False

    def record(self, signum, _frame=None) -> None:
        if self.signum is None or signum == signal.SIGINT:
            self.signum = signum

    def consume_pending(self) -> None:
        for _ in range(MAX_PENDING_SIGNAL_DRAIN):
            try:
                pending = signal.sigtimedwait(self.signals, 0)
            except InterruptedError:
                continue
            except OSError as exc:
                raise RunnerError("cannot consume pending runner signal") from exc
            if pending is None:
                return
            self.record(pending.si_signo)
        raise RunnerError("pending publication runner signals did not converge")

    @staticmethod
    def retry(operation, message: str) -> BaseException | None:
        failure: BaseException | None = None
        for _ in range(3):
            try:
                operation()
                return failure
            except BaseException as exc:
                failure = choose_failure(failure, exc, message)
        if failure is None:
            failure = RunnerError(message)
        failure.add_note(message)
        return failure

    def restore_handlers(self) -> tuple[BaseException, ...]:
        if not self.handlers_captured:
            return ()
        failures: list[BaseException] = []
        for signum, handler, label in (
            (signal.SIGTERM, self.previous_term_handler, "SIGTERM"),
            (signal.SIGINT, self.previous_int_handler, "SIGINT"),
        ):
            failure = self.retry(
                lambda signum=signum, handler=handler: signal.signal(signum, handler),
                f"publication runner {label} handler restore did not converge",
            )
            if failure is not None:
                failures.append(failure)
        return tuple(failures)

    def install(self) -> None:
        if not hasattr(signal, "sigtimedwait"):
            raise RunnerError("publication runner requires bounded signal waits")
        primary: BaseException | None = None
        try:
            try:
                self.original_mask = frozenset(
                    signal.pthread_sigmask(signal.SIG_BLOCK, set())
                )
            except BaseException as exc:
                if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
                    raise
                raise RunnerError(
                    "cannot inspect publication runner signal mask"
                ) from exc
            try:
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
            except BaseException as exc:
                raise
            if frozenset(previous) != self.original_mask:
                raise RunnerError(
                    "publication runner signal mask changed during installation"
                )
            if self.original_mask & self.signals:
                raise RunnerError("publication runner inherited blocked cancellation")
            self.previous_int_handler = signal.getsignal(signal.SIGINT)
            self.previous_term_handler = signal.getsignal(signal.SIGTERM)
            self.handlers_captured = True
            signal.signal(signal.SIGINT, self.record)
            signal.signal(signal.SIGTERM, self.record)
            self.consume_pending()
            signal.pthread_sigmask(signal.SIG_SETMASK, self.original_mask)
            return
        except BaseException as exc:
            if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
                primary = exc
            else:
                primary = RunnerError("cannot install publication runner signal state")
                primary.__cause__ = exc
        failures = list(self.restore_handlers())
        if self.original_mask is not None:
            failure = self.retry(
                lambda: signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    self.original_mask,
                ),
                "publication runner signal-mask restore did not converge",
            )
            if failure is not None:
                failures.append(failure)
        if primary is None:
            primary = RunnerError("cannot install publication runner signal state")
        for failure in failures:
            primary = choose_failure(
                primary,
                failure,
                "publication runner signal installation cleanup also failed",
            )
        raise primary

    def checkpoint(self) -> None:
        if self.signum is not None:
            raise RunnerError("publication fixture was cancelled")

    def close(self, primary: BaseException | None) -> None:
        if self.original_mask is None:
            raise RunnerError(
                "publication runner signal close has no installed mask state"
            )
        failures: list[BaseException] = []
        blocked = False
        for _ in range(3):
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
            except BaseException as exc:
                failures.append(exc)
            try:
                current_mask = frozenset(
                    signal.pthread_sigmask(signal.SIG_BLOCK, set())
                )
            except BaseException as exc:
                failures.append(exc)
                continue
            if self.signals <= current_mask:
                blocked = True
                break
        if not blocked:
            failures.append(
                RunnerError(
                    "publication runner terminal cancellation block did not converge"
                )
            )
        else:
            try:
                self.consume_pending()
            except BaseException as exc:
                failures.append(exc)
            failures.extend(self.restore_handlers())
            try:
                self.consume_pending()
            except BaseException as exc:
                failures.append(exc)
            failure = self.retry(
                lambda: signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    self.original_mask,
                ),
                "publication runner signal-mask restore did not converge",
            )
            if failure is not None:
                failures.append(failure)
        if self.signum is not None:
            cancellation = RunnerSignal(self.signum)
            if primary is not None:
                add_failure_evidence(
                    cancellation,
                    primary,
                    "publication runner failed before cancellation cleanup completed",
                )
            for failure in failures:
                add_failure_evidence(
                    cancellation,
                    failure,
                    "publication runner cancellation cleanup also failed",
                )
            raise cancellation
        if primary is not None:
            selected = primary
            for failure in failures:
                selected = choose_failure(
                    selected,
                    failure,
                    "publication runner signal restoration also failed",
                )
            if selected is not primary:
                raise selected
            return
        if failures:
            selected: BaseException | None = None
            for failure in failures:
                selected = choose_failure(
                    selected,
                    failure,
                    "publication runner signal restoration also failed",
                )
            assert selected is not None
            if not isinstance(selected, Exception):
                raise selected
            failure = RunnerError("publication runner signal restoration failed")
            add_failure_evidence(
                failure,
                selected,
                "publication runner signal restoration failed",
            )
            failure.__cause__ = selected
            raise failure


def signal_state() -> tuple[
    frozenset[signal.Signals],
    signal.Handlers,
    signal.Handlers,
]:
    return (
        frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set())),
        signal.getsignal(signal.SIGINT),
        signal.getsignal(signal.SIGTERM),
    )


def block_spawn_signals(cancellation: CancellationLatch) -> frozenset[signal.Signals]:
    if cancellation.original_mask is None:
        raise RunnerError("publication runner spawn mask has no original state")
    try:
        previous = frozenset(
            signal.pthread_sigmask(signal.SIG_BLOCK, cancellation.signals)
        )
    except BaseException as exc:
        recovered: frozenset[signal.Signals] | None = None
        try:
            current = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
        except BaseException as recovery:
            selected = choose_failure(
                exc,
                recovery,
                "publication runner could not recover its applied spawn mask",
            )
            if selected is not exc:
                raise selected
            exc.add_note("publication runner could not recover its applied spawn mask")
        else:
            recovered = (
                frozenset(current - cancellation.signals)
                if cancellation.signals <= current
                else current
            )
            failure = CancellationLatch.retry(
                lambda: signal.pthread_sigmask(signal.SIG_SETMASK, recovered),
                "publication runner spawn-mask recovery did not converge",
            )
            if failure is not None:
                selected = choose_failure(
                    exc,
                    failure,
                    "publication runner spawn-mask recovery also failed",
                )
                if selected is not exc:
                    raise selected
        if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
            raise
        raise RunnerError("cannot block publication runner spawn signals") from exc
    if previous != cancellation.original_mask:
        failure = CancellationLatch.retry(
            lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous),
            "publication runner unexpected spawn mask restore did not converge",
        )
        mismatch = RunnerError("publication runner spawn mask changed unexpectedly")
        if failure is not None:
            raise choose_failure(
                mismatch,
                failure,
                "publication runner unexpected spawn-mask restore also failed",
            )
        raise mismatch
    return previous


def restore_spawn_mask(
    spawn_mask: frozenset[signal.Signals],
    primary: BaseException | None,
) -> BaseException | None:
    failure = CancellationLatch.retry(
        lambda: signal.pthread_sigmask(signal.SIG_SETMASK, spawn_mask),
        "publication runner spawn-mask restore did not converge",
    )
    if failure is None:
        return primary
    if primary is not None:
        return choose_failure(
            primary,
            failure,
            "publication runner spawn-mask restore also failed",
        )
    if not isinstance(failure, Exception):
        return failure
    restored = RunnerError("cannot restore publication runner spawn mask")
    restored.add_note(str(failure))
    return restored


class BinaryCapture:
    def __init__(self) -> None:
        self.buffer = tempfile.SpooledTemporaryFile(max_size=OUTPUT_LIMIT + 1)

    def write(self, text: str) -> int:
        raw = text.encode("utf-8")
        self.buffer.write(raw)
        return len(text)

    def flush(self) -> None:
        self.buffer.flush()

    def bytes(self) -> bytes:
        self.buffer.seek(0)
        return self.buffer.read(OUTPUT_LIMIT + 1)

    def close(self) -> None:
        self.buffer.close()


def verify_post_checkpoint_cancellation() -> None:
    expected_signal_state = signal_state()
    original_argv = sys.argv
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    original_run_bounded = globals()["run_bounded"]
    original_checkpoint = CancellationLatch.checkpoint

    def fixture_run(*_args, **_kwargs) -> BoundedResult:
        return BoundedResult(0, b"PUBLICATION_CHILD=PASS\n", b"")

    for injected_signal, expected_status in (
        (signal.SIGINT, 130),
        (signal.SIGTERM, 143),
    ):
        stdout = BinaryCapture()
        stderr = BinaryCapture()
        checkpoints = 0

        def checkpoint_then_cancel(self) -> None:
            nonlocal checkpoints
            original_checkpoint(self)
            checkpoints += 1
            if checkpoints == 2:
                os.kill(os.getpid(), injected_signal)

        globals()["run_bounded"] = fixture_run
        CancellationLatch.checkpoint = checkpoint_then_cancel
        sys.argv = [str(pathlib.Path(__file__).resolve())]
        sys.stdout = stdout
        sys.stderr = stderr
        caught: SystemExit | None = None
        try:
            main()
        except SystemExit as exc:
            caught = exc
        finally:
            sys.argv = original_argv
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            globals()["run_bounded"] = original_run_bounded
            CancellationLatch.checkpoint = original_checkpoint
        try:
            if (
                checkpoints != 2
                or caught is None
                or caught.code != expected_status
                or stdout.bytes()
                or stderr.bytes()
                or signal_state() != expected_signal_state
            ):
                raise RunnerError(
                    "publication runner post-checkpoint cancellation drifted: "
                    f"signal={injected_signal} checkpoints={checkpoints} "
                    f"caught={caught!r} stdout={stdout.bytes()!r} "
                    f"stderr={stderr.bytes()!r}"
                )
        finally:
            stdout.close()
            stderr.close()

    stdout = BinaryCapture()
    stderr = BinaryCapture()
    original_sigmask = signal.pthread_sigmask
    body_failure = RunnerError("injected publication runner body failure")
    cleanup_cancellation = KeyboardInterrupt(
        "injected publication runner terminal cleanup cancellation"
    )
    cancellation_injected = False
    arm_cleanup = False

    def fail_body(*_args, **_kwargs):
        nonlocal arm_cleanup
        arm_cleanup = True
        raise body_failure

    def cancel_terminal_restore(how, mask):
        nonlocal cancellation_injected
        result = original_sigmask(how, mask)
        if (
            arm_cleanup
            and not cancellation_injected
            and how == signal.SIG_SETMASK
            and frozenset(mask) == expected_signal_state[0]
        ):
            cancellation_injected = True
            raise cleanup_cancellation
        return result

    globals()["run_bounded"] = fail_body
    signal.pthread_sigmask = cancel_terminal_restore
    sys.argv = [str(pathlib.Path(__file__).resolve())]
    sys.stdout = stdout
    sys.stderr = stderr
    cleanup_caught: BaseException | None = None
    try:
        try:
            main()
        except BaseException as exc:
            cleanup_caught = exc
    finally:
        sys.argv = original_argv
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        signal.pthread_sigmask = original_sigmask
        globals()["run_bounded"] = original_run_bounded
    try:
        if (
            not cancellation_injected
            or cleanup_caught is not cleanup_cancellation
            or stdout.bytes()
            or stderr.bytes()
            or signal_state() != expected_signal_state
        ):
            raise RunnerError(
                "publication runner internal-exit cancellation priority drifted: "
                f"injected={cancellation_injected} caught={cleanup_caught!r} "
                f"stdout={stdout.bytes()!r} stderr={stderr.bytes()!r}"
            ) from cleanup_caught
    finally:
        stdout.close()
        stderr.close()


def verify_latch_state_machine(cancellation: CancellationLatch) -> None:
    expected_state = signal_state()
    normal = CancellationLatch()
    normal.install()
    normal.close(None)
    if signal_state() != expected_state:
        raise RunnerError("publication runner normal latch restoration drifted")

    original_sigmask = signal.pthread_sigmask
    cancellation_signals = frozenset((signal.SIGINT, signal.SIGTERM))
    base_mask = expected_state[0] - cancellation_signals
    for inherited_subset in (
        frozenset(),
        frozenset((signal.SIGINT,)),
        frozenset((signal.SIGTERM,)),
        cancellation_signals,
    ):
        inherited_mask = frozenset(base_mask | inherited_subset)
        original_sigmask(signal.SIG_SETMASK, inherited_mask)
        for applied in (False, True):
            mask_injected = False
            tested_latch = CancellationLatch()

            def mask_fail(how, mask):
                nonlocal mask_injected
                if (
                    not mask_injected
                    and how == signal.SIG_BLOCK
                    and frozenset(mask) == cancellation_signals
                ):
                    mask_injected = True
                    if applied:
                        original_sigmask(how, mask)
                    raise OSError("injected runner mask installation failure")
                return original_sigmask(how, mask)

            signal.pthread_sigmask = mask_fail
            mask_failure: BaseException | None = None
            try:
                tested_latch.install()
            except BaseException as exc:
                mask_failure = exc
            finally:
                signal.pthread_sigmask = original_sigmask
            observed_mask = frozenset(
                original_sigmask(signal.SIG_BLOCK, set())
            )
            if (
                not mask_injected
                or tested_latch.original_mask != inherited_mask
                or not isinstance(mask_failure, RunnerError)
                or str(mask_failure)
                != "cannot install publication runner signal state"
                or observed_mask != inherited_mask
            ):
                original_sigmask(signal.SIG_SETMASK, expected_state[0])
                raise RunnerError(
                    "publication runner exact entry-mask recovery drifted: "
                    f"subset={sorted(inherited_subset)} applied={applied} "
                    f"observed={sorted(observed_mask)} caught={mask_failure!r}"
                ) from mask_failure
    original_sigmask(signal.SIG_SETMASK, expected_state[0])

    original_signal = signal.signal
    handler_injected = False
    partial = CancellationLatch()

    def handler_apply_then_fail(signum, handler):
        nonlocal handler_injected
        result = original_signal(signum, handler)
        if (
            not handler_injected
            and signum == signal.SIGINT
            and getattr(handler, "__self__", None) is partial
        ):
            handler_injected = True
            raise OSError("injected runner handler installation failure")
        return result

    signal.signal = handler_apply_then_fail
    handler_failure: BaseException | None = None
    try:
        partial.install()
    except BaseException as exc:
        handler_failure = exc
    finally:
        signal.signal = original_signal
    if (
        not handler_injected
        or not isinstance(handler_failure, RunnerError)
        or str(handler_failure) != "cannot install publication runner signal state"
        or signal_state() != expected_state
    ):
        raise RunnerError("publication runner handler applied-error recovery drifted")

    spawn_calls: list[tuple[int, frozenset[signal.Signals]]] = []
    spawn_injected = False

    def spawn_mask_apply_then_fail(how, mask):
        nonlocal spawn_injected
        spawn_calls.append((how, frozenset(mask)))
        result = original_sigmask(how, mask)
        if (
            not spawn_injected
            and how == signal.SIG_BLOCK
            and set(mask) == {signal.SIGINT, signal.SIGTERM}
        ):
            spawn_injected = True
            raise OSError("injected runner spawn-mask failure")
        return result

    signal.pthread_sigmask = spawn_mask_apply_then_fail
    spawn_failure: BaseException | None = None
    try:
        block_spawn_signals(cancellation)
    except BaseException as exc:
        spawn_failure = exc
    finally:
        signal.pthread_sigmask = original_sigmask
    if (
        not spawn_injected
        or not spawn_calls
        or spawn_calls[0]
        != (
            signal.SIG_BLOCK,
            frozenset((signal.SIGINT, signal.SIGTERM)),
        )
        or not isinstance(spawn_failure, RunnerError)
        or str(spawn_failure) != "cannot block publication runner spawn signals"
        or signal_state() != expected_state
    ):
        raise RunnerError("publication runner spawn-mask recovery drifted")

    retry_calls = 0
    retry_error = OSError("injected preliminary cleanup retry failure")
    retry_cancellation = KeyboardInterrupt(
        "injected cleanup retry cancellation"
    )

    def fail_then_cancel_then_succeed() -> None:
        nonlocal retry_calls
        retry_calls += 1
        if retry_calls == 1:
            raise retry_error
        if retry_calls == 2:
            raise retry_cancellation

    retry_result = CancellationLatch.retry(
        fail_then_cancel_then_succeed,
        "publication runner retry-priority oracle",
    )
    if (
        retry_calls != 3
        or retry_result is not retry_cancellation
        or "earlier OSError" not in " ".join(
            getattr(retry_result, "__notes__", ())
        )
    ):
        raise RunnerError("publication runner retry-priority oracle drifted")

    folding_latch = CancellationLatch()
    folding_latch.install()
    folding_body = RunnerError("injected folding body failure")
    folding_body.add_note("injected folding body note")
    folding_first = OSError("injected first folding cleanup failure")
    folding_cancellation = KeyboardInterrupt(
        "injected folding cleanup cancellation"
    )
    folding_later = OSError("injected later folding cleanup failure")
    original_folding_restore = folding_latch.restore_handlers

    def restore_handlers_with_evidence() -> tuple[BaseException, ...]:
        actual_failures = original_folding_restore()
        return (
            folding_first,
            folding_cancellation,
            folding_later,
            *actual_failures,
        )

    folding_latch.restore_handlers = restore_handlers_with_evidence
    folding_caught: BaseException | None = None
    try:
        folding_latch.close(folding_body)
    except BaseException as exc:
        folding_caught = exc
    folding_notes = "\n".join(
        getattr(folding_caught, "__notes__", ())
    )
    if (
        folding_caught is not folding_cancellation
        or folding_caught.__cause__ is not folding_body
        or "injected folding body failure" not in folding_notes
        or "injected folding body note" not in folding_notes
        or "injected first folding cleanup failure" not in folding_notes
        or "injected later folding cleanup failure" not in folding_notes
        or signal_state() != expected_state
    ):
        raise RunnerError(
            "publication runner terminal failure-folding oracle drifted"
        ) from folding_caught

    signum_latch = CancellationLatch()
    signum_latch.install()
    signum_body = RunnerError("injected signum body failure")
    signum_body.add_note("injected signum body nested note")
    signum_first = OSError("injected signum first cleanup failure")
    signum_first.add_note("injected signum first nested note")
    signum_cleanup_cancellation = KeyboardInterrupt(
        "injected signum cleanup cancellation"
    )
    signum_cleanup_cancellation.add_note(
        "injected signum cancellation nested note"
    )
    signum_later = OSError("injected signum later cleanup failure")
    signum_later.add_note("injected signum later nested note")
    original_signum_restore = signum_latch.restore_handlers

    def restore_signum_handlers() -> tuple[BaseException, ...]:
        actual_failures = original_signum_restore()
        return (
            signum_first,
            signum_cleanup_cancellation,
            signum_later,
            *actual_failures,
        )

    signum_latch.restore_handlers = restore_signum_handlers
    os.kill(os.getpid(), signal.SIGTERM)
    signum_caught: BaseException | None = None
    try:
        signum_latch.close(signum_body)
    except BaseException as exc:
        signum_caught = exc
    signum_notes = "\n".join(
        getattr(signum_caught, "__notes__", ())
    )
    if (
        not isinstance(signum_caught, RunnerSignal)
        or signum_caught.signum != signal.SIGTERM
        or "RunnerError: injected signum body failure" not in signum_notes
        or "injected signum body nested note" not in signum_notes
        or "OSError: injected signum first cleanup failure" not in signum_notes
        or "injected signum first nested note" not in signum_notes
        or "KeyboardInterrupt: injected signum cleanup cancellation"
        not in signum_notes
        or "injected signum cancellation nested note" not in signum_notes
        or "OSError: injected signum later cleanup failure" not in signum_notes
        or "injected signum later nested note" not in signum_notes
        or signal_state() != expected_state
    ):
        raise RunnerError(
            "publication runner signum evidence-folding oracle drifted"
        ) from signum_caught

    original_sigtimedwait = signal.sigtimedwait
    drain_calls = 0

    class PendingSignal:
        si_signo = signal.SIGTERM

    def endless_pending(_signals, _timeout):
        nonlocal drain_calls
        drain_calls += 1
        return PendingSignal()

    signal.sigtimedwait = endless_pending
    drain_failure: BaseException | None = None
    try:
        CancellationLatch().consume_pending()
    except BaseException as exc:
        drain_failure = exc
    finally:
        signal.sigtimedwait = original_sigtimedwait
    if (
        drain_calls != MAX_PENDING_SIGNAL_DRAIN
        or not isinstance(drain_failure, RunnerError)
        or str(drain_failure)
        != "pending publication runner signals did not converge"
    ):
        raise RunnerError("publication runner pending-signal bound oracle drifted")

    child = os.fork()
    if child == 0:
        exit_status = 97
        original_sigmask = signal.pthread_sigmask
        original_signal = signal.signal
        try:
            original_sigmask(
                signal.SIG_UNBLOCK,
                {signal.SIGINT, signal.SIGTERM},
            )
            original_signal(signal.SIGINT, signal.SIG_DFL)
            original_signal(signal.SIGTERM, signal.SIG_DFL)
            child_expected_state = signal_state()
            child_latch = CancellationLatch()
            child_latch.install()
            block_failed = False
            signal_sent = False

            def fail_first_terminal_block(how, mask):
                nonlocal block_failed
                if (
                    not block_failed
                    and how == signal.SIG_BLOCK
                    and frozenset(mask) == frozenset(child_latch.signals)
                ):
                    block_failed = True
                    raise OSError(
                        "injected nonapplied terminal cancellation block failure"
                    )
                return original_sigmask(how, mask)

            def signal_after_default_restore(signum, handler):
                nonlocal signal_sent
                result = original_signal(signum, handler)
                if (
                    not signal_sent
                    and signum == signal.SIGINT
                    and handler == signal.SIG_DFL
                ):
                    signal_sent = True
                    os.kill(os.getpid(), signal.SIGINT)
                return result

            signal.pthread_sigmask = fail_first_terminal_block
            signal.signal = signal_after_default_restore
            caught: BaseException | None = None
            try:
                child_latch.close(None)
            except BaseException as exc:
                caught = exc
            if (
                block_failed
                and signal_sent
                and isinstance(caught, RunnerSignal)
                and caught.signum == signal.SIGINT
                and signal_state() == child_expected_state
            ):
                exit_status = 0
            else:
                exit_status = 96
        except BaseException:
            exit_status = 95
        finally:
            signal.pthread_sigmask = original_sigmask
            signal.signal = original_signal
        os._exit(exit_status)
    while True:
        try:
            waited, child_status = os.waitpid(child, 0)
        except InterruptedError:
            continue
        break
    if (
        waited != child
        or not os.WIFEXITED(child_status)
        or os.WEXITSTATUS(child_status) != 0
    ):
        raise RunnerError(
            "publication runner terminal block/handoff oracle drifted: "
            f"status={child_status}"
        )


def verify_cleanup_resource_failures() -> None:
    mismatch_before = open_descriptor_set()
    mismatch_descriptor = os.open(
        "/dev/null",
        os.O_RDONLY | os.O_CLOEXEC,
    )
    mismatch_cancellation = KeyboardInterrupt(
        "injected publication recovery mismatch cancellation"
    )
    mismatch_selected, mismatch_failed = recover_descriptor_handoff(
        mismatch_before,
        (0, 0),
        mismatch_cancellation,
        "publication runner mismatch oracle",
    )
    try:
        os.fstat(mismatch_descriptor)
    except OSError as exc:
        mismatch_closed = exc.errno == errno.EBADF
    else:
        mismatch_closed = False
        os.close(mismatch_descriptor)
    if (
        mismatch_selected is not mismatch_cancellation
        or not mismatch_failed
        or not mismatch_closed
        or "recovery identity also differed"
        not in " ".join(getattr(mismatch_selected, "__notes__", ()))
    ):
        raise RunnerError(
            "publication runner mismatch recovery custody drifted"
        ) from mismatch_selected

    for failure_site, failure_call in (("snapshot", 1), ("helper", 3)):
        probe_before = open_descriptor_set()
        probe_metadata = os.stat("/dev/null", follow_symlinks=False)
        probe_descriptor = os.open(
            "/dev/null",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        original_fstat = os.fstat
        probe_calls = 0
        probe_cancellation = KeyboardInterrupt(
            f"injected publication recovery {failure_site} fstat cancellation"
        )

        def cancel_target_fstat(descriptor: int):
            nonlocal probe_calls
            if descriptor == probe_descriptor:
                probe_calls += 1
                if probe_calls == failure_call:
                    raise probe_cancellation
            return original_fstat(descriptor)

        os.fstat = cancel_target_fstat
        probe_selected: BaseException | None = None
        probe_failed = False
        try:
            probe_selected, probe_failed = recover_descriptor_handoff(
                probe_before,
                (probe_metadata.st_dev, probe_metadata.st_ino),
                RunnerError("injected ordinary recovery primary"),
                f"publication runner {failure_site} fstat oracle",
            )
        finally:
            os.fstat = original_fstat
        try:
            original_fstat(probe_descriptor)
        except OSError as exc:
            probe_closed = exc.errno == errno.EBADF
        else:
            probe_closed = False
            os.close(probe_descriptor)
        if (
            probe_selected is not probe_cancellation
            or not probe_failed
            or probe_calls < failure_call
            or not probe_closed
        ):
            raise RunnerError(
                f"publication runner {failure_site} fstat recovery custody drifted"
            ) from probe_selected

    original_scandir = os.scandir
    original_trusted_snapshot = globals()["trusted_descriptor_set"]
    bounded_trusted_baseline = original_trusted_snapshot()
    original_table_limit = PROCESS_TABLE_LIMIT
    iterator_calls = 0
    iterator_closed = False

    class BoundedDescriptorIterator:
        def __iter__(self):
            return self

        def __next__(self):
            nonlocal iterator_calls
            iterator_calls += 1
            if iterator_calls <= 3:
                return type("DescriptorEntry", (), {"name": str(iterator_calls)})()
            raise StopIteration

        def close(self) -> None:
            nonlocal iterator_closed
            iterator_closed = True

    globals()["PROCESS_TABLE_LIMIT"] = 2
    globals()["trusted_descriptor_set"] = (
        lambda partial=None: (
            partial.update(bounded_trusted_baseline)
            if partial is not None
            else None
        )
        or bounded_trusted_baseline
    )
    os.scandir = lambda _path: BoundedDescriptorIterator()
    bounded_failure: BaseException | None = None
    try:
        try:
            open_descriptor_set()
        except BaseException as exc:
            bounded_failure = exc
    finally:
        os.scandir = original_scandir
        globals()["trusted_descriptor_set"] = original_trusted_snapshot
        globals()["PROCESS_TABLE_LIMIT"] = original_table_limit
    if (
        not isinstance(bounded_failure, RunnerError)
        or str(bounded_failure)
        != "publication runner descriptor table exceeds its bound"
        or iterator_calls != 3
        or not iterator_closed
    ):
        raise RunnerError(
            "publication runner streaming descriptor bound oracle drifted"
        ) from bounded_failure

    acquisition_before = trusted_descriptor_set()
    acquisition_cancellation = KeyboardInterrupt(
        "injected publication descriptor-table acquisition cancellation"
    )
    retained_iterators: list[object] = []
    retained_descriptors: list[int] = []

    def cancel_scandir_after_acquisition(path: str):
        iterator = original_scandir(path)
        retained_iterators.append(iterator)
        retained_descriptors.extend(
            sorted(trusted_descriptor_set() - acquisition_before)
        )
        raise acquisition_cancellation

    os.scandir = cancel_scandir_after_acquisition
    acquisition_caught: BaseException | None = None
    try:
        try:
            open_descriptor_set()
        except BaseException as exc:
            acquisition_caught = exc
    finally:
        os.scandir = original_scandir
    retained_closed = True
    for descriptor in retained_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                retained_closed = False
        else:
            retained_closed = False
            os.close(descriptor)
    for iterator in retained_iterators:
        try:
            iterator.close()
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
    if (
        acquisition_caught is not acquisition_cancellation
        or len(retained_iterators) != 1
        or len(retained_descriptors) != 1
        or not retained_closed
    ):
        raise RunnerError(
            "publication runner descriptor acquisition custody drifted"
        ) from acquisition_caught

    pidfd_process = subprocess.Popen(
        ["/usr/bin/sleep", "30"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    original_pidfd_open = os.pidfd_open
    pidfd_descriptors: list[int] = []
    pidfd_cancellation = KeyboardInterrupt(
        "injected publication pidfd open handoff cancellation"
    )

    def cancel_pidfd_open(pid: int, flags: int) -> int:
        descriptor = original_pidfd_open(pid, flags)
        pidfd_descriptors.append(descriptor)
        raise pidfd_cancellation

    os.pidfd_open = cancel_pidfd_open
    pidfd_caught: BaseException | None = None
    pidfd_owner = DescriptorOwner()
    try:
        try:
            acquire_pidfd(
                pidfd_owner,
                pidfd_process.pid,
                "publication runner pidfd handoff oracle",
            )
        except BaseException as exc:
            pidfd_caught = exc
    finally:
        os.pidfd_open = original_pidfd_open
        try:
            os.kill(pidfd_process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        pidfd_process.wait(timeout=2.0)
    pidfd_leaked = False
    for descriptor in pidfd_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            pidfd_leaked = True
            os.close(descriptor)
    if (
        pidfd_caught is not pidfd_cancellation
        or len(pidfd_descriptors) != 1
        or pidfd_leaked
        or pidfd_owner.descriptor != -1
    ):
        raise RunnerError(
            "publication runner pidfd open handoff custody drifted"
        ) from pidfd_caught

    descendant_baseline = frozenset(direct_child_pids())
    descendant_child = os.fork()
    if descendant_child == 0:
        try:
            time.sleep(30)
        except BaseException:
            pass
        os._exit(0)
    original_acquire_pidfd = globals()["acquire_pidfd"]
    descendant_descriptors: list[int] = []
    descendant_cancelled = False
    descendant_cancellation = KeyboardInterrupt(
        "injected publication descendant pidfd helper-return cancellation"
    )

    def cancel_descendant_after_acquire(
        owner: DescriptorOwner,
        pid: int,
        label: str,
    ) -> None:
        nonlocal descendant_cancelled
        original_acquire_pidfd(owner, pid, label)
        if pid == descendant_child and not descendant_cancelled:
            descendant_cancelled = True
            descendant_descriptors.append(owner.descriptor)
            raise descendant_cancellation

    globals()["acquire_pidfd"] = cancel_descendant_after_acquire
    descendant_caught: BaseException | None = None
    try:
        try:
            cleanup_descendants(descendant_baseline)
        except BaseException as exc:
            descendant_caught = exc
    finally:
        globals()["acquire_pidfd"] = original_acquire_pidfd
    descendant_fds_closed = True
    for descriptor in descendant_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                descendant_fds_closed = False
        else:
            descendant_fds_closed = False
            os.close(descriptor)
    try:
        waited, _ = os.waitpid(descendant_child, os.WNOHANG)
    except ChildProcessError:
        descendant_reaped = True
    else:
        descendant_reaped = False
        if waited == 0:
            try:
                os.kill(descendant_child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(descendant_child, 0)
            except ChildProcessError:
                pass
    if (
        descendant_caught is not descendant_cancellation
        or not descendant_cancelled
        or len(descendant_descriptors) != 1
        or not descendant_fds_closed
        or not descendant_reaped
    ):
        raise RunnerError(
            "publication runner descendant pidfd owner-slot custody drifted"
        ) from descendant_caught

    original_read = os.read

    def short_read(descriptor: int, size: int) -> bytes:
        return original_read(descriptor, min(size, 3))

    os.read = short_read
    try:
        short_snapshot = process_map()
    finally:
        os.read = original_read
    if os.getpid() not in short_snapshot:
        raise RunnerError("publication runner process short-read oracle drifted")
    with tempfile.TemporaryFile() as oversized:
        oversized.write(b"x" * 4097)
        oversized.seek(0)
        overflow: BaseException | None = None
        try:
            read_process_record(oversized.fileno())
        except BaseException as exc:
            overflow = exc
    if (
        not isinstance(overflow, RunnerError)
        or str(overflow)
        != "publication runner process record exceeds its bound"
    ):
        raise RunnerError("publication runner process-record bound oracle drifted")
    with tempfile.TemporaryFile() as interrupted:
        expected_record = b"short process record\n"
        interrupted.write(expected_record)
        interrupted.seek(0)
        read_calls = 0

        def interrupt_twice(descriptor: int, size: int) -> bytes:
            nonlocal read_calls
            read_calls += 1
            if read_calls <= 2:
                raise InterruptedError("injected process-record interruption")
            return original_read(descriptor, size)

        os.read = interrupt_twice
        try:
            observed_record = read_process_record(interrupted.fileno())
        finally:
            os.read = original_read
    if read_calls != 4 or observed_record != expected_record:
        raise RunnerError("publication runner process-record EINTR oracle drifted")
    with tempfile.TemporaryFile() as interrupted:
        os.read = lambda _descriptor, _size: (_ for _ in ()).throw(
            InterruptedError("injected persistent process-record interruption")
        )
        interrupt_failure: BaseException | None = None
        try:
            read_process_record(interrupted.fileno())
        except BaseException as exc:
            interrupt_failure = exc
        finally:
            os.read = original_read
    if (
        not isinstance(interrupt_failure, RunnerError)
        or str(interrupt_failure)
        != "publication runner process record read did not converge"
    ):
        raise RunnerError(
            "publication runner process-record persistent-EINTR oracle drifted"
        )

    original_open = os.open
    original_close = os.close
    original_reader = globals()["read_process_record"]
    target_record = f"/proc/{os.getpid()}/stat"
    for caller_failure in (
        KeyboardInterrupt("injected process-record read cancellation"),
        SystemExit("injected process-record read exit policy"),
    ):
        for close_applied in (False, True):
            target_descriptors: list[int] = []
            close_calls = 0

            def record_target_open(path, flags, *args, **kwargs):
                descriptor = original_open(path, flags, *args, **kwargs)
                if os.fspath(path) == target_record:
                    target_descriptors.append(descriptor)
                return descriptor

            def cancel_target_read(descriptor: int) -> bytes:
                if descriptor in target_descriptors:
                    raise caller_failure
                return original_reader(descriptor)

            def fail_target_close_once(descriptor: int) -> None:
                nonlocal close_calls
                if descriptor in target_descriptors:
                    close_calls += 1
                    if close_calls == 1:
                        if close_applied:
                            original_close(descriptor)
                        raise OSError(
                            "injected process-record finalizer close failure"
                        )
                original_close(descriptor)

            os.open = record_target_open
            os.close = fail_target_close_once
            globals()["read_process_record"] = cancel_target_read
            map_caught: BaseException | None = None
            try:
                process_map()
            except BaseException as exc:
                map_caught = exc
            finally:
                globals()["read_process_record"] = original_reader
                os.close = original_close
                os.open = original_open
            target_closed = False
            if len(target_descriptors) == 1:
                try:
                    os.fstat(target_descriptors[0])
                except OSError as exc:
                    target_closed = exc.errno == errno.EBADF
            expected_close_calls = 1 if close_applied else 2
            map_notes = "\n".join(
                getattr(map_caught, "__notes__", ())
            )
            if (
                map_caught is not caller_failure
                or len(target_descriptors) != 1
                or close_calls != expected_close_calls
                or not target_closed
                or "finalizer close failure" not in map_notes
            ):
                if len(target_descriptors) == 1 and not target_closed:
                    original_close(target_descriptors[0])
                raise RunnerError(
                    "publication runner process-record finalizer priority drifted: "
                    f"applied={close_applied} caught={map_caught!r}"
                ) from map_caught

    handoff_descriptor = -1
    handoff_failure = KeyboardInterrupt(
        "injected process-record open handoff cancellation"
    )

    def cancel_after_target_open(path, flags, *args, **kwargs):
        nonlocal handoff_descriptor
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == target_record and handoff_descriptor < 0:
            handoff_descriptor = descriptor
            raise handoff_failure
        return descriptor

    os.open = cancel_after_target_open
    handoff_caught: BaseException | None = None
    try:
        process_map()
    except BaseException as exc:
        handoff_caught = exc
    finally:
        os.open = original_open
    handoff_closed = False
    if handoff_descriptor >= 0:
        try:
            os.fstat(handoff_descriptor)
        except OSError as exc:
            handoff_closed = exc.errno == errno.EBADF
    if (
        handoff_caught is not handoff_failure
        or handoff_descriptor < 0
        or not handoff_closed
    ):
        if handoff_descriptor >= 0 and not handoff_closed:
            original_close(handoff_descriptor)
        raise RunnerError(
            "publication runner process-record open-handoff oracle drifted"
        ) from handoff_caught

    expected_subreaper = inspect_subreaper()
    original_apply_subreaper = globals()["apply_subreaper"]
    subreaper_injected = False

    def subreaper_apply_then_fail(enabled: bool) -> None:
        nonlocal subreaper_injected
        original_apply_subreaper(enabled)
        if not subreaper_injected and enabled:
            subreaper_injected = True
            raise OSError("injected subreaper entry failure")

    globals()["apply_subreaper"] = subreaper_apply_then_fail
    subreaper_failure: BaseException | None = None
    try:
        enter_subreaper()
    except BaseException as exc:
        subreaper_failure = exc
    finally:
        globals()["apply_subreaper"] = original_apply_subreaper
    if (
        not subreaper_injected
        or not isinstance(subreaper_failure, RunnerError)
        or str(subreaper_failure) != "cannot enter publication runner subreaper state"
        or inspect_subreaper() != expected_subreaper
    ):
        raise RunnerError("publication runner subreaper entry recovery drifted")

    original_open = os.open
    original_close = os.close
    opened: list[int] = []
    closed: list[int] = []

    def bounded_open(path, _flags):
        if path != "/dev/null":
            return original_open(path, _flags)
        if len(opened) == 5:
            raise OSError("injected descriptor exhaustion")
        descriptor = 500000 + len(opened)
        opened.append(descriptor)
        return descriptor

    def bounded_close(descriptor):
        if descriptor in opened:
            closed.append(descriptor)
            return
        return original_close(descriptor)

    os.open = bounded_open
    os.close = bounded_close
    capacity_failure: BaseException | None = None
    try:
        preflight_pidfd_capacity()
    except BaseException as exc:
        capacity_failure = exc
    finally:
        os.open = original_open
        os.close = original_close
    if (
        not isinstance(capacity_failure, RunnerError)
        or str(capacity_failure)
        != "publication runner has insufficient descriptor capacity"
        or closed != opened
    ):
        raise RunnerError("publication runner descriptor-capacity oracle drifted")

    opened = []
    open_descriptors: set[int] = set()
    close_calls: list[int] = []
    close_error = OSError("injected nonapplied preflight close failure")
    close_cancellation = KeyboardInterrupt(
        "injected applied preflight close cancellation"
    )

    def custody_open(path, _flags):
        if path != "/dev/null":
            return original_open(path, _flags)
        descriptor = 510000 + len(opened)
        opened.append(descriptor)
        open_descriptors.add(descriptor)
        return descriptor

    def custody_close(descriptor: int) -> None:
        if descriptor not in open_descriptors:
            return original_close(descriptor)
        close_calls.append(descriptor)
        if descriptor == opened[0] and close_calls.count(descriptor) == 1:
            raise close_error
        open_descriptors.remove(descriptor)
        if descriptor == opened[0]:
            raise close_cancellation

    original_fstat = os.fstat

    def custody_fstat(descriptor: int):
        if descriptor in open_descriptors:
            return object()
        if descriptor in opened:
            raise OSError(errno.EBADF, "fixture descriptor is closed")
        return original_fstat(descriptor)

    os.open = custody_open
    os.close = custody_close
    os.fstat = custody_fstat
    custody_failure: BaseException | None = None
    try:
        preflight_pidfd_capacity()
    except BaseException as exc:
        custody_failure = exc
    finally:
        os.open = original_open
        os.close = original_close
        os.fstat = original_fstat
    if (
        custody_failure is not close_cancellation
        or len(opened) != PIDFD_BATCH + 4
        or open_descriptors
        or set(close_calls) != set(opened)
        or close_calls.count(opened[0]) != 2
    ):
        raise RunnerError(
            "publication runner descriptor-preflight custody oracle drifted"
        ) from custody_failure

    preflight_open_cancellation = KeyboardInterrupt(
        "injected publication preflight open handoff cancellation"
    )
    preflight_open_descriptors: list[int] = []

    def cancel_preflight_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == "/dev/null" and not preflight_open_descriptors:
            preflight_open_descriptors.append(descriptor)
            raise preflight_open_cancellation
        return descriptor

    os.open = cancel_preflight_open
    preflight_open_caught: BaseException | None = None
    try:
        try:
            preflight_pidfd_capacity()
        except BaseException as exc:
            preflight_open_caught = exc
    finally:
        os.open = original_open
    preflight_open_leaked = False
    for descriptor in preflight_open_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            preflight_open_leaked = True
            original_close(descriptor)
    if (
        preflight_open_caught is not preflight_open_cancellation
        or len(preflight_open_descriptors) != 1
        or preflight_open_leaked
    ):
        raise RunnerError(
            "publication runner preflight open handoff custody drifted"
        ) from preflight_open_caught

    original_owned = globals()["owned_processes"]
    original_reap = globals()["reap_owned"]
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_close = os.close
    snapshots = [
        {600001: 700001},
        {600001: 700001},
        {},
    ]
    closed_pidfds: list[int] = []

    def fixture_owned(_baseline, *, processes=None, selection_offset=0):
        del selection_offset
        if processes is not None:
            return original_owned(_baseline, processes=processes)
        if not snapshots:
            return {}
        return snapshots.pop(0)

    globals()["owned_processes"] = fixture_owned
    globals()["reap_owned"] = lambda _pids: None
    os.pidfd_open = lambda _pid, _flags: 800001

    def fail_signal(_descriptor, _signum, _info, _flags):
        raise OSError("injected pidfd signal failure")

    signal.pidfd_send_signal = fail_signal

    def close_pidfd(descriptor):
        if descriptor == 800001:
            closed_pidfds.append(descriptor)
            return
        return original_close(descriptor)

    os.close = close_pidfd
    cleanup_failure: BaseException | None = None
    try:
        cleanup_descendants(frozenset())
    except BaseException as exc:
        cleanup_failure = exc
    finally:
        globals()["owned_processes"] = original_owned
        globals()["reap_owned"] = original_reap
        os.pidfd_open = original_pidfd_open
        signal.pidfd_send_signal = original_pidfd_signal
        os.close = original_close
    if (
        not isinstance(cleanup_failure, RunnerError)
        or str(cleanup_failure)
        != "publication runner descendant cleanup encountered errors"
        or snapshots
        or closed_pidfds != [800001]
    ):
        raise RunnerError("publication runner cleanup-error oracle drifted")

    original_owned = globals()["owned_processes"]
    original_reap = globals()["reap_owned"]
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_close = os.close
    original_fstat = os.fstat
    owned = {
        600101: 700101,
        600102: 700102,
        600103: 700103,
    }
    snapshots = [owned, owned, {}]
    descriptor_to_pid: dict[int, int] = {}
    open_descriptors: set[int] = set()
    close_calls: list[int] = []
    signal_calls: list[int] = []
    reap_calls: list[set[int]] = []
    close_failed = False
    cancellation = KeyboardInterrupt(
        "injected publication descendant cleanup cancellation"
    )

    def custody_owned(_baseline, *, processes=None, selection_offset=0):
        del selection_offset
        if processes is not None:
            return original_owned(_baseline, processes=processes)
        if not snapshots:
            return {}
        return snapshots.pop(0)

    def custody_pidfd_open(pid: int, _flags: int) -> int:
        descriptor = 810000 + pid
        descriptor_to_pid[descriptor] = pid
        open_descriptors.add(descriptor)
        return descriptor

    def custody_signal(descriptor, _signum, _info, _flags) -> None:
        pid = descriptor_to_pid[descriptor]
        signal_calls.append(pid)
        if pid == 600102:
            raise cancellation

    def custody_close(descriptor: int) -> None:
        nonlocal close_failed
        if descriptor not in open_descriptors:
            return original_close(descriptor)
        close_calls.append(descriptor)
        if descriptor_to_pid[descriptor] == 600101 and not close_failed:
            close_failed = True
            raise OSError("injected nonapplied descendant pidfd close failure")
        open_descriptors.remove(descriptor)

    def custody_fstat(descriptor: int):
        if descriptor in open_descriptors:
            return object()
        if descriptor in descriptor_to_pid:
            raise OSError(errno.EBADF, "fixture descriptor is closed")
        return original_fstat(descriptor)

    globals()["owned_processes"] = custody_owned
    globals()["reap_owned"] = lambda pids: reap_calls.append(set(pids))
    os.pidfd_open = custody_pidfd_open
    signal.pidfd_send_signal = custody_signal
    os.close = custody_close
    os.fstat = custody_fstat
    custody_failure: BaseException | None = None
    try:
        cleanup_descendants(frozenset())
    except BaseException as exc:
        custody_failure = exc
    finally:
        globals()["owned_processes"] = original_owned
        globals()["reap_owned"] = original_reap
        os.pidfd_open = original_pidfd_open
        signal.pidfd_send_signal = original_pidfd_signal
        os.close = original_close
        os.fstat = original_fstat
    expected_descriptors = {810000 + pid for pid in owned}
    if (
        custody_failure is not cancellation
        or not close_failed
        or signal_calls != sorted(owned)
        or len(reap_calls) != 1
        or reap_calls[0] != set(owned)
        or open_descriptors
        or set(close_calls) != expected_descriptors
        or close_calls.count(810000 + 600101) != 2
        or snapshots
    ):
        raise RunnerError(
            "publication runner descendant custody/cancellation oracle drifted"
        ) from custody_failure

    original_owned = globals()["owned_processes"]
    original_reap = globals()["reap_owned"]
    original_direct = globals()["direct_child_pids"]
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    persistent_identity = {620001: 720001}
    persistent_cancellation = KeyboardInterrupt(
        "injected persistent descendant cleanup cancellation"
    )
    persistent_opened: list[int] = []
    persistent_signal_calls = 0
    persistent_reap_calls = 0

    def persistent_owned(
        _baseline,
        *,
        processes=None,
        selection_offset=0,
    ):
        del _baseline, selection_offset
        if processes is not None:
            return original_owned(
                frozenset(),
                processes=processes,
            )
        return dict(persistent_identity)

    def persistent_pidfd_open(_pid: int, _flags: int) -> int:
        descriptor = original_open(
            "/dev/null",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        persistent_opened.append(descriptor)
        return descriptor

    def persistent_signal(_descriptor, _signum, _info, _flags) -> None:
        nonlocal persistent_signal_calls
        persistent_signal_calls += 1
        if persistent_signal_calls == 1:
            raise persistent_cancellation

    def persistent_reap(_pids: set[int]) -> None:
        nonlocal persistent_reap_calls
        persistent_reap_calls += 1

    globals()["owned_processes"] = persistent_owned
    globals()["reap_owned"] = persistent_reap
    globals()["direct_child_pids"] = lambda: set()
    os.pidfd_open = persistent_pidfd_open
    signal.pidfd_send_signal = persistent_signal
    persistent_caught: BaseException | None = None
    try:
        cleanup_descendants(frozenset())
    except BaseException as exc:
        persistent_caught = exc
    finally:
        signal.pidfd_send_signal = original_pidfd_signal
        os.pidfd_open = original_pidfd_open
        globals()["direct_child_pids"] = original_direct
        globals()["reap_owned"] = original_reap
        globals()["owned_processes"] = original_owned
    persistent_closed = True
    for descriptor in persistent_opened:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                persistent_closed = False
        else:
            persistent_closed = False
            original_close(descriptor)
    if (
        persistent_caught is not persistent_cancellation
        or persistent_signal_calls != PROCESS_PASSES
        or persistent_reap_calls != PROCESS_PASSES
        or len(persistent_opened) != PROCESS_PASSES
        or not persistent_closed
        or "did not converge" not in "\n".join(
            getattr(persistent_caught, "__notes__", ())
        )
    ):
        raise RunnerError(
            "publication runner descendant nonconvergence priority drifted"
        ) from persistent_caught

    original_process_map = globals()["process_map"]
    original_reap = globals()["reap_owned"]
    original_direct = globals()["direct_child_pids"]
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_process_limit = PROCESS_LIMIT
    original_process_passes = PROCESS_PASSES
    rotating_pids = (630001, 630002, 630003)
    rotating_map = {
        pid: (os.getpid(), 730000 + index)
        for index, pid in enumerate(rotating_pids, 1)
    }
    rotating_attempts: list[int] = []
    rotating_signals: list[int] = []
    rotating_descriptors: dict[int, int] = {}
    rotating_opened: list[int] = []

    def rotating_pidfd_open(pid: int, _flags: int) -> int:
        rotating_attempts.append(pid)
        if pid in rotating_pids[:2]:
            raise OSError("injected persistent first-page pidfd failure")
        descriptor = original_open(
            "/dev/null",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        rotating_descriptors[descriptor] = pid
        rotating_opened.append(descriptor)
        return descriptor

    def rotating_signal(descriptor, _signum, _info, _flags) -> None:
        rotating_signals.append(rotating_descriptors[descriptor])

    globals()["PROCESS_LIMIT"] = 2
    globals()["PROCESS_PASSES"] = 3
    globals()["process_map"] = lambda: dict(rotating_map)
    globals()["reap_owned"] = lambda _pids: None
    globals()["direct_child_pids"] = lambda: set()
    os.pidfd_open = rotating_pidfd_open
    signal.pidfd_send_signal = rotating_signal
    rotating_caught: BaseException | None = None
    try:
        cleanup_descendants(frozenset())
    except BaseException as exc:
        rotating_caught = exc
    finally:
        signal.pidfd_send_signal = original_pidfd_signal
        os.pidfd_open = original_pidfd_open
        globals()["direct_child_pids"] = original_direct
        globals()["reap_owned"] = original_reap
        globals()["process_map"] = original_process_map
        globals()["PROCESS_PASSES"] = original_process_passes
        globals()["PROCESS_LIMIT"] = original_process_limit
    rotating_closed = True
    for descriptor in rotating_opened:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                rotating_closed = False
        else:
            rotating_closed = False
            original_close(descriptor)
    if (
        not isinstance(rotating_caught, RunnerError)
        or set(rotating_attempts) != set(rotating_pids)
        or rotating_pids[2] not in rotating_signals
        or not rotating_closed
    ):
        raise RunnerError(
            "publication runner descendant pagination oracle drifted: "
            f"attempted={rotating_attempts} signalled={rotating_signals}"
        ) from rotating_caught


def inspect_subreaper() -> bool:
    current = ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
        raise RunnerError("cannot inspect publication runner subreaper state")
    return bool(current.value)


def apply_subreaper(enabled: bool) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(
        PR_SET_CHILD_SUBREAPER,
        int(enabled),
        0,
        0,
        0,
    ) != 0:
        raise RunnerError("cannot set publication runner subreaper state")


def enter_subreaper() -> bool:
    previous = inspect_subreaper()
    try:
        apply_subreaper(True)
    except BaseException as exc:
        failure = CancellationLatch.retry(
            lambda: apply_subreaper(previous),
            "publication runner subreaper entry rollback did not converge",
        )
        if failure is not None:
            selected = choose_failure(
                exc,
                failure,
                "publication runner subreaper entry rollback also failed",
            )
            if selected is not exc:
                raise selected
        if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
            raise
        raise RunnerError("cannot enter publication runner subreaper state") from exc
    return previous


def restore_subreaper(
    previous: bool,
    primary: BaseException | None,
) -> tuple[BaseException | None, bool]:
    def restore_once() -> None:
        apply_subreaper(previous)
        if inspect_subreaper() != previous:
            raise RunnerError(
                "publication runner subreaper restore did not converge"
            )

    failure = CancellationLatch.retry(
        restore_once,
        "publication runner subreaper restore did not converge",
    )
    if failure is None:
        return primary, False
    if primary is not None:
        return (
            choose_failure(
                primary,
                failure,
                "publication runner subreaper restore also failed",
            ),
            True,
        )
    if not isinstance(failure, Exception):
        return failure, True
    restored = RunnerError("publication runner subreaper restore failed")
    add_failure_evidence(
        restored,
        failure,
        "publication runner subreaper restore failed",
    )
    restored.__cause__ = failure
    return restored, True


def read_bounded_record(
    descriptor: int,
    limit: int,
    overflow_message: str,
    interruption_message: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    interruptions = 0
    while total <= limit:
        try:
            chunk = os.read(descriptor, limit + 1 - total)
        except InterruptedError:
            interruptions += 1
            if interruptions > 3:
                raise RunnerError(interruption_message)
            continue
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise RunnerError(overflow_message)
    raise RunnerError(overflow_message)


def read_process_record(descriptor: int) -> bytes:
    return read_bounded_record(
        descriptor,
        4096,
        "publication runner process record exceeds its bound",
        "publication runner process record read did not converge",
    )


def fixed_process_failure(exc: BaseException, message: str) -> BaseException:
    if isinstance(exc, RunnerError) or not isinstance(exc, Exception):
        return exc
    failure = RunnerError(message)
    failure.__cause__ = exc
    return failure


def process_disappeared(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and exc.errno in (errno.ENOENT, errno.ESRCH)


def process_map() -> dict[int, tuple[int, int]]:
    processes: dict[int, tuple[int, int]] = {}
    count = 0
    entries = None
    scan_primary: BaseException | None = None
    try:
        proc_metadata = os.stat("/proc", follow_symlinks=False)
        descriptor_baseline = open_descriptor_set()
        try:
            entries = os.scandir("/proc")
        except BaseException as exc:
            candidate = fixed_process_failure(
                exc,
                "cannot inspect publication runner process table",
            )
            candidate, _ = recover_descriptor_handoff(
                descriptor_baseline,
                (proc_metadata.st_dev, proc_metadata.st_ino),
                candidate,
                "publication runner process-table iterator handoff",
            )
            raise candidate
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            count += 1
            if count > PROCESS_TABLE_LIMIT:
                raise RunnerError("publication runner process table exceeds its bound")
            pid = int(entry.name, 10)
            descriptor = -1
            raw = b""
            skipped = False
            primary: BaseException | None = None
            record_path = f"/proc/{pid}/stat"
            try:
                try:
                    record_metadata = os.stat(record_path, follow_symlinks=False)
                except BaseException as exc:
                    if process_disappeared(exc):
                        skipped = True
                    else:
                        primary = fixed_process_failure(
                            exc,
                            f"cannot inspect publication runner process record {pid}",
                        )
                if primary is None and not skipped:
                    descriptor_baseline = open_descriptor_set()
                    try:
                        descriptor = os.open(
                            record_path,
                            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        )
                    except BaseException as exc:
                        candidate = fixed_process_failure(
                            exc,
                            f"cannot open publication runner process record {pid}",
                        )
                        candidate, recovery_failed = recover_descriptor_handoff(
                            descriptor_baseline,
                            (record_metadata.st_dev, record_metadata.st_ino),
                            candidate,
                            "publication runner process-record open handoff",
                        )
                        if process_disappeared(exc) and not recovery_failed:
                            skipped = True
                        else:
                            primary = candidate
                if descriptor >= 0:
                    try:
                        opened_metadata = os.fstat(descriptor)
                        if (
                            opened_metadata.st_dev,
                            opened_metadata.st_ino,
                        ) != (
                            record_metadata.st_dev,
                            record_metadata.st_ino,
                        ):
                            raise RunnerError(
                                f"publication runner process record {pid} changed"
                            )
                        raw = read_process_record(descriptor)
                    except BaseException as exc:
                        if process_disappeared(exc):
                            skipped = True
                        else:
                            primary = fixed_process_failure(
                                exc,
                                f"cannot inspect publication runner process record {pid}",
                            )
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    "publication runner process-record inspection also failed",
                )
            if descriptor >= 0:
                primary = settle_owned_descriptor(
                    descriptor,
                    primary,
                    "publication runner process-table descriptor",
                )
            if primary is not None:
                if not isinstance(primary, Exception):
                    raise primary
                scan_primary = choose_failure(
                    scan_primary,
                    primary,
                    "publication runner process-table scan also failed",
                )
                continue
            if skipped:
                continue
            closing = raw.rfind(b") ")
            fields = raw[closing + 2:].split() if closing > 0 else []
            if (
                len(fields) < 20
                or not fields[1].isascii()
                or not fields[1].isdigit()
                or not fields[19].isascii()
                or not fields[19].isdigit()
            ):
                scan_primary = choose_failure(
                    scan_primary,
                    RunnerError(
                        f"publication runner process record {pid} is malformed"
                    ),
                    "publication runner process-table scan also failed",
                )
                continue
            processes[pid] = (int(fields[1], 10), int(fields[19], 10))
    except BaseException as exc:
        scan_primary = choose_failure(
            scan_primary,
            fixed_process_failure(
                exc,
                "cannot inspect publication runner process table",
            ),
            "publication runner process-table scan also failed",
        )
    if entries is not None:
        scan_primary = settle_scandir_iterator(
            entries,
            scan_primary,
            "publication runner process-table iterator",
        )
    if scan_primary is not None:
        try:
            setattr(scan_primary, "publication_processes", processes)
        except Exception:
            pass
        raise scan_primary
    return processes


def direct_child_pids() -> set[int]:
    record_path = f"/proc/self/task/{os.getpid()}/children"
    try:
        record_metadata = os.stat(record_path, follow_symlinks=False)
        descriptor_baseline = open_descriptor_set()
    except BaseException as exc:
        raise fixed_process_failure(
            exc,
            "cannot inspect publication runner direct children",
        )
    descriptor = -1
    primary: BaseException | None = None
    raw = b""
    try:
        try:
            descriptor = os.open(
                record_path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except BaseException as exc:
            candidate = fixed_process_failure(
                exc,
                "cannot open publication runner direct-child record",
            )
            candidate, _ = recover_descriptor_handoff(
                descriptor_baseline,
                (record_metadata.st_dev, record_metadata.st_ino),
                candidate,
                "publication runner direct-child record handoff",
            )
            primary = candidate
        if descriptor >= 0:
            try:
                opened_metadata = os.fstat(descriptor)
                if (
                    opened_metadata.st_dev,
                    opened_metadata.st_ino,
                ) != (
                    record_metadata.st_dev,
                    record_metadata.st_ino,
                ):
                    raise RunnerError(
                        "publication runner direct-child record changed"
                    )
                raw = read_bounded_record(
                    descriptor,
                    PROCESS_CHILDREN_LIMIT,
                    "publication runner direct-child record exceeds its bound",
                    "publication runner direct-child record read did not converge",
                )
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    fixed_process_failure(
                        exc,
                        "cannot inspect publication runner direct-child record",
                    ),
                    "publication runner direct-child inspection also failed",
                )
    finally:
        if descriptor >= 0:
            primary = settle_owned_descriptor(
                descriptor,
                primary,
                "publication runner direct-child descriptor",
            )
    if primary is not None:
        raise primary
    fields = raw.split()
    if len(fields) > PROCESS_TABLE_LIMIT:
        raise RunnerError(
            "publication runner direct-child record exceeds its bound"
        )
    children: set[int] = set()
    for field in fields:
        if not field.isascii() or not field.isdigit():
            raise RunnerError(
                "publication runner direct-child record is malformed"
            )
        children.add(int(field, 10))
    return children


def preflight_pidfd_capacity() -> None:
    descriptors: list[int] = []
    primary: BaseException | None = None
    try:
        for _ in range(PIDFD_BATCH + 4):
            descriptors.append(-1)
            slot = len(descriptors) - 1
            local_descriptor = -1
            baseline = open_descriptor_set()
            null_metadata = os.stat("/dev/null", follow_symlinks=False)
            try:
                local_descriptor = os.open(
                    "/dev/null",
                    os.O_RDONLY | os.O_CLOEXEC,
                )
                descriptors[slot] = local_descriptor
                local_descriptor = -1
            except BaseException as exc:
                selected: BaseException | None = exc
                owned_descriptor = (
                    local_descriptor
                    if local_descriptor >= 0
                    else descriptors[slot]
                )
                if owned_descriptor >= 0:
                    selected = settle_owned_descriptor(
                        owned_descriptor,
                        selected,
                        "publication runner descriptor preflight handoff",
                    )
                    descriptors[slot] = -1
                else:
                    selected, _ = recover_descriptor_handoff(
                        baseline,
                        (null_metadata.st_dev, null_metadata.st_ino),
                        selected,
                        "publication runner descriptor preflight open",
                    )
                assert selected is not None
                raise selected
    except BaseException as exc:
        if not isinstance(exc, Exception):
            primary = exc
        else:
            primary = RunnerError(
                "publication runner has insufficient descriptor capacity"
            )
            primary.__cause__ = exc
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        close_error, closed = close_owned_descriptor(
            descriptor,
            "publication runner descriptor preflight",
        )
        if close_error is not None:
            if primary is None:
                if not isinstance(close_error, Exception):
                    primary = close_error
                else:
                    primary = RunnerError(
                        "publication runner descriptor preflight cleanup failed"
                    )
                    primary.__cause__ = close_error
            else:
                primary = choose_failure(
                    primary,
                    close_error,
                    "publication runner descriptor preflight cleanup also failed",
                )
        if not closed:
            not_closed = RunnerError(
                "publication runner descriptor preflight cleanup did not converge"
            )
            primary = choose_failure(
                primary,
                not_closed,
                "publication runner descriptor preflight cleanup also failed",
            )
    if primary is not None:
        raise primary


def owned_processes(
    baseline_children: frozenset[int],
    *,
    processes: dict[int, tuple[int, int]] | None = None,
    selection_offset: int = 0,
) -> dict[int, int]:
    snapshot = process_map() if processes is None else processes
    owner = os.getpid()
    ordered_snapshot = sorted(snapshot.items())
    children: dict[int, list[tuple[int, int]]] = {}
    direct: list[tuple[int, int]] = []
    for pid, (parent, start_time) in ordered_snapshot:
        children.setdefault(parent, []).append((pid, start_time))
        if parent == owner and pid not in baseline_children:
            direct.append((pid, start_time))
    reachable: dict[int, int] = dict(direct)
    queue = list(reachable)
    cursor = 0
    while cursor < len(queue):
        parent = queue[cursor]
        cursor += 1
        for pid, start_time in children.get(parent, ()):
            if pid not in reachable and pid not in baseline_children:
                reachable[pid] = start_time
                queue.append(pid)
    ordered = list(reachable.items())
    if len(ordered) <= PROCESS_LIMIT:
        return dict(ordered)
    start = selection_offset % len(ordered)
    selected: dict[int, int] = {}
    for index in range(PROCESS_LIMIT):
        pid, start_time = ordered[(start + index) % len(ordered)]
        selected[pid] = start_time
    return selected


def reap_owned(pids: set[int]) -> None:
    deadline = time.monotonic() + 2.0
    pending = set(pids)
    while pending and time.monotonic() < deadline:
        for pid in tuple(pending):
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pending.discard(pid)
                continue
            except InterruptedError:
                continue
            if waited == pid:
                pending.discard(pid)
        if pending:
            time.sleep(0.01)


def cleanup_descendants(baseline_children: frozenset[int]) -> bool:
    found = False
    cleanup_error: BaseException | None = None
    selection_offset = 0

    def remember(exc: BaseException) -> None:
        nonlocal cleanup_error
        cleanup_error = choose_failure(
            cleanup_error,
            exc,
            "publication runner descendant cleanup also failed",
        )

    def snapshot_owned(offset: int) -> tuple[dict[int, int], bool]:
        try:
            return (
                owned_processes(
                    baseline_children,
                    selection_offset=offset,
                ),
                False,
            )
        except BaseException as exc:
            remember(exc)
            partial = getattr(exc, "publication_processes", None)
            if not isinstance(partial, dict):
                return {}, True
            try:
                return (
                    owned_processes(
                        baseline_children,
                        processes=partial,
                        selection_offset=offset,
                    ),
                    True,
                )
            except BaseException as partial_error:
                remember(partial_error)
                return {}, True

    def snapshot_direct(offset: int) -> tuple[set[int], bool]:
        try:
            ordered = sorted(direct_child_pids() - set(baseline_children))
        except BaseException as exc:
            remember(exc)
            return set(), True
        if len(ordered) <= PROCESS_LIMIT:
            return set(ordered), False
        start = offset % len(ordered)
        return {
            ordered[(start + index) % len(ordered)]
            for index in range(PROCESS_LIMIT)
        }, False

    for _ in range(PROCESS_PASSES):
        owned, owned_unknown = snapshot_owned(selection_offset)
        direct, direct_unknown = snapshot_direct(selection_offset)
        work: dict[int, tuple[int | None, bool]] = {
            pid: (start_time, False)
            for pid, start_time in owned.items()
        }
        for pid in direct:
            expected_start, _ = work.get(pid, (None, False))
            work[pid] = (expected_start, True)
        if not work:
            if cleanup_error is not None or owned_unknown or direct_unknown:
                if cleanup_error is not None and not isinstance(
                    cleanup_error,
                    Exception,
                ):
                    raise cleanup_error
                failure = RunnerError(
                    "publication runner descendant cleanup encountered errors"
                )
                failure.__cause__ = cleanup_error
                raise failure
            return found
        found = True
        ordered = sorted(work.items())
        for batch_offset in range(0, len(ordered), PIDFD_BATCH):
            pinned: list[tuple[int, int | None, bool, DescriptorOwner]] = []
            try:
                for pid, (expected_start_time, was_direct) in ordered[
                    batch_offset:batch_offset + PIDFD_BATCH
                ]:
                    owner = DescriptorOwner()
                    pinned.append((pid, expected_start_time, was_direct, owner))
                    try:
                        acquire_pidfd(
                            owner,
                            pid,
                            "publication runner descendant pidfd open handoff",
                        )
                    except ProcessLookupError:
                        pinned.pop()
                        continue
                    except BaseException as exc:
                        registered_owner = pinned.pop()[3]
                        if registered_owner.descriptor >= 0:
                            exc = settle_owned_descriptor(
                                registered_owner.descriptor,
                                exc,
                                "publication runner descendant pidfd registration",
                            ) or exc
                            registered_owner.descriptor = -1
                        remember(exc)
                        continue
                current, _ = snapshot_owned(selection_offset)
                current_direct, _ = snapshot_direct(selection_offset)
                for pid, expected_start_time, was_direct, owner in pinned:
                    descriptor = owner.descriptor
                    identity_matches = (
                        expected_start_time is not None
                        and current.get(pid) == expected_start_time
                    )
                    direct_matches = was_direct and pid in current_direct
                    if not identity_matches and not direct_matches:
                        continue
                    try:
                        signal.pidfd_send_signal(
                            descriptor,
                            signal.SIGKILL,
                            None,
                            0,
                        )
                    except ProcessLookupError:
                        pass
                    except BaseException as exc:
                        remember(exc)
            finally:
                for _, _, _, owner in pinned:
                    descriptor = owner.descriptor
                    if descriptor < 0:
                        continue
                    close_error, closed = close_owned_descriptor(
                        descriptor,
                        "publication runner descendant pidfd",
                    )
                    if close_error is not None:
                        remember(close_error)
                    if not closed:
                        remember(
                            RunnerError(
                                "publication runner descendant pidfd cleanup "
                                "did not converge"
                            )
                        )
                    else:
                        owner.descriptor = -1
        try:
            reap_owned(set(work))
        except BaseException as exc:
            remember(exc)
        selection_offset += PROCESS_LIMIT
        try:
            time.sleep(0.01)
        except BaseException as exc:
            remember(exc)
    remaining, remaining_unknown = snapshot_owned(selection_offset)
    remaining_direct, direct_unknown = snapshot_direct(selection_offset)
    if remaining or remaining_direct:
        failure = RunnerError(
            "publication runner descendant cleanup did not converge"
        )
        if cleanup_error is not None and not isinstance(
            cleanup_error,
            Exception,
        ):
            raise choose_failure(
                cleanup_error,
                failure,
                "publication runner descendant cleanup did not converge",
            )
        if cleanup_error is not None:
            failure.__cause__ = cleanup_error
            add_failure_evidence(
                failure,
                cleanup_error,
                "publication runner descendant cleanup earlier failure",
            )
        raise failure
    if remaining_unknown or direct_unknown or cleanup_error is not None:
        if cleanup_error is not None and not isinstance(cleanup_error, Exception):
            raise cleanup_error
        failure = RunnerError(
            "publication runner descendant cleanup encountered errors"
        )
        failure.__cause__ = cleanup_error
        raise failure
    return found


def clean_environment(home: pathlib.Path) -> dict[str, str]:
    tmpdir = home.parent / "tmp"
    tmpdir.mkdir(mode=0o700)
    metadata = tmpdir.stat(follow_symlinks=False)
    if (
        not tmpdir.is_dir()
        or tmpdir.is_symlink()
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or metadata.st_mode & 0o777 != 0o700
    ):
        raise RunnerError("publication runner TMPDIR differs from policy")
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONOPTIMIZE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def run_bounded(
    arguments: list[str],
    cwd: pathlib.Path,
    environment: dict[str, str],
    deadline: float,
    cancellation: CancellationLatch,
) -> BoundedResult:
    if (
        not arguments
        or not math.isfinite(deadline)
        or deadline <= time.monotonic()
    ):
        raise RunnerError("publication runner inputs are invalid")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RunnerError("publication runner requires pidfd support")
    require_waitable_sigchld_policy()
    previous_subreaper = enter_subreaper()
    try:
        before = process_map()
    except BaseException as exc:
        restored, _ = restore_subreaper(previous_subreaper, exc)
        if restored is not exc:
            raise restored
        raise
    baseline_children = frozenset(
        pid for pid, (parent, _) in before.items() if parent == os.getpid()
    )
    if baseline_children:
        failure = RunnerError("publication runner inherited pre-existing children")
        restored, _ = restore_subreaper(previous_subreaper, failure)
        assert restored is not None
        raise restored
    process: subprocess.Popen[bytes] | None = None
    root_pidfd = DescriptorOwner()
    primary: BaseException | None = None
    timed_out = False
    leaked_descendants = False
    containment_failed = False
    stdout = b""
    stderr = b""
    stdout_size = 0
    stderr_size = 0

    def child_setup() -> None:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        if cancellation.original_mask is None:
            raise RunnerError("publication runner child signal mask is missing")
        signal.pthread_sigmask(signal.SIG_SETMASK, cancellation.original_mask)
        limit = OUTPUT_LIMIT + 1
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    def remember_cleanup(
        failure: BaseException,
        message: str,
        *,
        containment: bool = True,
    ) -> None:
        nonlocal primary, containment_failed
        containment_failed = containment_failed or containment
        if isinstance(failure, RunnerError) or not isinstance(failure, Exception):
            candidate = failure
        else:
            candidate = RunnerError(message)
            candidate.__cause__ = failure
        primary = choose_failure(primary, candidate, message)

    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            preflight_pidfd_capacity()
            spawn_mask: frozenset[signal.Signals] | None = None
            try:
                cancellation.checkpoint()
                spawn_mask = block_spawn_signals(cancellation)
                cancellation.checkpoint()
                process = subprocess.Popen(
                    arguments,
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=child_setup,
                )
                acquire_pidfd(
                    root_pidfd,
                    process.pid,
                    "publication runner root pidfd open handoff",
                )
                primary = restore_spawn_mask(spawn_mask, primary)
                spawn_mask = None
                if primary is not None:
                    raise primary
                while process.returncode is None:
                    if cancellation.signum is not None:
                        primary = RunnerError("publication fixture was cancelled")
                        break
                    remaining = deadline - time.monotonic()
                    if not math.isfinite(remaining) or remaining <= 0:
                        timed_out = True
                        break
                    try:
                        process.wait(timeout=min(remaining, SIGNAL_POLL_SECONDS))
                    except subprocess.TimeoutExpired:
                        continue
            except BaseException as exc:
                primary = choose_failure(
                    primary,
                    exc,
                    "publication runner body also failed",
                )
            finally:
                if spawn_mask is not None:
                    primary = restore_spawn_mask(spawn_mask, primary)
                    spawn_mask = None
                if process is not None:
                    poll_known = False
                    root_running = True
                    try:
                        root_running = process.poll() is None
                        poll_known = True
                    except BaseException as exc:
                        remember_cleanup(
                            exc,
                            "publication runner root poll failed",
                        )
                    if root_running:
                        use_numeric_fallback = (
                            root_pidfd.descriptor < 0 and poll_known
                        )
                        if root_pidfd.descriptor >= 0:
                            try:
                                signal.pidfd_send_signal(
                                    root_pidfd.descriptor,
                                    signal.SIGKILL,
                                    None,
                                    0,
                                )
                            except ProcessLookupError:
                                pass
                            except BaseException as exc:
                                remember_cleanup(
                                    exc,
                                    "publication runner root pidfd signal failed",
                                )
                                use_numeric_fallback = poll_known
                        if use_numeric_fallback:
                            numeric_running = False
                            try:
                                numeric_running = process.poll() is None
                            except BaseException as exc:
                                remember_cleanup(
                                    exc,
                                    "publication runner root numeric custody poll failed",
                                )
                            if numeric_running:
                                try:
                                    os.kill(process.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                except BaseException as exc:
                                    remember_cleanup(
                                        exc,
                                        "publication runner root numeric signal failed",
                                    )
                        try:
                            process.wait(timeout=2.0)
                        except BaseException as exc:
                            remember_cleanup(
                                exc,
                                "publication runner root wait failed",
                            )
                try:
                    leaked_descendants = cleanup_descendants(baseline_children)
                except BaseException as exc:
                    remember_cleanup(
                        exc,
                        "publication runner descendant cleanup failed",
                    )
                if root_pidfd.descriptor >= 0:
                    close_error, closed = close_owned_descriptor(
                        root_pidfd.descriptor,
                        "publication runner root pidfd",
                    )
                    if close_error is not None:
                        remember_cleanup(
                            close_error,
                            "publication runner root pidfd cleanup failed",
                        )
                    if closed:
                        root_pidfd.descriptor = -1
                    else:
                        remember_cleanup(
                            RunnerError(
                                "publication runner root pidfd cleanup did not converge"
                            ),
                            "publication runner root pidfd cleanup did not converge",
                        )
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(OUTPUT_LIMIT + 1)
            stderr = stderr_file.read(OUTPUT_LIMIT + 1)
    finally:
        active = sys.exception()
        terminal = active
        if primary is not None:
            terminal = choose_failure(
                terminal,
                primary,
                "publication runner terminal selection retained an earlier failure",
            )
        if root_pidfd.descriptor >= 0:
            close_error, closed = close_owned_descriptor(
                root_pidfd.descriptor,
                "publication runner terminal root pidfd",
            )
            if close_error is not None:
                containment_failed = True
                if isinstance(close_error, RunnerError) or not isinstance(
                    close_error,
                    Exception,
                ):
                    candidate = close_error
                else:
                    candidate = RunnerError(
                        "publication runner terminal root pidfd cleanup failed"
                    )
                    candidate.__cause__ = close_error
                terminal = choose_failure(
                    terminal,
                    candidate,
                    "publication runner terminal root pidfd cleanup failed",
                )
            if closed:
                root_pidfd.descriptor = -1
            else:
                containment_failed = True
                terminal = choose_failure(
                    terminal,
                    RunnerError(
                        "publication runner terminal root pidfd cleanup did not converge"
                    ),
                    "publication runner terminal root pidfd cleanup did not converge",
                )
        restored_primary, subreaper_restore_failed = restore_subreaper(
            previous_subreaper,
            terminal,
        )
        containment_failed = containment_failed or subreaper_restore_failed
        if active is None:
            primary = restored_primary
        elif restored_primary is not active:
            raise restored_primary
    if containment_failed:
        if primary is None:
            primary = RunnerError("publication runner containment cleanup failed")
        raise primary
    if cancellation.signum is not None:
        return BoundedResult(128 + cancellation.signum, b"", b"")
    if timed_out:
        return BoundedResult(124, b"", b"publication fixture exceeded its deadline\n")
    if primary is not None:
        raise primary
    if process is None:
        raise RunnerError("publication fixture process was not created")
    if process.returncode is None:
        raise RunnerError("publication fixture process was not reaped")
    if leaked_descendants:
        return BoundedResult(125, b"", b"publication fixture left descendants\n")
    if (
        stdout_size > OUTPUT_LIMIT
        or stderr_size > OUTPUT_LIMIT
        or len(stdout) > OUTPUT_LIMIT
        or len(stderr) > OUTPUT_LIMIT
        or (stdout_size == OUTPUT_LIMIT and process.returncode != 0)
        or (stderr_size == OUTPUT_LIMIT and process.returncode != 0)
    ):
        return BoundedResult(125, b"", b"publication fixture output exceeded its bound\n")
    return BoundedResult(process.returncode, stdout, stderr)


def verify_run_cleanup_failures(
    cancellation: CancellationLatch,
    private: pathlib.Path,
    environment: dict[str, str],
) -> None:
    original_pidfd_signal = signal.pidfd_send_signal
    original_cleanup = globals()["cleanup_descendants"]
    signal_failed = False
    cleanup_calls = 0

    def fail_root_pidfd_once(descriptor, signum, info, flags):
        nonlocal signal_failed
        if not signal_failed:
            signal_failed = True
            raise OSError("injected root pidfd signal failure")
        return original_pidfd_signal(descriptor, signum, info, flags)

    def record_cleanup(baseline):
        nonlocal cleanup_calls
        cleanup_calls += 1
        return original_cleanup(baseline)

    signal.pidfd_send_signal = fail_root_pidfd_once
    globals()["cleanup_descendants"] = record_cleanup
    pidfd_failure: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
                private,
                environment,
                time.monotonic() + 0.1,
                cancellation,
            )
        except BaseException as exc:
            pidfd_failure = exc
    finally:
        signal.pidfd_send_signal = original_pidfd_signal
        globals()["cleanup_descendants"] = original_cleanup
    if (
        not signal_failed
        or cleanup_calls != 1
        or not isinstance(pidfd_failure, RunnerError)
        or str(pidfd_failure) != "publication runner root pidfd signal failed"
    ):
        raise RunnerError("publication runner root-pidfd failure oracle drifted")

    original_acquire_pidfd = globals()["acquire_pidfd"]
    original_popen = subprocess.Popen
    owner_slot_processes: list[subprocess.Popen[bytes]] = []
    owner_slot_descriptors: list[int] = []
    owner_slot_cancelled = False
    owner_slot_cancellation = KeyboardInterrupt(
        "injected publication root pidfd helper-return cancellation"
    )

    def record_owner_slot_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        owner_slot_processes.append(process)
        return process

    def cancel_root_after_acquire(
        owner: DescriptorOwner,
        pid: int,
        label: str,
    ) -> None:
        nonlocal owner_slot_cancelled
        original_acquire_pidfd(owner, pid, label)
        if not owner_slot_cancelled and "root pidfd" in label:
            owner_slot_cancelled = True
            owner_slot_descriptors.append(owner.descriptor)
            raise owner_slot_cancellation

    globals()["acquire_pidfd"] = cancel_root_after_acquire
    subprocess.Popen = record_owner_slot_process
    owner_slot_caught: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
                private,
                environment,
                time.monotonic() + 5.0,
                cancellation,
            )
        except BaseException as exc:
            owner_slot_caught = exc
    finally:
        subprocess.Popen = original_popen
        globals()["acquire_pidfd"] = original_acquire_pidfd
    owner_slot_fds_closed = True
    for descriptor in owner_slot_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                owner_slot_fds_closed = False
        else:
            owner_slot_fds_closed = False
            os.close(descriptor)
    owner_slot_processes_reaped = True
    for process in owner_slot_processes:
        if process.returncode is None:
            owner_slot_processes_reaped = False
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2.0)
            except BaseException:
                pass
    if (
        owner_slot_caught is not owner_slot_cancellation
        or not owner_slot_cancelled
        or len(owner_slot_processes) != 1
        or len(owner_slot_descriptors) != 1
        or not owner_slot_fds_closed
        or not owner_slot_processes_reaped
    ):
        raise RunnerError(
            "publication runner root pidfd owner-slot custody drifted"
        ) from owner_slot_caught

    original_pidfd_open = os.pidfd_open
    original_kill = os.kill
    original_cleanup = globals()["cleanup_descendants"]
    open_failed = False
    kill_failed = False
    cleanup_calls = 0

    def fail_root_pidfd_open_once(pid: int, flags: int):
        nonlocal open_failed
        if not open_failed:
            open_failed = True
            raise OSError("injected root pidfd open failure")
        return original_pidfd_open(pid, flags)

    def fail_numeric_kill_once(pid: int, signum: int) -> None:
        nonlocal kill_failed
        if not kill_failed:
            kill_failed = True
            raise OSError("injected root numeric signal failure")
        original_kill(pid, signum)

    def record_numeric_cleanup(baseline):
        nonlocal cleanup_calls
        cleanup_calls += 1
        return original_cleanup(baseline)

    os.pidfd_open = fail_root_pidfd_open_once
    os.kill = fail_numeric_kill_once
    globals()["cleanup_descendants"] = record_numeric_cleanup
    numeric_failure: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
                private,
                environment,
                time.monotonic() + 0.1,
                cancellation,
            )
        except BaseException as exc:
            numeric_failure = exc
    finally:
        os.pidfd_open = original_pidfd_open
        os.kill = original_kill
        globals()["cleanup_descendants"] = original_cleanup
    numeric_notes = tuple(getattr(numeric_failure, "__notes__", ()))
    if (
        not open_failed
        or not kill_failed
        or cleanup_calls != 1
        or not isinstance(numeric_failure, OSError)
        or not any("root numeric signal failed" in note for note in numeric_notes)
        or not any("root wait failed" in note for note in numeric_notes)
    ):
        raise RunnerError("publication runner numeric-signal failure oracle drifted")

    original_cleanup = globals()["cleanup_descendants"]

    def fail_cleanup(_baseline):
        raise RunnerError("injected descendant cleanup failure")

    globals()["cleanup_descendants"] = fail_cleanup
    combined_failure: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/nonexistent/tb321fu-publication-fixture"],
                private,
                environment,
                time.monotonic() + 5.0,
                cancellation,
            )
        except BaseException as exc:
            combined_failure = exc
    finally:
        globals()["cleanup_descendants"] = original_cleanup
    combined_notes = tuple(getattr(combined_failure, "__notes__", ()))
    if (
        not isinstance(combined_failure, FileNotFoundError)
        or not any(
            "publication runner descendant cleanup failed" in note
            and "injected descendant cleanup failure" in note
            for note in combined_notes
        )
    ):
        raise RunnerError("publication runner combined-primary oracle drifted")

    original_cleanup = globals()["cleanup_descendants"]
    cleanup_cancellation = KeyboardInterrupt(
        "injected publication runner cleanup cancellation"
    )
    cancellation_cleanup_calls = 0

    def cancel_cleanup(_baseline):
        nonlocal cancellation_cleanup_calls
        cancellation_cleanup_calls += 1
        raise cleanup_cancellation

    globals()["cleanup_descendants"] = cancel_cleanup
    cancellation_failure: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/nonexistent/tb321fu-publication-fixture"],
                private,
                environment,
                time.monotonic() + 5.0,
                cancellation,
            )
        except BaseException as exc:
            cancellation_failure = exc
    finally:
        globals()["cleanup_descendants"] = original_cleanup
    if (
        cancellation_cleanup_calls != 1
        or cancellation_failure is not cleanup_cancellation
        or "earlier FileNotFoundError" not in " ".join(
            getattr(cancellation_failure, "__notes__", ())
        )
    ):
        raise RunnerError(
            "publication runner cleanup-cancellation priority oracle drifted"
        ) from cancellation_failure

    original_pidfd_open = os.pidfd_open
    original_close = os.close
    root_descriptor: int | None = None
    root_close_calls: list[int] = []
    root_close_failed = False

    def record_root_pidfd(pid: int, flags: int) -> int:
        nonlocal root_descriptor
        descriptor = original_pidfd_open(pid, flags)
        if root_descriptor is None:
            root_descriptor = descriptor
        return descriptor

    def fail_root_close_once(descriptor: int) -> None:
        nonlocal root_close_failed
        if descriptor == root_descriptor:
            root_close_calls.append(descriptor)
            if not root_close_failed:
                root_close_failed = True
                raise OSError("injected nonapplied root pidfd close failure")
        original_close(descriptor)

    os.pidfd_open = record_root_pidfd
    os.close = fail_root_close_once
    root_close_failure: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
                private,
                environment,
                time.monotonic() + 0.1,
                cancellation,
            )
        except BaseException as exc:
            root_close_failure = exc
    finally:
        os.close = original_close
        os.pidfd_open = original_pidfd_open
    root_closed = False
    if root_descriptor is not None:
        try:
            os.fstat(root_descriptor)
        except OSError as exc:
            root_closed = exc.errno == errno.EBADF
    if (
        root_descriptor is None
        or not root_close_failed
        or root_close_calls != [root_descriptor, root_descriptor]
        or not root_closed
        or not isinstance(root_close_failure, RunnerError)
        or str(root_close_failure)
        != "publication runner root pidfd cleanup failed"
    ):
        if root_descriptor is not None and not root_closed:
            original_close(root_descriptor)
        raise RunnerError(
            "publication runner root-pidfd close-custody oracle drifted"
        ) from root_close_failure

    original_popen = subprocess.Popen
    original_cleanup = globals()["cleanup_descendants"]
    created: list[
        tuple[subprocess.Popen[bytes], object]
    ] = []
    poll_failure = OSError("injected publication runner root poll failure")
    poll_failed = False
    poll_cleanup_calls = 0

    def fail_first_root_poll(*args, **kwargs):
        nonlocal poll_failed
        process = original_popen(*args, **kwargs)
        original_poll = process.poll

        def fault_poll():
            nonlocal poll_failed
            if not poll_failed:
                poll_failed = True
                raise poll_failure
            return original_poll()

        process.poll = fault_poll
        created.append((process, original_poll))
        return process

    def record_poll_cleanup(baseline):
        nonlocal poll_cleanup_calls
        poll_cleanup_calls += 1
        return original_cleanup(baseline)

    subprocess.Popen = fail_first_root_poll
    globals()["cleanup_descendants"] = record_poll_cleanup
    poll_caught: BaseException | None = None
    try:
        try:
            run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
                private,
                environment,
                time.monotonic() + 0.1,
                cancellation,
            )
        except BaseException as exc:
            poll_caught = exc
    finally:
        globals()["cleanup_descendants"] = original_cleanup
        subprocess.Popen = original_popen
    oracle_reaped = True
    for process, original_poll in created:
        if original_poll() is None:
            oracle_reaped = False
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2.0)
            except BaseException:
                pass
        elif process.returncode is None:
            oracle_reaped = False
    if (
        not poll_failed
        or len(created) != 1
        or poll_cleanup_calls != 1
        or not oracle_reaped
        or not isinstance(poll_caught, RunnerError)
        or str(poll_caught) != "publication runner root poll failed"
    ):
        raise RunnerError(
            "publication runner root-poll custody oracle drifted: "
            f"cleanup_calls={poll_cleanup_calls} reaped={oracle_reaped} "
            f"caught={poll_caught!r}"
        ) from poll_caught


def verify_subreaper_restore_priority(
    cancellation: CancellationLatch,
    private: pathlib.Path,
    environment: dict[str, str],
) -> None:
    original_apply = globals()["apply_subreaper"]
    original_popen = subprocess.Popen
    initial_subreaper = inspect_subreaper()
    for restore_mode in ("applied", "persistent"):
        for terminal_case in ("timeout", signal.SIGINT, signal.SIGTERM):
            entry_seen = False
            restore_attempts = 0
            created: list[subprocess.Popen[bytes]] = []

            def inject_restore(enabled: bool) -> None:
                nonlocal entry_seen, restore_attempts
                if not entry_seen:
                    entry_seen = True
                    original_apply(enabled)
                    return
                if enabled == initial_subreaper:
                    restore_attempts += 1
                    if restore_mode == "applied" and restore_attempts == 1:
                        original_apply(enabled)
                        raise OSError(
                            "injected applied subreaper restore failure"
                        )
                    if restore_mode == "persistent":
                        raise OSError(
                            "injected persistent subreaper restore failure"
                        )
                original_apply(enabled)

            def record_terminal_process(*args, **kwargs):
                process = original_popen(*args, **kwargs)
                created.append(process)
                if terminal_case != "timeout":
                    cancellation.signum = int(terminal_case)
                return process

            globals()["apply_subreaper"] = inject_restore
            subprocess.Popen = record_terminal_process
            result: BoundedResult | None = None
            caught: BaseException | None = None
            try:
                result = run_bounded(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-c",
                        "import time;time.sleep(30)",
                    ],
                    private,
                    environment,
                    time.monotonic()
                    + (0.05 if terminal_case == "timeout" else 5.0),
                    cancellation,
                )
            except BaseException as exc:
                caught = exc
            finally:
                cancellation.signum = None
                subprocess.Popen = original_popen
                globals()["apply_subreaper"] = original_apply
            state_before_emergency_restore: bool | None = None
            final_subreaper: bool | None = None
            oracle_cleanup_error: BaseException | None = None
            oracle_reaped = True

            def remember_oracle_cleanup(exc: BaseException) -> None:
                nonlocal oracle_cleanup_error
                oracle_cleanup_error = choose_failure(
                    oracle_cleanup_error,
                    exc,
                    "publication runner subreaper oracle cleanup also failed",
                )

            try:
                state_before_emergency_restore = inspect_subreaper()
            except BaseException as exc:
                remember_oracle_cleanup(exc)
            try:
                original_apply(initial_subreaper)
            except BaseException as exc:
                remember_oracle_cleanup(exc)
            for process in created:
                running = True
                try:
                    running = process.poll() is None
                except BaseException as exc:
                    remember_oracle_cleanup(exc)
                if running:
                    oracle_reaped = False
                    try:
                        os.kill(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except BaseException as exc:
                        remember_oracle_cleanup(exc)
                try:
                    process.wait(timeout=2.0)
                except BaseException as exc:
                    remember_oracle_cleanup(exc)
                try:
                    if process.poll() is None:
                        oracle_reaped = False
                        remember_oracle_cleanup(
                            RunnerError(
                                "publication runner subreaper oracle child "
                                "settlement did not converge"
                            )
                        )
                except BaseException as exc:
                    oracle_reaped = False
                    remember_oracle_cleanup(exc)
            try:
                final_subreaper = inspect_subreaper()
            except BaseException as exc:
                remember_oracle_cleanup(exc)
            evidence = "\n".join(
                (
                    str(caught),
                    *getattr(caught, "__notes__", ()),
                )
            )
            expected_attempts = 2 if restore_mode == "applied" else 3
            if (
                result is not None
                or not isinstance(caught, RunnerError)
                or not entry_seen
                or restore_attempts != expected_attempts
                or len(created) != 1
                or not oracle_reaped
                or oracle_cleanup_error is not None
                or "subreaper restore" not in evidence
                or restore_mode not in evidence
                or final_subreaper != initial_subreaper
                or (
                    restore_mode == "persistent"
                    and not initial_subreaper
                    and state_before_emergency_restore is not True
                )
            ):
                raise RunnerError(
                    "publication runner subreaper containment-priority oracle "
                    "drifted: "
                    f"mode={restore_mode} terminal={terminal_case} "
                    f"attempts={restore_attempts} result={result!r} "
                    f"caught={caught!r} cleanup={oracle_cleanup_error!r}"
                ) from caught


def verify_sigchld_waitability_policy(
    cancellation: CancellationLatch,
    private: pathlib.Path,
    environment: dict[str, str],
) -> None:
    original_action = inspect_sigchld_action()
    parent_action = sigaction_complete_signature(original_action)
    signature_mutations: list[LinuxSigaction] = []
    for signal_number in range(1, KERNEL_SIGSET_BITS + 1):
        mask_mutation = copy_sigaction(original_action)
        bit_index = signal_number - 1
        mask_mutation.mask.words[
            bit_index // NATIVE_WORD_BITS
        ] ^= 1 << (bit_index % NATIVE_WORD_BITS)
        signature_mutations.append(mask_mutation)
    handler_mutation = copy_sigaction(original_action)
    handler_mutation.handler = int(original_action.handler or 0) ^ 1
    signature_mutations.append(handler_mutation)
    flags_mutation = copy_sigaction(original_action)
    flags_mutation.flags ^= 0x20000000
    signature_mutations.append(flags_mutation)
    restorer_mutation = copy_sigaction(original_action)
    restorer_mutation.restorer = int(original_action.restorer or 0) ^ 1
    signature_mutations.append(restorer_mutation)
    if any(
        sigaction_complete_signature(mutation) == parent_action
        for mutation in signature_mutations
    ):
        raise RunnerError("publication runner complete sigaction signature drifted")
    if KERNEL_SIGSET_WORDS < len(original_action.mask.words):
        opaque_tail_mutation = copy_sigaction(original_action)
        opaque_tail_mutation.mask.words[-1] ^= 1
        if sigaction_complete_signature(opaque_tail_mutation) != parent_action:
            raise RunnerError(
                "publication runner opaque sigset tail affected policy signature"
            )
    oracle_child = os.fork()
    if oracle_child == 0:
        exit_status = 97
        marker_reader = -1
        marker_writer = -1
        probe_child = -1
        probe_auto_reaped = False
        probe_reaped_by_oracle = False
        try:
            no_wait_action = copy_sigaction(inspect_sigchld_action())
            no_wait_action.handler = None
            no_wait_action.flags |= SA_NOCLDWAIT
            apply_sigchld_action(no_wait_action)
            installed_action = inspect_sigchld_action()
            installed_signature = sigaction_complete_signature(installed_action)
            if (
                installed_action.handler not in (None, 0)
                or not installed_action.flags & SA_NOCLDWAIT
            ):
                raise RunnerError(
                    "publication runner SA_NOCLDWAIT setup oracle drifted"
                )
            marker_reader, marker_writer = os.pipe2(os.O_CLOEXEC)
            marker = b"SA_NOCLDWAIT_CHILD_EXIT=7\n"
            probe_child = os.fork()
            if probe_child == 0:
                try:
                    os.close(marker_reader)
                    os.write(marker_writer, marker)
                    os.close(marker_writer)
                    os._exit(7)
                except BaseException:
                    os._exit(99)
            os.close(marker_writer)
            marker_writer = -1
            os.set_blocking(marker_reader, False)
            observed = b""
            marker_eof = False
            probe_status: int | None = None
            probe_deadline = time.monotonic() + 2.0
            while time.monotonic() < probe_deadline:
                if not marker_eof:
                    try:
                        chunk = os.read(marker_reader, len(marker) + 1)
                    except BlockingIOError:
                        chunk = None
                    if chunk:
                        observed += chunk
                    elif chunk == b"":
                        marker_eof = True
                try:
                    waited, status = os.waitpid(probe_child, os.WNOHANG)
                except ChildProcessError:
                    probe_auto_reaped = True
                except InterruptedError:
                    pass
                else:
                    if waited == probe_child:
                        probe_reaped_by_oracle = True
                        probe_status = status
                if (
                    marker_eof
                    and (probe_auto_reaped or probe_reaped_by_oracle)
                ):
                    break
                time.sleep(0.01)
            policy_failure: BaseException | None = None
            try:
                run_bounded(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-c",
                        "print('RESULT=PASS release-publication-regressions');"
                        "raise SystemExit(7)",
                    ],
                    private,
                    environment,
                    time.monotonic() + 5.0,
                    cancellation,
                )
            except BaseException as exc:
                policy_failure = exc
            if (
                observed == marker
                and marker_eof
                and probe_auto_reaped
                and not probe_reaped_by_oracle
                and probe_status is None
                and isinstance(policy_failure, RunnerError)
                and str(policy_failure)
                == "publication runner requires default SIGCHLD policy"
                and sigaction_complete_signature(inspect_sigchld_action())
                == installed_signature
            ):
                exit_status = 0
            else:
                exit_status = 96
        except BaseException:
            exit_status = 95
        finally:
            for descriptor in (marker_writer, marker_reader):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if (
                probe_child > 0
                and not probe_auto_reaped
                and not probe_reaped_by_oracle
            ):
                try:
                    os.kill(probe_child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(probe_child, 0)
                except ChildProcessError:
                    pass
        os._exit(exit_status)
    oracle_status: int | None = None
    oracle_deadline = time.monotonic() + 5.0
    while time.monotonic() < oracle_deadline:
        try:
            waited, status = os.waitpid(oracle_child, os.WNOHANG)
        except InterruptedError:
            continue
        if waited == oracle_child:
            oracle_status = status
            break
        time.sleep(0.01)
    if oracle_status is None:
        try:
            os.kill(oracle_child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            _, oracle_status = os.waitpid(oracle_child, 0)
        except ChildProcessError:
            oracle_status = None
    if (
        oracle_status is None
        or not os.WIFEXITED(oracle_status)
        or os.WEXITSTATUS(oracle_status) != 0
        or sigaction_complete_signature(inspect_sigchld_action())
        != parent_action
    ):
        raise RunnerError(
            "publication runner SA_NOCLDWAIT waitability oracle drifted: "
            f"status={oracle_status!r}"
        )


def run_self_test(cancellation: CancellationLatch) -> None:
    verify_latch_state_machine(cancellation)
    verify_cleanup_resource_failures()
    with tempfile.TemporaryDirectory(prefix="tb321fu-publication-runner-test.") as raw:
        private = pathlib.Path(raw)
        home = private / "home"
        home.mkdir(mode=0o700)
        environment = clean_environment(home)
        for disposition in (signal.SIG_IGN, lambda _signum, _frame: None):
            previous_sigchld = signal.signal(signal.SIGCHLD, disposition)
            sigchld_failure: BaseException | None = None
            try:
                try:
                    run_bounded(
                        [
                            "/usr/bin/python3",
                            "-I",
                            "-B",
                            "-c",
                            "print('RESULT=PASS release-publication-regressions');"
                            "raise SystemExit(7)",
                        ],
                        private,
                        environment,
                        time.monotonic() + 5.0,
                        cancellation,
                    )
                except BaseException as exc:
                    sigchld_failure = exc
            finally:
                observed_sigchld = signal.getsignal(signal.SIGCHLD)
                signal.signal(signal.SIGCHLD, previous_sigchld)
            if (
                not isinstance(sigchld_failure, RunnerError)
                or str(sigchld_failure)
                != "publication runner requires default SIGCHLD policy"
                or observed_sigchld != disposition
            ):
                raise RunnerError("publication runner SIGCHLD policy oracle drifted")
        verify_sigchld_waitability_policy(
            cancellation,
            private,
            environment,
        )
        waitable_marker = b"RESULT=PASS release-publication-regressions\n"
        waitable_exit = run_bounded(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                "print('RESULT=PASS release-publication-regressions');"
                "raise SystemExit(7)",
            ],
            private,
            environment,
            time.monotonic() + 5.0,
            cancellation,
        )
        if waitable_exit != BoundedResult(7, waitable_marker, b""):
            raise RunnerError(
                "publication runner waitable marker/exit oracle drifted"
            )
        exact = run_bounded(
            ["/usr/bin/python3", "-I", "-B", "-c", "print('exact')"],
            private,
            environment,
            time.monotonic() + 5.0,
            cancellation,
        )
        if exact != BoundedResult(0, b"exact\n", b""):
            raise RunnerError("publication runner exact-output oracle drifted")
        flood = run_bounded(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                f"import sys;sys.stdout.buffer.write(b'x'*{OUTPUT_LIMIT + 1})",
            ],
            private,
            environment,
            time.monotonic() + 5.0,
            cancellation,
        )
        if flood.returncode == 0 or b"output exceeded" not in flood.stderr:
            raise RunnerError("publication runner output oracle drifted")
        hung = run_bounded(
            ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
            private,
            environment,
            time.monotonic() + 0.1,
            cancellation,
        )
        if hung.returncode != 124 or b"deadline" not in hung.stderr:
            raise RunnerError("publication runner deadline oracle drifted")
        verify_run_cleanup_failures(cancellation, private, environment)
        verify_subreaper_restore_priority(
            cancellation,
            private,
            environment,
        )
        identity = private / "detached.identity"
        detached_source = (
            "import os,pathlib,time\n"
            f"identity=pathlib.Path({str(identity)!r})\n"
            "child=os.fork()\n"
            "if child == 0:\n"
            " os.setsid()\n"
            " raw=pathlib.Path('/proc/self/stat').read_bytes()\n"
            " closing=raw.rfind(b') ')\n"
            " fields=raw[closing+2:].split()\n"
            " identity.write_bytes(str(os.getpid()).encode()+b'\\t'+fields[19]+b'\\n')\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "deadline=time.monotonic()+2\n"
            "while not identity.exists():\n"
            "  if time.monotonic() >= deadline: raise SystemExit(2)\n"
            "  time.sleep(0.01)\n"
            "os._exit(0)\n"
        )
        detached = run_bounded(
            ["/usr/bin/python3", "-I", "-B", "-c", detached_source],
            private,
            environment,
            time.monotonic() + 5.0,
            cancellation,
        )
        raw_identity = identity.read_bytes()
        fields = raw_identity.split(b"\t")
        if (
            detached.returncode != 125
            or b"left descendants" not in detached.stderr
            or len(fields) != 2
            or not fields[0].isdigit()
            or not fields[1].endswith(b"\n")
            or not fields[1][:-1].isdigit()
        ):
            raise RunnerError("publication runner detached-process oracle drifted")
        pid = int(fields[0], 10)
        start_time = int(fields[1][:-1], 10)
        current = process_map().get(pid)
        if current is not None and current[1] == start_time:
            raise RunnerError("publication runner left a detached process")

        eio_identity = private / "detached-eio.identity"
        eio_source = (
            "import os,pathlib,time\n"
            f"identity=pathlib.Path({str(eio_identity)!r})\n"
            "child=os.fork()\n"
            "if child == 0:\n"
            " os.setsid()\n"
            " raw=pathlib.Path('/proc/self/stat').read_bytes()\n"
            " closing=raw.rfind(b') ')\n"
            " fields=raw[closing+2:].split()\n"
            " identity.write_bytes(str(os.getpid()).encode()+b'\\t'+fields[19]+b'\\n')\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "deadline=time.monotonic()+2\n"
            "while not identity.exists():\n"
            "  if time.monotonic() >= deadline: raise SystemExit(2)\n"
            "  time.sleep(0.01)\n"
            "os._exit(0)\n"
        )
        original_open = os.open
        original_pidfd_open = os.pidfd_open
        original_pidfd_signal = signal.pidfd_send_signal
        eio_injections = 0
        target_pid: int | None = None
        target_start_time: int | None = None
        target_signalled = False
        pidfd_targets: dict[int, int] = {}

        def target_identity() -> tuple[int, int] | None:
            nonlocal target_pid, target_start_time
            if target_pid is not None and target_start_time is not None:
                return target_pid, target_start_time
            try:
                raw = eio_identity.read_bytes()
            except FileNotFoundError:
                return None
            fields = raw.split(b"\t")
            if (
                len(fields) != 2
                or not fields[0].isdigit()
                or not fields[1].endswith(b"\n")
                or not fields[1][:-1].isdigit()
            ):
                return None
            target_pid = int(fields[0], 10)
            target_start_time = int(fields[1][:-1], 10)
            return target_pid, target_start_time

        def fail_target_stat_open(path, flags, *args, **kwargs):
            nonlocal eio_injections
            identity_pair = target_identity()
            if (
                identity_pair is not None
                and not target_signalled
                and os.fspath(path) == f"/proc/{identity_pair[0]}/stat"
            ):
                eio_injections += 1
                raise OSError(errno.EIO, "injected detached process-record EIO")
            return original_open(path, flags, *args, **kwargs)

        def record_target_pidfd(pid: int, flags: int) -> int:
            descriptor = original_pidfd_open(pid, flags)
            pidfd_targets[descriptor] = pid
            return descriptor

        def record_target_signal(descriptor, signum, info, flags) -> None:
            nonlocal target_signalled
            identity_pair = target_identity()
            if (
                identity_pair is not None
                and pidfd_targets.get(descriptor) == identity_pair[0]
            ):
                target_signalled = True
            original_pidfd_signal(descriptor, signum, info, flags)

        os.open = fail_target_stat_open
        os.pidfd_open = record_target_pidfd
        signal.pidfd_send_signal = record_target_signal
        eio_caught: BaseException | None = None
        try:
            run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", eio_source],
                private,
                environment,
                time.monotonic() + 5.0,
                cancellation,
            )
        except BaseException as exc:
            eio_caught = exc
        finally:
            signal.pidfd_send_signal = original_pidfd_signal
            os.pidfd_open = original_pidfd_open
            os.open = original_open
        identity_pair = target_identity()
        eio_remaining = None
        if identity_pair is not None:
            eio_remaining = process_map().get(identity_pair[0])
        eio_live = (
            identity_pair is not None
            and eio_remaining is not None
            and eio_remaining[1] == identity_pair[1]
        )
        if (
            identity_pair is None
            or eio_injections < 2
            or not target_signalled
            or eio_live
            or not isinstance(eio_caught, RunnerError)
            or str(eio_caught)
            != "publication runner descendant cleanup encountered errors"
        ):
            if identity_pair is not None and eio_live:
                try:
                    os.kill(identity_pair[0], signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(identity_pair[0], 0)
                except ChildProcessError:
                    pass
            raise RunnerError(
                "publication runner detached-EIO custody oracle drifted: "
                f"identity={identity_pair!r} injections={eio_injections} "
                f"signalled={target_signalled} live={eio_live} "
                f"caught={eio_caught!r}"
            ) from eio_caught
        direct = tuple(range(50000, 50000 + PROCESS_LIMIT))
        later = 70000
        first_wave = {pid: (os.getpid(), pid + 1) for pid in direct}
        first_wave[later] = (direct[0], later + 1)
        bounded = owned_processes(frozenset(), processes=first_wave)
        next_wave = owned_processes(
            frozenset(),
            processes={later: (os.getpid(), later + 1)},
        )
        if (
            len(bounded) != PROCESS_LIMIT
            or later in bounded
            or next_wave != {later: later + 1}
        ):
            raise RunnerError("publication runner process-wave oracle drifted")

        class CountingSnapshot(dict[int, tuple[int, int]]):
            def __init__(self, *args) -> None:
                super().__init__(*args)
                self.item_calls = 0

            def items(self):
                self.item_calls += 1
                return super().items()

        chain_pairs: list[tuple[int, tuple[int, int]]] = []
        parent = os.getpid()
        for offset in range(128):
            chain_pid = 80000 + offset
            chain_pairs.append((chain_pid, (parent, 90000 + offset)))
            parent = chain_pid
        reverse_chain = CountingSnapshot(reversed(chain_pairs))
        chain_owned = owned_processes(
            frozenset(),
            processes=reverse_chain,
        )
        if (
            len(chain_owned) != len(chain_pairs)
            or set(chain_owned) != {pid for pid, _ in chain_pairs}
            or reverse_chain.item_calls > 3
        ):
            raise RunnerError(
                "publication runner process-graph complexity oracle drifted: "
                f"owned={len(chain_owned)} item_calls={reverse_chain.item_calls}"
            )
    verify_post_checkpoint_cancellation()


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    cancellation = CancellationLatch()
    try:
        cancellation.install()
    except RunnerSignal as exc:
        raise SystemExit(128 + exc.signum) from None
    except RunnerError as exc:
        raise SystemExit(f"bounded publication fixture failed: {exc}") from exc
    output = b""
    diagnostic = b""
    status = 0
    try:
        if arguments.self_test:
            run_self_test(cancellation)
            output = b"HAPTICS_PUBLICATION_FIXTURE_RUNNER_SELF_TEST=PASS\n"
        else:
            with tempfile.TemporaryDirectory(
                prefix="tb321fu-publication-runner."
            ) as raw:
                private = pathlib.Path(raw)
                home = private / "home"
                home.mkdir(mode=0o700)
                result = run_bounded(
                    ["/bin/bash", "-p", str(PUBLICATION_FIXTURE)],
                    SCRIPT_DIR.parents[1],
                    clean_environment(home),
                    time.monotonic() + PUBLICATION_TIMEOUT_SECONDS,
                    cancellation,
                )
                cancellation.checkpoint()
            status = result.returncode
            diagnostic = result.stderr
            if status == 0:
                if (
                    result.stdout.count(PUBLICATION_RESULT_MARKER) != 1
                    or not result.stdout.endswith(PUBLICATION_RESULT_MARKER)
                ):
                    status = 125
                    diagnostic = b"publication fixture omitted its terminal marker\n"
                else:
                    output = (
                        result.stdout
                        + b"HAPTICS_PUBLICATION_FIXTURE_RUNNER=PASS\n"
                    )
        cancellation.checkpoint()
    finally:
        active = sys.exception()
        try:
            cancellation.close(active)
        except RunnerSignal as exc:
            raise SystemExit(128 + exc.signum) from None
        except RunnerError as exc:
            if active is None:
                raise
            active.add_note(str(exc))
    if diagnostic:
        sys.stderr.buffer.write(diagnostic)
    if status:
        raise SystemExit(status)
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    try:
        main()
    except RunnerError as exc:
        raise SystemExit(f"bounded publication fixture failed: {exc}") from exc
