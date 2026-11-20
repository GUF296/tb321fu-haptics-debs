#!/usr/bin/env python3
"""Small Linux fixture helpers; never identify an old PID at assertion time.

Only ``spawn_fixture_process`` / ``capture_child_identity`` may obtain a new
identity, immediately after Popen and before poll/wait. Other processes must
publish their own PID/start-time record. Callers own descendant/cgroup cleanup;
waiting for a Popen here deliberately does not wait for inherited pipe EOF.
"""

from __future__ import annotations

from collections import namedtuple
from collections.abc import Callable, Iterator
from contextlib import contextmanager
import errno
import math
import os
import pathlib
import signal
import subprocess
import threading
import time


HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


class FixtureCleanupError(RuntimeError):
    """A fixture intervention or resource failure invalidated its result."""


class ProcessIdentity(namedtuple("_ProcessIdentity", "pid start_time")):
    """Immutable birth identity, also suitable for a target-published record."""

    __slots__ = ()

    def __new__(cls, pid: int, start_time: str):
        if (
            type(pid) is not int
            or pid <= 1
            or not isinstance(start_time, str)
            or not start_time.isascii()
            or not start_time.isdigit()
        ):
            raise ValueError("fixture process birth identity is invalid")
        return super().__new__(cls, pid, start_time)


@contextmanager
def _blocked_signals() -> Iterator[None]:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    try:
        yield
    except BaseException as original:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except BaseException as restoration:
            raise BaseExceptionGroup(
                "fixture operation and signal-mask restoration failed",
                [original, restoration],
            ) from None
        raise
    else:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class CleanupLedger:
    """Run every callback LIFO, preserving the oracle and all cleanup errors.

    ``release`` closes ordinary resources. ``emergency`` callbacks must return
    bool: True means product convergence needed fixture help and is a failure.
    ``expected-retained`` is only for a deliberately retained fault resource;
    its True interventions are recorded, but its exceptions still fail the test.
    Registration happens before the resource can escape its protected owner.
    """

    def __init__(self) -> None:
        self._callbacks: list[tuple[str, Callable[[], object], str]] = []
        self._closed = False
        self.expected_retained: list[str] = []
        self.emergency_interventions: list[str] = []

    def add(
        self,
        label: str,
        callback: Callable[[], object],
        *,
        kind: str = "emergency",
    ) -> None:
        if self._closed or kind not in {"release", "emergency", "expected-retained"}:
            raise ValueError("invalid or closed fixture cleanup registration")
        self._callbacks.append((label, callback, kind))

    def __enter__(self) -> CleanupLedger:
        if self._closed:
            raise ValueError("fixture cleanup ledger is already closed")
        return self

    def __exit__(self, _type, original, _traceback) -> bool:
        if self._closed:
            raise ValueError("fixture cleanup ledger is already closed")
        self._closed = True
        failures: list[BaseException] = []
        ran = False

        def run_callbacks() -> None:
            nonlocal ran
            ran = True
            for label, callback, kind in reversed(self._callbacks):
                try:
                    result = callback()
                    if kind != "release" and type(result) is not bool:
                        raise TypeError("intervention callback must return bool")
                    if result is True and kind == "expected-retained":
                        self.expected_retained.append(label)
                    elif result is True and kind == "emergency":
                        self.emergency_interventions.append(label)
                        raise FixtureCleanupError("unexpected fixture emergency cleanup")
                except BaseException as failure:
                    failure.add_note(f"fixture cleanup: {label} ({kind})")
                    failures.append(failure)

        try:
            with _blocked_signals():
                run_callbacks()
        except BaseException as failure:
            failures.append(failure)
        if not ran:
            # Even a failed mask syscall must not skip independent resources.
            run_callbacks()
        if failures:
            if original is not None:
                failures.insert(0, original)
            raise BaseExceptionGroup("fixture oracle / cleanup failures", failures) from None
        return False


def process_start_time(pid: int) -> str | None:
    if type(pid) is not int or pid <= 1:
        raise ValueError("fixture PID is invalid")
    try:
        data = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            return None
        raise
    parts = data.rsplit(") ", 1)
    tail = parts[1].split() if len(parts) == 2 else []
    if len(tail) < 20 or not tail[19].isascii() or not tail[19].isdigit():
        raise FixtureCleanupError("malformed fixture process start time")
    return tail[19]


def _require_identity(identity: ProcessIdentity) -> None:
    if not isinstance(identity, ProcessIdentity):
        raise TypeError("a creation-time ProcessIdentity is required")


def identity_exists(identity: ProcessIdentity) -> bool:
    _require_identity(identity)
    return process_start_time(identity.pid) == identity.start_time


def capture_child_identity(process: subprocess.Popen[bytes]) -> ProcessIdentity:
    """Capture an unreaped direct child; caller must own failure cleanup.

    No poll/wait may precede this call, and no other thread/signal handler may
    reap this child. A fast exit is safe: its waitable zombie retains /proc.
    Prefer spawn_fixture_process, which also handles failed registration.
    """
    if process.returncode is not None:
        raise FixtureCleanupError("cannot capture a reaped fixture child")
    with _blocked_signals(), CleanupLedger() as cleanup:
        descriptor = os.pidfd_open(process.pid, 0)
        cleanup.add("capture pidfd", lambda: os.close(descriptor), kind="release")
        os.fstat(descriptor)
        start_time = process_start_time(process.pid)
        if start_time is None:
            raise FixtureCleanupError("fixture child vanished before birth registration")
        return ProcessIdentity(process.pid, start_time)


def signal_identity(identity: ProcessIdentity, signum: int) -> bool:
    """Authenticate before/after pidfd acquisition; never signal a numeric PID."""
    _require_identity(identity)
    with _blocked_signals(), CleanupLedger() as cleanup:
        if not identity_exists(identity):
            return False
        try:
            descriptor = os.pidfd_open(identity.pid, 0)
        except ProcessLookupError:
            return False
        cleanup.add("signal pidfd", lambda: os.close(descriptor), kind="release")
        os.fstat(descriptor)
        if not identity_exists(identity):
            return False
        try:
            signal.pidfd_send_signal(descriptor, signum)
        except ProcessLookupError:
            return False
        return True


def _timeout(value: float) -> float:
    if not math.isfinite(value) or value < 0:
        raise ValueError("fixture timeout must be finite and nonnegative")
    return value


def require_identity_gone(identity: ProcessIdentity, timeout: float = 3.0) -> None:
    """Read-only assertion: unlike emergency cleanup it cannot make its own PASS."""
    _require_identity(identity)
    deadline = time.monotonic() + _timeout(timeout)
    while identity_exists(identity):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FixtureCleanupError(f"fixture left process birth identity {identity.pid}")
        time.sleep(min(0.01, remaining))


def kill_identity(identity: ProcessIdentity, timeout: float = 3.0) -> bool:
    """Kill a published non-Popen identity; an unreaped zombie remains a failure."""
    _timeout(timeout)
    intervened = signal_identity(identity, signal.SIGKILL)
    require_identity_gone(identity, timeout)
    return intervened


def converge_process(
    process: subprocess.Popen[bytes],
    identity: ProcessIdentity,
    *,
    term_timeout: float = 1.0,
    kill_timeout: float = 2.0,
) -> bool:
    """Bound TERM/KILL/reap without communicate or descendant-owned pipe EOF."""
    _require_identity(identity)
    if process.pid != identity.pid:
        raise ValueError("fixture Popen and birth identity disagree")
    _timeout(term_timeout)
    _timeout(kill_timeout)
    failures: list[BaseException] = []
    try:
        process.wait(timeout=0)
        return False
    except subprocess.TimeoutExpired:
        pass
    except BaseException as failure:
        failures.append(failure)
    intervened = False
    try:
        intervened = signal_identity(identity, signal.SIGTERM)
    except BaseException as failure:
        failures.append(failure)
    reaped = False
    try:
        process.wait(timeout=term_timeout)
        reaped = True
    except subprocess.TimeoutExpired:
        pass
    except BaseException as failure:
        failures.append(failure)
    if not reaped:
        try:
            intervened = signal_identity(identity, signal.SIGKILL) or intervened
        except BaseException as failure:
            failures.append(failure)
        try:
            process.wait(timeout=kill_timeout)
        except BaseException as failure:
            failures.append(failure)
    if failures:
        raise BaseExceptionGroup("fixture process convergence failures", failures)
    return intervened


def close_process_streams(process: subprocess.Popen[bytes]) -> None:
    with CleanupLedger() as cleanup:
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(process, name, None)
            if stream is not None:
                cleanup.add(f"process {name}", stream.close, kind="release")


def _kill_unreaped_child(process: subprocess.Popen[bytes]) -> None:
    # Only the spawn rollback calls this, before ANY wait/poll. The direct-child
    # wait slot pins this PID even when /proc identity acquisition itself failed.
    if process.returncode is not None:
        return
    with _blocked_signals(), CleanupLedger() as cleanup:
        try:
            descriptor = os.pidfd_open(process.pid, 0)
        except ProcessLookupError:
            return
        cleanup.add("unregistered child pidfd", lambda: os.close(descriptor), kind="release")
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError:
            pass


def spawn_fixture_process(
    *arguments,
    cleanup: CleanupLedger,
    **keywords,
) -> tuple[subprocess.Popen[bytes], ProcessIdentity]:
    """Single-threaded Popen + identity + cleanup registration before unmask.

    The ledger is mandatory so a handled signal at the return handoff cannot
    abandon the process. The child restores the caller's pre-spawn signal mask;
    blocking the parent's ownership transition must not change tested behavior.
    """
    if not isinstance(cleanup, CleanupLedger) or cleanup._closed:
        raise ValueError("fixture spawn requires an open cleanup ledger")
    if threading.active_count() != 1 or keywords.pop("preexec_fn", None) is not None:
        raise ValueError("fixture spawn requires one thread and no custom preexec_fn")
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, ())

    def child_setup() -> None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    with _blocked_signals():
        process = subprocess.Popen(*arguments, preexec_fn=child_setup, **keywords)
        try:
            identity = capture_child_identity(process)
            cleanup.add("spawned process streams", lambda: close_process_streams(process), kind="release")
            cleanup.add("spawned process convergence", lambda: converge_process(process, identity))
        except BaseException:
            with CleanupLedger() as rollback:
                rollback.add("failed spawn streams", lambda: close_process_streams(process), kind="release")
                rollback.add("failed spawn reap", lambda: process.wait(timeout=2.0), kind="release")
                rollback.add("failed spawn kill", lambda: _kill_unreaped_child(process), kind="release")
                raise
        return process, identity
