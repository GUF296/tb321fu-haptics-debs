#!/usr/bin/env python3
"""Hostile fixtures for bounded dpkg mutable and trigger state."""

from __future__ import annotations

import difflib
import errno
import importlib.util
import hashlib
import os
import pathlib
import select
import signal
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "verify-haptics-dpkg-state.py"
STATUS = b"""Package: handler
Status: install ok installed
Architecture: amd64
Version: 1.0-1

Package: removed
Status: deinstall ok config-files
Architecture: amd64
Version: 2.0-1

"""
DIVERSIONS = b"/usr/bin/tool\n/usr/bin/tool.distrib\nhandler\n"
STATOVERRIDE = b"root root 4755 /usr/bin/helper\n"
TRIGGER_FILE = b"/usr/share/example handler/noawait\n"
EXPLICIT_TRIGGER = b"handler/noawait\n"
TRIGGER_METADATA = b"interest-noawait /usr/share/example\n"
POSTINST = b"#!/bin/sh\nexit 0\n"
FIXTURE_FORK_SIGNALS = frozenset((signal.SIGINT, signal.SIGTERM))
MAX_FIXTURE_FD_SNAPSHOT_ENTRIES = 4096
_FIXTURE_TRUSTED_SCANDIR = os.scandir
_FIXTURE_TRUSTED_FSTAT = os.fstat


class FixturePipeOwner:
    def __init__(self) -> None:
        self.read_descriptor = -1
        self.write_descriptor = -1


def choose_fixture_failure(
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


def close_fixture_descriptor(
    descriptor: int,
    label: str,
) -> tuple[BaseException | None, bool]:
    failure: BaseException | None = None
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            failure = choose_fixture_failure(
                failure,
                exc,
                f"{label} close also failed",
            )
        try:
            os.fstat(descriptor)
        except OSError as probe:
            if probe.errno == errno.EBADF:
                return failure, True
            failure = choose_fixture_failure(
                failure,
                probe,
                f"{label} close-state inspection also failed",
            )
        except BaseException as probe:
            failure = choose_fixture_failure(
                failure,
                probe,
                f"{label} close-state inspection also failed",
            )
    if failure is None:
        failure = RuntimeError(f"{label} close did not converge")
    return failure, False


def fixture_descriptor_snapshot(label: str) -> frozenset[int]:
    descriptors: set[int] = set()
    try:
        with _FIXTURE_TRUSTED_SCANDIR("/proc/self/fd") as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_FIXTURE_FD_SNAPSHOT_ENTRIES:
                    raise RuntimeError(
                        f"{label} descriptor snapshot exceeds its entry bound"
                    )
                if not entry.name.isascii() or not entry.name.isdecimal():
                    raise RuntimeError(f"{label} descriptor snapshot is malformed")
                descriptor = int(entry.name, 10)
                if str(descriptor) != entry.name:
                    raise RuntimeError(
                        f"{label} descriptor snapshot is not canonical"
                    )
                descriptors.add(descriptor)
    except BaseException:
        raise
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            _FIXTURE_TRUSTED_FSTAT(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        live.add(descriptor)
    return frozenset(live)


def close_fixture_pipe_slot(
    owner: FixturePipeOwner,
    attribute: str,
    label: str,
) -> BaseException | None:
    descriptor = getattr(owner, attribute)
    if descriptor < 0:
        return None
    failure, closed = close_fixture_descriptor(descriptor, label)
    if closed:
        setattr(owner, attribute, -1)
    return failure


def settle_fixture_pipe_owner(
    owner: FixturePipeOwner,
    label: str,
) -> BaseException | None:
    failure: BaseException | None = None
    for attribute, suffix in (
        ("write_descriptor", "write"),
        ("read_descriptor", "read"),
    ):
        close_failure = close_fixture_pipe_slot(
            owner,
            attribute,
            f"{label} {suffix} descriptor",
        )
        if close_failure is not None:
            failure = choose_fixture_failure(
                failure,
                close_failure,
                f"{label} {suffix}-descriptor cleanup also failed",
            )
    return failure


def acquire_fixture_pipe(owner: FixturePipeOwner) -> None:
    if owner.read_descriptor >= 0 or owner.write_descriptor >= 0:
        raise RuntimeError("dpkg fixture pipe owner is already populated")
    label = "dpkg fixture pipe handoff"
    baseline = fixture_descriptor_snapshot(label)
    returned: object = None
    try:
        candidate = os.pipe()
        returned = candidate
        if (
            not isinstance(candidate, tuple)
            or len(candidate) != 2
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and item >= 0
                for item in candidate
            )
            or candidate[0] == candidate[1]
            or any(item in baseline for item in candidate)
        ):
            raise RuntimeError("dpkg fixture pipe returned invalid descriptors")
        owner.read_descriptor = candidate[0]
        owner.write_descriptor = candidate[1]
        for descriptor in candidate:
            _FIXTURE_TRUSTED_FSTAT(descriptor)
            if os.get_inheritable(descriptor):
                raise RuntimeError("dpkg fixture pipe returned an inheritable descriptor")
        return
    except BaseException as exc:
        primary: BaseException = exc
        candidates = {
            descriptor
            for descriptor in (owner.read_descriptor, owner.write_descriptor)
            if descriptor >= 0 and descriptor not in baseline
        }
        if isinstance(returned, tuple):
            candidates.update(
                descriptor
                for descriptor in returned
                if isinstance(descriptor, int)
                and not isinstance(descriptor, bool)
                and descriptor >= 0
                and descriptor not in baseline
            )
        try:
            candidates.update(fixture_descriptor_snapshot(label) - baseline)
        except BaseException as snapshot_exc:
            primary = choose_fixture_failure(
                primary,
                snapshot_exc,
                "dpkg fixture pipe handoff recovery snapshot also failed",
            )
        for descriptor in sorted(candidates, reverse=True):
            temporary = FixturePipeOwner()
            temporary.read_descriptor = descriptor
            close_failure = settle_fixture_pipe_owner(
                temporary,
                "applied dpkg fixture pipe handoff",
            )
            if descriptor == owner.read_descriptor:
                owner.read_descriptor = temporary.read_descriptor
            if descriptor == owner.write_descriptor:
                owner.write_descriptor = temporary.read_descriptor
            if close_failure is not None:
                primary = choose_fixture_failure(
                    primary,
                    close_failure,
                    "applied dpkg fixture pipe recovery also failed",
                )
        raise primary


def fixture_signal_mask() -> frozenset[signal.Signals]:
    return frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))


def restore_fixture_fork_mask(
    expected: frozenset[signal.Signals],
) -> tuple[BaseException | None, bool]:
    failure: BaseException | None = None
    for _ in range(3):
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, set(expected))
        except BaseException as exc:
            failure = choose_fixture_failure(
                failure,
                exc,
                "dpkg fixture fork signal-mask restore also failed",
            )
        try:
            current = fixture_signal_mask()
        except BaseException as exc:
            failure = choose_fixture_failure(
                failure,
                exc,
                "dpkg fixture fork signal-mask inspection also failed",
            )
            continue
        if current == expected:
            return failure, True
    if failure is None:
        failure = RuntimeError("dpkg fixture fork signal-mask restore did not converge")
    return failure, False


def block_fixture_fork_signals() -> frozenset[signal.Signals]:
    original = fixture_signal_mask()
    try:
        previous = frozenset(
            signal.pthread_sigmask(signal.SIG_BLOCK, set(FIXTURE_FORK_SIGNALS))
        )
    except BaseException as exc:
        restore_failure, _ = restore_fixture_fork_mask(original)
        if restore_failure is not None:
            exc = choose_fixture_failure(
                exc,
                restore_failure,
                "dpkg fixture fork signal-mask recovery also failed",
            )
        raise exc
    try:
        current = fixture_signal_mask()
    except BaseException as exc:
        primary: BaseException = exc
    else:
        if previous == original and FIXTURE_FORK_SIGNALS <= current:
            return original
        primary = RuntimeError("dpkg fixture fork signal mask changed unexpectedly")
    restore_failure, _ = restore_fixture_fork_mask(original)
    if restore_failure is not None:
        primary = choose_fixture_failure(
            primary,
            restore_failure,
            "dpkg fixture unexpected fork signal-mask recovery also failed",
        )
    raise primary


def load_module():
    if not MODULE_PATH.is_file():
        raise SystemExit("dpkg state verifier is missing")
    spec = importlib.util.spec_from_file_location("haptics_dpkg_state", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load dpkg state verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_file(path: pathlib.Path, raw: bytes, mode: int) -> None:
    path.write_bytes(raw)
    path.chmod(mode)


def make_valid_tree(root: pathlib.Path) -> pathlib.Path:
    admin = root / "var/lib/dpkg"
    triggers = admin / "triggers"
    info = admin / "info"
    updates = admin / "updates"
    parts = admin / "parts"
    for path in (admin, triggers, info, updates, parts):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    write_file(admin / "status", STATUS, 0o644)
    write_file(admin / "diversions", DIVERSIONS, 0o644)
    write_file(admin / "statoverride", STATOVERRIDE, 0o644)
    write_file(triggers / "File", TRIGGER_FILE, 0o644)
    write_file(triggers / "update-example", EXPLICIT_TRIGGER, 0o644)
    write_file(triggers / "Unincorp", b"", 0o644)
    write_file(
        info / "handler.triggers",
        TRIGGER_METADATA,
        0o644,
    )
    write_file(info / "handler.postinst", POSTINST, 0o755)
    return admin


def require_rejected(verifier, callback, label: str, expected: str) -> None:
    try:
        callback()
    except verifier.DpkgStateError as exc:
        if expected not in str(exc):
            raise SystemExit(
                f"dpkg state verifier rejected {label} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"dpkg state verifier raised an unexpected exception for {label}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"dpkg state verifier accepted hostile fixture: {label}")


def cleanup_fixture_child(child: int) -> None:
    while True:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        if waited == child:
            return
        if waited != 0:
            raise SystemExit("dpkg fixture cleanup returned an unexpected process")
        break
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            waited, _ = os.waitpid(child, 0)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        if waited != child:
            raise SystemExit("dpkg fixture cleanup reaped an unexpected process")
        return


def require_bounded_child_rejection(
    verifier, callback, label: str, expected: str, timeout: float = 2.0
) -> None:
    pipe_owner = FixturePipeOwner()
    read_descriptor = -1
    write_descriptor = -1
    child_pid = -1
    child_owned = False
    fork_mask: frozenset[signal.Signals] | None = None
    fork_mask_owned = False
    message = ""
    waited = -1
    status_value = -1
    primary_error: BaseException | None = None
    try:
        acquire_fixture_pipe(pipe_owner)
        read_descriptor = pipe_owner.read_descriptor
        write_descriptor = pipe_owner.write_descriptor
        fork_mask = block_fixture_fork_signals()
        fork_mask_owned = True
        try:
            child_pid = os.fork()
        except BaseException:
            raise
        if child_pid == 0:
            restore_failure, restored = restore_fixture_fork_mask(fork_mask)
            if restore_failure is not None or not restored:
                os._exit(125)
            os.close(read_descriptor)
            try:
                callback()
            except verifier.DpkgStateError as exc:
                child_message = (
                    f"DpkgStateError:{exc}"
                ).encode("utf-8", errors="replace")[:4096]
            except BaseException as exc:
                child_message = (
                    f"unexpected:{type(exc).__name__}:{exc}"
                ).encode("utf-8", errors="replace")[:4096]
            else:
                child_message = b"accepted"
            try:
                os.write(write_descriptor, child_message)
            finally:
                os.close(write_descriptor)
            os._exit(0)
        child_owned = True
        restore_failure, restored = restore_fixture_fork_mask(fork_mask)
        fork_mask_owned = not restored
        if restore_failure is not None:
            raise restore_failure
        if not restored:
            raise RuntimeError(
                "dpkg fixture fork signal-mask restoration did not converge"
            )
        close_failure, closed = close_fixture_descriptor(
            write_descriptor,
            "dpkg fixture child-write descriptor",
        )
        if closed:
            pipe_owner.write_descriptor = -1
        if close_failure is not None:
            raise close_failure
        ready, _, _ = select.select([read_descriptor], [], [], timeout)
        if not ready:
            raise SystemExit(
                f"dpkg state verifier blocked on hostile fixture: {label}"
            )
        message = os.read(read_descriptor, 4096).decode("utf-8", errors="replace")
        while True:
            try:
                waited, status_value = os.waitpid(child_pid, 0)
            except InterruptedError:
                continue
            break
        if waited != child_pid:
            raise SystemExit("dpkg fixture wait returned an unexpected process")
        child_owned = False
    except BaseException as exc:
        primary_error = choose_fixture_failure(
            primary_error,
            exc,
            "dpkg fixture operation also failed",
        )
    if fork_mask_owned and fork_mask is not None:
        restore_failure, restored = restore_fixture_fork_mask(fork_mask)
        fork_mask_owned = not restored
        if restore_failure is not None:
            primary_error = choose_fixture_failure(
                primary_error,
                restore_failure,
                "dpkg fixture fork signal-mask cleanup also failed",
            )
        if not restored:
            primary_error = choose_fixture_failure(
                primary_error,
                RuntimeError(
                    "dpkg fixture fork signal-mask cleanup did not converge"
                ),
                "dpkg fixture fork signal-mask cleanup also did not converge",
            )
    if pipe_owner.read_descriptor >= 0:
        cleanup_error = close_fixture_pipe_slot(
            pipe_owner,
            "read_descriptor",
            "dpkg fixture child-read descriptor",
        )
        if cleanup_error is not None:
            primary_error = choose_fixture_failure(
                primary_error,
                cleanup_error,
                "dpkg fixture read-descriptor cleanup also failed",
            )
    if pipe_owner.write_descriptor >= 0:
        cleanup_error = close_fixture_pipe_slot(
            pipe_owner,
            "write_descriptor",
            "dpkg fixture child-write descriptor",
        )
        if cleanup_error is not None:
            primary_error = choose_fixture_failure(
                primary_error,
                cleanup_error,
                "dpkg fixture write-descriptor cleanup also failed",
            )
    if child_owned:
        for _ in range(3):
            try:
                cleanup_fixture_child(child_pid)
            except BaseException as exc:
                primary_error = choose_fixture_failure(
                    primary_error,
                    exc,
                    "dpkg fixture child cleanup also failed",
                )
                continue
            child_owned = False
            break
        if child_owned:
            primary_error = choose_fixture_failure(
                primary_error,
                RuntimeError("dpkg fixture child cleanup did not converge"),
                "dpkg fixture child cleanup also did not converge",
            )
    if primary_error is not None:
        raise primary_error
    if (
        waited != child_pid
        or not os.WIFEXITED(status_value)
        or os.WEXITSTATUS(status_value) != 0
        or not message.startswith("DpkgStateError:")
        or expected not in message
    ):
        raise SystemExit(
            f"dpkg state verifier did not reject {label} at the expected boundary: "
            f"{message or status_value}"
        )


def require_fixture_child_cleanup_oracles() -> None:
    original_waitpid = os.waitpid
    original_kill = os.kill
    child_pid = 424242
    try:
        signals = []

        def reject_signal(pid: int, signal_number: int) -> None:
            signals.append((pid, signal_number))
            raise SystemExit("dpkg fixture signalled a child without live custody")

        def lost_waitpid(pid: int, options: int):
            if pid != child_pid or options != os.WNOHANG:
                raise SystemExit("dpkg fixture lost-child oracle changed wait identity")
            raise ChildProcessError

        os.waitpid = lost_waitpid
        os.kill = reject_signal
        cleanup_fixture_child(child_pid)
        if signals:
            raise SystemExit("dpkg fixture signalled a lost child")

        def reaped_waitpid(pid: int, options: int):
            if pid != child_pid or options != os.WNOHANG:
                raise SystemExit("dpkg fixture reaped-child oracle changed wait identity")
            return child_pid, 0

        os.waitpid = reaped_waitpid
        cleanup_fixture_child(child_pid)
        if signals:
            raise SystemExit("dpkg fixture signalled an already reaped child")

        wait_options = []
        live_results = [
            InterruptedError(),
            (0, 0),
            InterruptedError(),
            (child_pid, 0),
        ]

        def live_waitpid(pid: int, options: int):
            if pid != child_pid or not live_results:
                raise SystemExit("dpkg fixture live-child oracle changed wait identity")
            wait_options.append(options)
            result = live_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        def record_signal(pid: int, signal_number: int) -> None:
            signals.append((pid, signal_number))

        signals.clear()
        os.waitpid = live_waitpid
        os.kill = record_signal
        cleanup_fixture_child(child_pid)
        if live_results or wait_options != [os.WNOHANG, os.WNOHANG, 0, 0]:
            raise SystemExit("dpkg fixture live-child wait/retry contract changed")
        if signals != [(child_pid, signal.SIGKILL)]:
            raise SystemExit("dpkg fixture live-child signal identity changed")
    finally:
        os.waitpid = original_waitpid
        os.kill = original_kill


def require_bounded_child_custody_oracles(verifier) -> None:
    original_pipe = os.pipe
    original_fork = os.fork
    original_select = select.select
    original_read = os.read
    original_waitpid = os.waitpid

    applied_pipe_descriptors: list[int] = []
    applied_pipe_cancellation = KeyboardInterrupt(
        "injected pipe applied-before-assignment cancellation"
    )

    def cancel_after_applied_pipe() -> tuple[int, int]:
        descriptors = original_pipe()
        applied_pipe_descriptors.extend(descriptors)
        raise applied_pipe_cancellation

    os.pipe = cancel_after_applied_pipe
    applied_pipe_caught: BaseException | None = None
    try:
        require_bounded_child_rejection(
            verifier,
            lambda: None,
            "pipe applied-before-assignment oracle",
            "unused",
        )
    except BaseException as exc:
        applied_pipe_caught = exc
    finally:
        os.pipe = original_pipe
    applied_pipe_leaked = False
    for descriptor in applied_pipe_descriptors:
        try:
            _FIXTURE_TRUSTED_FSTAT(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        os.close(descriptor)
        applied_pipe_leaked = True
    if (
        applied_pipe_caught is not applied_pipe_cancellation
        or len(applied_pipe_descriptors) != 2
        or applied_pipe_leaked
    ):
        raise SystemExit(
            "dpkg fixture lost applied pipe ownership or exact cancellation"
        ) from applied_pipe_caught

    pipe_descriptors = []
    fork_error = OSError("injected fork failure")

    def recording_pipe():
        descriptors = original_pipe()
        pipe_descriptors.extend(descriptors)
        return descriptors

    def failing_fork():
        raise fork_error

    os.pipe = recording_pipe
    os.fork = failing_fork
    try:
        try:
            require_bounded_child_rejection(
                verifier,
                lambda: None,
                "fork-failure oracle",
                "unused",
            )
        except OSError as exc:
            if exc is not fork_error:
                raise SystemExit("dpkg fixture changed the fork-failure primary") from exc
        else:
            raise SystemExit("dpkg fixture accepted an injected fork failure")
    finally:
        os.pipe = original_pipe
        os.fork = original_fork
    if len(pipe_descriptors) != 2:
        raise SystemExit("dpkg fixture fork-failure oracle did not capture one pipe")
    for descriptor in pipe_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        os.close(descriptor)
        raise SystemExit("dpkg fixture leaked a pipe descriptor after fork failure")

    def require_reaped(child_pid: int, stage: str) -> None:
        try:
            waited, _ = original_waitpid(child_pid, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == 0:
            cleanup_fixture_child(child_pid)
        elif waited != child_pid:
            raise SystemExit(
                f"dpkg fixture {stage} oracle waited for an unexpected child"
            )
        raise SystemExit(f"dpkg fixture left the {stage} child unreaped")

    def reject_for_oracle() -> None:
        raise verifier.DpkgStateError("oracle rejection")

    boundary_pipe_descriptors: list[int] = []
    boundary_children: list[int] = []
    boundary_cancellation = KeyboardInterrupt(
        "injected pre-close-helper ownership cancellation"
    )
    boundary_injected = False
    original_close_helper = close_fixture_descriptor

    def record_boundary_pipe() -> tuple[int, int]:
        descriptors = original_pipe()
        boundary_pipe_descriptors.extend(descriptors)
        return descriptors

    def record_boundary_fork() -> int:
        child_pid = original_fork()
        if child_pid > 0:
            boundary_children.append(child_pid)
        return child_pid

    def cancel_before_close_helper(
        descriptor: int,
        label: str,
    ) -> tuple[BaseException | None, bool]:
        nonlocal boundary_injected
        if label == "dpkg fixture child-write descriptor" and not boundary_injected:
            boundary_injected = True
            raise boundary_cancellation
        return original_close_helper(descriptor, label)

    os.pipe = record_boundary_pipe
    os.fork = record_boundary_fork
    globals()["close_fixture_descriptor"] = cancel_before_close_helper
    caught: BaseException | None = None
    try:
        require_bounded_child_rejection(
            verifier,
            reject_for_oracle,
            "pre-close-helper ownership",
            "oracle rejection",
            timeout=1.0,
        )
    except BaseException as exc:
        caught = exc
    finally:
        os.pipe = original_pipe
        os.fork = original_fork
        globals()["close_fixture_descriptor"] = original_close_helper
    if (
        caught is not boundary_cancellation
        or not boundary_injected
        or len(boundary_children) != 1
        or len(boundary_pipe_descriptors) != 2
    ):
        if boundary_children:
            cleanup_fixture_child(boundary_children[0])
        raise SystemExit(
            f"dpkg pre-close-helper ownership handoff drifted: {caught}"
        ) from caught
    require_reaped(boundary_children[0], "pre-close-helper ownership")
    for descriptor in boundary_pipe_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        os.close(descriptor)
        raise SystemExit("dpkg pre-close-helper ownership oracle leaked a descriptor")

    original_mask = fixture_signal_mask()
    for signum, cancellation in (
        (signal.SIGINT, KeyboardInterrupt("injected fork-handoff SIGINT")),
        (signal.SIGTERM, SystemExit("injected fork-handoff SIGTERM")),
    ):
        if signum in original_mask:
            raise SystemExit("dpkg fork-handoff oracle inherited blocked cancellation")
        previous_handler = signal.getsignal(signum)
        children = []
        events = []

        def raise_cancellation(received: int, _frame) -> None:
            events.append(received)
            raise cancellation

        def signal_at_fork_return() -> int:
            child_pid = original_fork()
            if child_pid > 0:
                children.append(child_pid)
                os.kill(os.getpid(), signum)
            return child_pid

        signal.signal(signum, raise_cancellation)
        os.fork = signal_at_fork_return
        caught: BaseException | None = None
        try:
            require_bounded_child_rejection(
                verifier,
                reject_for_oracle,
                f"fork-handoff-{signum.name}",
                "oracle rejection",
                timeout=1.0,
            )
        except BaseException as exc:
            caught = exc
        finally:
            os.fork = original_fork
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, set(original_mask))
            except BaseException as exc:
                if caught is None:
                    caught = exc
            signal.signal(signum, previous_handler)
        if caught is not cancellation or events != [signum] or len(children) != 1:
            if children:
                try:
                    cleanup_fixture_child(children[0])
                except BaseException:
                    pass
            raise SystemExit(
                f"dpkg fixture lost atomic {signum.name} fork handoff: {caught}"
            ) from caught
        require_reaped(children[0], f"fork-handoff-{signum.name}")
        if fixture_signal_mask() != original_mask:
            raise SystemExit(
                f"dpkg fixture changed the caller mask after {signum.name} handoff"
            )

    parent_pid = os.getpid()
    cleanup_pipe_descriptors: list[int] = []
    cleanup_children: list[int] = []
    operation_error = OSError("injected pre-cleanup ordinary primary")
    cleanup_cancellation = KeyboardInterrupt(
        "injected applied child-read close cancellation"
    )
    original_close = os.close

    def record_cleanup_pipe() -> tuple[int, int]:
        descriptors = original_pipe()
        cleanup_pipe_descriptors.extend(descriptors)
        return descriptors

    def record_cleanup_fork() -> int:
        child_pid = original_fork()
        if child_pid > 0:
            cleanup_children.append(child_pid)
        return child_pid

    def fail_cleanup_select(*arguments):
        if os.getpid() == parent_pid:
            raise operation_error
        return original_select(*arguments)

    def cancel_after_close(descriptor: int) -> None:
        original_close(descriptor)
        if (
            os.getpid() == parent_pid
            and cleanup_pipe_descriptors
            and descriptor == cleanup_pipe_descriptors[0]
        ):
            raise cleanup_cancellation

    os.pipe = record_cleanup_pipe
    os.fork = record_cleanup_fork
    os.close = cancel_after_close
    select.select = fail_cleanup_select
    caught = None
    try:
        require_bounded_child_rejection(
            verifier,
            signal.pause,
            "cleanup-cancellation-priority",
            "unused",
            timeout=1.0,
        )
    except BaseException as exc:
        caught = exc
    finally:
        os.pipe = original_pipe
        os.fork = original_fork
        os.close = original_close
        select.select = original_select
    if (
        caught is not cleanup_cancellation
        or caught.__cause__ is not operation_error
        or len(cleanup_children) != 1
    ):
        if cleanup_children:
            try:
                cleanup_fixture_child(cleanup_children[0])
            except BaseException:
                pass
        raise SystemExit(
            f"dpkg fixture cleanup cancellation did not outrank its primary: {caught}"
        ) from caught
    require_reaped(cleanup_children[0], "cleanup-cancellation-priority")
    if len(cleanup_pipe_descriptors) != 2:
        raise SystemExit("dpkg cleanup-cancellation oracle missed its pipe")
    for descriptor in cleanup_pipe_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        original_close(descriptor)
        raise SystemExit("dpkg cleanup-cancellation oracle leaked a descriptor")

    cleanup_children = []
    operation_error = OSError("injected pre-child-cleanup ordinary primary")
    child_cleanup_cancellation = KeyboardInterrupt(
        "injected applied child cleanup cancellation"
    )
    original_child_cleanup = cleanup_fixture_child
    cleanup_cancelled = False

    def record_child_cleanup_fork() -> int:
        child_pid = original_fork()
        if child_pid > 0:
            cleanup_children.append(child_pid)
        return child_pid

    def fail_before_child_cleanup(*arguments):
        if os.getpid() == parent_pid:
            raise operation_error
        return original_select(*arguments)

    def cleanup_then_cancel(child_pid: int) -> None:
        nonlocal cleanup_cancelled
        original_child_cleanup(child_pid)
        if not cleanup_cancelled:
            cleanup_cancelled = True
            raise child_cleanup_cancellation

    os.fork = record_child_cleanup_fork
    select.select = fail_before_child_cleanup
    globals()["cleanup_fixture_child"] = cleanup_then_cancel
    caught = None
    try:
        require_bounded_child_rejection(
            verifier,
            signal.pause,
            "child-cleanup-cancellation-priority",
            "unused",
            timeout=1.0,
        )
    except BaseException as exc:
        caught = exc
    finally:
        os.fork = original_fork
        select.select = original_select
        globals()["cleanup_fixture_child"] = original_child_cleanup
    if (
        caught is not child_cleanup_cancellation
        or caught.__cause__ is not operation_error
        or not cleanup_cancelled
        or len(cleanup_children) != 1
    ):
        if cleanup_children:
            original_child_cleanup(cleanup_children[0])
        raise SystemExit(
            f"dpkg child-cleanup cancellation did not outrank its primary: {caught}"
        ) from caught
    require_reaped(cleanup_children[0], "child-cleanup-cancellation-priority")

    for stage in ("select", "read", "waitpid"):
        parent_pid = os.getpid()
        children = []
        injected_error = OSError(f"injected {stage} failure")
        wait_failed = False

        def recording_fork():
            child_pid = original_fork()
            if child_pid > 0:
                children.append(child_pid)
            return child_pid

        def failing_select(*arguments):
            if os.getpid() == parent_pid:
                raise injected_error
            return original_select(*arguments)

        def failing_read(descriptor: int, size: int):
            if os.getpid() == parent_pid:
                raise injected_error
            return original_read(descriptor, size)

        def failing_waitpid(child_pid: int, options: int):
            nonlocal wait_failed
            if os.getpid() == parent_pid and options == 0 and not wait_failed:
                wait_failed = True
                raise injected_error
            return original_waitpid(child_pid, options)

        os.fork = recording_fork
        if stage == "select":
            select.select = failing_select
            callback = signal.pause
        elif stage == "read":
            os.read = failing_read
            callback = reject_for_oracle
        else:
            os.waitpid = failing_waitpid
            callback = reject_for_oracle
        try:
            try:
                require_bounded_child_rejection(
                    verifier,
                    callback,
                    f"{stage}-failure oracle",
                    "oracle rejection",
                    timeout=1.0,
                )
            except OSError as exc:
                if exc is not injected_error:
                    raise SystemExit(
                        f"dpkg fixture changed the {stage}-failure primary"
                    ) from exc
            else:
                raise SystemExit(f"dpkg fixture accepted an injected {stage} failure")
        finally:
            os.fork = original_fork
            select.select = original_select
            os.read = original_read
            os.waitpid = original_waitpid
        if len(children) != 1:
            raise SystemExit(f"dpkg fixture {stage} oracle did not record one child")
        require_reaped(children[0], stage)

    parent_pid = os.getpid()
    children = []
    interrupted = False

    def recording_fork():
        child_pid = original_fork()
        if child_pid > 0:
            children.append(child_pid)
        return child_pid

    def interrupt_waitpid_once(child_pid: int, options: int):
        nonlocal interrupted
        if os.getpid() == parent_pid and options == 0 and not interrupted:
            interrupted = True
            raise InterruptedError
        return original_waitpid(child_pid, options)

    os.fork = recording_fork
    os.waitpid = interrupt_waitpid_once
    try:
        require_bounded_child_rejection(
            verifier,
            reject_for_oracle,
            "waitpid-EINTR oracle",
            "oracle rejection",
            timeout=1.0,
        )
    finally:
        os.fork = original_fork
        os.waitpid = original_waitpid
    if not interrupted or len(children) != 1:
        raise SystemExit("dpkg fixture did not exercise the waitpid EINTR retry")
    require_reaped(children[0], "waitpid-EINTR")


def require_state_descriptor_custody_oracles(verifier, admin: pathlib.Path) -> None:
    original_open = verifier.os.open
    original_close = verifier.os.close
    baseline = fixture_descriptor_snapshot("dpkg state custody oracle baseline")
    acquisition_targets = (
        ("root", lambda path, flags, dir_fd: path == "/" and dir_fd is None),
        (
            "ancestor",
            lambda path, flags, dir_fd: path == "var" and dir_fd is not None,
        ),
        (
            "child-directory",
            lambda path, flags, dir_fd: (
                path == "triggers"
                and dir_fd is not None
                and bool(flags & getattr(os, "O_DIRECTORY", 0))
            ),
        ),
        (
            "regular-file",
            lambda path, flags, dir_fd: (
                path == "status"
                and dir_fd is not None
                and not bool(flags & getattr(os, "O_DIRECTORY", 0))
            ),
        ),
    )
    for stage, target in acquisition_targets:
        cancellation = KeyboardInterrupt(
            f"injected {stage} open applied-before-assignment cancellation"
        )
        applied_descriptors: list[int] = []
        fired = False

        def cancel_after_target_open(path, *arguments, **keywords):
            nonlocal fired
            descriptor = original_open(path, *arguments, **keywords)
            flags = arguments[0] if arguments else keywords.get("flags", 0)
            dir_fd = keywords.get("dir_fd")
            if not fired and target(os.fspath(path), flags, dir_fd):
                fired = True
                applied_descriptors.append(descriptor)
                raise cancellation
            return descriptor

        verifier.os.open = cancel_after_target_open
        caught: BaseException | None = None
        try:
            verifier.capture_dpkg_state(admin, os.getuid(), os.getgid())
        except BaseException as exc:
            caught = exc
        finally:
            verifier.os.open = original_open
        after = fixture_descriptor_snapshot(
            f"dpkg state {stage} acquisition oracle result"
        )
        leaked = sorted(after - baseline)
        for descriptor in leaked:
            original_close(descriptor)
        descriptor_live = False
        for descriptor in applied_descriptors:
            try:
                _FIXTURE_TRUSTED_FSTAT(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            descriptor_live = True
        if (
            caught is not cancellation
            or not fired
            or len(applied_descriptors) != 1
            or leaked
            or descriptor_live
        ):
            raise SystemExit(
                f"dpkg state {stage} open custody oracle drifted: {caught}"
            ) from caught

    for timing in ("before", "after"):
        cancellation = KeyboardInterrupt(
            f"injected terminal close cancellation {timing} application"
        )
        opened_descriptors: list[int] = []
        close_cancelled = False

        def track_open(path, *arguments, **keywords):
            descriptor = original_open(path, *arguments, **keywords)
            opened_descriptors.append(descriptor)
            return descriptor

        def cancel_terminal_close(descriptor: int) -> None:
            nonlocal close_cancelled
            if descriptor in opened_descriptors and not close_cancelled:
                close_cancelled = True
                if timing == "before":
                    raise cancellation
                original_close(descriptor)
                raise cancellation
            original_close(descriptor)

        verifier.os.open = track_open
        verifier.os.close = cancel_terminal_close
        caught = None
        try:
            verifier.capture_dpkg_state(admin, os.getuid(), os.getgid())
        except BaseException as exc:
            caught = exc
        finally:
            verifier.os.open = original_open
            verifier.os.close = original_close
        after = fixture_descriptor_snapshot(
            f"dpkg state terminal-close-{timing} oracle result"
        )
        leaked = sorted(after - baseline)
        for descriptor in leaked:
            original_close(descriptor)
        live_recorded = []
        for descriptor in opened_descriptors:
            try:
                _FIXTURE_TRUSTED_FSTAT(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            live_recorded.append(descriptor)
        if (
            caught is not cancellation
            or not close_cancelled
            or len(opened_descriptors) < 2
            or leaked
            or live_recorded
        ):
            raise SystemExit(
                f"dpkg state terminal close {timing} custody oracle drifted: "
                f"{caught}"
            ) from caught


def run_cli(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", "-B", str(MODULE_PATH), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": "/nonexistent",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )


def main() -> None:
    verifier = load_module()
    if not hasattr(verifier, "main"):
        raise SystemExit("dpkg state verifier CLI is missing")
    if not hasattr(verifier, "parse_status_identities"):
        raise SystemExit("dpkg status identity parser is missing Multi-Arch support")
    require_fixture_child_cleanup_oracles()
    require_bounded_child_custody_oracles(verifier)
    if verifier.parse_status(b"") != {}:
        raise SystemExit("empty initial dpkg status did not parse as an empty package set")
    multiarch_status = STATUS.replace(
        b"Architecture: amd64\n",
        b"Architecture: amd64\nMulti-Arch: same\n",
        1,
    )
    identities = verifier.parse_status_identities(multiarch_status)
    if identities[("handler", "amd64")] != (
        "1.0-1",
        "install ok installed",
        "same",
    ) or identities[("removed", "amd64")] != (
        "2.0-1",
        "deinstall ok config-files",
        "no",
    ):
        raise SystemExit("dpkg status identity parser changed Multi-Arch semantics")
    if verifier.parse_triggers(b"", {}) != ():
        raise SystemExit("empty initial trigger registry did not parse as an empty set")
    require_rejected(
        verifier,
        lambda: verifier.parse_status(STATUS.replace(b"\nStatus:", b"\vStatus:", 1)),
        "vertical-tab status separator",
        "invalid framing",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_status(
            STATUS.replace(
                b"Status: install ok installed\n",
                b"Status: install ok installed\n"
                b"Triggers-Pending: /usr/share/example\n",
                1,
            )
        ),
        "status Triggers-Pending state",
        "pending or awaited",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_status(
            STATUS.replace(
                b"Status: install ok installed\n",
                b"Status: install ok installed\n"
                b"Triggers-pending: /usr/share/example\n",
                1,
            )
        ),
        "case-variant pending trigger field",
        "pending or awaited",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_status(
            STATUS.replace(
                b"Status: install ok installed\n",
                b"Status: install ok installed\n"
                b"status: install ok installed\n",
                1,
            )
        ),
        "case-variant duplicate status field",
        "malformed field",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_status(
            STATUS.replace(
                b"Status: install ok installed\n",
                b"Status: install ok installed\nBad\tName: ignored\n",
                1,
            )
        ),
        "status field name with embedded TAB",
        "malformed field",
    )
    for simple_field in (
        b"Package: handler\n",
        b"Status: install ok installed\n",
        b"Architecture: amd64\n",
        b"Version: 1.0-1\n",
    ):
        require_rejected(
            verifier,
            lambda simple_field=simple_field: verifier.parse_status(
                STATUS.replace(
                    simple_field,
                    simple_field + b" folded-value\n",
                    1,
                )
            ),
            f"folded simple status field {simple_field!r}",
            "simple field must not be folded",
        )
    status_with_description = STATUS.replace(
        b"Status: install ok installed\n",
        b"Status: install ok installed\n"
        b"Description: example package\n"
        b" continued description\n",
        1,
    )
    if verifier.parse_status(status_with_description) != verifier.parse_status(STATUS):
        raise SystemExit("legal folded status description changed package identity")
    status_with_empty_folded_field = STATUS.replace(
        b"Status: install ok installed\n",
        b"Status: install ok installed\n"
        b"Conffiles:\n"
        b" /etc/example 0123456789abcdef\n",
        1,
    )
    if verifier.parse_status(status_with_empty_folded_field) != verifier.parse_status(STATUS):
        raise SystemExit("legal empty folded status field changed package identity")
    require_rejected(
        verifier,
        lambda: verifier.parse_status(
            STATUS.replace(
                b"Status: install ok installed",
                b"Status: install ok triggers-pending",
                1,
            )
        ),
        "status-value triggers-pending state",
        "pending or awaited",
    )
    for hostile_status in (
        b"banana ok installed",
        b"install broken installed",
        b"install ok imaginary",
    ):
        require_rejected(
            verifier,
            lambda hostile_status=hostile_status: verifier.parse_status(
                STATUS.replace(b"install ok installed", hostile_status, 1)
            ),
            f"invalid dpkg status domain {hostile_status!r}",
            "unsafe package identity",
        )
    packages = verifier.parse_status(STATUS)
    multiarch_status = STATUS + (
        b"Package: handler\n"
        b"Status: deinstall ok config-files\n"
        b"Architecture: i386\n"
        b"Version: 1.0-1\n\n"
    )
    installed_identity_trigger = verifier.parse_triggers(
        TRIGGER_FILE,
        verifier.parse_status(multiarch_status),
    )
    if installed_identity_trigger != (
        verifier.TriggerRecord(
            "/usr/share/example", "handler", "amd64", "noawait"
        ),
    ):
        raise SystemExit(
            "unqualified trigger owner did not select its unique installed identity"
        )
    require_rejected(
        verifier,
        lambda: verifier.parse_triggers(
            b"/usr/share/example handler\n"
            b"/usr/share/example handler/noawait\n",
            packages,
        ),
        "conflicting trigger wait mode",
        "unsafe owner",
    )
    excessive_triggers = b"".join(
        f"/usr/share/trigger-{index} handler/noawait\n".encode("ascii")
        for index in range(verifier.MAX_TRIGGER_RECORDS + 1)
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_triggers(excessive_triggers, packages),
        "excessive trigger registry",
        "count bound",
    )
    deep_path = b"/" + b"/".join([b"a"] * 129)
    require_rejected(
        verifier,
        lambda: verifier.parse_triggers(
            deep_path + b" handler/noawait\n",
            packages,
        ),
        "excessively deep trigger path",
        "depth bound",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_triggers(
            b"/usr/share/a handler/noawait\v/usr/share/b handler/noawait\n",
            packages,
        ),
        "vertical-tab trigger separator",
        "invalid framing",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_diversions(b"/usr/bin/a\v/usr/bin/b\nhandler\n"),
        "vertical-tab diversion separator",
        "invalid framing",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_statoverrides(
            b"root root 4755 /usr/bin/a\vroot root 0755 /usr/bin/b\n"
        ),
        "vertical-tab statoverride separator",
        "invalid framing",
    )
    explicit_records = verifier.parse_explicit_triggers(
        "update-example", EXPLICIT_TRIGGER, packages
    )
    if explicit_records != (
        verifier.TriggerRecord(
            "explicit:update-example", "handler", "amd64", "noawait"
        ),
    ):
        raise SystemExit("explicit trigger registry changed its semantic owner")
    for label, name, raw, expected in (
        (
            "empty explicit trigger registry",
            "update-example",
            b"",
            "invalid framing or size",
        ),
        (
            "vertical-tab explicit trigger registry",
            "update-example",
            b"handler/noawait\v",
            "invalid framing or size",
        ),
        (
            "duplicate explicit trigger owner",
            "update-example",
            b"handler/noawait\nhandler/noawait\n",
            "repeats an owner",
        ),
        (
            "spaced explicit trigger owner",
            "update-example",
            b"handler noawait\n",
            "malformed owner",
        ),
        (
            "unknown explicit trigger owner",
            "update-example",
            b"unknown/noawait\n",
            "unsafe owner",
        ),
        (
            "invalid explicit trigger name",
            "Update Example",
            EXPLICIT_TRIGGER,
            "explicit name is not canonical",
        ),
        (
            "oversized explicit trigger registry",
            "update-example",
            b"x" * (verifier.MAX_EXPLICIT_TRIGGER_FILE_BYTES + 1),
            "invalid framing or size",
        ),
    ):
        require_rejected(
            verifier,
            lambda name=name, raw=raw: verifier.parse_explicit_triggers(
                name, raw, packages
            ),
            label,
            expected,
        )
    numeric_statoverride = b"#0 #65534 4755 /usr/bin/helper\n"
    try:
        numeric_records = verifier.parse_statoverrides(numeric_statoverride)
    except verifier.DpkgStateError as exc:
        raise SystemExit(
            "dpkg state verifier rejected legal numeric statoverride identities: "
            + str(exc)
        ) from exc
    if numeric_records != (
        verifier.StatoverrideRecord("#0", "#65534", "4755", "/usr/bin/helper"),
    ):
        raise SystemExit("numeric statoverride identities changed during parsing")
    for hostile_identity in (b"#", b"#+1", b"#-1", b"#00", b"#01", b"#4294967296"):
        require_rejected(
            verifier,
            lambda hostile_identity=hostile_identity: verifier.parse_statoverrides(
                hostile_identity + b" root 4755 /usr/bin/helper\n"
            ),
            f"invalid numeric statoverride identity {hostile_identity!r}",
            "unsafe record",
        )
    exact_utf8_path = "/" + "é" * 2047 + "a"
    if len(exact_utf8_path.encode("utf-8")) != 4096:
        raise SystemExit("UTF-8 path boundary fixture has the wrong byte length")
    if (
        verifier.validate_absolute_path(exact_utf8_path, "UTF-8 path fixture")
        != exact_utf8_path
    ):
        raise SystemExit("exact 4096-byte UTF-8 path changed during validation")
    require_rejected(
        verifier,
        lambda: verifier.validate_absolute_path(
            exact_utf8_path + "a", "UTF-8 path fixture"
        ),
        "4097-byte UTF-8 dpkg path",
        "is not canonical",
    )
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-dpkg-state-test.") as raw:
        root = pathlib.Path(raw)
        admin = make_valid_tree(root)
        require_state_descriptor_custody_oracles(verifier, admin)
        state = verifier.capture_dpkg_state(admin, os.getuid(), os.getgid())
        live_script_total = sum(item.size for item in state.scripts)
        original_script_total_bound = verifier.MAX_SCRIPT_TOTAL_BYTES
        try:
            verifier.MAX_SCRIPT_TOTAL_BYTES = live_script_total
            verifier.capture_dpkg_state(admin, os.getuid(), os.getgid())
            verifier.MAX_SCRIPT_TOTAL_BYTES = live_script_total - 1
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(
                    admin, os.getuid(), os.getgid()
                ),
                "live maintainer-script aggregate limit+1",
                "maintainer scripts exceed their total byte bound",
            )
        finally:
            verifier.MAX_SCRIPT_TOTAL_BYTES = original_script_total_bound
        serialized = verifier.serialize_dpkg_state(state)
        expected_reference = (
            "schema\ttb321fu.haptics-dpkg-state/v1\n"
            f"state-file\tdiversions\t644\t{len(DIVERSIONS)}\t"
            f"{hashlib.sha256(DIVERSIONS).hexdigest()}\n"
            f"state-file\tstatoverride\t644\t{len(STATOVERRIDE)}\t"
            f"{hashlib.sha256(STATOVERRIDE).hexdigest()}\n"
            f"state-file\tstatus\t644\t{len(STATUS)}\t"
            f"{hashlib.sha256(STATUS).hexdigest()}\n"
            f"state-file\ttriggers/File\t644\t{len(TRIGGER_FILE)}\t"
            f"{hashlib.sha256(TRIGGER_FILE).hexdigest()}\n"
            "state-file\ttriggers/Unincorp\t644\t0\t"
            f"{hashlib.sha256(b'').hexdigest()}\n"
            f"state-file\ttriggers/update-example\t644\t{len(EXPLICIT_TRIGGER)}\t"
            f"{hashlib.sha256(EXPLICIT_TRIGGER).hexdigest()}\n"
            "trigger\t/usr/share/example\thandler\tamd64\tnoawait\n"
            "trigger\texplicit:update-example\thandler\tamd64\tnoawait\n"
            "handler\thandler\tamd64\t1.0-1\tinstall ok installed\n"
            "diversion\t/usr/bin/tool\t/usr/bin/tool.distrib\thandler\n"
            "statoverride\troot\troot\t4755\t/usr/bin/helper\n"
            f"script\thandler\tamd64\thandler.postinst\t755\t{len(POSTINST)}\t"
            f"{hashlib.sha256(POSTINST).hexdigest()}\n"
            f"script\thandler\tamd64\thandler.triggers\t644\t"
            f"{len(TRIGGER_METADATA)}\t{hashlib.sha256(TRIGGER_METADATA).hexdigest()}\n"
        ).encode("ascii")
        if serialized != expected_reference:
            difference = "".join(
                difflib.unified_diff(
                    expected_reference.decode("ascii").splitlines(keepends=True),
                    serialized.decode("ascii").splitlines(keepends=True),
                    fromfile="independent-expected",
                    tofile="captured-actual",
                    n=1,
                )
            )
            raise SystemExit(
                "dpkg state serializer differs from the independent literal oracle:\n"
                + difference[:8192]
            )
        statoverride_path = admin / "statoverride"
        write_file(statoverride_path, numeric_statoverride, 0o644)
        try:
            numeric_state = verifier.capture_dpkg_state(
                admin, os.getuid(), os.getgid()
            )
            numeric_state_raw = verifier.serialize_dpkg_state(numeric_state)
            if (
                b"statoverride\t#0\t#65534\t4755\t/usr/bin/helper\n"
                not in numeric_state_raw
                or verifier.parse_dpkg_state_bytes(numeric_state_raw) != numeric_state
            ):
                raise SystemExit("numeric statoverride full-state round-trip failed")
            numeric_host = verifier.host_reference_from_state(numeric_state)
            numeric_host_raw = verifier.serialize_host_reference(numeric_host)
            if verifier.parse_host_reference_bytes(numeric_host_raw) != numeric_host:
                raise SystemExit("numeric statoverride host-reference round-trip failed")
        finally:
            write_file(statoverride_path, STATOVERRIDE, 0o644)
        utf8_diversions = (
            "/usr/bin/café\n/usr/bin/café.distrib\nhandler\n"
        ).encode("utf-8")
        diversions_path = admin / "diversions"
        write_file(diversions_path, utf8_diversions, 0o644)
        try:
            utf8_state = verifier.capture_dpkg_state(
                admin, os.getuid(), os.getgid()
            )
            utf8_state_raw = verifier.serialize_dpkg_state(utf8_state)
            if (
                b"caf\xc3\xa9" not in utf8_state_raw
                or verifier.parse_dpkg_state_bytes(utf8_state_raw) != utf8_state
            ):
                raise SystemExit("UTF-8 diversion full-state round-trip failed")
            utf8_host = verifier.host_reference_from_state(utf8_state)
            utf8_host_raw = verifier.serialize_host_reference(utf8_host)
            if (
                b"caf\xc3\xa9" not in utf8_host_raw
                or verifier.parse_host_reference_bytes(utf8_host_raw) != utf8_host
            ):
                raise SystemExit("UTF-8 diversion host-reference round-trip failed")
        finally:
            write_file(diversions_path, DIVERSIONS, 0o644)
        serialized_lines = serialized.splitlines(keepends=True)
        state_positions = [
            index
            for index, line in enumerate(serialized_lines)
            if line.startswith(b"state-file\t")
        ]
        reversed_state_files = list(serialized_lines)
        reversed_state_files[state_positions[0]], reversed_state_files[state_positions[-1]] = (
            reversed_state_files[state_positions[-1]],
            reversed_state_files[state_positions[0]],
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(b"".join(reversed_state_files)),
            "reordered state-file records",
            "noncanonical",
        )
        handler_line = b"handler\thandler\tamd64\t1.0-1\tinstall ok installed\n"
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(
                    handler_line,
                    handler_line
                    + b"handler\thandler\tamd64\t2.0-1\tinstall ok installed\n",
                    1,
                )
            ),
            "conflicting handler identity",
            "logical key",
        )
        trigger_line = b"trigger\t/usr/share/example\thandler\tamd64\tnoawait\n"
        diversion_line = (
            b"diversion\t/usr/bin/tool\t/usr/bin/tool.distrib\thandler\n"
        )
        statoverride_line = (
            b"statoverride\troot\troot\t4755\t/usr/bin/helper\n"
        )
        trigger_script_line = (
            f"script\thandler\tamd64\thandler.triggers\t644\t"
            f"{len(TRIGGER_METADATA)}\t{hashlib.sha256(TRIGGER_METADATA).hexdigest()}\n"
        ).encode("ascii")
        for label, hostile_reference in (
            (
                "conflicting trigger mode",
                serialized.replace(
                    trigger_line,
                    trigger_line
                    + b"trigger\t/usr/share/example\thandler\tamd64\tawait\n",
                    1,
                ),
            ),
            (
                "conflicting diversion source",
                serialized.replace(
                    diversion_line,
                    diversion_line
                    + b"diversion\t/usr/bin/tool\t/usr/bin/tool.other\thandler\n",
                    1,
                ),
            ),
            (
                "conflicting diversion destination",
                serialized.replace(
                    diversion_line,
                    diversion_line
                    + b"diversion\t/usr/bin/other\t/usr/bin/tool.distrib\thandler\n",
                    1,
                ),
            ),
            (
                "conflicting statoverride path",
                serialized.replace(
                    statoverride_line,
                    statoverride_line
                    + b"statoverride\troot\troot\t0755\t/usr/bin/helper\n",
                    1,
                ),
            ),
            (
                "conflicting maintainer-script identity",
                serialized.replace(
                    trigger_script_line,
                    trigger_script_line.replace(
                        hashlib.sha256(TRIGGER_METADATA).hexdigest().encode("ascii"),
                        b"2" * 64,
                    )
                    + trigger_script_line,
                    1,
                ),
            ),
            (
                "extra unregistered handler",
                serialized.replace(
                    handler_line,
                    handler_line
                    + b"handler\textra\tamd64\t1.0-1\tinstall ok installed\n",
                    1,
                ),
            ),
            (
                "missing handler triggers metadata",
                serialized.replace(trigger_script_line, b"", 1),
            ),
        ):
            require_rejected(
                verifier,
                lambda hostile_reference=hostile_reference: verifier.parse_dpkg_state_bytes(
                    hostile_reference
                ),
                label,
                "logical key",
            )
        diversion_state = next(
            item for item in state.state_files if item.name == "diversions"
        )
        diversion_state_line = (
            f"state-file\tdiversions\t644\t{diversion_state.size}\t"
            f"{diversion_state.sha256}\n"
        ).encode("ascii")
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(
                    diversion_state_line,
                    diversion_state_line.replace(
                        f"\t{diversion_state.size}\t".encode("ascii"),
                        b"\t4194305\t",
                        1,
                    ),
                    1,
                )
            ),
            "oversized diversion reference",
            "size bound",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(b"\nstate-file", b"\vstate-file", 1)
            ),
            "vertical-tab reference separator",
            "invalid framing",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(b"/usr/bin/tool", b"/usr/bin/\xff", 1)
            ),
            "invalid UTF-8 full-state path",
            "UTF-8 only",
        )
        if not hasattr(verifier, "parse_dpkg_state_bytes"):
            raise SystemExit("dpkg state reference parser is missing")
        if verifier.parse_dpkg_state_bytes(serialized) != state:
            raise SystemExit("dpkg state reference did not round-trip exactly")

        def script_total_reference(last_size: int) -> bytes:
            empty_digest = hashlib.sha256(b"").hexdigest()
            lines = [
                "schema\ttb321fu.haptics-dpkg-state/v1",
                f"state-file\tdiversions\t644\t0\t{empty_digest}",
                f"state-file\tstatoverride\t644\t0\t{empty_digest}",
                f"state-file\tstatus\t644\t0\t{empty_digest}",
                f"state-file\ttriggers/File\t644\t0\t{empty_digest}",
                f"state-file\ttriggers/Unincorp\t644\t0\t{empty_digest}",
            ]
            lines.extend(
                f"trigger\t/trigger/{index:02d}\th{index:02d}\tamd64\tawait"
                for index in range(17)
            )
            lines.extend(
                f"handler\th{index:02d}\tamd64\t1.0-1\tinstall ok installed"
                for index in range(17)
            )
            lines.extend(
                f"script\th{index:02d}\tamd64\th{index:02d}.triggers\t644\t"
                f"{4 * 1024 * 1024 if index < 16 else last_size}\t{empty_digest}"
                for index in range(17)
            )
            return ("\n".join(lines) + "\n").encode("ascii")

        exact_script_total = script_total_reference(0)
        verifier.parse_dpkg_state_bytes(exact_script_total)
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(script_total_reference(1)),
            "maintainer-script aggregate limit+1",
            "maintainer scripts exceed their total byte bound",
        )
        explicit_state_line = (
            f"state-file\ttriggers/update-example\t644\t{len(EXPLICIT_TRIGGER)}\t"
            f"{hashlib.sha256(EXPLICIT_TRIGGER).hexdigest()}\n"
        ).encode("ascii")
        explicit_trigger_line = (
            b"trigger\texplicit:update-example\thandler\tamd64\tnoawait\n"
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(explicit_trigger_line, b"", 1)
            ),
            "explicit trigger registry file without records",
            "explicit trigger registry files and records differ",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(explicit_state_line, b"", 1)
            ),
            "explicit trigger records without registry file",
            "explicit trigger registry files and records differ",
        )
        empty_explicit_state_line = (
            b"state-file\ttriggers/update-example\t644\t0\t"
            + hashlib.sha256(b"").hexdigest().encode("ascii")
            + b"\n"
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(
                    explicit_state_line,
                    empty_explicit_state_line,
                    1,
                )
            ),
            "empty explicit trigger registry reference",
            "explicit trigger registry file is empty",
        )
        trigger_script = next(
            item for item in state.scripts if item.filename == "handler.triggers"
        )
        unqualified_trigger_line = (
            f"script\thandler\tamd64\thandler.triggers\t644\t"
            f"{trigger_script.size}\t{trigger_script.sha256}\n"
        ).encode("ascii")
        qualified_trigger_line = unqualified_trigger_line.replace(
            b"handler.triggers", b"handler:amd64.triggers", 1
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(
                    unqualified_trigger_line,
                    unqualified_trigger_line + qualified_trigger_line,
                    1,
                )
            ),
            "qualified and unqualified script aliases",
            "logical key",
        )
        postinst_script = next(
            item for item in state.scripts if item.filename == "handler.postinst"
        )
        i386_script_lines = (
            f"script\thandler\ti386\thandler.postinst\t755\t"
            f"{postinst_script.size}\t{postinst_script.sha256}\n"
            f"script\thandler\ti386\thandler.triggers\t644\t"
            f"{trigger_script.size}\t{trigger_script.sha256}\n"
        ).encode("ascii")
        multiarch_unqualified_reference = (
            serialized.replace(
                trigger_line,
                trigger_line
                + b"trigger\t/usr/share/example-i386\thandler\ti386\tnoawait\n",
                1,
            )
            .replace(
                handler_line,
                handler_line
                + b"handler\thandler\ti386\t1.0-1\tinstall ok installed\n",
                1,
            )
            .replace(
                unqualified_trigger_line,
                unqualified_trigger_line + i386_script_lines,
                1,
            )
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(multiarch_unqualified_reference),
            "multiarch reference sharing unqualified maintainer metadata",
            "unqualified maintainer metadata is ambiguous across architectures",
        )
        orphan_script_line = unqualified_trigger_line.replace(
            b"script\thandler\tamd64\thandler.triggers",
            b"script\torphan\tamd64\torphan.triggers",
            1,
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(
                    unqualified_trigger_line,
                    orphan_script_line,
                    1,
                )
            ),
            "orphan unqualified maintainer metadata",
            "logical key",
        )
        trigger_line = b"trigger\t/usr/share/example\thandler\tamd64\tnoawait\n"
        oversized_trigger_lines = b"".join(
            f"trigger\t/usr/share/example-{index:04d}\thandler\tamd64\tnoawait\n".encode(
                "ascii"
            )
            for index in range(verifier.MAX_TRIGGER_RECORDS + 1)
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(trigger_line, oversized_trigger_lines, 1)
            ),
            "oversized full-state trigger reference",
            "record-count bound",
        )
        handler_line = b"handler\thandler\tamd64\t1.0-1\tinstall ok installed\n"
        original_script_lines = b"".join(
            (
                f"script\t{item.package}\t{item.architecture}\t{item.filename}\t"
                f"{item.mode:o}\t{item.size}\t{item.sha256}\n"
            ).encode("ascii")
            for item in state.scripts
        )
        oversized_handler_triggers = b"".join(
            (
                f"trigger\t/usr/share/handler-{index:04d}\t"
                f"handler{index:04d}\tamd64\tnoawait\n"
            ).encode("ascii")
            for index in range(verifier.MAX_HANDLER_RECORDS + 1)
        )
        oversized_handlers = b"".join(
            (
                f"handler\thandler{index:04d}\tamd64\t1.0-1\t"
                "install ok installed\n"
            ).encode("ascii")
            for index in range(verifier.MAX_HANDLER_RECORDS + 1)
        )
        oversized_handler_scripts = b"".join(
            (
                f"script\thandler{index:04d}\tamd64\t"
                f"handler{index:04d}.triggers\t644\t{len(TRIGGER_METADATA)}\t"
                f"{hashlib.sha256(TRIGGER_METADATA).hexdigest()}\n"
            ).encode("ascii")
            for index in range(verifier.MAX_HANDLER_RECORDS + 1)
        )

        def with_oversized_handler_set(raw: bytes) -> bytes:
            return (
                raw.replace(trigger_line, oversized_handler_triggers, 1)
                .replace(handler_line, oversized_handlers, 1)
                .replace(original_script_lines, oversized_handler_scripts, 1)
            )

        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                with_oversized_handler_set(serialized)
            ),
            "oversized full-state handler set",
            "handler set exceeds its count bound",
        )
        max_script_records = verifier.MAX_HANDLER_RECORDS * len(
            verifier.SCRIPT_SUFFIXES
        )
        oversized_script_lines = unqualified_trigger_line * (max_script_records + 1)
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(
                    original_script_lines,
                    oversized_script_lines,
                    1,
                )
            ),
            "oversized full-state script set",
            "script set exceeds its count bound",
        )
        required_host_interfaces = (
            "DpkgHostReference",
            "host_reference_from_state",
            "serialize_host_reference",
            "parse_host_reference_bytes",
            "verify_host_reference",
        )
        if not all(hasattr(verifier, name) for name in required_host_interfaces):
            raise SystemExit("dpkg reviewed-host reference interface is missing")
        host_reference = verifier.host_reference_from_state(state)
        host_raw = verifier.serialize_host_reference(host_reference)
        expected_host_reference = (
            "schema\ttb321fu.haptics-dpkg-host-reference/v1\n"
            f"state-file\tdiversions\t644\t{len(DIVERSIONS)}\t"
            f"{hashlib.sha256(DIVERSIONS).hexdigest()}\n"
            f"state-file\tstatoverride\t644\t{len(STATOVERRIDE)}\t"
            f"{hashlib.sha256(STATOVERRIDE).hexdigest()}\n"
            f"state-file\ttriggers/File\t644\t{len(TRIGGER_FILE)}\t"
            f"{hashlib.sha256(TRIGGER_FILE).hexdigest()}\n"
            f"state-file\ttriggers/update-example\t644\t{len(EXPLICIT_TRIGGER)}\t"
            f"{hashlib.sha256(EXPLICIT_TRIGGER).hexdigest()}\n"
            "trigger\t/usr/share/example\thandler\tamd64\tnoawait\n"
            "trigger\texplicit:update-example\thandler\tamd64\tnoawait\n"
            "handler\thandler\tamd64\t1.0-1\tinstall ok installed\n"
            "diversion\t/usr/bin/tool\t/usr/bin/tool.distrib\thandler\n"
            "statoverride\troot\troot\t4755\t/usr/bin/helper\n"
            f"script\thandler\tamd64\thandler.postinst\t755\t{len(POSTINST)}\t"
            f"{hashlib.sha256(POSTINST).hexdigest()}\n"
            f"script\thandler\tamd64\thandler.triggers\t644\t"
            f"{len(TRIGGER_METADATA)}\t{hashlib.sha256(TRIGGER_METADATA).hexdigest()}\n"
        ).encode("ascii")
        if host_raw != expected_host_reference:
            raise SystemExit("host reference differs from the independent literal oracle")
        if verifier.parse_host_reference_bytes(host_raw) != host_reference:
            raise SystemExit("host reference did not round-trip exactly")
        require_rejected(
            verifier,
            lambda: verifier.parse_host_reference_bytes(
                host_raw.replace(b"/usr/bin/tool", b"/usr/bin/\xff", 1)
            ),
            "invalid UTF-8 host-reference path",
            "UTF-8 only",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_host_reference_bytes(
                host_raw.replace(
                    unqualified_trigger_line,
                    unqualified_trigger_line + qualified_trigger_line,
                    1,
                )
            ),
            "qualified and unqualified host script aliases",
            "logical key",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_host_reference_bytes(
                host_raw.replace(trigger_line, oversized_trigger_lines, 1)
            ),
            "oversized host trigger reference",
            "record-count bound",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_host_reference_bytes(
                with_oversized_handler_set(host_raw)
            ),
            "oversized host handler set",
            "handler set exceeds its count bound",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_host_reference_bytes(
                host_raw.replace(
                    original_script_lines,
                    oversized_script_lines,
                    1,
                )
            ),
            "oversized host script set",
            "script set exceeds its count bound",
        )
        verifier.verify_host_reference(state, host_reference)
        diversions_path = admin / "diversions"
        write_file(
            diversions_path,
            DIVERSIONS.replace(b"/usr/bin/tool.distrib", b"/usr/bin/tool.vendor", 1),
            0o644,
        )
        try:
            diversion_drift = verifier.capture_dpkg_state(
                admin, os.getuid(), os.getgid()
            )
            require_rejected(
                verifier,
                lambda: verifier.verify_host_reference(
                    diversion_drift, host_reference
                ),
                "reviewed diversion drift",
                "differs from its reviewed reference",
            )
        finally:
            write_file(diversions_path, DIVERSIONS, 0o644)

        statoverride_path = admin / "statoverride"
        write_file(
            statoverride_path,
            STATOVERRIDE.replace(b" 4755 ", b" 0755 ", 1),
            0o644,
        )
        try:
            statoverride_drift = verifier.capture_dpkg_state(
                admin, os.getuid(), os.getgid()
            )
            require_rejected(
                verifier,
                lambda: verifier.verify_host_reference(
                    statoverride_drift, host_reference
                ),
                "reviewed statoverride drift",
                "differs from its reviewed reference",
            )
        finally:
            write_file(statoverride_path, STATOVERRIDE, 0o644)

        trigger_file_path = admin / "triggers/File"
        trigger_metadata_path = admin / "info/handler.triggers"
        drifted_trigger_file = TRIGGER_FILE.replace(
            b"/usr/share/example", b"/usr/share/example-drift", 1
        )
        drifted_trigger_metadata = TRIGGER_METADATA.replace(
            b"/usr/share/example", b"/usr/share/example-drift", 1
        )
        write_file(trigger_file_path, drifted_trigger_file, 0o644)
        write_file(trigger_metadata_path, drifted_trigger_metadata, 0o644)
        try:
            trigger_registry_drift = verifier.capture_dpkg_state(
                admin, os.getuid(), os.getgid()
            )
            require_rejected(
                verifier,
                lambda: verifier.verify_host_reference(
                    trigger_registry_drift, host_reference
                ),
                "reviewed trigger-registry drift",
                "differs from its reviewed reference",
            )
        finally:
            write_file(trigger_file_path, TRIGGER_FILE, 0o644)
            write_file(trigger_metadata_path, TRIGGER_METADATA, 0o644)
        approved_handler = (("handler", "amd64"),)
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, diversion_drift, approved_handler
            ),
            "approved handler with diversion drift",
            "static mutable state changed",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, statoverride_drift, approved_handler
            ),
            "approved handler with statoverride drift",
            "static mutable state changed",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, trigger_registry_drift, ()
            ),
            "unapproved trigger-registry transition",
            "outside the approved package set",
        )
        verifier.verify_post_dpkg_state(
            state, trigger_registry_drift, approved_handler
        )

        status_path = admin / "status"
        other_trigger_path = admin / "info/other.triggers"
        other_status = (
            STATUS
            + b"Package: other\n"
            + b"Status: install ok installed\n"
            + b"Architecture: amd64\n"
            + b"Version: 1.0-1\n\n"
        )
        write_file(status_path, other_status, 0o644)
        write_file(
            trigger_file_path,
            TRIGGER_FILE + b"/usr/share/other other/noawait\n",
            0o644,
        )
        write_file(other_trigger_path, b"interest-noawait /usr/share/other\n", 0o644)
        try:
            unrelated_handler_drift = verifier.capture_dpkg_state(
                admin, os.getuid(), os.getgid()
            )
        finally:
            write_file(status_path, STATUS, 0o644)
            write_file(trigger_file_path, TRIGGER_FILE, 0o644)
            other_trigger_path.unlink()
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, unrelated_handler_drift, approved_handler
            ),
            "approved handler with unrelated trigger owner drift",
            "outside the approved package set",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_host_reference_bytes(
                host_raw.replace(b"\nstate-file", b"\vstate-file", 1)
            ),
            "vertical-tab host-reference separator",
            "invalid framing",
        )
        uid = str(os.getuid())
        gid = str(os.getgid())
        capture_state = run_cli("--capture-state", str(admin), uid, gid)
        if capture_state.returncode or capture_state.stdout != serialized or capture_state.stderr:
            raise SystemExit(
                "dpkg state capture CLI failed: "
                + capture_state.stderr.decode("utf-8", errors="replace")
            )
        abbreviated_mode = run_cli(
            "--capture-state", "--capture-s", str(admin), uid, gid
        )
        if abbreviated_mode.returncode == 0:
            raise SystemExit("dpkg state CLI accepted an abbreviated long option")
        if b"unrecognized arguments: --capture-s" not in abbreviated_mode.stderr:
            raise SystemExit("dpkg state CLI rejected an abbreviation at the wrong boundary")
        capture_host = run_cli("--capture-host-reference", str(admin), uid, gid)
        if capture_host.returncode or capture_host.stdout != host_raw or capture_host.stderr:
            raise SystemExit(
                "dpkg host-reference capture CLI failed: "
                + capture_host.stderr.decode("utf-8", errors="replace")
            )
        state_reference_path = root / "state-reference.tsv"
        host_reference_path = root / "host-reference.tsv"
        write_file(state_reference_path, serialized, 0o600)
        write_file(host_reference_path, host_raw, 0o600)
        verify_state_cli = run_cli(
            "--verify-state", str(admin), uid, gid, str(state_reference_path)
        )
        if (
            verify_state_cli.returncode
            or verify_state_cli.stdout != b"HAPTICS_DPKG_STATE=PASS\n"
            or verify_state_cli.stderr
        ):
            raise SystemExit("dpkg state verify CLI failed")
        status_path = admin / "status"
        write_file(
            status_path,
            STATUS.replace(b"Version: 2.0-1", b"Version: 8.0-1", 1),
            0o644,
        )
        try:
            drifted_verify_state_cli = run_cli(
                "--verify-state", str(admin), uid, gid, str(state_reference_path)
            )
            if drifted_verify_state_cli.returncode == 0:
                raise SystemExit("dpkg state verify CLI accepted unrelated status drift")
            if (
                b"dpkg mutable or trigger state differs from its reference"
                not in drifted_verify_state_cli.stderr
            ):
                raise SystemExit("dpkg state verify CLI rejected drift at the wrong boundary")
        finally:
            write_file(status_path, STATUS, 0o644)
        verify_host_cli = run_cli(
            "--verify-host-reference", str(admin), uid, gid, str(host_reference_path)
        )
        if (
            verify_host_cli.returncode
            or verify_host_cli.stdout != b"HAPTICS_DPKG_HOST_REFERENCE=PASS\n"
            or verify_host_cli.stderr
        ):
            raise SystemExit("dpkg host-reference verify CLI failed")
        unknown_mode = run_cli(
            "--verify-state",
            "--verify-hook",
            str(admin),
            uid,
            gid,
            str(state_reference_path),
        )
        if unknown_mode.returncode == 0:
            raise SystemExit("dpkg state CLI accepted an unknown hook mode")
        if b"unrecognized arguments: --verify-hook" not in unknown_mode.stderr:
            raise SystemExit("dpkg state CLI rejected an unknown mode at the wrong boundary")
        if not hasattr(verifier, "verify_dpkg_state"):
            raise SystemExit("dpkg state comparison verifier is missing")
        if not hasattr(verifier, "verify_post_dpkg_state"):
            raise SystemExit("dpkg post-transition verifier is missing")
        verifier.verify_dpkg_state(state, verifier.parse_dpkg_state_bytes(serialized))
        for hostile_allowlist, label in (
            ([], "non-tuple post-state allowlist"),
            ((("handler",),), "malformed post-state identity"),
            (
                (("handler", "amd64"), ("handler", "amd64")),
                "duplicate post-state identity",
            ),
            (
                (("zeta", "amd64"), ("alpha", "amd64")),
                "unsorted post-state identities",
            ),
        ):
            require_rejected(
                verifier,
                lambda hostile_allowlist=hostile_allowlist: verifier.verify_post_dpkg_state(
                    state, state, hostile_allowlist
                ),
                label,
                "package identities are not canonical",
            )
        write_file(
            status_path,
            STATUS.replace(b"Version: 2.0-1", b"Version: 8.0-1", 1),
            0o644,
        )
        unrelated_status_drift = verifier.capture_dpkg_state(
            admin, os.getuid(), os.getgid()
        )
        verifier.verify_host_reference(unrelated_status_drift, host_reference)
        verifier.verify_post_dpkg_state(state, unrelated_status_drift, ())
        require_rejected(
            verifier,
            lambda: verifier.verify_dpkg_state(unrelated_status_drift, state),
            "unrelated full-status drift",
            "differs from its reference",
        )
        write_file(status_path, STATUS, 0o644)
        write_file(
            status_path,
            STATUS.replace(b"Version: 1.0-1", b"Version: 9.0-1", 1),
            0o644,
        )
        handler_status_drift = verifier.capture_dpkg_state(
            admin, os.getuid(), os.getgid()
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_host_reference(handler_status_drift, host_reference),
            "trigger-handler package version drift",
            "differs from its reviewed reference",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, handler_status_drift, ()
            ),
            "unapproved trigger-handler transition",
            "outside the approved package set",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, handler_status_drift, (("handler", "arm64"),)
            ),
            "cross-architecture post-state allowance",
            "outside the approved package set",
        )
        verifier.verify_post_dpkg_state(
            state, handler_status_drift, (("handler", "amd64"),)
        )
        write_file(status_path, STATUS, 0o644)
        postinst = admin / "info/handler.postinst"
        original_mtime = postinst.stat().st_mtime_ns
        write_file(postinst, b"#!/bin/sh\nexit 1\n", 0o755)
        os.utime(postinst, ns=(original_mtime, original_mtime))
        drifted_state = verifier.capture_dpkg_state(admin, os.getuid(), os.getgid())
        require_rejected(
            verifier,
            lambda: verifier.verify_dpkg_state(drifted_state, state),
            "same-size maintainer-script drift",
            "differs from its reference",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_host_reference(drifted_state, host_reference),
            "reviewed maintainer-script drift",
            "differs from its reviewed reference",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(state, drifted_state, ()),
            "unapproved maintainer-script transition",
            "outside the approved package set",
        )
        verifier.verify_post_dpkg_state(
            state, drifted_state, (("handler", "amd64"),)
        )
        write_file(postinst, b"#!/bin/sh\nexit 0\n", 0o755)
        explicit_trigger_path = admin / "triggers/update-example"
        write_file(explicit_trigger_path, b"handler\n", 0o644)
        explicit_semantic_drift = verifier.capture_dpkg_state(
            admin, os.getuid(), os.getgid()
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_host_reference(
                explicit_semantic_drift, host_reference
            ),
            "reviewed explicit trigger semantic drift",
            "differs from its reviewed reference",
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state, explicit_semantic_drift, ()
            ),
            "unapproved explicit trigger semantic transition",
            "outside the approved package set",
        )
        verifier.verify_post_dpkg_state(
            state,
            explicit_semantic_drift,
            (("handler", "amd64"),),
        )
        write_file(
            explicit_trigger_path,
            b"handler:amd64/noawait\n",
            0o644,
        )
        explicit_byte_drift = verifier.capture_dpkg_state(
            admin, os.getuid(), os.getgid()
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_post_dpkg_state(
                state,
                explicit_byte_drift,
                (("handler", "amd64"),),
            ),
            "explicit trigger byte drift without semantic transition",
            "registry bytes changed without a semantic transition",
        )
        write_file(explicit_trigger_path, EXPLICIT_TRIGGER, 0o644)
        require_rejected(
            verifier,
            lambda: verifier.parse_dpkg_state_bytes(
                serialized.replace(b"a", b"b", 1)
            ),
            "mutated state reference",
            "schema mismatch",
        )
        if not serialized.startswith(b"schema\ttb321fu.haptics-dpkg-state/v1\n"):
            raise SystemExit("dpkg state serializer omitted its exact schema")
        required = (
            b"trigger\t/usr/share/example\thandler\tamd64\tnoawait\n",
            b"handler\thandler\tamd64\t1.0-1\tinstall ok installed\n",
            b"diversion\t/usr/bin/tool\t/usr/bin/tool.distrib\thandler\n",
            b"statoverride\troot\troot\t4755\t/usr/bin/helper\n",
            b"script\thandler\tamd64\thandler.postinst\t755\t",
            b"script\thandler\tamd64\thandler.triggers\t644\t",
        )
        for record in required:
            if record not in serialized:
                raise SystemExit(f"dpkg state serializer omitted record: {record!r}")
        alias = root / "admin-alias"
        alias.symlink_to(admin, target_is_directory=True)
        require_rejected(
            verifier,
            lambda: verifier.capture_dpkg_state(alias, os.getuid(), os.getgid()),
            "admin-directory symlink",
            "cannot pin dpkg admin directory path",
        )
        original_open = verifier.os.open
        original_fstat = verifier.os.fstat
        failed_component_descriptor = None

        def track_directory_component(path, *arguments, **keywords):
            nonlocal failed_component_descriptor
            descriptor = original_open(path, *arguments, **keywords)
            if path == "var" and keywords.get("dir_fd") is not None:
                failed_component_descriptor = descriptor
            return descriptor

        def fail_component_fstat(descriptor):
            if descriptor == failed_component_descriptor:
                raise OSError("injected component fstat failure")
            return original_fstat(descriptor)

        verifier.os.open = track_directory_component
        verifier.os.fstat = fail_component_fstat
        failed_component_owners = []
        try:
            require_rejected(
                verifier,
                lambda: verifier.pin_directory_chain(
                    admin,
                    failed_component_owners,
                ),
                "directory component fstat failure",
                "cannot pin dpkg admin directory path",
            )
        finally:
            verifier.os.open = original_open
            verifier.os.fstat = original_fstat
        if failed_component_descriptor is None:
            raise SystemExit("directory-pin leak fixture did not reach its target component")
        try:
            original_fstat(failed_component_descriptor)
        except OSError:
            pass
        else:
            os.close(failed_component_descriptor)
            raise SystemExit("directory-pin failure leaked its newly opened descriptor")
        alternate_root = root / "alternate-admin-root"
        alternate_admin = make_valid_tree(alternate_root)
        var_dir = root / "var"
        displaced_var = root / "var.displaced"
        alternate_var = alternate_root / "var"
        original_require_directory = verifier.require_directory
        ancestor_replaced = False

        def replace_admin_ancestor_after_validation(*arguments, **keywords):
            nonlocal ancestor_replaced
            result = original_require_directory(*arguments, **keywords)
            if not ancestor_replaced:
                ancestor_replaced = True
                var_dir.rename(displaced_var)
                alternate_var.rename(var_dir)
            return result

        verifier.require_directory = replace_admin_ancestor_after_validation
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "dpkg admin ancestor replacement before open",
                "ancestor namespace changed",
            )
        finally:
            verifier.require_directory = original_require_directory
            if displaced_var.exists():
                var_dir.rename(alternate_var)
                displaced_var.rename(var_dir)
        lock_target = root / "hostile-lock-target"
        write_file(lock_target, b"", 0o600)
        (admin / "triggers/Lock").symlink_to(lock_target)
        require_rejected(
            verifier,
            lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
            "trigger Lock symlink",
            "cannot open trigger Lock",
        )
        (admin / "triggers/Lock").unlink()
        displaced_status = admin / "status.displaced"
        status_descriptor = os.open(
            status_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )

        def replace_status_namespace():
            status_path.rename(displaced_status)
            write_file(
                status_path,
                STATUS.replace(b"Version: 1.0-1", b"Version: 9.0-1", 1),
                0o644,
            )
            return status_path.lstat()

        try:
            require_rejected(
                verifier,
                lambda: verifier.read_open_regular(
                    status_descriptor,
                    replace_status_namespace,
                    0o644,
                    os.getuid(),
                    os.getgid(),
                    verifier.MAX_STATUS_BYTES,
                    "status",
                ),
                "status pathname replacement during read",
                "namespace changed",
            )
        finally:
            os.close(status_descriptor)
            if displaced_status.exists():
                status_path.unlink(missing_ok=True)
                displaced_status.rename(status_path)
        original_read_regular_at = verifier.read_regular_at
        status_mutated_after_read = False

        def mutate_status_after_stable_read(*arguments, **keywords):
            nonlocal status_mutated_after_read
            result = original_read_regular_at(*arguments, **keywords)
            if arguments[6] == "status" and not status_mutated_after_read:
                status_mutated_after_read = True
                write_file(
                    status_path,
                    STATUS.replace(b"Version: 1.0-1", b"Version: 9.0-1", 1),
                    0o644,
                )
            return result

        verifier.read_regular_at = mutate_status_after_stable_read
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "status mutation after its stable read",
                "regular file changed before capture completed",
            )
        finally:
            verifier.read_regular_at = original_read_regular_at
            write_file(status_path, STATUS, 0o644)
        original_verify_directory_chain = verifier.verify_directory_chain
        status_mutated_during_outer_recheck = False

        def mutate_status_during_outer_recheck(entries):
            nonlocal status_mutated_during_outer_recheck
            if not status_mutated_during_outer_recheck:
                status_mutated_during_outer_recheck = True
                write_file(
                    status_path,
                    STATUS.replace(b"Version: 1.0-1", b"Version: 9.0-1", 1),
                    0o644,
                )
            return original_verify_directory_chain(entries)

        verifier.verify_directory_chain = mutate_status_during_outer_recheck
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "status mutation during outer namespace recheck",
                "regular file changed before capture completed",
            )
        finally:
            verifier.verify_directory_chain = original_verify_directory_chain
            write_file(status_path, STATUS, 0o644)
        fifo_status = admin / "status.fifo"
        status_path.rename(displaced_status)
        os.mkfifo(fifo_status, 0o644)
        fifo_status.rename(status_path)
        try:
            require_bounded_child_rejection(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "status FIFO",
                "metadata differs from policy",
            )
        finally:
            status_path.unlink(missing_ok=True)
            displaced_status.rename(status_path)

        updates_dir = admin / "updates"
        parts_dir = admin / "parts"
        trigger_dir = admin / "triggers"
        info_dir = admin / "info"
        for journal_dir, label in ((updates_dir, "updates"), (parts_dir, "parts")):
            journal_entry = journal_dir / "0000"
            write_file(journal_entry, b"pending\n", 0o644)
            try:
                require_rejected(
                    verifier,
                    lambda: verifier.capture_dpkg_state(
                        admin, os.getuid(), os.getgid()
                    ),
                    f"nonempty dpkg {label} journal",
                    "journal directory is not empty",
                )
            finally:
                journal_entry.unlink()

        unincorp = trigger_dir / "Unincorp"
        write_file(unincorp, b"handler /usr/share/example\n", 0o644)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "nonempty Unincorp",
                "Unincorp is not empty",
            )
        finally:
            write_file(unincorp, b"", 0o644)

        status_path.chmod(0o600)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "status mode drift",
                "status metadata differs from policy",
            )
        finally:
            status_path.chmod(0o644)

        status_link = admin / "status.hardlink"
        os.link(status_path, status_link)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "status hardlink",
                "status metadata differs from policy",
            )
        finally:
            status_link.unlink()

        status_descriptor = os.open(
            status_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
        )
        try:
            require_rejected(
                verifier,
                lambda: verifier.read_open_regular(
                    status_descriptor,
                    status_path.lstat,
                    0o644,
                    os.getuid() + 1,
                    os.getgid(),
                    verifier.MAX_STATUS_BYTES,
                    "status",
                ),
                "status owner drift",
                "metadata differs from policy",
            )
        finally:
            os.close(status_descriptor)

        diversions_path = admin / "diversions"
        original_diversions = diversions_path.read_bytes()
        with diversions_path.open("r+b") as stream:
            stream.truncate(verifier.MAX_STATE_FILE_BYTES + 1)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "oversized live diversions",
                "diversions metadata differs from policy",
            )
        finally:
            write_file(diversions_path, original_diversions, 0o644)

        explicit_trigger_path = trigger_dir / "update-example"
        explicit_trigger_path.chmod(0o600)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "explicit trigger registry mode drift",
                "metadata differs from policy",
            )
        finally:
            explicit_trigger_path.chmod(0o644)

        explicit_symlink = trigger_dir / "explicit-symlink"
        explicit_symlink.symlink_to(explicit_trigger_path.name)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "explicit trigger registry symlink",
                "cannot open explicit trigger registry",
            )
        finally:
            explicit_symlink.unlink()

        explicit_hardlink = trigger_dir / "explicit-hardlink"
        os.link(explicit_trigger_path, explicit_hardlink)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "hardlinked explicit trigger registry",
                "metadata differs from policy",
            )
        finally:
            explicit_hardlink.unlink()

        oversized_explicit = trigger_dir / "oversized-explicit"
        write_file(
            oversized_explicit,
            b"x" * (verifier.MAX_EXPLICIT_TRIGGER_FILE_BYTES + 1),
            0o644,
        )
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "oversized live explicit trigger registry",
                "metadata differs from policy",
            )
        finally:
            oversized_explicit.unlink()

        bulk_explicit_paths = [
            trigger_dir / f"bulk-explicit-{index:02d}" for index in range(16)
        ]
        for path in bulk_explicit_paths:
            write_file(path, b"x" * verifier.MAX_EXPLICIT_TRIGGER_FILE_BYTES, 0o644)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "explicit trigger registry total byte overflow",
                "total byte bound",
            )
        finally:
            for path in bulk_explicit_paths:
                path.unlink()

        displaced_info = admin / "info.displaced"
        info_dir.rename(displaced_info)
        info_dir.symlink_to(displaced_info, target_is_directory=True)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "dpkg info-directory symlink",
                "cannot pin dpkg info directory",
            )
        finally:
            info_dir.unlink()
            displaced_info.rename(info_dir)

        admin_descriptor = os.open(
            admin,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )
        original_fstat = verifier.os.fstat

        def cross_device_child(descriptor):
            metadata = original_fstat(descriptor)
            if descriptor != admin_descriptor:
                fields = list(metadata)
                fields[2] = metadata.st_dev + 1
                return os.stat_result(fields)
            return metadata

        verifier.os.fstat = cross_device_child
        cross_device_owner = verifier.DescriptorOwner()
        try:
            require_rejected(
                verifier,
                lambda: verifier.open_directory_at(
                    cross_device_owner,
                    admin_descriptor,
                    "info",
                    os.getuid(),
                    os.getgid(),
                    "dpkg info directory",
                ),
                "cross-device info directory",
                "metadata differs from policy",
            )
        finally:
            verifier.os.fstat = original_fstat
            os.close(admin_descriptor)

        qualified_triggers = info_dir / "handler:amd64.triggers"
        write_file(qualified_triggers, TRIGGER_METADATA, 0o644)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "ambiguous maintainer trigger metadata",
                "ambiguous maintainer metadata names",
            )
        finally:
            qualified_triggers.unlink()

        status_path = admin / "status"
        trigger_file_path = admin / "triggers/File"
        explicit_trigger_path = admin / "triggers/update-example"
        multiarch_installed_status = STATUS + (
            b"Package: handler\n"
            b"Status: install ok installed\n"
            b"Architecture: i386\n"
            b"Version: 1.0-1\n\n"
        )
        multiarch_trigger_file = (
            b"/usr/share/example-amd64 handler:amd64/noawait\n"
            b"/usr/share/example-i386 handler:i386/noawait\n"
        )
        write_file(status_path, multiarch_installed_status, 0o644)
        write_file(trigger_file_path, multiarch_trigger_file, 0o644)
        write_file(
            explicit_trigger_path,
            b"handler:amd64/noawait\nhandler:i386/noawait\n",
            0o644,
        )
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "multiarch handlers sharing unqualified maintainer metadata",
                "unqualified maintainer metadata is ambiguous across architectures",
            )
        finally:
            write_file(status_path, STATUS, 0o644)
            write_file(trigger_file_path, TRIGGER_FILE, 0o644)
            write_file(explicit_trigger_path, EXPLICIT_TRIGGER, 0o644)

        postinst = info_dir / "handler.postinst"
        displaced_postinst = info_dir / "handler.postinst.displaced"
        postinst.rename(displaced_postinst)
        postinst.symlink_to(displaced_postinst)
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "maintainer-script symlink",
                "cannot open maintainer metadata handler.postinst",
            )
        finally:
            postinst.unlink()
            displaced_postinst.rename(postinst)

        updates_descriptor = os.open(
            updates_dir,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )
        original_listdir = verifier.os.listdir
        verifier.os.listdir = lambda descriptor: (_ for _ in ()).throw(
            AssertionError("eager directory allocation")
        )
        try:
            try:
                streamed_names = verifier.bounded_directory_names(
                    updates_descriptor, "dpkg updates directory"
                )
            except AssertionError as exc:
                raise SystemExit(
                    "dpkg state verifier used eager directory allocation"
                ) from exc
            if streamed_names:
                raise SystemExit("empty journal directory produced names")
        finally:
            verifier.os.listdir = original_listdir
            os.close(updates_descriptor)

        class FakeEntry:
            def __init__(self, name: str) -> None:
                self.name = name

        class FakeScandir:
            def __init__(self, names: list[str], on_enter=None) -> None:
                self.names = names
                self.on_enter = on_enter

            def __enter__(self):
                if self.on_enter is not None:
                    self.on_enter()
                return self

            def __exit__(self, exception_type, exception, traceback) -> None:
                return None

            def __iter__(self):
                return (FakeEntry(name) for name in self.names)

        updates_descriptor = os.open(
            updates_dir,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )
        original_scandir = verifier.os.scandir
        verifier.os.scandir = lambda descriptor: FakeScandir(
            [
                f"entry-{index}"
                for index in range(verifier.MAX_DIRECTORY_ENTRIES + 1)
            ]
        )
        try:
            require_rejected(
                verifier,
                lambda: verifier.bounded_directory_names(
                    updates_descriptor, "dpkg updates directory"
                ),
                "oversized journal directory listing",
                "entry-count bound",
            )
        finally:
            verifier.os.scandir = original_scandir
            os.close(updates_descriptor)

        updates_descriptor = os.open(
            updates_dir,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )

        original_fstat = verifier.os.fstat
        target_fstat_calls = 0

        def drift_directory_identity(descriptor):
            nonlocal target_fstat_calls
            metadata = original_fstat(descriptor)
            if descriptor == updates_descriptor:
                target_fstat_calls += 1
                if target_fstat_calls >= 2:
                    fields = list(metadata)
                    fields[8] = metadata.st_mtime + 1
                    return os.stat_result(fields)
            return metadata

        verifier.os.scandir = lambda descriptor: FakeScandir([])
        verifier.os.fstat = drift_directory_identity
        try:
            require_rejected(
                verifier,
                lambda: verifier.bounded_directory_names(
                    updates_descriptor, "dpkg updates directory"
                ),
                "journal directory mutation during enumeration",
                "changed while it was enumerated",
            )
        finally:
            verifier.os.scandir = original_scandir
            verifier.os.fstat = original_fstat
            os.close(updates_descriptor)

        reference_parent = root / "reference-parent"
        hostile_reference_parent = root / "reference-parent-hostile"
        displaced_reference_parent = root / "reference-parent-displaced"
        reference_parent.mkdir()
        hostile_reference_parent.mkdir()
        reference_path = reference_parent / "reference.tsv"
        hostile_reference_path = hostile_reference_parent / "reference.tsv"
        write_file(reference_path, b"trusted reference\n", 0o600)
        write_file(hostile_reference_path, b"hostile reference\n", 0o600)
        original_verify_directory_chain = verifier.verify_directory_chain
        reference_parent_replaced = False

        def replace_reference_parent_before_final_check(entries):
            nonlocal reference_parent_replaced
            if not reference_parent_replaced:
                reference_parent_replaced = True
                reference_parent.rename(displaced_reference_parent)
                hostile_reference_parent.rename(reference_parent)
            try:
                return original_verify_directory_chain(entries)
            finally:
                if displaced_reference_parent.exists():
                    reference_parent.rename(hostile_reference_parent)
                    displaced_reference_parent.rename(reference_parent)

        verifier.verify_directory_chain = replace_reference_parent_before_final_check
        try:
            require_rejected(
                verifier,
                lambda: verifier.read_regular(
                    reference_path,
                    0o600,
                    os.getuid(),
                    os.getgid(),
                    4096,
                    "dpkg reference fixture",
                ),
                "dpkg reference parent replacement",
                "ancestor namespace changed",
            )
        finally:
            verifier.verify_directory_chain = original_verify_directory_chain
            if displaced_reference_parent.exists():
                reference_parent.rename(hostile_reference_parent)
                displaced_reference_parent.rename(reference_parent)

        replacement_admin = make_valid_tree(root / "replacement")
        displaced_admin = root / "dpkg.displaced"
        original_read_regular_at = verifier.read_regular_at
        admin_replaced = False

        def replace_admin_after_first_file(*arguments, **keywords):
            nonlocal admin_replaced
            result = original_read_regular_at(*arguments, **keywords)
            if not admin_replaced:
                admin_replaced = True
                admin.rename(displaced_admin)
                replacement_admin.rename(admin)
            return result

        verifier.read_regular_at = replace_admin_after_first_file
        try:
            require_rejected(
                verifier,
                lambda: verifier.capture_dpkg_state(admin, os.getuid(), os.getgid()),
                "dpkg admin directory replacement during capture",
                "namespace changed",
            )
        finally:
            verifier.read_regular_at = original_read_regular_at
            if displaced_admin.exists():
                admin.rename(replacement_admin)
                displaced_admin.rename(admin)
    print("HAPTICS_DPKG_STATE_FIXTURE=PASS")


if __name__ == "__main__":
    main()
