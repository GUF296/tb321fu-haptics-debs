#!/usr/bin/env python3
"""Independent fixtures for apt plans and package-state transitions."""

from __future__ import annotations

import contextlib
import errno
import importlib.util
import hashlib
import io
import pathlib
import os
import signal
import subprocess
import sys
import tempfile
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "verify-haptics-build-packages.py"
APT_MODULE_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"
AWK_QUERY = b"""Name: awk
Link: /usr/bin/awk
Slaves:
 awk.1.gz /usr/share/man/man1/awk.1.gz
 nawk /usr/bin/nawk
 nawk.1.gz /usr/share/man/man1/nawk.1.gz
Status: manual
Best: /usr/bin/gawk
Value: /usr/bin/gawk

Alternative: /usr/bin/gawk
Priority: 10
Slaves:
 awk.1.gz /usr/share/man/man1/gawk.1.gz
 nawk /usr/bin/gawk
 nawk.1.gz /usr/share/man/man1/gawk.1.gz

Alternative: /usr/bin/mawk
Priority: 5
Slaves:
 awk.1.gz /usr/share/man/man1/mawk.1.gz
 nawk /usr/bin/mawk
 nawk.1.gz /usr/share/man/man1/mawk.1.gz
"""
ZERO_CANDIDATE_QUERY = b"""Name: editor
Link: /usr/bin/editor
Status: auto
Value: none
"""
SPACED_CANDIDATE_QUERY = b"""Name: editor
Link: /usr/bin/editor
Status: manual
Best: /usr/bin/editor tool
Value: /usr/bin/editor tool

Alternative: /usr/bin/editor tool
Priority: 10
"""
UNSAFE_QUERY = (
    b"Name: edi\xfftor\n"
    b"Link: /usr/bin/edi tor\n"
    b"Slaves:\n"
    b" man\x0b /usr/share/man/edi\t1\n"
    b"Status: auto\n"
    b"Best: /usr/bin/edi\x0ctor\n"
    b"Value: none\n"
    b"\n"
    b"Alternative: /usr/bin/edi\x0ctor\n"
    b"Priority: 10\n"
    b"Slaves:\n"
    b" man\x0b /usr/share/man/a\x1cb\n"
    b"\n"
    b"Alternative: /usr/bin/edi tor 2\n"
    b"Priority: 5\n"
    b"Slaves:\n"
    b" man\x0b /usr/share/man/c\x1dd\n"
)
UNSAFE_CANONICAL_V2 = (
    b"schema\ttb321fu.alternative-query/v2\n"
    b"name-hex\t656469ff746f72\n"
    b"link-hex\t2f7573722f62696e2f65646920746f72\n"
    b"status\tauto\n"
    b"best-hex\t2f7573722f62696e2f6564690c746f72\n"
    b"value-hex\t-\n"
    b"master-slave-hex\t6d616e0b\t"
    b"2f7573722f73686172652f6d616e2f6564690931\n"
    b"candidate-hex\t2f7573722f62696e2f6564690c746f72\t10\n"
    b"candidate-slave-hex\t6d616e0b\t"
    b"2f7573722f73686172652f6d616e2f611c62\n"
    b"candidate-hex\t2f7573722f62696e2f65646920746f722032\t5\n"
    b"candidate-slave-hex\t6d616e0b\t"
    b"2f7573722f73686172652f6d616e2f631d64\n"
)
UNSAFE_CANONICAL_V2_SHA256 = (
    "a55266a7cc94a5cac700f6947a3636ca8393ed530eecb4faa5048eb2d3655f1e"
)
ZERO_CANDIDATE_V1_SHA256 = (
    "3b719128e48a1dab9a4dd368d9582d8e08757dce995c24b9834da73fd61f3996"
)
TIED_CURRENT_QUERY = b"""Name: editor
Link: /usr/bin/editor
Status: manual
Best: /usr/bin/true
Value: /usr/bin/true

Alternative: /usr/bin/false
Priority: 10

Alternative: /usr/bin/true
Priority: 10
"""
TIED_NO_CURRENT_QUERY = b"""Name: editor
Link: /usr/bin/editor
Status: auto
Best: /usr/bin/false
Value: none

Alternative: /usr/bin/false
Priority: 10

Alternative: /usr/bin/true
Priority: 10
"""
TIED_HIGHER_QUERY = b"""Name: editor
Link: /usr/bin/editor
Status: manual
Best: /usr/bin/false
Value: /usr/bin/echo

Alternative: /usr/bin/echo
Priority: 5

Alternative: /usr/bin/false
Priority: 10

Alternative: /usr/bin/true
Priority: 10
"""
SINGLE_CANDIDATE_QUERY = b"""Name: editor
Link: /usr/bin/editor
Status: manual
Best: /usr/bin/vim
Value: /usr/bin/vim

Alternative: /usr/bin/vim
Priority: 0
"""


def alternative_selection_record(
    name: bytes,
    mode: bytes,
    target: bytes | None,
) -> bytes:
    return (
        name
        + b" " * (max(30 - len(name), 0) + 1)
        + mode
        + b" " * (max(8 - len(mode), 0) + 1)
        + (target or b"")
        + b"\n"
    )


def load_module():
    spec = importlib.util.spec_from_file_location("haptics_package_verifier", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load package verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_apt_module():
    spec = importlib.util.spec_from_file_location(
        "haptics_apt_transaction_pid_fixture",
        APT_MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT transaction verifier for PID fixture")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_rejected(
    verifier,
    callback,
    name: str,
    expected: str,
    *,
    exact: bool = False,
) -> None:
    if not expected:
        raise SystemExit(f"empty rejection boundary for hostile fixture: {name}")
    try:
        callback()
    except verifier.PackageLockError as exc:
        diagnostic = str(exc)
        wrong_boundary = diagnostic != expected if exact else expected not in diagnostic
        if wrong_boundary:
            raise SystemExit(
                f"package transaction verifier rejected {name} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"package transaction verifier raised an unexpected exception for {name}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"package transaction verifier accepted hostile fixture: {name}")


def prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier) -> None:
    for sentinel in (
        ValueError("oracle sentinel"),
        OSError("oracle sentinel"),
        SystemExit("oracle sentinel"),
    ):
        try:
            require_rejected(
                verifier,
                lambda sentinel=sentinel: (_ for _ in ()).throw(sentinel),
                "oracle sentinel",
                "must not match",
            )
        except SystemExit as exc:
            if (
                "unexpected exception" not in str(exc)
                or f"{type(sentinel).__name__}: oracle sentinel" not in str(exc)
            ):
                raise SystemExit(
                    f"package transaction rejection oracle failed unclearly: {exc}"
                ) from exc
            continue
        raise SystemExit(
            "package transaction rejection oracle swallowed "
            f"{type(sentinel).__name__}"
        )


def prove_lock_self_test_checks_diagnostic(verifier) -> None:
    original_parse_lock_bytes = verifier.parse_lock_bytes
    for mutation_label, mutation_diagnostic in (
        ("wrong", "package lock schema mismatch"),
        ("non-exact", "package lock has invalid line framing: appended text"),
    ):
        def mutated_crlf_boundary(
            raw: bytes,
            diagnostic: str = mutation_diagnostic,
        ):
            if b"\r" in raw:
                raise verifier.PackageLockError(diagnostic)
            return original_parse_lock_bytes(raw)

        verifier.parse_lock_bytes = mutated_crlf_boundary
        captured_stdout = io.StringIO()
        try:
            try:
                with contextlib.redirect_stdout(captured_stdout):
                    verifier.self_test()
            except verifier.PackageLockError as exc:
                if "self-test rejected crlf.tsv at wrong boundary" not in str(exc):
                    raise SystemExit(
                        "package-lock self-test rejected its mutation unclearly: "
                        f"{exc}"
                    ) from exc
            else:
                raise SystemExit(
                    "package-lock self-test accepted a "
                    f"{mutation_label} CRLF rejection boundary: "
                    f"{captured_stdout.getvalue()!r}"
                )
        finally:
            verifier.parse_lock_bytes = original_parse_lock_bytes


def verify_literal_command_policy(verifier) -> None:
    actual = (
        verifier.COMMAND_TIMEOUT_SECONDS,
        verifier.COMMAND_TERM_GRACE_SECONDS,
        verifier.COMMAND_KILL_REAP_SECONDS,
        verifier.CAPTURE_TIMEOUT_SECONDS,
        verifier.VERIFY_INSTALLED_TIMEOUT_SECONDS,
        verifier.VERIFY_BOOTSTRAP_TIMEOUT_SECONDS,
        verifier.MAX_COMMAND_STDOUT_BYTES,
        verifier.MAX_COMMAND_STDERR_BYTES,
        verifier.MAX_ALTERNATIVE_GROUPS,
    )
    expected = (
        30.0,
        0.25,
        1.0,
        120.0,
        120.0,
        60.0,
        4 * 1024 * 1024,
        8192,
        4096,
    )
    if actual != expected:
        raise SystemExit(f"bounded command policy drifted: {actual!r}")
    exact_diagnostic = b"d" * 8192
    if verifier.render_command_diagnostic(exact_diagnostic) != "d" * 8192:
        raise SystemExit("command diagnostic changed at its exact byte limit")
    overflow_diagnostic = exact_diagnostic + b"x"
    expected_overflow = "d" * 8192 + "...:bytes=8193"
    if verifier.render_command_diagnostic(overflow_diagnostic) != expected_overflow:
        raise SystemExit("command diagnostic truncation boundary changed")


def verify_kill_reap_deadline_and_exception(verifier) -> None:
    original_subprocess = verifier.subprocess
    original_select = verifier.select
    original_os = verifier.os
    original_time = verifier.time
    wait_timeouts: list[float] = []
    process_kills = 0
    group_signals: list[int] = []

    class FakeClock:
        def __init__(self):
            self.now = 0.0

        def monotonic(self):
            return self.now

        def sleep(self, amount):
            self.now += amount

    clock = FakeClock()

    class FakeStream:
        def __init__(self, descriptor):
            self.descriptor = descriptor
            self.closed = False

        def fileno(self):
            return self.descriptor

        def close(self):
            self.closed = True

    class FakeProcess:
        pid = 424242
        returncode = None
        _child_created = True

        def __init__(self):
            self.stdout = FakeStream(10)
            self.stderr = FakeStream(11)

        def poll(self):
            return None

        def wait(self, timeout):
            wait_timeouts.append(timeout)
            clock.now += timeout
            raise original_subprocess.TimeoutExpired(["cleanup wait"], timeout)

        def kill(self):
            nonlocal process_kills
            process_kills += 1

    process = FakeProcess()

    class FakePopen:
        def __new__(cls, *args, **kwargs):
            del cls, args, kwargs
            return process

        @staticmethod
        def __init__(instance, *args, **kwargs):
            del instance, args, kwargs

    class FakeSubprocess:
        def __getattr__(self, name):
            return getattr(original_subprocess, name)

        Popen = FakePopen

    class EmptySelect:
        @staticmethod
        def select(readable, writable, exceptional, timeout):
            del readable, writable, exceptional, timeout
            return [], [], []

    class PersistentGroupOS:
        def __getattr__(self, name):
            return getattr(original_os, name)

        def killpg(self, pid, signum):
            if pid != process.pid:
                raise SystemExit("bounded command signaled the wrong process group")
            if signum:
                group_signals.append(signum)

        @staticmethod
        def waitid(idtype, process_id, options):
            if (
                idtype != original_os.P_PID
                or process_id != process.pid
                or options
                != original_os.WEXITED | original_os.WNOHANG | original_os.WNOWAIT
            ):
                raise SystemExit("bounded command changed its leader ownership probe")
            return None

    arguments = ["/usr/bin/fake-bounded-command"]
    verifier.subprocess = FakeSubprocess()
    verifier.select = EmptySelect
    verifier.os = PersistentGroupOS()
    verifier.time = clock
    try:
        try:
            verifier._bounded_command(
                arguments,
                "kill deadline fixture",
                env={},
                timeout=0.5,
                max_stdout=0,
                max_stderr=0,
            )
        except original_subprocess.TimeoutExpired as exc:
            if exc.cmd != arguments:
                raise SystemExit(
                    "bounded command cleanup replaced the original timeout: "
                    f"{exc!r}"
                ) from exc
        else:
            raise SystemExit("bounded command accepted an unterminated process group")
    finally:
        verifier.subprocess = original_subprocess
        verifier.select = original_select
        verifier.os = original_os
        verifier.time = original_time
    if wait_timeouts != [0.75]:
        raise SystemExit(f"bounded command used multiple KILL waits: {wait_timeouts!r}")
    if process_kills:
        raise SystemExit("bounded command added a second direct-process KILL phase")
    if group_signals != [signal.SIGTERM, signal.SIGKILL]:
        raise SystemExit(f"bounded command signal order drifted: {group_signals!r}")
    if clock.now > 1.000001:
        raise SystemExit(f"bounded command exceeded the cleanup deadline: {clock.now}")
    if not process.stdout.closed or not process.stderr.closed:
        raise SystemExit("bounded command leaked a pipe after cleanup failure")


def verify_bounded_command_process_group_ownership(*verifiers) -> None:
    for verifier in verifiers:
        for scenario, expected_signals in (
            ("normal", [signal.SIGKILL]),
            ("timeout", [signal.SIGTERM, signal.SIGKILL]),
            ("read-error", [signal.SIGTERM, signal.SIGKILL]),
        ):
            original_subprocess = verifier.subprocess
            original_select = verifier.select
            original_os = verifier.os
            original_time = verifier.time
            signals_before_reap: list[int] = []
            calls_after_reap: list[int] = []
            read_sentinel = OSError(errno.EIO, "injected bounded-command read failure")

            class FakeClock:
                def __init__(self):
                    self.now = 0.0

                def monotonic(self):
                    return self.now

                def sleep(self, amount):
                    self.now += amount

            clock = FakeClock()

            class FakeStream:
                def __init__(self, descriptor):
                    self.descriptor = descriptor
                    self.closed = False

                def fileno(self):
                    return self.descriptor

                def close(self):
                    self.closed = True

            class FakeWaitResult:
                si_pid = 454545

            class FakeProcess:
                pid = FakeWaitResult.si_pid
                _child_created = True

                def __init__(self):
                    self.stdout = FakeStream(30)
                    self.stderr = FakeStream(31)
                    self.returncode = None
                    self.exited = scenario == "normal"
                    self.reaped = False
                    self.poll_calls = 0
                    self.wait_calls = 0

                def poll(self):
                    self.poll_calls += 1
                    self.exited = True
                    self.reaped = True
                    self.returncode = 0
                    return self.returncode

                def wait(self, timeout):
                    del timeout
                    self.wait_calls += 1
                    if self.reaped:
                        raise ChildProcessError("leader was reaped more than once")
                    self.exited = True
                    self.reaped = True
                    self.returncode = 0
                    return self.returncode

            process = FakeProcess()

            class FakePopen:
                def __new__(cls, *args, **kwargs):
                    del cls, args, kwargs
                    return process

                @staticmethod
                def __init__(instance, *args, **kwargs):
                    del instance, args, kwargs

            class FakeSubprocess:
                def __getattr__(self, name):
                    return getattr(original_subprocess, name)

                Popen = FakePopen

            class FakeSelect:
                POLLIN = original_select.POLLIN
                POLLPRI = original_select.POLLPRI
                POLLHUP = original_select.POLLHUP
                POLLERR = original_select.POLLERR
                POLLNVAL = original_select.POLLNVAL

                @staticmethod
                def select(readable, writable, exceptional, timeout):
                    del writable, exceptional, timeout
                    if scenario == "timeout":
                        return [], [], []
                    return list(readable), [], []

                @staticmethod
                def poll():
                    class FakePoll:
                        def __init__(self):
                            self.descriptors = []

                        def register(self, descriptor, event_mask):
                            if event_mask != FakeSelect.POLLIN:
                                raise SystemExit(
                                    "bounded command registered an unexpected poll event"
                                )
                            self.descriptors.append(descriptor)

                        def unregister(self, descriptor):
                            try:
                                self.descriptors.remove(descriptor)
                            except ValueError as exc:
                                raise OSError("poll descriptor was not registered") from exc

                        def poll(self, timeout):
                            del timeout
                            if scenario == "timeout":
                                return []
                            return [
                                (descriptor, FakeSelect.POLLIN)
                                for descriptor in tuple(self.descriptors)
                            ]

                    return FakePoll()

            class OwnershipOS:
                def __getattr__(self, name):
                    return getattr(original_os, name)

                @staticmethod
                def read(descriptor, amount):
                    del descriptor, amount
                    if scenario == "read-error":
                        raise read_sentinel
                    return b""

                @staticmethod
                def waitid(idtype, process_id, options):
                    if idtype != original_os.P_PID or process_id != process.pid:
                        raise SystemExit("bounded command observed the wrong process leader")
                    expected_options = (
                        original_os.WEXITED | original_os.WNOHANG | original_os.WNOWAIT
                    )
                    if options != expected_options:
                        raise SystemExit("bounded command changed the waitid ownership probe")
                    if process.reaped:
                        raise ChildProcessError("fixture leader identity was released")
                    return FakeWaitResult() if process.exited else None

                @staticmethod
                def killpg(process_group, signum):
                    if process_group != process.pid:
                        raise SystemExit("bounded command signaled the wrong process group")
                    if process.reaped:
                        calls_after_reap.append(signum)
                        raise ProcessLookupError
                    signals_before_reap.append(signum)
                    if signum:
                        process.exited = True

            verifier.subprocess = FakeSubprocess()
            verifier.select = FakeSelect
            verifier.os = OwnershipOS()
            verifier.time = clock
            try:
                try:
                    result = verifier._bounded_command(
                        ["/usr/bin/pid-ownership-fixture"],
                        f"{scenario} PID ownership fixture",
                        env={},
                        timeout=0.5,
                        max_stdout=0,
                        max_stderr=0,
                    )
                except BaseException as exc:
                    if scenario == "normal":
                        raise SystemExit(
                            "bounded command rejected the normal PID ownership fixture"
                        ) from exc
                    if scenario == "timeout":
                        if not isinstance(exc, original_subprocess.TimeoutExpired):
                            raise SystemExit(
                                "bounded command replaced the timeout ownership sentinel"
                            ) from exc
                    else:
                        preserved = exc is read_sentinel
                        if not preserved:
                            transaction_error = getattr(
                                verifier, "AptTransactionError", ()
                            )
                            preserved = (
                                bool(transaction_error)
                                and isinstance(exc, transaction_error)
                                and exc.__cause__ is read_sentinel
                            )
                        if not preserved:
                            raise SystemExit(
                                "bounded command replaced the read ownership sentinel"
                            ) from exc
                else:
                    if scenario != "normal" or result != (0, b"", b""):
                        raise SystemExit(
                            f"bounded command accepted {scenario} unexpectedly: {result!r}"
                        )
            finally:
                verifier.subprocess = original_subprocess
                verifier.select = original_select
                verifier.os = original_os
                verifier.time = original_time
            if calls_after_reap:
                raise SystemExit(
                    "bounded command used a numeric PGID after releasing its leader: "
                    f"{scenario}: {calls_after_reap!r}"
                )
            if process.poll_calls:
                raise SystemExit(
                    f"bounded command reaped its leader through poll: {scenario}"
                )
            if process.wait_calls != 1:
                raise SystemExit(
                    "bounded command did not reap its leader exactly once: "
                    f"{scenario}: {process.wait_calls}"
                )
            if signals_before_reap != expected_signals:
                raise SystemExit(
                    "bounded command process-group signal order drifted: "
                    f"{scenario}: {signals_before_reap!r}"
                )
            if not process.stdout.closed or not process.stderr.closed:
                raise SystemExit(
                    f"bounded command leaked a pipe in {scenario} ownership fixture"
                )


def verify_bounded_command_spawn_contract(verifier) -> None:
    original_subprocess = verifier.subprocess
    original_select = verifier.select
    original_os = verifier.os
    arguments = [b"/usr/bin/spawn-contract", b"argument"]
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "HOME": "/nonexistent",
    }
    popen_calls = []

    class FakeStream:
        def __init__(self, descriptor: int):
            self.descriptor = descriptor
            self.closed = False

        def fileno(self):
            return self.descriptor

        def close(self):
            self.closed = True

    class FakeProcess:
        pid = 434343
        _child_created = True

        def __init__(self):
            self.stdout = FakeStream(20)
            self.stderr = FakeStream(21)
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            del timeout
            return self.returncode

    process = FakeProcess()

    class FakePopen:
        def __new__(cls, *args, **kwargs):
            del cls, args, kwargs
            return process

        @staticmethod
        def __init__(instance, actual_arguments, **kwargs):
            del instance
            popen_calls.append((actual_arguments, kwargs))

    class FakeSubprocess:
        def __getattr__(self, name):
            return getattr(original_subprocess, name)

        Popen = FakePopen

    class ReadySelect:
        @staticmethod
        def select(readable, writable, exceptional, timeout):
            del writable, exceptional, timeout
            return list(readable), [], []

    class NoGroupOS:
        def __getattr__(self, name):
            return getattr(original_os, name)

        @staticmethod
        def read(descriptor, amount):
            del descriptor, amount
            return b""

        @staticmethod
        def killpg(pid, signum):
            if pid != process.pid or signum != signal.SIGKILL:
                raise SystemExit("spawn-contract fixture observed an unexpected signal")

        @staticmethod
        def waitid(idtype, process_id, options):
            if (
                idtype != original_os.P_PID
                or process_id != process.pid
                or options
                != original_os.WEXITED | original_os.WNOHANG | original_os.WNOWAIT
            ):
                raise SystemExit("spawn-contract fixture saw a noncanonical waitid call")

            class Result:
                si_pid = process.pid

            return Result()

    verifier.subprocess = FakeSubprocess()
    verifier.select = ReadySelect
    verifier.os = NoGroupOS()
    try:
        result = verifier._bounded_command(
            arguments,
            "spawn contract fixture",
            env=environment,
            timeout=0.5,
            max_stdout=17,
            max_stderr=19,
        )
    finally:
        verifier.subprocess = original_subprocess
        verifier.select = original_select
        verifier.os = original_os
    if result != (0, b"", b""):
        raise SystemExit(f"bounded command changed fake process output: {result!r}")
    if len(popen_calls) != 1 or popen_calls[0][0] is not arguments:
        raise SystemExit(f"bounded command changed Popen argv identity: {popen_calls!r}")
    popen_kwargs = popen_calls[0][1]
    if set(popen_kwargs) != {
        "stdout",
        "stderr",
        "env",
        "start_new_session",
    }:
        raise SystemExit(f"bounded command changed Popen keyword set: {popen_kwargs!r}")
    if (
        popen_kwargs["stdout"] != original_subprocess.PIPE
        or popen_kwargs["stderr"] != original_subprocess.PIPE
        or popen_kwargs["env"] is not environment
        or popen_kwargs["start_new_session"] is not True
    ):
        raise SystemExit(f"bounded command changed Popen contract: {popen_kwargs!r}")
    if not process.stdout.closed or not process.stderr.closed:
        raise SystemExit("bounded command leaked a pipe after normal completion")

    spawn_failure = OSError(errno.EACCES, "injected spawn failure")

    class RaisingPopen:
        def __new__(cls, *args, **kwargs):
            del args, kwargs
            return object.__new__(cls)

        @staticmethod
        def __init__(instance, *args, **kwargs):
            del instance, args, kwargs
            raise spawn_failure

    class RaisingSubprocess:
        def __getattr__(self, name):
            return getattr(original_subprocess, name)

        Popen = RaisingPopen

    verifier.subprocess = RaisingSubprocess()
    try:
        try:
            verifier._bounded_command(
                arguments,
                "spawn sentinel fixture",
                env=environment,
                timeout=0.5,
                max_stdout=17,
                max_stderr=19,
            )
        except OSError as exc:
            if exc is not spawn_failure:
                raise SystemExit("bounded command replaced the Popen sentinel") from exc
        else:
            raise SystemExit("bounded command accepted an injected Popen failure")
    finally:
        verifier.subprocess = original_subprocess


def verify_bounded_command_real_handoff_cancellation(verifier) -> None:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
    }
    sleeping_command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        "import time; time.sleep(30)",
    ]
    exiting_command = [sys.executable, "-I", "-B", "-c", "pass"]
    original_popen = verifier.subprocess.Popen
    original_initializer = verifier._initialize_owned_popen

    def direct_children() -> frozenset[int]:
        raw = pathlib.Path(
            f"/proc/self/task/{os.getpid()}/children"
        ).read_bytes()
        return frozenset(int(field) for field in raw.split())

    def remember_process(process, processes, descriptors) -> None:
        processes.append(process)
        if process.stdout is None or process.stderr is None:
            raise SystemExit("real handoff fixture did not receive both Popen pipes")
        descriptors.extend((process.stdout.fileno(), process.stderr.fileno()))

    def emergency_settle(process) -> None:
        try:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    process.wait(timeout=2)
                except BaseException:
                    pass
        finally:
            for stream in (process.stderr, process.stdout):
                if stream is None:
                    continue
                for _ in range(2):
                    try:
                        if stream.closed:
                            break
                        stream.close()
                    except BaseException:
                        continue

    def require_settled(
        label: str,
        baseline_children: frozenset[int],
        processes: list[subprocess.Popen[bytes]],
        descriptors: list[int],
        owners,
        expected: BaseException,
        observed: BaseException | None,
        *,
        unassigned: bool,
    ) -> None:
        try:
            if observed is not expected:
                raise SystemExit(
                    f"{label} did not preserve exact cancellation: {observed!r}"
                )
            if len(processes) != 1 or len(descriptors) != 2:
                raise SystemExit(
                    f"{label} did not publish one process and two pipes: "
                    f"processes={len(processes)} descriptors={descriptors!r}"
                )
            process = processes[0]
            if len(owners) != 1:
                raise SystemExit(f"{label} did not publish exactly one owner")
            owner = owners[0]
            if unassigned:
                if (
                    owner.recovered_pid != process.pid
                    or type(owner.recovered_returncode) is not int
                    or set(owner.recovered_descriptors) != set(descriptors)
                ):
                    raise SystemExit(
                        f"{label} did not reconcile recovered child/pipe custody"
                    )
            elif type(process.returncode) is not int:
                raise SystemExit(f"{label} did not reconcile the Popen return code")
            try:
                waited, _ = os.waitpid(process.pid, os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                raise SystemExit(
                    f"{label} did not exactly reap its child: waitpid={waited}"
                )
            for descriptor in descriptors:
                try:
                    os.fstat(descriptor)
                except OSError as exc:
                    if exc.errno == errno.EBADF:
                        continue
                    raise
                raise SystemExit(
                    f"{label} left a live Popen pipe descriptor: {descriptor}"
                )
            if direct_children() != baseline_children:
                raise SystemExit(f"{label} changed the direct-child baseline")
            if unassigned:
                process.returncode = owner.recovered_returncode
                for stream in (process.stderr, process.stdout):
                    try:
                        stream.close()
                    except BaseException:
                        pass
        except BaseException:
            for process in processes:
                emergency_settle(process)
            raise

    def run_case(label, installer, command, *, unassigned=False) -> None:
        baseline_children = direct_children()
        processes: list[subprocess.Popen[bytes]] = []
        descriptors: list[int] = []
        owners = []
        expected = KeyboardInterrupt(f"injected {label} cancellation")
        observed: BaseException | None = None
        original_owner_type = verifier._BoundedPopenOwner

        class RecordingOwner(original_owner_type):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                owners.append(self)

        verifier._BoundedPopenOwner = RecordingOwner
        restore = lambda: None
        try:
            restore = installer(expected, processes, descriptors)
            try:
                verifier._bounded_command(
                    command,
                    label,
                    env=environment,
                    timeout=1.0,
                    max_stdout=17,
                    max_stderr=19,
                )
            except BaseException as exc:
                observed = exc
        finally:
            restore()
            verifier._BoundedPopenOwner = original_owner_type
        require_settled(
            label,
            baseline_children,
            processes,
            descriptors,
            owners,
            expected,
            observed,
            unassigned=unassigned,
        )

    def install_function_popen(expected, processes, descriptors):
        def popen_then_cancel(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            remember_process(process, processes, descriptors)
            raise expected

        verifier.subprocess.Popen = popen_then_cancel
        return lambda: setattr(verifier.subprocess, "Popen", original_popen)

    def install_popen_init(expected, processes, descriptors):
        class PopenInitCancellation(original_popen):
            def __init__(self, *args, **kwargs):
                original_popen.__init__(self, *args, **kwargs)
                remember_process(self, processes, descriptors)
                raise expected

        verifier.subprocess.Popen = PopenInitCancellation
        return lambda: setattr(verifier.subprocess, "Popen", original_popen)

    def install_helper_return(expected, processes, descriptors):
        def initialize_then_cancel(owner, args, *, env):
            process = original_initializer(owner, args, env=env)
            remember_process(process, processes, descriptors)
            raise expected

        verifier._initialize_owned_popen = initialize_then_cancel
        return lambda: setattr(
            verifier, "_initialize_owned_popen", original_initializer
        )

    class FaultingStream:
        def __init__(self, inner, boundary, expected, shared):
            self.inner = inner
            self.boundary = boundary
            self.expected = expected
            self.shared = shared

        @property
        def closed(self):
            return self.inner.closed

        def fileno(self):
            descriptor = self.inner.fileno()
            if self.boundary == "fileno" and not self.shared[0]:
                self.shared[0] = True
                raise self.expected
            return descriptor

        def close(self):
            self.inner.close()
            if self.boundary == "close" and not self.shared[0]:
                self.shared[0] = True
                raise self.expected

        def __getattr__(self, name):
            return getattr(self.inner, name)

    def install_stream_boundary(boundary):
        def installer(expected, processes, descriptors):
            shared = [False]

            class StreamCancellationPopen(original_popen):
                def __init__(self, *args, **kwargs):
                    original_popen.__init__(self, *args, **kwargs)
                    remember_process(self, processes, descriptors)
                    self.stdout = FaultingStream(
                        self.stdout, boundary, expected, shared
                    )
                    self.stderr = FaultingStream(
                        self.stderr, boundary, expected, shared
                    )

            verifier.subprocess.Popen = StreamCancellationPopen
            return lambda: setattr(
                verifier.subprocess, "Popen", original_popen
            )

        return installer

    def install_wait(expected, processes, descriptors):
        class WaitCancellationPopen(original_popen):
            injected = False

            def __init__(self, *args, **kwargs):
                original_popen.__init__(self, *args, **kwargs)
                remember_process(self, processes, descriptors)

            def wait(self, *args, **kwargs):
                result = super().wait(*args, **kwargs)
                if not self.injected:
                    self.injected = True
                    raise expected
                return result

        verifier.subprocess.Popen = WaitCancellationPopen
        return lambda: setattr(verifier.subprocess, "Popen", original_popen)

    run_case(
        "Popen applied-before-assignment",
        install_function_popen,
        sleeping_command,
        unassigned=True,
    )
    run_case("Popen init handoff", install_popen_init, sleeping_command)
    run_case("Popen helper return", install_helper_return, sleeping_command)
    run_case(
        "Popen stream fileno handoff",
        install_stream_boundary("fileno"),
        sleeping_command,
    )
    run_case(
        "Popen stream close settlement",
        install_stream_boundary("close"),
        exiting_command,
    )
    run_case("Popen wait settlement", install_wait, exiting_command)


def verify_bounded_command_process_boundary(verifier) -> None:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
    }
    returncode, stdout, stderr = verifier._bounded_command(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 17)",
        ],
        "exact stdout fixture",
        env=environment,
        timeout=0.5,
        max_stdout=17,
        max_stderr=19,
    )
    if (returncode, stdout, stderr) != (0, b"x" * 17, b""):
        raise SystemExit("bounded command changed exact-limit stdout")
    require_rejected(
        verifier,
        lambda: verifier._bounded_command(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 18)",
            ],
            "overflow stdout fixture",
            env=environment,
            timeout=0.5,
            max_stdout=17,
            max_stderr=19,
        ),
        "bounded command stdout overflow",
        "overflow stdout fixture stdout exceeds its size bound",
    )
    returncode, stdout, stderr = verifier._bounded_command(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; sys.stderr.buffer.write(b'e' * 19)",
        ],
        "exact stderr fixture",
        env=environment,
        timeout=0.5,
        max_stdout=17,
        max_stderr=19,
    )
    if (returncode, stdout, stderr) != (0, b"", b"e" * 19):
        raise SystemExit("bounded command changed exact-limit stderr")
    require_rejected(
        verifier,
        lambda: verifier._bounded_command(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys; sys.stderr.buffer.write(b'e' * 20)",
            ],
            "overflow stderr fixture",
            env=environment,
            timeout=0.5,
            max_stdout=17,
            max_stderr=19,
        ),
        "bounded command stderr overflow",
        "overflow stderr fixture stderr exceeds its size bound",
    )
    returncode, stdout, stderr = verifier._bounded_command(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; sys.stdout.buffer.write(b'ok'); "
            "sys.stderr.buffer.write(b'bad\\n'); sys.exit(7)",
        ],
        "exit-seven fixture",
        env=environment,
        timeout=0.5,
        max_stdout=17,
        max_stderr=19,
    )
    if (returncode, stdout, stderr) != (7, b"ok", b"bad\n"):
        raise SystemExit("bounded command changed nonzero command bytes")
    high_volume_size = 1024 * 1024
    high_volume_script = (
        "import os,threading\n"
        "def write(fd,value):\n"
        " chunk=value*4096\n"
        " for _ in range(256): os.write(fd,chunk)\n"
        "threads=(threading.Thread(target=write,args=(1,b'o')),"
        "threading.Thread(target=write,args=(2,b'e')))\n"
        "[thread.start() for thread in threads]\n"
        "[thread.join() for thread in threads]\n"
    )
    returncode, stdout, stderr = verifier._bounded_command(
        [sys.executable, "-I", "-B", "-c", high_volume_script],
        "simultaneous dual-stream fixture",
        env=environment,
        timeout=5.0,
        max_stdout=high_volume_size,
        max_stderr=high_volume_size,
    )
    if (
        returncode != 0
        or stdout != b"o" * high_volume_size
        or stderr != b"e" * high_volume_size
    ):
        raise SystemExit("bounded command changed simultaneous dual-stream bytes")
    missing_executable = "/definitely/not/a/tb321fu-command"
    try:
        verifier._bounded_command(
            [missing_executable],
            "spawn failure fixture",
            env=environment,
            timeout=0.5,
            max_stdout=17,
            max_stderr=19,
        )
    except OSError as exc:
        if (
            not isinstance(exc, FileNotFoundError)
            or exc.errno != errno.ENOENT
            or exc.filename != missing_executable
        ):
            raise SystemExit(
                f"bounded command changed spawn-failure evidence: {exc!r}"
            ) from exc
    else:
        raise SystemExit("bounded command accepted a nonexistent executable")
    started = time.monotonic()
    try:
        verifier._bounded_command(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
            "silent timeout fixture",
            env=environment,
            timeout=0.5,
            max_stdout=17,
            max_stderr=19,
        )
    except subprocess.TimeoutExpired:
        pass
    else:
        raise SystemExit("bounded command accepted a silent hang")
    if time.monotonic() - started > 3:
        raise SystemExit("bounded command timeout exceeded its outer watchdog")
    started = time.monotonic()
    require_rejected(
        verifier,
        lambda: verifier._bounded_command(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import os\nwhile True:\n os.write(2, b'flood' * 1024)",
            ],
            "stderr flood fixture",
            env=environment,
            timeout=0.5,
            max_stdout=17,
            max_stderr=19,
        ),
        "bounded command stderr flood",
        "stderr flood fixture stderr exceeds its size bound",
    )
    if time.monotonic() - started > 3:
        raise SystemExit("bounded stderr flood exceeded its outer watchdog")

    def wait_pid_file(path: pathlib.Path, expected: int) -> tuple[int, ...]:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                values = tuple(int(item) for item in path.read_text().split())
            except (FileNotFoundError, ValueError):
                time.sleep(0.01)
                continue
            if len(values) == expected:
                return values
            time.sleep(0.01)
        raise SystemExit(f"bounded command fixture did not publish PIDs: {path}")

    def require_pid_gone(pid: int, label: str) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        raise SystemExit(f"bounded command left {label} PID alive: {pid}")

    original_term_grace = verifier.COMMAND_TERM_GRACE_SECONDS
    original_kill_reap = verifier.COMMAND_KILL_REAP_SECONDS
    verifier.COMMAND_TERM_GRACE_SECONDS = 0.1
    verifier.COMMAND_KILL_REAP_SECONDS = 0.5
    try:
        with tempfile.TemporaryDirectory(
            prefix="tb321fu-haptics-command-"
        ) as temporary:
            root = pathlib.Path(temporary)
            inherited_pid_file = root / "inherited-pipes.pid"
            inherited_script = (
                "import os,pathlib,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " time.sleep(30)\n"
                " os._exit(0)\n"
                f"pathlib.Path({str(inherited_pid_file)!r}).write_text(str(child))\n"
                "os._exit(0)\n"
            )
            try:
                verifier._bounded_command(
                    [sys.executable, "-I", "-B", "-c", inherited_script],
                    "inherited-pipes fixture",
                    env=environment,
                    timeout=0.5,
                    max_stdout=17,
                    max_stderr=19,
                )
            except subprocess.TimeoutExpired:
                pass
            else:
                raise SystemExit("pipe-inheriting descendant was accepted")
            inherited_pid = wait_pid_file(inherited_pid_file, 1)[0]
            require_pid_gone(inherited_pid, "pipe-inheriting descendant")

            cooperative_pid_file = root / "cooperative.pid"
            cooperative_marker = root / "cooperative.term"
            cooperative_script = (
                "import os,pathlib,signal,time\n"
                f"pid=pathlib.Path({str(cooperative_pid_file)!r})\n"
                f"marker=pathlib.Path({str(cooperative_marker)!r})\n"
                "pid.write_text(str(os.getpid()))\n"
                "def stop(signum, frame):\n"
                " marker.write_text('TERM')\n"
                " raise SystemExit(0)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                "while True:\n"
                " time.sleep(1)\n"
            )
            try:
                verifier._bounded_command(
                    [sys.executable, "-I", "-B", "-c", cooperative_script],
                    "cooperative TERM fixture",
                    env=environment,
                    timeout=0.5,
                    max_stdout=17,
                    max_stderr=19,
                )
            except subprocess.TimeoutExpired:
                pass
            else:
                raise SystemExit("cooperative TERM timeout was accepted")
            cooperative_pid = wait_pid_file(cooperative_pid_file, 1)[0]
            if cooperative_marker.read_text() != "TERM":
                raise SystemExit("cooperative process did not receive TERM")
            require_pid_gone(cooperative_pid, "cooperative parent")

            stubborn_pid_file = root / "stubborn.pids"
            stubborn_script = (
                "import os,pathlib,signal,time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " while True:\n"
                "  time.sleep(1)\n"
                f"pathlib.Path({str(stubborn_pid_file)!r}).write_text("
                "f'{os.getpid()} {child}')\n"
                "while True:\n"
                " time.sleep(1)\n"
            )
            try:
                verifier._bounded_command(
                    [sys.executable, "-I", "-B", "-c", stubborn_script],
                    "stubborn TERM fixture",
                    env=environment,
                    timeout=0.5,
                    max_stdout=17,
                    max_stderr=19,
                )
            except subprocess.TimeoutExpired:
                pass
            else:
                raise SystemExit("stubborn TERM timeout was accepted")
            stubborn_pids = wait_pid_file(stubborn_pid_file, 2)
            for stubborn_pid in stubborn_pids:
                require_pid_gone(stubborn_pid, "stubborn process")

            select_failure_pid_file = root / "select-failure.pids"
            select_failure_script = (
                "import os,pathlib,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " while True:\n"
                "  time.sleep(1)\n"
                f"pathlib.Path({str(select_failure_pid_file)!r}).write_text("
                "f'{os.getpid()} {child}')\n"
                "while True:\n"
                " time.sleep(1)\n"
            )
            select_failure = OSError("injected select failure")

            class FailingSelect:
                @staticmethod
                def select(readable, writable, exceptional, timeout):
                    del readable, writable, exceptional, timeout
                    wait_pid_file(select_failure_pid_file, 2)
                    raise select_failure

            original_select = verifier.select
            verifier.select = FailingSelect
            try:
                try:
                    verifier._bounded_command(
                        [sys.executable, "-I", "-B", "-c", select_failure_script],
                        "select failure fixture",
                        env=environment,
                        timeout=0.5,
                        max_stdout=17,
                        max_stderr=19,
                    )
                except OSError as exc:
                    if exc is not select_failure:
                        raise SystemExit(
                            "bounded command replaced the injected select failure"
                        ) from exc
                else:
                    raise SystemExit("bounded command accepted an injected select failure")
            finally:
                verifier.select = original_select
            for select_failure_pid in wait_pid_file(select_failure_pid_file, 2):
                require_pid_gone(select_failure_pid, "select-failure process")

            read_failure_pid_file = root / "read-failure.pids"
            read_failure_script = (
                "import os,pathlib,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " while True:\n"
                "  time.sleep(1)\n"
                f"pathlib.Path({str(read_failure_pid_file)!r}).write_text("
                "f'{os.getpid()} {child}')\n"
                "os.write(1, b'x')\n"
                "while True:\n"
                " time.sleep(1)\n"
            )
            read_failure = OSError("injected read failure")
            original_os = verifier.os
            read_amounts: list[int] = []

            class FailingReadOS:
                def __getattr__(self, name):
                    return getattr(original_os, name)

                def read(self, descriptor, amount):
                    del descriptor
                    read_amounts.append(amount)
                    if amount != 18:
                        raise SystemExit(
                            f"bounded command read past remaining+1: {amount}"
                        )
                    wait_pid_file(read_failure_pid_file, 2)
                    raise read_failure

            verifier.os = FailingReadOS()
            try:
                try:
                    verifier._bounded_command(
                        [sys.executable, "-I", "-B", "-c", read_failure_script],
                        "read failure fixture",
                        env=environment,
                        timeout=0.5,
                        max_stdout=17,
                        max_stderr=19,
                    )
                except OSError as exc:
                    if exc is not read_failure:
                        raise SystemExit(
                            "bounded command replaced the injected read failure"
                        ) from exc
                else:
                    raise SystemExit("bounded command accepted an injected read failure")
            finally:
                verifier.os = original_os
            for read_failure_pid in wait_pid_file(read_failure_pid_file, 2):
                require_pid_gone(read_failure_pid, "read-failure process")
            if read_amounts != [18]:
                raise SystemExit(f"bounded command read amount drifted: {read_amounts!r}")

            background_pid_file = root / "background.pid"
            background_script = (
                "import os,pathlib,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " null=os.open('/dev/null', os.O_RDWR)\n"
                " os.dup2(null, 1)\n"
                " os.dup2(null, 2)\n"
                " time.sleep(30)\n"
                " os._exit(0)\n"
                f"pathlib.Path({str(background_pid_file)!r}).write_text(str(child))\n"
            )
            returncode, stdout, stderr = verifier._bounded_command(
                [sys.executable, "-I", "-B", "-c", background_script],
                "successful background fixture",
                env=environment,
                timeout=0.5,
                max_stdout=17,
                max_stderr=19,
            )
            if (returncode, stdout, stderr) != (0, b"", b""):
                raise SystemExit("successful background parent changed command bytes")
            background_pid = wait_pid_file(background_pid_file, 1)[0]
            require_pid_gone(background_pid, "successful background descendant")
    finally:
        verifier.COMMAND_TERM_GRACE_SECONDS = original_term_grace
        verifier.COMMAND_KILL_REAP_SECONDS = original_kill_reap


def verify_command_output_routing(verifier) -> None:
    arguments = [b"/usr/bin/printf", b"legacy-output"]
    expected_output = b"bounded\0output\n"
    calls = []
    original_bounded_command = verifier._bounded_command

    def recording_bounded_command(
        actual_arguments,
        label,
        *,
        env,
        timeout,
        max_stdout,
        max_stderr,
    ):
        calls.append(
            (
                actual_arguments,
                label,
                env,
                timeout,
                max_stdout,
                max_stderr,
            )
        )
        return 0, expected_output, b""

    verifier._bounded_command = recording_bounded_command
    try:
        actual_output = verifier.command_output(arguments, "command routing fixture")
    finally:
        verifier._bounded_command = original_bounded_command
    expected_environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": os.environ.get("HOME", "/nonexistent"),
    }
    expected_calls = [
        (
            arguments,
            "command routing fixture",
            expected_environment,
            verifier.COMMAND_TIMEOUT_SECONDS,
            verifier.MAX_COMMAND_STDOUT_BYTES,
            verifier.MAX_COMMAND_STDERR_BYTES,
        )
    ]
    if actual_output != expected_output or calls != expected_calls:
        raise SystemExit(
            "command_output did not preserve the bounded runner contract: "
            f"output={actual_output!r} calls={calls!r}"
        )


def verify_installed_record_routing(verifier) -> None:
    calls = []
    original_bounded_command = verifier._bounded_command
    expected_stdout = b"apt\tamd64\t2.8.3\tinstall ok installed\n"

    def recording_bounded_command(
        arguments,
        label,
        *,
        env,
        timeout,
        max_stdout,
        max_stderr,
    ):
        calls.append(
            (
                arguments,
                label,
                env,
                timeout,
                max_stdout,
                max_stderr,
            )
        )
        return 0, expected_stdout, b""

    verifier._bounded_command = recording_bounded_command
    try:
        actual = verifier.installed_record("apt", "amd64")
    finally:
        verifier._bounded_command = original_bounded_command
    expected_arguments = [
        "/usr/bin/dpkg-query",
        "-W",
        "-f=${binary:Package}\t${Architecture}\t${Version}\t${Status}\n",
        "apt",
    ]
    expected_environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", "/nonexistent"),
    }
    expected_calls = [
        (
            expected_arguments,
            "installed package query: apt",
            expected_environment,
            verifier.COMMAND_TIMEOUT_SECONDS,
            verifier.MAX_COMMAND_STDOUT_BYTES,
            verifier.MAX_COMMAND_STDERR_BYTES,
        )
    ]
    if actual != ("2.8.3", "install ok installed") or calls != expected_calls:
        raise SystemExit(
            "installed_record did not preserve the bounded runner contract: "
            f"actual={actual!r} calls={calls!r}"
        )

    for label, response, expected_error in (
        (
            "noninstalled package query",
            (1, b"", b"not installed\n"),
            "required package is not installed: apt",
        ),
        (
            "empty installed package query",
            (0, b"", b""),
            "installed package identity is ambiguous: apt",
        ),
        (
            "duplicate installed package identity",
            (0, expected_stdout + expected_stdout, b""),
            "installed package identity is ambiguous: apt",
        ),
        (
            "installed package query missing terminal LF",
            (0, expected_stdout[:-1], b""),
            "installed package query: apt output has invalid line framing",
        ),
        (
            "installed package query non-ASCII byte",
            (0, expected_stdout.replace(b"2.8.3", b"2.8.3\xff"), b""),
            "installed package query: apt output is not ASCII",
        ),
        (
            "installed package query malformed fields",
            (0, b"apt\tamd64\t2.8.3\n", b""),
            "installed package query: apt emitted an invalid record",
        ),
        (
            "installed package query unsafe metadata",
            (0, expected_stdout.replace(b"2.8.3", b"bad version"), b""),
            "installed package query: apt emitted unsafe metadata",
        ),
    ):
        verifier._bounded_command = lambda *args, response=response, **kwargs: response
        try:
            require_rejected(
                verifier,
                lambda: verifier.installed_record("apt", "amd64"),
                label,
                expected_error,
            )
        finally:
            verifier._bounded_command = original_bounded_command

    verifier._bounded_command = lambda *args, **kwargs: (
        0,
        expected_stdout.replace(b"apt\t", b"apt:amd64\t"),
        b"",
    )
    try:
        if verifier.installed_record("apt", "amd64") != (
            "2.8.3",
            "install ok installed",
        ):
            raise SystemExit("installed_record rejected a legal multiarch binary name")
    finally:
        verifier._bounded_command = original_bounded_command


def verify_installed_routing(verifier, policy) -> None:
    calls = []
    original_bounded_command = verifier._bounded_command
    original_subprocess = verifier.subprocess
    package_by_name = {
        name: (architecture, record)
        for (name, architecture), record in policy.packages.items()
    }

    def recording_bounded_command(
        arguments,
        label,
        *,
        env,
        timeout,
        max_stdout,
        max_stderr,
    ):
        calls.append(
            (
                arguments,
                label,
                env,
                timeout,
                max_stdout,
                max_stderr,
            )
        )
        if arguments == ["/usr/bin/dpkg", "--print-architecture"]:
            return 0, b"amd64\n", b""
        if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            return 0, b"", b""
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            name = arguments[-1]
            architecture, record = package_by_name[name]
            return (
                0,
                (
                    f"{name}\t{architecture}\t{record.version}\t"
                    "install ok installed\n"
                ).encode("ascii"),
                b"",
            )
        raise SystemExit(f"unexpected installed verification command: {arguments!r}")

    class LegacyProbeSubprocess:
        def __getattr__(self, name):
            return getattr(original_subprocess, name)

        @staticmethod
        def run(arguments, **kwargs):
            del kwargs
            if arguments == ["/usr/bin/dpkg", "--print-architecture"]:
                return original_subprocess.CompletedProcess(
                    arguments, 0, stdout="amd64\n"
                )
            if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
                return original_subprocess.CompletedProcess(arguments, 0, stdout="")
            raise SystemExit(f"unexpected legacy subprocess command: {arguments!r}")

    verifier._bounded_command = recording_bounded_command
    verifier.subprocess = LegacyProbeSubprocess()
    try:
        verifier.verify_installed(policy)
    finally:
        verifier._bounded_command = original_bounded_command
        verifier.subprocess = original_subprocess
    expected_environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", "/nonexistent"),
    }
    expected_commands = [
        (["/usr/bin/dpkg", "--print-architecture"], "native package architecture"),
        (
            ["/usr/bin/dpkg", "--print-foreign-architectures"],
            "foreign package architectures",
        ),
    ] + [
        (
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f=${binary:Package}\t${Architecture}\t${Version}\t${Status}\n",
                name,
            ],
            f"installed package query: {name}",
        )
        for name in package_by_name
    ]
    expected_calls = [
        (
            arguments,
            label,
            expected_environment,
            verifier.COMMAND_TIMEOUT_SECONDS,
            verifier.MAX_COMMAND_STDOUT_BYTES,
            verifier.MAX_COMMAND_STDERR_BYTES,
        )
        for arguments, label in expected_commands
    ]
    if calls != expected_calls:
        raise SystemExit(f"verify_installed bounded command routing drifted: {calls!r}")

    architecture_arguments = ["/usr/bin/dpkg", "--print-architecture"]
    foreign_arguments = ["/usr/bin/dpkg", "--print-foreign-architectures"]
    for label, responses, expected_command, expected_returncode in (
        (
            "native architecture command failure",
            [(7, b"native partial", b"native failure")],
            architecture_arguments,
            7,
        ),
        (
            "foreign architecture command failure",
            [
                (0, b"amd64\n", b""),
                (8, b"foreign partial", b"foreign failure"),
            ],
            foreign_arguments,
            8,
        ),
    ):
        failure_calls = 0

        def failing_bounded_command(*args, **kwargs):
            nonlocal failure_calls
            del args, kwargs
            if failure_calls >= len(responses):
                raise SystemExit(f"{label} issued an unexpected command")
            response = responses[failure_calls]
            failure_calls += 1
            return response

        verifier._bounded_command = failing_bounded_command
        try:
            try:
                verifier.verify_installed(policy)
            except subprocess.CalledProcessError as exc:
                if (
                    exc.returncode != expected_returncode
                    or exc.cmd != expected_command
                    or exc.output != responses[-1][1]
                    or exc.stderr != responses[-1][2]
                ):
                    raise SystemExit(
                        f"{label} changed CalledProcessError evidence: {exc!r}"
                    ) from exc
            else:
                raise SystemExit(f"{label} did not preserve CalledProcessError")
        finally:
            verifier._bounded_command = original_bounded_command

    direct_output_cases = (
        (
            "native architecture missing terminal LF",
            [(0, b"amd64", b"")],
            "native package architecture output has invalid line framing",
        ),
        (
            "native architecture non-ASCII byte",
            [(0, b"amd64\xff\n", b"")],
            "native package architecture output is not ASCII",
        ),
        (
            "native architecture multiple records",
            [(0, b"amd64\namd64\n", b"")],
            "native package architecture emitted an invalid record",
        ),
        (
            "native architecture unsafe metadata",
            [(0, b"_amd64\n", b"")],
            "native package architecture emitted unsafe metadata",
        ),
        (
            "unsupported native architecture",
            [(0, b"arm64\n", b"")],
            "unsupported package architecture: arm64",
        ),
        (
            "foreign architecture missing terminal LF",
            [(0, b"amd64\n", b""), (0, b"arm64", b"")],
            "foreign package architectures output has invalid line framing",
        ),
        (
            "foreign architecture non-ASCII byte",
            [(0, b"amd64\n", b""), (0, b"arm64\xff\n", b"")],
            "foreign package architectures output is not ASCII",
        ),
        (
            "duplicate foreign architecture",
            [(0, b"amd64\n", b""), (0, b"arm64\narm64\n", b"")],
            "foreign package architectures emitted unsafe metadata",
        ),
        (
            "present foreign architecture",
            [(0, b"amd64\n", b""), (0, b"arm64\n", b"")],
            "foreign package architectures are not allowed: ['arm64']",
        ),
    )
    for label, responses, expected_error in direct_output_cases:
        response_index = 0

        def output_bounded_command(*args, **kwargs):
            nonlocal response_index
            del args, kwargs
            if response_index >= len(responses):
                raise SystemExit(f"{label} crossed its direct-output boundary")
            response = responses[response_index]
            response_index += 1
            return response

        verifier._bounded_command = output_bounded_command
        try:
            require_rejected(
                verifier,
                lambda: verifier.verify_installed(policy),
                label,
                expected_error,
            )
        finally:
            verifier._bounded_command = original_bounded_command

    original_time = verifier.time

    class InstalledClock:
        def __init__(self):
            self.now = 0.0

        def monotonic(self):
            return self.now

        def __getattr__(self, name):
            return getattr(original_time, name)

    deadline_clock = InstalledClock()
    deadline_calls: list[tuple[list[str], float]] = []

    def deadline_bounded_command(arguments, label, **kwargs):
        del label
        deadline_calls.append((arguments, kwargs["timeout"]))
        if len(deadline_calls) == 1:
            deadline_clock.now = 100.0
            return 0, b"amd64\n", b""
        if len(deadline_calls) == 2:
            deadline_clock.now = 121.0
            return 0, b"", b""
        raise SystemExit("expired installed verification started a package query")

    verifier.time = deadline_clock
    verifier._bounded_command = deadline_bounded_command
    try:
        require_rejected(
            verifier,
            lambda: verifier.verify_installed(policy),
            "installed verification command deadline",
            "installed package verification exceeds its deadline",
        )
    finally:
        verifier.time = original_time
        verifier._bounded_command = original_bounded_command
    if [timeout for _, timeout in deadline_calls] != [
        verifier.COMMAND_TIMEOUT_SECONDS,
        20.0,
    ]:
        raise SystemExit(f"installed verification deadline drifted: {deadline_calls!r}")

    final_clock = InstalledClock()
    final_call_count = 0

    def final_deadline_bounded_command(arguments, label, **kwargs):
        nonlocal final_call_count
        del label, kwargs
        final_call_count += 1
        if arguments == architecture_arguments:
            output = b"amd64\n"
        elif arguments == foreign_arguments:
            output = b""
        else:
            name = arguments[-1]
            architecture, record = package_by_name[name]
            output = (
                f"{name}\t{architecture}\t{record.version}\tinstall ok installed\n"
            ).encode("ascii")
        if final_call_count == len(policy.packages) + 2:
            final_clock.now = verifier.VERIFY_INSTALLED_TIMEOUT_SECONDS + 1
        return 0, output, b""

    verifier.time = final_clock
    verifier._bounded_command = final_deadline_bounded_command
    try:
        require_rejected(
            verifier,
            lambda: verifier.verify_installed(policy),
            "installed verification final deadline",
            "installed package verification exceeds its deadline",
        )
    finally:
        verifier.time = original_time
        verifier._bounded_command = original_bounded_command


def verify_bootstrap_deadline(verifier, policy) -> None:
    bootstrap_packages = {}
    for identity in tuple(policy.packages)[:2]:
        record = policy.packages[identity]
        bootstrap_packages[identity] = verifier.PackageRecord(
            record.version,
            "bootstrap",
            record.source,
            record.url,
            record.digest,
        )
    bootstrap_policy = verifier.LockPolicy(
        policy.snapshots,
        bootstrap_packages,
        {},
    )
    original_time = verifier.time
    original_bounded_command = verifier._bounded_command

    class BootstrapClock:
        def __init__(self):
            self.now = 0.0

        def monotonic(self):
            return self.now

        def __getattr__(self, name):
            return getattr(original_time, name)

    clock = BootstrapClock()
    calls: list[tuple[list[str], float]] = []

    def recording_bounded_command(arguments, label, **kwargs):
        del label
        calls.append((arguments, kwargs["timeout"]))
        name = arguments[-1]
        (identity, record) = next(
            (identity, record)
            for identity, record in bootstrap_packages.items()
            if identity[0] == name
        )
        if len(calls) == 1:
            clock.now = 45.0
        return (
            0,
            (
                f"{name}\t{identity[1]}\t{record.version}\tinstall ok installed\n"
            ).encode("ascii"),
            b"",
        )

    verifier.time = clock
    verifier._bounded_command = recording_bounded_command
    try:
        verifier.verify_bootstrap(bootstrap_policy)
    finally:
        verifier.time = original_time
        verifier._bounded_command = original_bounded_command
    if [timeout for _, timeout in calls] != [
        verifier.COMMAND_TIMEOUT_SECONDS,
        15.0,
    ]:
        raise SystemExit(f"bootstrap verification deadline drifted: {calls!r}")

    final_clock = BootstrapClock()
    final_calls = 0

    def final_deadline_bounded_command(arguments, label, **kwargs):
        nonlocal final_calls
        del label, kwargs
        final_calls += 1
        name = arguments[-1]
        (identity, record) = next(
            (identity, record)
            for identity, record in bootstrap_packages.items()
            if identity[0] == name
        )
        if final_calls == len(bootstrap_packages):
            final_clock.now = verifier.VERIFY_BOOTSTRAP_TIMEOUT_SECONDS + 1
        return (
            0,
            (
                f"{name}\t{identity[1]}\t{record.version}\tinstall ok installed\n"
            ).encode("ascii"),
            b"",
        )

    verifier.time = final_clock
    verifier._bounded_command = final_deadline_bounded_command
    try:
        require_rejected(
            verifier,
            lambda: verifier.verify_bootstrap(bootstrap_policy),
            "bootstrap verification final deadline",
            "bootstrap package verification exceeds its deadline",
        )
    finally:
        verifier.time = original_time
        verifier._bounded_command = original_bounded_command


def verify_capture_machine_format_boundaries(verifier) -> None:
    original_command_output = verifier.command_output

    def capture_with(
        selection_output: bytes,
        foreign_output: bytes,
    ):
        def fixture_command_output(
            arguments: list[str | bytes],
            label: str,
            *,
            timeout: float | None = None,
        ) -> bytes:
            del label, timeout
            if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
                return b""
            if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
                return selection_output
            if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
                return foreign_output
            if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
                return b""
            raise SystemExit(f"unexpected machine-format capture command: {arguments!r}")

        verifier.command_output = fixture_command_output
        try:
            return verifier.capture_system_state()
        finally:
            verifier.command_output = original_command_output

    exact_state = capture_with(b"apt" + b"\t" * 6 + b"install\n", b"arm64\n")
    if exact_state.selections != {"apt": "install"}:
        raise SystemExit("exact dpkg selection padding was not preserved")
    if exact_state.foreign_architectures != ("arm64",):
        raise SystemExit("exact foreign architecture record was not preserved")
    for name, tab_count in (
        (b"a", 6),
        (b"a" * 7, 6),
        (b"a" * 8, 5),
        (b"a" * 47, 1),
        (b"a" * 48, 1),
        (b"a" * 80, 1),
    ):
        boundary_state = capture_with(
            name + b"\t" * tab_count + b"hold\n",
            b"",
        )
        if boundary_state.selections != {name.decode("ascii"): "hold"}:
            raise SystemExit(
                f"dpkg selection padding boundary changed: {len(name)} bytes"
            )

    for label, separator in (
        ("SP", b" "),
        ("CR", b"\r"),
        ("VT", b"\v"),
        ("FF", b"\f"),
        ("FS", b"\x1c"),
        ("GS", b"\x1d"),
        ("RS", b"\x1e"),
    ):
        require_rejected(
            verifier,
            lambda separator=separator: capture_with(
                b"apt" + separator + b"install\n",
                b"",
            ),
            f"dpkg selection {label} separator",
            "dpkg selection capture emitted an invalid record",
            exact=True,
        )
    require_rejected(
        verifier,
        lambda: capture_with(b"apt\tinstall\n", b""),
        "dpkg selection wrong tab padding",
        "dpkg selection capture emitted an invalid record",
        exact=True,
    )
    require_rejected(
        verifier,
        lambda: capture_with(b"apt" + b"\t" * 6 + b"install\t\n", b""),
        "dpkg selection trailing tab",
        "dpkg selection capture emitted an invalid record",
        exact=True,
    )
    require_rejected(
        verifier,
        lambda: capture_with(b"apt" + b"\t" * 6 + b"install \n", b""),
        "dpkg selection trailing space",
        "dpkg selection capture emitted unsafe metadata",
        exact=True,
    )
    for label, foreign_output in (
        ("empty foreign architecture record", b"\n"),
        ("trailing empty foreign architecture record", b"arm64\n\n"),
    ):
        require_rejected(
            verifier,
            lambda foreign_output=foreign_output: capture_with(b"", foreign_output),
            label,
            "foreign-architecture capture emitted unsafe metadata",
            exact=True,
        )


def verify_alternative_canonical_sorting(verifier) -> None:
    unsorted_query = b"""Name: editor
Link: /usr/bin/editor
Slaves:
 z /master/z
 a /master/a
Status: manual
Best: /candidate/a
Value: /candidate/a

Alternative: /candidate/z
Priority: 5
Slaves:
 z /candidate/z/z
 a /candidate/z/a

Alternative: /candidate/a
Priority: 10
Slaves:
 z /candidate/a/z
 a /candidate/a/a
"""
    expected_v1 = b"""schema\ttb321fu.alternative-query/v1
name\teditor
link\t/usr/bin/editor
status\tmanual
best\t/candidate/a
value\t/candidate/a
master-slave\ta\t/master/a
master-slave\tz\t/master/z
candidate\t/candidate/a\t10
candidate-slave\t/candidate/a\ta\t/candidate/a/a
candidate-slave\t/candidate/a\tz\t/candidate/a/z
candidate\t/candidate/z\t5
candidate-slave\t/candidate/z\ta\t/candidate/z/a
candidate-slave\t/candidate/z\tz\t/candidate/z/z
"""
    safe_state = verifier.parse_alternative_query_bytes(unsorted_query, b"editor")
    if safe_state.query_sha256 != hashlib.sha256(expected_v1).hexdigest():
        raise SystemExit("unsorted alternative query changed canonical v1 ordering")

    unsafe_link = b"/usr/bin/edi\xfftor"
    unsafe_query = unsorted_query.replace(b"/usr/bin/editor", unsafe_link, 1)
    expected_v2_lines = [
        b"schema\ttb321fu.alternative-query/v2",
        b"name-hex\t" + b"editor".hex().encode("ascii"),
        b"link-hex\t" + unsafe_link.hex().encode("ascii"),
        b"status\tmanual",
        b"best-hex\t" + b"/candidate/a".hex().encode("ascii"),
        b"value-hex\t" + b"/candidate/a".hex().encode("ascii"),
        b"master-slave-hex\t"
        + b"a".hex().encode("ascii")
        + b"\t"
        + b"/master/a".hex().encode("ascii"),
        b"master-slave-hex\t"
        + b"z".hex().encode("ascii")
        + b"\t"
        + b"/master/z".hex().encode("ascii"),
        b"candidate-hex\t" + b"/candidate/a".hex().encode("ascii") + b"\t10",
        b"candidate-slave-hex\t"
        + b"a".hex().encode("ascii")
        + b"\t"
        + b"/candidate/a/a".hex().encode("ascii"),
        b"candidate-slave-hex\t"
        + b"z".hex().encode("ascii")
        + b"\t"
        + b"/candidate/a/z".hex().encode("ascii"),
        b"candidate-hex\t" + b"/candidate/z".hex().encode("ascii") + b"\t5",
        b"candidate-slave-hex\t"
        + b"a".hex().encode("ascii")
        + b"\t"
        + b"/candidate/z/a".hex().encode("ascii"),
        b"candidate-slave-hex\t"
        + b"z".hex().encode("ascii")
        + b"\t"
        + b"/candidate/z/z".hex().encode("ascii"),
    ]
    expected_v2 = b"\n".join(expected_v2_lines) + b"\n"
    unsafe_state = verifier.parse_alternative_query_bytes(unsafe_query, b"editor")
    if unsafe_state.query_sha256 != hashlib.sha256(expected_v2).hexdigest():
        raise SystemExit("unsorted alternative query changed canonical v2 ordering")


def verify_capture_fanout_limit(verifier) -> None:
    names = tuple(
        f"a{index:04x}".encode("ascii")
        for index in range(verifier.MAX_ALTERNATIVE_GROUPS + 1)
    )
    selection_output = b"".join(
        alternative_selection_record(name, b"auto", None) for name in names
    )
    calls: list[list[str | bytes]] = []
    original_command_output = verifier.command_output

    def fanout_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del label, timeout
        calls.append(arguments)
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            return b""
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return selection_output
        raise SystemExit(
            "capture queried an alternative before enforcing the fan-out limit: "
            f"{arguments!r}"
        )

    verifier.command_output = fanout_command_output
    try:
        require_rejected(
            verifier,
            verifier.capture_system_state,
            "4097 alternative groups",
            "alternative-state capture exceeds its group bound",
        )
    finally:
        verifier.command_output = original_command_output
    if any(
        arguments[:2] == [b"/usr/bin/update-alternatives", b"--query"]
        for arguments in calls
    ):
        raise SystemExit("capture queried an alternative after fan-out rejection")

    accepted_names = names[: verifier.MAX_ALTERNATIVE_GROUPS]
    accepted_selection_output = b"".join(
        alternative_selection_record(name, b"auto", None)
        for name in accepted_names
    )
    accepted_calls: list[tuple[list[str | bytes], float | None]] = []

    def accepted_fanout_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del label
        accepted_calls.append((arguments, timeout))
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            return b""
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return accepted_selection_output
        if arguments[:2] == [
            b"/usr/bin/update-alternatives",
            b"--query",
        ] and len(arguments) == 3:
            name = arguments[2]
            assert isinstance(name, bytes)
            return (
                b"Name: "
                + name
                + b"\nLink: /usr/bin/"
                + name
                + b"\nStatus: auto\nValue: none\n"
            )
        raise SystemExit(f"unexpected 4096-group capture command: {arguments!r}")

    verifier.command_output = accepted_fanout_command_output
    try:
        accepted_state = verifier.capture_system_state()
    finally:
        verifier.command_output = original_command_output
    if len(accepted_state.alternatives) != verifier.MAX_ALTERNATIVE_GROUPS:
        raise SystemExit("capture did not accept exactly 4096 alternative groups")
    query_calls = [
        arguments
        for arguments, _ in accepted_calls
        if arguments[:2] == [b"/usr/bin/update-alternatives", b"--query"]
    ]
    if len(query_calls) != verifier.MAX_ALTERNATIVE_GROUPS * 2:
        raise SystemExit(
            "4096-group capture issued the wrong number of query/recapture commands"
        )
    if any(
        timeout != verifier.COMMAND_TIMEOUT_SECONDS
        for _, timeout in accepted_calls
    ):
        raise SystemExit("4096-group capture command timeout drifted")


def verify_capture_deadline(verifier) -> None:
    original_time = verifier.time
    original_command_output = verifier.command_output

    class MutableClock:
        def __init__(self):
            self.now = 0.0

        def monotonic(self):
            return self.now

        def __getattr__(self, name):
            return getattr(original_time, name)

    outer_clock = MutableClock()
    outer_clock.now = 100.0
    outer_calls: list[float | None] = []

    def outer_deadline_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del arguments, label
        outer_calls.append(timeout)
        outer_clock.now = 116.0
        return b""

    verifier.time = outer_clock
    verifier.command_output = outer_deadline_command_output
    try:
        require_rejected(
            verifier,
            lambda: verifier.capture_system_state(deadline=115.0),
            "capture outer deadline",
            "system-state capture exceeds its deadline",
        )
    finally:
        verifier.time = original_time
        verifier.command_output = original_command_output
    if outer_calls != [15.0]:
        raise SystemExit(
            f"capture did not consume the outer deadline: {outer_calls!r}"
        )

    clock = MutableClock()
    partial_calls: list[tuple[list[str | bytes], float | None]] = []

    def partial_deadline_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del label
        partial_calls.append((arguments, timeout))
        if len(partial_calls) == 1:
            clock.now = 100.0
            return b""
        if len(partial_calls) == 2:
            clock.now = 121.0
            return b""
        raise SystemExit("expired capture started a third command")

    verifier.time = clock
    verifier.command_output = partial_deadline_command_output
    try:
        require_rejected(
            verifier,
            verifier.capture_system_state,
            "capture-wide command deadline",
            "system-state capture exceeds its deadline",
        )
    finally:
        verifier.time = original_time
        verifier.command_output = original_command_output
    if [timeout for _, timeout in partial_calls] != [
        verifier.COMMAND_TIMEOUT_SECONDS,
        20.0,
    ]:
        raise SystemExit(f"capture did not pass its remaining deadline: {partial_calls!r}")

    final_clock = MutableClock()
    final_calls: list[list[str | bytes]] = []

    def final_deadline_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del label, timeout
        final_calls.append(arguments)
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            output = b""
        elif arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
            output = b""
        elif arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            output = b""
        elif arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            output = alternative_selection_record(b"editor", b"auto", None)
        elif arguments == [
            b"/usr/bin/update-alternatives",
            b"--query",
            b"editor",
        ]:
            output = ZERO_CANDIDATE_QUERY
        else:
            raise SystemExit(f"unexpected final-deadline command: {arguments!r}")
        if len(final_calls) == 7:
            final_clock.now = 121.0
        return output

    verifier.time = final_clock
    verifier.command_output = final_deadline_command_output
    try:
        require_rejected(
            verifier,
            verifier.capture_system_state,
            "capture final serialization deadline",
            "system-state capture exceeds its deadline",
        )
    finally:
        verifier.time = original_time
        verifier.command_output = original_command_output
    if len(final_calls) != 7:
        raise SystemExit("final capture deadline did not run the exact seven commands")

    valid_package_record = b"apt\tamd64\t1\tinstall ok installed\n"
    for label, hostile_output, expected_error in (
        (
            "package capture missing terminal LF",
            valid_package_record[:-1],
            "dpkg package-state capture output has invalid line framing",
        ),
        (
            "package capture non-ASCII byte",
            valid_package_record.replace(b"\t1\t", b"\t1\xff\t"),
            "dpkg package-state capture output is not ASCII",
        ),
        (
            "package capture VT record separator",
            valid_package_record[:-1] + b"\v" + valid_package_record,
            "dpkg package-state capture emitted an invalid record",
        ),
    ):
        raw_calls = 0

        def raw_command_output(
            arguments: list[str | bytes],
            command_label: str,
            *,
            timeout: float | None = None,
        ) -> bytes:
            nonlocal raw_calls
            del command_label
            raw_calls += 1
            if (
                raw_calls != 1
                or arguments[:2] != ["/usr/bin/dpkg-query", "-W"]
                or timeout != verifier.COMMAND_TIMEOUT_SECONDS
            ):
                raise SystemExit("hostile raw capture crossed its first command boundary")
            return hostile_output

        verifier.command_output = raw_command_output
        try:
            require_rejected(
                verifier,
                verifier.capture_system_state,
                label,
                expected_error,
            )
        finally:
            verifier.command_output = original_command_output
        if raw_calls != 1:
            raise SystemExit("hostile raw capture issued an unexpected command")


def main() -> None:
    verifier = load_module()
    apt_verifier = load_apt_module()
    prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier)
    prove_lock_self_test_checks_diagnostic(verifier)
    verify_literal_command_policy(verifier)
    verify_kill_reap_deadline_and_exception(verifier)
    verify_bounded_command_process_group_ownership(verifier, apt_verifier)
    verify_bounded_command_spawn_contract(verifier)
    verify_bounded_command_real_handoff_cancellation(verifier)
    verify_bounded_command_process_boundary(verifier)
    verify_command_output_routing(verifier)
    verify_installed_record_routing(verifier)
    verify_capture_machine_format_boundaries(verifier)
    verify_alternative_canonical_sorting(verifier)
    verify_capture_fanout_limit(verifier)
    verify_capture_deadline(verifier)
    exact_spaced_selection = (
        b"editor"
        + b" " * 25
        + b"manual"
        + b" " * 3
        + b"/usr/bin/editor tool  "
    )
    if verifier.parse_alternative_selection_line(exact_spaced_selection) != (
        b"editor",
        "manual",
        b"/usr/bin/editor tool  ",
    ):
        raise SystemExit("exact padded alternative selection was not preserved")
    require_rejected(
        verifier,
        lambda: verifier.parse_alternative_selection_line(
            alternative_selection_record(b"bad/name", b"auto", None)[:-1]
        ),
        "slash alternative selection name",
        "alternative-state capture contains an invalid selection name",
    )
    for line, expected_selection in (
        (
            alternative_selection_record(b"edi\vtor", b"auto", None)[:-1],
            (b"edi\vtor", "auto", None),
        ),
        (
            alternative_selection_record(b"edi\ftor", b"auto", None)[:-1],
            (b"edi\ftor", "auto", None),
        ),
        (
            alternative_selection_record(
                b"n" * 129,
                b"manual",
                b"/path\twith\r\v\f\x1c\x1d\x1e controls  ",
            )[:-1],
            (
                b"n" * 129,
                "manual",
                b"/path\twith\r\v\f\x1c\x1d\x1e controls  ",
            ),
        ),
    ):
        if verifier.parse_alternative_selection_line(line) != expected_selection:
            raise SystemExit("alternative selection byte grammar lost a legal value")
    invalid_selection_lines = (
        (
            "dot alternative selection name",
            alternative_selection_record(b".", b"auto", None)[:-1],
            "alternative-state capture contains an invalid selection name",
        ),
        (
            "dot-dot alternative selection name",
            alternative_selection_record(b"..", b"auto", None)[:-1],
            "alternative-state capture contains an invalid selection name",
        ),
        (
            "short alternative selection name padding",
            b"editor" + b" " * 24 + b"auto" + b" " * 5,
            "alternative-state capture emitted invalid name padding",
        ),
        (
            "long alternative selection name padding",
            b"editor" + b" " * 26 + b"auto" + b" " * 5,
            "alternative-state capture emitted an invalid status",
        ),
        (
            "alternative selection status padding",
            b"editor" + b" " * 25 + b"manual" + b" " * 2,
            "alternative-state capture emitted an invalid status",
        ),
        (
            "unknown alternative selection status",
            alternative_selection_record(b"editor", b"automatic", None)[:-1],
            "alternative-state capture emitted an invalid status",
        ),
        (
            "literal none direct alternative target",
            alternative_selection_record(b"editor", b"auto", b"none")[:-1],
            "alternative-state capture emitted an invalid target",
        ),
        (
            "relative direct alternative target",
            alternative_selection_record(b"editor", b"auto", b"relative")[:-1],
            "alternative-state capture contains an invalid selection target",
        ),
        (
            "NUL direct alternative target",
            alternative_selection_record(b"editor", b"auto", b"/bad\0path")[:-1],
            "alternative-state capture contains an invalid selection target",
        ),
        (
            "LF direct alternative target",
            alternative_selection_record(b"editor", b"auto", b"/bad\npath")[:-1],
            "alternative-state capture contains an invalid selection target",
        ),
    )
    for label, line, expected_error in invalid_selection_lines:
        require_rejected(
            verifier,
            lambda line=line: verifier.parse_alternative_selection_line(line),
            label,
            expected_error,
        )
    zero_candidate_query_state = verifier.parse_alternative_query_bytes(
        ZERO_CANDIDATE_QUERY, b"editor"
    )
    if zero_candidate_query_state.query_sha256 != ZERO_CANDIDATE_V1_SHA256:
        raise SystemExit("safe zero-candidate canonical v1 digest changed")
    require_rejected(
        verifier,
        lambda: verifier.parse_alternative_query_bytes(
            ZERO_CANDIDATE_QUERY + b"\n", b"editor"
        ),
        "zero-candidate alternative query trailing blank stanza",
        "alternative query contains a trailing blank stanza",
    )
    awk_state = verifier.parse_alternative_query_bytes(AWK_QUERY, b"awk")
    if awk_state != verifier.EXPECTED_AWK_ALTERNATIVE_STATE:
        raise SystemExit("reviewed awk query does not match the fixed complete-state oracle")
    if hashlib.sha256(UNSAFE_CANONICAL_V2).hexdigest() != UNSAFE_CANONICAL_V2_SHA256:
        raise SystemExit("unsafe canonical v2 fixture digest is internally inconsistent")
    unsafe_state = verifier.parse_alternative_query_bytes(
        UNSAFE_QUERY, b"edi\xfftor"
    )
    if unsafe_state.query_sha256 != UNSAFE_CANONICAL_V2_SHA256:
        raise SystemExit("unsafe alternative query did not use canonical v2")
    control_path = b"/path\twith\r\v\f\x1c\x1d\x1e\xff controls  "
    long_role_path = b"/" + b"p" * 600
    for label, positive_query in (
        (
            "control master link",
            AWK_QUERY.replace(
                b"Link: /usr/bin/awk\n", b"Link: " + control_path + b"\n", 1
            ),
        ),
        (
            "control master slave path",
            AWK_QUERY.replace(
                b" nawk /usr/bin/nawk\n",
                b" nawk " + control_path + b"\n",
                1,
            ),
        ),
        (
            "control candidate slave path",
            AWK_QUERY.replace(
                b" awk.1.gz /usr/share/man/man1/gawk.1.gz\n",
                b" awk.1.gz " + control_path + b"\n",
                1,
            ),
        ),
        (
            "long master link",
            AWK_QUERY.replace(
                b"Link: /usr/bin/awk\n", b"Link: " + long_role_path + b"\n", 1
            ),
        ),
        (
            "long master slave path",
            AWK_QUERY.replace(
                b" nawk /usr/bin/nawk\n",
                b" nawk " + long_role_path + b"\n",
                1,
            ),
        ),
        (
            "long candidate slave path",
            AWK_QUERY.replace(
                b" awk.1.gz /usr/share/man/man1/gawk.1.gz\n",
                b" awk.1.gz " + long_role_path + b"\n",
                1,
            ),
        ),
    ):
        try:
            verifier.parse_alternative_query_bytes(positive_query, b"awk")
        except verifier.PackageLockError as exc:
            raise SystemExit(f"legal {label} was rejected: {exc}") from exc
    for label, hostile_query, expected_error in (
        (
            "empty master link path",
            AWK_QUERY.replace(b"Link: /usr/bin/awk\n", b"Link: \n", 1),
            "alternative query contains an empty Link",
        ),
        (
            "relative master link path",
            AWK_QUERY.replace(b"Link: /usr/bin/awk\n", b"Link: relative\n", 1),
            "alternative query contains an invalid master link",
        ),
        (
            "NUL master link path",
            AWK_QUERY.replace(
                b"Link: /usr/bin/awk\n", b"Link: /usr/bin/awk\0bad\n", 1
            ),
            "alternative query has invalid line framing",
        ),
        (
            "relative master slave path",
            AWK_QUERY.replace(
                b" nawk /usr/bin/nawk\n", b" nawk relative\n", 1
            ),
            "alternative query contains an invalid slave path",
        ),
        (
            "relative best path",
            AWK_QUERY.replace(b"Best: /usr/bin/gawk\n", b"Best: relative\n", 1),
            "alternative query contains an invalid best path",
        ),
        (
            "relative selected path",
            AWK_QUERY.replace(
                b"Value: /usr/bin/gawk\n", b"Value: relative\n", 1
            ),
            "alternative query contains an invalid selected path",
        ),
        (
            "relative candidate path",
            AWK_QUERY.replace(
                b"Alternative: /usr/bin/gawk\n", b"Alternative: relative\n", 1
            ),
            "alternative query contains an invalid candidate path",
        ),
        (
            "relative candidate slave path",
            AWK_QUERY.replace(
                b" awk.1.gz /usr/share/man/man1/gawk.1.gz\n",
                b" awk.1.gz relative\n",
                1,
            ),
            "alternative query contains an invalid slave path",
        ),
    ):
        require_rejected(
            verifier,
            lambda hostile_query=hostile_query: verifier.parse_alternative_query_bytes(
                hostile_query, b"awk"
            ),
            label,
            expected_error,
        )
    query_limit_template = b"""Name: bound
Link: /
Status: manual
Best: /candidate
Value: /candidate

Alternative: /candidate
Priority: 0
"""
    query_link_growth = verifier.MAX_ALTERNATIVE_QUERY_BYTES - len(
        query_limit_template
    )
    if query_link_growth <= 0:
        raise SystemExit("alternative query limit fixture has no link growth budget")
    exact_limit_query = query_limit_template.replace(
        b"Link: /\n",
        b"Link: /" + b"q" * query_link_growth + b"\n",
        1,
    )
    if len(exact_limit_query) != 512 * 1024:
        raise SystemExit(
            f"alternative query exact-limit fixture drifted: {len(exact_limit_query)}"
        )
    exact_limit_state = verifier.parse_alternative_query_bytes(
        exact_limit_query,
        b"bound",
    )
    if exact_limit_state.target != b"/candidate":
        raise SystemExit("alternative query exact-limit target changed")
    oversized_query = exact_limit_query.replace(
        b"\nStatus: manual\n",
        b"x\nStatus: manual\n",
        1,
    )
    if len(oversized_query) != 512 * 1024 + 1:
        raise SystemExit("alternative query limit+1 fixture drifted")
    require_rejected(
        verifier,
        lambda: verifier.parse_alternative_query_bytes(oversized_query, b"bound"),
        "alternative query size limit+1",
        "alternative query is empty or exceeds its size bound",
        exact=True,
    )
    amplified_candidate = b"/" + b"x" * (32 * 1024)
    amplified_slaves = tuple(
        (f"s{index:03d}".encode("ascii"), f"/slave/{index:03d}".encode("ascii"))
        for index in range(200)
    )
    amplified_query = (
        b"Name: editor\n"
        b"Link: /usr/bin/editor\n"
        b"Slaves:\n"
        + b"".join(
            b" " + name + b" " + b"/master" + path + b"\n"
            for name, path in amplified_slaves
        )
        + b"Status: manual\n"
        + b"Best: " + amplified_candidate + b"\n"
        + b"Value: " + amplified_candidate + b"\n"
        + b"\n"
        + b"Alternative: " + amplified_candidate + b"\n"
        + b"Priority: 0\n"
        + b"Slaves:\n"
        + b"".join(
            b" " + name + b" " + b"/candidate" + path + b"\n"
            for name, path in amplified_slaves
        )
    )
    if len(amplified_query) > verifier.MAX_ALTERNATIVE_QUERY_BYTES:
        raise SystemExit("amplification fixture exceeds the raw query bound")
    projected_v1_size = sum(
        len(b"candidate-slave\t")
        + len(amplified_candidate)
        + 1
        + len(name)
        + 1
        + len(b"/candidate")
        + len(path)
        + 1
        for name, path in amplified_slaves
    )
    if projected_v1_size <= verifier.MAX_ALTERNATIVE_CANONICAL_BYTES:
        raise SystemExit("amplification fixture does not exceed the v1 work bound")
    amplified_v2 = [
        b"schema\ttb321fu.alternative-query/v2",
        b"name-hex\t" + b"editor".hex().encode("ascii"),
        b"link-hex\t" + b"/usr/bin/editor".hex().encode("ascii"),
        b"status\tmanual",
        b"best-hex\t" + amplified_candidate.hex().encode("ascii"),
        b"value-hex\t" + amplified_candidate.hex().encode("ascii"),
    ]
    amplified_v2.extend(
        b"master-slave-hex\t"
        + name.hex().encode("ascii")
        + b"\t"
        + (b"/master" + path).hex().encode("ascii")
        for name, path in amplified_slaves
    )
    amplified_v2.append(
        b"candidate-hex\t"
        + amplified_candidate.hex().encode("ascii")
        + b"\t0"
    )
    amplified_v2.extend(
        b"candidate-slave-hex\t"
        + name.hex().encode("ascii")
        + b"\t"
        + (b"/candidate" + path).hex().encode("ascii")
        for name, path in amplified_slaves
    )
    amplified_v2_bytes = b"\n".join(amplified_v2) + b"\n"
    amplified_state = verifier.parse_alternative_query_bytes(
        amplified_query, b"editor"
    )
    if amplified_state.query_sha256 != hashlib.sha256(
        amplified_v2_bytes
    ).hexdigest():
        raise SystemExit("amplified printable query did not fall back to canonical v2")
    original_canonical_bound = verifier.MAX_ALTERNATIVE_CANONICAL_BYTES
    verifier.MAX_ALTERNATIVE_CANONICAL_BYTES = len(amplified_v2_bytes) - 1
    try:
        require_rejected(
            verifier,
            lambda: verifier.parse_alternative_query_bytes(
                amplified_query, b"editor"
            ),
            "canonical v2 work bound",
            "alternative canonical state exceeds its work bound",
        )
    finally:
        verifier.MAX_ALTERNATIVE_CANONICAL_BYTES = original_canonical_bound
    for priority in (b"-2147483648", b"2147483647"):
        verifier.parse_alternative_query_bytes(
            SINGLE_CANDIDATE_QUERY.replace(b"Priority: 0\n", b"Priority: " + priority + b"\n"),
            b"editor",
        )
    for priority, expected_error in (
        (b"-0", "alternative query contains an invalid priority"),
        (b"+0", "alternative query contains an invalid priority"),
        (b"+1", "alternative query contains an invalid priority"),
        (b"00", "alternative query contains an invalid priority"),
        (b"01", "alternative query contains an invalid priority"),
        (b"-00", "alternative query contains an invalid priority"),
        (b"-2147483649", "alternative query priority exceeds its bound"),
        (b"2147483648", "alternative query priority exceeds its bound"),
    ):
        require_rejected(
            verifier,
            lambda priority=priority: verifier.parse_alternative_query_bytes(
                SINGLE_CANDIDATE_QUERY.replace(
                    b"Priority: 0\n", b"Priority: " + priority + b"\n"
                ),
                b"editor",
            ),
            f"noncanonical priority {priority!r}",
            expected_error,
        )
    for label, valid_query, hostile_query in (
        (
            "current tied candidate",
            TIED_CURRENT_QUERY,
            TIED_CURRENT_QUERY.replace(
                b"Best: /usr/bin/true\n", b"Best: /usr/bin/false\n", 1
            ),
        ),
        (
            "no-current tied candidate",
            TIED_NO_CURRENT_QUERY,
            TIED_NO_CURRENT_QUERY.replace(
                b"Best: /usr/bin/false\n", b"Best: /usr/bin/true\n", 1
            ),
        ),
        (
            "first strictly higher tied candidate",
            TIED_HIGHER_QUERY,
            TIED_HIGHER_QUERY.replace(
                b"Best: /usr/bin/false\n", b"Best: /usr/bin/true\n", 1
            ),
        ),
    ):
        verifier.parse_alternative_query_bytes(valid_query, b"editor")
        require_rejected(
            verifier,
            lambda hostile_query=hostile_query: verifier.parse_alternative_query_bytes(
                hostile_query, b"editor"
            ),
            label,
            "alternative query Best differs from dpkg selection semantics",
        )
    for legal_name in (
        b"-awk",
        b".awk",
        b"_awk",
        b"+awk",
        b"awk:gnu",
        b"awk@1",
        b"a" * 129,
    ):
        verifier.parse_alternative_query_bytes(
            AWK_QUERY.replace(
                b"Name: awk\n", b"Name: " + legal_name + b"\n", 1
            ),
            legal_name,
        )
    for legal_slave_name in (b".", b".."):
        verifier.parse_alternative_query_bytes(
            AWK_QUERY.replace(
                b" nawk ", b" " + legal_slave_name + b" "
            ),
            b"awk",
        )
    for label, invalid_name, expected_error in (
        ("empty", b"", "alternative query contains an invalid expected name"),
        ("dot", b".", "alternative query contains an invalid expected name"),
        ("dot-dot", b"..", "alternative query contains an invalid expected name"),
        ("slash", b"awk/gnu", "alternative query contains an invalid expected name"),
        ("space", b"awk gnu", "alternative query contains an invalid expected name"),
        ("tab", b"awk\tgnu", "alternative query contains an invalid expected name"),
        ("NUL", b"awk\0gnu", "alternative query has invalid line framing"),
        ("LF", b"awk\ngnu", "alternative query contains an invalid expected name"),
    ):
        require_rejected(
            verifier,
            lambda invalid_name=invalid_name: verifier.parse_alternative_query_bytes(
                AWK_QUERY.replace(
                    b"Name: awk\n", b"Name: " + invalid_name + b"\n", 1
                ),
                invalid_name,
            ),
            f"invalid alternative expected name {label}",
            expected_error,
        )
    verifier.parse_alternative_query_bytes(
        AWK_QUERY.replace(
            b"Link: /usr/bin/awk\n", b"Link: /usr/bin/awk tool\n", 1
        ),
        b"awk",
    )
    verifier.parse_alternative_query_bytes(
        AWK_QUERY.replace(
            b" nawk /usr/bin/nawk\n", b" nawk /usr/bin/nawk tool\n", 1
        ),
        b"awk",
    )
    crlf_query = AWK_QUERY.replace(b"\n", b"\r\n")
    captured_crlf_query = verifier.command_output(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            f"import sys; sys.stdout.buffer.write({crlf_query!r})",
        ],
        "CRLF alternative query oracle",
    )
    if isinstance(captured_crlf_query, str):
        captured_crlf_query = captured_crlf_query.encode("ascii")
    require_rejected(
        verifier,
        lambda: verifier.parse_alternative_query_bytes(captured_crlf_query, b"awk"),
        "command-output CRLF query normalization",
        "alternative query name differs from its selection",
    )
    hostile_stderr_prefix = b"plain\n\t\xff"
    hostile_stderr = hostile_stderr_prefix + b"x" * (
        verifier.MAX_COMMAND_STDERR_BYTES - len(hostile_stderr_prefix)
    )
    try:
        verifier.command_output(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                f"import sys; sys.stderr.buffer.write({hostile_stderr!r}); sys.exit(7)",
            ],
            "hostile stderr oracle",
        )
    except verifier.PackageLockError as exc:
        diagnostic = str(exc)
        if "plain\\x0a\\x09\\xff" not in diagnostic:
            raise SystemExit(f"stderr diagnostic was not byte escaped: {diagnostic!r}")
        if any(character in diagnostic for character in "\r\n\t\v\f"):
            raise SystemExit("stderr diagnostic exposed a raw control character")
        if len(diagnostic) > verifier.MAX_COMMAND_STDERR_BYTES * 4 + 256:
            raise SystemExit("stderr diagnostic did not retain its bounded length evidence")
    else:
        raise SystemExit("hostile stderr command failure was accepted")
    if verifier.render_alternative_name(b"a" * 64) != "a" * 64:
        raise SystemExit("short printable alternative diagnostic changed")
    long_rendered_name = verifier.render_alternative_name(b"a" * 65)
    if long_rendered_name == "a" * 65 or ":bytes=65" not in long_rendered_name:
        raise SystemExit("long printable alternative diagnostic was not bounded")
    control_rendered_name = verifier.render_alternative_name(b"edi\vtor")
    if "\v" in control_rendered_name or ":bytes=7" not in control_rendered_name:
        raise SystemExit("control-bearing alternative diagnostic was not escaped")
    awk_drift_states = {}
    for label, mutated in (
        ("candidate priority", AWK_QUERY.replace(b"Priority: 10", b"Priority: 11", 1)),
        (
            "candidate slave",
            AWK_QUERY.replace(
                b"nawk /usr/bin/gawk\n", b"nawk /usr/bin/gawk-drift\n", 1
            ),
        ),
        (
            "candidate set",
            AWK_QUERY
            + b"\nAlternative: /usr/bin/other-awk\nPriority: 1\nSlaves:\n",
        ),
    ):
        drifted = verifier.parse_alternative_query_bytes(mutated, b"awk")
        if drifted == awk_state:
            raise SystemExit(f"alternative query parser lost {label} drift")
        awk_drift_states[label] = drifted
    alternative_expected_names = {
        "empty master Slaves header": b"editor",
        "candidate Slaves header without master slaves": b"editor",
    }
    alternative_expected_errors = {
        "duplicate master slave": (
            "alternative query contains an invalid slave name"
        ),
        "duplicate master slave link": (
            "alternative query contains a duplicate master link"
        ),
        "master name equals slave name": (
            "alternative query master name conflicts with a slave name"
        ),
        "master link equals candidate path": (
            "alternative query master link conflicts with a candidate path"
        ),
        "slave link equals candidate slave path": (
            "alternative query slave link conflicts with a candidate slave path"
        ),
        "master slave link equals master link": (
            "alternative query contains a duplicate master link"
        ),
        "candidate missing mandatory Slaves header": (
            "alternative query has invalid candidate Slaves framing"
        ),
        "empty candidate missing mandatory Slaves header": (
            "alternative query has invalid candidate Slaves framing"
        ),
        "empty master Slaves header": (
            "alternative query has invalid master Slaves framing"
        ),
        "candidate Slaves header without master slaves": (
            "alternative query has invalid candidate Slaves framing"
        ),
        "lower-priority best candidate": (
            "alternative query Best differs from dpkg selection semantics"
        ),
        "duplicate candidate": "alternative query contains a duplicate candidate",
        "unknown candidate slave": "alternative candidate declares an unknown slave",
        "missing best": "alternative query Best does not match its candidate set",
        "unknown value": "alternative query Value is not a candidate",
        "VT query line separator": "alternative query contains an invalid name",
        "FF query line separator": "alternative query contains an invalid name",
        "FS query line separator": "alternative query contains an invalid name",
        "GS query line separator": "alternative query contains an invalid name",
        "RS query line separator": "alternative query contains an invalid name",
        "CRLF query": "alternative query name differs from its selection",
        "trailing blank stanza": "alternative query contains a trailing blank stanza",
    }
    for label, hostile_query in (
        (
            "duplicate master slave",
            AWK_QUERY.replace(
                b" awk.1.gz /usr/share/man/man1/awk.1.gz\n",
                b" awk.1.gz /usr/share/man/man1/awk.1.gz\n"
                b" awk.1.gz /usr/share/man/man1/other.1.gz\n",
                1,
            ),
        ),
        (
            "duplicate master slave link",
            AWK_QUERY.replace(
                b" nawk /usr/bin/nawk\n",
                b" nawk /usr/share/man/man1/awk.1.gz\n",
                1,
            ),
        ),
        (
            "master name equals slave name",
            AWK_QUERY.replace(
                b" nawk /usr/bin/nawk\n",
                b" awk /usr/bin/nawk\n",
                1,
            ),
        ),
        (
            "master link equals candidate path",
            AWK_QUERY.replace(
                b"Link: /usr/bin/awk\n",
                b"Link: /usr/bin/gawk\n",
                1,
            ),
        ),
        (
            "slave link equals candidate slave path",
            AWK_QUERY.replace(
                b" nawk /usr/bin/gawk\n",
                b" nawk /usr/bin/nawk\n",
                1,
            ),
        ),
        (
            "master slave link equals master link",
            AWK_QUERY.replace(
                b" nawk /usr/bin/nawk\n",
                b" nawk /usr/bin/awk\n",
                1,
            ),
        ),
        (
            "candidate missing mandatory Slaves header",
            AWK_QUERY.replace(
                b"Priority: 10\nSlaves:\n",
                b"Priority: 10\n",
                1,
            ),
        ),
        (
            "empty candidate missing mandatory Slaves header",
            AWK_QUERY
            + b"\nAlternative: /usr/bin/other-awk\nPriority: 1\n",
        ),
        (
            "empty master Slaves header",
            ZERO_CANDIDATE_QUERY.replace(b"Status: auto\n", b"Slaves:\nStatus: auto\n"),
        ),
        (
            "candidate Slaves header without master slaves",
            b"Name: editor\n"
            b"Link: /usr/bin/editor\n"
            b"Status: auto\n"
            b"Best: /usr/bin/vim.basic\n"
            b"Value: /usr/bin/vim.basic\n"
            b"\n"
            b"Alternative: /usr/bin/vim.basic\n"
            b"Priority: 10\n"
            b"Slaves:\n",
        ),
        (
            "lower-priority best candidate",
            AWK_QUERY.replace(
                b"Best: /usr/bin/gawk\n", b"Best: /usr/bin/mawk\n", 1
            ),
        ),
        (
            "duplicate candidate",
            AWK_QUERY
            + b"\nAlternative: /usr/bin/gawk\nPriority: 10\n",
        ),
        (
            "unknown candidate slave",
            AWK_QUERY.replace(
                b" awk.1.gz /usr/share/man/man1/gawk.1.gz\n",
                b" unknown.1.gz /usr/share/man/man1/gawk.1.gz\n",
                1,
            ),
        ),
        ("missing best", AWK_QUERY.replace(b"Best: /usr/bin/gawk\n", b"")),
        (
            "unknown value",
            AWK_QUERY.replace(
                b"Value: /usr/bin/gawk\n", b"Value: /usr/bin/not-a-candidate\n"
            ),
        ),
        ("FF query line separator", AWK_QUERY.replace(b"\n", b"\f", 1)),
        ("VT query line separator", AWK_QUERY.replace(b"\n", b"\v", 1)),
        ("FS query line separator", AWK_QUERY.replace(b"\n", b"\x1c", 1)),
        ("GS query line separator", AWK_QUERY.replace(b"\n", b"\x1d", 1)),
        ("RS query line separator", AWK_QUERY.replace(b"\n", b"\x1e", 1)),
        ("CRLF query", AWK_QUERY.replace(b"\n", b"\r\n")),
        ("trailing blank stanza", AWK_QUERY + b"\n"),
    ):
        expected_name = alternative_expected_names.get(label, b"awk")
        require_rejected(
            verifier,
            lambda hostile_query=hostile_query, expected_name=expected_name: (
                verifier.parse_alternative_query_bytes(hostile_query, expected_name)
            ),
            f"alternative query {label}",
            alternative_expected_errors[label],
        )
    if "dpkg" not in verifier.BOOTSTRAP_PACKAGES:
        raise SystemExit("native dpkg is not locked before the first transaction")
    lock_text = b"""schema\ttb321fu.haptics-build-packages/v2
snapshot\thttps://snapshot.ubuntu.com/ubuntu/20260730T000000Z/
package\tapt\tamd64\t2.8.3\tbootstrap
package\troot-tool\tamd64\t1.0\trequested
package\ttransitive\tall\t2.0\tclosure
compat-package\tcompat-lib\tamd64\t3.0\trequested\thttps://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/c/compat/compat-lib_3.0_amd64.deb\t%s
alternative\tawk\tmanual\t/usr/bin/gawk
""" % (b"a" * 64)
    policy = verifier.parse_lock_bytes(lock_text)
    if policy.packages[("apt", "amd64")].role != "bootstrap":
        raise SystemExit("package-lock parser lost the bootstrap role")
    if policy.packages[("compat-lib", "amd64")].source != "compat":
        raise SystemExit("package-lock parser lost the compatibility source")
    if policy.alternatives != {"awk": ("manual", "/usr/bin/gawk")}:
        raise SystemExit("package-lock parser lost the alternative contract")
    verify_installed_routing(verifier, policy)
    verify_bootstrap_deadline(verifier, policy)
    for label, separator in (
        ("VT", b"\v"),
        ("FF", b"\f"),
        ("FS", b"\x1c"),
        ("GS", b"\x1d"),
        ("RS", b"\x1e"),
    ):
        require_rejected(
            verifier,
            lambda separator=separator: verifier.parse_lock_bytes(
                lock_text.replace(b"\n", separator, 1)
            ),
            f"{label} package-lock line separator",
            "package lock has invalid line framing",
            exact=True,
        )
    for label, hostile_lock, expected_error in (
        (
            "CR package-lock line separator",
            lock_text.replace(b"\n", b"\r", 1),
            "package lock has invalid line framing",
        ),
        (
            "CRLF package-lock line separator",
            lock_text.replace(b"\n", b"\r\n", 1),
            "package lock has invalid line framing",
        ),
        (
            "embedded CR package-lock field",
            lock_text.replace(b"root-tool", b"root\rtool", 1),
            "package lock has invalid line framing",
        ),
        (
            "embedded NUL package-lock field",
            lock_text.replace(b"root-tool", b"root\0tool", 1),
            "package lock has invalid line framing",
        ),
        (
            "package lock missing terminal LF",
            lock_text[:-1],
            "package lock has invalid line framing",
        ),
        (
            "package lock non-ASCII byte",
            lock_text.replace(b"root-tool", b"root-\xfftool", 1),
            "package lock must contain ASCII only",
        ),
        (
            "package lock UTF-8 NEL boundary",
            lock_text.replace(b"\n", b"\xc2\x85", 1),
            "package lock must contain ASCII only",
        ),
        (
            "package lock UTF-8 line separator",
            lock_text.replace(b"\n", b"\xe2\x80\xa8", 1),
            "package lock must contain ASCII only",
        ),
        (
            "package lock UTF-8 paragraph separator",
            lock_text.replace(b"\n", b"\xe2\x80\xa9", 1),
            "package lock must contain ASCII only",
        ),
    ):
        require_rejected(
            verifier,
            lambda hostile_lock=hostile_lock: verifier.parse_lock_bytes(hostile_lock),
            label,
            expected_error,
            exact=True,
        )
    require_rejected(
        verifier,
        lambda: verifier.parse_lock_bytes(
            lock_text.replace(b"package\ttransitive\tall\t", b"package\ttransitive\t")
        ),
        "missing package architecture",
        "package lock contains an invalid record",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_lock_bytes(
            lock_text.replace(
                b"package\tapt\tamd64\t2.8.3\tbootstrap\n",
                b"package\tapt\tamd64\t2.8.3\tbootstrap\n"
                b"package\tapt\tamd64\t2.8.3\tclosure\n",
                1,
            )
        ),
        "duplicate package identity",
        "duplicate package identity",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_lock_bytes(
            lock_text.replace(
                b"package\troot-tool\tamd64\t1.0\trequested\npackage\ttransitive\tall\t2.0\tclosure\n",
                b"package\ttransitive\tall\t2.0\tclosure\npackage\troot-tool\tamd64\t1.0\trequested\n",
            )
        ),
        "unsorted package identities",
        "package records are not lexically ordered",
    )
    expected = {
        ("apt", "amd64"): "2.8.3",
        ("libc6", "amd64"): "2.39-0ubuntu8.7",
        ("ubuntu-keyring", "all"): "2023.11.28.1",
    }
    valid_plan = b"""Inst ubuntu-keyring (2023.11.28.1 local-deb [all])
Conf ubuntu-keyring (2023.11.28.1 local-deb [all])
Inst libc6 (2.39-0ubuntu8.7 local-deb [amd64]) []
Conf libc6 (2.39-0ubuntu8.7 local-deb [amd64])
Inst apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])
Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])
"""
    plan = verifier.parse_apt_plan_bytes(valid_plan)
    verifier.verify_closure_plan(expected, plan)
    require_rejected(
        verifier,
        lambda: verifier.parse_apt_plan_bytes(
            valid_plan.replace(b"\n", b"\v", 1)
        ),
        "vertical-tab APT plan line separator",
        "apt plan has invalid line framing",
    )

    annotated_plan = valid_plan.replace(
        b"Inst apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])\n",
        (
            b"Inst apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])"
            b" [apt:amd64 on libc6:amd64]"
            b" [ubuntu-keyring:all on apt:amd64]"
            b" [libc-bin:amd64 ]\n"
        ),
    )
    verifier.verify_closure_plan(
        expected, verifier.parse_apt_plan_bytes(annotated_plan)
    )
    closure_with_old_version = valid_plan.replace(
        b"Inst apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])",
        b"Inst apt [2.8.2] (2.8.3 Ubuntu:24.04/noble-updates [amd64])",
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_closure_plan(
            expected, verifier.parse_apt_plan_bytes(closure_with_old_version)
        ),
        "empty-status closure old version",
        "empty-status apt closure contains an old version",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_apt_plan_bytes(
            valid_plan.replace(
                b"Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])",
                b"Conf apt [2.8.2] (2.8.3 Ubuntu:24.04/noble-updates [amd64])",
            )
        ),
        "configure record old version",
        "apt configure record contains an old version",
    )
    annotation_expected_errors = {
        "unclosed annotation": "apt plan contains an unclosed annotation",
        "missing dependency target": "apt plan contains a malformed annotation",
        "extra dependency separator": "apt plan contains a malformed annotation",
        "short-break identity without trailing space": "apt plan contains a malformed annotation",
        "dependency after short-break list": "apt plan dependency annotation follows its short-break list",
        "multiple short-break lists": "apt plan contains multiple short-break lists",
        "duplicate dependency annotation": "apt plan contains a duplicate dependency annotation",
        "duplicate short-break identity": "apt plan contains a duplicate short-break identity",
        "forged action in annotation": "apt plan contains a malformed annotation",
        "trailing annotation garbage": "apt plan contains malformed annotation framing",
        "dependency source without architecture": "apt plan contains a malformed annotation",
        "dependency target without architecture": "apt plan contains a malformed annotation",
        "short-break identity without architecture": "apt plan contains a malformed annotation",
    }
    for label, suffix in (
        ("unclosed annotation", b" [apt:amd64 on libc6:amd64"),
        ("missing dependency target", b" [apt:amd64 on]"),
        ("extra dependency separator", b" [apt:amd64 on libc6:amd64 on dpkg:amd64]"),
        ("short-break identity without trailing space", b" [apt:amd64]"),
        ("dependency after short-break list", b" [apt:amd64 ] [libc6:amd64 on apt:amd64]"),
        ("multiple short-break lists", b" [apt:amd64 ] [libc6:amd64 ]"),
        (
            "duplicate dependency annotation",
            b" [apt:amd64 on libc6:amd64] [apt:amd64 on libc6:amd64]",
        ),
        ("duplicate short-break identity", b" [apt:amd64 apt:amd64 ]"),
        ("forged action in annotation", b" [Remv ]"),
        ("trailing annotation garbage", b" [] Remv surprise"),
        ("dependency source without architecture", b" [apt on libc6:amd64]"),
        ("dependency target without architecture", b" [apt:amd64 on libc6]"),
        ("short-break identity without architecture", b" [apt ]"),
    ):
        require_rejected(
            verifier,
            lambda suffix=suffix: verifier.parse_apt_plan_bytes(
                valid_plan.replace(
                    b"Inst apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])\n",
                    b"Inst apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])"
                    + suffix
                    + b"\n",
                )
            ),
            label,
            annotation_expected_errors[label],
        )

    for configure_suffix in (b" []", b" [apt:amd64 ]"):
        configure_short_breaks_plan = valid_plan.replace(
            b"Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])\n",
            b"Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])"
            + configure_suffix
            + b"\n",
        )
        verifier.verify_closure_plan(
            expected,
            verifier.parse_apt_plan_bytes(configure_short_breaks_plan),
        )
    configure_expected_errors = {
        "configure dependency annotation": "apt configure record contains a dependency annotation",
        "configure multiple short-break lists": "apt plan contains multiple short-break lists",
        "configure short-break identity without trailing space": "apt plan contains a malformed annotation",
    }
    for label, configure_suffix in (
        (
            "configure dependency annotation",
            b" [apt:amd64 on libc6:amd64]",
        ),
        (
            "configure multiple short-break lists",
            b" [apt:amd64 ] [libc6:amd64 ]",
        ),
        (
            "configure short-break identity without trailing space",
            b" [apt:amd64]",
        ),
    ):
        require_rejected(
            verifier,
            lambda configure_suffix=configure_suffix: verifier.parse_apt_plan_bytes(
                valid_plan.replace(
                    b"Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])\n",
                    b"Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])"
                    + configure_suffix
                    + b"\n",
                )
            ),
            label,
            configure_expected_errors[label],
        )

    original_command_output = verifier.command_output

    def zero_candidate_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del timeout
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            return b""
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return alternative_selection_record(b"editor", b"auto", None)
        if arguments == [
            b"/usr/bin/update-alternatives",
            b"--query",
            b"editor",
        ]:
            return ZERO_CANDIDATE_QUERY
        raise SystemExit(f"unexpected zero-candidate capture command: {arguments!r} ({label})")

    verifier.command_output = zero_candidate_command_output
    try:
        zero_candidate_state = verifier.capture_system_state()
    finally:
        verifier.command_output = original_command_output
    if zero_candidate_state.alternatives.get(b"editor") != verifier.AlternativeState(
        "auto",
        None,
        verifier.parse_alternative_query_bytes(
            ZERO_CANDIDATE_QUERY, b"editor"
        ).query_sha256,
    ):
        raise SystemExit("zero-candidate alternative selection was not captured exactly")

    control_name = b"edi\vtor"
    control_name_query = ZERO_CANDIDATE_QUERY.replace(
        b"Name: editor\n", b"Name: edi\vtor\n", 1
    )

    def control_name_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del timeout
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            return b""
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return alternative_selection_record(control_name, b"auto", None)
        if arguments == [
            b"/usr/bin/update-alternatives",
            b"--query",
            control_name,
        ]:
            return control_name_query
        raise SystemExit(
            f"unexpected control-name capture command: {arguments!r} ({label})"
        )

    verifier.command_output = control_name_command_output
    try:
        control_name_state = verifier.capture_system_state()
    finally:
        verifier.command_output = original_command_output
    expected_control_name = verifier.parse_alternative_query_bytes(
        control_name_query, control_name
    )
    if control_name_state.alternatives.get(control_name) != expected_control_name:
        raise SystemExit("control-byte alternative name was not captured exactly")

    def literal_none_selection_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del timeout
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return alternative_selection_record(b"editor", b"auto", b"none")
        return zero_candidate_command_output(arguments, label)

    verifier.command_output = literal_none_selection_command_output
    try:
        require_rejected(
            verifier,
            verifier.capture_system_state,
            "literal none alternative selection target",
            "alternative-state capture emitted an invalid target",
        )
    finally:
        verifier.command_output = original_command_output

    def missing_lf_selection_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del timeout
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return alternative_selection_record(b"editor", b"auto", None)[:-1]
        return zero_candidate_command_output(arguments, label)

    verifier.command_output = missing_lf_selection_command_output
    try:
        require_rejected(
            verifier,
            verifier.capture_system_state,
            "alternative selection missing terminal LF",
            "alternative-state capture output has invalid line framing",
        )
    finally:
        verifier.command_output = original_command_output

    def spaced_candidate_command_output(
        arguments: list[str | bytes],
        label: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        del timeout
        if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
            return b""
        if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
            return b""
        if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
            return alternative_selection_record(
                b"editor", b"manual", b"/usr/bin/editor tool"
            )
        if arguments == [
            b"/usr/bin/update-alternatives",
            b"--query",
            b"editor",
        ]:
            return SPACED_CANDIDATE_QUERY
        raise SystemExit(
            f"unexpected spaced-candidate capture command: {arguments!r} ({label})"
        )

    verifier.command_output = spaced_candidate_command_output
    try:
        spaced_candidate_state = verifier.capture_system_state()
    finally:
        verifier.command_output = original_command_output
    expected_spaced_candidate = verifier.parse_alternative_query_bytes(
        SPACED_CANDIDATE_QUERY, b"editor"
    )
    if spaced_candidate_state.alternatives.get(b"editor") != expected_spaced_candidate:
        raise SystemExit("spaced alternative selection was not captured exactly")

    def capture_single_alternative(
        name: bytes,
        mode: bytes,
        target: bytes | None,
        query: bytes,
    ):
        calls: list[tuple[list[str | bytes], str, float | None]] = []

        def fixture_command_output(
            arguments: list[str | bytes],
            label: str,
            *,
            timeout: float | None = None,
        ) -> bytes:
            calls.append((arguments, label, timeout))
            if arguments[:2] == ["/usr/bin/dpkg-query", "-W"]:
                return b""
            if arguments == ["/usr/bin/dpkg", "--get-selections", "*"]:
                return b""
            if arguments == ["/usr/bin/dpkg", "--print-foreign-architectures"]:
                return b""
            if arguments == ["/usr/bin/update-alternatives", "--get-selections"]:
                return alternative_selection_record(name, mode, target)
            if arguments == [b"/usr/bin/update-alternatives", b"--query", name]:
                return query
            raise SystemExit(
                f"unexpected unsafe capture command: {arguments!r} ({label})"
            )

        verifier.command_output = fixture_command_output
        try:
            state = verifier.capture_system_state()
        finally:
            verifier.command_output = original_command_output
        expected_argv = [
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f=${Package}\t${Architecture}\t${Version}\t${Status}\n",
            ],
            ["/usr/bin/dpkg", "--get-selections", "*"],
            ["/usr/bin/dpkg", "--print-foreign-architectures"],
            ["/usr/bin/update-alternatives", "--get-selections"],
            [b"/usr/bin/update-alternatives", b"--query", name],
            ["/usr/bin/update-alternatives", "--get-selections"],
            [b"/usr/bin/update-alternatives", b"--query", name],
        ]
        if [arguments for arguments, _, _ in calls] != expected_argv:
            raise SystemExit(f"unsafe capture argv/order drifted: {calls!r}")
        if [timeout for _, _, timeout in calls] != [
            verifier.COMMAND_TIMEOUT_SECONDS
        ] * len(expected_argv):
            raise SystemExit(f"unsafe capture command timeout drifted: {calls!r}")
        if any(
            any(character in label for character in "\r\n\t\v\f\x1c\x1d\x1e")
            or len(label) > 256
            for _, label, _ in calls
        ):
            raise SystemExit("unsafe capture label exposed controls or unbounded data")
        serialized_state = verifier.serialize_system_state(state)
        if verifier.parse_system_state_bytes(serialized_state) != state:
            raise SystemExit("unsafe alternative capture did not round-trip through v3")
        try:
            serialized_state.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SystemExit("v3 system state exposed raw non-ASCII bytes") from exc
        return state

    unsafe_capture = capture_single_alternative(
        b"edi\xfftor", b"auto", None, UNSAFE_QUERY
    )
    if unsafe_capture.alternatives[b"edi\xfftor"].query_sha256 != (
        UNSAFE_CANONICAL_V2_SHA256
    ):
        raise SystemExit("unsafe captured alternative lost its canonical v2 digest")
    ff_name = b"edi\ftor"
    ff_name_query = ZERO_CANDIDATE_QUERY.replace(
        b"Name: editor\n", b"Name: " + ff_name + b"\n", 1
    )
    ff_capture = capture_single_alternative(
        ff_name, b"auto", None, ff_name_query
    )
    if ff_name not in ff_capture.alternatives:
        raise SystemExit("FF alternative name did not round-trip through v3")

    control_target = b"/usr/bin/tool\twith\r\v\f\x1c\x1d\x1e controls  "
    control_target_query = (
        b"Name: tool\n"
        b"Link: /usr/bin/tool-link\n"
        b"Status: manual\n"
        b"Best: " + control_target + b"\n"
        b"Value: " + control_target + b"\n"
        b"\n"
        b"Alternative: " + control_target + b"\n"
        b"Priority: 0\n"
    )
    control_target_capture = capture_single_alternative(
        b"tool", b"manual", control_target, control_target_query
    )
    if control_target_capture.alternatives[b"tool"].target != control_target:
        raise SystemExit("control-bearing selection target was not preserved")

    long_name = b"n" * 129
    long_target = b"/" + b"x" * 600
    long_query = (
        b"Name: " + long_name + b"\n"
        b"Link: /usr/bin/long-link\n"
        b"Status: manual\n"
        b"Best: " + long_target + b"\n"
        b"Value: " + long_target + b"\n"
        b"\n"
        b"Alternative: " + long_target + b"\n"
        b"Priority: 0\n"
    )
    long_capture = capture_single_alternative(
        long_name, b"manual", long_target, long_query
    )
    if long_capture.alternatives[long_name].target != long_target:
        raise SystemExit("long alternative name/path did not survive byte argv capture")

    require_rejected(
        verifier,
        lambda: verifier.verify_closure_plan(
            expected,
            verifier.parse_apt_plan_bytes(
                valid_plan
                + b"Inst surprise (1 Ubuntu:24.04/noble [amd64])\n"
                + b"Conf surprise (1 Ubuntu:24.04/noble [amd64])\n"
            ),
        ),
        "extra dependency",
        "apt closure plan differs from lock",
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_closure_plan(
            expected,
            verifier.parse_apt_plan_bytes(valid_plan.replace(b"2.8.3", b"2.8.4")),
        ),
        "wrong selected version",
        "apt closure plan differs from lock",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_apt_plan_bytes(
            valid_plan + b"Remv base-files [13ubuntu10.4]\n"
        ),
        "removal",
        "apt plan contains an unparsed line: 'Remv base-files",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_apt_plan_bytes(valid_plan + b"unexpected summary\n"),
        "unparsed plan output",
        "apt plan contains an unparsed line: 'unexpected summary'",
    )

    host_plan = verifier.parse_apt_plan_bytes(
        b"""Inst libc6 (2.39-0ubuntu8.7 local-deb [amd64])
Conf libc6 (2.39-0ubuntu8.7 local-deb [amd64])
Inst apt [2.8.2] (2.8.3 Ubuntu:24.04/noble-updates [amd64])
Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])
"""
    )
    before_awk = verifier.AlternativeState("auto", b"/usr/bin/mawk", "1" * 64)
    editor_state = verifier.AlternativeState(
        "auto", b"/usr/bin/vim.basic", "2" * 64
    )

    before = verifier.SystemState(
        packages={
            ("apt", "amd64"): ("2.8.2", "install ok installed"),
            ("base-files", "amd64"): ("13ubuntu10.4", "install ok installed"),
            ("ubuntu-keyring", "all"): ("2023.11.28.1", "install ok installed"),
        },
        selections={"apt": "install", "base-files": "install", "ubuntu-keyring": "install"},
        foreign_architectures=(),
        alternatives={
            b"awk": before_awk,
            b"editor": editor_state,
        },
    )
    after = verifier.SystemState(
        packages={
            ("apt", "amd64"): ("2.8.3", "install ok installed"),
            ("base-files", "amd64"): ("13ubuntu10.4", "install ok installed"),
            ("libc6", "amd64"): ("2.39-0ubuntu8.7", "install ok installed"),
            ("ubuntu-keyring", "all"): ("2023.11.28.1", "install ok installed"),
        },
        selections={
            "apt": "install",
            "base-files": "install",
            "libc6": "install",
            "ubuntu-keyring": "install",
        },
        foreign_architectures=(),
        alternatives={
            b"awk": awk_state,
            b"editor": editor_state,
        },
    )
    verifier.verify_baseline_state(before)
    verifier.verify_state_transition(
        expected,
        {"awk": ("manual", "/usr/bin/gawk")},
        before,
        after,
    )
    verifier.verify_host_plan(expected, before, host_plan)
    config_files_before = verifier.SystemState(
        packages={
            **before.packages,
            ("libc6", "amd64"): ("2.39-0ubuntu8.6", "deinstall ok config-files"),
        },
        selections={**before.selections, "libc6": "deinstall"},
        foreign_architectures=(),
        alternatives=before.alternatives,
    )
    verifier.verify_host_plan(expected, config_files_before, host_plan)
    exact_before = verifier.SystemState(
        packages={
            identity: (version, "install ok installed")
            for identity, version in expected.items()
        },
        selections={name: "install" for name, _ in expected},
        foreign_architectures=(),
        alternatives={b"awk": awk_state},
    )
    verifier.verify_host_plan(
        expected, exact_before, verifier.parse_apt_plan_bytes(b"", allow_empty=True)
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_host_plan(
            expected,
            before,
            verifier.parse_apt_plan_bytes(
                b"""Inst libc6 (2.39-0ubuntu8.7 local-deb [amd64])
Conf libc6 (2.39-0ubuntu8.7 local-deb [amd64])
Inst apt [2.8.1] (2.8.3 Ubuntu:24.04/noble-updates [amd64])
Conf apt (2.8.3 Ubuntu:24.04/noble-updates [amd64])
"""
            ),
        ),
        "wrong host-plan old version",
        "host apt plan has wrong prior version: apt:amd64",
    )

    serialized = verifier.serialize_system_state(before)
    if verifier.parse_system_state_bytes(serialized) != before:
        raise SystemExit("system-state serialization did not round-trip")
    original_state_bound = verifier.MAX_SYSTEM_STATE_BYTES
    verifier.MAX_SYSTEM_STATE_BYTES = len(serialized)
    try:
        if verifier.serialize_system_state(before) != serialized:
            raise SystemExit("system-state exact size bound changed its bytes")
        if verifier.parse_system_state_bytes(serialized) != before:
            raise SystemExit("system-state parser rejected its exact size bound")
        verifier.MAX_SYSTEM_STATE_BYTES = len(serialized) - 1
        require_rejected(
            verifier,
            lambda: verifier.serialize_system_state(before),
            "system-state serializer size bound",
            "system state exceeds its size bound",
        )
        require_rejected(
            verifier,
            lambda: verifier.parse_system_state_bytes(serialized),
            "system-state parser size bound",
            "system state is empty or exceeds its size bound",
        )
    finally:
        verifier.MAX_SYSTEM_STATE_BYTES = original_state_bound
    for label, separator in (
        ("VT", b"\v"),
        ("FF", b"\f"),
        ("FS", b"\x1c"),
        ("GS", b"\x1d"),
        ("RS", b"\x1e"),
    ):
        require_rejected(
            verifier,
            lambda separator=separator: verifier.parse_system_state_bytes(
                serialized.replace(b"\n", separator, 1)
            ),
            f"{label} system-state line separator",
            "system state has invalid line framing",
            exact=True,
        )
    for label, hostile_state, expected_error in (
        (
            "CR system-state line separator",
            serialized.replace(b"\n", b"\r", 1),
            "system state has invalid line framing",
        ),
        (
            "CRLF system-state line separator",
            serialized.replace(b"\n", b"\r\n", 1),
            "system state has invalid line framing",
        ),
        (
            "embedded CR system-state field",
            serialized.replace(b"tb321fu", b"tb321\rfu", 1),
            "system state has invalid line framing",
        ),
        (
            "embedded NUL system-state field",
            serialized.replace(b"tb321fu", b"tb321\0fu", 1),
            "system state has invalid line framing",
        ),
        (
            "system state missing terminal LF",
            serialized[:-1],
            "system state has invalid line framing",
        ),
        (
            "system state non-ASCII byte",
            serialized.replace(b"tb321fu", b"tb321\xfffu", 1),
            "system state must contain ASCII only",
        ),
        (
            "system state UTF-8 NEL boundary",
            serialized.replace(b"\n", b"\xc2\x85", 1),
            "system state must contain ASCII only",
        ),
        (
            "system state UTF-8 line separator",
            serialized.replace(b"\n", b"\xe2\x80\xa8", 1),
            "system state must contain ASCII only",
        ),
        (
            "system state UTF-8 paragraph separator",
            serialized.replace(b"\n", b"\xe2\x80\xa9", 1),
            "system state must contain ASCII only",
        ),
    ):
        require_rejected(
            verifier,
            lambda hostile_state=hostile_state: verifier.parse_system_state_bytes(
                hostile_state
            ),
            label,
            expected_error,
            exact=True,
        )
    require_rejected(
        verifier,
        lambda: verifier.parse_system_state_bytes(
            serialized.replace(
                b"alternative\t61776b\t",
                b"alternative\t2f\t",
                1,
            )
        ),
        "slash alternative state name",
        "system state contains an invalid state name",
    )
    alternative_lines = [
        line + b"\n"
        for line in serialized[:-1].split(b"\n")
        if line.startswith(b"alternative\t")
    ]
    if len(alternative_lines) != 2:
        raise SystemExit("system-state fixture lost its two alternative records")
    unsorted_alternatives = serialized.replace(
        alternative_lines[0] + alternative_lines[1],
        alternative_lines[1] + alternative_lines[0],
        1,
    )
    awk_target_hex = before_awk.target.hex().encode("ascii")
    for label, hostile_state, expected_error in (
        (
            "legacy v2 system-state schema",
            serialized.replace(
                b"tb321fu.haptics-system-state/v3",
                b"tb321fu.haptics-system-state/v2",
                1,
            ),
            "system state schema mismatch",
        ),
        (
            "uppercase alternative state name hex",
            serialized.replace(b"alternative\t61776b\t", b"alternative\t61776B\t", 1),
            "invalid alternative state record",
        ),
        (
            "odd alternative state name hex",
            serialized.replace(b"alternative\t61776b\t", b"alternative\t61776\t", 1),
            "invalid alternative state record",
        ),
        (
            "uppercase alternative state target hex",
            serialized.replace(
                b"\t" + awk_target_hex + b"\t",
                b"\t" + awk_target_hex.replace(b"f", b"F", 1) + b"\t",
                1,
            ),
            "invalid alternative state record",
        ),
        (
            "odd alternative state target hex",
            serialized.replace(
                b"\t" + awk_target_hex + b"\t",
                b"\t" + awk_target_hex[:-1] + b"\t",
                1,
            ),
            "invalid alternative state record",
        ),
        (
            "relative alternative state target",
            serialized.replace(
                b"\t" + awk_target_hex + b"\t",
                b"\t" + b"relative".hex().encode("ascii") + b"\t",
                1,
            ),
            "system state contains an invalid state target",
        ),
        (
            "uppercase alternative state digest",
            serialized.replace(b"\t" + b"1" * 64 + b"\n", b"\t" + b"A" * 64 + b"\n", 1),
            "invalid alternative state record",
        ),
        (
            "unsorted alternative state records",
            unsorted_alternatives,
            "system state alternative records are duplicate or unsorted",
        ),
        (
            "blank system-state record",
            serialized + b"\n",
            "system state record is out of section order",
        ),
    ):
        require_rejected(
            verifier,
            lambda hostile_state=hostile_state: verifier.parse_system_state_bytes(
                hostile_state
            ),
            label,
            expected_error,
        )
    first_package = b"package\tapt\tamd64\t2.8.2\tinstall ok installed\n"
    require_rejected(
        verifier,
        lambda: verifier.parse_system_state_bytes(
            serialized.replace(
                first_package,
                first_package + b"package\tapt\tamd64\t2.8.3\tinstall ok installed\n",
            )
        ),
        "duplicate system-state package",
        "invalid package state record",
    )

    hostile_package = verifier.SystemState(
        packages={
            **after.packages,
            ("base-files", "amd64"): ("13ubuntu10.5", "install ok installed"),
        },
        selections=after.selections,
        foreign_architectures=(),
        alternatives=after.alternatives,
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_state_transition(
            expected, {"awk": ("manual", "/usr/bin/gawk")}, before, hostile_package
        ),
        "unlocked package upgrade",
        "package outside the lock changed: base-files:amd64",
    )
    hostile_foreign = verifier.SystemState(
        packages=after.packages,
        selections=after.selections,
        foreign_architectures=("arm64",),
        alternatives=after.alternatives,
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_baseline_state(hostile_foreign),
        "foreign architecture baseline",
        "foreign dpkg architectures are not allowed",
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_state_transition(
            expected, {"awk": ("manual", "/usr/bin/gawk")}, before, hostile_foreign
        ),
        "foreign architecture",
        "foreign dpkg architectures are not allowed",
    )
    hostile_alternative = verifier.SystemState(
        packages=after.packages,
        selections=after.selections,
        foreign_architectures=(),
        alternatives={
            **after.alternatives,
            b"editor": verifier.AlternativeState(
                "manual", b"/usr/bin/nano", "3" * 64
            ),
        },
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_state_transition(
            expected,
            {"awk": ("manual", "/usr/bin/gawk")},
            before,
            hostile_alternative,
        ),
        "unlocked alternative",
        "alternative outside the lock changed: editor",
    )
    hostile_editor_digest = verifier.SystemState(
        packages=after.packages,
        selections=after.selections,
        foreign_architectures=(),
        alternatives={
            **after.alternatives,
            b"editor": verifier.AlternativeState(
                editor_state.mode, editor_state.target, "4" * 64
            ),
        },
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_state_transition(
            expected,
            {"awk": ("manual", "/usr/bin/gawk")},
            before,
            hostile_editor_digest,
        ),
        "unlocked alternative complete-state digest",
        "alternative outside the lock changed: editor",
    )
    for label, drifted_awk in awk_drift_states.items():
        hostile_awk = verifier.SystemState(
            packages=after.packages,
            selections=after.selections,
            foreign_architectures=(),
            alternatives={**after.alternatives, b"awk": drifted_awk},
        )
        require_rejected(
            verifier,
            lambda hostile_awk=hostile_awk: verifier.verify_state_transition(
                expected,
                {"awk": ("manual", "/usr/bin/gawk")},
                before,
                hostile_awk,
            ),
            f"awk {label} drift",
            "locked alternative has wrong complete group state: awk",
        )
    hostile_status = verifier.SystemState(
        packages={**after.packages, ("apt", "amd64"): ("2.8.3", "install ok unpacked")},
        selections=after.selections,
        foreign_architectures=(),
        alternatives=after.alternatives,
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_state_transition(
            expected, {"awk": ("manual", "/usr/bin/gawk")}, before, hostile_status
        ),
        "non-installed final state",
        "locked package has wrong final state: apt:amd64",
    )
    hostile_selection = verifier.SystemState(
        packages=after.packages,
        selections={**after.selections, "apt": "hold"},
        foreign_architectures=(),
        alternatives=after.alternatives,
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_state_transition(
            expected,
            {"awk": ("manual", "/usr/bin/gawk")},
            before,
            hostile_selection,
        ),
        "held final package",
        "locked package has wrong final selection: apt:amd64",
    )

    print("HAPTICS_PACKAGE_TRANSACTION_FIXTURE=PASS")


if __name__ == "__main__":
    main()
