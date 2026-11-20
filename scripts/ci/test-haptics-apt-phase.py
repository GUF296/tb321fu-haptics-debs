#!/usr/bin/env python3
"""Hostile fixtures for the bounded APT runner and installer custody."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import fcntl
import functools
import os
import pathlib
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from unittest import mock


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
RUNNER = SCRIPT_DIR / "run-haptics-apt-phase.py"
INSTALLER = SCRIPT_DIR / "install-haptics-build-dependencies.sh"
PYTHON = "/usr/bin/python3"
FLOOD_CHUNK = b"f" * (1024 * 1024 - 1) + b"\n"
STDOUT_CHUNK = b"o" * (1024 * 1024 - 1) + b"\n"
FLOOD_SIZE = 57_671_764
FLOOD_LINES = 58
FLOOD_SHA256 = "e6dfcb52301d46155bdb00f12c66a30ee83f5faa48f7db926916516b317ae389"
DUAL_STDOUT_CHUNK = b"u" * (256 * 1024 - 1) + b"\n"
DUAL_STDERR_CHUNK = b"v" * (256 * 1024 - 1) + b"\n"
DUAL_CHUNKS = 16


def load_fixture_support():
    spec = importlib.util.spec_from_file_location(
        "haptics_apt_fixture_support", SCRIPT_DIR / "haptics-apt-fixture-support.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load fixture custody support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FIXTURE_SUPPORT = load_fixture_support()
ProcessIdentity = FIXTURE_SUPPORT.ProcessIdentity
FIXTURE_LEDGERS: list[object] = []


def managed_fixture(function):
    @functools.wraps(function)
    def wrapped(*arguments, **keywords):
        with FIXTURE_SUPPORT.CleanupLedger() as cleanup:
            FIXTURE_LEDGERS.append(cleanup)
            try:
                return function(*arguments, **keywords)
            finally:
                FIXTURE_LEDGERS.pop()
    return wrapped


def current_fixture_cleanup():
    if not FIXTURE_LEDGERS:
        raise SystemExit("fixture process has no cleanup owner")
    return FIXTURE_LEDGERS[-1]


def identity_record_path(output: pathlib.Path) -> pathlib.Path:
    return output.with_name(output.name + ".identity")


def read_fixture_identities(path: pathlib.Path) -> tuple[ProcessIdentity, ...]:
    records = []
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise SystemExit("malformed fixture birth identity record")
        records.append(ProcessIdentity(int(fields[0], 10), fields[1]))
    if not records or len({record.pid for record in records}) != len(records):
        raise SystemExit("empty or duplicate fixture birth identity record")
    return tuple(records)


def recorded_identity(path: pathlib.Path, pid: int) -> ProcessIdentity:
    identities = [identity for identity in read_fixture_identities(path) if identity.pid == pid]
    if len(identities) != 1:
        raise SystemExit("published fixture PID has no unique birth identity")
    return identities[0]


def cleanup_identity_record(path: pathlib.Path) -> bool:
    if not path.exists():
        return False
    identities = read_fixture_identities(path)
    changed = False
    with FIXTURE_SUPPORT.CleanupLedger() as cleanup:
        for identity in identities:
            def remove(identity=identity):
                nonlocal changed
                changed = FIXTURE_SUPPORT.kill_identity(identity) or changed
            cleanup.add(f"published identity {identity.pid}", remove, kind="release")
    return changed


def fixture_popen(*arguments, **keywords):
    cleanup = current_fixture_cleanup()
    command = arguments[0] if arguments else keywords.get("args", ())
    record_text = keywords.get("env", os.environ).get("HAPTICS_TEST_IDENTITY_RECORD")
    if "--fixture-identity-record" in command:
        record_text = command[command.index("--fixture-identity-record") + 1]
    if record_text:
        path = pathlib.Path(record_text)
        cleanup.add("published fixture processes", lambda: cleanup_identity_record(path))
    process, identity = FIXTURE_SUPPORT.spawn_fixture_process(
        *arguments, cleanup=cleanup, **keywords
    )
    process.fixture_birth_identity = identity
    return process


@managed_fixture
def fixture_run(command, *, check=False, timeout=None, **keywords):
    process = fixture_popen(command, **keywords)
    stdout, stderr = process.communicate(timeout=timeout)
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


def publish_fixture_identities(path: pathlib.Path | None, *pids: int) -> None:
    if path is None:
        return
    records = []
    for pid in pids:
        start = process_start_time(pid)
        if start is None:
            raise SystemExit("fixture lost process before birth publication")
        records.append(ProcessIdentity(pid, start))
    path.write_text("".join(f"{item.pid} {item.start_time}\n" for item in records), encoding="ascii")


def fixture(mode: str, arguments: list[str]) -> None:
    record_text = os.environ.get("HAPTICS_TEST_IDENTITY_RECORD")
    if len(arguments) >= 2 and arguments[-2] == "--fixture-identity-record":
        record_text = arguments[-1]
        arguments = arguments[:-2]
    record = pathlib.Path(record_text) if record_text else None
    if mode == "status":
        print("status-stdout", flush=True)
        print("status-stderr", file=sys.stderr, flush=True)
        raise SystemExit(int(arguments[0], 10))
    if mode == "delayed-status":
        time.sleep(0.35)
        raise SystemExit(int(arguments[0], 10))
    if mode == "flood":
        beginning = b"begin \x1b[31m\n"
        ending = b"end-sentinel\n"
        os.write(2, beginning)
        for index in range(55):
            if index == 27:
                os.write(
                    2,
                    b"N: Download is performed unsandboxed as root hidden-middle\n",
                )
            os.write(2, FLOOD_CHUNK)
        os.write(2, ending)
        raise SystemExit(73)
    if mode == "dual-flood":
        def emit(descriptor: int, chunk: bytes) -> None:
            for _ in range(DUAL_CHUNKS):
                os.write(descriptor, chunk)

        stdout_thread = threading.Thread(target=emit, args=(1, DUAL_STDOUT_CHUNK))
        stderr_thread = threading.Thread(target=emit, args=(2, DUAL_STDERR_CHUNK))
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()
        raise SystemExit(77)
    if mode == "diagnostic-backpressure":
        def emit_control_stream(descriptor: int) -> None:
            os.write(descriptor, b"\x00" * (1024 * 1024))

        stdout_thread = threading.Thread(target=emit_control_stream, args=(1,))
        stderr_thread = threading.Thread(target=emit_control_stream, args=(2,))
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()
        raise SystemExit(77)
    if mode == "private-controls":
        os.write(
            2,
            b"E: private="
            + os.fsencode(arguments[0])
            + b" \x1b[31m\r\x00\n::error::hostile\n",
        )
        raise SystemExit(72)
    if mode == "long-cause":
        private_root = os.fsencode(arguments[0])
        os.write(
            2,
            b"x" * 5000
            + b"E: long-no-newline private="
            + private_root
            + b" suffix",
        )
        raise SystemExit(74)
    if mode == "boundary-private":
        private_root = os.fsencode(arguments[0])
        padding = b"p" * (16 * 1024 - 5)
        os.write(2, padding + private_root + b" final-boundary\n")
        raise SystemExit(75)
    if mode == "stdout-sandbox":
        os.write(1, b"N: Download is performed unsandboxed as root\n")
        raise SystemExit(0)
    if mode == "stdout-overflow":
        for _ in range(33):
            os.write(1, STDOUT_CHUNK)
        raise SystemExit(0)
    if mode in (
        "detached-descendant",
        "detached-descendant-status",
        "timeout-descendant",
    ):
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                time.sleep(30)
            finally:
                os._exit(0)
        publish_fixture_identities(record, child)
        print(child, flush=True)
        if mode == "timeout-descendant":
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            time.sleep(30)
        raise SystemExit(77 if mode == "detached-descendant-status" else 0)
    if mode == "pipe-eof":
        os.close(1)
        os.close(2)
        time.sleep(0.35)
        raise SystemExit(77)
    if mode == "wait":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        publish_fixture_identities(record, os.getpid())
        print(os.getpid(), flush=True)
        time.sleep(30)
        raise SystemExit(91)
    if mode == "supervisor-death-detached":
        if record is None:
            raise SystemExit("supervisor-death fixture has no birth record")
        # Publish the parent relationship while the target is first starting,
        # not by discovering an arbitrary current parent at injection time.
        custodian_pid = os.getppid()
        custodian_start = process_start_time(custodian_pid)
        if custodian_start is None or os.getppid() != custodian_pid:
            raise SystemExit("supervisor-death custodian changed during birth publication")
        record.with_name(record.name + ".custodian").write_text(
            f"{custodian_pid} {custodian_start}\n", encoding="ascii"
        )
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                    signal.signal(signum, signal.SIG_IGN)
                time.sleep(30)
            finally:
                os._exit(0)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, signal.SIG_IGN)
        publish_fixture_identities(record, os.getpid(), child)
        print(f"{os.getpid()} {child}", flush=True)
        time.sleep(30)
        raise SystemExit(92)
    if mode == "kill-custodian":
        os.kill(os.getppid(), signal.SIGKILL)
        time.sleep(30)
        raise SystemExit(93)
    if mode == "installer-sentinel":
        publish_fixture_identities(record, os.getpid())
        pathlib.Path(os.environ["HAPTICS_TEST_COMMAND_SENTINEL"]).write_text(
            "executed\n", encoding="ascii"
        )
        print(os.getpid(), flush=True)
        raise SystemExit(0)
    if mode == "identity-settlement-wait":
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, signal.SIG_IGN)
        pid = os.getpid()
        start_time = process_start_time(pid)
        if start_time is None:
            raise SystemExit("identity settlement target lost its own identity")
        pathlib.Path(os.environ["HAPTICS_TEST_IDENTITY_TARGET_RECORD"]).write_text(
            f"{pid} {start_time}\n", encoding="ascii"
        )
        time.sleep(30)
        raise SystemExit(91)
    if mode == "replace-output":
        output = pathlib.Path(arguments[0])
        time.sleep(0.1)
        output.unlink()
        output.write_bytes(b"replacement-owned-by-fixture\n")
        output.chmod(0o600)
        print("orphaned-original-output", flush=True)
        raise SystemExit(0)
    if mode == "replace-parent":
        parent = pathlib.Path(arguments[0])
        replacement_target = pathlib.Path(arguments[1])
        time.sleep(0.1)
        parent.rename(replacement_target)
        parent.mkdir(mode=0o700)
        print("orphaned-parent-output", flush=True)
        raise SystemExit(0)
    if mode == "handoff-detached":
        pid_file = pathlib.Path(arguments[0])
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                pid_file.write_text(str(os.getpid()), encoding="ascii")
                time.sleep(30)
            finally:
                os._exit(0)
        time.sleep(30)
        raise SystemExit(0)
    raise SystemExit("unknown fixture mode")


def runner_command(
    root: pathlib.Path,
    output: pathlib.Path,
    phase: str,
    timeout: float,
    fixture_mode: str,
    *fixture_arguments: str,
) -> list[str]:
    return [
        PYTHON,
        "-I",
        "-B",
        str(RUNNER),
        "--phase",
        phase,
        "--timeout-seconds",
        str(timeout),
        "--private-root",
        str(root),
        "--stdout",
        str(output),
        "--",
        PYTHON,
        "-I",
        "-B",
        str(pathlib.Path(__file__).resolve()),
        "--fixture",
        fixture_mode,
        *fixture_arguments,
        "--fixture-identity-record",
        str(identity_record_path(output)),
    ]


def run_runner(
    root: pathlib.Path,
    name: str,
    phase: str,
    timeout: float,
    fixture_mode: str,
    *fixture_arguments: str,
) -> tuple[subprocess.CompletedProcess[bytes], pathlib.Path]:
    output = root / name
    result = fixture_run(
        runner_command(
            root,
            output,
            phase,
            timeout,
            fixture_mode,
            *fixture_arguments,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=max(timeout + 8.0, 12.0),
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    return result, output


def require_status(result: subprocess.CompletedProcess[bytes], status: int, label: str) -> None:
    if result.returncode != status:
        raise SystemExit(
            f"{label} returned {result.returncode}, expected {status}: "
            + repr(result.stderr[:8192])
        )


def signal_exact_identity(pid: int, start_time: str, signum: int) -> bool:
    return FIXTURE_SUPPORT.signal_identity(ProcessIdentity(pid, start_time), signum)


def cleanup_exact_identity(pid: int, start_time: str) -> bool:
    return FIXTURE_SUPPORT.kill_identity(ProcessIdentity(pid, start_time))


def cleanup_handoff_child(identity: ProcessIdentity) -> bool:
    """These unit-created direct children have no surviving fixture Popen owner."""
    changed = FIXTURE_SUPPORT.signal_identity(identity, signal.SIGKILL)
    deadline = time.monotonic() + 3.0
    while FIXTURE_SUPPORT.identity_exists(identity):
        try:
            os.waitpid(identity.pid, os.WNOHANG)
        except ChildProcessError:
            pass
        if time.monotonic() >= deadline:
            raise SystemExit("fixture handoff child did not converge")
        time.sleep(0.01)
    return changed


def require_pid_gone(
    pid: int,
    label: str,
    start_time: str,
) -> None:
    try:
        FIXTURE_SUPPORT.require_identity_gone(ProcessIdentity(pid, start_time), timeout=2.0)
    except BaseException as error:
        error.add_note(label)
        raise


def converge_fixture_process(
    process: subprocess.Popen[bytes],
) -> bool:
    return FIXTURE_SUPPORT.converge_process(process, process.fixture_birth_identity)


@managed_fixture
def run_signal_fixture(
    root: pathlib.Path,
    signum: int,
    expected_status: int,
) -> None:
    label = signal.Signals(signum).name.lower()
    output = root / f"cancel-{label}.out"
    process = fixture_popen(
        runner_command(root, output, f"cancel-{label}", 10, "wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    child_pid: int | None = None
    child_start: str | None = None
    emergency = False
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if output.exists() and output.stat().st_size:
                break
            if process.poll() is not None:
                break
            time.sleep(0.02)
        if not output.exists() or not output.stat().st_size:
            raise SystemExit(f"{label} fixture did not reach its signal boundary")
        child_pid = int(output.read_text("ascii").strip(), 10)
        child_start = recorded_identity(identity_record_path(output), child_pid).start_time
        FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signum)
        public_stdout, public_stderr = process.communicate(timeout=8.0)
        require_pid_gone(child_pid, f"{label} phase", child_start)
        if process.returncode != expected_status or public_stdout:
            raise SystemExit(
                f"real {label} did not preserve status {expected_status}: "
                + repr(public_stderr[:8192])
            )
        if (
            f"status={expected_status} command_status=".encode("ascii")
            not in public_stderr
            or b"reason=caller-cancelled" not in public_stderr
        ):
            raise SystemExit(f"{label} phase lost caller and command status evidence")
    finally:
        finish_fixture_cleanup(process)


def load_runner():
    spec = importlib.util.spec_from_file_location("haptics_apt_phase_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT phase runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def descriptor_set() -> frozenset[int]:
    with os.scandir("/proc/self/fd") as entries:
        descriptors = {
            int(entry.name, 10)
            for entry in entries
            if entry.name.isascii() and entry.name.isdigit()
        }
    return frozenset(
        descriptor
        for descriptor in descriptors
        if _descriptor_open(descriptor)
    )


def _descriptor_open(descriptor: int) -> bool:
    try:
        os.fstat(descriptor)
    except OSError:
        return False
    return True


@managed_fixture
def unit_spawn_handoff(root: pathlib.Path) -> None:
    module = load_runner()
    original_popen = module.subprocess.Popen
    spawned: list[ProcessIdentity] = []

    def construct_then_raise(*arguments, **keywords):
        process = original_popen(*arguments, **keywords)
        identity = FIXTURE_SUPPORT.capture_child_identity(process)
        spawned.append(identity)
        cleanup = current_fixture_cleanup()
        cleanup.add("handoff process identity", lambda: cleanup_handoff_child(identity))
        raise KeyboardInterrupt("injected Popen initializer handoff cancellation")

    before = descriptor_set()
    module.subprocess.Popen = construct_then_raise
    try:
        status = module.run_phase(
            "spawn-handoff",
            5.0,
            str(root),
            str(root / "spawn-handoff.out"),
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--fixture",
                "wait",
            ],
        )
    finally:
        module.subprocess.Popen = original_popen
    if status != 125 or len(spawned) != 1:
        raise SystemExit("Popen initializer handoff did not fail closed")
    require_pid_gone(spawned[0].pid, "Popen initializer handoff", spawned[0].start_time)
    if descriptor_set() != before or module.direct_children():
        raise SystemExit("Popen initializer handoff leaked fd or child custody")
    print("HAPTICS_APT_PHASE_SPAWN_HANDOFF=PASS")


@managed_fixture
def unit_pidfd_handoff(root: pathlib.Path) -> None:
    module = load_runner()
    original_pidfd_open = module.os.pidfd_open
    pid_file = root / "pidfd-handoff-descendant.pid"
    opened: list[int] = []
    opened_pids: list[ProcessIdentity] = []
    injected = False

    def open_then_raise(pid: int, flags: int = 0) -> int:
        nonlocal injected
        if injected:
            return original_pidfd_open(pid, flags)
        injected = True
        descriptor = original_pidfd_open(pid, flags)
        opened.append(descriptor)
        start = process_start_time(pid)
        if start is None:
            raise SystemExit("pidfd handoff child vanished before identity publication")
        identity = ProcessIdentity(pid, start)
        opened_pids.append(identity)
        current_fixture_cleanup().add("pidfd handoff child", lambda: cleanup_handoff_child(identity))
        deadline = time.monotonic() + 1.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise OSError("injected pidfd applied-then-raise handoff failure")

    before = descriptor_set()
    module.os.pidfd_open = open_then_raise
    try:
        status = module.run_phase(
            "pidfd-handoff",
            5.0,
            str(root),
            str(root / "pidfd-handoff.out"),
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--fixture",
                "handoff-detached",
                str(pid_file),
            ],
        )
    finally:
        module.os.pidfd_open = original_pidfd_open
    if status != 125 or not opened or not opened_pids or pid_file.exists():
        raise SystemExit("pidfd handoff failure did not fail closed")
    require_pid_gone(opened_pids[0].pid, "pidfd handoff exec gate", opened_pids[0].start_time)
    if any(_descriptor_open(descriptor) for descriptor in opened):
        raise SystemExit("pidfd handoff retained an applied-then-raised descriptor")
    if descriptor_set() != before or module.direct_children():
        raise SystemExit("pidfd handoff leaked fd or child custody")
    print("HAPTICS_APT_PHASE_PIDFD_HANDOFF=PASS")


def unit_cleanup_failure(root: pathlib.Path) -> None:
    module = load_runner()
    original_apply = module.apply_subreaper
    previous = module.inspect_subreaper()
    before = descriptor_set()
    apply_calls = 0

    def restore_then_raise(enabled: bool) -> None:
        nonlocal apply_calls
        apply_calls += 1
        original_apply(enabled)
        if apply_calls > 1 and enabled == previous:
            raise OSError("injected subreaper restore post-apply failure")

    module.apply_subreaper = restore_then_raise
    try:
        statuses = (
            module.run_phase(
                "cleanup-success",
                5.0,
                str(root),
                str(root / "cleanup-success.out"),
                ["/bin/printf", "cleanup-success"],
            ),
            module.run_phase(
                "cleanup-nonzero",
                5.0,
                str(root),
                str(root / "cleanup-nonzero.out"),
                [
                    PYTHON,
                    "-I",
                    "-B",
                    str(pathlib.Path(__file__).resolve()),
                    "--fixture",
                    "status",
                    "77",
                ],
            ),
            module.run_phase(
                "cleanup-timeout",
                0.2,
                str(root),
                str(root / "cleanup-timeout.out"),
                [
                    PYTHON,
                    "-I",
                    "-B",
                    str(pathlib.Path(__file__).resolve()),
                    "--fixture",
                    "wait",
                ],
            ),
        )
    finally:
        module.apply_subreaper = original_apply
    if statuses != (125, 77, 124) or module.inspect_subreaper() != previous:
        raise SystemExit(
            "cleanup failure did not preserve success/nonzero/timeout precedence: "
            + repr(statuses)
        )
    if descriptor_set() != before or module.direct_children():
        raise SystemExit("cleanup failure leaked fd or child custody")
    print("HAPTICS_APT_PHASE_CLEANUP_FAILURE=PASS")


def unit_final_signal_boundary(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_settle = module.settle_output
    delivered = False

    def settle_then_signal(owner) -> None:
        nonlocal delivered
        original_settle(owner)
        if not delivered:
            delivered = True
            os.kill(os.getpid(), signal.SIGTERM)

    module.settle_output = settle_then_signal
    try:
        status = module.run_phase(
            "final-signal",
            5.0,
            str(root),
            str(root / "final-signal.out"),
            ["/bin/printf", "final-signal"],
        )
    finally:
        module.settle_output = original_settle
    if (
        status != 143
        or not delivered
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("final signal boundary lost status or resource custody")
    print("HAPTICS_APT_PHASE_FINAL_SIGNAL=PASS")


def unit_prepare_signal_boundary(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_prepare = module.prepare_output
    output = root / "prepare-signal.out"
    sentinel = root / "prepare-signal.command-ran"
    delivered = False

    def prepare_then_signal(private_root: str, output_path: str):
        nonlocal delivered
        prepared = original_prepare(private_root, output_path)
        if not delivered:
            delivered = True
            os.kill(os.getpid(), signal.SIGTERM)
        return prepared

    module.prepare_output = prepare_then_signal
    try:
        status = module.run_phase(
            "prepare-signal",
            5.0,
            str(root),
            str(output),
            ["/usr/bin/touch", str(sentinel)],
        )
    finally:
        module.prepare_output = original_prepare
    if (
        status != 143
        or not delivered
        or output.exists()
        or sentinel.exists()
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("prepare-output signal boundary lost cancellation custody")
    print("HAPTICS_APT_PHASE_PREPARE_SIGNAL=PASS")


def unit_prespawn_signal_boundary(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_selector = module.selectors.DefaultSelector
    output = root / "prespawn-signal.out"
    sentinel = root / "prespawn-signal.command-ran"
    delivered = False

    def selector_then_signal():
        nonlocal delivered
        selector = original_selector()
        if not delivered:
            delivered = True
            os.kill(os.getpid(), signal.SIGTERM)
        return selector

    module.selectors.DefaultSelector = selector_then_signal
    try:
        status = module.run_phase(
            "prespawn-signal",
            5.0,
            str(root),
            str(output),
            ["/usr/bin/touch", str(sentinel)],
        )
    finally:
        module.selectors.DefaultSelector = original_selector
    if (
        status != 143
        or not delivered
        or output.exists()
        or sentinel.exists()
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("pre-spawn pending signal did not suppress command launch")
    print("HAPTICS_APT_PHASE_PRESPAWN_SIGNAL=PASS")


def unit_spawn_commit_signal_boundary(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_popen = module.subprocess.Popen
    output = root / "spawn-commit-signal.out"
    sentinel = root / "spawn-commit-signal.command-ran"
    delivered = False

    def signal_then_popen(*args, **kwargs):
        nonlocal delivered
        if not delivered:
            delivered = True
            os.kill(os.getpid(), signal.SIGTERM)
        result = original_popen(*args, **kwargs)
        deadline = time.monotonic() + 0.5
        while not sentinel.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        return result

    module.subprocess.Popen = signal_then_popen
    try:
        status = module.run_phase(
            "spawn-commit-signal",
            5.0,
            str(root),
            str(output),
            ["/usr/bin/touch", str(sentinel)],
        )
    finally:
        module.subprocess.Popen = original_popen
    if (
        status != 143
        or not delivered
        or output.exists()
        or sentinel.exists()
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("spawn-commit signal executed the untrusted command")
    print("HAPTICS_APT_PHASE_SPAWN_COMMIT_SIGNAL=PASS")


def unit_deadline_observation_boundary(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_spawn = module.spawn_owned_process
    delayed = False

    def spawn_then_delay(owner, command, child_setup) -> None:
        nonlocal delayed
        original_spawn(owner, command, child_setup)
        delayed = True
        time.sleep(0.4)

    module.spawn_owned_process = spawn_then_delay
    try:
        status = module.run_phase(
            "deadline-observe",
            0.2,
            str(root),
            str(root / "deadline-observe.out"),
            ["/bin/true"],
        )
    finally:
        module.spawn_owned_process = original_spawn
    if (
        status != 124
        or not delayed
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("absolute deadline was lost after delayed leader observation")
    print("HAPTICS_APT_PHASE_DEADLINE_OBSERVATION=PASS")


def unit_terminal_sigpending_failure(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_sigpending = module.signal.sigpending
    calls = 0

    def fail_second_sigpending():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected terminal sigpending failure")
        return original_sigpending()

    module.signal.sigpending = fail_second_sigpending
    try:
        status = module.run_phase(
            "late-sigpending",
            5.0,
            str(root),
            str(root / "late-sigpending.out"),
            ["/bin/true"],
        )
    finally:
        module.signal.sigpending = original_sigpending
    if (
        status != 125
        or calls < 2
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("terminal sigpending failure did not fail closed")
    print("HAPTICS_APT_PHASE_TERMINAL_SIGPENDING=PASS")


def unit_restrictive_umask_output(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    output = root / "restrictive-umask.out"
    sentinel = root / "restrictive-umask.command-ran"
    original_fchmod = module.os.fchmod
    fchmod_applied = False

    def fchmod_then_raise(descriptor: int, mode: int) -> None:
        nonlocal fchmod_applied
        original_fchmod(descriptor, mode)
        fchmod_applied = True
        raise OSError("injected post-fchmod output failure")

    previous_umask = os.umask(0o777)
    module.os.fchmod = fchmod_then_raise
    try:
        try:
            status = module.run_phase(
                "restrictive-umask",
                5.0,
                str(root),
                str(output),
                ["/usr/bin/touch", str(sentinel)],
            )
        except module.PhaseError:
            status = 125
    finally:
        module.os.fchmod = original_fchmod
        os.umask(previous_umask)
    if (
        status != 125
        or not fchmod_applied
        or output.exists()
        or sentinel.exists()
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("restrictive umask left an unauthenticated output inode")
    print("HAPTICS_APT_PHASE_RESTRICTIVE_UMASK=PASS")


def unit_final_signal_handoff(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_mask = module.signal.pthread_sigmask
    original_term_handler = signal.getsignal(signal.SIGTERM)
    setmask_calls = 0
    delivered = False
    prior_handler_called = False

    def prior_handler(_signum: int, _frame: object) -> None:
        nonlocal prior_handler_called
        prior_handler_called = True

    def mask_then_signal(operation, mask):
        nonlocal delivered, setmask_calls
        if operation == signal.SIG_SETMASK:
            setmask_calls += 1
            if setmask_calls == 2:
                delivered = True
                os.kill(os.getpid(), signal.SIGTERM)
        return original_mask(operation, mask)

    signal.signal(signal.SIGTERM, prior_handler)
    module.signal.pthread_sigmask = mask_then_signal
    try:
        status = module.run_phase(
            "signal-handoff",
            5.0,
            str(root),
            str(root / "signal-handoff.out"),
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--fixture",
                "status",
                "77",
            ],
        )
    finally:
        module.signal.pthread_sigmask = original_mask
        signal.signal(signal.SIGTERM, original_term_handler)
    if (
        status != 77
        or not delivered
        or not prior_handler_called
        or setmask_calls != 2
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("final signal-mask handoff did not restore prior custody")
    print("HAPTICS_APT_PHASE_SIGNAL_HANDOFF=PASS")


def unit_handler_restore_signal_boundary(root: pathlib.Path) -> None:
    module = load_runner()
    before = descriptor_set()
    previous = module.inspect_subreaper()
    original_signal = module.signal.signal
    parent_pid = os.getpid()
    delivered = False

    def restore_then_signal(signum, handler):
        nonlocal delivered
        result = original_signal(signum, handler)
        if (
            os.getpid() == parent_pid
            and signum == signal.SIGTERM
            and handler is signal.SIG_DFL
            and not delivered
        ):
            delivered = True
            os.kill(parent_pid, signal.SIGTERM)
        return result

    module.signal.signal = restore_then_signal
    try:
        status = module.run_phase(
            "handler-restore-signal",
            5.0,
            str(root),
            str(root / "handler-restore-signal.out"),
            ["/bin/true"],
        )
    finally:
        module.signal.signal = original_signal
    if (
        status != 143
        or not delivered
        or module.inspect_subreaper() != previous
        or descriptor_set() != before
        or module.direct_children()
    ):
        raise SystemExit("signal-handler restoration lost cancellation custody")
    print("HAPTICS_APT_PHASE_HANDLER_RESTORE_SIGNAL=PASS")


def unit_exec_gate_failures(root: pathlib.Path) -> None:
    denied = root / "exec-gate-denied"
    denied_sentinel = root / "exec-gate-denied.command-ran"
    denied.write_text(
        f"#!/bin/sh\ntouch -- {denied_sentinel}\n",
        encoding="ascii",
    )
    denied.chmod(0o600)
    invalid = root / "exec-gate-invalid"
    invalid.write_bytes(b"not-an-executable\n")
    invalid.chmod(0o700)
    cases = (
        ("missing", ["/definitely/not/a/real/haptics-command"]),
        ("denied", [str(denied)]),
        ("invalid", [str(invalid)]),
    )
    for name, command in cases:
        output = root / f"exec-gate-{name}.out"
        result = fixture_run(
            [
                PYTHON,
                "-I",
                "-B",
                str(RUNNER),
                "--phase",
                f"exec-gate-{name}",
                "--timeout-seconds",
                "5",
                "--private-root",
                str(root),
                "--stdout",
                str(output),
                "--",
                *command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": str(root),
                "TMPDIR": "/tmp",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        if (
            result.returncode != 125
            or result.stdout
            or output.exists()
            or b"status=125 command_status=none reason=runner-containment-failed"
            not in result.stderr
            or b"Traceback (most recent call last)" in result.stderr
        ):
            raise SystemExit(
                f"exec-gate {name} failure escaped containment: "
                + repr(result.stderr[-4096:])
            )
    if denied_sentinel.exists():
        raise SystemExit("exec-gate EACCES fixture executed its denied target")
    print("HAPTICS_APT_PHASE_EXEC_GATE_FAILURES=PASS")


@managed_fixture
def unit_unread_diagnostic(root: pathlib.Path) -> None:
    output = root / "unread-diagnostic.out"
    process = fixture_popen(
        runner_command(
            root,
            output,
            "unread-diagnostic",
            10,
            "diagnostic-backpressure",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    blocked = False
    try:
        try:
            status = process.wait(timeout=3.0)
        except subprocess.TimeoutExpired as error:
            raise SystemExit("unread terminal diagnostic blocked runner exit") from error
    finally:
        finish_fixture_cleanup(process)
    if blocked or status != 77 or output.stat().st_size != 1024 * 1024:
        raise SystemExit(
            f"unread terminal diagnostic blocked runner exit: status={status}"
        )
    print("HAPTICS_APT_PHASE_UNREAD_DIAGNOSTIC=PASS")


def run_unit_case(
    root: pathlib.Path,
    mode: str,
    marker: bytes,
    *stderr_tokens: bytes,
) -> None:
    result = fixture_run(
        [
            PYTHON,
            "-I",
            "-B",
            str(pathlib.Path(__file__).resolve()),
            mode,
            str(root),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15.0,
    )
    if (
        result.returncode != 0
        or result.stdout != marker + b"\n"
        or any(token not in result.stderr for token in stderr_tokens)
    ):
        raise SystemExit(
            f"{mode} failed: status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr[-2048:]!r}"
        )


def exec_runner_wrapper(mode: str, root: pathlib.Path) -> None:
    output = root / f"wrapper-{mode}.out"
    command = runner_command(root, output, f"wrapper-{mode}", 5, "status", "77")
    if mode == "ignored-sigchld":
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    elif mode == "blocked-sigchld":
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    elif mode == "high-fd":
        # Keep the runner's pipes above FD_SETSIZE even on sudo's low soft
        # limit. Only this disposable wrapper and its exec inherit the change.
        highest_fixture_fd = 1100
        required_limit = highest_fixture_fd + 1 + 32
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < required_limit:
            raise SystemExit(
                f"high-fd fixture requires RLIMIT_NOFILE hard >= {required_limit}, got {hard}"
            )
        if soft != resource.RLIM_INFINITY and soft < required_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (required_limit, hard))
        descriptors = []
        while not descriptors or descriptors[-1] < highest_fixture_fd:
            descriptor = os.open("/dev/null", os.O_RDONLY)
            os.set_inheritable(descriptor, True)
            descriptors.append(descriptor)
    else:
        raise SystemExit("unknown runner wrapper mode")
    os.execve(
        command[0],
        command,
        {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )


def run_runner_wrapper(root: pathlib.Path, mode: str, expected: int) -> None:
    result = fixture_run(
        [
            PYTHON,
            "-I",
            "-B",
            str(pathlib.Path(__file__).resolve()),
            "--exec-runner-wrapper",
            mode,
            str(root),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=12.0,
    )
    require_status(result, expected, f"{mode} wrapper")
    output = root / f"wrapper-{mode}.out"
    if mode == "high-fd":
        if (
            output.read_bytes() != b"status-stdout\n"
            or b"command_status=77 reason=command-failed" not in result.stderr
        ):
            raise SystemExit("high-fd runner lost output or command status")
    elif (
        output.exists()
        or b"command_status=none reason=runner-containment-failed" not in result.stderr
        or b"requires" not in result.stderr
        or b"SIGCHLD" not in result.stderr
    ):
        raise SystemExit(f"{mode} runner did not fail closed before command spawn")


def unit_failure_bound() -> None:
    module = load_runner()
    ledger = module.FailureLedger()
    for index in range(100):
        ledger.add(module.PhaseError(f"bounded failure {index}"))
    if len(ledger.entries) != module.MAX_FAILURES or ledger.omitted != 92:
        raise SystemExit("APT phase failure ledger is not strictly bounded")


def exact_section(source: str, start: str, end: str, role: str) -> str:
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError(f"installer {role} boundary changed")
    return source.split(start, 1)[1].split(end, 1)[0]


def replace_once(source: str, old: str, new: str, role: str) -> str:
    if source.count(old) != 1:
        raise SystemExit(f"installer {role} injection anchor changed")
    return source.replace(old, new, 1)


TERMINAL_SETTLEMENT = (
    '  if [ "$process_settled" = 1 ]; then\n'
    "    apt_phase_pid=\n"
    "    apt_phase_start_time=\n"
    "  fi\n"
    "  if ! settle_apt_phase_cgroup; then\n"
    "    cgroup_status=125\n"
    "    apt_phase_cgroup_unsettled=1\n"
    "  fi\n"
)


def validate_installer_custody(source: str) -> None:
    lifecycle = exact_section(
        source, "work_dir=\n", "\nearly_script_path=", "lifecycle"
    )
    handler = exact_section(
        lifecycle,
        "handle_installer_signal() {\n",
        "\n}\ntrap 'handle_installer_signal HUP 129'",
        "signal handler",
    )
    if (
        "/bin/kill" in handler
        or "signal_owned_apt_phase" in handler
        or 'if [ "$apt_phase_starting" = 1 ] || [ -n "$apt_phase_pid" ]' not in handler
        or 'if [ "$apt_transaction_active" = 1 ]' not in handler
        or '[ "$apt_transaction_cancel_forward" != 1 ]' not in handler
    ):
        raise ValueError("installer signal handler is not latch-only")
    audit_latch = handler.find('[ "$apt_transaction_cancel_forward" != 1 ]')
    active_phase_latch = handler.find(
        'if [ "$apt_phase_starting" = 1 ] || [ -n "$apt_phase_pid" ]'
    )
    if audit_latch < 0 or active_phase_latch < 0 or audit_latch > active_phase_latch:
        raise ValueError("installer audit cancellation latch ordering changed")

    run_phase = "run_apt_phase() {\n" + exact_section(
        source,
        "run_apt_phase() {\n",
        "\n}\n\nverify_apt_partial_directory_empty()",
        "phase runner",
    )
    ordered_phase_tokens = (
        "apt_phase_starting=1",
        'if [ "$apt_transaction_active" = 1 ] &&',
        "if ! create_apt_phase_cgroup; then",
        '--cgroup "$apt_phase_cgroup"',
        '--cgroup-identity "$apt_phase_cgroup_identity"',
        '    -- "$@" &',
        "runner_pid=$!",
        'if ! runner_start_time=$(read_process_start_time "$runner_pid"); then',
        "apt_phase_pid=$runner_pid",
        "apt_phase_start_time=$runner_start_time",
        "phase_ceiling_cs=$((apt_phase_now_cs + timeout_cs + APT_PHASE_TAIL_GRACE_CS))",
        'if state=$(read_process_state "$runner_pid" "$runner_start_time"); then',
        'if wait "$runner_pid"; then',
        'if [ "$process_settled" = 1 ]; then',
        "\n    apt_phase_pid=\n",
        "\n    apt_phase_start_time=\n",
    )
    positions = [run_phase.find(token) for token in ordered_phase_tokens]
    if -1 in positions or positions != sorted(positions):
        raise ValueError("installer phase custody ordering changed")
    if run_phase.count(TERMINAL_SETTLEMENT) != 1:
        raise ValueError("installer terminal cgroup settlement ordering changed")
    publication_failure = exact_section(
        run_phase,
        'if ! runner_start_time=$(read_process_start_time "$runner_pid"); then\n',
        '\n  fi\n  apt_phase_pid=$runner_pid',
        "phase identity publication failure",
    )
    failure_tokens = (
        "kill -s TERM %+",
        'if ! reap_started_apt_phase "$runner_pid" "$APT_PHASE_TAIL_GRACE_CS"; then',
        "kill -s KILL %+",
        "if ! settle_apt_phase_cgroup; then",
        "apt_phase_cgroup_unsettled=1",
        'if ! reap_started_apt_phase "$runner_pid"; then',
        "apt_phase_starting=0",
        'if [ -n "$apt_phase_signal_status" ]; then',
        "apt_phase_signal_name=",
        "apt_phase_signal_status=",
        'return "$status"',
    )
    failure_positions = [publication_failure.find(token) for token in failure_tokens]
    if -1 in failure_positions or failure_positions != sorted(failure_positions):
        raise ValueError("installer unpublished phase rollback ordering changed")
    if "apt_phase_cgroup_unsettled=0" in publication_failure:
        raise ValueError("installer unpublished failure cleared unsettled containment")
    publication = exact_section(
        run_phase,
        "\n  apt_phase_pid=$runner_pid",
        "\n  while :; do",
        "phase identity publication",
    )
    if publication.splitlines() != (
        [
            "",
            "  apt_phase_start_time=$runner_start_time",
            "  apt_phase_starting=0",
            "  if read_apt_phase_clock; then",
            "    phase_ceiling_cs=$((apt_phase_now_cs + timeout_cs + APT_PHASE_TAIL_GRACE_CS))",
            "  else",
            "    phase_ceiling_cs=0",
            "  fi",
        ]
    ):
        raise ValueError("installer phase identity publication changed")
    bounded_cancellation = (
        'if [ -n "$apt_phase_signal_name" ]; then\n'
        "      if converge_owned_apt_phase; then\n"
        "        process_settled=1\n"
        "      fi\n"
        "      status=$apt_phase_signal_status\n"
        "      break\n"
        "    fi"
    )
    post_cgroup_reap = (
        'if [ "$process_settled" != 1 ] && [ "$cgroup_status" -eq 0 ]; then\n'
        '    if reap_owned_apt_phase "$runner_pid" "$runner_start_time" \\\n'
        '      "$APT_PHASE_KILL_GRACE_CS"; then\n'
        "      process_settled=1\n"
        "      apt_phase_pid=\n"
        "      apt_phase_start_time=\n"
        "    else\n"
        "      cgroup_status=125\n"
        "      apt_phase_cgroup_unsettled=1\n"
        "    fi\n"
        "  fi"
    )
    if bounded_cancellation not in run_phase or post_cgroup_reap not in run_phase:
        raise ValueError("installer bounded cancellation convergence changed")
    terminal_wait = (
        'if [ "$observation_status" -eq 1 ] ||\n'
        '      { [ "$observation_status" -eq 0 ] && [[ "$state" = Z || "$state" = X || "$state" = x ]]; }; then\n'
        '      if wait "$runner_pid"; then\n'
    )
    if terminal_wait not in run_phase or run_phase.count('wait "$runner_pid"') != 1:
        raise ValueError("installer waits before authenticated process termination")
    for token in (
        'if [ "$observation_status" -ne 0 ] || [ "$phase_ceiling_cs" -eq 0 ] ||',
        'if [ "$apt_phase_now_cs" -ge "$phase_ceiling_cs" ]; then\n      status=124',
        'if [ "$process_settled" != 1 ]; then\n    apt_phase_cgroup_unsettled=1',
    ):
        if token not in run_phase:
            raise ValueError("installer independent deadline/unknown custody changed")
    if (
        'if [ "$apt_transaction_active" = 1 ] &&\n'
        '    [ "$apt_transaction_cancel_forward" = 1 ] &&\n'
        '    [ -n "$installer_signal_status" ]; then\n'
        "    apt_phase_starting=0\n"
        '    return "$installer_signal_status"\n'
        "  fi"
    ) not in run_phase:
        raise ValueError("installer pre-install cancellation latch changed")
    cgroup_contract = (
        "exec {apt_phase_cgroup_parent_fd}< \"$parent\"",
        "exec {apt_phase_cgroup_fd}< \"$child_path\"",
        '"/proc/self/fd/$apt_phase_cgroup_fd/cgroup.events"',
        '"/proc/self/fd/$apt_phase_cgroup_fd/cgroup.kill"',
        '[ "$populated" = 0 ] || apt_phase_cgroup_had_members=1',
        "reap_owned_apt_phase",
        "reap_started_apt_phase",
        "apt_phase_cgroup_object_removed",
        "remove_apt_phase_cgroup_leaf",
    )
    if any(token not in lifecycle for token in cgroup_contract):
        raise ValueError("installer cgroup identity/settlement contract changed")
    completion_contract = (
        "create_apt_phase_completion_channel",
        '--status-fd "$apt_phase_completion_write_fd"',
        "exec {apt_phase_completion_write_fd}>&-",
        'authenticate_apt_phase_completion "$status"',
        'runner_completion_authenticated=1',
        '[ "$status" -ne 124 ] && [ "$runner_completion_authenticated" != 1 ]',
    )
    if any(token not in run_phase for token in completion_contract):
        raise ValueError("installer runner completion contract changed")
    cleanup_contract = (
        "converge_owned_apt_phase() {",
        'signal_owned_apt_phase TERM 2>/dev/null || true',
        'signal_owned_apt_phase KILL 2>/dev/null || true',
        'reap_owned_apt_phase "$apt_phase_pid" "$apt_phase_start_time" && return 0',
        "converge_owned_apt_phase || process_settled=0",
        'if [ "$process_settled" = 1 ]; then',
        'wait "$apt_phase_pid" 2>/dev/null || true',
        "APT phase process cleanup did not converge",
        'cleanup() {\n'
        '  local entry_status=$? apt_cleanup_active=1 cgroup_settled=1 process_settled=1 cleanup_failed=0',
        'if [ "$cleanup_failed" = 1 ] && [ "$entry_status" -eq 0 ]; then',
        'exit "${installer_signal_status:-$entry_status}"',
        'apt_cleanup_active=1',
        'if [ "$apt_cleanup_active" = 1 ]; then\n    return 0',
        'readonly APT_PHASE_TAIL_GRACE_CS=1000',
        'readonly APT_PHASE_KILL_GRACE_CS=200',
        'read -r uptime idle < /proc/uptime',
        'descriptor = os.pidfd_open(int(pid))',
        'signal.pidfd_send_signal(descriptor, getattr(signal, "SIG" + name))',
    )
    if any(token not in lifecycle for token in cleanup_contract):
        raise ValueError("installer bounded process cleanup contract changed")
    if (
        lifecycle.count("R|S|D|Z|T|t|X|x|K|W|P|I)") != 2
        or lifecycle.count('if [ "$observation_status" -eq 1 ]; then') != 3
        or 'Z|X|x)\n          wait "$pid" 2>/dev/null || true' not in lifecycle
        or (
            'if ! IFS= read -r stat_line < "/proc/$pid/stat"; then\n'
            '    [ ! -e "/proc/$pid" ] && return 1\n'
            "    return 2\n"
            "  fi"
        )
        not in lifecycle
    ):
        raise ValueError("installer process observation tri-state changed")
    cgroup_name_tokens = (
        "installer_pid=$BASHPID",
        'start_time=$(read_process_start_time "$installer_pid")',
        'apt_phase_cgroup_leaf="tb321fu-haptics-apt-$installer_pid-'
        '$start_time-$apt_phase_cgroup_sequence"',
    )
    cgroup_name_positions = [lifecycle.find(token) for token in cgroup_name_tokens]
    if -1 in cgroup_name_positions or cgroup_name_positions != sorted(
        cgroup_name_positions
    ):
        raise ValueError("installer cgroup process identity contract changed")
    if (
        '> "$apt_phase_cgroup/cgroup.kill"' in lifecycle
        or '< "$apt_phase_cgroup/cgroup.events"' in lifecycle
        or run_phase.count("settle_apt_phase_cgroup") < 3
        or (
            'elif [ "$cgroup_status" -eq 0 ] && '
            '[ "$apt_phase_cgroup_had_members" = 1 ] &&\n'
            '    [ "$status" -eq 0 ]; then\n'
            "    status=125\n"
            '  elif [ "$status" -ne 124 ] && '
            '[ "$runner_completion_authenticated" != 1 ]; then\n'
            "    status=125\n"
            '  elif [ "$cgroup_status" -ne 0 ] && [ "$status" -eq 0 ]; then'
        )
        not in run_phase
        or '    [ "$status" -ge 128 ] && [ "$status" -le 192 ]; then' in run_phase
    ):
        raise ValueError("installer cgroup cleanup/status precedence changed")

    transaction = (
        "apt_transaction_cancel_forward=1\n"
        "apt_transaction_active=1\n"
        "if run_apt_phase install"
        + exact_section(
        source,
        "apt_transaction_cancel_forward=1\n"
        "apt_transaction_active=1\n"
        "if run_apt_phase install",
        '\nif /usr/bin/python3 -I -B "$BISON_NORMALIZER"',
        "install transaction",
        )
    )
    transaction_tokens = (
        "apt_transaction_cancel_forward=1",
        "apt_transaction_active=1",
        'if run_apt_phase install 600 "$compat_apt_stdout"',
        "apt_transaction_cancel_forward=0",
        "install_cgroup_unsettled=$apt_phase_cgroup_unsettled",
        'if [ "$install_cgroup_unsettled" = 1 ]; then',
        "marker_status=125",
        "post_status=125",
        'if run_apt_phase install-marker 120 "$marker_stdout"',
        'if run_apt_phase install-post 120 "$post_stdout"',
        "apt_transaction_active=0",
        'if [ -n "$installer_signal_status" ]; then',
        'if [ "$apt_install_status" -ne 0 ]; then',
        'if [ "$marker_status" -ne 0 ] || [ "$post_status" -ne 0 ]; then',
    )
    transaction_positions = [transaction.find(token) for token in transaction_tokens]
    if -1 in transaction_positions or transaction_positions != sorted(
        transaction_positions
    ):
        raise ValueError("installer transaction ordering changed")
    if transaction.count("run_apt_phase ") != 3:
        raise ValueError("installer transaction is not exactly three custodial phases")
    if (
        'if [ "$install_cgroup_unsettled" = 1 ]; then\n'
        "  marker_status=125\n"
        "  post_status=125\n"
        "else\n"
        not in transaction
    ):
        raise ValueError("installer unsettled cgroup did not suppress transaction audit")


def installer_custody_mutations(source: str) -> None:
    mutations = (
        source.replace(
            'if ! runner_start_time=$(read_process_start_time "$runner_pid"); then',
            'if runner_start_time=$(read_process_start_time "$runner_pid"); then',
            1,
        ),
        source.replace(
            'if [ "$observation_status" -eq 1 ] ||\n',
            'if [ "$observation_status" -ge 0 ] ||\n',
            1,
        ),
        source.replace(
            'if [ "$apt_phase_starting" = 1 ] || [ -n "$apt_phase_pid" ]; then',
            'if [ -n "$apt_phase_pid" ]; then',
            1,
        ),
        source.replace(
            '[ "$apt_transaction_cancel_forward" != 1 ]',
            '[ "$apt_transaction_cancel_forward" = 1 ]',
            1,
        ),
        source.replace(
            "apt_transaction_cancel_forward=0\n"
            "install_cgroup_unsettled=$apt_phase_cgroup_unsettled",
            "apt_transaction_cancel_forward=1\n"
            "install_cgroup_unsettled=$apt_phase_cgroup_unsettled",
            1,
        ),
        source.replace(
            'if run_apt_phase install-marker 120 "$marker_stdout"',
            'if /usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER"',
            1,
        ),
        source.replace(
            "apt_transaction_active=0\nif [ -n \"$installer_signal_status\" ]; then",
            "apt_transaction_active=0\nif [ \"$apt_install_status\" -ne 0 ]; then",
            1,
        ),
        source.replace(
            "  if ! create_apt_phase_cgroup; then\n",
            "  if /bin/false; then\n",
            1,
        ),
        source.replace(
            '      --cgroup-identity "$apt_phase_cgroup_identity"\n',
            "",
            1,
        ),
        source.replace(
            '"/proc/self/fd/$apt_phase_cgroup_fd/cgroup.kill"',
            '"$apt_phase_cgroup/cgroup.kill"',
            1,
        ),
        source.replace(
            "install_cgroup_unsettled=$apt_phase_cgroup_unsettled",
            "install_cgroup_unsettled=0",
            1,
        ),
        source.replace(
            '  elif [ "$cgroup_status" -ne 0 ] && [ "$status" -eq 0 ]; then',
            '  elif [ "$cgroup_status" -ne 0 ]; then',
            1,
        ),
        source.replace(
            '    --status-fd "$apt_phase_completion_write_fd" \\\n',
            "",
            1,
        ),
        source.replace(
            '    authenticate_apt_phase_completion "$status"; then',
            '    /bin/true; then',
            1,
        ),
        source.replace(
            '[ "$status" -ne 124 ] && [ "$runner_completion_authenticated" != 1 ]; then',
            '[ "$status" -ne 124 ] && [ "$runner_completion_authenticated" = 1 ]; then',
            1,
        ),
        source.replace(
            '  runner_pid=$!\n'
            '  exec {apt_phase_completion_write_fd}>&-\n'
            '  apt_phase_completion_write_fd=\n',
            '  runner_pid=$!\n',
            1,
        ),
        source.replace(
            'start_time=$(read_process_start_time "$installer_pid")',
            'start_time=$(read_process_start_time "$BASHPID")',
            1,
        ),
        source.replace(
            '[ "$populated" = 0 ] || apt_phase_cgroup_had_members=1',
            ":",
            1,
        ),
        source.replace(
            'signal_owned_apt_phase KILL 2>/dev/null || true',
            'signal_owned_apt_phase TERM 2>/dev/null || true',
            1,
        ),
        source.replace(
            'reap_owned_apt_phase "$apt_phase_pid" "$apt_phase_start_time"',
            "/bin/false",
            1,
        ),
        source.replace(
            'if ! reap_started_apt_phase "$runner_pid"; then',
            "if /bin/false; then",
            1,
        ),
        source.replace(
            '    if [ -n "$apt_phase_signal_name" ]; then\n'
            "      if converge_owned_apt_phase; then",
            '    if [ -n "$apt_phase_signal_name" ]; then\n'
            '      if wait "$runner_pid"; then',
            1,
        ),
        source.replace(
            'if [ "$observation_status" -eq 1 ]; then\n'
            '        wait "$pid" 2>/dev/null || true\n'
            "        return 0\n"
            "      fi\n"
            "      return 2",
            'if [ "$observation_status" -ge 1 ]; then\n'
            '        wait "$pid" 2>/dev/null || true\n'
            "        return 0\n"
            "      fi\n"
            "      return 2",
            1,
        ),
        source.replace(
            "R|S|D|Z|T|t|X|x|K|W|P|I)",
            "R|S|D|Z|T|X|x|K|W|P|I)",
            1,
        ),
        source.replace(
            'if [ "$cleanup_failed" = 1 ] && [ "$entry_status" -eq 0 ]; then',
            'if [ "$cleanup_failed" = 1 ] && [ "$entry_status" -ne 0 ]; then',
            1,
        ),
        source.replace('readonly APT_PHASE_TAIL_GRACE_CS=1000',
                       'readonly APT_PHASE_TAIL_GRACE_CS=100', 1),
        source.replace('if [ "$apt_cleanup_active" = 1 ]; then\n    return 0',
                       'if [ "$apt_cleanup_active" = 1 ]; then\n    exit 143', 1),
        source.replace(
            '  local entry_status=$? apt_cleanup_active=1 cgroup_settled=1 process_settled=1 cleanup_failed=0',
            '  local entry_status=$? cgroup_settled=1 process_settled=1 cleanup_failed=0\n'
            '  apt_cleanup_active=1',
            1,
        ),
        source.replace('if [ "$apt_phase_now_cs" -ge "$phase_ceiling_cs" ]; then',
                       'if /bin/false; then', 1),
        source.replace('    return "$status"\n  fi\n  apt_phase_pid=$runner_pid',
                       '    apt_phase_cgroup_unsettled=0\n    return "$status"\n  fi\n  apt_phase_pid=$runner_pid', 1),
    )
    unchanged = [index for index, mutated in enumerate(mutations) if mutated == source]
    if unchanged:
        raise SystemExit(f"installer custody mutation anchor changed: {unchanged}")
    for mutated in mutations:
        try:
            validate_installer_custody(mutated)
        except ValueError:
            continue
        raise SystemExit("installer custody oracle accepted a hostile mutation")


def render_installer_harness(
    source: str,
    destination: pathlib.Path,
    boundary: str | None = None,
    *,
    lifecycle_replacements: tuple[tuple[str, str], ...] = (),
    run_phase_replacements: tuple[tuple[str, str], ...] = (),
    preamble: str = "",
) -> None:
    lifecycle = "work_dir=\n" + exact_section(
        source, "work_dir=\n", "\nearly_script_path=", "lifecycle"
    )
    run_phase = "run_apt_phase() {\n" + exact_section(
        source,
        "run_apt_phase() {\n",
        "\n}\n\nverify_apt_partial_directory_empty()",
        "phase runner",
    ) + "\n}\n"
    if boundary == "spawn":
        anchor = '    -- "$@" &\n  runner_pid=$!\n'
        replacement = (
            '    -- "$@" &\n'
            '  : > "$HAPTICS_TEST_GAP_MARKER"\n'
            '  while [ ! -e "$HAPTICS_TEST_GAP_RELEASE" ]; do :; done\n'
            "  runner_pid=$!\n"
        )
        if run_phase.count(anchor) != 1:
            raise SystemExit("installer spawn-boundary anchor changed")
        run_phase = run_phase.replace(anchor, replacement, 1)
    elif boundary == "prologue":
        anchor = "  apt_phase_starting=1\n"
        replacement = (
            "  apt_phase_starting=1\n"
            '  : > "$HAPTICS_TEST_GAP_MARKER"\n'
            '  while [ ! -e "$HAPTICS_TEST_GAP_RELEASE" ]; do :; done\n'
        )
        if run_phase.count(anchor) != 1:
            raise SystemExit("installer prologue-boundary anchor changed")
        run_phase = run_phase.replace(anchor, replacement, 1)
    elif boundary == "identity":
        anchor = (
            "  runner_pid=$!\n"
            "  exec {apt_phase_completion_write_fd}>&-\n"
            "  apt_phase_completion_write_fd=\n"
            '  if ! runner_start_time=$(read_process_start_time "$runner_pid"); then\n'
        )
        replacement = (
            "  runner_pid=$!\n"
            "  exec {apt_phase_completion_write_fd}>&-\n"
            "  apt_phase_completion_write_fd=\n"
            '  : > "$HAPTICS_TEST_GAP_MARKER"\n'
            '  while [ ! -e "$HAPTICS_TEST_GAP_RELEASE" ]; do :; done\n'
            "  if ! runner_start_time=$(/bin/false); then\n"
        )
        if run_phase.count(anchor) != 1:
            raise SystemExit("installer identity-boundary anchor changed")
        run_phase = run_phase.replace(anchor, replacement, 1)
    elif boundary == "identity-cleanup":
        identity_anchor = (
            "  runner_pid=$!\n"
            "  exec {apt_phase_completion_write_fd}>&-\n"
            "  apt_phase_completion_write_fd=\n"
            '  if ! runner_start_time=$(read_process_start_time "$runner_pid"); then\n'
        )
        identity_replacement = (
            "  runner_pid=$!\n"
            "  exec {apt_phase_completion_write_fd}>&-\n"
            "  apt_phase_completion_write_fd=\n"
            "  if ! runner_start_time=$(/bin/false); then\n"
        )
        cleanup_anchor = (
            "    kill -s TERM %+ 2>/dev/null || true\n"
            '    if ! reap_started_apt_phase "$runner_pid" "$APT_PHASE_TAIL_GRACE_CS"; then\n'
            "      kill -s KILL %+ 2>/dev/null || true\n"
            "    fi\n"
            "    if ! settle_apt_phase_cgroup; then\n"
            "      cgroup_status=125\n"
            "      apt_phase_cgroup_unsettled=1\n"
            "    fi\n"
            '    if ! reap_started_apt_phase "$runner_pid"; then\n'
            "      cgroup_status=125\n"
            "      apt_phase_cgroup_unsettled=1\n"
            "    fi\n"
            "    apt_phase_starting=0\n"
        )
        cleanup_replacement = (
            "    kill -s TERM %+ 2>/dev/null || true\n"
            '    if ! reap_started_apt_phase "$runner_pid" "$APT_PHASE_TAIL_GRACE_CS"; then\n'
            "      kill -s KILL %+ 2>/dev/null || true\n"
            "    fi\n"
            "    if ! settle_apt_phase_cgroup; then\n"
            "      cgroup_status=125\n"
            "      apt_phase_cgroup_unsettled=1\n"
            "    fi\n"
            '    if ! reap_started_apt_phase "$runner_pid"; then\n'
            "      cgroup_status=125\n"
            "      apt_phase_cgroup_unsettled=1\n"
            "    fi\n"
            '    : > "$HAPTICS_TEST_GAP_MARKER"\n'
            '    while [ ! -e "$HAPTICS_TEST_GAP_RELEASE" ]; do :; done\n'
            "    apt_phase_starting=0\n"
        )
        if run_phase.count(identity_anchor) != 1 or run_phase.count(cleanup_anchor) != 1:
            raise SystemExit("installer identity-cleanup boundary anchor changed")
        run_phase = run_phase.replace(identity_anchor, identity_replacement, 1)
        run_phase = run_phase.replace(cleanup_anchor, cleanup_replacement, 1)
    elif boundary == "wait":
        anchor = (
            '      if wait "$runner_pid"; then\n'
            "        status=0\n"
            "      else\n"
            "        status=$?\n"
            "      fi\n"
        )
        replacement = anchor + (
            '    printf \'%s\\n\' "$runner_pid" > "$HAPTICS_TEST_WAIT_MARKER"\n'
            '    while [ ! -e "$HAPTICS_TEST_WAIT_RELEASE" ]; do :; done\n'
        )
        if run_phase.count(anchor) != 1:
            raise SystemExit("installer wait-boundary anchor changed")
        run_phase = run_phase.replace(anchor, replacement, 1)
    elif boundary == "supervisor-death-cgroup":
        anchor = (
            "  apt_phase_pid=$runner_pid\n"
            "  apt_phase_start_time=$runner_start_time\n"
            "  apt_phase_starting=0\n"
        )
        replacement = anchor + (
            '  printf \'%s %s\\n\' "$runner_pid" "$runner_start_time" > "$HAPTICS_TEST_RUNNER_PID"\n'
        )
        if run_phase.count(anchor) != 1:
            raise SystemExit("installer cgroup supervisor boundary anchor changed")
        run_phase = run_phase.replace(anchor, replacement, 1)
    elif boundary is not None:
        raise SystemExit("unknown installer harness boundary")

    for old, new in lifecycle_replacements:
        if lifecycle.count(old) != 1:
            raise SystemExit("installer lifecycle fault anchor changed")
        lifecycle = lifecycle.replace(old, new, 1)
    for old, new in run_phase_replacements:
        if run_phase.count(old) != 1:
            raise SystemExit(
                f"installer phase fault anchor changed: {old[:120]!r}"
            )
        run_phase = run_phase.replace(old, new, 1)

    transaction_setup = ""
    if boundary == "prologue":
        transaction_setup = (
            "apt_transaction_cancel_forward=1\n"
            "apt_transaction_active=1\n"
        )
    harness = f"""#!/bin/bash -p
set -euo pipefail
umask 077
{lifecycle}
{preamble}
APT_PHASE_RUNNER=$1
mode=$2
work_dir=$3
fixture_script=$4
timeout_seconds=${{HAPTICS_TEST_TIMEOUT_SECONDS:-8}}
fixture_argument=${{HAPTICS_TEST_FIXTURE_ARGUMENT:-0}}
{run_phase}
/usr/bin/mkdir -m 0700 -- "$work_dir"
{transaction_setup}if run_apt_phase installer-custody "$timeout_seconds" "$work_dir/phase.out" \\
  {PYTHON} -I -B "$fixture_script" --fixture "$mode" \\
    "$fixture_argument"; then
  phase_status=0
else
  phase_status=$?
fi
printf 'INSTALLER_PHASE_STATUS=%s\\n' "$phase_status"
exit "$phase_status"
"""
    destination.write_text(harness, encoding="utf-8")
    destination.chmod(0o700)


def wait_for_path(path: pathlib.Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise SystemExit(f"timed out waiting for installer fixture path: {path.name}")


def wait_for_pid_output(path: pathlib.Path) -> int:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            value = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            value = ""
        if value.isascii() and value.isdigit() and int(value, 10) > 1:
            return int(value, 10)
        time.sleep(0.01)
    raise SystemExit("timed out waiting for installer-managed command pid")


def wait_for_pid_pair_output(path: pathlib.Path) -> tuple[int, int]:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            fields = path.read_text(encoding="ascii").strip().split()
        except FileNotFoundError:
            fields = []
        if (
            len(fields) == 2
            and all(field.isascii() and field.isdigit() for field in fields)
            and all(int(field, 10) > 1 for field in fields)
        ):
            return int(fields[0], 10), int(fields[1], 10)
        time.sleep(0.01)
    raise SystemExit("timed out waiting for supervisor-death process identities")


def process_start_time(pid: int) -> str | None:
    return FIXTURE_SUPPORT.process_start_time(pid)


def process_parent_pid(pid: int) -> int:
    try:
        data = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ESRCH):
            raise SystemExit(f"fixture process {pid} exited before parent capture") from exc
        raise
    fields = data.rsplit(") ", 1)
    if len(fields) != 2:
        raise SystemExit("malformed fixture parent stat")
    tail = fields[1].split()
    if len(tail) < 2 or not tail[1].isdigit():
        raise SystemExit("malformed fixture parent pid")
    return int(tail[1], 10)


def process_cgroup_directory(pid: int) -> pathlib.Path:
    try:
        records = pathlib.Path(f"/proc/{pid}/cgroup").read_text(
            encoding="ascii"
        ).splitlines()
    except OSError as exc:
        raise SystemExit("fixture could not read installer cgroup membership") from exc
    if len(records) != 1 or not records[0].startswith("0::/"):
        raise SystemExit("fixture requires one unified cgroup v2 record")
    relative = records[0][3:]
    if "\x00" in relative or not relative.startswith("/"):
        raise SystemExit("fixture observed malformed cgroup membership")
    return pathlib.Path("/sys/fs/cgroup") / relative.removeprefix("/")


class FixtureCgroup:
    __slots__ = ("path", "device", "inode")

    def __init__(self, path: pathlib.Path, device: int, inode: int) -> None:
        self.path = path
        self.device = device
        self.inode = inode

    @property
    def identity(self) -> str:
        return f"{self.device}:{self.inode}"

    @property
    def name(self) -> str:
        return self.path.name

    def exists(self) -> bool:
        return self.path.exists()

    def stat(self):
        return self.path.stat()


INSTALLER_START_TIMES: dict[tuple[str, int], str] = {}


def register_installer_process(parent: pathlib.Path, process: subprocess.Popen[bytes]) -> str:
    start_time = process.fixture_birth_identity.start_time
    INSTALLER_START_TIMES[(os.fspath(parent), process.pid)] = start_time
    return start_time


def open_fixture_cgroup(cgroup: FixtureCgroup) -> tuple[int, int]:
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(cgroup.path.parent, directory_flags)
    child_fd = -1
    try:
        child_fd = os.open(cgroup.path.name, directory_flags, dir_fd=parent_fd)
        metadata = os.fstat(child_fd)
        if (metadata.st_dev, metadata.st_ino) != (cgroup.device, cgroup.inode):
            raise SystemExit("fixture cgroup pathname identity changed")
        return parent_fd, child_fd
    except BaseException:
        with FIXTURE_SUPPORT.CleanupLedger() as rollback:
            rollback.add("cgroup parent open rollback", lambda: os.close(parent_fd), kind="release")
            if child_fd >= 0:
                rollback.add("cgroup child open rollback", lambda: os.close(child_fd), kind="release")
            raise


def close_fixture_cgroup(parent_fd: int, child_fd: int) -> None:
    with FIXTURE_SUPPORT.CleanupLedger() as cleanup:
        cleanup.add("cgroup parent descriptor", lambda: os.close(parent_fd), kind="release")
        cleanup.add("cgroup child descriptor", lambda: os.close(child_fd), kind="release")


def installer_cgroups(
    parent: pathlib.Path,
    installer_pid: int,
    installer_start: str | None = None,
) -> list[FixtureCgroup]:
    if installer_start is None:
        installer_start = INSTALLER_START_TIMES.get((os.fspath(parent), installer_pid))
    if (
        installer_pid <= 1
        or installer_start is None
        or not installer_start.isascii()
        or not installer_start.isdigit()
    ):
        raise SystemExit("installer cgroup lookup identity is invalid")
    name_pattern = re.compile(
        rf"tb321fu-haptics-apt-{installer_pid}-{re.escape(installer_start)}-"
        r"[1-9][0-9]*\Z"
    )
    matches: list[FixtureCgroup] = []
    for entry in parent.iterdir():
        if not name_pattern.fullmatch(entry.name) or entry.is_symlink():
            continue
        try:
            metadata = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not entry.is_dir():
            continue
        matches.append(FixtureCgroup(entry, metadata.st_dev, metadata.st_ino))
    return sorted(matches, key=lambda item: item.path.name)


def wait_for_installer_cgroup(
    installer_pid: int,
    installer_start: str | None = None,
) -> FixtureCgroup:
    parent = process_cgroup_directory(installer_pid)
    if installer_start is None:
        installer_start = INSTALLER_START_TIMES.get((os.fspath(parent), installer_pid))
    if installer_start is None:
        raise SystemExit("installer cgroup wait has no registered process identity")
    if process_start_time(installer_pid) != installer_start:
        raise SystemExit("installer exited before cgroup naming validation")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        matches = installer_cgroups(parent, installer_pid, installer_start)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise SystemExit("installer fixture observed multiple owned cgroups")
        time.sleep(0.01)
    raise SystemExit("timed out waiting for installer-owned cgroup")


def read_cgroup_members_fd(child_fd: int) -> frozenset[int]:
    try:
        descriptor = os.open(
            "cgroup.procs",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=child_fd,
        )
        with os.fdopen(descriptor, "r", encoding="ascii") as stream:
            records = stream.read().splitlines()
    except OSError as exc:
        raise SystemExit("fixture could not read cgroup members") from exc
    if any(not record.isascii() or not record.isdigit() for record in records):
        raise SystemExit("fixture observed malformed cgroup member record")
    return frozenset(int(record, 10) for record in records)


def read_cgroup_members(cgroup: FixtureCgroup) -> frozenset[int]:
    try:
        parent_fd, child_fd = open_fixture_cgroup(cgroup)
    except FileNotFoundError:
        raise SystemExit("fixture cgroup disappeared before member observation")
    try:
        return read_cgroup_members_fd(child_fd)
    finally:
        close_fixture_cgroup(parent_fd, child_fd)


def cleanup_fixture_cgroup(cgroup: FixtureCgroup) -> None:
    try:
        parent_fd, child_fd = open_fixture_cgroup(cgroup)
    except FileNotFoundError:
        return
    try:
        kill_fd = os.open(
            "cgroup.kill",
            os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=child_fd,
        )
        try:
            if os.write(kill_fd, b"1\n") != 2:
                raise SystemExit("fixture emergency cgroup kill was incomplete")
        finally:
            os.close(kill_fd)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if read_cgroup_members_fd(child_fd):
                time.sleep(0.01)
                continue
            try:
                metadata = os.stat(
                    cgroup.path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if os.readlink(f"/proc/self/fd/{child_fd}").endswith(" (deleted)"):
                    return
                raise SystemExit("fixture cgroup pathname vanished without deletion")
            if (metadata.st_dev, metadata.st_ino) != (cgroup.device, cgroup.inode):
                raise SystemExit("fixture refused to remove a replacement cgroup")
            try:
                os.rmdir(cgroup.path.name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            if os.readlink(f"/proc/self/fd/{child_fd}").endswith(" (deleted)"):
                return
            time.sleep(0.01)
        raise SystemExit("fixture emergency cgroup cleanup did not converge")
    finally:
        close_fixture_cgroup(parent_fd, child_fd)


def close_process_streams(process: subprocess.Popen[bytes]) -> None:
    FIXTURE_SUPPORT.close_process_streams(process)


def cleanup_owned_cgroups(parent: pathlib.Path, process: subprocess.Popen[bytes]) -> bool:
    groups = installer_cgroups(parent, process.pid, process.fixture_birth_identity.start_time)
    with FIXTURE_SUPPORT.CleanupLedger() as cleanup:
        for group in groups:
            cleanup.add(group.name, lambda group=group: cleanup_fixture_cgroup(group), kind="release")
    if installer_cgroups(parent, process.pid, process.fixture_birth_identity.start_time):
        raise SystemExit("fixture cgroup collection cleanup left an owned group")
    return bool(groups)


def finish_fixture_cleanup(
    process: subprocess.Popen[bytes],
    *,
    parent: pathlib.Path | None = None,
    work: pathlib.Path | None = None,
    identities=(),
    identity_records=(),
    expected_retained: bool = False,
) -> None:
    """Called in finally: keep its active oracle and run every cleanup independently."""
    original = sys.exc_info()
    identities = tuple(ProcessIdentity(*identity) for identity in identities if identity is not None)
    cleanup = FIXTURE_SUPPORT.CleanupLedger()
    cleanup.add("fixture streams", lambda: close_process_streams(process), kind="release")

    def remove_work() -> bool:
        if work is None or not work.exists():
            return False
        if process.returncode is None or any(FIXTURE_SUPPORT.identity_exists(item) for item in identities):
            raise SystemExit("fixture retained work directory for unconverged processes")
        if parent is not None and installer_cgroups(parent, process.pid, process.fixture_birth_identity.start_time):
            raise SystemExit("fixture retained work directory for unconverged cgroups")
        shutil.rmtree(work)
        return True

    cleanup.add("fixture work directory", remove_work,
                kind="expected-retained" if expected_retained else "emergency")
    for identity in identities:
        cleanup.add(f"fixture exact identity {identity.pid}",
                    lambda identity=identity: FIXTURE_SUPPORT.kill_identity(identity))
    for path in identity_records:
        def remove_recorded_identity(path=path):
            if not path.exists():
                return False
            fields = path.read_text(encoding="ascii").split()
            if len(fields) not in (2, 4):
                raise SystemExit("malformed cleanup birth identity record")
            return FIXTURE_SUPPORT.kill_identity(ProcessIdentity(int(fields[0], 10), fields[1]))
        cleanup.add(f"fixture recorded identity {path.name}", remove_recorded_identity)
    if parent is not None:
        cleanup.add("fixture cgroup collection", lambda: cleanup_owned_cgroups(parent, process),
                    kind="expected-retained" if expected_retained else "emergency")
    cleanup.add("fixture direct child", lambda: converge_fixture_process(process))
    cleanup.__exit__(*original)


@managed_fixture
def run_cgroup_clean_fault_case(
    root: pathlib.Path,
    source: str,
    name: str,
    *,
    lifecycle_replacements: tuple[tuple[str, str], ...],
    run_phase_replacements: tuple[tuple[str, str], ...] = (),
    preamble: str = "",
    signum: int | None = None,
    expected_status: int = 125,
    mode: str = "installer-sentinel",
    fixture_argument: str = "0",
) -> None:
    harness = root / f"installer-cgroup-{name}.sh"
    work = root / f"installer-cgroup-{name}.work"
    sentinel = root / f"installer-cgroup-{name}.command"
    marker = root / f"installer-cgroup-{name}.marker"
    release = root / f"installer-cgroup-{name}.release"
    render_installer_harness(
        source,
        harness,
        lifecycle_replacements=lifecycle_replacements,
        run_phase_replacements=run_phase_replacements,
        preamble=preamble,
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_COMMAND_SENTINEL": str(sentinel),
            "HAPTICS_TEST_FIXTURE_ARGUMENT": fixture_argument,
        }
    )
    if signum is not None:
        environment["HAPTICS_TEST_GAP_MARKER"] = str(marker)
        environment["HAPTICS_TEST_GAP_RELEASE"] = str(release)
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            mode,
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    try:
        register_installer_process(parent, process)
        if signum is not None:
            wait_for_path(marker)
            FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signum)
            release.write_text("release\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=15.0)
        groups = installer_cgroups(parent, process.pid)
        if (
            process.returncode != expected_status
            or stdout
            != f"INSTALLER_PHASE_STATUS={expected_status}\n".encode("ascii")
            or groups
            or work.exists()
            or sentinel.exists()
        ):
            raise SystemExit(
                f"installer cgroup clean fault {name} changed: "
                f"status={process.returncode} stdout={stdout!r} "
                f"stderr={stderr[-512:]!r} groups={[entry.name for entry in groups]} "
                f"work={int(work.exists())} sentinel={int(sentinel.exists())}"
            )
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work)


@managed_fixture
def run_cgroup_settlement_fault_case(
    root: pathlib.Path,
    source: str,
    name: str,
    *,
    expected_status: int,
    mode: str,
    fixture_argument: str = "0",
    signum: int | None = None,
    timeout_seconds: str = "8",
) -> None:
    kill_anchor = (
        "    printf '1\\n' > "
        '"/proc/self/fd/$apt_phase_cgroup_fd/cgroup.kill" || return 1'
    )
    harness = root / f"installer-cgroup-settle-{name}.sh"
    work = root / f"installer-cgroup-settle-{name}.work"
    render_installer_harness(
        source,
        harness,
        lifecycle_replacements=((kill_anchor, "    /bin/false || return 1"),),
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_FIXTURE_ARGUMENT": fixture_argument,
            "HAPTICS_TEST_TIMEOUT_SECONDS": timeout_seconds,
        }
    )
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            mode,
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    managed_pid: int | None = None
    managed_start: str | None = None
    try:
        register_installer_process(parent, process)
        if mode == "wait":
            managed_pid = wait_for_pid_output(work / "phase.out")
            managed_start = recorded_identity(pathlib.Path(environment["HAPTICS_TEST_IDENTITY_RECORD"]), managed_pid).start_time
            if managed_start is None:
                raise SystemExit("settlement fault target exited before injection")
        if signum is not None:
            FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signum)
        stdout, stderr = process.communicate(timeout=15.0)
        groups = installer_cgroups(parent, process.pid)
        if managed_pid is not None and managed_start is not None:
            require_identity_gone(managed_pid, managed_start)
        if (
            process.returncode != expected_status
            or stdout
            != f"INSTALLER_PHASE_STATUS={expected_status}\n".encode("ascii")
            or len(groups) != 1
            or read_cgroup_members(groups[0])
            or not work.exists()
            or b"APT phase cgroup cleanup did not converge" not in stderr
        ):
            raise SystemExit(
                f"installer cgroup settlement fault {name} changed: "
                f"status={process.returncode} stdout={stdout!r} "
                f"stderr={stderr[-512:]!r} groups={[entry.name for entry in groups]} "
                f"work={int(work.exists())}"
            )
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work, expected_retained=True,
                               identities=((managed_pid, managed_start) if managed_pid is not None and managed_start is not None else None,))


@managed_fixture
def run_cgroup_real_member_case(
    root: pathlib.Path,
    source: str,
    command_status: int,
    expected_status: int,
) -> None:
    terminal_settlement = TERMINAL_SETTLEMENT
    injected_settlement = terminal_settlement.replace(
        "  if ! settle_apt_phase_cgroup; then\n",
        "  fixture_seed_real_cgroup_member || return 125\n"
        "  if ! settle_apt_phase_cgroup; then\n", 1,
    )
    preamble = """fixture_seed_real_cgroup_member() {
  local sleeper_pid sleeper_start

  /usr/bin/sleep 30 </dev/null >/dev/null 2>&1 &
  sleeper_pid=$!
  if ! printf '%s\\n' "$sleeper_pid" > \
      "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.procs"; then
    /bin/kill -s TERM -- "$sleeper_pid" 2>/dev/null || true
    wait "$sleeper_pid" 2>/dev/null || true
    return 1
  fi
  sleeper_start=$(read_process_start_time "$sleeper_pid") || return 1
  printf '%s %s\\n' "$sleeper_pid" "$sleeper_start" > \
    "$HAPTICS_TEST_REAL_MEMBER_RECORD"
}
"""
    name = f"real-member-{command_status}"
    harness = root / f"installer-cgroup-{name}.sh"
    work = root / f"installer-cgroup-{name}.work"
    record = root / f"installer-cgroup-{name}.record"
    render_installer_harness(
        source,
        harness,
        lifecycle_replacements=(),
        run_phase_replacements=((terminal_settlement, injected_settlement),),
        preamble=preamble,
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_FIXTURE_ARGUMENT": str(command_status),
            "HAPTICS_TEST_REAL_MEMBER_RECORD": str(record),
        }
    )
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            "delayed-status",
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    sleeper_pid: int | None = None
    sleeper_start: str | None = None
    try:
        register_installer_process(parent, process)
        stdout, stderr = process.communicate(timeout=15.0)
        fields = record.read_text(encoding="ascii").strip().split()
        if (
            len(fields) != 2
            or not fields[0].isdigit()
            or not fields[1].isdigit()
        ):
            raise SystemExit("real cgroup member record is malformed")
        sleeper_pid = int(fields[0], 10)
        sleeper_start = fields[1]
        require_identity_gone(sleeper_pid, sleeper_start)
        groups = installer_cgroups(parent, process.pid)
        if (
            process.returncode != expected_status
            or stdout
            != f"INSTALLER_PHASE_STATUS={expected_status}\n".encode("ascii")
            or groups
            or work.exists()
        ):
            raise SystemExit(
                f"real cgroup member status {command_status} changed: "
                f"status={process.returncode} stdout={stdout!r} "
                f"stderr={stderr[-512:]!r} groups={[entry.name for entry in groups]}"
            )
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work, identity_records=(record,))


def read_identity_record(path: pathlib.Path, role: str) -> tuple[int, str]:
    fields = path.read_text(encoding="ascii").strip().split()
    if (
        len(fields) != 2
        or not fields[0].isdigit()
        or not fields[1].isdigit()
        or int(fields[0], 10) <= 1
    ):
        raise SystemExit(f"{role} identity record is malformed")
    return int(fields[0], 10), fields[1]


def wait_for_identity_record(path: pathlib.Path, role: str) -> tuple[int, str]:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            return read_identity_record(path, role)
        except (FileNotFoundError, SystemExit):
            # Opening the publication path can precede its single record write.
            time.sleep(0.01)
    raise SystemExit(f"timed out waiting for {role} birth identity record")


@managed_fixture
def run_identity_settlement_fault_case(
    root: pathlib.Path,
    source: str,
    signum: int | None,
) -> None:
    kill_anchor = (
        "    printf '1\\n' > "
        '"/proc/self/fd/$apt_phase_cgroup_fd/cgroup.kill" || return 1'
    )
    identity_anchor = (
        "  runner_pid=$!\n"
        "  exec {apt_phase_completion_write_fd}>&-\n"
        "  apt_phase_completion_write_fd=\n"
        "  if ! runner_start_time=$(/bin/false); then\n"
    )
    identity_replacement = (
        "  runner_pid=$!\n"
        "  exec {apt_phase_completion_write_fd}>&-\n"
        "  apt_phase_completion_write_fd=\n"
        "  fixture_publish_runner_identity \"$runner_pid\" || return 125\n"
        "  if ! runner_start_time=$(/bin/false); then\n"
    )
    preamble = """fixture_publish_runner_identity() {
  local runner_pid=$1 runner_start attempts=0

  runner_start=$(read_process_start_time "$runner_pid") || return 1
  printf '%s %s\\n' "$runner_pid" "$runner_start" > \
    "$HAPTICS_TEST_IDENTITY_RUNNER_RECORD" || return 1
  while [ ! -s "$HAPTICS_TEST_IDENTITY_TARGET_RECORD" ] && \
      [ "$attempts" -lt 500 ]; do
    attempts=$((attempts + 1))
    /usr/bin/sleep 0.01
  done
  [ -s "$HAPTICS_TEST_IDENTITY_TARGET_RECORD" ]
}
"""
    signal_name = "none" if signum is None else signal.Signals(signum).name.lower()
    expected_status = 125 if signum is None else 128 + signum
    name = f"identity-settlement-{signal_name}"
    harness = root / f"installer-cgroup-{name}.sh"
    work = root / f"installer-cgroup-{name}.work"
    marker = root / f"installer-cgroup-{name}.marker"
    release = root / f"installer-cgroup-{name}.release"
    runner_record = root / f"installer-cgroup-{name}.runner"
    target_record = root / f"installer-cgroup-{name}.target"
    render_installer_harness(
        source,
        harness,
        "identity-cleanup",
        lifecycle_replacements=((kill_anchor, "    /bin/false || return 1"),),
        run_phase_replacements=((identity_anchor, identity_replacement),),
        preamble=preamble,
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_GAP_MARKER": str(marker),
            "HAPTICS_TEST_GAP_RELEASE": str(release),
            "HAPTICS_TEST_IDENTITY_RUNNER_RECORD": str(runner_record),
            "HAPTICS_TEST_IDENTITY_TARGET_RECORD": str(target_record),
        }
    )
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            "identity-settlement-wait",
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    runner_identity: tuple[int, str] | None = None
    target_identity: tuple[int, str] | None = None
    try:
        register_installer_process(parent, process)
        wait_for_path(marker)
        runner_identity = read_identity_record(runner_record, "runner")
        target_identity = read_identity_record(target_record, "target")
        require_identity_gone(*runner_identity)
        require_identity_gone(*target_identity)
        deadline = time.monotonic() + 5.0
        groups = installer_cgroups(parent, process.pid)
        while (
            len(groups) == 1
            and read_cgroup_members(groups[0])
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
            groups = installer_cgroups(parent, process.pid)
        if len(groups) != 1 or read_cgroup_members(groups[0]) or not work.exists():
            raise SystemExit(
                f"identity settlement {signal_name} pre-release residue changed: "
                f"groups={[entry.name for entry in groups]} "
                f"members={[] if len(groups) != 1 else sorted(read_cgroup_members(groups[0]))} "
                f"work={int(work.exists())}"
            )
        if signum is not None:
            FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signum)
        release.write_text("release\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=15.0)
        groups = installer_cgroups(parent, process.pid)
        if (
            process.returncode != expected_status
            or stdout
            != f"INSTALLER_PHASE_STATUS={expected_status}\n".encode("ascii")
            or len(groups) != 1
            or read_cgroup_members(groups[0])
            or not work.exists()
            or b"APT phase cgroup cleanup did not converge" not in stderr
        ):
            raise SystemExit(
                f"identity settlement {signal_name} changed: "
                f"status={process.returncode} stdout={stdout!r} "
                f"stderr={stderr[-512:]!r} groups={[entry.name for entry in groups]}"
            )
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work, expected_retained=True,
                               identity_records=(runner_record, target_record))


@managed_fixture
def run_cgroup_path_replacement_case(root: pathlib.Path, source: str) -> None:
    path_anchor = (
        "  apt_phase_cgroup_path_identity_matches || return 1\n"
        '  leaf_path="/proc/self/fd/$apt_phase_cgroup_parent_fd/'
        '$apt_phase_cgroup_leaf"\n'
    )
    path_replacement = (
        "  fixture_replace_apt_phase_cgroup_path || return 1\n"
        '  leaf_path="/proc/self/fd/$apt_phase_cgroup_parent_fd/'
        '$apt_phase_cgroup_leaf"\n'
    )
    preamble = """fixture_replace_apt_phase_cgroup_path() {
  local leaf_path sleeper_pid sleeper_start original_identity
  local replacement_identity

  if [ -e "$HAPTICS_TEST_REPLACEMENT_DONE" ]; then
    apt_phase_cgroup_path_identity_matches
    return
  fi
  leaf_path="/proc/self/fd/$apt_phase_cgroup_parent_fd/$apt_phase_cgroup_leaf"
  original_identity=$(/usr/bin/stat -Lc '%d:%i' -- "$leaf_path") || return 1
  /usr/bin/rmdir -- "$leaf_path" || return 1
  /usr/bin/mkdir -- "$leaf_path" || return 1
  replacement_identity=$(/usr/bin/stat -Lc '%d:%i' -- "$leaf_path") || return 1
  /usr/bin/sleep 30 </dev/null >/dev/null 2>&1 &
  sleeper_pid=$!
  if ! printf '%s\\n' "$sleeper_pid" > "$leaf_path/cgroup.procs"; then
    /bin/kill -s TERM -- "$sleeper_pid" 2>/dev/null || true
    wait "$sleeper_pid" 2>/dev/null || true
    return 1
  fi
  sleeper_start=$(read_process_start_time "$sleeper_pid") || return 1
  printf '%s %s %s %s\\n' "$sleeper_pid" "$sleeper_start" \
    "$original_identity" "$replacement_identity" > \
    "$HAPTICS_TEST_REPLACEMENT_RECORD" || return 1
  : > "$HAPTICS_TEST_REPLACEMENT_DONE"
  apt_phase_cgroup_path_identity_matches
}
"""
    harness = root / "installer-cgroup-path-replacement.sh"
    work = root / "installer-cgroup-path-replacement.work"
    sentinel = root / "installer-cgroup-path-replacement.command"
    record = root / "installer-cgroup-path-replacement.record"
    done = root / "installer-cgroup-path-replacement.done"
    render_installer_harness(
        source,
        harness,
        lifecycle_replacements=((path_anchor, path_replacement),),
        preamble=preamble,
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_COMMAND_SENTINEL": str(sentinel),
            "HAPTICS_TEST_REPLACEMENT_RECORD": str(record),
            "HAPTICS_TEST_REPLACEMENT_DONE": str(done),
        }
    )
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            "installer-sentinel",
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    try:
        register_installer_process(parent, process)
        stdout, stderr = process.communicate(timeout=15.0)
        fields = record.read_text(encoding="ascii").strip().split()
        if (
            len(fields) != 4
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or any(
                len(identity.split(":")) != 2
                or any(not part.isdigit() for part in identity.split(":"))
                for identity in fields[2:]
            )
        ):
            raise SystemExit("cgroup replacement fixture record is malformed")
        sleeper_pid = int(fields[0], 10)
        sleeper_start = fields[1]
        original_identity, replacement_identity = fields[2:]
        groups = installer_cgroups(parent, process.pid)
        identities = {
            f"{group.stat().st_dev}:{group.stat().st_ino}": group for group in groups
        }
        replacement = identities.get(replacement_identity)
        replacement_members = (
            frozenset() if replacement is None else read_cgroup_members(replacement)
        )
        sleeper_current = process_start_time(sleeper_pid)
        if (
            process.returncode != 125
            or stdout != b"INSTALLER_PHASE_STATUS=125\n"
            or not sentinel.exists()
            or not work.exists()
            or len(groups) != 1
            or original_identity in identities
            or replacement is None
            or sleeper_pid not in replacement_members
            or sleeper_current != sleeper_start
            or b"APT phase cgroup cleanup did not converge" not in stderr
        ):
            raise SystemExit(
                "installer cgroup path replacement changed: "
                f"status={process.returncode} stdout={stdout!r} "
                f"stderr={stderr[-512:]!r} groups={[entry.name for entry in groups]} "
                f"record={fields!r} identities={tuple(identities)} "
                f"members={sorted(replacement_members)} sleeper={sleeper_current!r}"
            )
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work, expected_retained=True,
                               identity_records=(record,))


def installer_cgroup_fault_matrix(root: pathlib.Path) -> None:
    if os.geteuid() != 0:
        raise SystemExit("installer cgroup fault matrix requires root")
    source = INSTALLER.read_text(encoding="utf-8")
    barrier = """fixture_fault_barrier() {
  if [ -n "${HAPTICS_TEST_GAP_MARKER:-}" ]; then
    printf 'ready\\n' > "$HAPTICS_TEST_GAP_MARKER"
    while [ ! -e "$HAPTICS_TEST_GAP_RELEASE" ]; do
      /usr/bin/sleep 0.01
    done
  fi
}
"""
    mkdir_fault = barrier + """fixture_mkdir_applied_error() {
  /usr/bin/mkdir "$@" || return $?
  fixture_fault_barrier
  return 77
}
"""
    stat_fault = barrier + """fixture_stat_applied_error() {
  /usr/bin/stat "$@" || return $?
  fixture_fault_barrier
  return 77
}
"""
    mkdir_anchor = '  if ! /usr/bin/mkdir -- "$child_path"; then'
    identity_anchor = (
        "  if ! identity=$(/usr/bin/stat -Lc '%d:%i' -- \\\n"
        '    "/proc/self/fd/$apt_phase_cgroup_fd"); then'
    )
    run_cgroup_clean_fault_case(
        root,
        source,
        "mkdir-applied-error",
        lifecycle_replacements=(
            (
                mkdir_anchor,
                '  if ! fixture_mkdir_applied_error -- "$child_path"; then',
            ),
        ),
        preamble=mkdir_fault,
    )
    run_cgroup_clean_fault_case(
        root,
        source,
        "directory-open-error",
        lifecycle_replacements=(
            (
                '  if ! exec {apt_phase_cgroup_fd}< "$child_path"; then',
                "  if ! /bin/false; then",
            ),
        ),
    )
    run_cgroup_clean_fault_case(
        root,
        source,
        "identity-applied-error",
        lifecycle_replacements=(
            (
                identity_anchor,
                "  if ! identity=$(fixture_stat_applied_error -Lc '%d:%i' -- \\\n"
                '    "/proc/self/fd/$apt_phase_cgroup_fd"); then',
            ),
        ),
        preamble=stat_fault,
    )
    control_line = (
        "  for control in cgroup.procs cgroup.kill cgroup.events cgroup.type; do"
    )
    controls = ("cgroup.procs", "cgroup.kill", "cgroup.events", "cgroup.type")
    for index, control in enumerate(controls):
        mutated = list(controls)
        mutated[index] = f"{control}.missing"
        run_cgroup_clean_fault_case(
            root,
            source,
            f"missing-{control.replace('.', '-')}",
            lifecycle_replacements=(
                (control_line, "  for control in " + " ".join(mutated) + "; do"),
            ),
        )
    run_cgroup_clean_fault_case(
        root,
        source,
        "wrong-type",
        lifecycle_replacements=(
            (
                '  cgroup_type=$(< "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.type")',
                "  cgroup_type=threaded",
            ),
        ),
    )
    run_cgroup_clean_fault_case(
        root,
        source,
        "events-read-error",
        lifecycle_replacements=(
            (
                '"$(apt_phase_cgroup_populated)" != 0',
                '"$(fixture_populated_failure)" != 0',
            ),
        ),
        preamble="fixture_populated_failure() { return 77; }\n",
    )

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal_name = signal.Signals(signum).name.lower()
        expected = 128 + signum
        run_cgroup_clean_fault_case(
            root,
            source,
            f"mkdir-applied-error-{signal_name}",
            lifecycle_replacements=(
                (
                    mkdir_anchor,
                    '  if ! fixture_mkdir_applied_error -- "$child_path"; then',
                ),
            ),
            preamble=mkdir_fault,
            signum=signum,
            expected_status=expected,
        )
        run_cgroup_clean_fault_case(
            root,
            source,
            f"identity-applied-error-{signal_name}",
            lifecycle_replacements=(
                (
                    identity_anchor,
                    "  if ! identity=$(fixture_stat_applied_error -Lc '%d:%i' -- \\\n"
                    '    "/proc/self/fd/$apt_phase_cgroup_fd"); then',
                ),
            ),
            preamble=stat_fault,
            signum=signum,
            expected_status=expected,
        )

    rmdir_preamble = """fixture_rmdir_applied_error() {
  /usr/bin/rmdir "$@" || return $?
  return 77
}
"""
    run_cgroup_clean_fault_case(
        root,
        source,
        "rmdir-applied-error",
        lifecycle_replacements=(
            (
                '  if /usr/bin/rmdir -- "$leaf_path"; then',
                '  if fixture_rmdir_applied_error -- "$leaf_path"; then',
            ),
        ),
        preamble=rmdir_preamble,
        expected_status=0,
        mode="status",
    )
    run_cgroup_path_replacement_case(root, source)

    run_cgroup_settlement_fault_case(
        root,
        source,
        "success",
        expected_status=125,
        mode="status",
    )
    run_cgroup_settlement_fault_case(
        root,
        source,
        "command-77",
        expected_status=77,
        mode="status",
        fixture_argument="77",
    )
    for status in (100, 125):
        run_cgroup_settlement_fault_case(
            root,
            source,
            f"command-{status}",
            expected_status=status,
            mode="status",
            fixture_argument=str(status),
        )
    run_cgroup_settlement_fault_case(
        root,
        source,
        "timeout",
        expected_status=124,
        mode="wait",
        timeout_seconds="0.25",
    )
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        run_cgroup_settlement_fault_case(
            root,
            source,
            f"cancel-{signal.Signals(signum).name.lower()}",
            expected_status=128 + signum,
            mode="wait",
            signum=signum,
        )

    terminal_settlement = TERMINAL_SETTLEMENT
    injected_members = terminal_settlement + "  apt_phase_cgroup_had_members=1\n"
    for command_status, expected_status in (
        (0, 125),
        (77, 77),
        (100, 100),
        (124, 124),
        (125, 125),
        (130, 130),
        (137, 137),
        (143, 143),
    ):
        run_cgroup_clean_fault_case(
            root,
            source,
            f"settled-members-{command_status}",
            lifecycle_replacements=(),
            run_phase_replacements=((terminal_settlement, injected_members),),
            expected_status=expected_status,
            mode="status",
            fixture_argument=str(command_status),
        )

    for command_status, expected_status in (
        (0, 125),
        (77, 77),
        (130, 130),
        (137, 137),
        (143, 143),
    ):
        run_cgroup_real_member_case(
            root,
            source,
            command_status,
            expected_status,
        )

    run_identity_settlement_fault_case(root, source, None)
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        run_identity_settlement_fault_case(root, source, signum)

    for install_status, expected_status in (
        ("0", 125),
        ("77", 77),
        ("100", 100),
        ("124", 124),
        ("125", 125),
    ):
        run_installer_transaction_case(
            root,
            source,
            f"cgroup-settlement-{install_status}",
            expected_status,
            install_status=install_status,
            settlement_failure=True,
        )


def require_identity_gone(pid: int, start_time: str) -> None:
    FIXTURE_SUPPORT.require_identity_gone(ProcessIdentity(pid, start_time), timeout=5.0)


def installer_cgroup_hostile_integration(root: pathlib.Path) -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    mutated = replace_once(
        source, '[ "$populated" = 0 ] || apt_phase_cgroup_had_members=1',
        ":", "real-member observation mutation",
    )
    try:
        run_cgroup_real_member_case(root, mutated, 0, 125)
    except SystemExit as error:
        if "real cgroup member status 0 changed" not in str(error):
            raise
    else:
        raise SystemExit("real-member integration accepted a missing populated latch")
    print("HAPTICS_CGROUP_REAL_MEMBER_MUTATION=PASS")


@managed_fixture
def run_installer_signal_case(
    root: pathlib.Path,
    source: str,
    name: str,
    signum: int,
    boundary: str | None = None,
) -> None:
    harness = root / f"installer-{name}.sh"
    work = root / f"installer-{name}.work"
    render_installer_harness(source, harness, boundary)
    environment = os.environ.copy()
    marker = root / f"installer-{name}.marker"
    release = root / f"installer-{name}.release"
    command_sentinel = root / f"installer-{name}.command"
    environment["HAPTICS_TEST_COMMAND_SENTINEL"] = str(command_sentinel)
    if boundary in {"spawn", "identity", "identity-cleanup", "prologue"}:
        environment["HAPTICS_TEST_GAP_MARKER"] = str(marker)
        environment["HAPTICS_TEST_GAP_RELEASE"] = str(release)
        fixture_mode = "installer-sentinel" if boundary == "prologue" else "wait"
    elif boundary == "wait":
        environment["HAPTICS_TEST_WAIT_MARKER"] = str(marker)
        environment["HAPTICS_TEST_WAIT_RELEASE"] = str(release)
        fixture_mode = "status"
    else:
        fixture_mode = "wait"
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            fixture_mode,
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    managed_pid: int | None = None
    managed_start: str | None = None
    cancellation_started: float | None = None
    try:
        if boundary is not None:
            wait_for_path(marker)
        if boundary == "wait":
            runner_pid = int(marker.read_text(encoding="ascii").strip(), 10)
            if process_start_time(runner_pid) is not None:
                raise SystemExit("installer wait-boundary runner was not reaped")
        elif boundary in {"prologue", "identity-cleanup"}:
            pass
        else:
            managed_pid = wait_for_pid_output(work / "phase.out")
            managed_start = recorded_identity(pathlib.Path(environment["HAPTICS_TEST_IDENTITY_RECORD"]), managed_pid).start_time
            if managed_start is None:
                raise SystemExit("installer managed command exited before cancellation")
        cancellation_started = time.monotonic()
        FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signum)
        if boundary is not None:
            release.write_text("release\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=15.0)
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work,
                               identities=((managed_pid, managed_start) if managed_pid is not None and managed_start is not None else None,))

    if managed_pid is not None and managed_start is not None:
        require_pid_gone(managed_pid, f"installer {name}", managed_start)
    expected = 128 + signum
    cancellation_elapsed = (
        0.0
        if cancellation_started is None
        else time.monotonic() - cancellation_started
    )
    if (
        process.returncode != expected
        or stdout != f"INSTALLER_PHASE_STATUS={expected}\n".encode("ascii")
        or (
            boundary not in {"wait", "prologue", "identity-cleanup"}
            and b"caller-cancelled" not in stderr
        )
        or (boundary == "identity" and cancellation_elapsed >= 4.0)
        or (boundary == "prologue" and command_sentinel.exists())
        or work.exists()
    ):
        raise SystemExit(
            f"installer {name} cancellation contract changed: "
            f"status={process.returncode} elapsed={cancellation_elapsed:.3f} "
            f"stdout={stdout!r} stderr={stderr[-512:]!r}"
        )


@managed_fixture
def installer_bootstrap_int_fixture(root: pathlib.Path, source: str) -> None:
    harness = root / "installer-bootstrap-int.sh"
    wrapper = root / "installer-bootstrap-int.py"
    work = root / "installer-bootstrap-int.work"
    marker = root / "installer-bootstrap-int.marker"
    release = root / "installer-bootstrap-int.release"
    command_sentinel = root / "installer-bootstrap-int.command"
    render_installer_harness(source, harness)
    wrapper.write_text(
        """#!/usr/bin/python3
import os
import pathlib
import signal
import sys
import time

marker = pathlib.Path(os.environ["HAPTICS_TEST_BOOTSTRAP_MARKER"])
release = pathlib.Path(os.environ["HAPTICS_TEST_BOOTSTRAP_RELEASE"])
signal.signal(signal.SIGINT, signal.SIG_IGN)
ignored = int(signal.getsignal(signal.SIGINT) is signal.SIG_IGN)
ready = marker.with_suffix(".preparing")
ready.write_text(f"ignored={ignored}\\npid={os.getpid()}\\n", encoding="ascii")
ready.replace(marker)
while not release.exists():
    time.sleep(0.005)
python = "/usr/bin/python3"
runner = os.environ["HAPTICS_TEST_REAL_RUNNER"]
os.execv(python, [python, "-I", "-B", runner, *sys.argv[1:]])
""",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_BOOTSTRAP_MARKER": str(marker),
            "HAPTICS_TEST_BOOTSTRAP_RELEASE": str(release),
            "HAPTICS_TEST_REAL_RUNNER": str(RUNNER),
            "HAPTICS_TEST_COMMAND_SENTINEL": str(command_sentinel),
        }
    )
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(wrapper),
            "installer-sentinel",
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    required_release = False
    cancellation_started = 0.0
    try:
        wait_for_path(marker)
        if "ignored=1\n" not in marker.read_text(encoding="ascii"):
            raise SystemExit("bootstrap Python did not establish ignored SIGINT")
        cancellation_started = time.monotonic()
        FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signal.SIGINT)
        prompt_deadline = cancellation_started + 1.5
        while process.poll() is None and time.monotonic() < prompt_deadline:
            time.sleep(0.01)
        if process.poll() is None:
            required_release = True
            release.write_text("release\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=12.0)
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work)

    elapsed = time.monotonic() - cancellation_started
    if (
        process.returncode != 130
        or stdout != b"INSTALLER_PHASE_STATUS=130\n"
        or required_release
        or elapsed >= 1.5
        or command_sentinel.exists()
        or work.exists()
        or b"deadline-exceeded" in stderr
    ):
        raise SystemExit(
            "installer bootstrap INT cancellation contract changed: "
            f"status={process.returncode} elapsed={elapsed:.3f} "
            f"required_release={int(required_release)} stdout={stdout!r} "
            f"stderr={stderr[-512:]!r}"
        )


def installer_custody_fixture(root: pathlib.Path) -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    validate_installer_custody(source)
    installer_custody_mutations(source)
    run_installer_signal_case(root, source, "hup", signal.SIGHUP)
    run_installer_signal_case(root, source, "int", signal.SIGINT)
    run_installer_signal_case(root, source, "term", signal.SIGTERM)
    installer_bootstrap_int_fixture(root, source)
    run_installer_signal_case(
        root, source, "prologue-gap", signal.SIGTERM, "prologue"
    )
    run_installer_signal_case(root, source, "spawn-gap", signal.SIGTERM, "spawn")
    run_installer_signal_case(
        root, source, "identity-gap", signal.SIGTERM, "identity"
    )
    run_installer_signal_case(
        root,
        source,
        "identity-cleanup-gap",
        signal.SIGTERM,
        "identity-cleanup",
    )
    run_installer_signal_case(root, source, "wait-gap", signal.SIGTERM, "wait")
    run_installer_transaction_case(
        root, source, "cancel-install", 143, cancel_role="install"
    )
    run_installer_transaction_case(
        root,
        source,
        "cancel-marker",
        143,
        cancel_role="marker",
        install_status="0",
    )
    run_installer_transaction_case(
        root,
        source,
        "cancel-post",
        143,
        cancel_role="post",
        install_status="0",
    )
    run_installer_transaction_case(
        root,
        source,
        "cancel-gap-marker",
        143,
        cancel_role="gap-marker",
        install_status="0",
    )
    run_installer_transaction_case(
        root,
        source,
        "cancel-gap-post",
        143,
        cancel_role="gap-post",
        install_status="0",
    )
    run_installer_transaction_case(
        root,
        source,
        "install-failure",
        77,
        install_status="77",
        marker_status="88",
        post_status="89",
    )
    run_installer_transaction_case(
        root,
        source,
        "secondary-failure",
        1,
        install_status="0",
        marker_status="88",
        post_status="89",
    )


def render_installer_transaction_harness(
    source: str,
    destination: pathlib.Path,
    *,
    settlement_failure: bool = False,
    identity_settlement_failure: bool = False,
) -> None:
    lifecycle = "work_dir=\n" + exact_section(
        source, "work_dir=\n", "\nearly_script_path=", "lifecycle"
    )
    run_phase = "run_apt_phase() {\n" + exact_section(
        source,
        "run_apt_phase() {\n",
        "\n}\n\nverify_apt_partial_directory_empty()",
        "phase runner",
    ) + "\n}\n"
    preamble = ""
    if identity_settlement_failure:
        # Retain real cgroup cleanup in EXIT, but force the install return
        # boundary to report unknown containment. Only the real transaction
        # ledger can prove that this latch excludes marker/post.
        run_phase = replace_once(
            run_phase,
            'if ! runner_start_time=$(read_process_start_time "$runner_pid"); then',
            'if ! runner_start_time=$(fixture_transaction_identity "$runner_pid" "$phase"); then',
            "transaction identity failure",
        )
        run_phase = run_phase.replace(
            "if ! settle_apt_phase_cgroup; then",
            "if ! fixture_transaction_settlement; then",
        )
        preamble = """fixture_transaction_identity() {
  if [ "$2" != install ]; then
    read_process_start_time "$1"
    return
  fi
  local attempts=0
  while [ ! -s "$HAPTICS_TEST_TRANSACTION_LEDGER" ] && [ "$attempts" -lt 500 ]; do
    attempts=$((attempts + 1))
    /usr/bin/sleep 0.01
  done
  [ -s "$HAPTICS_TEST_TRANSACTION_LEDGER" ] || return 2
  printf '%s\\n' "$$" > "$HAPTICS_TEST_TRANSACTION_PID"
  if [ "$HAPTICS_TEST_TRANSACTION_CANCEL_ROLE" = identity ]; then
    while [ ! -e "$HAPTICS_TEST_TRANSACTION_RELEASE" ] && [ "$attempts" -lt 1000 ]; do
      attempts=$((attempts + 1))
      /usr/bin/sleep 0.01
    done
  fi
  return 1
}
fixture_transaction_settlement() {
  settle_apt_phase_cgroup || return $?
  return 1
}
"""
    if settlement_failure:
        terminal_settlement = TERMINAL_SETTLEMENT
        injected_settlement = terminal_settlement + (
            "  cgroup_status=125\n  apt_phase_cgroup_unsettled=1\n"
        )
        run_phase = replace_once(
            run_phase,
            terminal_settlement,
            injected_settlement,
            "terminal settlement failure",
        )
    transaction = 'compat_apt_stdout="$work_dir/package-install.stdout"\n' + exact_section(
        source,
        'compat_apt_stdout="$work_dir/package-install.stdout"\n',
        '\nif /usr/bin/python3 -I -B "$BISON_NORMALIZER"',
        "install transaction",
    )
    gap_marker_anchor = (
        'if [ "$install_cgroup_unsettled" = 1 ]; then\n'
        "  marker_status=125\n"
        "  post_status=125\n"
        "else\n"
        '  if run_apt_phase install-marker 120 "$marker_stdout"'
    )
    gap_marker = (
        'if [ "$install_cgroup_unsettled" = 1 ]; then\n'
        "  marker_status=125\n"
        "  post_status=125\n"
        "else\n"
        'if [ "$HAPTICS_TEST_TRANSACTION_CANCEL_ROLE" = gap-marker ]; then\n'
        '  printf \'%s\\n\' "$$" > "$HAPTICS_TEST_TRANSACTION_PID"\n'
        '  while [ ! -e "$HAPTICS_TEST_TRANSACTION_RELEASE" ]; do :; done\n'
        "fi\n"
        '  if run_apt_phase install-marker 120 "$marker_stdout"'
    )
    gap_post_anchor = (
        "  fi\n"
        '  if run_apt_phase install-post 120 "$post_stdout"'
    )
    gap_post = (
        "  fi\n"
        'if [ "$HAPTICS_TEST_TRANSACTION_CANCEL_ROLE" = gap-post ]; then\n'
        '  printf \'%s\\n\' "$$" > "$HAPTICS_TEST_TRANSACTION_PID"\n'
        '  while [ ! -e "$HAPTICS_TEST_TRANSACTION_RELEASE" ]; do :; done\n'
        "fi\n"
        '  if run_apt_phase install-post 120 "$post_stdout"'
    )
    if transaction.count(gap_marker_anchor) != 1 or transaction.count(
        gap_post_anchor
    ) != 1:
        raise SystemExit("installer transaction gap anchors changed")
    transaction = transaction.replace(gap_marker_anchor, gap_marker, 1)
    transaction = transaction.replace(gap_post_anchor, gap_post, 1)
    harness = f"""#!/bin/bash -p
set -euo pipefail
umask 077
{lifecycle}
{preamble}
APT_PHASE_RUNNER=$1
work_dir=$2
fixture_script=$3
{run_phase}
/usr/bin/mkdir -m 0700 -- "$work_dir"
APT_TRANSACTION_VERIFIER=$fixture_script
apt_command=({PYTHON} -I -B "$fixture_script" --fixture-transaction-install)
transaction_arguments=()
hook_manifest="$work_dir/fixture-manifest"
hook_marker="$work_dir/fixture-marker"
before_dpkg_state="$work_dir/fixture-before"
{transaction}
printf 'INSTALLER_TRANSACTION_STATUS=0\\n'
"""
    destination.write_text(harness, encoding="utf-8")
    destination.chmod(0o700)


def append_transaction_ledger(role: str) -> None:
    ledger_text = os.environ.get("HAPTICS_TEST_TRANSACTION_LEDGER", "")
    if not ledger_text or not pathlib.PurePosixPath(ledger_text).is_absolute():
        raise SystemExit("transaction helper ledger is not absolute")
    ledger = pathlib.Path(ledger_text)
    descriptor = os.open(
        ledger,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, role.encode("ascii") + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def transaction_helper(role: str) -> None:
    cancel_role = os.environ.get("HAPTICS_TEST_TRANSACTION_CANCEL_ROLE", "")
    pid_path = pathlib.Path(os.environ["HAPTICS_TEST_TRANSACTION_PID"])
    release_path = pathlib.Path(os.environ["HAPTICS_TEST_TRANSACTION_RELEASE"])

    def publish_and_wait() -> None:
        publish_fixture_identities(identity_record_path(pid_path), os.getpid())
        record_text = os.environ.get("HAPTICS_TEST_IDENTITY_RECORD")
        publish_fixture_identities(pathlib.Path(record_text) if record_text else None, os.getpid())
        pid_path.write_text(str(os.getpid()), encoding="ascii")
        if role == "install":
            time.sleep(30)
            return
        deadline = time.monotonic() + 10.0
        while not release_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not release_path.exists():
            raise SystemExit("transaction audit release did not arrive")

    if role == "install":
        append_transaction_ledger("install-start")
        if cancel_role == role:
            publish_and_wait()
        status = os.environ.get("HAPTICS_TEST_INSTALL_STATUS", "sleep")
        if status == "sleep":
            time.sleep(30)
        elif not status.isascii() or not status.isdigit():
            raise SystemExit("transaction helper install status is invalid")
        append_transaction_ledger("install-end")
        raise SystemExit(int(status, 10))
    if role == "marker":
        append_transaction_ledger("marker")
        if cancel_role == role:
            publish_and_wait()
            append_transaction_ledger("marker-complete")
        raise SystemExit(int(os.environ["HAPTICS_TEST_MARKER_STATUS"], 10))
    if role == "post":
        append_transaction_ledger("post")
        if cancel_role == role:
            publish_and_wait()
            append_transaction_ledger("post-complete")
        raise SystemExit(int(os.environ["HAPTICS_TEST_POST_STATUS"], 10))
    raise SystemExit("unknown transaction helper role")


@managed_fixture
def run_installer_transaction_case(
    root: pathlib.Path,
    source: str,
    name: str,
    expected_status: int,
    *,
    cancel_role: str | None = None,
    install_status: str = "sleep",
    marker_status: str = "0",
    post_status: str = "0",
    settlement_failure: bool = False,
    identity_settlement_failure: bool = False,
    signum: int = signal.SIGTERM,
) -> None:
    harness = root / f"installer-transaction-{name}.sh"
    work = root / f"installer-transaction-{name}.work"
    ledger = root / f"installer-transaction-{name}.ledger"
    pid_path = root / f"installer-transaction-{name}.pid"
    release_path = root / f"installer-transaction-{name}.release"
    render_installer_transaction_harness(
        source,
        harness,
        settlement_failure=settlement_failure,
        identity_settlement_failure=identity_settlement_failure,
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HAPTICS_TEST_TRANSACTION_LEDGER": str(ledger),
            "HAPTICS_TEST_TRANSACTION_PID": str(pid_path),
            "HAPTICS_TEST_TRANSACTION_RELEASE": str(release_path),
            "HAPTICS_TEST_TRANSACTION_CANCEL_ROLE": cancel_role or "",
            "HAPTICS_TEST_INSTALL_STATUS": install_status,
            "HAPTICS_TEST_MARKER_STATUS": marker_status,
            "HAPTICS_TEST_POST_STATUS": post_status,
        }
    )
    parent = process_cgroup_directory(os.getpid())
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    managed_pid: int | None = None
    managed_start: str | None = None
    try:
        if cancel_role is not None:
            wait_for_path(pid_path)
            managed_pid = int(pid_path.read_text(encoding="ascii").strip(), 10)
            managed_start = (process.fixture_birth_identity.start_time if managed_pid == process.pid else
                             recorded_identity(identity_record_path(pid_path), managed_pid).start_time)
            if managed_start is None:
                raise SystemExit("transaction helper exited before cancellation")
            FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signum)
            if cancel_role != "install":
                release_path.write_text("release\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=18.0)
    finally:
        finish_fixture_cleanup(process, parent=parent, work=work,
                               identities=((managed_pid, managed_start) if managed_pid is not None and managed_start is not None else None,))

    if managed_pid is not None and managed_start is not None:
        require_pid_gone(
            managed_pid,
            f"installer transaction {name}",
            managed_start,
        )
    if identity_settlement_failure:
        expected_ledger = b"install-start\n"
    elif settlement_failure:
        expected_ledger = b"install-start\ninstall-end\n"
    elif cancel_role == "install":
        expected_ledger = b"install-start\nmarker\npost\n"
    elif cancel_role == "marker":
        expected_ledger = (
            b"install-start\ninstall-end\nmarker\nmarker-complete\npost\n"
        )
    elif cancel_role == "post":
        expected_ledger = (
            b"install-start\ninstall-end\nmarker\npost\npost-complete\n"
        )
    else:
        expected_ledger = b"install-start\ninstall-end\nmarker\npost\n"
    if (
        process.returncode != expected_status
        or stdout
        or ledger.read_bytes() != expected_ledger
        or work.exists()
    ):
        raise SystemExit(
            f"installer transaction {name} changed: status={process.returncode} "
            f"stdout={stdout!r} stderr={stderr[-1024:]!r}"
        )
    if cancel_role == "install" and b"reason=caller-cancelled" not in stderr:
        raise SystemExit("installer transaction cancellation lost runner evidence")
    if cancel_role in {"marker", "post", "gap-marker", "gap-post"} and (
        b"reason=caller-cancelled" in stderr
    ):
        raise SystemExit("installer audit runner received a latched cancellation")


@managed_fixture
def installer_cgroup_supervisor_death_fixture(root: pathlib.Path) -> None:
    if os.geteuid() != 0:
        raise SystemExit("installer cgroup fixture requires root")
    source = INSTALLER.read_text(encoding="utf-8")
    harness = root / "installer-cgroup-supervisor-death.sh"
    work = root / "installer-cgroup-supervisor-death.work"
    runner_marker = root / "installer-cgroup-supervisor-death.runner"
    render_installer_harness(source, harness, "supervisor-death-cgroup")
    environment = os.environ.copy()
    environment["HAPTICS_TEST_RUNNER_PID"] = str(runner_marker)
    cgroup_parent = process_cgroup_directory(os.getpid())
    identities: dict[str, tuple[int, str]] = {}
    cgroup: FixtureCgroup | None = None
    emergency_cleanup = False
    environment["HAPTICS_TEST_IDENTITY_RECORD"] = str(work) + ".identity"
    process = fixture_popen(
        [
            "/bin/bash",
            "-p",
            str(harness),
            str(RUNNER),
            "supervisor-death-detached",
            str(work),
            str(pathlib.Path(__file__).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    try:
        installer_start = register_installer_process(cgroup_parent, process)
        runner_pid, runner_start = wait_for_identity_record(runner_marker, "runner")
        identities["runner"] = (runner_pid, runner_start)
        cgroup = wait_for_installer_cgroup(process.pid, installer_start)
        target_pid, descendant_pid = wait_for_pid_pair_output(work / "phase.out")
        birth_record = pathlib.Path(environment["HAPTICS_TEST_IDENTITY_RECORD"])
        for role, pid in (("target", target_pid), ("descendant", descendant_pid)):
            identity = recorded_identity(birth_record, pid)
            identities[role] = (identity.pid, identity.start_time)
        custodian_pid, custodian_start = read_identity_record(
            birth_record.with_name(birth_record.name + ".custodian"), "custodian"
        )
        custodian_identity = ProcessIdentity(custodian_pid, custodian_start)
        if (
            any(not FIXTURE_SUPPORT.identity_exists(ProcessIdentity(pid, start))
                for pid, start in identities.values())
            or not FIXTURE_SUPPORT.identity_exists(custodian_identity)
            or process_parent_pid(target_pid) != custodian_pid
            or process_parent_pid(custodian_pid) != runner_pid
        ):
            raise SystemExit("installer cgroup birth identities are not the owned command tree")
        expected_members = frozenset(pid for pid, _ in identities.values()) | {custodian_pid}
        if expected_members != read_cgroup_members(cgroup):
            raise SystemExit("installer cgroup did not contain the complete command tree")
        # A temporary parent observation must never become a cleanup target.
        # Only the birth record plus the authenticated tree/domain admits it.
        identities["custodian"] = (custodian_pid, custodian_start)

        for role in ("runner", "custodian"):
            pid, start = identities[role]
            if not signal_exact_identity(pid, start, signal.SIGSTOP):
                raise SystemExit(f"installer cgroup {role} stop was not delivered")
        stop_deadline = time.monotonic() + 2.0
        while True:
            all_stopped = True
            for role in ("runner", "custodian"):
                pid, start = identities[role]
                fields = pathlib.Path(f"/proc/{pid}/stat").read_text(
                    encoding="ascii"
                ).rsplit(") ", 1)[1].split()
                if len(fields) < 20 or fields[19] != start:
                    raise SystemExit(f"installer cgroup {role} changed before SIGKILL")
                all_stopped = all_stopped and fields[0] in ("T", "t")
            if all_stopped:
                break
            if time.monotonic() >= stop_deadline:
                raise SystemExit("installer cgroup supervisors did not stop")
            time.sleep(0.01)
        for role in ("custodian", "runner"):
            pid, start = identities[role]
            if not signal_exact_identity(pid, start, signal.SIGKILL):
                raise SystemExit(f"installer cgroup {role} kill was not delivered")
        stdout, stderr = process.communicate(timeout=15.0)

        for role, (pid, start) in identities.items():
            require_identity_gone(pid, start)
        if (
            process.returncode != 125
            or stdout != b"INSTALLER_PHASE_STATUS=125\n"
            or cgroup.exists()
            or work.exists()
        ):
            raise SystemExit(
                "installer cgroup supervisor-death cleanup changed: "
                f"status={process.returncode} stdout={stdout!r} stderr={stderr[-512:]!r} "
                f"cgroup_exists={cgroup.exists()} work_exists={work.exists()}"
            )
    finally:
        finish_fixture_cleanup(process, parent=cgroup_parent, work=work,
                               identities=identities.values())


@managed_fixture
def runner_supervisor_death_fixture(root: pathlib.Path) -> None:
    output = root / "supervisor-death.out"
    process = fixture_popen(
        runner_command(
            root,
            output,
            "supervisor-death",
            10,
            "supervisor-death-detached",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    target_pid: int | None = None
    target_start: str | None = None
    descendant_pid: int | None = None
    descendant_start: str | None = None
    emergency_cleanup = False
    try:
        target_pid, descendant_pid = wait_for_pid_pair_output(output)
        target_start = recorded_identity(identity_record_path(output), target_pid).start_time
        descendant_start = recorded_identity(identity_record_path(output), descendant_pid).start_time
        if target_start is None or descendant_start is None:
            raise SystemExit("supervisor-death process exited before injection")
        FIXTURE_SUPPORT.signal_identity(process.fixture_birth_identity, signal.SIGKILL)
        process.wait(timeout=3.0)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if (
                process_start_time(target_pid) != target_start
                and process_start_time(descendant_pid) != descendant_start
            ):
                break
            time.sleep(0.01)
        else:
            raise SystemExit("runner death left a published process identity")
        process.communicate(timeout=3.0)
    finally:
        finish_fixture_cleanup(process,
                               identities=((target_pid, target_start) if target_pid is not None and target_start is not None else None,
                                           (descendant_pid, descendant_start) if descendant_pid is not None and descendant_start is not None else None))
    if process.returncode != -signal.SIGKILL or emergency_cleanup:
        raise SystemExit("runner death did not contain its exact command tree")


def shared_stderr_flags_fixture() -> None:
    read_fd, write_fd = os.pipe()
    original_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    child = os.fork()
    if child == 0:
        try:
            os.dup2(write_fd, 2)
            os.close(read_fd)
            if write_fd != 2:
                os.close(write_fd)
            module = load_runner()
            module.write_bounded_stderr(b"d" * module.PUBLIC_DIAGNOSTIC_LIMIT)
        finally:
            os._exit(0)
    observed_nonblocking = False
    child_status: int | None = None
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            current_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
            if current_flags & os.O_NONBLOCK:
                observed_nonblocking = True
                os.kill(child, signal.SIGKILL)
                break
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                child_status = status
                break
            time.sleep(0.001)
        if child_status is None:
            waited, child_status = os.waitpid(child, 0)
            if waited != child:
                raise SystemExit("stderr flag fixture lost its child")
        final_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        if final_flags != original_flags:
            fcntl.fcntl(write_fd, fcntl.F_SETFL, original_flags)
            raise SystemExit("runner left inherited stderr flags changed")
        if observed_nonblocking:
            raise SystemExit("runner temporarily changed inherited stderr flags")
        if not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
            raise SystemExit("stderr flag fixture writer did not exit cleanly")
    finally:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            waited = child
        if waited == 0:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        current_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        if current_flags != original_flags:
            fcntl.fcntl(write_fd, fcntl.F_SETFL, original_flags)
        os.close(read_fd)
        os.close(write_fd)


def validate_installer_renderers(root: pathlib.Path) -> None:
    """Visit every matrix renderer before creating any fixture processes."""
    source = INSTALLER.read_text(encoding="utf-8")
    rendered: list[str] = []
    cases: list[str] = []

    class RenderComplete(Exception):
        pass

    def save_render(path, content, *args, **kwargs):
        rendered.append(content)
        return len(content)

    def prohibit_spawn(*args, **kwargs):
        raise RenderComplete()

    def render_only(function):
        def wrapped(*args, **kwargs):
            before = len(rendered)
            try:
                function(*args, **kwargs)
            except RenderComplete:
                if len(rendered) != before + 1:
                    raise SystemExit("matrix case did not render exactly one harness")
                cases.append(function.__name__)
                return
            raise SystemExit("matrix render preflight did not reach the spawn boundary")
        return wrapped

    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(pathlib.Path, "write_text", save_render))
        stack.enter_context(mock.patch.object(pathlib.Path, "chmod", lambda *a, **kw: None))
        stack.enter_context(mock.patch.object(subprocess, "Popen", prohibit_spawn))
        stack.enter_context(mock.patch.dict(globals(), {"fixture_popen": prohibit_spawn}))
        stack.enter_context(mock.patch.object(os, "geteuid", lambda: 0))
        stack.enter_context(mock.patch.dict(globals(), {
            "process_cgroup_directory": lambda pid: pathlib.Path("/sys/fs/cgroup"),
        }))
        for name in (
            "run_cgroup_clean_fault_case", "run_cgroup_settlement_fault_case",
            "run_cgroup_real_member_case", "run_identity_settlement_fault_case",
            "run_cgroup_path_replacement_case", "run_installer_transaction_case",
        ):
            stack.enter_context(mock.patch.dict(globals(), {name: render_only(globals()[name])}))
        for boundary in (None, "spawn", "identity", "identity-cleanup", "prologue",
                         "wait", "supervisor-death-cgroup"):
            render_installer_harness(source, root / "render-only.sh", boundary)
        render_installer_transaction_harness(source, root / "transaction-render-only.sh")
        installer_cgroup_fault_matrix(root)
    if len(cases) < 40 or not rendered:
        raise SystemExit("matrix render preflight missed the expected case set")
    print(f"HAPTICS_INSTALLER_RENDERERS=PASS cases={len(cases)}")


def installer_completion_protocol_fixture() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    functions = []
    for name in ("close_apt_phase_completion_channel",
                 "authenticate_apt_phase_completion"):
        start = source.index(name + "() {\n")
        end = source.index("\n}\n", start) + 3
        functions.append(source[start:end])
    program = "set -u\n" + "\n".join(functions) + r'''
apt_phase_completion_read_fd=$1
apt_phase_completion_write_fd=
if [ "$3" = closed ]; then
  exec {apt_phase_completion_read_fd}<&-
fi
result=0
authenticate_apt_phase_completion "$2" || result=$?
[ -z "$apt_phase_completion_read_fd" ] || exit 99
[ -z "$apt_phase_completion_write_fd" ] || exit 99
exit "$result"
'''
    cases = [(f"valid-{status}", f"{status}\n".encode(), status, 0)
             for status in (0, 1, 124, 125, 130, 137, 143, 255)]
    cases += [
        ("empty", b"", 0, 1),
        ("closed-descriptor", b"", 0, 1),
        ("missing-newline", b"0", 0, 1),
        ("different-status", b"1\n", 0, 1),
        ("extra-record", b"0\n0\n", 0, 1),
        ("partial-tail", b"0\nx", 0, 1),
        ("embedded-nul", b"0\x00\n", 0, 1),
        ("trailing-nul", b"0\n\x00", 0, 1),
        ("whitespace-tail", b"0\n ", 0, 1),
        ("long-frame", b"0\n" + b"x" * 64, 0, 1),
    ]
    for label, payload, expected, status in cases:
        read_fd, write_fd = os.pipe()
        try:
            if os.write(write_fd, payload) != len(payload):
                raise SystemExit("short fixture completion write")
            os.close(write_fd)
            write_fd = -1
            result = fixture_run(
                ["/bin/bash", "--noprofile", "--norc", "-p", "-c",
                 program, "completion-fixture", str(read_fd), str(expected),
                 "closed" if label == "closed-descriptor" else "open"],
                pass_fds=(read_fd,), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3.0,
            )
            require_status(result, status, f"completion record {label}")
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
    print(f"HAPTICS_COMPLETION_PROTOCOL=PASS cases={len(cases)}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-apt-phase-test.") as raw:
        root = pathlib.Path(raw)
        root.chmod(0o700)
        validate_installer_renderers(root)
        installer_completion_protocol_fixture()

        run_unit_case(
            root,
            "--unit-prepare-signal",
            b"HAPTICS_APT_PHASE_PREPARE_SIGNAL=PASS",
            b"status=143",
        )
        run_unit_case(
            root,
            "--unit-prespawn-signal",
            b"HAPTICS_APT_PHASE_PRESPAWN_SIGNAL=PASS",
            b"status=143",
        )
        run_unit_case(
            root,
            "--unit-spawn-commit-signal",
            b"HAPTICS_APT_PHASE_SPAWN_COMMIT_SIGNAL=PASS",
            b"status=143",
        )
        run_unit_case(
            root,
            "--unit-deadline-observation",
            b"HAPTICS_APT_PHASE_DEADLINE_OBSERVATION=PASS",
            b"status=124",
            b"reason=deadline-exceeded",
        )
        run_unit_case(
            root,
            "--unit-terminal-sigpending",
            b"HAPTICS_APT_PHASE_TERMINAL_SIGPENDING=PASS",
            b"status=125",
            b"terminal pending signal collection failed",
        )
        run_unit_case(
            root,
            "--unit-restrictive-umask",
            b"HAPTICS_APT_PHASE_RESTRICTIVE_UMASK=PASS",
        )
        run_unit_case(
            root,
            "--unit-signal-handoff",
            b"HAPTICS_APT_PHASE_SIGNAL_HANDOFF=PASS",
        )
        run_unit_case(
            root,
            "--unit-handler-restore-signal",
            b"HAPTICS_APT_PHASE_HANDLER_RESTORE_SIGNAL=PASS",
            b"status=143",
        )
        unit_exec_gate_failures(root)
        run_unit_case(
            root,
            "--unit-unread-diagnostic",
            b"HAPTICS_APT_PHASE_UNREAD_DIAGNOSTIC=PASS",
        )

        success, success_output = run_runner(
            root, "success.out", "success", 5, "status", "0"
        )
        require_status(success, 0, "successful phase")
        if success.stderr or success_output.read_bytes() != b"status-stdout\n":
            raise SystemExit("successful phase changed its private/public output contract")

        failed, failed_output = run_runner(
            root, "failed.out", "failed", 5, "status", "77"
        )
        require_status(failed, 77, "failed phase")
        if failed_output.read_bytes() != b"status-stdout\n" or not re.search(
            rb"APT_PHASE_FAILURE phase=failed status=77 command_status=77 "
            rb"reason=command-failed ",
            failed.stderr,
        ):
            raise SystemExit("failed phase did not preserve its exact status or output")

        pipe_eof_started = time.monotonic()
        pipe_eof, pipe_eof_output = run_runner(
            root, "pipe-eof.out", "pipe-eof", 5, "pipe-eof"
        )
        pipe_eof_elapsed = time.monotonic() - pipe_eof_started
        require_status(pipe_eof, 77, "pipe EOF phase")
        if (
            pipe_eof_output.read_bytes()
            or pipe_eof_elapsed < 0.25
            or b"command_status=77 reason=command-failed" not in pipe_eof.stderr
        ):
            raise SystemExit("pipe EOF was mistaken for leader termination")

        flood, flood_output = run_runner(
            root, "flood.out", "flood", 10, "flood"
        )
        require_status(flood, 73, "55 MiB phase")
        summary = (
            f"stderr_bytes={FLOOD_SIZE} stderr_lines={FLOOD_LINES} "
            f"stderr_sha256={FLOOD_SHA256}"
        ).encode("ascii")
        if (
            summary not in flood.stderr
            or b"reason=command-failed,apt-sandbox-fallback" not in flood.stderr
            or b"\\x1b" not in flood.stderr
            or f"omitted={FLOOD_SIZE - 2 * 16 * 1024}".encode("ascii")
            not in flood.stderr
            or b"--- apt stderr first cause ---" not in flood.stderr
            or b"hidden-middle" not in flood.stderr
            or len(flood.stderr) > 160 * 1024
            or flood_output.read_bytes()
        ):
            raise SystemExit("55 MiB phase lost evidence, sandbox scan, or sanitization")

        dual_flood, dual_flood_output = run_runner(
            root, "dual-flood.out", "dual-flood", 10, "dual-flood"
        )
        require_status(dual_flood, 77, "simultaneous stdout/stderr flood phase")
        expected_dual_stdout = DUAL_STDOUT_CHUNK * DUAL_CHUNKS
        expected_dual_stderr = DUAL_STDERR_CHUNK * DUAL_CHUNKS
        dual_tokens = (
            f"stdout_bytes={len(expected_dual_stdout)} stdout_lines={DUAL_CHUNKS} ".encode(
                "ascii"
            )
            + f"stdout_sha256={hashlib.sha256(expected_dual_stdout).hexdigest()}".encode(
                "ascii"
            ),
            f"stderr_bytes={len(expected_dual_stderr)} stderr_lines={DUAL_CHUNKS} ".encode(
                "ascii"
            )
            + f"stderr_sha256={hashlib.sha256(expected_dual_stderr).hexdigest()}".encode(
                "ascii"
            ),
        )
        if (
            dual_flood_output.read_bytes() != expected_dual_stdout
            or any(token not in dual_flood.stderr for token in dual_tokens)
            or b"command_status=77 reason=command-failed" not in dual_flood.stderr
        ):
            raise SystemExit("simultaneous stream flood lost bytes or status")

        controls, _ = run_runner(
            root, "controls.out", "controls", 5, "private-controls", str(root)
        )
        require_status(controls, 72, "private/control diagnostic phase")
        if (
            os.fsencode(root) in controls.stderr
            or b"\x1b" in controls.stderr
            or b"\r" in controls.stderr
            or b"\x00" in controls.stderr
            or b"<PRIVATE_ROOT>" not in controls.stderr
            or b"\\x1b" not in controls.stderr
            or b"\\x0d" not in controls.stderr
            or b"\\x00" not in controls.stderr
            or b"\n::error::" in controls.stderr
            or b"\\x3a:error::hostile" not in controls.stderr
        ):
            raise SystemExit("private/control diagnostic bytes were not sanitized")

        long_cause, _ = run_runner(
            root, "long-cause.out", "long-cause", 5, "long-cause", str(root)
        )
        require_status(long_cause, 74, "long no-newline cause phase")
        if (
            b"--- apt stderr first cause ---" not in long_cause.stderr
            or b"E: long-no-newline" not in long_cause.stderr
            or os.fsencode(root) in long_cause.stderr
            or b"<PRIVATE_ROOT>" not in long_cause.stderr
        ):
            raise SystemExit("long no-newline first-cause evidence was lost or leaked")

        boundary_private, _ = run_runner(
            root,
            "boundary-private.out",
            "boundary-private",
            5,
            "boundary-private",
            str(root),
        )
        require_status(boundary_private, 75, "private-path excerpt boundary phase")
        if (
            os.fsencode(root) in boundary_private.stderr
            or os.fsencode(root)[:5] in boundary_private.stderr
            or b"<PRIVATE_ROOT_FRAGMENT>" not in boundary_private.stderr
        ):
            raise SystemExit("private path fragment crossed an excerpt boundary")

        stdout_sandbox, stdout_sandbox_output = run_runner(
            root, "stdout-sandbox.out", "stdout-sandbox", 5, "stdout-sandbox"
        )
        require_status(stdout_sandbox, 125, "stdout sandbox phase")
        if (
            b"command_status=0 reason=apt-sandbox-fallback" not in stdout_sandbox.stderr
            or b"unsandboxed as root" not in stdout_sandbox_output.read_bytes()
        ):
            raise SystemExit("stdout sandbox fallback was not detected and retained")

        overflow, overflow_output = run_runner(
            root, "overflow.out", "overflow", 10, "stdout-overflow"
        )
        require_status(overflow, 125, "stdout overflow phase")
        expected_stdout_digest = hashlib.sha256()
        for _ in range(33):
            expected_stdout_digest.update(STDOUT_CHUNK)
        if (
            overflow_output.stat().st_size != 8 * 1024 * 1024
            or b"reason=stdout-limit-exceeded" not in overflow.stderr
            or f"stdout_sha256={expected_stdout_digest.hexdigest()}".encode("ascii")
            not in overflow.stderr
        ):
            raise SystemExit("stdout overflow did not retain its complete evidence and cap")

        descendant, descendant_output = run_runner(
            root, "descendant.out", "descendant", 5, "detached-descendant"
        )
        require_status(descendant, 125, "detached descendant phase")
        descendant_pid = int(descendant_output.read_text("ascii").strip(), 10)
        require_pid_gone(descendant_pid, "detached descendant phase",
                         recorded_identity(identity_record_path(descendant_output), descendant_pid).start_time)
        if b"unexpected-descendant" not in descendant.stderr:
            raise SystemExit("detached descendant was cleaned without failure evidence")

        failed_descendant, failed_descendant_output = run_runner(
            root,
            "failed-descendant.out",
            "failed-descendant",
            5,
            "detached-descendant-status",
        )
        require_status(failed_descendant, 77, "failed detached descendant phase")
        failed_descendant_pid = int(
            failed_descendant_output.read_text("ascii").strip(), 10
        )
        require_pid_gone(failed_descendant_pid, "failed detached descendant phase",
                         recorded_identity(identity_record_path(failed_descendant_output), failed_descendant_pid).start_time)
        if (
            b"command_status=77" not in failed_descendant.stderr
            or b"command-failed" not in failed_descendant.stderr
            or b"unexpected-descendant" not in failed_descendant.stderr
        ):
            raise SystemExit("natural failure was overwritten by descendant cleanup")

        timed, timed_output = run_runner(
            root, "timeout.out", "timeout", 0.5, "wait"
        )
        require_status(timed, 124, "timeout phase")
        timed_pid = int(timed_output.read_text("ascii").strip(), 10)
        require_pid_gone(timed_pid, "timeout phase",
                         recorded_identity(identity_record_path(timed_output), timed_pid).start_time)
        if b"reason=deadline-exceeded" not in timed.stderr:
            raise SystemExit("timeout phase lost its terminal reason")

        timeout_descendant, timeout_descendant_output = run_runner(
            root,
            "timeout-descendant.out",
            "timeout-descendant",
            0.5,
            "timeout-descendant",
        )
        require_status(timeout_descendant, 124, "timeout detached descendant phase")
        timeout_descendant_pid = int(
            timeout_descendant_output.read_text("ascii").strip(), 10
        )
        require_pid_gone(timeout_descendant_pid, "timeout detached descendant phase",
                         recorded_identity(identity_record_path(timeout_descendant_output), timeout_descendant_pid).start_time)
        if (
            b"reason=deadline-exceeded" not in timeout_descendant.stderr
            or b"unexpected-descendant" not in timeout_descendant.stderr
        ):
            raise SystemExit("timeout status was overwritten by descendant cleanup")

        run_runner_wrapper(root, "ignored-sigchld", 125)
        run_runner_wrapper(root, "blocked-sigchld", 125)
        run_runner_wrapper(root, "high-fd", 77)

        for signum, expected_status in (
            (signal.SIGHUP, 129),
            (signal.SIGINT, 130),
            (signal.SIGTERM, 143),
        ):
            run_signal_fixture(root, signum, expected_status)

        replacement_path = root / "replacement.out"
        replacement = fixture_run(
            runner_command(
                root,
                replacement_path,
                "replacement",
                5,
                "replace-output",
                str(replacement_path),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
        )
        require_status(replacement, 125, "output replacement phase")
        if (
            replacement_path.read_bytes() != b"replacement-owned-by-fixture\n"
            or b"runner-containment-failed" not in replacement.stderr
        ):
            raise SystemExit("output replacement was deleted, overwritten, or accepted")

        owned_parent = root / "owned-parent"
        moved_parent = root / "moved-parent"
        owned_parent.mkdir(mode=0o700)
        parent_output = owned_parent / "parent.out"
        parent_replacement = fixture_run(
            runner_command(
                root,
                parent_output,
                "parent-replacement",
                5,
                "replace-parent",
                str(owned_parent),
                str(moved_parent),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
        )
        require_status(parent_replacement, 125, "output parent replacement phase")
        if (
            not owned_parent.is_dir()
            or list(owned_parent.iterdir())
            or not moved_parent.is_dir()
            or list(moved_parent.iterdir())
            or b"runner-containment-failed" not in parent_replacement.stderr
        ):
            raise SystemExit("output parent replacement was accepted or not rolled back")

        root_link = root.parent / f"{root.name}.root-link"
        root_link.symlink_to(root, target_is_directory=True)
        linked_root_output = root_link / "linked-root.out"
        linked_root = fixture_run(
            runner_command(
                root_link,
                linked_root_output,
                "linked-root",
                5,
                "status",
                "0",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=8.0,
        )
        require_status(linked_root, 125, "symlink private-root phase")
        if linked_root_output.exists():
            raise SystemExit("symlink private-root phase created output")
        root_link.unlink()

        real_parent = root / "real-parent"
        linked_parent = root / "linked-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        linked_parent_output = linked_parent / "linked-parent.out"
        linked_parent_result = fixture_run(
            runner_command(
                root,
                linked_parent_output,
                "linked-parent",
                5,
                "status",
                "0",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=8.0,
        )
        require_status(linked_parent_result, 125, "symlink stdout-parent phase")
        if (real_parent / linked_parent_output.name).exists():
            raise SystemExit("symlink stdout-parent phase created output")
        linked_parent.unlink()

        preexisting = root / "preexisting.out"
        preexisting.write_bytes(b"do-not-truncate\n")
        preexisting.chmod(0o600)
        preexisting_result = fixture_run(
            runner_command(root, preexisting, "preexisting", 5, "status", "0"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=8.0,
        )
        require_status(preexisting_result, 125, "preexisting stdout phase")
        if preexisting.read_bytes() != b"do-not-truncate\n":
            raise SystemExit("preexisting stdout phase truncated its victim")

        spawn_handoff = fixture_run(
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--unit-spawn-handoff",
                str(root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
        )
        require_status(spawn_handoff, 0, "Popen initializer handoff fixture")
        if (
            spawn_handoff.stdout != b"HAPTICS_APT_PHASE_SPAWN_HANDOFF=PASS\n"
            or b"command_status=none" not in spawn_handoff.stderr
            or b"runner-containment-failed" not in spawn_handoff.stderr
        ):
            raise SystemExit("Popen initializer handoff evidence changed")

        pidfd_handoff = fixture_run(
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--unit-pidfd-handoff",
                str(root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
        )
        require_status(pidfd_handoff, 0, "pidfd handoff fixture")
        if (
            pidfd_handoff.stdout != b"HAPTICS_APT_PHASE_PIDFD_HANDOFF=PASS\n"
            or b"command_status=none" not in pidfd_handoff.stderr
            or b"runner-containment-failed" not in pidfd_handoff.stderr
        ):
            raise SystemExit("pidfd handoff evidence changed")

        cleanup_failure = fixture_run(
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--unit-cleanup-failure",
                str(root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
        )
        require_status(cleanup_failure, 0, "cleanup-failure fixture")
        if (
            cleanup_failure.stdout != b"HAPTICS_APT_PHASE_CLEANUP_FAILURE=PASS\n"
            or b"status=125 command_status=0" not in cleanup_failure.stderr
            or b"status=77 command_status=77" not in cleanup_failure.stderr
            or b"status=124 command_status=137" not in cleanup_failure.stderr
            or b"runner-containment-failed" not in cleanup_failure.stderr
        ):
            raise SystemExit("cleanup-failure evidence changed")

        final_signal = fixture_run(
            [
                PYTHON,
                "-I",
                "-B",
                str(pathlib.Path(__file__).resolve()),
                "--unit-final-signal",
                str(root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=12.0,
        )
        require_status(final_signal, 0, "final signal boundary fixture")
        if (
            final_signal.stdout != b"HAPTICS_APT_PHASE_FINAL_SIGNAL=PASS\n"
            or b"status=143 command_status=0" not in final_signal.stderr
            or b"reason=caller-cancelled" not in final_signal.stderr
        ):
            raise SystemExit("final signal boundary evidence changed")

        unit_failure_bound()
        runner_supervisor_death_fixture(root)
        killed_custodian, killed_custodian_output = run_runner(
            root,
            "killed-custodian.out",
            "killed-custodian",
            5,
            "kill-custodian",
        )
        require_status(killed_custodian, 125, "killed custodian phase")
        if (
            killed_custodian_output.read_bytes()
            or b"command_status=none" not in killed_custodian.stderr
            or b"runner-containment-failed" not in killed_custodian.stderr
        ):
            raise SystemExit("missing custody report authenticated wrapper status")
        shared_stderr_flags_fixture()

        escape = root.parent / "tb321fu-haptics-apt-phase-escape"
        if escape.exists() or escape.is_symlink():
            raise SystemExit("path-escape fixture target already exists")
        escaped = fixture_run(
            runner_command(root, escape, "escape", 5, "status", "0"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=8.0,
        )
        require_status(escaped, 125, "path escape phase")
        if escape.exists() or escape.is_symlink():
            raise SystemExit("path escape phase created an output outside its root")

        installer_custody_fixture(root)
        if os.geteuid() == 0:
            installer_cgroup_supervisor_death_fixture(root)
            installer_cgroup_fault_matrix(root)
            installer_cgroup_hostile_integration(root)
            print("HAPTICS_APT_PHASE_CGROUP=PASS")

    print("HAPTICS_APT_PHASE_FIXTURE=PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["--unit-installer-completion"]:
        installer_completion_protocol_fixture()
    elif len(sys.argv) >= 3 and sys.argv[1] == "--fixture":
        fixture(sys.argv[2], sys.argv[3:])
    elif len(sys.argv) >= 2 and sys.argv[1] == "--fixture-transaction-install":
        transaction_helper("install")
    elif (
        len(sys.argv) == 4
        and sys.argv[1] in ("--verify-marker", "--verify-post")
        and "HAPTICS_TEST_TRANSACTION_LEDGER" in os.environ
    ):
        transaction_helper("marker" if sys.argv[1] == "--verify-marker" else "post")
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-spawn-handoff":
        unit_spawn_handoff(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-pidfd-handoff":
        unit_pidfd_handoff(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-cleanup-failure":
        unit_cleanup_failure(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-final-signal":
        unit_final_signal_boundary(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-prepare-signal":
        unit_prepare_signal_boundary(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-prespawn-signal":
        unit_prespawn_signal_boundary(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-spawn-commit-signal":
        unit_spawn_commit_signal_boundary(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-deadline-observation":
        unit_deadline_observation_boundary(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-terminal-sigpending":
        unit_terminal_sigpending_failure(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-restrictive-umask":
        unit_restrictive_umask_output(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-signal-handoff":
        unit_final_signal_handoff(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-handler-restore-signal":
        unit_handler_restore_signal_boundary(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-exec-gate-failures":
        unit_exec_gate_failures(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--unit-unread-diagnostic":
        unit_unread_diagnostic(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "--exec-runner-wrapper":
        exec_runner_wrapper(sys.argv[2], pathlib.Path(sys.argv[3]))
    elif len(sys.argv) != 1:
        raise SystemExit("unknown APT phase fixture mode")
    else:
        main()
