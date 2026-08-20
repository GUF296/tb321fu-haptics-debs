#!/usr/bin/env python3
"""Focused offline self-test for the production sealed-launcher consumer."""

from __future__ import annotations

import ast
import errno
import fcntl
import hashlib
import importlib.util
import os
import pathlib
import pwd
import signal
import stat
import subprocess
import sys
import tempfile
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
RUNNER = SCRIPT_DIR / "run-haptics-workflow-dispatch-bootstrap.py"
PASS = b"HAPTICS_WORKFLOW_LAUNCHER_RUNNER_SELF_TEST=PASS\n"
MAX_CAPTURE = 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"sealed launcher runner self-test failed: {message}")


def require_ebadf(descriptor: int, label: str) -> None:
    try:
        os.fstat(descriptor)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return
        raise
    fail(f"{label} descriptor remained live")


def load_runner():
    spec = importlib.util.spec_from_file_location("haptics_launcher_runner", RUNNER)
    if spec is None or spec.loader is None:
        fail("cannot load production runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    previous_dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous_dont_write_bytecode
    return module


def child_source() -> bytes:
    return b"""#!/usr/bin/env python3
import argparse
import fcntl
import os
import pathlib
import sys

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--verify-only', action='store_true')
parser.add_argument('--profile')
parser.add_argument('--repo-dir', required=True)
args = parser.parse_args()
if not args.verify_only or args.profile is not None:
    raise SystemExit(91)
fd = int(pathlib.Path(__file__).name)
required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != required:
    raise SystemExit(92)
for hostile in ('BASH_ENV', 'ENV', 'PYTHONHOME', 'PYTHONPATH', 'GH_TOKEN', 'HTTPS_PROXY'):
    if hostile in os.environ:
        raise SystemExit(94)
if os.environ.get('PATH') != '/usr/sbin:/usr/bin:/sbin:/bin':
    raise SystemExit(95)
sys.stdout.buffer.write(b'schema\\ttb321fu.runner-self-test/v1\\nHAPTICS_WORKFLOW_BOOTSTRAP=PASS\\n')
sys.stderr.buffer.write(b'exact-stderr\\n')
"""


def invoke(
    launcher: pathlib.Path,
    repo: pathlib.Path,
    digest: str,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(RUNNER),
            "--launcher",
            str(launcher),
            "--launcher-sha256",
            digest,
            "--repo-dir",
            str(repo),
            "--timeout-seconds",
            "10",
            "--verify-only",
        ],
        cwd=repo,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20.0,
        check=False,
    )


def runner_command(
    launcher: pathlib.Path,
    repo: pathlib.Path,
    digest: str,
    timeout_seconds: str,
) -> list[str]:
    return [
        "/usr/bin/python3",
        "-I",
        "-B",
        str(RUNNER),
        "--launcher",
        str(launcher),
        "--launcher-sha256",
        digest,
        "--repo-dir",
        str(repo),
        "--timeout-seconds",
        timeout_seconds,
        "--verify-only",
    ]


def write_launcher(path: pathlib.Path, raw: bytes) -> str:
    path.write_bytes(raw)
    path.chmod(0o500)
    return hashlib.sha256(raw).hexdigest()


def assert_atomic_entry(module) -> None:
    raw = RUNNER.read_text(encoding="utf-8")
    tree = ast.parse(raw, filename=str(RUNNER))
    latch = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "CancellationLatch"
    )


    enter = next(
        node
        for node in latch.body
        if isinstance(node, ast.FunctionDef) and node.name == "enter"
    )
    calls = [
        node
        for node in ast.walk(enter)
        if isinstance(node, ast.Call)
    ]
    atomic = [
        node
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "atomic_capture_and_block"
    ]
    empty_queries = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and node.func.attr == "pthread_sigmask"
        and len(node.args) >= 2
        and isinstance(node.args[1], (ast.Set, ast.Dict))
        and len(node.args[1].elts if isinstance(node.args[1], ast.Set) else node.args[1].keys) == 0
    ]
    if len(atomic) != 1 or empty_queries:
        fail("signal entry is not one atomic capture-and-block operation")

    expected_mask = frozenset(
        signal.pthread_sigmask(signal.SIG_BLOCK, set())
    )
    latch_instance = module.CancellationLatch()
    original_atomic = module.atomic_capture_and_block
    injected = KeyboardInterrupt("injected atomic capture handoff cancellation")

    def applied_then_cancel(signals, old_mask, applied):
        original_atomic(signals, old_mask, applied)
        raise injected

    module.atomic_capture_and_block = applied_then_cancel
    caught = None
    try:
        latch_instance.enter()
    except BaseException as exc:
        caught = exc
    finally:
        module.atomic_capture_and_block = original_atomic
    observed_mask = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
    if caught is not injected or observed_mask != expected_mask:
        fail("applied-before-error atomic signal entry did not recover exactly")


def assert_high_fd_output_poll(
    launcher: pathlib.Path,
    repo: pathlib.Path,
    digest: str,
    environment: dict[str, str],
) -> None:
    """The production runner must support inherited stdio above select's fd_set."""
    descriptors: list[int] = []
    result = None
    try:
        for _ in range(1100):
            descriptors.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
        result = subprocess.run(
            runner_command(launcher, repo, digest, "10"),
            cwd=repo,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            timeout=20,
            check=False,
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    if result is None or (
        result.returncode != 0
        or result.stdout
        != b"schema\ttb321fu.runner-self-test/v1\nHAPTICS_WORKFLOW_BOOTSTRAP=PASS\n"
        or result.stderr != b"exact-stderr\n"
    ):
        fail(
            "high-numbered runner stdio was not forwarded through poll: "
            f"status={getattr(result, 'returncode', None)} "
            f"stdout={getattr(result, 'stdout', None)!r} "
            f"stderr={getattr(result, 'stderr', None)!r}"
        )


def assert_entry_return_custody(module) -> None:
    expected_mask = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
    expected_handlers = {
        signal.SIGINT: signal.getsignal(signal.SIGINT),
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
    }
    original_enter = module.CancellationLatch.enter
    injected = KeyboardInterrupt("injected latch return-boundary cancellation")

    def enter_then_cancel(self):
        original_enter(self)
        raise injected

    module.CancellationLatch.enter = enter_then_cancel
    caught = None
    try:
        module.main()
    except BaseException as exc:
        caught = exc
    finally:
        module.CancellationLatch.enter = original_enter
    if caught is not injected:
        fail("latch return-boundary cancellation lost exact caller policy")
    if (
        frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set())) != expected_mask
        or signal.getsignal(signal.SIGINT) != expected_handlers[signal.SIGINT]
        or signal.getsignal(signal.SIGTERM) != expected_handlers[signal.SIGTERM]
    ):
        fail("latch return-boundary cancellation leaked caller signal policy")


def assert_signal_priority(module) -> None:
    expected_mask = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
    expected_handlers = {
        signal.SIGINT: signal.getsignal(signal.SIGINT),
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
    }

    def new_latch():
        latch = module.CancellationLatch()
        latch.enter()
        return latch

    for active in (
        KeyboardInterrupt("exact caller keyboard interrupt"),
        SystemExit(77),
    ):
        latch = new_latch()
        selected = latch.close(active)
        if selected is not active:
            fail("exact active caller BaseException lost priority")

    latch = new_latch()
    ordinary = module.RunnerError("ordinary body failure")
    latch.record(signal.SIGTERM)
    selected = latch.close(ordinary)
    if not isinstance(selected, module.RunnerSignal) or selected.signum != signal.SIGTERM:
        fail("latched SIGTERM did not outrank an ordinary body failure")
    if "ordinary body failure" not in "\n".join(getattr(selected, "__notes__", ())):
        fail("latched cancellation lost ordinary failure evidence")

    latch = new_latch()
    latch.record(signal.SIGINT)
    original_signal = signal.signal

    def fail_restore(signum, handler):
        if signum == signal.SIGTERM and handler == expected_handlers[signal.SIGTERM]:
            raise OSError("injected terminal handler restore failure")
        return original_signal(signum, handler)

    signal.signal = fail_restore
    try:
        selected = latch.close(None)
    finally:
        signal.signal = original_signal
        # The injected handler failed before applying; restore it for the oracle process.
        original_signal(signal.SIGTERM, expected_handlers[signal.SIGTERM])
    if (
        not isinstance(selected, module.RunnerError)
        or str(selected) != "launcher-runner signal restoration failed"
    ):
        fail("terminal restoration failure did not outrank latched cancellation")
    if (
        frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set())) != expected_mask
        or signal.getsignal(signal.SIGINT) != expected_handlers[signal.SIGINT]
        or signal.getsignal(signal.SIGTERM) != expected_handlers[signal.SIGTERM]
    ):
        fail("signal-priority oracle did not restore caller policy")


def assert_subreaper_return_custody(module, private: pathlib.Path) -> None:
    previous = module.inspect_subreaper()
    descriptor_baseline = module.descriptor_snapshot()
    execution = module.DescriptorOwner()
    module.write_and_seal(b"#!/usr/bin/env python3\n", execution)
    latch = module.CancellationLatch()
    latch.enter()
    original_set = module.set_subreaper
    injected = KeyboardInterrupt("injected subreaper applied-before-return cancellation")
    applied = False

    def set_then_cancel(enabled: bool) -> None:
        nonlocal applied
        original_set(enabled)
        if enabled and not applied:
            applied = True
            raise injected

    module.set_subreaper = set_then_cancel
    caught = None
    try:
        module.run_sealed_launcher(
            execution,
            ["/usr/bin/python3", "-I", "-B", f"/proc/self/fd/{execution.descriptor}"],
            private,
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            module.time.monotonic() + 10,
            latch,
        )
    except BaseException as exc:
        caught = exc
    finally:
        module.set_subreaper = original_set
        close_failure = module.settle_descriptor(execution, None, "subreaper oracle memfd")
        selected = latch.close(caught)
    if selected is not injected or close_failure is not None or not applied:
        fail("subreaper return-boundary cancellation lost exact caller policy")
    if module.inspect_subreaper() != previous:
        fail("subreaper return-boundary cancellation leaked subreaper policy")
    if module.descriptor_snapshot() != descriptor_baseline:
        fail("subreaper return-boundary cancellation changed descriptor custody")


def assert_preexisting_child_preserved(module, private: pathlib.Path) -> None:
    child = subprocess.Popen(
        ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    execution = module.DescriptorOwner()
    latch = module.CancellationLatch()
    caught = None
    try:
        module.write_and_seal(b"#!/usr/bin/env python3\n", execution)
        latch.enter()
        try:
            module.run_sealed_launcher(
                execution,
                ["/usr/bin/python3", "-I", "-B", f"/proc/self/fd/{execution.descriptor}"],
                private,
                {
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                module.time.monotonic() + 10,
                latch,
            )
        except BaseException as exc:
            caught = exc
        selected = latch.close(caught)
        if (
            not isinstance(selected, module.RunnerError)
            or str(selected) != "launcher runner inherited pre-existing children"
        ):
            fail("pre-existing-child rejection drifted")
        waited, _ = os.waitpid(child.pid, os.WNOHANG)
        if waited != 0 or child.poll() is not None:
            fail("runner adopted, killed, or reaped a pre-existing caller child")
    finally:
        module.settle_descriptor(execution, None, "pre-existing child oracle memfd")
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def assert_descriptor_handoffs(module, private: pathlib.Path) -> None:
    fixture = private / "handoff-source"
    fixture.write_bytes(b"handoff\n")
    fixture.chmod(0o500)
    identity = fixture.stat().st_dev, fixture.stat().st_ino
    baseline = module.descriptor_snapshot()

    owner = module.DescriptorOwner()
    retained: list[int] = []
    injected_open = KeyboardInterrupt("injected open applied-before-assignment cancellation")
    original_open = module.os.open

    def open_then_cancel(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        retained.append(descriptor)
        raise injected_open

    module.os.open = open_then_cancel
    caught = None
    try:
        module.acquire_path_descriptor(
            owner,
            str(fixture),
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            identity,
            "self-test open handoff",
        )
    except BaseException as exc:
        caught = exc
    finally:
        module.os.open = original_open
    if caught is not injected_open or owner.descriptor >= 0 or len(retained) != 1:
        fail("open applied-before-assignment recovery drifted")
    require_ebadf(retained[0], "recovered open")

    owner = module.DescriptorOwner()
    retained.clear()
    injected_memfd = KeyboardInterrupt("injected memfd applied-before-assignment cancellation")
    original_memfd = module.os.memfd_create

    def memfd_then_cancel(*args, **kwargs):
        descriptor = original_memfd(*args, **kwargs)
        retained.append(descriptor)
        raise injected_memfd

    module.os.memfd_create = memfd_then_cancel
    caught = None
    try:
        module.acquire_memfd(owner)
    except BaseException as exc:
        caught = exc
    finally:
        module.os.memfd_create = original_memfd
    if caught is not injected_memfd or owner.descriptor >= 0 or len(retained) != 1:
        fail("memfd applied-before-assignment recovery drifted")
    require_ebadf(retained[0], "recovered memfd")

    owner = module.DescriptorOwner()
    retained.clear()
    injected_seal = KeyboardInterrupt("injected seal applied-before-return cancellation")
    original_fcntl = module.fcntl.fcntl

    def seal_then_cancel(descriptor, command, argument=0):
        result = original_fcntl(descriptor, command, argument)
        if command == fcntl.F_ADD_SEALS:
            retained.append(descriptor)
            raise injected_seal
        return result

    module.fcntl.fcntl = seal_then_cancel
    caught = None
    try:
        module.write_and_seal(b"#!/usr/bin/env python3\n", owner)
    except BaseException as exc:
        caught = exc
    finally:
        module.fcntl.fcntl = original_fcntl
        selected = module.settle_descriptor(owner, caught, "seal oracle memfd")
    if selected is not injected_seal or len(retained) != 1:
        fail("seal return-boundary cancellation lost exact caller policy")
    require_ebadf(retained[0], "sealed memfd cancellation")

    child = subprocess.Popen(
        ["/usr/bin/python3", "-I", "-B", "-c", "import time;time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    owner = module.DescriptorOwner()
    retained.clear()
    injected_pidfd = KeyboardInterrupt("injected pidfd applied-before-assignment cancellation")
    original_pidfd_open = module.os.pidfd_open

    def pidfd_then_cancel(*args, **kwargs):
        descriptor = original_pidfd_open(*args, **kwargs)
        retained.append(descriptor)
        raise injected_pidfd

    module.os.pidfd_open = pidfd_then_cancel
    caught = None
    try:
        module.acquire_pidfd(owner, child.pid, "self-test pidfd handoff")
    except BaseException as exc:
        caught = exc
    finally:
        module.os.pidfd_open = original_pidfd_open
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
    if caught is not injected_pidfd or owner.descriptor >= 0 or len(retained) != 1:
        fail("pidfd applied-before-assignment recovery drifted")
    require_ebadf(retained[0], "recovered pidfd")

    original_scandir = module.os.scandir
    retained_iterators = []
    injected_scandir = KeyboardInterrupt("injected scandir applied-before-assignment cancellation")

    def scandir_then_cancel(*args, **kwargs):
        entries = original_scandir(*args, **kwargs)
        retained_iterators.append(entries)
        raise injected_scandir

    module.os.scandir = scandir_then_cancel
    caught = None
    try:
        module.descriptor_snapshot()
    except BaseException as exc:
        caught = exc
    finally:
        module.os.scandir = original_scandir
    if caught is not injected_scandir or len(retained_iterators) != 1:
        fail("scandir applied-before-assignment recovery drifted")
    if module.descriptor_snapshot() != baseline:
        fail("descriptor handoff oracles changed descriptor custody")
    retained_iterators[0].close()


def assert_launcher_replacement(module, private: pathlib.Path) -> None:
    launcher = private / "replacement-launcher.py"
    original_raw = b"#!/usr/bin/env python3\nprint('trusted')\n"
    hostile_raw = b"#!/usr/bin/env python3\nprint('hostile')\n"
    launcher.write_bytes(original_raw)
    launcher.chmod(0o500)
    held = private / "replacement-launcher.held"
    owner = module.DescriptorOwner()
    original_acquire = module.acquire_path_descriptor
    replaced = False

    def acquire_then_replace(*args, **kwargs):
        nonlocal replaced
        result = original_acquire(*args, **kwargs)
        os.replace(launcher, held)
        launcher.write_bytes(hostile_raw)
        launcher.chmod(0o500)
        replaced = True
        return result

    module.acquire_path_descriptor = acquire_then_replace
    caught = None
    try:
        module.authenticate_launcher(
            launcher,
            hashlib.sha256(original_raw).hexdigest(),
            owner,
        )
    except BaseException as exc:
        caught = exc
    finally:
        module.acquire_path_descriptor = original_acquire
        close_failure = module.settle_descriptor(owner, None, "replacement launcher fd")
        if replaced:
            launcher.unlink()
            os.replace(held, launcher)
    if (
        not isinstance(caught, module.RunnerError)
        or str(caught) != "rendered launcher metadata differs from policy"
        or close_failure is not None
        or launcher.read_bytes() != original_raw
    ):
        fail("launcher namespace replacement was not rejected without adoption")


def assert_popen_handoff(module, private: pathlib.Path) -> None:
    original_popen = subprocess.Popen
    retained: list[subprocess.Popen[bytes]] = []
    pipe_descriptors: list[int] = []
    injected = KeyboardInterrupt("injected Popen applied-before-assignment cancellation")

    def popen_then_cancel(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        retained.append(process)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                pipe_descriptors.append(stream.fileno())
        raise injected

    baseline = module.direct_child_snapshot()
    descriptor_baseline = module.descriptor_snapshot()
    subprocess.Popen = popen_then_cancel
    caught = None
    try:
        try:
            module.run_sealed_launcher(
                module.DescriptorOwner(0),
                ["/usr/bin/python3", "-I", "-B", "-c", "import time; time.sleep(30)"],
                private,
                {
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                module.time.monotonic() + 10,
                module.CancellationLatch(),
            )
        except BaseException as exc:
            caught = exc
    finally:
        subprocess.Popen = original_popen
    # This direct internal call intentionally lacks an entered latch and should
    # fail before spawn; exercise the actual applied-return boundary separately.
    if retained:
        fail("Popen handoff oracle unexpectedly spawned without an entered latch")

    latch = module.CancellationLatch()
    latch.enter()
    execution = module.DescriptorOwner()
    module.write_and_seal(
        b"#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n",
        execution,
    )
    subprocess.Popen = popen_then_cancel
    caught = None
    try:
        try:
            module.run_sealed_launcher(
                execution,
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    f"/proc/self/fd/{execution.descriptor}",
                ],
                private,
                {
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                module.time.monotonic() + 10,
                latch,
            )
        except BaseException as exc:
            caught = exc
    finally:
        subprocess.Popen = original_popen
        close_failure = module.settle_descriptor(execution, None, "self-test memfd")
        selected = latch.close(caught)
    if selected is not injected or close_failure is not None or len(retained) != 1:
        fail("Popen applied-before-assignment lost exact caller cancellation")
    pid = retained[0].pid
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        fail("recovered Popen child was not exactly reaped to ECHILD")
    if module.direct_child_snapshot() != baseline:
        fail("Popen handoff recovery left a direct child")
    for descriptor in pipe_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == 9:
                continue
        fail("Popen handoff recovery left a live pipe descriptor")
    if module.descriptor_snapshot() != descriptor_baseline:
        fail("Popen handoff recovery changed descriptor custody")


def assert_popen_pidfd_fallback(module, private: pathlib.Path) -> None:
    marker = private / "popen-pidfd-fallback-child.pid"
    descriptor_baseline = module.descriptor_snapshot()
    child_baseline = module.direct_child_snapshot()
    execution = module.DescriptorOwner()
    module.write_and_seal(
        (
            "#!/usr/bin/env python3\n"
            "import pathlib,subprocess,sys,time\n"
            "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],"
            "start_new_session=True)\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(child.pid), encoding='ascii')\n"
            "time.sleep(30)\n"
        ).encode("utf-8"),
        execution,
    )
    original_popen = module.subprocess.Popen
    original_acquire = module.acquire_pidfd
    injected = KeyboardInterrupt("injected Popen and pidfd recovery failure")
    processes: list[subprocess.Popen[bytes]] = []

    def popen_then_cancel(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        for _ in range(200):
            if marker.exists():
                break
            time.sleep(0.01)
        raise injected

    def unavailable_recovery_pidfd(owner, pid, label):
        if label in ("recovered root pidfd handoff", "descendant pidfd handoff"):
            raise OSError(errno.ENOSYS, "injected recovery pidfd unavailability")
        return original_acquire(owner, pid, label)

    latch = module.CancellationLatch()
    latch.enter()
    module.subprocess.Popen = popen_then_cancel
    module.acquire_pidfd = unavailable_recovery_pidfd
    caught = None
    selected = None
    close_failure = None
    try:
        module.run_sealed_launcher(
            execution,
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                f"/proc/self/fd/{execution.descriptor}",
            ],
            private,
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            module.time.monotonic() + 10,
            latch,
        )
    except BaseException as exc:
        caught = exc
    finally:
        module.acquire_pidfd = original_acquire
        module.subprocess.Popen = original_popen
        close_failure = module.settle_descriptor(
            execution,
            None,
            "Popen pidfd fallback oracle memfd",
        )
        selected = latch.close(caught)
    if (
        selected is not injected
        or close_failure is not None
        or len(processes) != 1
        or not marker.exists()
    ):
        fail("Popen pidfd fallback did not preserve exact recovery custody")
    detached_pid = int(marker.read_text(encoding="ascii"))
    try:
        os.kill(detached_pid, 0)
    except ProcessLookupError:
        pass
    else:
        fail("Popen pidfd fallback left detached descendant live")
    try:
        os.waitpid(processes[0].pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        fail("Popen pidfd fallback root was not exactly reaped")
    if module.direct_child_snapshot() != child_baseline:
        fail("Popen pidfd fallback changed direct-child custody")
    if module.descriptor_snapshot() != descriptor_baseline:
        fail("Popen pidfd fallback changed descriptor custody")


def assert_root_pidfd_return_custody(module, private: pathlib.Path) -> None:
    original_popen = module.subprocess.Popen
    original_acquire_pidfd = module.acquire_pidfd
    processes: list[subprocess.Popen[bytes]] = []
    pidfds: list[int] = []
    injected = KeyboardInterrupt("injected root pidfd return-boundary cancellation")
    fired = False

    def retain_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    def acquire_then_cancel(owner, pid, label):
        nonlocal fired
        result = original_acquire_pidfd(owner, pid, label)
        if not fired and label == "root pidfd handoff":
            fired = True
            pidfds.append(owner.descriptor)
            raise injected
        return result

    execution = module.DescriptorOwner()
    module.write_and_seal(
        b"#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n",
        execution,
    )
    latch = module.CancellationLatch()
    latch.enter()
    module.subprocess.Popen = retain_popen
    module.acquire_pidfd = acquire_then_cancel
    caught = None
    try:
        module.run_sealed_launcher(
            execution,
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                f"/proc/self/fd/{execution.descriptor}",
            ],
            private,
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            module.time.monotonic() + 10,
            latch,
        )
    except BaseException as exc:
        caught = exc
    finally:
        module.acquire_pidfd = original_acquire_pidfd
        module.subprocess.Popen = original_popen
        close_failure = module.settle_descriptor(execution, None, "root pidfd oracle memfd")
        selected = latch.close(caught)
    if (
        selected is not injected
        or close_failure is not None
        or not fired
        or len(processes) != 1
        or len(pidfds) != 1
        or processes[0].returncode is None
    ):
        fail("root pidfd return-boundary cancellation lost exact custody")
    require_ebadf(pidfds[0], "root pidfd")
    try:
        os.waitpid(processes[0].pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        fail("root pidfd return-boundary child was not exactly reaped")
    if module.direct_children():
        fail("root pidfd return-boundary cleanup left a child")


def assert_pidfd_capability_preflight(module, private: pathlib.Path) -> None:
    original_open = module.os.pidfd_open
    original_send = module.signal.pidfd_send_signal
    descriptor_baseline = module.descriptor_snapshot()
    child_baseline = module.direct_child_snapshot()

    module.preflight_pidfd_capability()
    if module.descriptor_snapshot() != descriptor_baseline:
        fail("successful pidfd capability preflight leaked a descriptor")
    if module.direct_child_snapshot() != child_baseline:
        fail("successful pidfd capability preflight leaked a child")

    def unavailable_open(*args, **kwargs):
        raise OSError(errno.ENOSYS, "injected pidfd_open unavailability")

    def unavailable_send(*args, **kwargs):
        raise OSError(errno.ENOSYS, "injected pidfd_send_signal unavailability")

    try:
        for label in ("open", "send"):
            if label == "open":
                module.os.pidfd_open = unavailable_open
            else:
                module.signal.pidfd_send_signal = unavailable_send
            caught = None
            try:
                module.preflight_pidfd_capability()
            except BaseException as exc:
                caught = exc
            finally:
                module.os.pidfd_open = original_open
                module.signal.pidfd_send_signal = original_send
            if not isinstance(caught, module.RunnerError):
                fail(f"pidfd {label} capability preflight accepted an unavailable syscall")
            if module.descriptor_snapshot() != descriptor_baseline:
                fail(f"pidfd {label} capability preflight leaked a descriptor")
            if module.direct_child_snapshot() != child_baseline:
                fail(f"pidfd {label} capability preflight leaked a child")
    finally:
        module.os.pidfd_open = original_open
        module.signal.pidfd_send_signal = original_send

    # The capability check must run before Popen.  Exercise the production
    # entrypoint with each syscall disabled and make any launch observable.
    def rejected_launcher_probe(attribute, replacement, label: str) -> None:
        original = getattr(attribute[0], attribute[1])
        original_popen = module.subprocess.Popen
        spawned = []

        def forbidden_popen(*args, **kwargs):
            spawned.append((args, kwargs))
            raise AssertionError("launcher spawned before pidfd capability rejection")

        setattr(attribute[0], attribute[1], replacement)
        module.subprocess.Popen = forbidden_popen
        execution = module.DescriptorOwner()
        latch = module.CancellationLatch()
        caught = None
        close_failure = None
        selected = None
        try:
            module.write_and_seal(b"#!/usr/bin/env python3\n", execution)
            latch.enter()
            try:
                module.run_sealed_launcher(
                    execution,
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        f"/proc/self/fd/{execution.descriptor}",
                    ],
                    private,
                    {
                        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "TZ": "UTC",
                        "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    module.time.monotonic() + 10,
                    latch,
                )
            except BaseException as exc:
                caught = exc
        finally:
            setattr(attribute[0], attribute[1], original)
            module.subprocess.Popen = original_popen
            close_failure = module.settle_descriptor(
                execution,
                None,
                f"pidfd {label} launcher oracle memfd",
            )
            selected = latch.close(caught)
        if spawned:
            fail(f"pidfd {label} failure spawned a production launcher")
        if (
            not isinstance(selected, module.RunnerError)
            or "pidfd" not in str(selected)
            or close_failure is not None
        ):
            fail(f"pidfd {label} failure did not fail closed before Popen")
        if module.descriptor_snapshot() != descriptor_baseline:
            fail(f"pidfd {label} launcher oracle leaked a descriptor")
        if module.direct_child_snapshot() != child_baseline:
            fail(f"pidfd {label} launcher oracle leaked a child")

    rejected_launcher_probe((module.os, "pidfd_open"), unavailable_open, "open")
    rejected_launcher_probe((module.signal, "pidfd_send_signal"), unavailable_send, "send")

    original_send = module.signal.pidfd_send_signal
    injected = KeyboardInterrupt("injected pidfd send applied-before-return cancellation")
    retained = []
    fired = False

    def send_then_cancel(descriptor, signum, *args, **kwargs):
        nonlocal fired
        result = original_send(descriptor, signum, *args, **kwargs)
        if signum == 0 and not fired:
            fired = True
            retained.append(descriptor)
            raise injected
        return result

    module.signal.pidfd_send_signal = send_then_cancel
    caught = None
    try:
        module.preflight_pidfd_capability()
    except BaseException as exc:
        caught = exc
    finally:
        module.signal.pidfd_send_signal = original_send
    if caught is not injected or not fired or len(retained) != 1:
        fail("pidfd send applied-before-return preflight lost caller exception")
    require_ebadf(retained[0], "pidfd capability preflight")
    if (
        module.descriptor_snapshot() != descriptor_baseline
        or module.direct_child_snapshot() != child_baseline
    ):
        fail("pidfd send applied-before-return preflight leaked custody")

    original_fork = module.os.fork
    fork_failure = OSError(errno.EIO, "injected fork applied-before-return failure")

    def fork_then_fail():
        child = original_fork()
        if child > 0:
            raise fork_failure
        return child

    module.os.fork = fork_then_fail
    caught = None
    try:
        module.preflight_pidfd_capability()
    except BaseException as exc:
        caught = exc
    finally:
        module.os.fork = original_fork
    if not isinstance(caught, module.RunnerError) or "pidfd" not in str(caught):
        fail("fork applied-before-return preflight did not fail closed")
    if (
        module.descriptor_snapshot() != descriptor_baseline
        or module.direct_child_snapshot() != child_baseline
    ):
        fail("fork applied-before-return preflight leaked custody")


def assert_detached_descendant_cleanup(
    private: pathlib.Path,
    environment: dict[str, str],
) -> None:
    marker = private / "detached-child.pid"
    launcher = private / "detached-launcher.py"
    digest = write_launcher(
        launcher,
        (
            "#!/usr/bin/env python3\n"
            "import pathlib,subprocess,sys,time\n"
            "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],"
            "start_new_session=True)\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(child.pid), encoding='ascii')\n"
            "time.sleep(30)\n"
        ).encode("utf-8"),
    )
    process = subprocess.Popen(
        runner_command(launcher, private, digest, "10"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    child_pid: int | None = None
    try:
        for _ in range(100):
            if marker.exists():
                child_pid = int(marker.read_text(encoding="ascii"))
                break
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if child_pid is None:
            fail("detached-descendant oracle did not enter its child")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        if process.returncode != 143 or stdout or stderr:
            fail("detached-descendant cancellation transcript drifted")
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            return
        fail("detached descendant survived runner cancellation")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def assert_transient_pidfd_fallback(module, private: pathlib.Path) -> None:
    for failure_label in ("root pidfd handoff", "descendant pidfd handoff"):
        slug = failure_label.replace(" ", "-")
        marker = private / f"transient-{slug}-child.pid"
        descriptor_baseline = module.descriptor_snapshot()
        child_baseline = module.direct_child_snapshot()
        source = (
            "import pathlib,subprocess,sys,time\n"
            "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],"
            "start_new_session=True)\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(child.pid), encoding='ascii')\n"
            "time.sleep(30)\n"
        ).encode("utf-8")
        execution = module.DescriptorOwner()
        module.write_and_seal(source, execution)
        latch = module.CancellationLatch()
        latch.enter()
        original_acquire = module.acquire_pidfd
        failed = False

        def transient_failure(owner, pid, label):
            nonlocal failed
            if label == failure_label:
                if label == "root pidfd handoff":
                    for _ in range(200):
                        if marker.exists():
                            break
                        time.sleep(0.01)
                failed = True
                raise OSError(errno.ENOSYS, "injected transient pidfd failure")
            return original_acquire(owner, pid, label)

        module.acquire_pidfd = transient_failure
        caught = None
        child_pid: int | None = None
        try:
            module.run_sealed_launcher(
                execution,
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    f"/proc/self/fd/{execution.descriptor}",
                ],
                private,
                {
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                module.time.monotonic() + 1,
                latch,
            )
        except BaseException as exc:
            caught = exc
        finally:
            module.acquire_pidfd = original_acquire
            close_failure = module.settle_descriptor(
                execution,
                None,
                f"transient {failure_label} fallback memfd",
            )
            selected = latch.close(caught)
        if marker.exists():
            child_pid = int(marker.read_text(encoding="ascii"))
        if (
            child_pid is None
            or not failed
            or caught is None
            or selected is None
            or close_failure is not None
        ):
            fail(f"transient {failure_label} oracle did not exercise the handoff")
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            fail(f"transient {failure_label} left a detached child live")
        if module.direct_child_snapshot() != child_baseline:
            fail(f"transient {failure_label} changed direct-child custody")
        if module.descriptor_snapshot() != descriptor_baseline:
            fail(f"transient {failure_label} changed descriptor custody")


def assert_timeout_contract(module) -> None:
    if module.DEFAULT_TIMEOUT_SECONDS != 330.0:
        fail("runner default timeout no longer matches the formal bootstrap contract")
    source = RUNNER.read_text(encoding="utf-8")
    if "default=DEFAULT_TIMEOUT_SECONDS" not in source:
        fail("runner parser is not bound to the reviewed timeout constant")


def assert_cli_boundaries(private: pathlib.Path, environment: dict[str, str]) -> None:
    timeout_launcher = private / "timeout-launcher.py"
    timeout_digest = write_launcher(
        timeout_launcher,
        b"#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n",
    )
    timed = subprocess.run(
        runner_command(timeout_launcher, private, timeout_digest, "1"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    if (
        timed.returncode != 124
        or timed.stdout
        or timed.stderr != b"launcher subprocess exceeded its deadline\n"
    ):
        fail("launcher timeout boundary drifted")

    nested_limit_launcher = private / "nested-limit-launcher.py"
    nested_limit_digest = write_launcher(
        nested_limit_launcher,
        (
            "#!/usr/bin/env python3\n"
            "import resource,subprocess,sys\n"
            "limit=2*1024*1024\n"
            "def child_setup():\n"
            "    resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))\n"
            "result=subprocess.run([sys.executable,'-I','-B','-c',"
            "'import resource,sys;sys.exit(0 if resource.getrlimit(resource.RLIMIT_FSIZE)==(2097152,2097152) else 93)'],"
            "preexec_fn=child_setup,check=False)\n"
            "if result.returncode:\n"
            "    raise SystemExit(result.returncode)\n"
            "sys.stdout.buffer.write(b'nested-limit-pass\\n')\n"
        ).encode("ascii"),
    )
    nested_limit = subprocess.run(
        runner_command(nested_limit_launcher, private, nested_limit_digest, "10"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if (
        nested_limit.returncode != 0
        or nested_limit.stdout != b"nested-limit-pass\n"
        or nested_limit.stderr
    ):
        fail("formal launcher nested file-size policy drifted")

    flood_launcher = private / "flood-launcher.py"
    flood_digest = write_launcher(
        flood_launcher,
        (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.buffer.write(b'x' * {MAX_CAPTURE + 1})\n"
        ).encode("ascii"),
    )
    flooded = subprocess.run(
        runner_command(flood_launcher, private, flood_digest, "10"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if (
        flooded.returncode != 125
        or flooded.stdout
        or flooded.stderr != b"launcher subprocess output exceeded its bound\n"
    ):
        fail("launcher output boundary drifted")

    nonzero_launcher = private / "nonzero-launcher.py"
    nonzero_digest = write_launcher(
        nonzero_launcher,
        b"#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b'exact-out\\n')\nsys.stderr.buffer.write(b'exact-err\\n')\nraise SystemExit(42)\n",
    )
    nonzero = subprocess.run(
        runner_command(nonzero_launcher, private, nonzero_digest, "10"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if (
        nonzero.returncode != 42
        or nonzero.stdout != b"exact-out\n"
        or nonzero.stderr != b"exact-err\n"
    ):
        fail("launcher exact nonzero transcript propagation drifted")

    blocked_output_launcher = private / "blocked-output-launcher.py"
    blocked_output_digest = write_launcher(
        blocked_output_launcher,
        (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.buffer.write(b'x' * {128 * 1024})\n"
        ).encode("ascii"),
    )
    blocked_output = subprocess.Popen(
        runner_command(blocked_output_launcher, private, blocked_output_digest, "10"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        try:
            blocked_output.wait(timeout=15)
        except subprocess.TimeoutExpired:
            fail("blocked caller output was allowed to hang the runner")
        blocked_stderr = blocked_output.stderr.read() if blocked_output.stderr else b""
        if (
            blocked_output.returncode != 125
            or b"runner output write exceeded its deadline" not in blocked_stderr
        ):
            fail("blocked caller output did not fail closed")
    finally:
        if blocked_output.poll() is None:
            blocked_output.kill()
            blocked_output.wait(timeout=5)
        if blocked_output.stdout is not None:
            blocked_output.stdout.close()
        if blocked_output.stderr is not None:
            blocked_output.stderr.close()

    def assert_blocked_error_stream(name: str, payload: str) -> None:
        launcher = private / f"{name}-launcher.py"
        digest = write_launcher(launcher, payload.encode("ascii"))
        process = subprocess.Popen(
            runner_command(launcher, private, digest, "10"),
            cwd=private,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        try:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                fail(f"blocked {name} caller output was allowed to hang the runner")
            if process.returncode != 125:
                fail(
                    f"blocked {name} caller output returned an unexpected status: "
                    f"{process.returncode}"
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    assert_blocked_error_stream(
        "blocked-stderr",
        f"#!/usr/bin/env python3\nimport sys\nsys.stderr.buffer.write(b'x' * {128 * 1024})\n",
    )
    assert_blocked_error_stream(
        "blocked-both",
        f"#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b'x' * {128 * 1024})\nsys.stderr.buffer.write(b'y' * {128 * 1024})\n",
    )

    marker = private / "signal-child.pid"
    signal_launcher = private / "signal-launcher.py"
    signal_digest = write_launcher(
        signal_launcher,
        (
            "#!/usr/bin/env python3\n"
            "import os,pathlib,time\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid()), encoding='ascii')\n"
            "time.sleep(30)\n"
        ).encode("utf-8"),
    )
    process = subprocess.Popen(
        runner_command(signal_launcher, private, signal_digest, "10"),
        cwd=private,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    child_pid: int | None = None
    try:
        for _ in range(100):
            if marker.exists():
                child_pid = int(marker.read_text(encoding="ascii"))
                break
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if child_pid is None:
            fail("signal oracle launcher did not enter its child")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        if process.returncode != 143 or stdout or stderr:
            fail("SIGTERM did not produce empty-evidence status 143")
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            fail("SIGTERM cleanup left the sealed launcher child live")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main() -> None:
    if sys.platform != "linux" or threading_count() != 1:
        fail("self-test requires one Linux thread")
    module = load_runner()
    assert_atomic_entry(module)
    assert_entry_return_custody(module)
    assert_signal_priority(module)
    with tempfile.TemporaryDirectory(prefix="tb321fu-launcher-runner-test.") as raw:
        private = pathlib.Path(raw)
        launcher = private / "launcher.py"
        launcher.write_bytes(child_source())
        launcher.chmod(0o500)
        if (
            not stat.S_ISREG(launcher.stat().st_mode)
            or stat.S_IMODE(launcher.stat().st_mode) != 0o500
            or launcher.stat().st_nlink != 1
        ):
            fail("cannot create the private launcher fixture")
        digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(private),
            "PYTHONDONTWRITEBYTECODE": "1",
            "BASH_ENV": "/hostile/bash-env",
            "ENV": "/hostile/env",
            "PYTHONHOME": "/hostile/python-home",
            "PYTHONPATH": "/hostile/python-path",
            "GH_TOKEN": "hostile-token",
            "HTTPS_PROXY": "https://hostile.invalid",
        }
        environment["HOME"] = pwd.getpwuid(os.geteuid()).pw_dir
        assert_descriptor_handoffs(module, private)
        assert_launcher_replacement(module, private)
        assert_preexisting_child_preserved(module, private)
        assert_subreaper_return_custody(module, private)
        assert_popen_handoff(module, private)
        assert_popen_pidfd_fallback(module, private)
        assert_root_pidfd_return_custody(module, private)
        assert_pidfd_capability_preflight(module, private)
        assert_timeout_contract(module)
        assert_cli_boundaries(private, environment)
        assert_detached_descendant_cleanup(private, environment)
        assert_transient_pidfd_fallback(module, private)
        assert_high_fd_output_poll(launcher, private, digest, environment)
        good = invoke(launcher, private, digest, environment)
        if (
            good.returncode != 0
            or good.stdout
            != b"schema\ttb321fu.runner-self-test/v1\nHAPTICS_WORKFLOW_BOOTSTRAP=PASS\n"
            or good.stderr != b"exact-stderr\n"
        ):
            fail(
                "sealed execution or exact output forwarding drifted: "
                f"status={good.returncode} stdout={good.stdout!r} stderr={good.stderr!r}"
            )
        wrong = invoke(launcher, private, "0" * 64, environment)
        if (
            wrong.returncode != 125
            or wrong.stdout
            or b"rendered launcher changed during authentication" not in wrong.stderr
            or b"HAPTICS_WORKFLOW_BOOTSTRAP=PASS" in wrong.stderr
            or len(wrong.stderr) > MAX_CAPTURE
        ):
            fail("wrong-digest rejection did not fail closed")
        link = private / "launcher-link.py"
        link.symlink_to(launcher)
        linked = invoke(link, private, digest, environment)
        if linked.returncode != 125 or linked.stdout:
            fail("symlink launcher was not rejected")
    sys.stdout.buffer.write(PASS)


def threading_count() -> int:
    import threading

    return threading.active_count()


if __name__ == "__main__":
    main()
