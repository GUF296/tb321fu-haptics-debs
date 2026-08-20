#!/usr/bin/env python3
"""Disposable root fixture for the production APT EIPP hook verifier."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import errno
import io
import os
import pathlib
import pwd
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
APT_MODULE_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"
DPKG_MODULE_PATH = SCRIPT_DIR / "verify-haptics-dpkg-state.py"
PACKAGE_MODULE_PATH = SCRIPT_DIR / "verify-haptics-build-packages.py"
HOOK_COMMAND = (
    "/usr/bin/python3 -I -B /tmp/private/verify-haptics-apt-transaction.py "
    "--verify-hook /tmp/private/expected.tsv /tmp/private/hook.ok"
)


class FixtureCleanupError(Exception):
    """Internal fixture-policy failure, never caller cancellation."""


def choose_fixture_failure(
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
        return new
    if new is not current:
        current.add_note(f"{note}: {type(new).__name__}: {new}")
    return current


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load fixture module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_file(path: pathlib.Path, raw: bytes, mode: int) -> None:
    path.write_bytes(raw)
    path.chmod(mode)


def make_empty_admin(root: pathlib.Path) -> pathlib.Path:
    admin = root / "var/lib/dpkg"
    for path in (
        admin,
        admin / "triggers",
        admin / "info",
        admin / "updates",
        admin / "parts",
    ):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    write_file(admin / "status", b"", 0o644)
    write_file(admin / "diversions", b"", 0o644)
    write_file(admin / "statoverride", b"", 0o644)
    write_file(admin / "triggers/File", b"", 0o644)
    write_file(admin / "triggers/Unincorp", b"", 0o644)
    return admin


def make_deb(root: pathlib.Path) -> pathlib.Path:
    package_root = root / "package"
    control_dir = package_root / "DEBIAN"
    data_dir = package_root / "usr/share/example"
    control_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    (control_dir / "control").write_text(
        "Package: example\n"
        "Version: 1.0-1\n"
        "Architecture: amd64\n"
        "Multi-Arch: no\n"
        "Maintainer: Fixture <fixture@example.invalid>\n"
        "Description: APT hook fixture\n"
        " This legal continuation must not enter the identity query.\n",
        encoding="ascii",
    )
    (data_dir / "payload").write_text("fixture\n", encoding="ascii")
    archive = root / "example_1.0-1_amd64.deb"
    result = subprocess.run(
        [
            "/usr/bin/dpkg-deb",
            "--build",
            "--root-owner-group",
            str(package_root),
            str(archive),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "SOURCE_DATE_EPOCH": "1",
        },
    )
    if result.returncode:
        raise SystemExit("fixture DEB creation failed: " + result.stderr.strip())
    archive.chmod(0o644)
    return archive


def run_hook_cli(eipp_path: pathlib.Path, arguments: list[str]):
    with eipp_path.open("rb") as stream:
        eipp_descriptor = stream.fileno()
        try:
            saved_descriptor = os.dup(21)
        except OSError:
            saved_descriptor = -1
        os.dup2(eipp_descriptor, 21, inheritable=True)
        try:
            return subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(APT_MODULE_PATH),
                    *arguments,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                pass_fds=(21,),
                env={
                    "APT_HOOK_INFO_FD": "21",
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": "/nonexistent",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        finally:
            if saved_descriptor >= 0:
                os.dup2(saved_descriptor, 21, inheritable=True)
                os.close(saved_descriptor)
            else:
                os.close(21)


def close_fixture_descriptor(descriptor: int, label: str) -> None:
    failures: list[BaseException] = []

    def remember(failure: BaseException) -> None:
        if any(previous is failure for previous in failures):
            return
        if not isinstance(failure, Exception) and failure.__cause__ is None:
            earlier = next(
                (previous for previous in failures if isinstance(previous, Exception)),
                None,
            )
            if earlier is not None:
                failure.__cause__ = earlier
        failures.append(failure)

    def cancellation() -> BaseException | None:
        return next(
            (failure for failure in failures if not isinstance(failure, Exception)),
            None,
        )

    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            remember(exc)
            closed = False
            try:
                os.fstat(descriptor)
            except OSError as probe:
                if probe.errno == errno.EBADF:
                    closed = True
                else:
                    remember(probe)
            except BaseException as probe:
                remember(probe)
            if not closed:
                continue
        interrupted = cancellation()
        if interrupted is not None:
            raise interrupted
        return
    if not failures:
        raise FixtureCleanupError(f"{label} close failed without an exception")
    raise cancellation() or failures[0]


FIXTURE_CANCELLATION_SIGNALS = frozenset((signal.SIGINT, signal.SIGTERM))


def fixture_signal_mask() -> frozenset[signal.Signals]:
    return frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))


def restore_fixture_signal_mask(
    expected: frozenset[signal.Signals],
) -> tuple[BaseException | None, bool]:
    first_failure: BaseException | None = None

    def remember(exc: BaseException) -> None:
        nonlocal first_failure
        if first_failure is None:
            first_failure = exc
        elif not isinstance(exc, Exception) and isinstance(first_failure, Exception):
            exc.add_note("APT hook signal-mask restoration also failed")
            first_failure = exc
        elif exc is not first_failure:
            first_failure.add_note("APT hook signal-mask restoration also failed")

    for _ in range(3):
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, set(expected))
        except BaseException as exc:
            remember(exc)
        try:
            current = fixture_signal_mask()
        except BaseException as exc:
            remember(exc)
            continue
        if current == expected:
            return first_failure, True
    return first_failure, False


def inspect_fixture_marker_inode(
    parent_descriptor: int,
    name: str,
) -> os.stat_result | None:
    try:
        metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    return metadata


def require_fixture_marker_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink not in (1, 2)
        or metadata.st_size <= 0
        or metadata.st_size > 65
    ):
        raise FixtureCleanupError("APT hook partial marker metadata differs from policy")


def cleanup_fixture_marker_inode(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int] | None,
    label: str,
) -> None:
    failure: BaseException | None = None
    for _ in range(3):
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if failure is not None:
                raise failure
            return
        except BaseException as exc:
            failure = choose_fixture_failure(
                failure,
                exc,
                f"{label} cleanup inspection also failed",
            )
            continue
        if expected_identity is None or (
            current.st_dev,
            current.st_ino,
        ) != expected_identity:
            changed = FixtureCleanupError(f"{label} cleanup namespace changed")
            raise choose_fixture_failure(
                failure,
                changed,
                f"{label} cleanup also failed",
            )
        try:
            os.unlink(name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except BaseException as exc:
            failure = choose_fixture_failure(
                failure,
                exc,
                f"{label} cleanup unlink also failed",
            )
            continue
        try:
            remaining = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if failure is not None:
                raise failure
            return
        except BaseException as exc:
            failure = choose_fixture_failure(
                failure,
                exc,
                f"{label} cleanup verification also failed",
            )
            continue
        if (remaining.st_dev, remaining.st_ino) != expected_identity:
            changed = FixtureCleanupError(f"{label} cleanup namespace changed")
            raise choose_fixture_failure(
                failure,
                changed,
                f"{label} cleanup also failed",
            )
        failure = choose_fixture_failure(
            failure,
            FixtureCleanupError(f"{label} cleanup left its owned inode present"),
            f"{label} cleanup also failed",
        )
    if failure is None:
        failure = FixtureCleanupError(f"{label} cleanup did not converge")
    raise failure


def terminate_fixture_child(child: int) -> int | None:
    while True:
        try:
            waited, status_value = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return None
        if waited == child:
            return status_value
        if waited != 0:
            raise FixtureCleanupError(
                "APT hook fixture cleanup returned an unexpected child"
            )
        break
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 2.0
    while True:
        try:
            waited, status_value = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return None
        if waited == child:
            return status_value
        if waited != 0:
            raise FixtureCleanupError(
                "APT hook fixture cleanup reaped an unexpected child"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FixtureCleanupError("APT hook fixture child cleanup timed out")
        time.sleep(min(0.01, remaining))


def run_partial_marker_kill_fixture(
    apt,
    manifest_path: pathlib.Path,
    killed_marker: pathlib.Path,
    manifest_digest: str,
) -> None:
    pinned_parent = -1
    pinned_manifest = -1
    ready_descriptor = -1
    notify_descriptor = -1
    child_pid = -1
    child_owned = False
    original_mask: frozenset[signal.Signals] | None = None
    mask_needs_restore = False
    temporary_name = f".{killed_marker.name}.tmp"
    temporary_identity: tuple[int, int] | None = None
    primary: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    child_status: int | None = None
    try:
        (
            pinned_parent,
            pinned_manifest,
            _,
            _,
            _,
        ) = apt.open_private_manifest(manifest_path, killed_marker)
        if (
            inspect_fixture_marker_inode(pinned_parent, killed_marker.name) is not None
            or inspect_fixture_marker_inode(pinned_parent, temporary_name) is not None
        ):
            raise FixtureCleanupError(
                "APT hook marker kill fixture inherited marker residue"
            )
        ready_descriptor, notify_descriptor = os.pipe()
        original_mask = fixture_signal_mask()
        mask_needs_restore = True
        previous_mask = frozenset(
            signal.pthread_sigmask(
                signal.SIG_BLOCK,
                set(FIXTURE_CANCELLATION_SIGNALS),
            )
        )
        if (
            previous_mask != original_mask
            or not FIXTURE_CANCELLATION_SIGNALS.issubset(fixture_signal_mask())
        ):
            raise FixtureCleanupError(
                "APT hook fixture cancellation mask changed before fork"
            )
        child_pid = os.fork()
        if child_pid == 0:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, set(original_mask))
            except BaseException:
                os._exit(4)
            os.close(ready_descriptor)
            child_write = apt.os.write
            child_write_count = 0

            def pause_after_partial_write(descriptor: int, raw: bytes) -> int:
                nonlocal child_write_count
                child_write_count += 1
                if child_write_count == 1:
                    count = child_write(descriptor, raw[:1])
                    child_write(notify_descriptor, b"1")
                    signal.pause()
                    return count
                return child_write(descriptor, raw)

            apt.os.write = pause_after_partial_write
            try:
                apt.write_hook_marker(
                    pinned_parent,
                    killed_marker,
                    manifest_digest,
                    deadline=(
                        apt.time.monotonic()
                        + apt.HOOK_VERIFICATION_TIMEOUT_SECONDS
                    ),
                )
            except BaseException:
                os._exit(2)
            os._exit(3)
        child_owned = True
        close_fixture_descriptor(notify_descriptor, "APT hook notify descriptor")
        notify_descriptor = -1
        ready, _, _ = select.select([ready_descriptor], [], [], 5)
        if not ready or os.read(ready_descriptor, 1) != b"1":
            raise FixtureCleanupError(
                "APT hook marker kill fixture did not reach partial write"
            )
        temporary_metadata = inspect_fixture_marker_inode(
            pinned_parent,
            temporary_name,
        )
        if temporary_metadata is None:
            raise FixtureCleanupError(
                "APT hook marker kill fixture omitted its temporary inode"
            )
        temporary_identity = (
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
        )
        require_fixture_marker_metadata(temporary_metadata)
        if inspect_fixture_marker_inode(pinned_parent, killed_marker.name) is not None:
            raise FixtureCleanupError(
                "killed APT hook marker writer linked a partial marker"
            )
        child_status = terminate_fixture_child(child_pid)
        child_owned = False
        if child_status is None:
            raise FixtureCleanupError(
                "APT hook marker kill fixture lost child custody"
            )
        if not os.WIFSIGNALED(child_status):
            raise FixtureCleanupError(
                "APT hook marker kill fixture did not kill its child"
            )
    except BaseException as exc:
        primary = exc
    if child_owned and pinned_parent >= 0 and temporary_identity is None:
        try:
            temporary_metadata = inspect_fixture_marker_inode(
                pinned_parent,
                temporary_name,
            )
            if temporary_metadata is not None:
                temporary_identity = (
                    temporary_metadata.st_dev,
                    temporary_metadata.st_ino,
                )
                require_fixture_marker_metadata(temporary_metadata)
        except BaseException as exc:
            cleanup_errors.append(exc)
    if child_owned:
        try:
            terminate_fixture_child(child_pid)
            child_owned = False
        except BaseException as exc:
            cleanup_errors.append(exc)
    if pinned_parent >= 0 and temporary_identity is None and not child_owned:
        try:
            temporary_metadata = inspect_fixture_marker_inode(
                pinned_parent,
                temporary_name,
            )
            if temporary_metadata is not None:
                temporary_identity = (
                    temporary_metadata.st_dev,
                    temporary_metadata.st_ino,
                )
                require_fixture_marker_metadata(temporary_metadata)
        except BaseException as exc:
            cleanup_errors.append(exc)
    if pinned_parent >= 0:
        for name, label in (
            (temporary_name, "APT hook temporary marker"),
            (killed_marker.name, "APT hook published marker"),
        ):
            try:
                cleanup_fixture_marker_inode(
                    pinned_parent,
                    name,
                    temporary_identity,
                    label,
                )
            except BaseException as exc:
                cleanup_errors.append(exc)
        for name, label in (
            (temporary_name, "temporary"),
            (killed_marker.name, "published"),
        ):
            try:
                remaining = inspect_fixture_marker_inode(pinned_parent, name)
            except BaseException as exc:
                cleanup_errors.append(exc)
                continue
            if remaining is not None:
                cleanup_errors.append(
                    FixtureCleanupError(
                        f"APT hook marker kill fixture left {label} residue"
                    )
                )
    for descriptor, label in (
        (notify_descriptor, "APT hook notify descriptor"),
        (ready_descriptor, "APT hook ready descriptor"),
        (pinned_manifest, "APT hook pinned manifest"),
        (pinned_parent, "APT hook pinned parent"),
    ):
        if descriptor < 0:
            continue
        try:
            close_fixture_descriptor(descriptor, label)
        except BaseException as exc:
            cleanup_errors.append(exc)
    if mask_needs_restore and original_mask is not None:
        restore_error, restored = restore_fixture_signal_mask(original_mask)
        if restored:
            mask_needs_restore = False
        if restore_error is not None:
            cleanup_errors.append(restore_error)
        if not restored:
            cleanup_errors.append(
                FixtureCleanupError(
                    "APT hook fixture cancellation mask restoration failed"
                )
            )
    cleanup_cancellation = next(
        (
            cleanup_error
            for cleanup_error in cleanup_errors
            if not isinstance(cleanup_error, Exception)
        ),
        None,
    )
    if (
        primary is not None
        and cleanup_cancellation is not None
        and isinstance(primary, Exception)
    ):
        cleanup_cancellation.add_note(
            "APT hook partial-marker primary also failed before cancellation: "
            f"{type(primary).__name__}: {primary}"
        )
        primary = cleanup_cancellation
    if primary is not None:
        for cleanup_error in cleanup_errors:
            if cleanup_error is primary:
                continue
            primary.add_note(
                "APT hook partial-marker cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        raise primary
    if cleanup_errors:
        raise cleanup_cancellation or cleanup_errors[0]


def prove_partial_marker_child_custody(
    apt,
    manifest_path: pathlib.Path,
    private: pathlib.Path,
    manifest_digest: str,
) -> None:
    original_manifest_open = apt.open_private_manifest
    original_pipe = os.pipe
    original_fork = os.fork
    original_close = os.close
    original_select = select.select
    original_read = os.read
    original_kill = os.kill
    original_waitpid = os.waitpid
    parent_pid = os.getpid()

    for case in ("fork", "close", "select", "read", "kill", "wait"):
        marker = private / f"killed-{case}.ok"
        injected = OSError(f"injected APT hook {case} failure")
        descriptors: list[int] = []
        children: list[int] = []
        after_fork = False
        fault_count = 0

        def record_manifest(*args, **kwargs):
            result = original_manifest_open(*args, **kwargs)
            descriptors.extend(result[:2])
            return result

        def record_pipe():
            result = original_pipe()
            descriptors.extend(result)
            return result

        def fault_fork():
            nonlocal after_fork
            if case == "fork":
                raise injected
            child = original_fork()
            if child > 0:
                children.append(child)
                after_fork = True
            return child

        def fault_close(descriptor: int) -> None:
            nonlocal fault_count
            if (
                case == "close"
                and os.getpid() == parent_pid
                and after_fork
                and fault_count < 3
            ):
                fault_count += 1
                raise injected
            original_close(descriptor)

        def fault_select(*args):
            nonlocal fault_count
            if case == "select" and os.getpid() == parent_pid and not fault_count:
                fault_count += 1
                raise injected
            return original_select(*args)

        def fault_read(descriptor: int, size: int):
            nonlocal fault_count
            if (
                case == "read"
                and os.getpid() == parent_pid
                and after_fork
                and not fault_count
            ):
                fault_count += 1
                raise injected
            return original_read(descriptor, size)

        def fault_kill(child: int, signum: int) -> None:
            nonlocal fault_count
            if case == "kill" and os.getpid() == parent_pid and not fault_count:
                fault_count += 1
                raise injected
            original_kill(child, signum)

        def fault_waitpid(child: int, options: int):
            nonlocal fault_count
            if case == "wait" and os.getpid() == parent_pid and not fault_count:
                fault_count += 1
                raise injected
            return original_waitpid(child, options)

        apt.open_private_manifest = record_manifest
        os.pipe = record_pipe
        os.fork = fault_fork
        os.close = fault_close
        select.select = fault_select
        os.read = fault_read
        os.kill = fault_kill
        os.waitpid = fault_waitpid
        caught: BaseException | None = None
        try:
            try:
                run_partial_marker_kill_fixture(
                    apt,
                    manifest_path,
                    marker,
                    manifest_digest,
                )
            except BaseException as exc:
                caught = exc
        finally:
            apt.open_private_manifest = original_manifest_open
            os.pipe = original_pipe
            os.fork = original_fork
            os.close = original_close
            select.select = original_select
            os.read = original_read
            os.kill = original_kill
            os.waitpid = original_waitpid
        if caught is not injected:
            raise SystemExit(
                f"APT hook {case} custody oracle changed its primary: {caught}"
            ) from caught
        if case == "fork":
            if children:
                raise SystemExit("APT hook fork-failure oracle created a child")
        elif len(children) != 1:
            raise SystemExit(f"APT hook {case} oracle did not record one child")
        else:
            try:
                waited, _ = original_waitpid(children[0], os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                if waited == 0:
                    try:
                        original_kill(children[0], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        original_waitpid(children[0], 0)
                    except ChildProcessError:
                        pass
                raise SystemExit(f"APT hook {case} oracle left its child unreaped")
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            original_close(descriptor)
            raise SystemExit(f"APT hook {case} oracle leaked a descriptor")
        for residue in (marker, marker.with_name(f".{marker.name}.tmp")):
            if residue.exists():
                residue.unlink()
                raise SystemExit(f"APT hook {case} oracle left marker residue")


def prove_partial_marker_signal_handoff(
    apt,
    manifest_path: pathlib.Path,
    private: pathlib.Path,
    manifest_digest: str,
) -> None:
    class PendingFixtureSignal(KeyboardInterrupt):
        def __init__(self, signum: int) -> None:
            super().__init__(f"pending fixture signal {signum}")
            self.signum = signum

    original_manifest_open = apt.open_private_manifest
    original_pipe = os.pipe
    original_fork = os.fork
    original_pthread_sigmask = signal.pthread_sigmask
    original_waitpid = os.waitpid
    original_kill = os.kill
    original_read = os.read
    original_unlink = os.unlink
    original_cleanup_marker_inode = globals()["cleanup_fixture_marker_inode"]
    original_close_fixture_descriptor = globals()["close_fixture_descriptor"]
    parent_pid = os.getpid()
    initial_mask = fixture_signal_mask()
    base_mask = initial_mask.difference(FIXTURE_CANCELLATION_SIGNALS)

    def require_case_cleanup(
        label: str,
        marker: pathlib.Path,
        descriptors: list[int],
        children: list[int],
        expected_children: int,
    ) -> None:
        if fixture_signal_mask() != base_mask:
            raise SystemExit(f"APT hook {label} oracle leaked its signal mask")
        if len(children) != expected_children:
            raise SystemExit(f"APT hook {label} oracle child count drifted")
        for child in children:
            try:
                waited, _ = original_waitpid(child, os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                if waited == 0:
                    try:
                        original_kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        original_waitpid(child, 0)
                    except ChildProcessError:
                        pass
                raise SystemExit(f"APT hook {label} oracle left its child unreaped")
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            os.close(descriptor)
            raise SystemExit(f"APT hook {label} oracle leaked a descriptor")
        for residue in (marker, marker.with_name(f".{marker.name}.tmp")):
            if residue.exists():
                residue.unlink()
                raise SystemExit(f"APT hook {label} oracle left marker residue")

    restore_error, restored = restore_fixture_signal_mask(base_mask)
    if restore_error is not None or not restored:
        raise SystemExit("APT hook signal oracle cannot establish its base mask")
    try:
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        original_close = os.close
        close_calls = 0
        close_cancellation = KeyboardInterrupt(
            "injected APT hook descriptor close cancellation"
        )

        def fail_then_cancel_close(value: int) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                raise OSError("injected preliminary descriptor close failure")
            original_close(value)
            raise close_cancellation

        os.close = fail_then_cancel_close
        close_caught: BaseException | None = None
        try:
            try:
                close_fixture_descriptor(descriptor, "APT hook priority descriptor")
            except BaseException as exc:
                close_caught = exc
        finally:
            os.close = original_close
        try:
            os.fstat(descriptor)
        except OSError as exc:
            descriptor_closed = exc.errno == errno.EBADF
        else:
            descriptor_closed = False
            original_close(descriptor)
        if (
            close_caught is not close_cancellation
            or close_calls != 2
            or not descriptor_closed
        ):
            raise SystemExit(
                "APT hook descriptor cleanup masked caller cancellation"
            ) from close_caught

        probe_descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        original_fstat = os.fstat
        probe_close_calls = 0
        probe_fstat_calls = 0
        probe_close_failure = OSError(
            "injected APT hook nonapplied descriptor close failure"
        )
        probe_cancellation = KeyboardInterrupt(
            "injected APT hook descriptor custody-probe cancellation"
        )

        def fail_probe_close_once(value: int) -> None:
            nonlocal probe_close_calls
            if value == probe_descriptor:
                probe_close_calls += 1
                if probe_close_calls == 1:
                    raise probe_close_failure
            original_close(value)

        def cancel_probe_fstat_once(value: int):
            nonlocal probe_fstat_calls
            if value == probe_descriptor:
                probe_fstat_calls += 1
                if probe_fstat_calls == 1:
                    raise probe_cancellation
            return original_fstat(value)

        os.close = fail_probe_close_once
        os.fstat = cancel_probe_fstat_once
        probe_caught: BaseException | None = None
        try:
            try:
                close_fixture_descriptor(
                    probe_descriptor,
                    "APT hook probe-priority descriptor",
                )
            except BaseException as exc:
                probe_caught = exc
        finally:
            os.fstat = original_fstat
            os.close = original_close
        try:
            original_fstat(probe_descriptor)
        except OSError as exc:
            probe_descriptor_closed = exc.errno == errno.EBADF
        else:
            probe_descriptor_closed = False
            original_close(probe_descriptor)
        if (
            probe_caught is not probe_cancellation
            or probe_cancellation.__cause__ is not probe_close_failure
            or probe_close_calls != 2
            or probe_fstat_calls != 1
            or not probe_descriptor_closed
        ):
            raise SystemExit(
                "APT hook descriptor probe cleanup masked caller cancellation"
            ) from probe_caught

        priority_error = OSError("injected nonapplied mask restoration failure")
        priority_cancellation = PendingFixtureSignal(signal.SIGINT)
        priority_injected = False
        priority_events: list[int] = []

        def raise_priority_signal(received: int, _frame) -> None:
            priority_events.append(received)
            raise priority_cancellation

        def fail_first_priority_restore(how, mask):
            nonlocal priority_injected
            if (
                not priority_injected
                and how == signal.SIG_SETMASK
                and frozenset(mask) == base_mask
            ):
                priority_injected = True
                raise priority_error
            return original_pthread_sigmask(how, mask)

        previous_int_handler = signal.getsignal(signal.SIGINT)
        original_pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        original_kill(os.getpid(), signal.SIGINT)
        signal.signal(signal.SIGINT, raise_priority_signal)
        signal.pthread_sigmask = fail_first_priority_restore
        try:
            priority_result, priority_restored = restore_fixture_signal_mask(base_mask)
        finally:
            signal.pthread_sigmask = original_pthread_sigmask
            signal.signal(signal.SIGINT, previous_int_handler)
        if (
            not priority_injected
            or priority_result is not priority_cancellation
            or not priority_restored
            or priority_events != [signal.SIGINT]
            or fixture_signal_mask() != base_mask
            or "APT hook signal-mask restoration also failed"
            not in getattr(priority_result, "__notes__", ())
        ):
            raise SystemExit(
                "APT hook mask restoration masked pending cancellation"
            ) from priority_result

        for signum in (signal.SIGINT, signal.SIGTERM):
            label = signal.Signals(signum).name.lower()
            marker = private / f"killed-pending-{label}.ok"
            descriptors: list[int] = []
            children: list[int] = []
            queued = False
            handler_events: list[int] = []

            def record_manifest(*args, **kwargs):
                result = original_manifest_open(*args, **kwargs)
                descriptors.extend(result[:2])
                return result

            def record_pipe():
                result = original_pipe()
                descriptors.extend(result)
                return result

            def queue_signal_after_fork():
                nonlocal queued
                child = original_fork()
                if child > 0:
                    children.append(child)
                    original_kill(os.getpid(), signum)
                    queued = True
                return child

            def raise_pending_signal(received: int, _frame) -> None:
                handler_events.append(received)
                raise PendingFixtureSignal(received)

            previous_handler = signal.getsignal(signum)
            apt.open_private_manifest = record_manifest
            os.pipe = record_pipe
            os.fork = queue_signal_after_fork
            signal.signal(signum, raise_pending_signal)
            caught: BaseException | None = None
            try:
                try:
                    run_partial_marker_kill_fixture(
                        apt,
                        manifest_path,
                        marker,
                        manifest_digest,
                    )
                except BaseException as exc:
                    caught = exc
            finally:
                signal.signal(signum, previous_handler)
                os.fork = original_fork
                os.pipe = original_pipe
                apt.open_private_manifest = original_manifest_open
            if (
                not queued
                or not isinstance(caught, PendingFixtureSignal)
                or caught.signum != signum
                or handler_events != [signum]
            ):
                raise SystemExit(
                    f"APT hook {label} handoff oracle changed caller policy: {caught}"
                ) from caught
            require_case_cleanup(label, marker, descriptors, children, 1)

        marker = private / "killed-pending-with-close-primary.ok"
        descriptors = []
        children = []
        pending_primary_queued = False
        pending_primary_close_failed = False
        pending_primary_events: list[int] = []
        pending_primary_error = OSError(
            "injected APT hook post-fork close primary"
        )
        pending_primary_cancellation = PendingFixtureSignal(signal.SIGINT)
        def record_manifest(*args, **kwargs):
            result = original_manifest_open(*args, **kwargs)
            descriptors.extend(result[:2])
            return result

        def record_pipe():
            result = original_pipe()
            descriptors.extend(result)
            return result

        def queue_pending_primary_after_fork():
            nonlocal pending_primary_queued
            child = original_fork()
            if child > 0:
                children.append(child)
                original_kill(os.getpid(), signal.SIGINT)
                pending_primary_queued = True
            return child

        def fail_notify_close(descriptor: int, label: str) -> None:
            nonlocal pending_primary_close_failed
            original_close_fixture_descriptor(descriptor, label)
            if label == "APT hook notify descriptor" and not pending_primary_close_failed:
                pending_primary_close_failed = True
                raise pending_primary_error

        def raise_pending_primary(received: int, _frame) -> None:
            pending_primary_events.append(received)
            raise pending_primary_cancellation

        previous_int_handler = signal.getsignal(signal.SIGINT)
        apt.open_private_manifest = record_manifest
        os.pipe = record_pipe
        os.fork = queue_pending_primary_after_fork
        globals()["close_fixture_descriptor"] = fail_notify_close
        signal.signal(signal.SIGINT, raise_pending_primary)
        pending_primary_caught: BaseException | None = None
        try:
            try:
                run_partial_marker_kill_fixture(
                    apt,
                    manifest_path,
                    marker,
                    manifest_digest,
                )
            except BaseException as exc:
                pending_primary_caught = exc
        finally:
            signal.signal(signal.SIGINT, previous_int_handler)
            globals()["close_fixture_descriptor"] = original_close_fixture_descriptor
            os.fork = original_fork
            os.pipe = original_pipe
            apt.open_private_manifest = original_manifest_open
        if (
            not pending_primary_queued
            or not pending_primary_close_failed
            or pending_primary_caught is not pending_primary_cancellation
            or pending_primary_events != [signal.SIGINT]
            or "primary also failed before cancellation"
            not in " ".join(getattr(pending_primary_caught, "__notes__", ()))
        ):
            raise SystemExit(
                "APT hook cleanup primary masked pending cancellation"
            ) from pending_primary_caught
        require_case_cleanup(
            "pending-with-close-primary",
            marker,
            descriptors,
            children,
            1,
        )

        marker = private / "killed-internal-cleanup-with-cancellation.ok"
        descriptors = []
        children = []
        after_fork = False
        read_failed = False
        unlink_failed = False
        cancellation_queued = False
        handler_events = []
        read_error = OSError("injected APT hook parent-read primary")
        unlink_error = OSError("injected APT hook temporary unlink failure")
        cleanup_cancellation = PendingFixtureSignal(signal.SIGINT)
        temporary_name = f".{marker.name}.tmp"

        def record_manifest(*args, **kwargs):
            result = original_manifest_open(*args, **kwargs)
            descriptors.extend(result[:2])
            return result

        def record_pipe():
            result = original_pipe()
            descriptors.extend(result)
            return result

        def record_fork():
            nonlocal after_fork
            child = original_fork()
            if child > 0:
                children.append(child)
                after_fork = True
            return child

        def fail_parent_read(descriptor: int, size: int):
            nonlocal read_failed
            if os.getpid() == parent_pid and after_fork and not read_failed:
                read_failed = True
                raise read_error
            return original_read(descriptor, size)

        def fail_temporary_unlink_once(name, *args, **kwargs):
            nonlocal unlink_failed, cancellation_queued
            if (
                os.getpid() == parent_pid
                and name == temporary_name
                and not unlink_failed
            ):
                unlink_failed = True
                original_kill(os.getpid(), signal.SIGINT)
                cancellation_queued = True
                raise unlink_error
            return original_unlink(name, *args, **kwargs)

        def raise_cleanup_cancellation(received: int, _frame) -> None:
            handler_events.append(received)
            raise cleanup_cancellation

        previous_int_handler = signal.getsignal(signal.SIGINT)
        apt.open_private_manifest = record_manifest
        os.pipe = record_pipe
        os.fork = record_fork
        os.read = fail_parent_read
        os.unlink = fail_temporary_unlink_once
        signal.signal(signal.SIGINT, raise_cleanup_cancellation)
        combined_caught: BaseException | None = None
        try:
            try:
                run_partial_marker_kill_fixture(
                    apt,
                    manifest_path,
                    marker,
                    manifest_digest,
                )
            except BaseException as exc:
                combined_caught = exc
        finally:
            signal.signal(signal.SIGINT, previous_int_handler)
            os.unlink = original_unlink
            os.read = original_read
            os.fork = original_fork
            os.pipe = original_pipe
            apt.open_private_manifest = original_manifest_open
        if (
            not read_failed
            or not unlink_failed
            or not cancellation_queued
            or combined_caught is not cleanup_cancellation
            or handler_events != [signal.SIGINT]
            or "parent-read primary" not in " ".join(
                getattr(combined_caught, "__notes__", ())
            )
        ):
            raise SystemExit(
                "APT hook internal cleanup failure masked caller cancellation: "
                f"read={read_failed} unlink={unlink_failed} "
                f"queued={cancellation_queued} caught={combined_caught!r} "
                f"events={handler_events!r} "
                f"notes={getattr(combined_caught, '__notes__', ())!r}"
            ) from combined_caught
        require_case_cleanup(
            "internal-cleanup-with-cancellation",
            marker,
            descriptors,
            children,
            1,
        )

        marker = private / "killed-internal-cleanup-without-cancellation.ok"
        descriptors = []
        children = []
        unlink_failed = False
        unlink_error = OSError("injected APT hook temporary unlink failure")
        temporary_name = f".{marker.name}.tmp"

        def record_manifest(*args, **kwargs):
            result = original_manifest_open(*args, **kwargs)
            descriptors.extend(result[:2])
            return result

        def record_pipe():
            result = original_pipe()
            descriptors.extend(result)
            return result

        def record_fork():
            child = original_fork()
            if child > 0:
                children.append(child)
            return child

        def fail_temporary_unlink_once(name, *args, **kwargs):
            nonlocal unlink_failed
            if (
                os.getpid() == parent_pid
                and name == temporary_name
                and not unlink_failed
            ):
                unlink_failed = True
                raise unlink_error
            return original_unlink(name, *args, **kwargs)

        apt.open_private_manifest = record_manifest
        os.pipe = record_pipe
        os.fork = record_fork
        os.unlink = fail_temporary_unlink_once
        cleanup_only_caught: BaseException | None = None
        try:
            try:
                run_partial_marker_kill_fixture(
                    apt,
                    manifest_path,
                    marker,
                    manifest_digest,
                )
            except BaseException as exc:
                cleanup_only_caught = exc
        finally:
            os.unlink = original_unlink
            os.fork = original_fork
            os.pipe = original_pipe
            apt.open_private_manifest = original_manifest_open
        if not unlink_failed or cleanup_only_caught is not unlink_error:
            raise SystemExit(
                "APT hook internal cleanup failure lost its ordinary primary"
            ) from cleanup_only_caught
        require_case_cleanup(
            "internal-cleanup-without-cancellation",
            marker,
            descriptors,
            children,
            1,
        )

        marker = private / "killed-cleanup-double-signal.ok"
        descriptors: list[int] = []
        children: list[int] = []
        cleanup_signals_queued = False
        handler_events: list[int] = []

        def record_manifest(*args, **kwargs):
            result = original_manifest_open(*args, **kwargs)
            descriptors.extend(result[:2])
            return result

        def record_pipe():
            result = original_pipe()
            descriptors.extend(result)
            return result

        def record_fork():
            child = original_fork()
            if child > 0:
                children.append(child)
            return child

        def queue_during_cleanup(*args, **kwargs):
            nonlocal cleanup_signals_queued
            if not cleanup_signals_queued:
                original_kill(os.getpid(), signal.SIGINT)
                original_kill(os.getpid(), signal.SIGTERM)
                cleanup_signals_queued = True
            return original_cleanup_marker_inode(*args, **kwargs)

        def raise_cleanup_signal(received: int, _frame) -> None:
            handler_events.append(received)
            raise PendingFixtureSignal(received)

        previous_handlers = {
            signum: signal.getsignal(signum)
            for signum in FIXTURE_CANCELLATION_SIGNALS
        }
        apt.open_private_manifest = record_manifest
        os.pipe = record_pipe
        os.fork = record_fork
        globals()["cleanup_fixture_marker_inode"] = queue_during_cleanup
        for signum in FIXTURE_CANCELLATION_SIGNALS:
            signal.signal(signum, raise_cleanup_signal)
        caught: BaseException | None = None
        try:
            try:
                run_partial_marker_kill_fixture(
                    apt,
                    manifest_path,
                    marker,
                    manifest_digest,
                )
            except BaseException as exc:
                caught = exc
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            globals()["cleanup_fixture_marker_inode"] = original_cleanup_marker_inode
            os.fork = original_fork
            os.pipe = original_pipe
            apt.open_private_manifest = original_manifest_open
        if (
            not cleanup_signals_queued
            or not isinstance(caught, PendingFixtureSignal)
            or len(handler_events) != 2
            or set(handler_events) != set(FIXTURE_CANCELLATION_SIGNALS)
        ):
            raise SystemExit(
                "APT hook cleanup double-signal oracle changed caller policy: "
                f"caught={caught!r} events={handler_events!r}"
            ) from caught
        require_case_cleanup(
            "cleanup-double-signal",
            marker,
            descriptors,
            children,
            1,
        )

        for case in ("block-applied", "restore-applied"):
            marker = private / f"killed-{case}.ok"
            descriptors: list[int] = []
            children: list[int] = []
            injected = OSError(f"injected APT hook {case} mask failure")
            injected_once = False
            after_fork = False

            def record_manifest(*args, **kwargs):
                result = original_manifest_open(*args, **kwargs)
                descriptors.extend(result[:2])
                return result

            def record_pipe():
                result = original_pipe()
                descriptors.extend(result)
                return result

            def record_fork():
                nonlocal after_fork
                child = original_fork()
                if child > 0:
                    children.append(child)
                    after_fork = True
                return child

            def inject_mask_failure(how, mask):
                nonlocal injected_once
                result = original_pthread_sigmask(how, mask)
                requested = frozenset(mask)
                should_inject = (
                    not injected_once
                    and (
                        (
                            case == "block-applied"
                            and how == signal.SIG_BLOCK
                            and requested == FIXTURE_CANCELLATION_SIGNALS
                        )
                        or (
                            case == "restore-applied"
                            and after_fork
                            and how == signal.SIG_SETMASK
                            and requested == base_mask
                        )
                    )
                )
                if should_inject:
                    injected_once = True
                    raise injected
                return result

            apt.open_private_manifest = record_manifest
            os.pipe = record_pipe
            os.fork = record_fork
            signal.pthread_sigmask = inject_mask_failure
            caught: BaseException | None = None
            try:
                try:
                    run_partial_marker_kill_fixture(
                        apt,
                        manifest_path,
                        marker,
                        manifest_digest,
                    )
                except BaseException as exc:
                    caught = exc
            finally:
                signal.pthread_sigmask = original_pthread_sigmask
                os.fork = original_fork
                os.pipe = original_pipe
                apt.open_private_manifest = original_manifest_open
            if caught is not injected or not injected_once:
                raise SystemExit(
                    f"APT hook {case} oracle changed its primary: {caught}"
                ) from caught
            require_case_cleanup(
                case,
                marker,
                descriptors,
                children,
                0 if case == "block-applied" else 1,
            )
    finally:
        signal.pthread_sigmask = original_pthread_sigmask
        os.unlink = original_unlink
        os.read = original_read
        os.fork = original_fork
        os.pipe = original_pipe
        apt.open_private_manifest = original_manifest_open
        globals()["cleanup_fixture_marker_inode"] = original_cleanup_marker_inode
        globals()["close_fixture_descriptor"] = original_close_fixture_descriptor
        restore_error, restored = restore_fixture_signal_mask(initial_mask)
        if restore_error is not None or not restored:
            raise SystemExit("APT hook signal oracle could not restore caller mask")


def run_hook_main(module, eipp_path: pathlib.Path, arguments: list[str]):
    original_argv = sys.argv
    original_info_fd = os.environ.get("APT_HOOK_INFO_FD")
    output = io.StringIO()
    caught = None
    with eipp_path.open("rb") as stream:
        eipp_descriptor = stream.fileno()
        try:
            saved_descriptor = os.dup(21)
        except OSError:
            saved_descriptor = -1
        os.dup2(eipp_descriptor, 21, inheritable=True)
        sys.argv = [str(APT_MODULE_PATH), *arguments]
        os.environ["APT_HOOK_INFO_FD"] = "21"
        try:
            with contextlib.redirect_stdout(output):
                module.main()
        except (SystemExit, KeyboardInterrupt) as exc:
            caught = exc
        finally:
            sys.argv = original_argv
            if original_info_fd is None:
                os.environ.pop("APT_HOOK_INFO_FD", None)
            else:
                os.environ["APT_HOOK_INFO_FD"] = original_info_fd
            if saved_descriptor >= 0:
                os.dup2(saved_descriptor, 21, inheritable=True)
                os.close(saved_descriptor)
            else:
                os.close(21)
    return caught, output.getvalue()


def require_cli_rejected(
    eipp_path: pathlib.Path,
    arguments: list[str],
    marker_path: pathlib.Path,
    label: str,
    expected: bytes,
) -> None:
    marker_before = marker_path.read_bytes() if marker_path.exists() else None
    result = run_hook_cli(eipp_path, arguments)
    marker_after = marker_path.read_bytes() if marker_path.exists() else None
    if (
        result.returncode == 0
        or expected not in result.stderr
        or marker_after != marker_before
    ):
        raise SystemExit(
            f"APT hook CLI did not reject {label} without marker drift: "
            + result.stderr[:8192].decode("utf-8", errors="replace")
        )


def require_rejected(
    module, callback, label: str, expected: str, *, exact: bool = False
) -> None:
    try:
        callback()
    except module.AptTransactionError as exc:
        if (str(exc) != expected) if exact else (expected not in str(exc)):
            raise SystemExit(
                f"APT hook verifier rejected {label} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"APT hook verifier raised an unexpected exception for {label}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"APT hook verifier accepted hostile fixture: {label}")


def verify_marker_cleanup_evidence(
    apt,
    private: pathlib.Path,
    manifest_digest: str,
) -> None:
    parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(private, parent_flags)
    original_stat = apt.os.stat
    original_unlink = apt.os.unlink
    original_fsync = apt.os.fsync
    original_link = apt.os.link
    original_write = apt.os.write
    original_open = apt.os.open
    original_close = apt.os.close
    original_monotonic = apt.time.monotonic

    cases = (
        (
            "published-unlink",
            (
                "APT hook marker cleanup could not remove published marker",
                "APT hook marker cleanup left the published marker inode present",
            ),
        ),
        (
            "temporary-unlink",
            (
                "APT hook marker cleanup could not remove temporary marker",
                "APT hook marker cleanup left the temporary marker inode present",
            ),
        ),
        (
            "both-unlink",
            (
                "APT hook marker cleanup could not remove published marker",
                "APT hook marker cleanup could not remove temporary marker",
                "APT hook marker cleanup left the published marker inode present",
                "APT hook marker cleanup left the temporary marker inode present",
            ),
        ),
        (
            "published-stat",
            (
                "APT hook marker cleanup could not inspect published marker",
                "APT hook marker cleanup could not confirm published marker removal",
            ),
        ),
        (
            "temporary-stat",
            (
                "APT hook marker cleanup could not inspect temporary marker",
                "APT hook marker cleanup could not confirm temporary marker removal",
            ),
        ),
        (
            "directory-fsync",
            ("APT hook marker cleanup could not synchronize marker directory",),
        ),
        (
            "published-recheck",
            ("APT hook marker cleanup could not confirm published marker removal",),
        ),
        (
            "published-namespace",
            ("APT hook marker cleanup found the published marker namespace changed",),
        ),
        (
            "write-and-temporary-unlink",
            (
                "APT hook marker cleanup could not remove temporary marker",
                "APT hook marker cleanup left the temporary marker inode present",
            ),
        ),
    )
    try:
        for case, expected_notes in cases:
            marker_path = private / f"cleanup-{case}.ok"
            temporary_name = f".{marker_path.name}.tmp"
            clock = [0.0]
            stat_calls = {marker_path.name: 0, temporary_name: 0}
            injected_write_error = OSError(
                errno.EIO, "injected marker write failure"
            )

            def expiring_link(*args, **kwargs):
                result = original_link(*args, **kwargs)
                clock[0] = 301.0
                return result

            def hostile_stat(path, *args, **kwargs):
                name = os.fspath(path)
                if kwargs.get("dir_fd") == parent_descriptor and name in stat_calls:
                    stat_calls[name] += 1
                    role = "published" if name == marker_path.name else "temporary"
                    if case == f"{role}-stat":
                        raise OSError(errno.EIO, "injected cleanup stat failure")
                    if (
                        case == "published-recheck"
                        and role == "published"
                        and stat_calls[name] == 2
                    ):
                        raise OSError(errno.EIO, "injected cleanup recheck failure")
                    if (
                        case == "published-namespace"
                        and role == "published"
                        and stat_calls[name] == 1
                    ):
                        original_unlink(name, dir_fd=parent_descriptor)
                        descriptor = original_open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            0o600,
                            dir_fd=parent_descriptor,
                        )
                        try:
                            original_write(descriptor, b"unrelated namespace\n")
                        finally:
                            original_close(descriptor)
                return original_stat(path, *args, **kwargs)

            def hostile_unlink(path, *args, **kwargs):
                name = os.fspath(path)
                if kwargs.get("dir_fd") == parent_descriptor:
                    if case in {"published-unlink", "both-unlink"} and name == marker_path.name:
                        raise OSError(errno.EIO, "injected published unlink failure")
                    if case in {
                        "temporary-unlink",
                        "both-unlink",
                        "write-and-temporary-unlink",
                    } and name == temporary_name:
                        raise OSError(errno.EIO, "injected temporary unlink failure")
                return original_unlink(path, *args, **kwargs)

            def hostile_fsync(descriptor: int) -> None:
                if case == "directory-fsync" and descriptor == parent_descriptor:
                    raise OSError(errno.EIO, "injected cleanup fsync failure")
                original_fsync(descriptor)

            def hostile_write(descriptor: int, raw: bytes) -> int:
                if case == "write-and-temporary-unlink":
                    raise injected_write_error
                return original_write(descriptor, raw)

            apt.os.stat = hostile_stat
            apt.os.unlink = hostile_unlink
            apt.os.fsync = hostile_fsync
            apt.os.link = expiring_link
            apt.os.write = hostile_write
            apt.time.monotonic = lambda: clock[0]
            caught = None
            try:
                apt.write_hook_marker(
                    parent_descriptor,
                    marker_path,
                    manifest_digest,
                    deadline=300.0,
                )
            except apt.AptTransactionError as exc:
                caught = exc
            finally:
                apt.os.stat = original_stat
                apt.os.unlink = original_unlink
                apt.os.fsync = original_fsync
                apt.os.link = original_link
                apt.os.write = original_write
                apt.time.monotonic = original_monotonic
            if caught is None:
                raise SystemExit(f"APT marker cleanup fixture accepted {case}")
            if case == "write-and-temporary-unlink":
                if (
                    not str(caught).startswith(
                        "cannot create or write APT hook marker: "
                    )
                    or caught.__cause__ is not injected_write_error
                ):
                    raise SystemExit(
                        "APT marker cleanup replaced the wrapped write failure"
                    ) from caught
            elif str(caught) != "APT hook verification exceeded its deadline":
                raise SystemExit(
                    f"APT marker cleanup replaced the deadline primary: {case}: {caught}"
                ) from caught
            notes = tuple(getattr(caught, "__notes__", ()))
            if notes != expected_notes:
                raise SystemExit(
                    "APT marker cleanup evidence drifted: "
                    f"{case}: expected={expected_notes!r} actual={notes!r}"
                ) from caught
            if any("injected" in note for note in notes):
                raise SystemExit("APT marker cleanup exposed injected exception text")
            rendered = apt.format_cli_failure(
                "haptics APT hook verification failed", caught
            )
            expected_rendered = (
                f"haptics APT hook verification failed: {caught}"
                + "".join(
                    "\nhaptics APT hook verification failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if rendered != expected_rendered:
                raise SystemExit(
                    f"APT marker CLI cleanup evidence drifted: {case}: {rendered!r}"
                ) from caught
            temporary_path = private / temporary_name
            if case == "published-namespace":
                if (
                    not marker_path.exists()
                    or marker_path.read_bytes() != b"unrelated namespace\n"
                ):
                    raise SystemExit("APT marker cleanup removed a replacement namespace")
            for remaining in (marker_path, temporary_path):
                if remaining.exists():
                    original_unlink(remaining.name, dir_fd=parent_descriptor)

        replacement_raw = b"unrelated post-link marker namespace\n"
        for case in ("applied-error", "applied-cancel", "applied-replacement"):
            marker_path = private / f"link-uncertain-{case}.ok"
            temporary_path = private / f".{marker_path.name}.tmp"
            injected_error = OSError(errno.EIO, "injected applied marker link failure")
            injected_cancel = KeyboardInterrupt("injected post-link cancellation")

            def applied_then_failed_link(*args, **kwargs):
                result = original_link(*args, **kwargs)
                if case == "applied-replacement":
                    original_unlink(marker_path.name, dir_fd=parent_descriptor)
                    replacement_descriptor = original_open(
                        marker_path.name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=parent_descriptor,
                    )
                    try:
                        original_write(replacement_descriptor, replacement_raw)
                    finally:
                        original_close(replacement_descriptor)
                if case == "applied-cancel":
                    raise injected_cancel
                raise injected_error

            apt.os.link = applied_then_failed_link
            caught: BaseException | None = None
            try:
                apt.write_hook_marker(
                    parent_descriptor,
                    marker_path,
                    manifest_digest,
                    deadline=apt.time.monotonic() + 300.0,
                )
            except BaseException as exc:
                caught = exc
            finally:
                apt.os.link = original_link
            if case == "applied-cancel":
                if caught is not injected_cancel:
                    raise SystemExit(
                        "APT marker applied-link cleanup replaced cancellation"
                    ) from caught
            elif (
                not isinstance(caught, apt.AptTransactionError)
                or caught.__cause__ is not injected_error
                or not str(caught).startswith(
                    "cannot create or write APT hook marker: "
                )
            ):
                raise SystemExit(
                    f"APT marker applied-link cleanup replaced {case}: {caught!r}"
                ) from caught
            expected_notes = (
                (
                    "APT hook marker cleanup found the published marker namespace "
                    "changed",
                )
                if case == "applied-replacement"
                else ()
            )
            if tuple(getattr(caught, "__notes__", ())) != expected_notes:
                raise SystemExit(
                    f"APT marker applied-link cleanup evidence drifted: {case}"
                ) from caught
            if temporary_path.exists():
                raise SystemExit(
                    f"APT marker applied-link cleanup left its temporary name: {case}"
                )
            if case == "applied-replacement":
                if (
                    not marker_path.exists()
                    or marker_path.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT marker applied-link cleanup removed replacement namespace"
                    )
                original_unlink(marker_path.name, dir_fd=parent_descriptor)
            elif marker_path.exists():
                raise SystemExit(
                    f"APT marker applied-link cleanup left its final name: {case}"
                )
    finally:
        apt.os.stat = original_stat
        apt.os.unlink = original_unlink
        apt.os.fsync = original_fsync
        apt.os.link = original_link
        apt.os.write = original_write
        apt.time.monotonic = original_monotonic
        original_close(parent_descriptor)


def verify_marker_publication_prepin(
    apt,
    admin: pathlib.Path,
    manifest_path: pathlib.Path,
    eipp_path: pathlib.Path,
    private: pathlib.Path,
) -> None:
    original_open = apt.os.open
    original_fstat = apt.os.fstat
    original_unlink = apt.os.unlink
    original_write = apt.os.write
    original_close = apt.os.close
    original_monotonic = apt.time.monotonic
    issues: list[str] = []
    for case in ("deadline", "first-fstat", "first-fstat-replacement"):
        marker_path = private / f"prepin-{case}.ok"
        temporary_name = f".{marker_path.name}.tmp"
        temporary_path = private / temporary_name
        clock = [0.0]
        created_descriptors: list[int] = []
        parent_descriptors: list[int] = []
        target_fstat_calls = 0
        replacement_raw = b"unrelated marker namespace\n"

        def prepin_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            if (
                os.fspath(path) == temporary_name
                and flags & os.O_EXCL
                and kwargs.get("dir_fd") is not None
            ):
                created_descriptors.append(descriptor)
                parent_descriptors.append(kwargs["dir_fd"])
                if case == "deadline":
                    clock[0] = apt.HOOK_VERIFICATION_TIMEOUT_SECONDS
            return descriptor

        def prepin_fstat(descriptor: int):
            nonlocal target_fstat_calls
            if created_descriptors and descriptor == created_descriptors[0]:
                target_fstat_calls += 1
                if case.startswith("first-fstat") and target_fstat_calls == 1:
                    if case.endswith("replacement"):
                        original_unlink(
                            temporary_name, dir_fd=parent_descriptors[0]
                        )
                        replacement_descriptor = original_open(
                            temporary_name,
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | os.O_CLOEXEC,
                            0o600,
                            dir_fd=parent_descriptors[0],
                        )
                        try:
                            original_write(replacement_descriptor, replacement_raw)
                        finally:
                            original_close(replacement_descriptor)
                    raise OSError("injected first post-open marker fstat failure")
            return original_fstat(descriptor)

        apt.os.open = prepin_open
        apt.os.fstat = prepin_fstat
        apt.time.monotonic = lambda: clock[0]
        try:
            caught, output = run_hook_main(
                apt,
                eipp_path,
                [
                    "--verify-hook-disposable",
                    str(admin),
                    "0",
                    "0",
                    str(manifest_path),
                    str(marker_path),
                ],
            )
        finally:
            apt.os.open = original_open
            apt.os.fstat = original_fstat
            apt.time.monotonic = original_monotonic
        expected_primary = (
            "APT hook verification exceeded its deadline"
            if case == "deadline"
            else "cannot create or write APT hook marker: "
            "injected first post-open marker fstat failure"
        )
        expected_notes = (
            (
                "APT hook marker cleanup found the temporary marker namespace "
                "changed",
            )
            if case.endswith("replacement")
            else ()
        )
        expected_rendered = (
            "haptics APT hook verification failed: " + expected_primary
            + "".join(
                "\nhaptics APT hook verification failed cleanup: " + note
                for note in expected_notes
            )
        )
        if caught is None:
            issues.append(f"{case} was accepted")
        else:
            primary = caught.__cause__
            if (
                not isinstance(primary, apt.AptTransactionError)
                or str(primary) != expected_primary
            ):
                issues.append(f"{case} replaced its primary with {primary!r}")
            elif tuple(getattr(primary, "__notes__", ())) != expected_notes:
                issues.append(
                    f"{case} cleanup notes were "
                    f"{tuple(getattr(primary, '__notes__', ()))!r}"
                )
            if str(caught) != expected_rendered:
                issues.append(f"{case} CLI evidence was {str(caught)!r}")
        if output:
            issues.append(f"{case} printed PASS output")
        minimum_fstats = 1 if case == "deadline" else 2
        if target_fstat_calls < minimum_fstats:
            issues.append(
                f"{case} used only {target_fstat_calls} owned-descriptor fstats"
            )
        for descriptor in created_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                issues.append(f"{case} leaked its publication descriptor")
        if marker_path.exists():
            issues.append(f"{case} exposed the final marker pathname")
        if case.endswith("replacement"):
            if (
                not temporary_path.exists()
                or temporary_path.read_bytes() != replacement_raw
            ):
                issues.append(f"{case} removed the replacement namespace")
        elif temporary_path.exists():
            issues.append(f"{case} left the owned temporary marker pathname")
        for remaining in (marker_path, temporary_path):
            try:
                original_unlink(remaining)
            except FileNotFoundError:
                pass
    apt.os.open = original_open
    apt.os.fstat = original_fstat
    apt.os.unlink = original_unlink
    apt.os.write = original_write
    apt.os.close = original_close
    apt.time.monotonic = original_monotonic
    if issues:
        raise SystemExit(
            "APT marker pre-pin fixture failures: " + "; ".join(issues)
        )


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("APT hook fixture must run as root")
    apt = load_module("haptics_apt_hook_transaction", APT_MODULE_PATH)
    dpkg = load_module("haptics_apt_hook_dpkg", DPKG_MODULE_PATH)
    package = load_module("haptics_apt_hook_packages", PACKAGE_MODULE_PATH)
    if not hasattr(apt, "verify_hook_inputs"):
        raise SystemExit("APT hook verifier interface is missing")
    if not hasattr(apt, "load_package_verifier"):
        raise SystemExit("APT hook package-state verifier interface is missing")
    native_status = pathlib.Path("/var/lib/dpkg/status")
    native_before = hashlib.sha256(native_status.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-apt-hook-test.") as raw:
        root = pathlib.Path(raw)
        root.chmod(0o755)
        admin = make_empty_admin(root)
        archive = make_deb(root)
        archive_record = apt.capture_deb_archive(archive, 0, 0)
        encoded_hook = HOOK_COMMAND.replace(" ", "%20")
        eipp_raw = (
            "VERSION 3\n"
            "APT::Architecture=amd64\n"
            "APT::Architectures::=amd64\n"
            "Dir::Bin::dpkg=/usr/bin/dpkg\n"
            "DPkg::ConfigurePending=1\n"
            "DPkg::Path=/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"DPkg::Pre-Install-Pkgs::={encoded_hook}\n"
            "DPkg::Run-Directory=/\n"
            f"DPkg::Tools::options::{encoded_hook}::InfoFD=21\n"
            f"DPkg::Tools::options::{encoded_hook}::Version=3\n"
            "\n"
            f"example - - none < 1.0-1 amd64 none {archive}\n"
            "example - - none < 1.0-1 amd64 none **CONFIGURE**\n"
        ).encode("ascii")
        document = apt.parse_eipp_v3_bytes(eipp_raw)
        state = dpkg.capture_dpkg_state(admin, 0, 0)
        state_raw = dpkg.serialize_dpkg_state(state)
        host_raw = dpkg.serialize_host_reference(dpkg.host_reference_from_state(state))
        package_state_raw = package.serialize_system_state(package.capture_system_state())
        transaction = apt.ExpectedTransaction(
            hashlib.sha256(package_state_raw).hexdigest(),
            hashlib.sha256(state_raw).hexdigest(),
            hashlib.sha256(host_raw).hexdigest(),
            document.configuration,
            document.actions,
            (archive_record,),
        )
        manifest_raw = apt.serialize_expected_transaction(transaction)
        apt_account = pwd.getpwnam("_apt")
        hook_deadline = apt.time.monotonic() + apt.HOOK_VERIFICATION_TIMEOUT_SECONDS
        digest = apt.verify_hook_inputs(
            eipp_raw,
            manifest_raw,
            admin,
            0,
            0,
            apt_account.pw_uid,
            apt_account.pw_gid,
            deadline=hook_deadline,
        )
        if digest != hashlib.sha256(manifest_raw).hexdigest():
            raise SystemExit("APT hook verifier returned the wrong manifest digest")

        original_archive_capture = apt.capture_deb_archive
        original_monotonic = apt.time.monotonic
        deadline_clock = [0.0]

        def deadline_archive_capture(*arguments, **kwargs):
            deadline_clock[0] = 301.0
            return archive_record

        apt.capture_deb_archive = deadline_archive_capture
        apt.time.monotonic = lambda: deadline_clock[0]
        try:
            require_rejected(
                apt,
                lambda: apt.verify_hook_inputs(
                    eipp_raw,
                    manifest_raw,
                    admin,
                    0,
                    0,
                    apt_account.pw_uid,
                    apt_account.pw_gid,
                ),
                "aggregate hook deadline",
                "APT hook verification exceeded its deadline",
            )
        finally:
            apt.time.monotonic = original_monotonic
            apt.capture_deb_archive = original_archive_capture

        class DriftingDpkgState:
            def __init__(self, delegate) -> None:
                self.delegate = delegate
                self.capture_count = 0

            def __getattr__(self, name):
                return getattr(self.delegate, name)

            def capture_dpkg_state(self, *arguments):
                captured = self.delegate.capture_dpkg_state(*arguments)
                self.capture_count += 1
                if self.capture_count == 1:
                    return captured
                files = list(captured.state_files)
                status_position = next(
                    index for index, item in enumerate(files) if item.name == "status"
                )
                status_record = files[status_position]
                files[status_position] = self.delegate.StateFileRecord(
                    status_record.name,
                    status_record.mode,
                    status_record.size,
                    "0" * 64,
                )
                return self.delegate.DpkgState(
                    tuple(files),
                    captured.triggers,
                    captured.handlers,
                    captured.diversions,
                    captured.statoverrides,
                    captured.scripts,
                )

        original_dpkg_loader = apt.load_dpkg_state_verifier
        apt.load_dpkg_state_verifier = lambda: DriftingDpkgState(dpkg)
        try:
            require_rejected(
                apt,
                lambda: apt.verify_hook_inputs(
                    eipp_raw,
                    manifest_raw,
                    admin,
                    0,
                    0,
                    apt_account.pw_uid,
                    apt_account.pw_gid,
                ),
                "dpkg state drift during hook verification",
                "dpkg state differs from the expected transaction",
            )
        finally:
            apt.load_dpkg_state_verifier = original_dpkg_loader

        class DriftingPackageState:
            def __init__(self, delegate) -> None:
                self.delegate = delegate
                self.capture_count = 0

            def __getattr__(self, name):
                return getattr(self.delegate, name)

            def capture_system_state(self, *, deadline=None):
                captured = self.delegate.capture_system_state(deadline=deadline)
                self.capture_count += 1
                if self.capture_count == 1:
                    return captured
                selections = dict(captured.selections)
                selections["hook-state-drift"] = "install"
                return self.delegate.SystemState(
                    captured.packages,
                    selections,
                    captured.foreign_architectures,
                    captured.alternatives,
                )

        original_package_loader = apt.load_package_verifier
        apt.load_package_verifier = lambda: DriftingPackageState(package)
        try:
            require_rejected(
                apt,
                lambda: apt.verify_hook_inputs(
                    eipp_raw,
                    manifest_raw,
                    admin,
                    0,
                    0,
                    apt_account.pw_uid,
                    apt_account.pw_gid,
                ),
                "package state drift during hook verification",
                "package state differs from the expected transaction",
            )
        finally:
            apt.load_package_verifier = original_package_loader

        class FailingPackageState:
            def __init__(self, delegate, failure) -> None:
                self.delegate = delegate
                self.failure = failure

            def __getattr__(self, name):
                return getattr(self.delegate, name)

            def capture_system_state(self, *, deadline=None):
                del deadline
                raise self.failure

        for label, failure in (
            (
                "hook package-state capture timeout",
                subprocess.TimeoutExpired(["injected hook package capture"], 1),
            ),
            (
                "hook package-state subprocess failure",
                subprocess.SubprocessError("injected hook package capture failure"),
            ),
            (
                "hook package-state operating-system failure",
                OSError("injected hook package capture failure"),
            ),
        ):
            apt.load_package_verifier = lambda failure=failure: FailingPackageState(
                package, failure
            )
            try:
                require_rejected(
                    apt,
                    lambda: apt.verify_hook_inputs(
                        eipp_raw,
                        manifest_raw,
                        admin,
                        0,
                        0,
                        apt_account.pw_uid,
                        apt_account.pw_gid,
                    ),
                    label,
                    "cannot capture package state at the APT hook boundary",
                    exact=True,
                )
            finally:
                apt.load_package_verifier = original_package_loader

        original_archive_capture = apt.capture_deb_archive
        archive_capture_count = 0

        def drifting_archive_capture(*arguments, **kwargs):
            nonlocal archive_capture_count
            captured = original_archive_capture(*arguments, **kwargs)
            archive_capture_count += 1
            if archive_capture_count == 1:
                return captured
            return apt.ArchiveRecord(
                captured.path,
                captured.device,
                captured.inode,
                captured.mode,
                captured.uid,
                captured.gid,
                captured.nlink,
                captured.size,
                "0" * 64,
                captured.package,
                captured.version,
                captured.architecture,
                captured.multiarch,
            )

        apt.capture_deb_archive = drifting_archive_capture
        try:
            require_rejected(
                apt,
                lambda: apt.verify_hook_inputs(
                    eipp_raw,
                    manifest_raw,
                    admin,
                    0,
                    0,
                    apt_account.pw_uid,
                    apt_account.pw_gid,
                ),
                "archive drift during hook verification",
                "APT archive changed during hook verification",
            )
        finally:
            apt.capture_deb_archive = original_archive_capture

        private = root / "private"
        private.mkdir()
        private.chmod(0o700)
        manifest_path = private / "expected.tsv"
        marker_path = private / "hook.ok"
        hook_command = (
            f"/usr/bin/python3 -I -B {APT_MODULE_PATH} --verify-hook-disposable "
            f"{admin} 0 0 {manifest_path} {marker_path}"
        )
        encoded_cli_hook = hook_command.replace(" ", "%20")
        cli_eipp_raw = (
            "VERSION 3\n"
            "APT::Architecture=amd64\n"
            "APT::Architectures::=amd64\n"
            "Dir::Bin::dpkg=/usr/bin/dpkg\n"
            "DPkg::ConfigurePending=1\n"
            "DPkg::Path=/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"DPkg::Pre-Install-Pkgs::={encoded_cli_hook}\n"
            "DPkg::Run-Directory=/\n"
            f"DPkg::Tools::options::{encoded_cli_hook}::InfoFD=21\n"
            f"DPkg::Tools::options::{encoded_cli_hook}::Version=3\n"
            "\n"
            f"example - - none < 1.0-1 amd64 none {archive}\n"
            "example - - none < 1.0-1 amd64 none **CONFIGURE**\n"
        ).encode("ascii")
        cli_document = apt.parse_eipp_v3_bytes(cli_eipp_raw)
        cli_transaction = apt.ExpectedTransaction(
            hashlib.sha256(package_state_raw).hexdigest(),
            hashlib.sha256(state_raw).hexdigest(),
            hashlib.sha256(host_raw).hexdigest(),
            cli_document.configuration,
            cli_document.actions,
            (archive_record,),
        )
        cli_manifest_raw = apt.serialize_expected_transaction(cli_transaction)
        write_file(manifest_path, cli_manifest_raw, 0o600)
        eipp_path = private / "eipp.raw"
        write_file(eipp_path, cli_eipp_raw, 0o600)
        verify_marker_publication_prepin(
            apt,
            admin,
            manifest_path,
            eipp_path,
            private,
        )
        (
            pinned_parent,
            pinned_manifest,
            pinned_raw,
            pinned_identity,
            pinned_parent_identity,
        ) = apt.open_private_manifest(manifest_path, marker_path)
        private.chmod(0o755)
        try:
            require_rejected(
                apt,
                lambda: apt.recheck_private_manifest(
                    pinned_parent,
                    pinned_manifest,
                    manifest_path,
                    pinned_raw,
                    pinned_identity,
                    pinned_parent_identity,
                ),
                "private directory mode drift after manifest open",
                "private directory changed before marker creation",
            )
        finally:
            private.chmod(0o700)
            os.close(pinned_manifest)
            os.close(pinned_parent)
        (
            pinned_parent,
            pinned_manifest,
            pinned_raw,
            pinned_identity,
            pinned_parent_identity,
        ) = apt.open_private_manifest(manifest_path, marker_path)
        drifted_manifest = bytearray(cli_manifest_raw)
        digest_position = drifted_manifest.index(
            cli_transaction.dpkg_state_sha256.encode("ascii")
        )
        drifted_manifest[digest_position] = ord("0") if drifted_manifest[digest_position] != ord("0") else ord("1")
        write_file(manifest_path, bytes(drifted_manifest), 0o600)
        try:
            require_rejected(
                apt,
                lambda: apt.recheck_private_manifest(
                    pinned_parent,
                    pinned_manifest,
                    manifest_path,
                    pinned_raw,
                    pinned_identity,
                    pinned_parent_identity,
                ),
                "same-size manifest content drift after open",
                "manifest changed before marker creation",
            )
        finally:
            os.close(pinned_manifest)
            os.close(pinned_parent)
            write_file(manifest_path, cli_manifest_raw, 0o600)
        partial_marker = private / "partial.ok"
        (
            pinned_parent,
            pinned_manifest,
            _,
            _,
            _,
        ) = apt.open_private_manifest(manifest_path, partial_marker)
        original_write = apt.os.write
        write_count = 0

        def fail_after_partial_write(descriptor: int, raw: bytes) -> int:
            nonlocal write_count
            write_count += 1
            if write_count == 1:
                return original_write(descriptor, raw[:1])
            raise OSError("injected marker write failure")

        apt.os.write = fail_after_partial_write
        try:
            require_rejected(
                apt,
                lambda: apt.write_hook_marker(
                    pinned_parent,
                    partial_marker,
                    hashlib.sha256(cli_manifest_raw).hexdigest(),
                    deadline=(
                        apt.time.monotonic()
                        + apt.HOOK_VERIFICATION_TIMEOUT_SECONDS
                    ),
                ),
                "partial marker write",
                "cannot create or write APT hook marker",
            )
            if partial_marker.exists():
                raise SystemExit("failed APT hook marker write left a partial marker")
        finally:
            apt.os.write = original_write
            os.close(pinned_manifest)
            os.close(pinned_parent)
        expired_marker = private / "expired.ok"
        (
            pinned_parent,
            pinned_manifest,
            _,
            _,
            _,
        ) = apt.open_private_manifest(manifest_path, expired_marker)
        original_link = apt.os.link
        original_monotonic = apt.time.monotonic
        deadline_clock = [0.0]

        def expire_after_link(*arguments, **kwargs):
            result = original_link(*arguments, **kwargs)
            deadline_clock[0] = 301.0
            return result

        apt.os.link = expire_after_link
        apt.time.monotonic = lambda: deadline_clock[0]
        try:
            require_rejected(
                apt,
                lambda: apt.write_hook_marker(
                    pinned_parent,
                    expired_marker,
                    hashlib.sha256(cli_manifest_raw).hexdigest(),
                    deadline=300.0,
                ),
                "marker promotion after the hook deadline",
                "APT hook verification exceeded its deadline",
                exact=True,
            )
            if expired_marker.exists() or (private / ".expired.ok.tmp").exists():
                raise SystemExit("expired APT hook marker left a visible inode")
        finally:
            apt.time.monotonic = original_monotonic
            apt.os.link = original_link
            os.close(pinned_manifest)
            os.close(pinned_parent)
        verify_marker_cleanup_evidence(
            apt,
            private,
            hashlib.sha256(cli_manifest_raw).hexdigest(),
        )
        original_marker_writer = apt.write_hook_marker
        original_monotonic = apt.time.monotonic
        original_stat = apt.os.stat
        original_unlink = apt.os.unlink
        original_fsync = apt.os.fsync
        original_fstat = apt.os.fstat
        original_dup = apt.os.dup
        original_close = apt.os.close
        successful_ownership: list[int] = []

        transfer_marker = private / "ownership-transfer-cancel.ok"
        transfer_cancel = KeyboardInterrupt(
            "injected marker ownership-transfer cancellation"
        )
        transfer_descriptors: list[int] = []
        original_accept = apt.PublicationOwnershipSlot.accept

        def accept_then_cancel(self, ownership) -> None:
            original_accept(self, ownership)
            if ownership.parent_descriptor is not None:
                raise SystemExit(
                    "APT marker transfer fixture unexpectedly retained a parent"
                )
            transfer_descriptors.append(ownership.descriptor)
            raise transfer_cancel

        apt.PublicationOwnershipSlot.accept = accept_then_cancel
        try:
            transfer_caught, transfer_output = run_hook_main(
                apt,
                eipp_path,
                [
                    "--verify-hook-disposable",
                    str(admin),
                    "0",
                    "0",
                    str(manifest_path),
                    str(transfer_marker),
                ],
            )
        finally:
            apt.PublicationOwnershipSlot.accept = original_accept
        if transfer_caught is not transfer_cancel:
            raise SystemExit(
                "APT marker transfer cleanup replaced cancellation: "
                f"{transfer_caught!r}"
            ) from transfer_caught
        if transfer_output:
            raise SystemExit("APT marker transfer cancellation printed PASS")
        if len(transfer_descriptors) != 1:
            raise SystemExit("APT marker transfer fixture missed ownership")
        try:
            original_fstat(transfer_descriptors[0])
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise SystemExit(
                "APT marker transfer cancellation leaked its publication descriptor"
            )
        if transfer_marker.exists() or (
            private / f".{transfer_marker.name}.tmp"
        ).exists():
            raise SystemExit(
                "APT marker transfer cancellation left a publication inode"
            )

        return_cancel_marker = private / "ownership-return-cancel.ok"
        return_cancel = KeyboardInterrupt("injected marker post-return cancellation")
        return_descriptors: list[int] = []

        def return_then_cancel(*args, **kwargs):
            result = original_marker_writer(*args, **kwargs)
            slot = kwargs.get("ownership_slot")
            if (
                result is None
                or type(slot) is not apt.PublicationOwnershipSlot
                or slot.ownership is not result
                or result.parent_descriptor is not None
            ):
                raise SystemExit(
                    "APT marker return fixture lost transferred ownership"
                )
            return_descriptors.append(result.descriptor)
            raise return_cancel

        apt.write_hook_marker = return_then_cancel
        try:
            return_caught, return_output = run_hook_main(
                apt,
                eipp_path,
                [
                    "--verify-hook-disposable",
                    str(admin),
                    "0",
                    "0",
                    str(manifest_path),
                    str(return_cancel_marker),
                ],
            )
        finally:
            apt.write_hook_marker = original_marker_writer
        if return_caught is not return_cancel:
            raise SystemExit(
                "APT marker post-return cleanup replaced cancellation: "
                f"{return_caught!r}"
            ) from return_caught
        if return_output:
            raise SystemExit("APT marker post-return cancellation printed PASS")
        if len(return_descriptors) != 1:
            raise SystemExit("APT marker return fixture missed ownership")
        try:
            original_fstat(return_descriptors[0])
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise SystemExit(
                "APT marker post-return cancellation leaked its descriptor"
            )
        if return_cancel_marker.exists() or (
            private / f".{return_cancel_marker.name}.tmp"
        ).exists():
            raise SystemExit(
                "APT marker post-return cancellation left a publication inode"
            )

        def recording_marker_writer(*args, **kwargs):
            result = original_marker_writer(*args, **kwargs)
            if result is None or result.parent_descriptor is not None:
                raise SystemExit(
                    "APT hook main did not retain successful marker ownership"
                )
            successful_ownership.append(result.descriptor)
            return result

        apt.write_hook_marker = recording_marker_writer
        try:
            caught, output = run_hook_main(
                apt,
                eipp_path,
                [
                    "--verify-hook-disposable",
                    str(admin),
                    "0",
                    "0",
                    str(manifest_path),
                    str(marker_path),
                ],
            )
        finally:
            apt.write_hook_marker = original_marker_writer
        if caught is not None or output != "HAPTICS_APT_HOOK=PASS\n":
            raise SystemExit(
                "APT hook in-process success route changed: "
                f"failure={caught} output={output!r}"
            ) from caught
        for descriptor in successful_ownership:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise SystemExit(
                    "APT hook main leaked successful marker ownership"
                )
        marker_path.unlink()
        outer_cases = (
            ("clean", ()),
            (
                "unlink-failure",
                (
                    "APT hook marker cleanup could not remove published marker",
                    "APT hook marker cleanup left the published marker inode present",
                ),
            ),
            (
                "namespace-replacement",
                (
                    "APT hook marker cleanup found the published marker namespace changed",
                ),
            ),
            (
                "directory-fsync",
                (
                    "APT hook marker cleanup could not synchronize marker directory",
                ),
            ),
            (
                "published-recheck",
                (
                    "APT hook marker cleanup could not confirm published marker removal",
                ),
            ),
            (
                "ownership-fstat",
                (
                    "APT hook marker cleanup could not inspect owned publication inode",
                    "APT hook marker cleanup left the published marker inode present",
                    "APT hook marker cleanup could not close publication descriptor",
                ),
            ),
            (
                "publication-close",
                (
                    "APT hook marker cleanup could not close publication descriptor",
                ),
            ),
        )
        for case, expected_notes in outer_cases:
            outer_return_clock = [0.0]
            stat_calls = 0
            owned_descriptors: list[int] = []
            replacement_raw = b"unrelated marker namespace\n"

            def hostile_stat(path, *args, **kwargs):
                nonlocal stat_calls
                if (
                    case == "published-recheck"
                    and os.fspath(path) == marker_path.name
                    and kwargs.get("dir_fd") is not None
                ):
                    stat_calls += 1
                    if stat_calls == 2:
                        raise OSError("injected outer marker recheck failure")
                return original_stat(path, *args, **kwargs)

            def hostile_unlink(path, *args, **kwargs):
                if (
                    case == "unlink-failure"
                    and os.fspath(path) == marker_path.name
                    and kwargs.get("dir_fd") is not None
                ):
                    raise OSError("injected outer marker unlink failure")
                return original_unlink(path, *args, **kwargs)

            def hostile_fsync(descriptor: int) -> None:
                del descriptor
                raise OSError("injected outer marker fsync failure")

            def hostile_fstat(descriptor: int):
                if (
                    case == "ownership-fstat"
                    and owned_descriptors
                    and descriptor == owned_descriptors[0]
                ):
                    raise OSError("injected outer marker ownership failure")
                return original_fstat(descriptor)

            def hostile_close(descriptor: int) -> None:
                original_close(descriptor)
                if descriptor == owned_descriptors[0]:
                    raise OSError("injected outer marker close failure")

            def returning_then_expiring_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT hook main did not retain marker publication ownership"
                    )
                owned_descriptors.append(result.descriptor)
                if case == "namespace-replacement":
                    original_unlink(marker_path)
                    marker_path.write_bytes(replacement_raw)
                    marker_path.chmod(0o600)
                elif case == "unlink-failure":
                    apt.os.unlink = hostile_unlink
                elif case == "directory-fsync":
                    apt.os.fsync = hostile_fsync
                elif case == "published-recheck":
                    apt.os.stat = hostile_stat
                elif case == "ownership-fstat":
                    apt.os.fstat = hostile_fstat
                elif case == "publication-close":
                    apt.os.close = hostile_close
                outer_return_clock[0] = apt.HOOK_VERIFICATION_TIMEOUT_SECONDS
                return result

            apt.write_hook_marker = returning_then_expiring_marker
            apt.time.monotonic = lambda: outer_return_clock[0]
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
                expected_failure = (
                    "haptics APT hook verification failed: "
                    "APT hook verification exceeded its deadline"
                )
                expected_failure += "".join(
                    "\nhaptics APT hook verification failed cleanup: " + note
                    for note in expected_notes
                )
                if caught is None or str(caught) != expected_failure:
                    raise SystemExit(
                        "APT hook main did not reject expiry after marker writer return: "
                        f"{case}: {caught}"
                    ) from caught
                if output:
                    raise SystemExit(
                        "APT hook main printed PASS after marker writer return expiry"
                    )
                primary = caught.__cause__
                if (
                    not isinstance(primary, apt.AptTransactionError)
                    or str(primary) != "APT hook verification exceeded its deadline"
                ):
                    raise SystemExit(
                        "APT hook outer cleanup replaced the deadline primary: "
                        f"{case}: {primary}"
                    ) from caught
                notes = tuple(getattr(primary, "__notes__", ()))
                if notes != expected_notes or any(
                    "injected" in note for note in notes
                ):
                    raise SystemExit(
                        "APT hook outer cleanup evidence drifted: "
                        f"{case}: expected={expected_notes!r} actual={notes!r}"
                    ) from caught
                for descriptor in owned_descriptors:
                    try:
                        original_fstat(descriptor)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise
                    else:
                        raise SystemExit(
                            "APT hook main leaked marker publication ownership"
                        )
                if case == "namespace-replacement":
                    if (
                        not marker_path.exists()
                        or marker_path.read_bytes() != replacement_raw
                    ):
                        raise SystemExit(
                            "APT hook outer cleanup removed a replacement namespace"
                        )
                elif case in {"unlink-failure", "ownership-fstat"}:
                    if not marker_path.exists():
                        raise SystemExit(
                            "APT hook unlink-failure fixture lost its owned inode"
                        )
                elif marker_path.exists():
                    raise SystemExit(
                        "APT hook retained the marker after its writer returned: "
                        f"{case}"
                    )
            finally:
                apt.os.stat = original_stat
                apt.os.unlink = original_unlink
                apt.os.fsync = original_fsync
                apt.os.fstat = original_fstat
                apt.os.close = original_close
                apt.time.monotonic = original_monotonic
                apt.write_hook_marker = original_marker_writer
                try:
                    original_unlink(marker_path)
                except FileNotFoundError:
                    pass

        replacement_raw = b"unrelated release-close marker namespace\n"
        for case in ("release-close", "release-close-replacement"):
            owned_descriptors: list[int] = []

            def close_owned_publication_then_fail(descriptor: int) -> None:
                original_close(descriptor)
                if owned_descriptors and descriptor == owned_descriptors[0]:
                    raise OSError("injected marker release close failure")

            def returning_release_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT marker release-close fixture lost publication ownership"
                    )
                owned_descriptors.append(result.descriptor)
                if case.endswith("replacement"):
                    original_unlink(marker_path)
                    marker_path.write_bytes(replacement_raw)
                    marker_path.chmod(0o600)
                apt.os.close = close_owned_publication_then_fail
                return result

            apt.write_hook_marker = returning_release_marker
            caught: SystemExit | None = None
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
            finally:
                apt.os.close = original_close
                apt.write_hook_marker = original_marker_writer
            expected_notes = (
                "APT hook marker cleanup could not close publication descriptor",
            ) + (
                (
                    "APT hook marker cleanup found the published marker namespace "
                    "changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected = (
                "haptics APT hook verification failed: cannot release "
                "APT hook marker ownership"
                + "".join(
                    "\nhaptics APT hook verification failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None or str(caught) != expected or output:
                raise SystemExit(
                    f"APT marker release-close rollback drifted: {case}: {caught}"
                ) from caught
            primary = caught.__cause__
            if (
                not isinstance(primary, apt.AptTransactionError)
                or str(primary) != "cannot release APT hook marker ownership"
                or tuple(getattr(primary, "__notes__", ())) != expected_notes
            ):
                raise SystemExit(
                    f"APT marker release-close primary drifted: {case}: {primary}"
                ) from caught
            for descriptor in owned_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT marker release-close fixture leaked original ownership"
                    )
            if case.endswith("replacement"):
                if (
                    not marker_path.exists()
                    or marker_path.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT marker release-close rollback removed replacement namespace"
                    )
                original_unlink(marker_path)
            elif marker_path.exists():
                raise SystemExit(
                    "APT marker release-close rollback left its published inode"
                )

        for case in (
            "publication-guard-close",
            "publication-guard-close-replacement",
            "parent-guard-close",
            "parent-guard-close-replacement",
        ):
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []

            def track_rollback_dup(descriptor: int) -> int:
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def close_rollback_guard_then_fail(descriptor: int) -> None:
                original_close(descriptor)
                target_index = 1 if case.startswith("parent") else 0
                if (
                    len(duplicated_descriptors) > target_index
                    and descriptor == duplicated_descriptors[target_index]
                ):
                    raise OSError("injected marker rollback guard close failure")

            def returning_guard_close_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT marker guard-close fixture lost publication ownership"
                    )
                owned_descriptors.append(result.descriptor)
                if case.endswith("replacement"):
                    original_unlink(marker_path)
                    marker_path.write_bytes(replacement_raw)
                    marker_path.chmod(0o600)
                apt.os.dup = track_rollback_dup
                apt.os.close = close_rollback_guard_then_fail
                return result

            apt.write_hook_marker = returning_guard_close_marker
            caught: SystemExit | None = None
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
            finally:
                apt.os.dup = original_dup
                apt.os.close = original_close
                apt.write_hook_marker = original_marker_writer
            close_role = "parent directory" if case.startswith("parent") else "publication"
            expected_notes = (
                f"APT hook marker cleanup could not close {close_role} descriptor",
            ) + (
                (
                    "APT hook marker cleanup found the published marker namespace "
                    "changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected = (
                "haptics APT hook verification failed: cannot release "
                "APT hook marker ownership"
                + "".join(
                    "\nhaptics APT hook verification failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None or str(caught) != expected or output:
                raise SystemExit(
                    f"APT marker rollback-guard close drifted: {case}: {caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT marker rollback-guard fixture leaked a descriptor"
                    )
            if case.endswith("replacement"):
                if (
                    not marker_path.exists()
                    or marker_path.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT marker rollback-guard cleanup removed replacement namespace"
                    )
                original_unlink(marker_path)
            elif marker_path.exists():
                raise SystemExit(
                    "APT marker rollback-guard cleanup left its published inode"
                )

        for case in (
            "cleanup-publication-close",
            "cleanup-parent-close",
            "terminal-parent-close",
        ):
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []

            def track_cleanup_dup(descriptor: int) -> int:
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def close_final_cleanup_then_fail(descriptor: int) -> None:
                original_close(descriptor)
                target_index = (
                    4
                    if case.startswith("terminal-parent")
                    else 3
                    if case.startswith("cleanup-parent")
                    else 2
                )
                if (
                    len(duplicated_descriptors) > target_index
                    and descriptor == duplicated_descriptors[target_index]
                ):
                    raise OSError("injected final marker cleanup close failure")

            def returning_cleanup_close_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT marker cleanup-close fixture lost publication ownership"
                    )
                owned_descriptors.append(result.descriptor)
                apt.os.dup = track_cleanup_dup
                apt.os.close = close_final_cleanup_then_fail
                return result

            apt.write_hook_marker = returning_cleanup_close_marker
            caught: SystemExit | None = None
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
            finally:
                apt.os.dup = original_dup
                apt.os.close = original_close
                apt.write_hook_marker = original_marker_writer
            close_role = "parent directory" if "parent" in case else "publication"
            expected_note = (
                f"APT hook marker cleanup could not close {close_role} descriptor"
            )
            expected = (
                "haptics APT hook verification failed: cannot release "
                "APT hook marker ownership\n"
                "haptics APT hook verification failed cleanup: "
                + expected_note
            )
            if caught is None or str(caught) != expected or output:
                raise SystemExit(
                    f"APT final marker cleanup-close semantics drifted: {case}: {caught}"
                ) from caught
            primary = caught.__cause__
            if (
                not isinstance(primary, apt.AptTransactionError)
                or str(primary) != "cannot release APT hook marker ownership"
                or expected_note not in tuple(getattr(primary, "__notes__", ()))
            ):
                raise SystemExit(
                    f"APT final marker cleanup-close primary drifted: {case}: {primary}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT final marker cleanup-close fixture leaked a descriptor"
                    )
            if marker_path.exists():
                raise SystemExit(
                    "APT final marker cleanup-close rollback left its published inode"
                )

        for case in (
            "cleanup-publication-cancel",
            "cleanup-parent-cancel",
            "terminal-parent-cancel",
        ):
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []
            cancellation = KeyboardInterrupt(
                f"injected final marker {case} cancellation"
            )

            def track_cleanup_dup(descriptor: int) -> int:
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def cancel_final_cleanup_close(descriptor: int) -> None:
                original_close(descriptor)
                target_index = (
                    4
                    if case.startswith("terminal-parent")
                    else 3
                    if case.startswith("cleanup-parent")
                    else 2
                )
                if (
                    len(duplicated_descriptors) > target_index
                    and descriptor == duplicated_descriptors[target_index]
                ):
                    raise cancellation

            def returning_cleanup_cancel_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT marker cleanup-cancellation fixture lost publication ownership"
                    )
                owned_descriptors.append(result.descriptor)
                apt.os.dup = track_cleanup_dup
                apt.os.close = cancel_final_cleanup_close
                return result

            apt.write_hook_marker = returning_cleanup_cancel_marker
            caught: BaseException | None = None
            output = ""
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
            finally:
                apt.os.dup = original_dup
                apt.os.close = original_close
                apt.write_hook_marker = original_marker_writer
            close_role = "parent directory" if "parent" in case else "publication"
            expected_note = (
                f"APT hook marker cleanup could not close {close_role} descriptor"
            )
            if (
                caught is not cancellation
                or output
                or expected_note not in tuple(getattr(caught, "__notes__", ()))
            ):
                raise SystemExit(
                    f"APT final marker cleanup cancellation drifted: {case}: {caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT final marker cleanup cancellation leaked a descriptor"
                    )
            if marker_path.exists():
                raise SystemExit(
                    "APT final marker cleanup cancellation left its published inode"
                )

        for case in (
            "publication-dup",
            "publication-dup-replacement",
            "parent-dup",
            "parent-dup-replacement",
            "cleanup-publication-dup",
            "cleanup-publication-dup-replacement",
            "cleanup-parent-dup",
            "cleanup-parent-dup-replacement",
        ):
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []
            dup_calls = 0

            def fail_selected_rollback_dup(descriptor: int) -> int:
                nonlocal dup_calls
                dup_calls += 1
                base_case = case.removesuffix("-replacement")
                target_call = {
                    "publication-dup": 1,
                    "parent-dup": 2,
                    "cleanup-publication-dup": 3,
                    "cleanup-parent-dup": 4,
                }[base_case]
                if dup_calls == target_call:
                    raise OSError("injected marker rollback dup failure")
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def returning_dup_failure_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT marker dup-failure fixture lost publication ownership"
                    )
                owned_descriptors.append(result.descriptor)
                if case.endswith("replacement"):
                    original_unlink(marker_path)
                    marker_path.write_bytes(replacement_raw)
                    marker_path.chmod(0o600)
                apt.os.dup = fail_selected_rollback_dup
                return result

            apt.write_hook_marker = returning_dup_failure_marker
            caught: SystemExit | None = None
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
            finally:
                apt.os.dup = original_dup
                apt.write_hook_marker = original_marker_writer
            expected_notes = (
                (
                    "APT hook marker cleanup found the published marker namespace "
                    "changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected = (
                "haptics APT hook verification failed: cannot preserve "
                "APT hook marker release rollback ownership"
                + "".join(
                    "\nhaptics APT hook verification failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None or str(caught) != expected or output:
                raise SystemExit(
                    f"APT marker rollback-dup cleanup drifted: {case}: {caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT marker rollback-dup fixture leaked a descriptor"
                    )
            if case.endswith("replacement"):
                if (
                    not marker_path.exists()
                    or marker_path.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT marker rollback-dup cleanup removed replacement namespace"
                    )
                original_unlink(marker_path)
            elif marker_path.exists():
                raise SystemExit(
                    "APT marker rollback-dup cleanup left its published inode"
                )

        for target_call in range(1, 6):
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []
            dup_calls = 0
            recovery_fstat_calls = 0
            target_descriptor: int | None = None
            cancellation = KeyboardInterrupt(
                f"injected applied marker dup {target_call} cancellation"
            )
            descriptors_before = apt.snapshot_live_descriptors(
                "applied marker dup fixture baseline"
            )
            private_before = frozenset(path.name for path in private.iterdir())
            children_path = pathlib.Path(
                f"/proc/self/task/{os.getpid()}/children"
            )
            children_before = frozenset(
                int(raw, 10)
                for raw in children_path.read_text(encoding="ascii").split()
            )

            def duplicate_then_cancel(descriptor: int) -> int:
                nonlocal dup_calls, target_descriptor
                dup_calls += 1
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                if dup_calls == target_call:
                    target_descriptor = duplicated
                    raise cancellation
                return duplicated

            def fail_target_recovery_fstat_once(descriptor: int):
                nonlocal recovery_fstat_calls
                if descriptor == target_descriptor and not recovery_fstat_calls:
                    recovery_fstat_calls += 1
                    raise OSError(
                        errno.EIO,
                        "injected applied marker duplicate recovery fstat failure",
                    )
                return original_fstat(descriptor)

            def returning_applied_dup_marker(*args, **kwargs):
                result = original_marker_writer(*args, **kwargs)
                if result is None or result.parent_descriptor is not None:
                    raise SystemExit(
                        "APT marker applied-dup fixture lost publication ownership"
                )
                owned_descriptors.append(result.descriptor)
                apt.os.dup = duplicate_then_cancel
                apt.os.fstat = fail_target_recovery_fstat_once
                return result

            apt.write_hook_marker = returning_applied_dup_marker
            caught: BaseException | None = None
            output = ""
            try:
                caught, output = run_hook_main(
                    apt,
                    eipp_path,
                    [
                        "--verify-hook-disposable",
                        str(admin),
                        "0",
                        "0",
                        str(manifest_path),
                        str(marker_path),
                    ],
                )
            finally:
                apt.os.dup = original_dup
                apt.os.fstat = original_fstat
                apt.write_hook_marker = original_marker_writer
            if (
                caught is not cancellation
                or output
                or dup_calls != target_call
                or recovery_fstat_calls != 1
            ):
                raise SystemExit(
                    "APT marker applied-dup cancellation drifted: "
                    f"call={target_call} fstat={recovery_fstat_calls} caught={caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT marker applied-dup fixture leaked a descriptor"
                    )
            descriptors_after = apt.snapshot_live_descriptors(
                "applied marker dup fixture terminal"
            )
            private_after = frozenset(path.name for path in private.iterdir())
            children_after = frozenset(
                int(raw, 10)
                for raw in children_path.read_text(encoding="ascii").split()
            )
            if descriptors_after != descriptors_before:
                raise SystemExit(
                    "APT marker applied-dup fixture changed the live descriptor set"
                )
            if private_after != private_before:
                raise SystemExit(
                    "APT marker applied-dup fixture left private-path residue"
                )
            if children_after != children_before:
                raise SystemExit(
                    "APT marker applied-dup fixture left process residue"
                )
            if marker_path.exists() or (
                private / f".{marker_path.name}.tmp"
            ).exists():
                raise SystemExit(
                    "APT marker applied-dup rollback left its published inode"
                )
        killed_marker = private / "killed.ok"
        partial_marker_digest = hashlib.sha256(cli_manifest_raw).hexdigest()
        prove_partial_marker_signal_handoff(
            apt,
            manifest_path,
            private,
            partial_marker_digest,
        )
        prove_partial_marker_child_custody(
            apt,
            manifest_path,
            private,
            partial_marker_digest,
        )
        run_partial_marker_kill_fixture(
            apt,
            manifest_path,
            killed_marker,
            partial_marker_digest,
        )
        result = run_hook_cli(
            eipp_path,
            [
                "--verify-hook-disposable",
                str(admin),
                "0",
                "0",
                str(manifest_path),
                str(marker_path),
            ],
        )
        if result.returncode:
            raise SystemExit(
                "production APT hook CLI failed: "
                + result.stderr[:8192].decode("utf-8", errors="replace")
            )
        expected_marker = (hashlib.sha256(cli_manifest_raw).hexdigest() + "\n").encode(
            "ascii"
        )
        marker_metadata = marker_path.stat()
        if (
            result.stdout != b"HAPTICS_APT_HOOK=PASS\n"
            or marker_path.read_bytes() != expected_marker
            or not stat.S_ISREG(marker_metadata.st_mode)
            or stat.S_IMODE(marker_metadata.st_mode) != 0o600
            or marker_metadata.st_uid != 0
            or marker_metadata.st_gid != 0
            or marker_metadata.st_nlink != 1
        ):
            raise SystemExit("production APT hook marker contract changed")
        cli_arguments = [
            "--verify-hook-disposable",
            str(admin),
            "0",
            "0",
            str(manifest_path),
            str(marker_path),
        ]
        require_cli_rejected(
            eipp_path,
            cli_arguments,
            marker_path,
            "pre-existing success marker",
            b"File exists",
        )
        marker_path.unlink()

        manifest_path.chmod(0o644)
        try:
            require_cli_rejected(
                eipp_path,
                cli_arguments,
                marker_path,
                "world-readable manifest",
                b"manifest metadata differs from policy",
            )
        finally:
            manifest_path.chmod(0o600)

        saved_manifest = private / "expected.saved"
        manifest_path.rename(saved_manifest)
        manifest_path.symlink_to(saved_manifest.name)
        try:
            require_cli_rejected(
                eipp_path,
                cli_arguments,
                marker_path,
                "manifest symlink",
                b"Too many levels of symbolic links",
            )
        finally:
            manifest_path.unlink()
            saved_manifest.rename(manifest_path)

        private.chmod(0o755)
        try:
            require_cli_rejected(
                eipp_path,
                cli_arguments,
                marker_path,
                "non-private manifest directory",
                b"private directory metadata differs from policy",
            )
        finally:
            private.chmod(0o700)

        state_drift_transaction = apt.ExpectedTransaction(
            cli_transaction.package_state_sha256,
            "0" * 64,
            cli_transaction.host_reference_sha256,
            cli_transaction.configuration,
            cli_transaction.actions,
            cli_transaction.archives,
        )
        write_file(
            manifest_path,
            apt.serialize_expected_transaction(state_drift_transaction),
            0o600,
        )
        require_cli_rejected(
            eipp_path,
            cli_arguments,
            marker_path,
            "dpkg state digest drift",
            b"dpkg state differs from the expected transaction",
        )

        host_drift_transaction = apt.ExpectedTransaction(
            cli_transaction.package_state_sha256,
            cli_transaction.dpkg_state_sha256,
            "0" * 64,
            cli_transaction.configuration,
            cli_transaction.actions,
            cli_transaction.archives,
        )
        write_file(
            manifest_path,
            apt.serialize_expected_transaction(host_drift_transaction),
            0o600,
        )
        require_cli_rejected(
            eipp_path,
            cli_arguments,
            marker_path,
            "dpkg host-reference digest drift",
            b"dpkg host reference differs from the expected transaction",
        )
        write_file(manifest_path, cli_manifest_raw, 0o600)

        write_file(
            eipp_path,
            cli_eipp_raw.replace(b"InfoFD=21", b"InfoFD=22", 1),
            0o600,
        )
        require_cli_rejected(
            eipp_path,
            cli_arguments,
            marker_path,
            "effective APT configuration drift",
            b"effective APT configuration differs",
        )

        write_file(
            eipp_path,
            cli_eipp_raw.replace(b"1.0-1 amd64 none", b"1.0-1 arm64 none", 1),
            0o600,
        )
        require_cli_rejected(
            eipp_path,
            cli_arguments,
            marker_path,
            "EIPP action drift",
            b"EIPP actions differ from the exact transaction closure",
        )
        write_file(eipp_path, cli_eipp_raw, 0o600)

        archive_raw = archive.read_bytes()
        archive.write_bytes(archive_raw + b"drift")
        archive.chmod(0o644)
        try:
            require_cli_rejected(
                eipp_path,
                cli_arguments,
                marker_path,
                "archive byte drift",
                b"APT archive identity differs from the manifest",
            )
        finally:
            archive.write_bytes(archive_raw)
            archive.chmod(0o644)

        root.chmod(0o700)
        try:
            require_cli_rejected(
                eipp_path,
                cli_arguments,
                marker_path,
                "archive unreadable by _apt",
                b"_apt could not open and hash the verified archive inode",
            )
        finally:
            root.chmod(0o755)

        native_manifest_path = private / "native-expected.tsv"
        native_marker_path = private / "native-hook.ok"
        native_eipp_path = private / "native-eipp.raw"
        native_hook_command = (
            f"/usr/bin/python3 -I -B {APT_MODULE_PATH} --verify-hook "
            f"{native_manifest_path} {native_marker_path}"
        )
        encoded_native_hook = native_hook_command.replace(" ", "%20")
        native_eipp_raw = (
            "VERSION 3\n"
            "APT::Architecture=amd64\n"
            "APT::Architectures::=amd64\n"
            "Dir::Bin::dpkg=/usr/bin/dpkg\n"
            "DPkg::ConfigurePending=1\n"
            "DPkg::Path=/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"DPkg::Pre-Install-Pkgs::={encoded_native_hook}\n"
            "DPkg::Run-Directory=/\n"
            f"DPkg::Tools::options::{encoded_native_hook}::InfoFD=21\n"
            f"DPkg::Tools::options::{encoded_native_hook}::Version=3\n"
            "\n"
            f"example - - none < 1.0-1 amd64 none {archive}\n"
            "example - - none < 1.0-1 amd64 none **CONFIGURE**\n"
        ).encode("ascii")
        native_document = apt.parse_eipp_v3_bytes(native_eipp_raw)
        native_dpkg_state = dpkg.capture_dpkg_state(
            pathlib.Path("/var/lib/dpkg"), 0, 0
        )
        native_transaction = apt.ExpectedTransaction(
            hashlib.sha256(package_state_raw).hexdigest(),
            hashlib.sha256(
                dpkg.serialize_dpkg_state(native_dpkg_state)
            ).hexdigest(),
            hashlib.sha256(
                dpkg.serialize_host_reference(
                    dpkg.host_reference_from_state(native_dpkg_state)
                )
            ).hexdigest(),
            native_document.configuration,
            native_document.actions,
            (archive_record,),
        )
        native_manifest_raw = apt.serialize_expected_transaction(native_transaction)
        write_file(native_manifest_path, native_manifest_raw, 0o600)
        write_file(native_eipp_path, native_eipp_raw, 0o600)
        native_result = run_hook_cli(
            native_eipp_path,
            [
                "--verify-hook",
                str(native_manifest_path),
                str(native_marker_path),
            ],
        )
        native_marker_metadata = native_marker_path.stat()
        if (
            native_result.returncode
            or native_result.stdout != b"HAPTICS_APT_HOOK=PASS\n"
            or native_result.stderr
            or native_marker_path.read_bytes()
            != (hashlib.sha256(native_manifest_raw).hexdigest() + "\n").encode(
                "ascii"
            )
            or stat.S_IMODE(native_marker_metadata.st_mode) != 0o600
            or native_marker_metadata.st_uid != 0
            or native_marker_metadata.st_gid != 0
            or native_marker_metadata.st_nlink != 1
        ):
            raise SystemExit(
                "production native APT hook fixture failed: "
                + native_result.stderr[:8192].decode("utf-8", errors="replace")
            )
        if not hasattr(apt, "verify_hook_marker"):
            raise SystemExit("APT hook marker verification interface is missing")
        if apt.verify_hook_marker(native_manifest_path, native_marker_path) != hashlib.sha256(
            native_manifest_raw
        ).hexdigest():
            raise SystemExit("APT hook marker verifier returned the wrong digest")
        marker_cli = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(APT_MODULE_PATH),
                "--verify-marker",
                str(native_manifest_path),
                str(native_marker_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": "/nonexistent",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        if (
            marker_cli.returncode
            or marker_cli.stdout != b"HAPTICS_APT_MARKER=PASS\n"
            or marker_cli.stderr
        ):
            raise SystemExit(
                "APT hook marker CLI failed: "
                + marker_cli.stderr[:8192].decode("utf-8", errors="replace")
            )
        native_marker_path.chmod(0o644)
        try:
            require_rejected(
                apt,
                lambda: apt.verify_hook_marker(
                    native_manifest_path, native_marker_path
                ),
                "post-hook marker mode drift",
                "APT hook marker metadata differs from policy",
            )
        finally:
            native_marker_path.chmod(0o600)
    native_after = hashlib.sha256(native_status.read_bytes()).hexdigest()
    if native_after != native_before:
        raise SystemExit("APT hook fixture changed native dpkg status")
    print("HAPTICS_APT_HOOK_FIXTURE=PASS")


if __name__ == "__main__":
    try:
        main()
    except FixtureCleanupError as exc:
        raise SystemExit(str(exc)) from exc
