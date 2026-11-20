#!/usr/bin/env python3
"""Run one APT phase with bounded output and Linux process custody."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import ctypes
from dataclasses import dataclass, field
import errno
import hashlib
import math
import os
import pathlib
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import time


OUTPUT_LIMIT = 8 * 1024 * 1024
EXCERPT_LIMIT = 16 * 1024
READ_SIZE = 64 * 1024
POLL_SECONDS = 0.05
TERM_GRACE_SECONDS = 2.0
CLEANUP_GRACE_SECONDS = 3.0
MAX_DIRECT_CHILDREN = 4096
MAX_FAILURES = 8
MAX_IO_INTERRUPTS = 64
MAX_PENDING_SIGNAL_DRAIN = 64
PUBLIC_DIAGNOSTIC_LIMIT = 384 * 1024
PUBLIC_WRITE_SECONDS = 0.25
PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
LIBC = ctypes.CDLL(None, use_errno=True)
PHASE = re.compile(r"[a-z][a-z0-9-]{0,31}")
OUTPUT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SANDBOX_WARNINGS = (
    b"Download is performed unsandboxed as root",
    b"couldn't be accessed by user '_apt'",
)
CAUSE_TOKENS = (
    b"E:",
    b"Err:",
    b"Failed to fetch",
    b"Could not",
    b"HTTP/",
    *SANDBOX_WARNINGS,
)
HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
EXEC_GATE_TOKEN = b"G"
EXEC_GATE_ERROR_LIMIT = 64
EXEC_GATE_HANDSHAKE_SECONDS = 2.0
CUSTODY_OK = b"O"
CUSTODY_DESCENDANT = b"D"
CUSTODY_FAILURE = b"F"
CUSTODIAN_TERM_GRACE_SECONDS = 1.5
CUSTODIAN_FINAL_REAP_SECONDS = 0.5
CGROUP_ROOT = pathlib.Path("/sys/fs/cgroup")
CGROUP_NAME = re.compile(
    r"tb321fu-haptics-apt-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*"
)
CGROUP_IDENTITY = re.compile(
    r"(?:0|[1-9][0-9]{0,19}):(?:0|[1-9][0-9]{0,19})"
)
CGROUP_CONTROL_LIMIT = 4096


class PhaseError(Exception):
    """A fixed-domain phase-runner failure."""


@dataclass
class SignalLatch:
    signum: int | None = None

    def handler(self, signum: int, _frame: object) -> None:
        if self.signum is None:
            self.signum = signum


@dataclass
class FailureLedger:
    entries: list[BaseException] = field(default_factory=list)
    omitted: int = 0

    def add(self, failure: BaseException) -> None:
        if len(self.entries) < MAX_FAILURES:
            self.entries.append(failure)
        else:
            self.omitted += 1

    def __bool__(self) -> bool:
        return bool(self.entries or self.omitted)


@dataclass
class StreamEvidence:
    private_root: bytes
    size: int = 0
    lines: int = 0
    digest: object = field(default_factory=hashlib.sha256)
    head: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    scan_tail: bytes = b""
    sandbox_fallback: bool = False
    cause_scan_tail: bytes = b""
    first_cause: bytes | None = None

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.size += len(chunk)
        self.lines += chunk.count(b"\n")
        self.digest.update(chunk)
        remaining = EXCERPT_LIMIT - len(self.head)
        if remaining > 0:
            self.head.extend(chunk[:remaining])
        if len(chunk) >= EXCERPT_LIMIT:
            self.tail[:] = chunk[-EXCERPT_LIMIT:]
        else:
            self.tail.extend(chunk)
            if len(self.tail) > EXCERPT_LIMIT:
                del self.tail[:-EXCERPT_LIMIT]
        scan = self.scan_tail + chunk
        if any(needle in scan for needle in SANDBOX_WARNINGS):
            self.sandbox_fallback = True
        overlap = max(len(needle) for needle in SANDBOX_WARNINGS) - 1
        self.scan_tail = scan[-overlap:]
        if self.first_cause is None:
            cause_scan = self.cause_scan_tail + chunk
            positions = tuple(
                position
                for token in CAUSE_TOKENS
                if (position := cause_scan.find(token)) >= 0
            )
            if positions:
                position = min(positions)
                line_start = cause_scan.rfind(b"\n", 0, position) + 1
                start = max(line_start, position - 1024)
                line_end = cause_scan.find(b"\n", position)
                if line_end < 0:
                    line_end = len(cause_scan)
                self.first_cause = cause_scan[start:min(line_end, start + 4096)]
            self.cause_scan_tail = cause_scan[-4096:]

    def finish(self) -> None:
        self.cause_scan_tail = b""

    @property
    def sha256(self) -> str:
        return self.digest.hexdigest()

    def sanitized(self, raw: bytes) -> bytes:
        if self.private_root:
            raw = raw.replace(self.private_root, b"<PRIVATE_ROOT>")
            for length in range(len(self.private_root) - 1, 3, -1):
                raw = raw.replace(
                    self.private_root[:length], b"<PRIVATE_ROOT_FRAGMENT>"
                )
                raw = raw.replace(
                    self.private_root[-length:], b"<PRIVATE_ROOT_FRAGMENT>"
                )
            if len(raw) >= 4 and raw in self.private_root:
                raw = b"<PRIVATE_ROOT_FRAGMENT>"
        rendered = bytearray()
        at_line_start = True
        for index, byte in enumerate(raw):
            if byte == 0x0A:
                rendered.extend(b"\n")
                at_line_start = True
            elif at_line_start and raw[index:index + 2] == b"::":
                rendered.extend(b"\\x3a")
                at_line_start = False
            elif 0x20 <= byte <= 0x7E:
                rendered.append(byte)
                at_line_start = False
            else:
                rendered.extend(f"\\x{byte:02x}".encode("ascii"))
                at_line_start = False
        return bytes(rendered)


@dataclass
class OutputOwner:
    parent_fd: int
    descriptor: int
    parent: pathlib.Path
    parent_identity: tuple[int, int]
    name: str
    identity: tuple[int, int]
    written: int = 0
    overflow: bool = False


@dataclass
class ProcessOwner:
    process: subprocess.Popen[bytes] | None = None
    pidfd: int = -1
    custody_fd: int = -1
    commit_check: Callable[[], bool] | None = None
    command_committed: bool = False


def read_bounded_file(path: pathlib.Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(4096, limit + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise PhaseError("APT phase control file exceeded its bound")
    finally:
        os.close(descriptor)


def unified_cgroup_path(pid: int | str = "self") -> str:
    raw = read_bounded_file(pathlib.Path(f"/proc/{pid}/cgroup"), CGROUP_CONTROL_LIMIT)
    records = raw.rstrip(b"\n").split(b"\n")
    if len(records) != 1 or not records[0].startswith(b"0::"):
        raise PhaseError("APT phase requires a unified cgroup v2 hierarchy")
    relative = records[0][3:]
    if not relative.startswith(b"/") or b"\x00" in relative:
        raise PhaseError("APT phase cgroup membership is malformed")
    try:
        return relative.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PhaseError("APT phase cgroup membership is not ASCII") from exc


def read_cgroup_members(directory_fd: int) -> frozenset[int]:
    descriptor = os.open(
        "cgroup.procs",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        data = bytearray()
        while len(data) <= CGROUP_CONTROL_LIMIT:
            chunk = os.read(
                descriptor,
                min(4096, CGROUP_CONTROL_LIMIT + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > CGROUP_CONTROL_LIMIT:
            raise PhaseError("APT phase cgroup member set exceeded its bound")
    finally:
        os.close(descriptor)
    members: set[int] = set()
    for record in bytes(data).splitlines():
        if not record.isascii() or not record.isdigit() or record.startswith(b"0"):
            raise PhaseError("APT phase cgroup member set is malformed")
        members.add(int(record, 10))
    return frozenset(members)


def join_execution_cgroup(
    cgroup_text: str | None, cgroup_identity_text: str | None
) -> None:
    if cgroup_text is None and cgroup_identity_text is None:
        return
    if (
        not cgroup_text
        or not cgroup_identity_text
        or "\x00" in cgroup_text
        or len(cgroup_text) > 4096
        or len(cgroup_identity_text) > 41
        or not CGROUP_IDENTITY.fullmatch(cgroup_identity_text)
    ):
        raise PhaseError("APT phase cgroup path is invalid")
    expected_device, expected_inode = (
        int(field, 10) for field in cgroup_identity_text.split(":", 1)
    )
    target = pathlib.Path(cgroup_text)
    if not target.is_absolute() or not CGROUP_NAME.fullmatch(target.name):
        raise PhaseError("APT phase cgroup path is outside its naming contract")
    current_relative = unified_cgroup_path()
    current_parent = (
        CGROUP_ROOT
        if current_relative == "/"
        else CGROUP_ROOT / current_relative.removeprefix("/")
    )
    if target.parent != current_parent or target.resolve(strict=True) != target:
        raise PhaseError("APT phase cgroup is not a direct child of current custody")
    directory_fd = os.open(
        target,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        metadata = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (expected_device, expected_inode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_mode & 0o022
        ):
            raise PhaseError("APT phase cgroup ownership is invalid")
        if read_cgroup_members(directory_fd):
            raise PhaseError("APT phase cgroup was not empty before runner join")
        procs_fd = os.open(
            "cgroup.procs",
            os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            record = f"{os.getpid()}\n".encode("ascii")
            if os.write(procs_fd, record) != len(record):
                raise PhaseError("APT phase cgroup join was incomplete")
        finally:
            os.close(procs_fd)
        expected_relative = "/" + target.relative_to(CGROUP_ROOT).as_posix()
        if unified_cgroup_path() != expected_relative:
            raise PhaseError("APT phase runner did not enter its execution cgroup")
        if read_cgroup_members(directory_fd) != frozenset({os.getpid()}):
            raise PhaseError("APT phase execution cgroup membership is not exclusive")
    finally:
        os.close(directory_fd)


def open_descriptors() -> frozenset[int]:
    descriptors: set[int] = set()
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            if entry.name.isascii() and entry.name.isdigit():
                descriptors.add(int(entry.name, 10))
            if len(descriptors) > 4096:
                raise PhaseError("APT phase descriptor set exceeds its bound")
    for descriptor in tuple(descriptors):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                descriptors.discard(descriptor)
            else:
                raise
    return frozenset(descriptors)


def custodial_pidfd_open(pid: int) -> int:
    baseline = open_descriptors()
    try:
        return os.pidfd_open(pid, 0)
    except BaseException:
        try:
            leaked = open_descriptors() - baseline
        except BaseException:
            leaked = frozenset()
        for descriptor in leaked:
            if descriptor < 3:
                continue
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def recover_spawn_handoff(
    baseline_children: frozenset[int],
    baseline_descriptors: frozenset[int],
    root_pid: int | None,
) -> None:
    recovery_failures: list[BaseException] = []
    deadline = time.monotonic() + CLEANUP_GRACE_SECONDS
    root_group_signalled = False
    empty_rounds = 0
    while time.monotonic() < deadline and empty_rounds < 2:
        try:
            children = set(direct_children()) - set(baseline_children)
        except BaseException as exc:
            recovery_failures.append(exc)
            break
        if root_pid is not None and not root_group_signalled:
            try:
                signal_group(root_pid, signal.SIGKILL)
                root_group_signalled = True
            except BaseException as exc:
                recovery_failures.append(exc)
        if not children:
            empty_rounds += 1
            time.sleep(0.01)
            continue
        empty_rounds = 0
        for pid in children:
            if pid != root_pid:
                descriptor = -1
                try:
                    descriptor = custodial_pidfd_open(pid)
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                except BaseException as exc:
                    recovery_failures.append(exc)
                finally:
                    if descriptor >= 0:
                        try:
                            os.close(descriptor)
                        except OSError as exc:
                            recovery_failures.append(exc)
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            except InterruptedError:
                continue
            if waited == 0:
                continue
        time.sleep(0.01)
    try:
        remaining_children = set(direct_children()) - set(baseline_children)
    except BaseException as exc:
        remaining_children = set()
        recovery_failures.append(exc)
    if remaining_children:
        recovery_failures.append(
            PhaseError("APT phase spawn handoff left an owned process")
        )
    try:
        leaked_descriptors = open_descriptors() - baseline_descriptors
    except BaseException as exc:
        leaked_descriptors = frozenset()
        recovery_failures.append(exc)
    for descriptor in leaked_descriptors:
        if descriptor < 3:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                recovery_failures.append(exc)
    if recovery_failures:
        raise PhaseError("APT phase spawn handoff recovery did not converge")


def spawn_owned_process(
    owner: ProcessOwner,
    command: list[str],
    child_setup: object,
) -> None:
    baseline_children = frozenset(direct_children())
    baseline_descriptors = open_descriptors()
    process: subprocess.Popen[bytes] | None = None
    gate_read = -1
    gate_write = -1
    exec_status_read = -1
    exec_status_write = -1
    custody_read = -1
    custody_write = -1
    source_fd = -1
    try:
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        exec_status_read, exec_status_write = os.pipe2(os.O_CLOEXEC)
        custody_read, custody_write = os.pipe2(os.O_CLOEXEC)
        source_fd = open_authenticated_self()
        process = subprocess.Popen(
            [
                "/proc/self/exe",
                "-I",
                "-B",
                f"/proc/self/fd/{source_fd}",
                "--custodian",
                str(gate_read),
                str(exec_status_write),
                str(custody_write),
                str(os.getpid()),
                "--",
                *command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(gate_read, exec_status_write, custody_write, source_fd),
            start_new_session=True,
            preexec_fn=child_setup,
        )
        os.close(gate_read)
        gate_read = -1
        os.close(exec_status_write)
        exec_status_write = -1
        os.close(custody_write)
        custody_write = -1
        os.close(source_fd)
        source_fd = -1
        owner.process = process
        owner.pidfd = custodial_pidfd_open(process.pid)
        owner.custody_fd = custody_read
        custody_read = -1
        if owner.commit_check is None:
            raise PhaseError("APT phase exec-gate commit check is unavailable")
        release_requested = owner.commit_check()
        if release_requested:
            if os.write(gate_write, EXEC_GATE_TOKEN) != len(EXEC_GATE_TOKEN):
                raise PhaseError("APT phase exec-gate commit was incomplete")
        os.close(gate_write)
        gate_write = -1
        if release_requested:
            os.set_blocking(exec_status_read, False)
            poller = select.poll()
            poller.register(
                exec_status_read,
                select.POLLIN | select.POLLHUP | select.POLLERR,
            )
            gate_error = bytearray()
            handshake_deadline = time.monotonic() + EXEC_GATE_HANDSHAKE_SECONDS
            while True:
                if not owner.commit_check():
                    raise PhaseError("APT phase exec-gate handshake was interrupted")
                remaining = handshake_deadline - time.monotonic()
                if not math.isfinite(remaining) or remaining <= 0:
                    raise PhaseError("APT phase exec-gate handshake timed out")
                ready = poller.poll(max(1, min(50, math.ceil(remaining * 1000))))
                if not ready:
                    continue
                chunk = os.read(
                    exec_status_read,
                    EXEC_GATE_ERROR_LIMIT + 1 - len(gate_error),
                )
                if not chunk:
                    break
                gate_error.extend(chunk)
                if len(gate_error) > EXEC_GATE_ERROR_LIMIT:
                    raise PhaseError("APT phase exec-gate error exceeded its bound")
            if gate_error:
                raise PhaseError("APT phase target exec failed")
            owner.command_committed = True
        os.close(exec_status_read)
        exec_status_read = -1
    except BaseException as original:
        reported_error: BaseException = original
        for descriptor in (
            gate_read,
            gate_write,
            exec_status_read,
            exec_status_write,
            custody_read,
            custody_write,
            source_fd,
        ):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    cleanup_error = PhaseError("APT phase exec-gate cleanup failed")
                    cleanup_error.__cause__ = exc
                    reported_error = cleanup_error
        recovery_error: BaseException | None = None
        try:
            recover_spawn_handoff(
                baseline_children,
                baseline_descriptors,
                None if process is None else process.pid,
            )
        except BaseException as exc:
            recovery_error = exc
        if process is not None:
            process.returncode = 125
            for stream in (process.stdout, process.stderr):
                if stream is None:
                    continue
                try:
                    stream.close()
                except OSError as exc:
                    if exc.errno != errno.EBADF and recovery_error is None:
                        recovery_error = exc
        owner.process = None
        owner.pidfd = -1
        close_quietly(owner.custody_fd)
        owner.custody_fd = -1
        owner.command_committed = False
        if recovery_error is not None:
            raise PhaseError(
                "APT phase spawn handoff recovery did not converge"
            ) from reported_error
        raise reported_error


def inspect_subreaper() -> bool:
    current = ctypes.c_int()
    if LIBC.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
        raise PhaseError("cannot inspect APT phase subreaper state")
    return bool(current.value)


def apply_subreaper(enabled: bool) -> None:
    if LIBC.prctl(PR_SET_CHILD_SUBREAPER, int(enabled), 0, 0, 0) != 0:
        raise PhaseError("cannot set APT phase subreaper state")


def verify_waitable_sigchld() -> None:
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise PhaseError("APT phase runner requires default SIGCHLD handling")
    inherited_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    if signal.SIGCHLD in inherited_mask:
        raise PhaseError("APT phase runner requires unblocked SIGCHLD")
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    try:
        while True:
            try:
                waited, _ = os.waitpid(pid, 0)
                break
            except InterruptedError:
                continue
    except ChildProcessError as exc:
        raise PhaseError("APT phase runner requires waitable children") from exc
    if waited != pid:
        raise PhaseError("APT phase SIGCHLD probe did not converge")


def direct_children() -> tuple[int, ...]:
    path = pathlib.Path(f"/proc/self/task/{os.getpid()}/children")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PhaseError("cannot inspect APT phase direct children") from exc
    if len(raw) > 128 * 1024:
        raise PhaseError("APT phase direct-child record exceeds its bound")
    fields = raw.split()
    if len(fields) > MAX_DIRECT_CHILDREN or any(
        not field.isascii() or not field.isdigit() for field in fields
    ):
        raise PhaseError("APT phase direct-child record is malformed")
    return tuple(int(field, 10) for field in fields)


def waitid_exited(pid: int) -> bool:
    while True:
        try:
            return (
                os.waitid(
                    os.P_PID,
                    pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
                is not None
            )
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise PhaseError("APT phase leader lost its waitable status") from exc


def signal_group(pgid: int, signum: int) -> None:
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


def kill_adopted_children(root_pid: int | None) -> bool:
    found = False
    for pid in direct_children():
        if root_pid is not None and pid == root_pid:
            continue
        found = True
        descriptor = -1
        try:
            descriptor = custodial_pidfd_open(pid)
            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return found


def reap_adopted_children(root_pid: int | None) -> bool:
    pending = False
    for pid in direct_children():
        if root_pid is not None and pid == root_pid:
            continue
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            continue
        except InterruptedError:
            pending = True
            continue
        if waited == 0:
            pending = True
    return pending


def write_control_record(descriptor: int, record: bytes) -> bool:
    written = 0
    while written < len(record):
        try:
            count = os.write(descriptor, record[written:])
        except InterruptedError:
            continue
        except OSError:
            return False
        if count <= 0:
            return False
        written += count
    return True


def close_quietly(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def open_authenticated_self() -> int:
    path = pathlib.Path(__file__)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > 1024 * 1024
            or metadata.st_mode & 0o022
        ):
            raise PhaseError("APT phase runner source is not immutable input")
        return descriptor
    except BaseException:
        close_quietly(descriptor)
        raise


def consume_custody_report(owner: ProcessOwner) -> bytes:
    descriptor = owner.custody_fd
    owner.custody_fd = -1
    if descriptor < 0:
        raise PhaseError("APT phase custody report is unavailable")
    report = bytearray()
    try:
        while len(report) < 2:
            try:
                chunk = os.read(descriptor, 2 - len(report))
            except InterruptedError:
                continue
            if not chunk:
                break
            report.extend(chunk)
    finally:
        os.close(descriptor)
    if bytes(report) not in (CUSTODY_OK, CUSTODY_DESCENDANT, CUSTODY_FAILURE):
        raise PhaseError("APT phase custody report is malformed")
    return bytes(report)


def custodian_emergency_converge(process: subprocess.Popen[bytes] | None) -> bool:
    deadline = time.monotonic() + CLEANUP_GRACE_SECONDS
    if process is not None:
        signal_group(process.pid, signal.SIGKILL)
    while time.monotonic() < deadline:
        root_pid = None
        if process is not None and process.poll() is None:
            root_pid = process.pid
        try:
            kill_adopted_children(root_pid)
            reap_adopted_children(root_pid)
            children = direct_children()
        except BaseException:
            return False
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=POLL_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            except BaseException:
                return False
        if process is None or process.poll() is not None:
            if not children:
                return True
        time.sleep(0.01)
    return False


def converge_custodian_tree(
    process: subprocess.Popen[bytes],
    latch: SignalLatch,
    expected_parent_pid: int,
) -> tuple[int, bool, bool, bool]:
    termination_started: float | None = None
    cleanup_deadline: float | None = None
    kill_sent = False
    unexpected_descendants = False
    parent_lost = False
    while True:
        now = time.monotonic()
        if os.getppid() != expected_parent_pid:
            parent_lost = True
            if latch.signum is None:
                latch.handler(signal.SIGTERM, None)
        if latch.signum is not None and termination_started is None:
            termination_started = now
            cleanup_deadline = now + CLEANUP_GRACE_SECONDS
            signal_group(process.pid, signal.SIGTERM)
        returncode = process.poll()
        root_pid = process.pid if returncode is None else None
        children = direct_children()
        extras = tuple(pid for pid in children if root_pid is None or pid != root_pid)
        if extras:
            unexpected_descendants = True
            if cleanup_deadline is None:
                cleanup_deadline = now + CLEANUP_GRACE_SECONDS
            kill_adopted_children(root_pid)
            reap_adopted_children(root_pid)
        if returncode is not None and not direct_children():
            return returncode, unexpected_descendants, True, parent_lost
        if (
            termination_started is not None
            and not kill_sent
            and now - termination_started >= CUSTODIAN_TERM_GRACE_SECONDS
        ):
            signal_group(process.pid, signal.SIGKILL)
            kill_sent = True
        if cleanup_deadline is not None and now >= cleanup_deadline:
            signal_group(process.pid, signal.SIGKILL)
            final_deadline = now + CUSTODIAN_FINAL_REAP_SECONDS
            while True:
                returncode = process.poll()
                root_pid = process.pid if returncode is None else None
                kill_adopted_children(root_pid)
                reap_adopted_children(root_pid)
                returncode = process.poll()
                if returncode is not None and not direct_children():
                    converged = True
                    break
                if time.monotonic() >= final_deadline:
                    converged = False
                    break
                time.sleep(0.01)
            return (
                125 if returncode is None else returncode,
                unexpected_descendants,
                converged,
                parent_lost,
            )
        time.sleep(0.01)


def run_custodian(
    control_fd: int,
    status_fd: int,
    report_fd: int,
    expected_parent_pid: int,
    command: list[str],
) -> int:
    process: subprocess.Popen[bytes] | None = None
    latch = SignalLatch()
    status_open = True
    report = CUSTODY_FAILURE
    target_status = 125
    parent_lost = False

    custodian_pid = os.getpid()

    def exact_target_setup() -> None:
        if LIBC.prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
            os._exit(125)
        if os.getppid() != custodian_pid:
            os.kill(os.getpid(), signal.SIGKILL)
            os._exit(125)
        for signum in HANDLED_SIGNALS:
            signal.signal(signum, signal.SIG_DFL)

    try:
        if (
            min(control_fd, status_fd, report_fd, expected_parent_pid) < 1
            or len({control_fd, status_fd, report_fd}) != 3
            or not command
        ):
            raise PhaseError("APT phase custodian arguments are invalid")
        for descriptor in (control_fd, status_fd, report_fd):
            os.fstat(descriptor)
            os.set_inheritable(descriptor, False)
        for signum in HANDLED_SIGNALS:
            signal.signal(signum, latch.handler)
        if LIBC.prctl(PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0) != 0:
            raise PhaseError("APT phase custodian cannot set parent-death signal")
        if os.getppid() != expected_parent_pid:
            latch.handler(signal.SIGTERM, None)
        apply_subreaper(True)
        if direct_children():
            raise PhaseError("APT phase custodian inherited children")
        token = bytearray()
        while len(token) < 2:
            try:
                chunk = os.read(control_fd, 2 - len(token))
            except InterruptedError:
                continue
            if not chunk:
                break
            token.extend(chunk)
        os.close(control_fd)
        control_fd = -1
        if bytes(token) != EXEC_GATE_TOKEN or latch.signum is not None:
            raise PhaseError("APT phase custodian was not authorized")
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            close_fds=True,
            start_new_session=True,
            preexec_fn=exact_target_setup,
        )
        if latch.signum is not None or os.getppid() != expected_parent_pid:
            parent_lost = os.getppid() != expected_parent_pid
            if parent_lost and latch.signum is None:
                latch.handler(signal.SIGTERM, None)
        os.close(status_fd)
        status_fd = -1
        status_open = False
        while process.poll() is None and latch.signum is None:
            if os.getppid() != expected_parent_pid:
                parent_lost = True
                latch.handler(signal.SIGTERM, None)
                break
            time.sleep(0.01)
        returncode, unexpected, converged, convergence_parent_lost = (
            converge_custodian_tree(process, latch, expected_parent_pid)
        )
        parent_lost = parent_lost or convergence_parent_lost
        target_status = shell_status(returncode)
        if not converged:
            report = CUSTODY_FAILURE
            target_status = 125
        elif unexpected:
            report = CUSTODY_DESCENDANT
        else:
            report = CUSTODY_OK
    except BaseException as exc:
        if status_open:
            code = getattr(exc, "errno", 0) or 0
            write_control_record(status_fd, f"{code}\n".encode("ascii"))
        if not custodian_emergency_converge(process):
            target_status = 125
        report = CUSTODY_FAILURE
    finally:
        close_quietly(control_fd)
        close_quietly(status_fd)
        report_written = write_control_record(report_fd, report)
        close_quietly(report_fd)
        if not report_written and not parent_lost:
            target_status = 125
    return target_status


def rollback_created_output(parent_fd: int, descriptor: int, name: str) -> None:
    descriptor_metadata = os.fstat(descriptor)
    try:
        path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (path_metadata.st_dev, path_metadata.st_ino) != (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
    ):
        return
    os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def prepare_output(private_root_text: str, output_text: str) -> tuple[pathlib.Path, OutputOwner]:
    private_root_input = pathlib.Path(private_root_text)
    output = pathlib.Path(output_text)
    try:
        private_root_metadata = private_root_input.lstat()
        private_root = private_root_input.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PhaseError("APT phase private root is unavailable") from exc
    if (
        private_root_input.is_symlink()
        or not stat.S_ISDIR(private_root_metadata.st_mode)
        or pathlib.Path(os.path.abspath(private_root_input)) != private_root
        or private_root_metadata.st_uid != os.geteuid()
        or private_root_metadata.st_gid != os.getegid()
    ):
        raise PhaseError("APT phase private root is not a real directory")
    if not output.is_absolute() or not OUTPUT_NAME.fullmatch(output.name):
        raise PhaseError("APT phase stdout path is not canonical")
    try:
        original_parent_metadata = output.parent.lstat()
        parent = output.parent.resolve(strict=True)
        parent_metadata = parent.lstat()
        parent.relative_to(private_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PhaseError("APT phase stdout parent escaped its private root") from exc
    if (
        output.parent.is_symlink()
        or pathlib.Path(os.path.abspath(output.parent)) != parent
        or not stat.S_ISDIR(original_parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (
            original_parent_metadata.st_dev,
            original_parent_metadata.st_ino,
        ) != (parent_metadata.st_dev, parent_metadata.st_ino)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_gid != os.getegid()
    ):
        raise PhaseError("APT phase stdout parent is not a real directory")
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        opened_parent = os.fstat(parent_fd)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            raise PhaseError("APT phase stdout parent changed during open")
        descriptor = os.open(
            output.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PhaseError("APT phase stdout inode metadata is unsafe")
        return private_root, OutputOwner(
            parent_fd,
            descriptor,
            parent,
            (opened_parent.st_dev, opened_parent.st_ino),
            output.name,
            (metadata.st_dev, metadata.st_ino),
        )
    except BaseException as original:
        cleanup_failure: BaseException | None = None
        if descriptor >= 0 and parent_fd >= 0:
            try:
                rollback_created_output(parent_fd, descriptor, output.name)
            except BaseException as exc:
                cleanup_failure = exc
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as exc:
                if cleanup_failure is None:
                    cleanup_failure = exc
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except BaseException as exc:
                if cleanup_failure is None:
                    cleanup_failure = exc
        if cleanup_failure is not None:
            failure = PhaseError("APT phase stdout creation rollback failed")
            failure.__cause__ = cleanup_failure
            raise failure from original
        raise


def write_stdout(owner: OutputOwner, chunk: bytes) -> None:
    if owner.written >= OUTPUT_LIMIT:
        owner.overflow = owner.overflow or bool(chunk)
        return
    permitted = min(len(chunk), OUTPUT_LIMIT - owner.written)
    view = memoryview(chunk)[:permitted]
    while view:
        try:
            written = os.write(owner.descriptor, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise PhaseError("APT phase stdout write did not converge")
        owner.written += written
        view = view[written:]
    if permitted != len(chunk):
        owner.overflow = True


def discard_output(owner: OutputOwner) -> None:
    primary: BaseException | None = None
    try:
        rollback_created_output(owner.parent_fd, owner.descriptor, owner.name)
    except BaseException as exc:
        primary = PhaseError("APT phase unused stdout rollback failed")
        primary.__cause__ = exc
    for descriptor in (owner.descriptor, owner.parent_fd):
        try:
            os.close(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF and primary is None:
                primary = PhaseError("APT phase unused stdout cleanup failed")
                primary.__cause__ = exc
    if primary is not None:
        raise primary


def settle_output(owner: OutputOwner) -> None:
    primary: BaseException | None = None
    verification_fd = -1
    try:
        os.fsync(owner.descriptor)
        verification_fd = os.open(
            owner.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        verification_parent = os.fstat(verification_fd)
        if (
            verification_parent.st_dev,
            verification_parent.st_ino,
        ) != owner.parent_identity:
            raise PhaseError("APT phase stdout parent path was replaced")
        descriptor_metadata = os.fstat(owner.descriptor)
        path_metadata = os.stat(owner.name, dir_fd=owner.parent_fd, follow_symlinks=False)
        if (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
        ) != owner.identity or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != owner.identity:
            raise PhaseError("APT phase stdout path was replaced")
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_IMODE(path_metadata.st_mode) != 0o600
            or path_metadata.st_uid != os.geteuid()
            or path_metadata.st_gid != os.getegid()
            or path_metadata.st_nlink != 1
            or path_metadata.st_size != owner.written
        ):
            raise PhaseError("APT phase stdout final metadata is unsafe")
    except BaseException as exc:
        primary = exc
    if primary is not None:
        try:
            owned_path = os.stat(
                owner.name,
                dir_fd=owner.parent_fd,
                follow_symlinks=False,
            )
            if (owned_path.st_dev, owned_path.st_ino) == owner.identity:
                os.unlink(owner.name, dir_fd=owner.parent_fd)
                os.fsync(owner.parent_fd)
        except FileNotFoundError:
            pass
        except BaseException as exc:
            cleanup_failure = PhaseError(
                f"{primary}; APT phase stdout containment rollback failed"
            )
            cleanup_failure.__cause__ = exc
            primary = cleanup_failure
    for descriptor in (verification_fd, owner.descriptor, owner.parent_fd):
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF and primary is None:
                primary = PhaseError("APT phase stdout descriptor cleanup failed")
                primary.__cause__ = exc
    if primary is not None:
        raise primary


def render_excerpt(label: str, evidence: StreamEvidence) -> bytes:
    if evidence.size == 0:
        return b""
    if evidence.size <= EXCERPT_LIMIT:
        first = bytes(evidence.head)
        final = b""
        omitted = 0
    elif evidence.size <= EXCERPT_LIMIT * 2:
        overlap = EXCERPT_LIMIT * 2 - evidence.size
        first = bytes(evidence.head)
        final = bytes(evidence.tail)[overlap:]
        omitted = 0
    else:
        first = bytes(evidence.head)
        final = bytes(evidence.tail)
        omitted = evidence.size - len(first) - len(final)
    rendered = bytearray()
    rendered.extend(
        f"--- {label} first bounded bytes; omitted={omitted} ---\n".encode("ascii")
    )
    rendered.extend(evidence.sanitized(first))
    if not first.endswith(b"\n"):
        rendered.extend(b"\n")
    if evidence.first_cause is not None:
        rendered.extend(f"--- {label} first cause ---\n".encode("ascii"))
        rendered.extend(evidence.sanitized(evidence.first_cause))
        if not evidence.first_cause.endswith(b"\n"):
            rendered.extend(b"\n")
    if final:
        rendered.extend(
            f"--- {label} final bounded bytes; omitted={omitted} ---\n".encode("ascii")
        )
        rendered.extend(evidence.sanitized(final))
        if not final.endswith(b"\n"):
            rendered.extend(b"\n")
    rendered.extend(f"--- end bounded {label} ---\n".encode("ascii"))
    return bytes(rendered)


def render_diagnostic(
    phase: str,
    selected_status: int,
    command_status: int | None,
    reasons: tuple[str, ...],
    stdout_evidence: StreamEvidence,
    stderr_evidence: StreamEvidence,
    failures: tuple[BaseException, ...],
    omitted_failures: int,
) -> bytes:
    reason = ",".join(reasons) if reasons else "command-failed"
    raw_command_status = "none" if command_status is None else str(command_status)
    line = (
        f"APT_PHASE_FAILURE phase={phase} status={selected_status} "
        f"command_status={raw_command_status} reason={reason} "
        f"stdout_bytes={stdout_evidence.size} stdout_lines={stdout_evidence.lines} "
        f"stdout_sha256={stdout_evidence.sha256} "
        f"stderr_bytes={stderr_evidence.size} stderr_lines={stderr_evidence.lines} "
        f"stderr_sha256={stderr_evidence.sha256}\n"
    )
    rendered = bytearray(line.encode("ascii"))
    rendered.extend(render_excerpt("apt stdout", stdout_evidence))
    rendered.extend(render_excerpt("apt stderr", stderr_evidence))
    for index, failure in enumerate(failures, 1):
        raw_message = str(failure).encode("ascii", "backslashreplace")[:2048]
        message = stderr_evidence.sanitized(raw_message)
        rendered.extend(
            f"APT_PHASE_RUNNER_ERROR index={index} "
            f"type={type(failure).__name__} message=".encode("ascii")
        )
        rendered.extend(message)
        rendered.extend(b"\n")
    if omitted_failures:
        rendered.extend(
            f"APT_PHASE_RUNNER_ERROR omitted={omitted_failures}\n".encode("ascii")
        )
    if len(rendered) > PUBLIC_DIAGNOSTIC_LIMIT:
        marker = b"APT_PHASE_RUNNER_ERROR public-diagnostic-truncated\n"
        rendered = rendered[: PUBLIC_DIAGNOSTIC_LIMIT - len(marker)]
        rendered.extend(marker)
    return bytes(rendered)


def write_bounded_stderr(raw: bytes) -> None:
    if not raw:
        return
    diagnostic_fd = -1
    try:
        inherited_metadata = os.fstat(2)
        diagnostic_fd = os.open(
            "/proc/self/fd/2",
            os.O_WRONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY,
        )
        diagnostic_metadata = os.fstat(diagnostic_fd)
        if (
            diagnostic_metadata.st_dev,
            diagnostic_metadata.st_ino,
            stat.S_IFMT(diagnostic_metadata.st_mode),
        ) != (
            inherited_metadata.st_dev,
            inherited_metadata.st_ino,
            stat.S_IFMT(inherited_metadata.st_mode),
        ):
            return
    except BaseException:
        if diagnostic_fd >= 0:
            try:
                os.close(diagnostic_fd)
            except OSError:
                pass
        return
    offset = 0
    interruptions = 0
    deadline = time.monotonic() + PUBLIC_WRITE_SECONDS
    try:
        poller = select.poll()
        poller.register(
            diagnostic_fd,
            select.POLLOUT | select.POLLHUP | select.POLLERR,
        )
        while offset < len(raw):
            remaining = deadline - time.monotonic()
            if not math.isfinite(remaining) or remaining <= 0:
                return
            try:
                ready = poller.poll(max(1, min(50, math.ceil(remaining * 1000))))
            except InterruptedError:
                interruptions += 1
                if interruptions > MAX_IO_INTERRUPTS:
                    return
                continue
            interruptions = 0
            if not any(
                descriptor == diagnostic_fd
                and events & (select.POLLOUT | select.POLLHUP | select.POLLERR)
                for descriptor, events in ready
            ):
                continue
            try:
                written = os.write(diagnostic_fd, raw[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            if written <= 0:
                return
            offset += written
    except BaseException:
        return
    finally:
        if diagnostic_fd >= 0:
            try:
                os.close(diagnostic_fd)
            except OSError:
                pass


def drain_pending_signals(latch: SignalLatch) -> None:
    pending_set = set(HANDLED_SIGNALS)
    for _ in range(MAX_PENDING_SIGNAL_DRAIN):
        try:
            pending = signal.sigtimedwait(pending_set, 0)
        except InterruptedError:
            continue
        if pending is None:
            return
        latch.handler(pending.si_signo, None)
    raise PhaseError("APT phase pending signals did not converge")


def collect_pending_signals(latch: SignalLatch) -> None:
    pending = signal.sigpending()
    for signum in HANDLED_SIGNALS:
        if signum not in pending:
            continue
        observed = signal.sigtimedwait({signum}, 0)
        if observed is None:
            raise PhaseError("APT phase pending signal disappeared")
        latch.handler(observed.si_signo, None)


def shell_status(returncode: int) -> int:
    return returncode if returncode >= 0 else 128 + (-returncode)


def run_phase(
    phase: str,
    timeout_seconds: float,
    private_root_text: str,
    output_text: str,
    command: list[str],
) -> int:
    if (
        not PHASE.fullmatch(phase)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 3600
        or not command
        or len(command) > 4096
        or any(not value or "\x00" in value or len(value) > 16384 for value in command)
    ):
        raise PhaseError("APT phase runner inputs are invalid")
    output_owner: OutputOwner | None = None
    private_root_bytes = os.fsencode(private_root_text)
    stdout_evidence = StreamEvidence(private_root_bytes)
    stderr_evidence = StreamEvidence(private_root_bytes)
    latch = SignalLatch()
    previous_handlers: dict[int, object] = {}
    installed_handlers: set[int] = set()
    previous_subreaper: bool | None = None
    process_owner = ProcessOwner()
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    primary_failures = FailureLedger()
    secondary_failures = FailureLedger()
    reasons: list[str] = []
    timed_out = False
    unexpected_descendants = False
    leader_exited = False
    natural_command_exit = False
    termination_started: float | None = None
    kill_sent = False
    deadline = time.monotonic() + timeout_seconds
    cleanup_deadline: float | None = None
    original_mask: set[signal.Signals] | None = None
    signal_mask_blocked = False
    command_status: int | None = None
    custody_authenticated = False
    expected_parent_pid = os.getpid()

    def record_failure(
        exc: BaseException,
        message: str,
        *,
        secondary: bool = False,
    ) -> None:
        ledger = secondary_failures if secondary else primary_failures
        if isinstance(exc, PhaseError):
            ledger.add(exc)
            return
        failure = PhaseError(message)
        failure.__cause__ = exc
        ledger.add(failure)

    def child_setup() -> None:
        assert original_mask is not None
        if LIBC.prctl(PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0) != 0:
            os._exit(125)
        if os.getppid() != expected_parent_pid:
            os.kill(os.getpid(), signal.SIGKILL)
            os._exit(125)
        for signum in HANDLED_SIGNALS:
            signal.signal(signum, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

    def permit_spawn_commit() -> bool:
        nonlocal timed_out
        drain_pending_signals(latch)
        if time.monotonic() >= deadline:
            timed_out = True
        return latch.signum is None and not timed_out

    def begin_termination(now: float, immediate: bool = False) -> None:
        nonlocal termination_started, kill_sent, cleanup_deadline
        if process is None:
            return
        if termination_started is None:
            termination_started = now
            cleanup_deadline = now + CLEANUP_GRACE_SECONDS
            signal_group(process.pid, signal.SIGKILL if immediate else signal.SIGTERM)
            kill_sent = immediate

    def drain_ready(timeout: float) -> None:
        if selector is None:
            raise PhaseError("APT phase selector is unavailable")
        try:
            events = selector.select(timeout)
        except InterruptedError:
            return
        for key, _ in events:
            try:
                chunk = os.read(key.fd, READ_SIZE)
            except BlockingIOError:
                continue
            except BaseException as exc:
                record_failure(exc, "APT phase output drain failed")
                selector.unregister(key.fileobj)
                continue
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            evidence, persist = key.data
            evidence.feed(chunk)
            if persist:
                try:
                    if output_owner is None:
                        raise PhaseError("APT phase stdout owner is unavailable")
                    write_stdout(output_owner, chunk)
                except BaseException as exc:
                    record_failure(exc, "APT phase stdout persistence failed")

    def emergency_converge() -> None:
        nonlocal command_status, unexpected_descendants
        owned_process = process_owner.process
        if owned_process is None:
            return
        try:
            signal_group(owned_process.pid, signal.SIGKILL)
        except BaseException as exc:
            record_failure(exc, "APT phase emergency group signal failed")
        convergence_deadline = time.monotonic() + CLEANUP_GRACE_SECONDS
        while time.monotonic() < convergence_deadline:
            root_filter = (
                owned_process.pid if owned_process.returncode is None else None
            )
            try:
                unexpected_descendants = (
                    kill_adopted_children(root_filter)
                    or unexpected_descendants
                )
                reap_adopted_children(root_filter)
            except BaseException as exc:
                record_failure(exc, "APT phase emergency descendant cleanup failed")
            if owned_process.returncode is None:
                try:
                    returncode = owned_process.wait(timeout=POLL_SECONDS)
                    command_status = shell_status(returncode)
                except subprocess.TimeoutExpired:
                    pass
                except BaseException as exc:
                    record_failure(exc, "APT phase emergency leader reap failed")
            try:
                children = direct_children()
                extra = (
                    tuple(pid for pid in children if pid != owned_process.pid)
                    if owned_process.returncode is None
                    else children
                )
            except BaseException as exc:
                record_failure(exc, "APT phase emergency child inspection failed")
                extra = (owned_process.pid,)
            if owned_process.returncode is not None and not extra:
                return
            time.sleep(0.01)
        record_failure(
            PhaseError("APT phase emergency cleanup did not converge"),
            "APT phase emergency cleanup did not converge",
        )

    try:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
        signal_mask_blocked = True
        if any(signum in original_mask for signum in HANDLED_SIGNALS):
            raise PhaseError("APT phase runner inherited blocked cancellation")
        previous_handlers = {
            signum: signal.getsignal(signum) for signum in HANDLED_SIGNALS
        }
        for signum in HANDLED_SIGNALS:
            signal.signal(signum, latch.handler)
            installed_handlers.add(signum)
        drain_pending_signals(latch)
        verify_waitable_sigchld()
        if direct_children():
            raise PhaseError("APT phase runner inherited pre-existing children")
        selector = selectors.DefaultSelector()
        drain_pending_signals(latch)
        if time.monotonic() >= deadline:
            timed_out = True
        if latch.signum is None and not timed_out:
            previous_subreaper = inspect_subreaper()
            apply_subreaper(True)
            private_root, output_owner = prepare_output(private_root_text, output_text)
            private_root_bytes = os.fsencode(private_root)
            stdout_evidence.private_root = private_root_bytes
            stderr_evidence.private_root = private_root_bytes
            drain_pending_signals(latch)
            if time.monotonic() >= deadline:
                timed_out = True
        try:
            if latch.signum is None and not timed_out:
                process_owner.commit_check = permit_spawn_commit
                spawn_owned_process(process_owner, command, child_setup)
                process = process_owner.process
                if process is None:
                    if latch.signum is None and not timed_out:
                        raise PhaseError(
                            "APT phase process ownership was not published"
                        )
                else:
                    if process.stdout is None or process.stderr is None:
                        raise PhaseError("APT phase output pipes are unavailable")
                    os.set_blocking(process.stdout.fileno(), False)
                    os.set_blocking(process.stderr.fileno(), False)
                    selector.register(
                        process.stdout,
                        selectors.EVENT_READ,
                        (stdout_evidence, True),
                    )
                    selector.register(
                        process.stderr,
                        selectors.EVENT_READ,
                        (stderr_evidence, False),
                    )
        finally:
            if original_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
                signal_mask_blocked = False
        while process is not None:
            now = time.monotonic()
            if now >= deadline and termination_started is None:
                timed_out = True
                begin_termination(now)
            if process is not None and not leader_exited:
                leader_exited = waitid_exited(process.pid)
                if leader_exited:
                    if termination_started is None:
                        natural_command_exit = True
                    try:
                        children = direct_children()
                        unexpected_descendants = unexpected_descendants or any(
                            pid != process.pid for pid in children
                        )
                    except BaseException as exc:
                        record_failure(
                            exc,
                            "APT phase direct-child inspection failed",
                        )
                    begin_termination(now, immediate=True)
            if latch.signum is not None:
                begin_termination(now)
            elif primary_failures and not leader_exited:
                begin_termination(now)
            if (
                termination_started is not None
                and not kill_sent
                and now - termination_started >= TERM_GRACE_SECONDS
            ):
                assert process is not None
                signal_group(process.pid, signal.SIGKILL)
                kill_sent = True
            if process is not None and termination_started is not None:
                try:
                    unexpected_descendants = (
                        kill_adopted_children(process.pid) or unexpected_descendants
                    )
                    reap_adopted_children(process.pid)
                except BaseException as exc:
                    record_failure(exc, "APT phase descendant cleanup failed")
            drain_ready(POLL_SECONDS)
            if process is not None and leader_exited and not selector.get_map():
                pending = reap_adopted_children(process.pid)
                children = direct_children()
                extra = tuple(pid for pid in children if pid != process.pid)
                if not pending and not extra:
                    break
                unexpected_descendants = True
            if cleanup_deadline is not None and now >= cleanup_deadline:
                record_failure(
                    PhaseError("APT phase process cleanup did not converge"),
                    "APT phase process cleanup did not converge",
                )
                break
        if process is not None:
            returncode = process.wait(timeout=1.0)
            try:
                custody_report = consume_custody_report(process_owner)
                if custody_report == CUSTODY_DESCENDANT:
                    unexpected_descendants = True
                    custody_authenticated = True
                elif custody_report == CUSTODY_OK:
                    custody_authenticated = True
                elif custody_report == CUSTODY_FAILURE:
                    record_failure(
                        PhaseError("APT phase custodian reported containment failure"),
                        "APT phase custodian reported containment failure",
                    )
            except BaseException as exc:
                record_failure(exc, "APT phase custody report failed")
            for _ in range(20):
                if not reap_adopted_children(None):
                    if not direct_children():
                        break
                kill_adopted_children(None)
                time.sleep(0.01)
            if direct_children():
                record_failure(
                    PhaseError("APT phase left an owned descendant"),
                    "APT phase left an owned descendant",
                )
            command_status = shell_status(returncode)
            if not custody_authenticated:
                command_status = None
                natural_command_exit = False
    except BaseException as exc:
        record_failure(exc, "APT phase execution failed")
        process = process_owner.process
        emergency_converge()
    finally:
        if installed_handlers:
            if not signal_mask_blocked:
                try:
                    observed_mask = signal.pthread_sigmask(
                        signal.SIG_BLOCK, HANDLED_SIGNALS
                    )
                    signal_mask_blocked = True
                    if original_mask is not None and observed_mask != original_mask:
                        raise PhaseError("APT phase signal mask changed during execution")
                except BaseException as exc:
                    record_failure(exc, "APT phase final signal custody failed")
        if selector is not None:
            try:
                selector.close()
            except BaseException as exc:
                record_failure(exc, "APT phase selector cleanup failed", secondary=True)
        process = process_owner.process
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is None:
                    continue
                try:
                    stream.close()
                except BaseException as exc:
                    record_failure(exc, "APT phase pipe cleanup failed", secondary=True)
        if process_owner.pidfd >= 0:
            try:
                os.close(process_owner.pidfd)
            except BaseException as exc:
                record_failure(
                    exc, "APT phase root pidfd cleanup failed", secondary=True
                )
            process_owner.pidfd = -1
        if process_owner.custody_fd >= 0:
            try:
                os.close(process_owner.custody_fd)
            except BaseException as exc:
                record_failure(
                    exc, "APT phase custody pipe cleanup failed", secondary=True
                )
            process_owner.custody_fd = -1
        if output_owner is not None:
            try:
                if (
                    process_owner.process is None
                    or not process_owner.command_committed
                ):
                    discard_output(output_owner)
                else:
                    settle_output(output_owner)
            except BaseException as exc:
                record_failure(exc, "APT phase stdout settlement failed", secondary=True)
        if previous_subreaper is not None:
            try:
                apply_subreaper(previous_subreaper)
                if inspect_subreaper() != previous_subreaper:
                    raise PhaseError("APT phase subreaper restoration did not converge")
            except BaseException as exc:
                record_failure(
                    exc, "APT phase subreaper restoration failed", secondary=True
                )
        for evidence, label in (
            (stdout_evidence, "stdout"),
            (stderr_evidence, "stderr"),
        ):
            try:
                evidence.finish()
            except BaseException as exc:
                record_failure(
                    exc, f"APT phase {label} evidence finalization failed", secondary=True
                )
        if signal_mask_blocked and installed_handlers:
            try:
                collect_pending_signals(latch)
            except BaseException as exc:
                record_failure(exc, "APT phase pending signal collection failed")
    def select_status() -> tuple[int, list[str]]:
        selected_reasons: list[str] = []
        output_overflow = output_owner is not None and output_owner.overflow
        policy_failure = (
            output_overflow
            or stdout_evidence.sandbox_fallback
            or stderr_evidence.sandbox_fallback
        )
        if latch.signum is not None:
            status = 128 + latch.signum
            selected_reasons.append("caller-cancelled")
        elif timed_out:
            status = 124
            selected_reasons.append("deadline-exceeded")
        elif natural_command_exit and command_status is not None and command_status != 0:
            status = command_status
            selected_reasons.append("command-failed")
        elif primary_failures or unexpected_descendants:
            status = 125
            selected_reasons.append("runner-containment-failed")
        elif command_status is not None and command_status != 0:
            status = command_status
            selected_reasons.append("command-failed")
        elif secondary_failures or policy_failure:
            status = 125
        else:
            status = 0
        if output_overflow:
            selected_reasons.append("stdout-limit-exceeded")
        if stdout_evidence.sandbox_fallback or stderr_evidence.sandbox_fallback:
            selected_reasons.append("apt-sandbox-fallback")
        if unexpected_descendants:
            selected_reasons.append("unexpected-descendant")
        if (
            primary_failures or secondary_failures
        ) and "runner-containment-failed" not in selected_reasons:
            selected_reasons.append("runner-containment-failed")
        return status, list(dict.fromkeys(selected_reasons))

    def publish_diagnostic(status: int, selected_reasons: list[str]) -> None:
        if status == 0 and not selected_reasons:
            return
        failures = tuple(primary_failures.entries + secondary_failures.entries)
        omitted = primary_failures.omitted + secondary_failures.omitted
        try:
            raw = render_diagnostic(
                phase,
                status,
                command_status,
                tuple(selected_reasons),
                stdout_evidence,
                stderr_evidence,
                failures,
                omitted,
            )
        except BaseException:
            raw = (
                f"APT_PHASE_FAILURE phase={phase} status={status} "
                "command_status=none reason=runner-containment-failed\n"
            ).encode("ascii")
        write_bounded_stderr(raw)

    selected_status, reasons = select_status()
    publish_diagnostic(selected_status, reasons)

    if signal_mask_blocked and installed_handlers:
        try:
            collect_pending_signals(latch)
        except BaseException as exc:
            record_failure(exc, "APT phase terminal pending signal collection failed")
        terminal_status, terminal_reasons = select_status()
        if terminal_status != selected_status or terminal_reasons != reasons:
            selected_status = terminal_status
            reasons = terminal_reasons
            publish_diagnostic(selected_status, reasons)

    for signum in HANDLED_SIGNALS:
        if signum not in installed_handlers:
            continue
        try:
            signal.signal(signum, previous_handlers[signum])
        except BaseException as exc:
            record_failure(
                exc, "APT phase signal handler restoration failed", secondary=True
            )
    if signal_mask_blocked and installed_handlers:
        try:
            collect_pending_signals(latch)
        except BaseException as exc:
            record_failure(
                exc,
                "APT phase post-handler pending signal collection failed",
            )
    terminal_status, terminal_reasons = select_status()
    if terminal_status != selected_status or terminal_reasons != reasons:
        selected_status = terminal_status
        reasons = terminal_reasons
        publish_diagnostic(selected_status, reasons)

    if signal_mask_blocked and original_mask is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    return selected_status


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PhaseError(f"APT phase runner arguments are invalid: {message}")


def main() -> None:
    status = 125
    status_fd: int | None = None
    try:
        parser = FailClosedParser(add_help=False, allow_abbrev=False)
        parser.add_argument("--phase", required=True)
        parser.add_argument("--timeout-seconds", required=True, type=float)
        parser.add_argument("--private-root", required=True)
        parser.add_argument("--stdout", required=True)
        parser.add_argument("--status-fd", type=int)
        parser.add_argument("--cgroup")
        parser.add_argument("--cgroup-identity")
        parser.add_argument("command", nargs=argparse.REMAINDER)
        arguments = parser.parse_args()
        status_fd = arguments.status_fd
        if status_fd is not None:
            if status_fd < 3 or not stat.S_ISFIFO(os.fstat(status_fd).st_mode):
                raise PhaseError("APT phase completion descriptor is invalid")
            os.set_inheritable(status_fd, False)
        command = arguments.command
        if command[:1] == ["--"]:
            command = command[1:]
        join_execution_cgroup(arguments.cgroup, arguments.cgroup_identity)
        status = run_phase(
            arguments.phase,
            arguments.timeout_seconds,
            arguments.private_root,
            arguments.stdout,
            command,
        )
    except (OSError, ValueError, PhaseError) as exc:
        message = str(exc).encode("ascii", "backslashreplace")[:2048]
        write_bounded_stderr(
            b"APT_PHASE_RUNNER_ERROR "
            + type(exc).__name__.encode("ascii", "backslashreplace")
            + b": "
            + message
            + b"\n"
        )
        status = 125
    if status_fd is not None:
        if not write_control_record(status_fd, f"{status}\n".encode("ascii")):
            status = 125
        close_quietly(status_fd)
    raise SystemExit(status)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--custodian"]:
        if len(sys.argv) < 8 or sys.argv[6] != "--":
            os._exit(125)
        try:
            custodian_status = run_custodian(
                int(sys.argv[2], 10),
                int(sys.argv[3], 10),
                int(sys.argv[4], 10),
                int(sys.argv[5], 10),
                sys.argv[7:],
            )
        except BaseException:
            custodian_status = 125
        os._exit(custodian_status)
    main()
