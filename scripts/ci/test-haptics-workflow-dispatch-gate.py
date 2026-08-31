#!/usr/bin/env python3
"""Fixtures for the operator-local trusted workflow dispatch gate."""

from __future__ import annotations

import ast
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import io
import os
import importlib.util
import json
import pathlib
import pwd
import resource
import select
import signal
import subprocess
import stat
import sys
import tempfile
import time
import urllib.parse
import zlib


_ORIGINAL_SCANDIR = os.scandir


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
GATE = SCRIPT_DIR / "dispatch-haptics-workflow.py"
REAL_WORKFLOW = SCRIPT_DIR.parent.parent / ".github/workflows/build.yml"
VALIDATORS = (
    "scripts/ci/check-workflow-input-boundaries.py",
    "scripts/ci/test-haptics-release-job-isolation.py",
)
VALIDATOR_SOURCE = """#!/usr/bin/env python3
import pathlib
import sys
source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if "exit 0" in source or "/usr/bin/true {0}" in source:
    raise SystemExit("trusted validator rejected workflow bypass")
print("TRUSTED_VALIDATOR=PASS")
"""
SAFE_WORKFLOW = "name: trusted\non: workflow_dispatch\njobs: {}\n"
TEST_REPOSITORY = "GUF296/tb321fu-haptics-debs"
TEST_REF = "codex/trusted-gate-test"
TEST_DISPATCH_ID = "0123456789abcdef0123456789abcdef"
TEST_AUTHENTICATED_LOGIN = "fixture-user"
FIXTURE_PROCESS_TIMEOUT_SECONDS = 10.0
FIXTURE_PROCESS_OUTPUT_BYTES = 1024 * 1024
FIXTURE_PROCESS_TABLE_LIMIT = 131072
FIXTURE_PROCESS_LIMIT = 4096
FIXTURE_OWNER_LIMIT = 1024
FIXTURE_OWNER_DRAIN_LIMIT = 4096
FIXTURE_OWNER_SETTLEMENT_ROUNDS = 4
FIXTURE_PROCESS_PASSES = 40
FIXTURE_PIDFD_BATCH = 32
FIXTURE_SIGNAL_POLL_SECONDS = 0.05
FIXTURE_PENDING_SIGNAL_DRAIN_LIMIT = 64
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
PROCESS_IDENTITY_HELPER = (
    "def record_identity(path):\n"
    "    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)\n"
    "    descriptor = os.open('/proc/self/stat', flags)\n"
    "    chunks = []\n"
    "    total = 0\n"
    "    interruptions = 0\n"
    "    active = None\n"
    "    try:\n"
    "        while total <= 4096:\n"
    "            try:\n"
    "                chunk = os.read(descriptor, 4097 - total)\n"
    "            except InterruptedError:\n"
    "                interruptions += 1\n"
    "                if interruptions > 3:\n"
    "                    raise SystemExit('fixture process identity read did not converge')\n"
    "                continue\n"
    "            if not chunk:\n"
    "                break\n"
    "            chunks.append(chunk)\n"
    "            total += len(chunk)\n"
    "            if total > 4096:\n"
    "                raise SystemExit('fixture process identity exceeds its bound')\n"
    "        else:\n"
    "            raise SystemExit('fixture process identity exceeds its bound')\n"
    "    except BaseException as exc:\n"
    "        active = exc\n"
    "    close_failure = None\n"
    "    closed = False\n"
    "    for _ in range(3):\n"
    "        try:\n"
    "            os.close(descriptor)\n"
    "        except BaseException as exc:\n"
    "            if close_failure is None or (not isinstance(exc, Exception) and isinstance(close_failure, Exception)):\n"
    "                close_failure = exc\n"
    "            try:\n"
    "                os.fstat(descriptor)\n"
    "            except OSError as probe:\n"
    "                if probe.errno == 9:\n"
    "                    closed = True\n"
    "                    break\n"
    "            except BaseException as probe:\n"
    "                if close_failure is None or (not isinstance(probe, Exception) and isinstance(close_failure, Exception)):\n"
    "                    close_failure = probe\n"
    "            continue\n"
    "        closed = True\n"
    "        break\n"
    "    if not closed:\n"
    "        raise SystemExit('fixture process identity descriptor close did not converge')\n"
    "    if close_failure is not None and (active is None or (not isinstance(close_failure, Exception) and isinstance(active, Exception))):\n"
    "        raise close_failure\n"
    "    if active is not None:\n"
    "        raise active\n"
    "    raw = b''.join(chunks)\n"
    "    closing = raw.rfind(b') ')\n"
    "    fields = raw[closing + 2:].split() if closing > 0 else []\n"
    "    if len(fields) < 20 or not fields[19].isascii() or not fields[19].isdigit():\n"
    "        raise SystemExit('cannot record fixture process identity')\n"
    "    pathlib.Path(path).write_text(\n"
    "        f'{os.getpid()}\\t{fields[19].decode(\"ascii\")}\\n', encoding='ascii'\n"
    "    )\n"
)


class FixtureCleanupError(Exception):
    """Internal fixture containment failure, never caller cancellation."""


def fixture_register_owner(owner) -> None:
    if not _FIXTURE_OWNER_SCOPES:
        raise FixtureCleanupError(
            "dispatch fixture owner was created outside a lifetime scope"
        )
    scope = _FIXTURE_OWNER_SCOPES[-1]
    if len(scope) >= FIXTURE_OWNER_LIMIT:
        raise FixtureCleanupError("dispatch fixture owner scope exceeds its bound")
    scope.append(owner)


class FixtureDescriptorOwner:
    def __init__(self) -> None:
        self.descriptor = -1
        fixture_register_owner(self)


class FixtureChildOwner:
    def __init__(self) -> None:
        self.pid = -1
        fixture_register_owner(self)


class FixturePopenOwner:
    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        fixture_register_owner(self)


def _fixture_local_descriptor_owner() -> FixtureDescriptorOwner:
    """Create custody for a helper that owns an unconditional local finalizer."""
    owner = object.__new__(FixtureDescriptorOwner)
    owner.descriptor = -1
    return owner


_FIXTURE_OWNER_SCOPES: list[
    list[FixtureDescriptorOwner | FixtureChildOwner | FixturePopenOwner]
] = []


class FixturePublicFailure(SystemExit):
    """Public conversion of internal fixture policy, never caller cancellation."""


class FixtureOwnerCancellation(BaseException):
    """Internal owner-scope unwind; converted after custody is settled."""

    def __init__(self, caller_policy: BaseException | None) -> None:
        super().__init__()
        self.caller_policy = caller_policy


def fixture_owner_scoped(function):
    def scoped(*args, **kwargs):
        with fixture_owner_lifetime(function.__name__):
            return function(*args, **kwargs)

    return scoped


def fixture_check_owner_scope_source(source: str) -> None:
    tree = ast.parse(source, filename=__file__)
    owner_calls = {
        "FixtureDescriptorOwner",
        "FixtureChildOwner",
        "FixturePopenOwner",
        "acquire_existing_fixture_descriptor",
        "acquire_fixture_pidfd",
        "spawn_fixture_child",
        "spawn_fixture_popen",
        "_fixture_local_descriptor_owner",
    }
    raw_primitives = {
        ("os", "fork"): {"spawn_fixture_child"},
        ("os", "pidfd_open"): {"acquire_fixture_pidfd"},
        ("subprocess", "Popen"): {"run", "spawn_fixture_popen"},
    }
    primitive_probe_functions = {
        "test_direct_fork_custody",
        "test_direct_popen_custody",
        "test_fixture_async_signal_custody",
        "test_fixture_cleanup_faults",
        "test_fixture_owner_fairness_and_capacity",
        "test_fixture_subprocess_bounds",
    }
    local_owner_callers = {
        "fixture_cleanup_descendants",
        "run",
    }

    def containing_function(node: ast.AST) -> str | None:
        current = parents.get(node)
        while current is not None:
            if isinstance(current, ast.Lambda):
                return "<lambda>"
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent = parents.get(current)
                if isinstance(parent, ast.ClassDef):
                    return f"{parent.name}.{current.name}"
                return current.name
            current = parents.get(current)
        return None

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            aliases = node.names
            if isinstance(node, ast.ImportFrom) and node.module in (
                "os",
                "subprocess",
            ):
                if any(
                    alias.name in {"fork", "pidfd_open", "Popen"}
                    for alias in aliases
                ):
                    raise SystemExit(
                        "dispatch raw process primitive import is forbidden"
                    )
            if isinstance(node, ast.Import) and any(
                alias.name in {"os", "subprocess"} and alias.asname
                for alias in aliases
            ):
                raise SystemExit(
                    "dispatch process module aliases are forbidden"
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                primitive = (node.func.value.id, node.func.attr)
                if primitive in raw_primitives:
                    caller = containing_function(node)
                    if caller not in raw_primitives[primitive]:
                        raise SystemExit(
                            "dispatch raw process primitive escaped its wrapper: "
                            f"{primitive[0]}.{primitive[1]} in {caller}"
                        )
            if node.func.attr in {"fork", "pidfd_open", "Popen"} and not (
                isinstance(node.func.value, ast.Name)
                and (node.func.value.id, node.func.attr) in raw_primitives
            ):
                raise SystemExit(
                    "dispatch dynamic process primitive attribute is forbidden"
                )
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in {"globals", "locals", "vars"}
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in {
                "FixtureDescriptorOwner",
                "FixtureChildOwner",
                "FixturePopenOwner",
                "acquire_existing_fixture_descriptor",
                "acquire_fixture_pidfd",
                "spawn_fixture_child",
                "spawn_fixture_popen",
                "_fixture_local_descriptor_owner",
                "fork",
                "pidfd_open",
                "Popen",
            }
            and containing_function(node) not in primitive_probe_functions
        ):
            raise SystemExit("dispatch dynamic owner/process lookup is forbidden")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in {
                "FixtureDescriptorOwner",
                "FixtureChildOwner",
                "FixturePopenOwner",
                "acquire_existing_fixture_descriptor",
                "acquire_fixture_pidfd",
                "spawn_fixture_child",
                "spawn_fixture_popen",
                "_fixture_local_descriptor_owner",
                "fork",
                "pidfd_open",
                "Popen",
            }
        ):
            raise SystemExit("dispatch dynamic owner/process lookup is forbidden")
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            if isinstance(value, ast.Name) and value.id in {
                "FixtureDescriptorOwner",
                "FixtureChildOwner",
                "FixturePopenOwner",
                "acquire_existing_fixture_descriptor",
                "acquire_fixture_pidfd",
                "spawn_fixture_child",
                "spawn_fixture_popen",
                "_fixture_local_descriptor_owner",
            }:
                raise SystemExit("dispatch owner/process callable alias is forbidden")
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and (value.value.id, value.attr) in raw_primitives
                and containing_function(node) not in primitive_probe_functions
            ):
                raise SystemExit("dispatch raw process primitive alias is forbidden")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in owner_calls
        ):
            current = parents.get(node)
            while current is not None:
                if isinstance(current, ast.Lambda):
                    raise SystemExit(
                        "dispatch class/lambda owner acquisition is forbidden"
                    )
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    class_parent = parents.get(current)
                    if isinstance(class_parent, ast.ClassDef):
                        raise SystemExit(
                            "dispatch class/lambda owner acquisition is forbidden"
                        )
                    outer = parents.get(current)
                    while outer is not None and not isinstance(
                        outer,
                        (ast.FunctionDef, ast.AsyncFunctionDef),
                    ):
                        outer = parents.get(outer)
                    if outer is not None and not (
                        (current.name, outer.name)
                        in {
                            (
                                "run_case",
                                "test_fixture_owner_finalizer_cancellation",
                            ),
                            (
                                "observed_popen",
                                "test_post_popen_cancellation",
                            ),
                        }
                    ):
                        raise SystemExit(
                            "dispatch nested owner acquisition escaped its allowlist"
                        )
                    break
                current = parents.get(current)
    top_level_functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    calls_by_function = {
        name: {
            node.func.id
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in top_level_functions
        }
        for name, function in top_level_functions.items()
    }
    owner_functions = {
        name
        for name, function in top_level_functions.items()
        if any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in owner_calls
            for node in ast.walk(function)
        )
    }
    changed = True
    while changed:
        changed = False
        for name, called in calls_by_function.items():
            if name not in owner_functions and called & owner_functions:
                owner_functions.add(name)
                changed = True
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_fixture_local_descriptor_owner"
            and containing_function(node) not in local_owner_callers
        ):
            raise SystemExit(
                "dispatch local owner factory escaped its allowlist: "
                f"{containing_function(node)}"
            )
    for function in (
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
        and node.name != "test_fixture_owner_scope_ast"
    ):
        uses_owner = function.name in owner_functions
        if uses_owner and isinstance(function, ast.AsyncFunctionDef):
            raise SystemExit(
                "dispatch async owner-bearing test requires an async lifetime"
            )
        if uses_owner and any(
            isinstance(node, (ast.Yield, ast.YieldFrom))
            for node in ast.walk(function)
        ):
            raise SystemExit(
                "dispatch deferred owner-bearing test is not permitted"
            )
        decorated = any(
            isinstance(decorator, ast.Name)
            and decorator.id == "fixture_owner_scoped"
            for decorator in function.decorator_list
        )
        explicit_scope = any(
            isinstance(node, ast.With)
            and any(
                isinstance(item.context_expr, ast.Call)
                and isinstance(item.context_expr.func, ast.Name)
                and item.context_expr.func.id == "fixture_owner_lifetime"
                for item in node.items
            )
            for node in ast.walk(function)
        )
        if uses_owner and not (decorated or explicit_scope):
            raise SystemExit(
                f"dispatch fixture owner-bearing test lacks lifetime scope: "
                f"{function.name}"
            )

    reader = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "read_fixture_process_identity"
        ),
        None,
    )
    if reader is None:
        raise SystemExit("dispatch fixture bounded identity reader is unavailable")
    reader_parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(reader):
        for child in ast.iter_child_nodes(parent):
            reader_parents[child] = parent
    acquisition = next(
        (
            node
            for node in ast.walk(reader)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "acquire_existing_fixture_descriptor"
        ),
        None,
    )
    if acquisition is None:
        raise SystemExit("dispatch fixture identity reader lacks owned acquisition")
    ancestor = reader_parents.get(acquisition)
    protected = False
    while ancestor is not None:
        if isinstance(ancestor, ast.Try) and any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "settle_fixture_descriptor_owner"
            for statement in ancestor.finalbody
            for node in ast.walk(statement)
        ):
            protected = True
            break
        ancestor = reader_parents.get(ancestor)
    if not protected:
        raise SystemExit(
            "dispatch fixture identity reader lacks outer-finally custody"
        )


def test_fixture_owner_scope_ast() -> None:
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    fixture_check_owner_scope_source(source)
    mutations = {
        "raw-fork": "def test_mutation():\n    return os.fork()\n",
        "raw-popen": (
            "def test_mutation():\n"
            "    return subprocess.Popen(['/usr/bin/true'])\n"
        ),
        "raw-pidfd": (
            "def test_mutation():\n"
            "    return os.pidfd_open(os.getpid(), 0)\n"
        ),
        "import-alias": (
            "def test_mutation():\n"
            "    import os as operating_system\n"
            "    return operating_system.fork()\n"
        ),
        "direct-import": (
            "def test_mutation():\n"
            "    from subprocess import Popen\n"
            "    return Popen(['/usr/bin/true'])\n"
        ),
        "owner-alias": (
            "def test_mutation():\n"
            "    make = FixtureChildOwner\n"
            "    return make()\n"
        ),
        "local-owner-method": (
            "class Mutation:\n"
            "    def run(self):\n"
            "        return _fixture_local_descriptor_owner()\n"
        ),
        "owner-method": (
            "class Mutation:\n"
            "    def run(self):\n"
            "        return FixtureChildOwner()\n"
        ),
        "owner-lambda": "test_mutation = lambda: FixtureChildOwner()\n",
        "owner-nested": (
            "def test_mutation():\n"
            "    def inner():\n"
            "        return FixtureChildOwner()\n"
            "    return inner()\n"
        ),
        "primitive-alias": (
            "def test_mutation():\n"
            "    spawn = os.fork\n"
            "    return spawn()\n"
        ),
        "dynamic-owner": (
            "def test_mutation():\n"
            "    return globals()['FixtureChildOwner']()\n"
        ),
        "dynamic-primitive": (
            "def test_mutation():\n"
            "    return getattr(os, 'fork')()\n"
        ),
        "nested": (
            "def test_mutation():\n"
            "    def inner():\n"
            "        return os.pidfd_open(os.getpid(), 0)\n"
            "    return inner()\n"
        ),
        "method": (
            "class Mutation:\n"
            "    def run(self):\n"
            "        return subprocess.Popen(['/usr/bin/true'])\n"
        ),
        "lambda": "test_mutation = lambda: os.fork()\n",
    }
    for label, mutation in mutations.items():
        try:
            fixture_check_owner_scope_source(source + "\n" + mutation)
        except SystemExit:
            pass
        else:
            raise SystemExit(
                f"dispatch owner/process AST mutation was accepted: {label}"
            )


def fixture_get_subreaper() -> bool:
    current = ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
        raise FixtureCleanupError("dispatch fixture cannot inspect subreaper state")
    return bool(current.value)


def fixture_set_subreaper(enabled: bool) -> bool:
    previous = fixture_get_subreaper()
    libc = ctypes.CDLL(None, use_errno=True)
    if previous != enabled and libc.prctl(
        PR_SET_CHILD_SUBREAPER,
        int(enabled),
        0,
        0,
        0,
    ) != 0:
        raise FixtureCleanupError("dispatch fixture cannot set subreaper state")
    return previous


def fixture_read_process_record(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    interruptions = 0
    while total <= 4096:
        try:
            chunk = os.read(descriptor, 4097 - total)
        except InterruptedError:
            interruptions += 1
            if interruptions > 3:
                raise FixtureCleanupError(
                    "dispatch fixture process record read did not converge"
                )
            continue
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > 4096:
            raise FixtureCleanupError(
                "dispatch fixture process record exceeds its bound"
            )
    raise FixtureCleanupError("dispatch fixture process record exceeds its bound")


def fixture_process_map() -> dict[int, tuple[int, int]]:
    processes: dict[int, tuple[int, int]] = {}
    process_table_baseline = fixture_open_descriptor_set()
    process_table_metadata = os.stat("/proc", follow_symlinks=False)
    count = 0
    entries = None
    scan_primary: BaseException | None = None
    try:
        entries = os.scandir("/proc")
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            count += 1
            if count > FIXTURE_PROCESS_TABLE_LIMIT:
                raise FixtureCleanupError(
                    "dispatch fixture process table exceeds its bound"
                )
            pid = int(entry.name, 10)
            descriptor = -1
            raw = b""
            skipped = False
            primary: BaseException | None = None
            record_path = f"/proc/{pid}/stat"
            try:
                record_metadata = os.stat(record_path, follow_symlinks=False)
                record_baseline = fixture_open_descriptor_set()
                try:
                    descriptor = os.open(
                        record_path,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                except BaseException as exc:
                    disappearance = isinstance(
                        exc,
                        (FileNotFoundError, ProcessLookupError),
                    )
                    if disappearance or not isinstance(exc, Exception):
                        primary = exc
                    else:
                        primary = FixtureCleanupError(
                            f"dispatch fixture cannot inspect process record {pid}"
                        )
                        primary.__cause__ = exc
                    notes_before = tuple(getattr(primary, "__notes__", ()))
                    primary = fixture_recover_descriptor_handoff(
                        record_baseline,
                        (record_metadata.st_dev, record_metadata.st_ino),
                        primary,
                        "dispatch fixture process-record open",
                    )
                    if disappearance and tuple(
                        getattr(primary, "__notes__", ())
                    ) == notes_before:
                        skipped = True
                        primary = None
                if descriptor >= 0:
                    opened_metadata = os.fstat(descriptor)
                    if (
                        opened_metadata.st_dev,
                        opened_metadata.st_ino,
                    ) != (
                        record_metadata.st_dev,
                        record_metadata.st_ino,
                    ):
                        raise FixtureCleanupError(
                            f"dispatch fixture process record {pid} changed"
                        )
                    raw = fixture_read_process_record(descriptor)
            except (FileNotFoundError, ProcessLookupError):
                skipped = True
            except OSError as exc:
                primary = FixtureCleanupError(
                    f"dispatch fixture cannot inspect process record {pid}"
                )
                primary.__cause__ = exc
            except BaseException as exc:
                primary = exc
            if descriptor >= 0:
                primary = fixture_settle_owned_descriptor(
                    descriptor,
                    primary,
                    "dispatch fixture process record close failed",
                )
            if primary is not None:
                raise primary
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
                raise FixtureCleanupError(
                    f"dispatch fixture process record {pid} is malformed"
                )
            processes[pid] = (int(fields[1], 10), int(fields[19], 10))
    except BaseException as exc:
        scan_primary = exc
        if entries is None:
            scan_primary = fixture_recover_descriptor_handoff(
                process_table_baseline,
                (process_table_metadata.st_dev, process_table_metadata.st_ino),
                scan_primary,
                "dispatch fixture process-table iterator open",
            )
    if entries is not None:
        scan_primary = fixture_settle_scandir_iterator(
            entries,
            scan_primary,
            "dispatch fixture process-table iterator",
        )
    if scan_primary is not None:
        raise scan_primary
    return processes


def fixture_process_start_time(pid: int) -> int:
    record = fixture_process_map().get(pid)
    if record is None or record[1] <= 0:
        raise FixtureCleanupError(
            "dispatch fixture process identity is unavailable"
        )
    return record[1]


def fixture_owned_processes(
    baseline_children: frozenset[int],
    *,
    process_map: dict[int, tuple[int, int]] | None = None,
) -> dict[int, int]:
    processes = fixture_process_map() if process_map is None else process_map
    owner = os.getpid()
    ordered_processes = sorted(processes.items())
    children: dict[int, list[tuple[int, int]]] = {}
    direct: list[tuple[int, int]] = []
    for pid, (parent, start_time) in ordered_processes:
        children.setdefault(parent, []).append((pid, start_time))
        if parent == owner and pid not in baseline_children:
            direct.append((pid, start_time))
    owned = dict(direct[:FIXTURE_PROCESS_LIMIT])
    queue = list(owned)
    cursor = 0
    while cursor < len(queue) and len(owned) < FIXTURE_PROCESS_LIMIT:
        parent = queue[cursor]
        cursor += 1
        for pid, start_time in children.get(parent, ()):
            if pid not in owned and pid not in baseline_children:
                owned[pid] = start_time
                queue.append(pid)
                if len(owned) >= FIXTURE_PROCESS_LIMIT:
                    break
    return owned


def fixture_reap_owned(pids: set[int]) -> None:
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


def fixture_choose_failure(
    current: BaseException | None,
    new: BaseException,
    note: str,
) -> BaseException:
    if current is None:
        return new
    current_is_caller_policy = (
        not isinstance(current, Exception)
        and not isinstance(current, FixturePublicFailure)
    )
    new_is_caller_policy = (
        not isinstance(new, Exception)
        and not isinstance(new, FixturePublicFailure)
    )
    if new_is_caller_policy and not current_is_caller_policy:
        new.add_note(note)
        if new.__cause__ is None and isinstance(current, Exception):
            new.__cause__ = current
        return new
    if current_is_caller_policy:
        if new is not current:
            current.add_note(note)
        return current
    if not isinstance(new, Exception) and isinstance(current, Exception):
        new.add_note(note)
        if new.__cause__ is None:
            new.__cause__ = current
        return new
    if new is not current:
        current.add_note(note)
    return current


def fixture_raise_selected_failure(primary: BaseException) -> None:
    if isinstance(primary, FixtureCleanupError):
        failure = FixturePublicFailure(str(primary))
        for note in getattr(primary, "__notes__", ()):
            failure.add_note(note)
        failure.__cause__ = (
            primary.__cause__ if primary.__cause__ is not None else primary
        )
        raise failure
    raise primary


def fixture_close_owned_descriptor(
    descriptor: int,
) -> tuple[BaseException | None, bool]:
    first_error: BaseException | None = None
    for _ in range(3):
        try:
            os.close(descriptor)
        except BaseException as exc:
            first_error = fixture_choose_failure(
                first_error,
                exc,
                "dispatch fixture descriptor close also failed",
            )
            try:
                os.fstat(descriptor)
            except BaseException as probe:
                if isinstance(probe, OSError) and probe.errno == errno.EBADF:
                    return first_error, True
                first_error = fixture_choose_failure(
                    first_error,
                    probe,
                    "dispatch fixture descriptor custody probe also failed",
                )
            continue
        return first_error, True
    try:
        os.fstat(descriptor)
    except BaseException as probe:
        if isinstance(probe, OSError) and probe.errno == errno.EBADF:
            return first_error, True
        first_error = fixture_choose_failure(
            first_error,
            probe,
            "dispatch fixture final descriptor custody probe also failed",
        )
    return first_error, False


def fixture_settle_owned_descriptor(
    descriptor: int,
    primary: BaseException | None,
    message: str,
) -> BaseException | None:
    close_error, closed = fixture_close_owned_descriptor(descriptor)
    if close_error is not None:
        if not isinstance(close_error, Exception):
            candidate = close_error
        else:
            candidate = FixtureCleanupError(message)
            candidate.__cause__ = close_error
        primary = fixture_choose_failure(
            primary,
            candidate,
            f"{message}; an earlier fixture failure also occurred",
        )
    if not closed:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{message} and did not converge"),
            f"{message}; descriptor custody also did not converge",
        )
    return primary


def settle_fixture_descriptor_owner(
    owner: FixtureDescriptorOwner,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    if owner.descriptor < 0:
        return primary
    close_error, closed = fixture_close_owned_descriptor(owner.descriptor)
    if close_error is not None:
        primary = fixture_choose_failure(
            primary,
            close_error,
            f"{label} close failed",
        )
    if not closed:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{label} close did not converge"),
            f"{label} custody also did not converge",
        )
    else:
        owner.descriptor = -1
    return primary


def acquire_existing_fixture_descriptor(
    owner: FixtureDescriptorOwner,
    path: os.PathLike[str] | str,
    flags: int,
    identity: tuple[int, int],
    label: str,
) -> None:
    if owner.descriptor >= 0:
        raise FixtureCleanupError(f"{label} owner is already populated")
    baseline = fixture_open_descriptor_set()
    try:
        owner.descriptor = os.open(path, flags)
        metadata = os.fstat(owner.descriptor)
        if (
            (metadata.st_dev, metadata.st_ino) != identity
            or os.get_inheritable(owner.descriptor)
        ):
            raise FixtureCleanupError(f"{label} identity differs from policy")
    except BaseException as exc:
        selected: BaseException | None = exc
        if owner.descriptor >= 0:
            selected = settle_fixture_descriptor_owner(owner, selected, label)
        else:
            selected = fixture_recover_descriptor_handoff(
                baseline,
                identity,
                exc,
                label,
            )
        assert selected is not None
        raise selected


def read_bounded_fixture_descriptor(
    descriptor: int,
    limit: int,
    label: str,
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
                raise FixtureCleanupError(f"{label} read did not converge")
            continue
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise FixtureCleanupError(f"{label} exceeds its bound")
    raise FixtureCleanupError(f"{label} exceeds its bound")


def read_fixture_process_identity(
    path: pathlib.Path,
    label: str,
) -> tuple[int, int]:
    try:
        namespace = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(f"dispatch fixture {label} identity is unavailable") from exc
    if not stat.S_ISREG(namespace.st_mode) or namespace.st_size > 128:
        raise SystemExit(f"dispatch fixture {label} identity is malformed")
    owner = FixtureDescriptorOwner()
    primary: BaseException | None = None
    raw = b""
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        acquire_existing_fixture_descriptor(
            owner,
            path,
            flags,
            (namespace.st_dev, namespace.st_ino),
            f"dispatch fixture {label} identity open",
        )
        before = os.fstat(owner.descriptor)
        raw = read_bounded_fixture_descriptor(
            owner.descriptor,
            128,
            f"dispatch fixture {label} identity",
        )
        after = os.fstat(owner.descriptor)
        final_namespace = os.stat(path, follow_symlinks=False)
        if (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (after.st_dev, after.st_ino) != (
            final_namespace.st_dev,
            final_namespace.st_ino,
        ):
            raise FixtureCleanupError(
                f"dispatch fixture {label} identity changed during read"
            )
    except BaseException as exc:
        primary = exc
    finally:
        primary = settle_fixture_descriptor_owner(
            owner,
            primary,
            f"dispatch fixture {label} identity",
        )
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        if isinstance(primary, SystemExit):
            raise primary
        raise SystemExit(
            f"dispatch fixture {label} identity is malformed"
        ) from primary
    fields = raw.split(b"\t")
    if (
        len(raw) > 128
        or len(fields) != 2
        or not fields[0].isascii()
        or not fields[0].isdigit()
        or not fields[1].endswith(b"\n")
        or not fields[1][:-1].isascii()
        or not fields[1][:-1].isdigit()
    ):
        raise SystemExit(f"dispatch fixture {label} identity is malformed")
    pid = int(fields[0], 10)
    start_time = int(fields[1][:-1], 10)
    if pid <= 1 or start_time <= 0:
        raise SystemExit(f"dispatch fixture {label} identity is outside its bound")
    return pid, start_time


def fixture_settle_scandir_iterator(
    entries,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    closed = False
    for _ in range(3):
        try:
            entries.close()
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} close also failed",
            )
            continue
        closed = True
        break
    if not closed:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{label} close did not converge"),
            f"{label} custody also did not converge",
        )
    return primary


def fixture_trusted_fd_snapshot(
    partial_descriptors: set[int] | None = None,
) -> frozenset[int]:
    descriptors: set[int] = set()
    entries = None
    primary: BaseException | None = None
    try:
        entries = _ORIGINAL_SCANDIR("/proc/self/fd")
        count = 0
        for entry in entries:
            count += 1
            if count > FIXTURE_PROCESS_LIMIT:
                raise FixtureCleanupError(
                    "dispatch fixture descriptor table exceeds its bound"
                )
            if entry.name.isascii() and entry.name.isdecimal():
                descriptor = int(entry.name, 10)
                descriptors.add(descriptor)
                if partial_descriptors is not None:
                    partial_descriptors.add(descriptor)
    except BaseException as exc:
        primary = exc
    if entries is not None:
        primary = fixture_settle_scandir_iterator(
            entries,
            primary,
            "trusted dispatch fixture descriptor-table iterator",
        )
    if primary is not None:
        fixture_raise_selected_failure(primary)
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            live.add(descriptor)
    return frozenset(live)


def fixture_recover_scandir_acquisition(
    before: frozenset[int],
    identity: tuple[int, int],
    primary: BaseException,
    label: str,
) -> BaseException:
    partial_descriptors: set[int] = set()
    try:
        after = fixture_trusted_fd_snapshot(partial_descriptors)
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    for descriptor in sorted(after - before):
        identity_matches: bool | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} recovery probe also failed",
            )
        else:
            identity_matches = (metadata.st_dev, metadata.st_ino) == identity
        primary = fixture_settle_owned_descriptor(
            descriptor,
            primary,
            f"{label} recovery close failed",
        )
        if identity_matches is None:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"{label} recovered descriptor identity is unknown"
                ),
                f"{label} recovery identity also became unknown",
            )
        elif not identity_matches:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"{label} recovered an unexpected descriptor"
                ),
                f"{label} recovery identity also differed",
            )
    return primary


def acquire_fixture_pidfd(
    owner: FixtureDescriptorOwner,
    pid: int,
    label: str,
) -> None:
    if owner.descriptor >= 0:
        raise FixtureCleanupError(f"{label} owner is already populated")
    before = fixture_open_descriptor_set()
    try:
        owner.descriptor = os.pidfd_open(pid, 0)
    except BaseException as exc:
        primary = exc
        if owner.descriptor >= 0:
            close_error, closed = fixture_close_owned_descriptor(owner.descriptor)
            if close_error is not None:
                primary = fixture_choose_failure(
                    primary,
                    close_error,
                    f"{label} owner close also failed",
                )
            if not closed:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(f"{label} owner close did not converge"),
                    f"{label} owner custody also did not converge",
                )
            else:
                owner.descriptor = -1
        else:
            partial_descriptors: set[int] = set()
            try:
                after = fixture_open_descriptor_set(partial_descriptors)
            except BaseException as scan_exc:
                primary = fixture_choose_failure(
                    primary,
                    scan_exc,
                    f"{label} recovery scan also failed",
                )
                after = frozenset(partial_descriptors)
            for descriptor in sorted(after - before):
                try:
                    target = os.readlink(f"/proc/self/fd/{descriptor}")
                except BaseException as probe_exc:
                    primary = fixture_choose_failure(
                        primary,
                        probe_exc,
                        f"{label} recovery probe also failed",
                    )
                    target = None
                primary = fixture_settle_owned_descriptor(
                    descriptor,
                    primary,
                    f"{label} recovery close failed",
                )
                if target != "anon_inode:[pidfd]":
                    primary = fixture_choose_failure(
                        primary,
                        FixtureCleanupError(
                            f"{label} recovered an unexpected descriptor"
                        ),
                        f"{label} recovery identity also differed",
                    )
        fixture_raise_selected_failure(primary)


def fixture_recover_descriptor_handoff(
    before: frozenset[int],
    identity: tuple[int, int],
    primary: BaseException,
    label: str,
) -> BaseException:
    partial_descriptors: set[int] = set()
    try:
        after = fixture_open_descriptor_set(partial_descriptors)
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial_descriptors)
    for descriptor in sorted(after - before):
        identity_matches: bool | None = None
        try:
            metadata = os.fstat(descriptor)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} recovery probe also failed",
            )
        else:
            identity_matches = (metadata.st_dev, metadata.st_ino) == identity
        primary = fixture_settle_owned_descriptor(
            descriptor,
            primary,
            f"{label} recovery close failed",
        )
        if identity_matches is None:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"{label} recovered descriptor identity is unknown"
                ),
                f"{label} recovery identity also became unknown",
            )
        elif not identity_matches:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"{label} recovered an unexpected descriptor"
                ),
                f"{label} recovery identity also differed",
            )
    return primary


def fixture_restore_subreaper(previous: bool) -> BaseException | None:
    first_error: BaseException | None = None
    for _ in range(3):
        try:
            fixture_set_subreaper(previous)
        except BaseException as exc:
            first_error = fixture_choose_failure(
                first_error,
                exc,
                "dispatch fixture subreaper restore also failed",
            )
            continue
        return first_error
    return first_error


def fixture_cleanup_descendants(
    baseline_children: frozenset[int],
) -> bool:
    found = False
    cleanup_error: BaseException | None = None

    def remember(exc: BaseException) -> None:
        nonlocal cleanup_error
        cleanup_error = fixture_choose_failure(
            cleanup_error,
            exc,
            "dispatch fixture descendant cleanup also failed",
        )

    for _ in range(FIXTURE_PROCESS_PASSES):
        try:
            owned = fixture_owned_processes(baseline_children)
        except BaseException as exc:
            remember(exc)
            continue
        if not owned:
            if cleanup_error is not None:
                if not isinstance(cleanup_error, Exception):
                    raise cleanup_error
                failure = FixtureCleanupError(
                    "dispatch fixture descendant cleanup encountered errors"
                )
                failure.__cause__ = cleanup_error
                raise failure
            return found
        found = True
        ordered = sorted(owned.items())
        for offset in range(0, len(ordered), FIXTURE_PIDFD_BATCH):
            pinned: list[tuple[int, int, FixtureDescriptorOwner]] = []
            try:
                for pid, expected_start_time in ordered[
                    offset:offset + FIXTURE_PIDFD_BATCH
                ]:
                    owner = _fixture_local_descriptor_owner()
                    pinned.append((pid, expected_start_time, owner))
                    try:
                        acquire_fixture_pidfd(
                            owner,
                            pid,
                            "dispatch fixture descendant pidfd handoff",
                        )
                    except ProcessLookupError:
                        pinned.pop()
                        continue
                    except BaseException as exc:
                        registered_owner = pinned.pop()[2]
                        if registered_owner.descriptor >= 0:
                            close_error, closed = fixture_close_owned_descriptor(
                                registered_owner.descriptor
                            )
                            if close_error is not None:
                                exc = fixture_choose_failure(
                                    exc,
                                    close_error,
                                    "dispatch fixture descendant pidfd "
                                    "registration close also failed",
                                )
                            if not closed:
                                exc = fixture_choose_failure(
                                    exc,
                                    FixtureCleanupError(
                                        "dispatch fixture descendant pidfd "
                                        "registration did not converge"
                                    ),
                                    "dispatch fixture descendant pidfd "
                                    "registration custody also did not converge",
                                )
                            else:
                                registered_owner.descriptor = -1
                        remember(exc)
                        continue
                try:
                    current = fixture_owned_processes(baseline_children)
                except BaseException as exc:
                    remember(exc)
                    current = {}
                for pid, expected_start_time, owner in pinned:
                    descriptor = owner.descriptor
                    if current.get(pid) != expected_start_time:
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
                for _, _, owner in pinned:
                    if owner.descriptor < 0:
                        continue
                    close_error, closed = fixture_close_owned_descriptor(
                        owner.descriptor
                    )
                    if close_error is not None:
                        remember(close_error)
                    if closed:
                        owner.descriptor = -1
        try:
            fixture_reap_owned(set(owned))
        except BaseException as exc:
            remember(exc)
        try:
            time.sleep(0.01)
        except BaseException as exc:
            remember(exc)
    remaining_unknown = False
    try:
        remaining = fixture_owned_processes(baseline_children)
    except BaseException as exc:
        remember(exc)
        remaining = {}
        remaining_unknown = True
    if remaining:
        failure = FixtureCleanupError(
            "dispatch fixture descendant cleanup did not converge"
        )
        if cleanup_error is not None:
            selected = fixture_choose_failure(
                failure,
                cleanup_error,
                "dispatch fixture descendant cleanup did not converge",
            )
            if selected is failure:
                failure.__cause__ = cleanup_error
            raise selected
        raise failure
    if remaining_unknown or cleanup_error is not None:
        if cleanup_error is not None and not isinstance(cleanup_error, Exception):
            raise cleanup_error
        failure = FixtureCleanupError(
            "dispatch fixture descendant cleanup encountered errors"
        )
        failure.__cause__ = cleanup_error
        raise failure
    return found


def fixture_preflight_pidfd_capacity() -> None:
    descriptors: list[int] = []
    primary: BaseException | None = None
    try:
        for _ in range(FIXTURE_PIDFD_BATCH + 4):
            descriptors.append(-1)
            slot = len(descriptors) - 1
            local_descriptor = -1
            baseline = fixture_open_descriptor_set()
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
                    selected = fixture_settle_owned_descriptor(
                        owned_descriptor,
                        selected,
                        "dispatch fixture pidfd preflight handoff close failed",
                    )
                    descriptors[slot] = -1
                else:
                    selected = fixture_recover_descriptor_handoff(
                        baseline,
                        (null_metadata.st_dev, null_metadata.st_ino),
                        selected,
                        "dispatch fixture pidfd preflight open",
                    )
                assert selected is not None
                fixture_raise_selected_failure(selected)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            primary = exc
        else:
            primary = FixtureCleanupError(
                "dispatch fixture has insufficient pidfd capacity"
            )
            primary.__cause__ = exc
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        close_error, closed = fixture_close_owned_descriptor(descriptor)
        if close_error is not None:
            if primary is None:
                if not isinstance(close_error, Exception):
                    primary = close_error
                else:
                    primary = FixtureCleanupError(
                        "dispatch fixture pidfd preflight cleanup failed"
                    )
                    primary.__cause__ = close_error
            else:
                primary = fixture_choose_failure(
                    primary,
                    close_error,
                    "dispatch fixture pidfd preflight cleanup failed",
                )
        if not closed:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    "dispatch fixture pidfd preflight cleanup did not converge"
                ),
                "dispatch fixture pidfd preflight cleanup also failed",
            )
    if primary is not None:
        raise primary


class FixtureNativeSignalSet(ctypes.Structure):
    _fields_ = [("bits", ctypes.c_ulong * 16)]


def fixture_decode_native_signal_mask(mask: FixtureNativeSignalSet) -> frozenset[int]:
    libc = ctypes.CDLL(None, use_errno=True)
    return frozenset(
        int(signum)
        for signum in signal.valid_signals()
        if libc.sigismember(ctypes.byref(mask), int(signum)) == 1
    )


def fixture_atomic_capture_and_block(
    signals: frozenset[int],
    old_mask: FixtureNativeSignalSet,
    applied: list[bool],
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    new_mask = FixtureNativeSignalSet()
    if libc.sigemptyset(ctypes.byref(new_mask)) != 0:
        raise FixtureCleanupError("dispatch fixture cannot initialize signal custody")
    for signum in signals:
        if libc.sigaddset(ctypes.byref(new_mask), int(signum)) != 0:
            raise FixtureCleanupError("dispatch fixture cannot initialize signal custody")
    result = libc.pthread_sigmask(
        int(signal.SIG_BLOCK),
        ctypes.byref(new_mask),
        ctypes.byref(old_mask),
    )
    if result != 0:
        raise OSError(result, os.strerror(result))
    applied[0] = True


class FixtureSignalLatch:
    """Keep fixture cancellation non-throwing until containment is settled."""

    def __init__(self) -> None:
        self.signals = frozenset((signal.SIGINT, signal.SIGTERM))
        self.original_mask: frozenset[int] | None = None
        self.native_original_mask = FixtureNativeSignalSet()
        self.atomic_block_applied = [False]
        self.previous_handlers: dict[int, object] = {}
        self.installed_handlers: list[int] = []
        self.signum: int | None = None
        self.closed = False
        self.closing = False
        self.cleanup_failure: BaseException | None = None

    def record(self, signum: int, _frame=None) -> None:
        if self.signum is None or signum == signal.SIGINT:
            self.signum = signum

    def consume_pending(self) -> None:
        if not hasattr(signal, "sigtimedwait"):
            raise FixtureCleanupError(
                "dispatch fixture requires bounded pending-signal custody"
            )
        for _ in range(FIXTURE_PENDING_SIGNAL_DRAIN_LIMIT):
            try:
                pending = signal.sigtimedwait(self.signals, 0.0)
            except InterruptedError:
                continue
            if pending is None:
                return
            self.record(pending.si_signo)
        raise FixtureCleanupError(
            "dispatch fixture pending-signal custody did not converge"
        )

    def remember(
        self,
        primary: BaseException | None,
        exc: BaseException,
        message: str,
    ) -> BaseException:
        if not isinstance(exc, Exception):
            candidate = exc
        else:
            candidate = FixtureCleanupError(message)
            candidate.__cause__ = exc
        if self.closing:
            self.cleanup_failure = fixture_choose_failure(
                self.cleanup_failure,
                candidate,
                f"{message}; another signal-custody cleanup failure occurred",
            )
        return fixture_choose_failure(
            primary,
            candidate,
            f"{message}; an earlier fixture failure also occurred",
        )

    def enter(self) -> None:
        primary: BaseException | None = None
        try:
            fixture_atomic_capture_and_block(
                self.signals,
                self.native_original_mask,
                self.atomic_block_applied,
            )
            self.original_mask = fixture_decode_native_signal_mask(
                self.native_original_mask
            )
            self.previous_handlers = {
                signal.SIGINT: signal.getsignal(signal.SIGINT),
                signal.SIGTERM: signal.getsignal(signal.SIGTERM),
            }
            for signum in (signal.SIGINT, signal.SIGTERM):
                self.installed_handlers.append(signum)
                signal.signal(signum, self.record)
            self.consume_pending()
            signal.pthread_sigmask(signal.SIG_SETMASK, self.original_mask)
        except BaseException as exc:
            primary = self.remember(
                primary,
                exc,
                "dispatch fixture signal-custody setup failed",
            )
            if self.atomic_block_applied[0] and self.original_mask is None:
                try:
                    self.original_mask = fixture_decode_native_signal_mask(
                        self.native_original_mask
                    )
                except BaseException as recovery:
                    primary = self.remember(
                        primary,
                        recovery,
                        "dispatch fixture original signal-mask recovery failed",
                    )
        if primary is not None:
            primary = self.close(primary)
            assert primary is not None
            fixture_raise_selected_failure(primary)

    def close(
        self,
        primary: BaseException | None,
    ) -> BaseException | None:
        if self.closed:
            return primary
        self.closing = True
        cancellation_blocked = False
        if self.original_mask is not None:
            for _ in range(3):
                try:
                    signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
                except BaseException as exc:
                    primary = self.remember(
                        primary,
                        exc,
                        "dispatch fixture cancellation block failed",
                    )
                try:
                    current = frozenset(
                        signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    )
                except BaseException as exc:
                    primary = self.remember(
                        primary,
                        exc,
                        "dispatch fixture cancellation state inspection failed",
                    )
                    continue
                if self.signals <= current:
                    cancellation_blocked = True
                    break
            if not cancellation_blocked:
                primary = self.remember(
                    primary,
                    FixtureCleanupError(
                        "dispatch fixture cancellation block did not converge"
                    ),
                    "dispatch fixture cancellation block did not converge",
                )
        if cancellation_blocked:
            try:
                self.consume_pending()
            except BaseException as exc:
                primary = self.remember(
                    primary,
                    exc,
                    "dispatch fixture pending-signal cleanup failed",
                )
            for signum in reversed(self.installed_handlers):
                restored = False
                for _ in range(3):
                    try:
                        signal.signal(signum, self.previous_handlers[signum])
                        restored = True
                        break
                    except BaseException as exc:
                        primary = self.remember(
                            primary,
                            exc,
                            "dispatch fixture signal-handler restore failed",
                        )
                if not restored:
                    primary = self.remember(
                        primary,
                        FixtureCleanupError(
                            "dispatch fixture signal-handler restore did not converge"
                        ),
                        "dispatch fixture signal-handler restore did not converge",
                    )
            try:
                self.consume_pending()
            except BaseException as exc:
                primary = self.remember(
                    primary,
                    exc,
                    "dispatch fixture pending-signal handoff failed",
                )
        if self.original_mask is not None:
            mask_restored = False
            for _ in range(3):
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, self.original_mask)
                    mask_restored = True
                    break
                except BaseException as exc:
                    primary = self.remember(
                        primary,
                        exc,
                        "dispatch fixture signal-mask restore failed",
                    )
            if not mask_restored:
                primary = self.remember(
                    primary,
                    FixtureCleanupError(
                        "dispatch fixture signal-mask restore did not converge"
                    ),
                    "dispatch fixture signal-mask restore did not converge",
                )
        self.closed = True
        if self.cleanup_failure is not None and isinstance(
            primary,
            subprocess.TimeoutExpired,
        ):
            failure = FixtureCleanupError(
                "dispatch fixture signal-custody cleanup failed after timeout"
            )
            failure.__cause__ = self.cleanup_failure
            failure.add_note("dispatch fixture subprocess timeout occurred first")
            primary = failure
        if self.signum is not None:
            policy = FixturePublicFailure(128 + self.signum)
            primary = fixture_choose_failure(
                primary,
                policy,
                "dispatch fixture cancellation followed an earlier failure",
            )
        return primary


class FixtureOwnerSignalLatch(FixtureSignalLatch):
    """Unwind owner bodies immediately, then only latch during settlement."""

    def __init__(self) -> None:
        super().__init__()
        self.finalizer_only = False

    def record(self, signum: int, _frame=None) -> None:
        super().record(signum, _frame)
        if not self.finalizer_only:
            caller_policy = sys.exception()
            if isinstance(caller_policy, FixtureOwnerCancellation):
                caller_policy = caller_policy.caller_policy
            if isinstance(caller_policy, Exception) or isinstance(
                caller_policy,
                FixturePublicFailure,
            ):
                caller_policy = None
            raise FixtureOwnerCancellation(caller_policy)

    def begin_finalizer(self) -> None:
        self.finalizer_only = True


def fixture_open_descriptor_set(
    partial_descriptors: set[int] | None = None,
) -> frozenset[int]:
    table_path = "/proc/self/fd"
    table_metadata = os.stat(table_path, follow_symlinks=False)
    if not stat.S_ISDIR(table_metadata.st_mode):
        raise FixtureCleanupError(
            "dispatch fixture descriptor table is not a directory"
        )
    primary: BaseException | None = None
    parsed: set[int] = set()
    entries = None
    acquisition_before = fixture_trusted_fd_snapshot(partial_descriptors)
    try:
        entries = os.scandir(table_path)
        count = 0
        for entry in entries:
            count += 1
            if count > FIXTURE_PROCESS_LIMIT:
                raise FixtureCleanupError(
                    "dispatch fixture descriptor table exceeds its bound"
                )
            if not entry.name.isascii() or not entry.name.isdecimal():
                raise FixtureCleanupError(
                    "dispatch fixture descriptor table is malformed"
                )
            descriptor = int(entry.name, 10)
            if str(descriptor) != entry.name:
                raise FixtureCleanupError(
                    "dispatch fixture descriptor table is noncanonical"
                )
            parsed.add(descriptor)
            if partial_descriptors is not None:
                partial_descriptors.add(descriptor)
    except BaseException as exc:
        primary = exc
        if entries is None:
            primary = fixture_recover_scandir_acquisition(
                acquisition_before,
                (table_metadata.st_dev, table_metadata.st_ino),
                primary,
                "dispatch fixture descriptor-table acquisition",
            )
    if entries is not None:
        primary = fixture_settle_scandir_iterator(
            entries,
            primary,
            "dispatch fixture descriptor-table iterator",
        )
    if primary is not None:
        raise primary
    final_table_metadata = os.stat(table_path, follow_symlinks=False)
    if (
        final_table_metadata.st_dev,
        final_table_metadata.st_ino,
        stat.S_IFMT(final_table_metadata.st_mode),
    ) != (
        table_metadata.st_dev,
        table_metadata.st_ino,
        stat.S_IFMT(table_metadata.st_mode),
    ):
        raise FixtureCleanupError(
            "dispatch fixture descriptor table changed during enumeration"
        )
    live: set[int] = set()
    for descriptor in sorted(parsed):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise FixtureCleanupError(
                "dispatch fixture descriptor-table entry probe failed"
            ) from exc
        except BaseException:
            raise
        live.add(descriptor)
    return frozenset(live)


def run(
    *arguments: str,
    cwd: pathlib.Path,
    timeout_seconds: float = FIXTURE_PROCESS_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    signal_latch = FixtureSignalLatch()
    signal_latch.enter()
    try:
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise FixturePublicFailure(
                "dispatch fixture requires default SIGCHLD policy"
            )
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        previous_subreaper = fixture_get_subreaper()
    except BaseException as exc:
        selected = signal_latch.close(exc)
        assert selected is not None
        fixture_raise_selected_failure(selected)
    invoked = list(arguments)
    if invoked and invoked[0] == "/usr/bin/git":
        invoked = [invoked[0], "-C", str(cwd), *invoked[1:]]
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(cwd / "home"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    def impose_output_limit() -> None:
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (FIXTURE_PROCESS_OUTPUT_BYTES, FIXTURE_PROCESS_OUTPUT_BYTES),
        )

    try:
        fixture_set_subreaper(True)
    except BaseException as exc:
        restore_error = fixture_restore_subreaper(previous_subreaper)
        if restore_error is not None:
            exc = fixture_choose_failure(
                exc,
                restore_error,
                "dispatch fixture initial subreaper rollback also failed",
            )
        selected = signal_latch.close(exc)
        assert selected is not None
        fixture_raise_selected_failure(selected)
    setup_primary: BaseException | None = None
    baseline_children: frozenset[int] = frozenset()
    try:
        before = fixture_process_map()
        baseline_children = frozenset(
            pid for pid, (parent, _) in before.items() if parent == os.getpid()
        )
        if baseline_children:
            setup_primary = FixtureCleanupError(
                "dispatch fixture inherited pre-existing children"
            )
    except BaseException as exc:
        setup_primary = exc
    if setup_primary is not None:
        restore_error = fixture_restore_subreaper(previous_subreaper)
        if restore_error is not None:
            setup_primary = fixture_choose_failure(
                setup_primary,
                restore_error,
                "dispatch fixture setup subreaper restore failed; an earlier "
                "fixture failure also occurred",
            )
        selected = signal_latch.close(setup_primary)
        assert selected is not None
        fixture_raise_selected_failure(selected)
    process: subprocess.Popen[bytes] | None = None
    # run() owns and settles this descriptor in its own cleanup boundary;
    # callers include the unscoped fixture repository setup.
    root_pidfd = _fixture_local_descriptor_owner()
    timed_out = False
    leaked_descendants = False
    primary: BaseException | None = None
    containment_failed = False
    terminal_cancellation: BaseException | None = None
    stdout_size = 0
    stderr_size = 0
    stdout = b""
    stderr = b""

    def remember_cleanup(exc: BaseException, message: str) -> None:
        nonlocal primary, containment_failed
        containment_failed = True
        if not isinstance(exc, Exception):
            candidate = exc
        else:
            candidate = FixtureCleanupError(message)
            candidate.__cause__ = exc
        primary = fixture_choose_failure(
            primary,
            candidate,
            f"{message}; an earlier fixture failure also occurred",
        )
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            fixture_preflight_pidfd_capacity()
            try:
                process = subprocess.Popen(
                    invoked,
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=impose_output_limit,
                )
                acquire_fixture_pidfd(
                    root_pidfd,
                    process.pid,
                    "dispatch fixture root pidfd handoff",
                )
                wait_deadline = time.monotonic() + timeout_seconds
                while process.returncode is None and signal_latch.signum is None:
                    remaining = wait_deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        primary = subprocess.TimeoutExpired(
                            process.args,
                            timeout_seconds,
                        )
                        break
                    try:
                        process.wait(
                            timeout=min(remaining, FIXTURE_SIGNAL_POLL_SECONDS)
                        )
                    except subprocess.TimeoutExpired:
                        continue
                    break
            except BaseException as exc:
                if primary is None:
                    primary = exc
            finally:
                if process is not None:
                    poll_known = False
                    root_running = True
                    try:
                        root_running = process.poll() is None
                        poll_known = True
                    except BaseException as exc:
                        remember_cleanup(exc, "dispatch fixture root poll failed")
                    if root_running:
                        numeric_fallback = (
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
                                    "dispatch fixture root pidfd signal failed",
                                )
                                numeric_fallback = poll_known
                        if numeric_fallback:
                            numeric_running = False
                            try:
                                numeric_running = process.poll() is None
                            except BaseException as exc:
                                remember_cleanup(
                                    exc,
                                    "dispatch fixture root numeric custody poll failed",
                                )
                            if numeric_running:
                                try:
                                    os.kill(process.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                except BaseException as exc:
                                    remember_cleanup(
                                        exc,
                                        "dispatch fixture root numeric signal failed",
                                    )
                        try:
                            process.wait(timeout=2.0)
                        except BaseException as exc:
                            remember_cleanup(exc, "dispatch fixture root wait failed")
                try:
                    leaked_descendants = fixture_cleanup_descendants(
                        baseline_children
                    )
                except BaseException as exc:
                    remember_cleanup(
                        exc,
                        "dispatch fixture descendant cleanup failed",
                    )
                if root_pidfd.descriptor >= 0:
                    close_error, closed = fixture_close_owned_descriptor(
                        root_pidfd.descriptor
                    )
                    if close_error is not None:
                        remember_cleanup(
                            close_error,
                            "dispatch fixture root pidfd close failed",
                        )
                    if closed:
                        root_pidfd.descriptor = -1
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(FIXTURE_PROCESS_OUTPUT_BYTES + 1)
            stderr = stderr_file.read(FIXTURE_PROCESS_OUTPUT_BYTES + 1)
    finally:
        active = sys.exception()
        if root_pidfd.descriptor >= 0:
            close_error, closed = fixture_close_owned_descriptor(
                root_pidfd.descriptor
            )
            if close_error is not None:
                if active is not None:
                    if not isinstance(close_error, Exception) and isinstance(
                        active,
                        Exception,
                    ):
                        terminal_cancellation = fixture_choose_failure(
                            terminal_cancellation,
                            close_error,
                            "dispatch fixture root pidfd close also cancelled",
                        )
                        terminal_cancellation.add_note(
                            "dispatch fixture root pidfd close failed"
                        )
                    else:
                        active.add_note("dispatch fixture root pidfd close failed")
                else:
                    remember_cleanup(
                        close_error,
                        "dispatch fixture root pidfd close failed",
                    )
            if closed:
                root_pidfd.descriptor = -1
        restore_error = fixture_restore_subreaper(previous_subreaper)
        if restore_error is not None:
            if active is not None:
                if not isinstance(restore_error, Exception) and isinstance(
                    active,
                    Exception,
                ):
                    terminal_cancellation = fixture_choose_failure(
                        terminal_cancellation,
                        restore_error,
                        "dispatch fixture subreaper restore also cancelled",
                    )
                    terminal_cancellation.add_note(
                        "dispatch fixture subreaper restore failed"
                    )
                else:
                    active.add_note(
                        "dispatch fixture subreaper restore failed: "
                        f"{type(restore_error).__name__}: {restore_error}"
                    )
            elif primary is not None:
                containment_failed = True
                primary = fixture_choose_failure(
                    primary,
                    restore_error,
                    "dispatch fixture subreaper restore failed; an earlier "
                    "fixture failure also occurred: "
                    f"{type(restore_error).__name__}: {restore_error}",
                )
            else:
                containment_failed = True
                if not isinstance(restore_error, Exception):
                    primary = restore_error
                else:
                    primary = FixtureCleanupError(
                        "dispatch fixture subreaper restore failed"
                    )
                    primary.__cause__ = restore_error
        selected = active if active is not None else primary
        if terminal_cancellation is not None:
            selected = fixture_choose_failure(
                selected,
                terminal_cancellation,
                "dispatch fixture terminal cleanup also cancelled",
            )
        selected = signal_latch.close(selected)
        if active is not None:
            if selected is not None and selected is not active:
                raise selected
        elif selected is not primary:
            primary = selected
    if containment_failed:
        assert primary is not None
        fixture_raise_selected_failure(primary)
    if primary is not None and not (
        timed_out and isinstance(primary, subprocess.TimeoutExpired)
    ):
        fixture_raise_selected_failure(primary)
    if timed_out:
        return subprocess.CompletedProcess(
            list(arguments),
            125,
            "",
            "bounded fixture subprocess failed: dispatch fixture subprocess "
            "exceeded its deadline",
        )
    if process is None:
        raise SystemExit("dispatch fixture subprocess was not created")
    if leaked_descendants:
        return subprocess.CompletedProcess(
            list(arguments),
            125,
            "",
            "bounded fixture subprocess failed: dispatch fixture subprocess "
            "left descendants",
        )
    if (
        stdout_size > FIXTURE_PROCESS_OUTPUT_BYTES
        or len(stdout) > FIXTURE_PROCESS_OUTPUT_BYTES
        or (
            stdout_size == FIXTURE_PROCESS_OUTPUT_BYTES
            and process.returncode != 0
        )
    ):
        return subprocess.CompletedProcess(
            list(arguments),
            125,
            "",
            "bounded fixture subprocess failed: dispatch fixture subprocess "
            "stdout exceeds its size bound",
        )
    if (
        stderr_size > FIXTURE_PROCESS_OUTPUT_BYTES
        or len(stderr) > FIXTURE_PROCESS_OUTPUT_BYTES
        or (
            stderr_size == FIXTURE_PROCESS_OUTPUT_BYTES
            and process.returncode != 0
        )
    ):
        return subprocess.CompletedProcess(
            list(arguments),
            125,
            "",
            "bounded fixture subprocess failed: dispatch fixture subprocess "
            "stderr exceeds its size bound",
        )
    try:
        stdout_text = stdout.decode("utf-8")
        stderr_text = stderr.decode("utf-8")
    except UnicodeDecodeError:
        return subprocess.CompletedProcess(
            list(arguments),
            125,
            "",
            "bounded fixture subprocess failed: dispatch fixture subprocess "
            "output is not UTF-8",
        )
    return subprocess.CompletedProcess(
        list(arguments),
        process.returncode,
        stdout_text,
        stderr_text,
    )


@fixture_owner_scoped
def test_fixture_subprocess_bounds(cwd: pathlib.Path) -> None:
    exact_stdout = run(
        "/usr/bin/python3",
        "-c",
        (
            "import sys;sys.stdout.buffer.write(b'x'*"
            f"{FIXTURE_PROCESS_OUTPUT_BYTES})"
        ),
        cwd=cwd,
    )
    if (
        exact_stdout.returncode
        or len(exact_stdout.stdout.encode("utf-8"))
        != FIXTURE_PROCESS_OUTPUT_BYTES
        or exact_stdout.stderr
    ):
        raise SystemExit("dispatch fixture rejected its exact stdout limit")
    exact_stderr = run(
        "/usr/bin/python3",
        "-c",
        (
            "import sys;sys.stderr.buffer.write(b'x'*"
            f"{FIXTURE_PROCESS_OUTPUT_BYTES})"
        ),
        cwd=cwd,
    )
    if (
        exact_stderr.returncode
        or exact_stderr.stdout
        or len(exact_stderr.stderr.encode("utf-8"))
        != FIXTURE_PROCESS_OUTPUT_BYTES
    ):
        raise SystemExit("dispatch fixture rejected its exact stderr limit")
    invalid_utf8 = run(
        "/usr/bin/python3",
        "-c",
        "import sys;sys.stdout.buffer.write(b'\\xffHAPTICS_WORKFLOW_DISPATCH=PASS\\n')",
        cwd=cwd,
    )
    if (
        invalid_utf8.returncode != 125
        or invalid_utf8.stdout
        or invalid_utf8.stderr
        != "bounded fixture subprocess failed: dispatch fixture subprocess "
        "output is not UTF-8"
    ):
        raise SystemExit("dispatch fixture accepted non-UTF-8 evidence")
    flood = run(
        "/usr/bin/python3",
        "-c",
        (
            "import sys;sys.stdout.buffer.write(b'x'*"
            f"{FIXTURE_PROCESS_OUTPUT_BYTES + 1})"
        ),
        cwd=cwd,
    )
    if (
        flood.returncode == 0
        or flood.stdout
        or "stdout exceeds its size bound" not in flood.stderr
    ):
        raise SystemExit("dispatch fixture subprocess stdout is not bounded")
    stderr_flood = run(
        "/usr/bin/python3",
        "-c",
        (
            "import sys;sys.stderr.buffer.write(b'x'*"
            f"{FIXTURE_PROCESS_OUTPUT_BYTES + 1})"
        ),
        cwd=cwd,
    )
    if (
        stderr_flood.returncode == 0
        or stderr_flood.stdout
        or "stderr exceeds its size bound" not in stderr_flood.stderr
    ):
        raise SystemExit("dispatch fixture subprocess stderr is not bounded")
    started = time.monotonic()
    hung = run(
        "/usr/bin/python3",
        "-c",
        "import time;time.sleep(30)",
        cwd=cwd,
        timeout_seconds=0.1,
    )
    elapsed = time.monotonic() - started
    if (
        hung.returncode == 0
        or hung.stdout
        or "exceeded its deadline" not in hung.stderr
        or elapsed > 3.0
    ):
        raise SystemExit("dispatch fixture subprocess deadline is not bounded")

    identity = cwd / "detached-descendant.identity"
    escaped = run(
        "/usr/bin/python3",
        "-c",
        (
            "import os,pathlib,time\n"
            + PROCESS_IDENTITY_HELPER
            + f"identity=pathlib.Path({str(identity)!r})\n"
            "child=os.fork()\n"
            "if child == 0:\n"
            " os.setsid()\n"
            " record_identity(identity)\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "deadline=time.monotonic()+2\n"
            "while not identity.exists():\n"
            "  if time.monotonic() >= deadline: raise SystemExit(2)\n"
            "  time.sleep(0.01)\n"
            "os._exit(0)\n"
        ),
        cwd=cwd,
    )
    escaped_pid, escaped_start = read_fixture_process_identity(
        identity,
        "detached descendant",
    )
    identity.unlink()
    if (
        escaped.returncode != 125
        or escaped.stdout
        or "left descendants" not in escaped.stderr
    ):
        raise SystemExit("dispatch fixture did not reject a detached descendant")
    current_escaped = fixture_process_map().get(escaped_pid)
    if current_escaped is not None and current_escaped[1] == escaped_start:
        raise SystemExit("dispatch fixture left its detached descendant alive")

    direct_pids = tuple(range(80000, 80000 + FIXTURE_PROCESS_LIMIT))
    later_pid = 90000
    first_wave = {
        pid: (os.getpid(), pid + 1)
        for pid in direct_pids
    }
    first_wave[later_pid] = (direct_pids[0], later_pid + 1)
    bounded_wave = fixture_owned_processes(
        frozenset(),
        process_map=first_wave,
    )
    later_wave = fixture_owned_processes(
        frozenset(),
        process_map={later_pid: (os.getpid(), later_pid + 1)},
    )
    if (
        len(bounded_wave) != FIXTURE_PROCESS_LIMIT
        or later_pid in bounded_wave
        or later_wave != {later_pid: later_pid + 1}
    ):
        raise SystemExit("dispatch fixture descendant waves are not bounded")


@fixture_owner_scoped
def test_fixture_cleanup_faults(cwd: pathlib.Path) -> None:
    original_scandir = os.scandir
    descriptor_baseline = fixture_open_descriptor_set()
    acquisition_cancellation = KeyboardInterrupt(
        "dispatch fixture descriptor-table acquisition cancellation"
    )
    retained_iterators: list[object] = []

    def cancel_descriptor_table_acquisition(path):
        entries = original_scandir(path)
        if os.fspath(path) == "/proc/self/fd":
            retained_iterators.append(entries)
            raise acquisition_cancellation
        return entries

    os.scandir = cancel_descriptor_table_acquisition
    acquisition_caught: BaseException | None = None
    try:
        try:
            fixture_open_descriptor_set()
        except BaseException as exc:
            acquisition_caught = exc
    finally:
        os.scandir = original_scandir
    acquisition_residue = fixture_open_descriptor_set() != descriptor_baseline
    for entries in retained_iterators:
        try:
            entries.close()
        except OSError:
            pass
    if (
        acquisition_caught is not acquisition_cancellation
        or len(retained_iterators) != 1
        or acquisition_residue
    ):
        raise SystemExit(
            "dispatch fixture scandir acquisition custody drifted"
        ) from acquisition_caught

    sigchld_popen_original = subprocess.Popen
    sigchld_popen_calls = 0

    def count_sigchld_popen(*args, **kwargs):
        nonlocal sigchld_popen_calls
        sigchld_popen_calls += 1
        return sigchld_popen_original(*args, **kwargs)

    subprocess.Popen = count_sigchld_popen
    try:
        for disposition in (signal.SIG_IGN, lambda _signum, _frame: None):
            previous_sigchld = signal.signal(signal.SIGCHLD, disposition)
            try:
                try:
                    run("/usr/bin/true", cwd=cwd)
                except FixturePublicFailure as exc:
                    if str(exc) != "dispatch fixture requires default SIGCHLD policy":
                        raise
                else:
                    raise SystemExit(
                        "dispatch fixture accepted inherited SIGCHLD policy"
                    )
                if signal.getsignal(signal.SIGCHLD) is not disposition:
                    raise SystemExit(
                        "dispatch fixture changed inherited SIGCHLD policy"
                    )
            finally:
                signal.signal(signal.SIGCHLD, previous_sigchld)
    finally:
        subprocess.Popen = sigchld_popen_original
    if sigchld_popen_calls:
        raise SystemExit("dispatch fixture spawned before SIGCHLD rejection")

    pidfd_target_owner = FixturePopenOwner()
    try:
        spawn_fixture_popen(
            pidfd_target_owner,
            ["/usr/bin/sleep", "30"],
            cwd=cwd,
            label="dispatch fixture pidfd handoff target spawn",
        )
        assert pidfd_target_owner.process is not None
        pidfd_target = pidfd_target_owner.process
    except BaseException as exc:
        selected = settle_fixture_popen_owner(
            pidfd_target_owner,
            exc,
            "dispatch fixture pidfd handoff target spawn",
        )
        assert selected is not None
        raise selected
    original_pidfd_open = os.pidfd_open
    handoff_pidfds: list[int] = []
    handoff_cancellation = KeyboardInterrupt(
        "injected dispatch fixture pidfd open handoff cancellation"
    )

    def cancel_pidfd_open(pid: int, flags: int) -> int:
        descriptor = original_pidfd_open(pid, flags)
        handoff_pidfds.append(descriptor)
        raise handoff_cancellation

    os.pidfd_open = cancel_pidfd_open
    handoff_caught: BaseException | None = None
    handoff_owner = FixtureDescriptorOwner()
    try:
        try:
            acquire_fixture_pidfd(
                handoff_owner,
                pidfd_target.pid,
                "dispatch fixture pidfd handoff oracle",
            )
        except BaseException as exc:
            handoff_caught = exc
    finally:
        os.pidfd_open = original_pidfd_open
        try:
            os.kill(pidfd_target.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        status = wait_fixture_child(
            pidfd_target.pid,
            "dispatch fixture pidfd handoff target cleanup",
        )
        pidfd_target.returncode = os.waitstatus_to_exitcode(status)
        pidfd_target_owner.process = None
    handoff_leaked = False
    for descriptor in handoff_pidfds:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            handoff_leaked = True
            os.close(descriptor)
    if (
        handoff_caught is not handoff_cancellation
        or len(handoff_pidfds) != 1
        or handoff_leaked
        or handoff_owner.descriptor != -1
    ):
        raise SystemExit(
            "dispatch fixture pidfd open handoff custody drifted"
        ) from handoff_caught

    snapshot_target_owner = FixturePopenOwner()
    try:
        spawn_fixture_popen(
            snapshot_target_owner,
            ["/usr/bin/sleep", "30"],
            cwd=cwd,
            label="dispatch fixture pidfd snapshot target spawn",
        )
        assert snapshot_target_owner.process is not None
        snapshot_target = snapshot_target_owner.process
    except BaseException as exc:
        selected = settle_fixture_popen_owner(
            snapshot_target_owner,
            exc,
            "dispatch fixture pidfd snapshot target spawn",
        )
        assert selected is not None
        raise selected
    original_snapshot_fstat = os.fstat
    snapshot_pidfds: list[int] = []
    snapshot_fstat_failed = False
    snapshot_cancellation = KeyboardInterrupt(
        "injected dispatch fixture pidfd recovery-snapshot cancellation"
    )

    def cancel_snapshot_pidfd(pid: int, flags: int) -> int:
        descriptor = original_pidfd_open(pid, flags)
        snapshot_pidfds.append(descriptor)
        raise snapshot_cancellation

    def fail_snapshot_pidfd_fstat(descriptor: int):
        nonlocal snapshot_fstat_failed
        if descriptor in snapshot_pidfds and not snapshot_fstat_failed:
            snapshot_fstat_failed = True
            raise OSError(errno.EIO, "injected pidfd recovery snapshot failure")
        return original_snapshot_fstat(descriptor)

    os.pidfd_open = cancel_snapshot_pidfd
    os.fstat = fail_snapshot_pidfd_fstat
    snapshot_owner = FixtureDescriptorOwner()
    snapshot_caught: BaseException | None = None
    try:
        try:
            acquire_fixture_pidfd(
                snapshot_owner,
                snapshot_target.pid,
                "dispatch fixture pidfd recovery-snapshot oracle",
            )
        except BaseException as exc:
            snapshot_caught = exc
    finally:
        os.fstat = original_snapshot_fstat
        os.pidfd_open = original_pidfd_open
        try:
            os.kill(snapshot_target.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        status = wait_fixture_child(
            snapshot_target.pid,
            "dispatch fixture pidfd snapshot target cleanup",
        )
        snapshot_target.returncode = os.waitstatus_to_exitcode(status)
        snapshot_target_owner.process = None
    snapshot_closed = True
    for descriptor in snapshot_pidfds:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                snapshot_closed = False
        else:
            snapshot_closed = False
            os.close(descriptor)
    if (
        snapshot_caught is not snapshot_cancellation
        or not snapshot_fstat_failed
        or len(snapshot_pidfds) != 1
        or snapshot_owner.descriptor != -1
        or not snapshot_closed
    ):
        raise SystemExit(
            "dispatch fixture pidfd recovery-snapshot custody drifted"
        ) from snapshot_caught

    original_acquire_fixture_pidfd = globals()["acquire_fixture_pidfd"]
    owner_slot_descriptors: list[int] = []
    owner_slot_processes: list[subprocess.Popen[bytes]] = []
    owner_slot_cancelled = False
    owner_slot_cancellation = KeyboardInterrupt(
        "injected dispatch fixture root pidfd helper-return cancellation"
    )

    def cancel_root_after_acquire(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
    ) -> None:
        nonlocal owner_slot_cancelled
        original_acquire_fixture_pidfd(owner, pid, label)
        if not owner_slot_cancelled and "root pidfd" in label:
            owner_slot_cancelled = True
            owner_slot_descriptors.append(owner.descriptor)
            raise owner_slot_cancellation

    def record_owner_slot_popen(*args, **kwargs):
        process = sigchld_popen_original(*args, **kwargs)
        owner_slot_processes.append(process)
        return process

    globals()["acquire_fixture_pidfd"] = cancel_root_after_acquire
    subprocess.Popen = record_owner_slot_popen
    owner_slot_caught: BaseException | None = None
    try:
        try:
            run("/usr/bin/sleep", "30", cwd=cwd)
        except BaseException as exc:
            owner_slot_caught = exc
    finally:
        subprocess.Popen = sigchld_popen_original
        globals()["acquire_fixture_pidfd"] = original_acquire_fixture_pidfd
    owner_slot_closed = True
    for descriptor in owner_slot_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                owner_slot_closed = False
        else:
            owner_slot_closed = False
            os.close(descriptor)
    owner_slot_reaped = False
    if len(owner_slot_processes) == 1:
        try:
            os.waitpid(owner_slot_processes[0].pid, os.WNOHANG)
        except ChildProcessError:
            owner_slot_reaped = True
    if (
        owner_slot_caught is not owner_slot_cancellation
        or not owner_slot_cancelled
        or len(owner_slot_descriptors) != 1
        or len(owner_slot_processes) != 1
        or owner_slot_processes[0].returncode is None
        or not owner_slot_reaped
        or not owner_slot_closed
    ):
        raise SystemExit(
            "dispatch fixture root pidfd owner-slot custody drifted"
        ) from owner_slot_caught

    descendant_baseline = frozenset(
        pid
        for pid, (parent, _) in fixture_process_map().items()
        if parent == os.getpid()
    )

    def descendant_child_main() -> int:
        time.sleep(30)
        return 0

    descendant_child_owner = FixtureChildOwner()
    try:
        spawn_fixture_child(
            descendant_child_owner,
            descendant_child_main,
            "dispatch fixture descendant pidfd target spawn",
        )
        descendant_child = descendant_child_owner.pid
    except BaseException as exc:
        selected = settle_fixture_child_owner(
            descendant_child_owner,
            exc,
            "dispatch fixture descendant pidfd target spawn",
        )
        assert selected is not None
        raise selected
    descendant_descriptors: list[int] = []
    descendant_cancelled = False
    descendant_cancellation = KeyboardInterrupt(
        "injected dispatch fixture descendant pidfd helper-return cancellation"
    )

    def cancel_descendant_after_acquire(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
    ) -> None:
        nonlocal descendant_cancelled
        original_acquire_fixture_pidfd(owner, pid, label)
        if pid == descendant_child and not descendant_cancelled:
            descendant_cancelled = True
            descendant_descriptors.append(owner.descriptor)
            raise descendant_cancellation

    globals()["acquire_fixture_pidfd"] = cancel_descendant_after_acquire
    descendant_caught: BaseException | None = None
    try:
        try:
            fixture_cleanup_descendants(descendant_baseline)
        except BaseException as exc:
            descendant_caught = exc
    finally:
        globals()["acquire_fixture_pidfd"] = original_acquire_fixture_pidfd
    descendant_closed = True
    for descriptor in descendant_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                descendant_closed = False
        else:
            descendant_closed = False
            os.close(descriptor)
    try:
        waited, _ = os.waitpid(descendant_child, os.WNOHANG)
    except ChildProcessError:
        descendant_reaped = True
        descendant_child_owner.pid = -1
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
        or not descendant_closed
        or not descendant_reaped
    ):
        raise SystemExit(
            "dispatch fixture descendant pidfd owner-slot custody drifted"
        ) from descendant_caught

    exact_exit = run("/bin/sh", "-c", "exit 7", cwd=cwd)
    if exact_exit.returncode != 7 or exact_exit.stdout or exact_exit.stderr:
        raise SystemExit("dispatch fixture lost exact child exit status")

    original_read = os.read
    short_read_calls = 0
    largest_requested_read = 0

    def short_read(descriptor: int, size: int) -> bytes:
        nonlocal short_read_calls, largest_requested_read
        short_read_calls += 1
        largest_requested_read = max(largest_requested_read, size)
        return original_read(descriptor, min(size, 3))

    os.read = short_read
    try:
        short_snapshot = fixture_process_map()
    finally:
        os.read = original_read
    if (
        os.getpid() not in short_snapshot
        or short_read_calls < 2
        or largest_requested_read > 4097
    ):
        raise SystemExit("dispatch fixture process short-read oracle drifted")

    identity_path = cwd / "bounded-identity-reader.tsv"
    identity_path.write_bytes(b"123\t456\n")
    identity_read_calls = 0
    identity_largest_read = 0

    def short_identity_read(descriptor: int, size: int) -> bytes:
        nonlocal identity_read_calls, identity_largest_read
        identity_read_calls += 1
        identity_largest_read = max(identity_largest_read, size)
        return original_read(descriptor, min(size, 2))

    os.read = short_identity_read
    try:
        parsed_identity = read_fixture_process_identity(
            identity_path,
            "bounded-reader oracle",
        )
    finally:
        os.read = original_read
    if (
        parsed_identity != (123, 456)
        or identity_read_calls < 2
        or identity_largest_read > 129
    ):
        raise SystemExit("dispatch fixture bounded identity reader drifted")

    identity_baseline = fixture_open_descriptor_set()
    identity_cancellation = KeyboardInterrupt(
        "injected dispatch bounded identity read cancellation"
    )

    def cancel_identity_read(_descriptor: int, _size: int) -> bytes:
        raise identity_cancellation

    os.read = cancel_identity_read
    identity_caught: BaseException | None = None
    try:
        try:
            read_fixture_process_identity(
                identity_path,
                "read-cancellation oracle",
            )
        except BaseException as exc:
            identity_caught = exc
    finally:
        os.read = original_read
    if (
        identity_caught is not identity_cancellation
        or fixture_open_descriptor_set() != identity_baseline
    ):
        raise SystemExit(
            "dispatch fixture identity read cancellation custody drifted"
        ) from identity_caught

    original_open = os.open
    identity_open_descriptors: list[int] = []
    identity_open_cancellation = KeyboardInterrupt(
        "injected dispatch identity open handoff cancellation"
    )

    def cancel_identity_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is None:
            descriptor = original_open(path, flags, mode)
        else:
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if os.fspath(path) == os.fspath(identity_path):
            identity_open_descriptors.append(descriptor)
            raise identity_open_cancellation
        return descriptor

    os.open = cancel_identity_open
    identity_open_caught: BaseException | None = None
    try:
        try:
            read_fixture_process_identity(
                identity_path,
                "open-handoff oracle",
            )
        except BaseException as exc:
            identity_open_caught = exc
    finally:
        os.open = original_open
    identity_open_closed = True
    for descriptor in identity_open_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                identity_open_closed = False
        else:
            identity_open_closed = False
            os.close(descriptor)
    if (
        identity_open_caught is not identity_open_cancellation
        or len(identity_open_descriptors) != 1
        or not identity_open_closed
    ):
        raise SystemExit(
            "dispatch fixture identity open handoff custody drifted"
        ) from identity_open_caught

    oversized_identity = cwd / "oversized-identity-reader.tsv"
    oversized_identity.write_bytes(b"1\t1\n" + b"x" * 125)
    oversized_caught: BaseException | None = None
    try:
        try:
            read_fixture_process_identity(
                oversized_identity,
                "oversized-reader oracle",
            )
        except BaseException as exc:
            oversized_caught = exc
    finally:
        oversized_identity.unlink()
        identity_path.unlink()
    if (
        not isinstance(oversized_caught, SystemExit)
        or str(oversized_caught)
        != "dispatch fixture oversized-reader oracle identity is malformed"
    ):
        raise SystemExit(
            "dispatch fixture oversized identity reader drifted"
        ) from oversized_caught

    target_record = f"/proc/{os.getpid()}/stat"
    for injected_errno in (errno.EMFILE, errno.EIO):
        def fail_process_open(path, flags, mode=0o777, *, dir_fd=None):
            if os.fspath(path) == target_record:
                raise OSError(injected_errno, os.strerror(injected_errno))
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        os.open = fail_process_open
        try:
            try:
                fixture_process_map()
            except FixtureCleanupError as exc:
                if str(exc) != (
                    f"dispatch fixture cannot inspect process record {os.getpid()}"
                ):
                    raise
            else:
                raise SystemExit(
                    "dispatch fixture skipped a live process-record I/O fault"
                )
        finally:
            os.open = original_open

    malformed_reader, malformed_writer = os.pipe()
    os.write(malformed_writer, b"malformed")
    os.close(malformed_writer)
    malformed_supplied = False
    malformed_original_fstat = os.fstat
    malformed_target_metadata = os.stat(target_record, follow_symlinks=False)

    def malformed_process_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal malformed_supplied
        if os.fspath(path) == target_record and not malformed_supplied:
            malformed_supplied = True
            return malformed_reader
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def malformed_process_fstat(descriptor: int):
        if descriptor == malformed_reader:
            return malformed_target_metadata
        return malformed_original_fstat(descriptor)

    os.open = malformed_process_open
    os.fstat = malformed_process_fstat
    try:
        try:
            fixture_process_map()
        except FixtureCleanupError as exc:
            if str(exc) != (
                f"dispatch fixture process record {os.getpid()} is malformed"
            ):
                raise
        else:
            raise SystemExit("dispatch fixture accepted a malformed live record")
    finally:
        os.fstat = malformed_original_fstat
        os.open = original_open
        try:
            os.close(malformed_reader)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
    exact_record = b"x" * 4096
    with tempfile.TemporaryFile() as exact:
        exact.write(exact_record)
        exact.seek(0)
        if fixture_read_process_record(exact.fileno()) != exact_record:
            raise SystemExit("dispatch fixture exact process-record bound drifted")
    with tempfile.TemporaryFile() as oversized:
        oversized.write(b"x" * 4097)
        oversized.seek(0)
        overflow: BaseException | None = None
        try:
            fixture_read_process_record(oversized.fileno())
        except BaseException as exc:
            overflow = exc
    if (
        not isinstance(overflow, FixtureCleanupError)
        or str(overflow) != "dispatch fixture process record exceeds its bound"
    ):
        raise SystemExit("dispatch fixture process-record bound oracle drifted")

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
        pid = 81000 + offset
        chain_pairs.append((pid, (parent, 91000 + offset)))
        parent = pid
    reverse_chain = CountingSnapshot(reversed(chain_pairs))
    expected_chain = {pid: record[1] for pid, record in chain_pairs}
    chain_owned = fixture_owned_processes(
        frozenset(),
        process_map=reverse_chain,
    )
    if (
        chain_owned != expected_chain
        or reverse_chain.item_calls != 1
    ):
        raise SystemExit(
            "dispatch fixture process-graph complexity oracle drifted"
        )

    original_close = os.close
    original_fstat = os.fstat
    probe_owner = FixtureDescriptorOwner()
    probe_metadata = os.stat("/dev/null", follow_symlinks=False)
    acquire_existing_fixture_descriptor(
        probe_owner,
        "/dev/null",
        os.O_RDONLY | os.O_CLOEXEC,
        (probe_metadata.st_dev, probe_metadata.st_ino),
        "dispatch fixture descriptor-close probe setup",
    )
    probe_descriptor = probe_owner.descriptor
    probe_close_calls = 0
    probe_fstat_calls = 0
    probe_close_failure = OSError(
        "injected dispatch descriptor nonapplied close failure"
    )
    probe_cancellation = KeyboardInterrupt(
        "injected dispatch descriptor custody-probe cancellation"
    )

    def fail_probe_close_once(descriptor: int) -> None:
        nonlocal probe_close_calls
        if descriptor == probe_descriptor:
            probe_close_calls += 1
            if probe_close_calls == 1:
                raise probe_close_failure
        original_close(descriptor)

    def cancel_probe_fstat_once(descriptor: int):
        nonlocal probe_fstat_calls
        if descriptor == probe_descriptor:
            probe_fstat_calls += 1
            if probe_fstat_calls == 1:
                raise probe_cancellation
        return original_fstat(descriptor)

    os.close = fail_probe_close_once
    os.fstat = cancel_probe_fstat_once
    try:
        probe_error, probe_closed = fixture_close_owned_descriptor(probe_descriptor)
    finally:
        os.fstat = original_fstat
        os.close = original_close
    try:
        original_fstat(probe_descriptor)
    except OSError as exc:
        probe_is_closed = exc.errno == errno.EBADF
        if probe_is_closed:
            probe_owner.descriptor = -1
    else:
        probe_is_closed = False
        original_close(probe_descriptor)
    if (
        probe_error is not probe_cancellation
        or probe_cancellation.__cause__ is not probe_close_failure
        or not probe_closed
        or not probe_is_closed
        or probe_close_calls != 2
        or probe_fstat_calls != 1
    ):
        raise SystemExit("dispatch descriptor-probe cancellation oracle drifted")

    original_open = os.open
    original_close = os.close
    original_reader = globals()["fixture_read_process_record"]
    map_descriptors: list[int] = []
    map_close_calls = 0
    map_cancellation = KeyboardInterrupt(
        "injected dispatch process-map read cancellation"
    )

    def record_map_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path).startswith("/proc/") and os.fspath(path).endswith("/stat"):
            map_descriptors.append(descriptor)
        return descriptor

    def cancel_map_read(descriptor: int) -> bytes:
        if descriptor in map_descriptors:
            raise map_cancellation
        return original_reader(descriptor)

    def fail_map_close_once(descriptor: int) -> None:
        nonlocal map_close_calls
        if descriptor in map_descriptors:
            map_close_calls += 1
            if map_close_calls == 1:
                raise OSError("injected dispatch process-map close failure")
        original_close(descriptor)

    os.open = record_map_open
    os.close = fail_map_close_once
    globals()["fixture_read_process_record"] = cancel_map_read
    map_caught: BaseException | None = None
    try:
        try:
            fixture_process_map()
        except BaseException as exc:
            map_caught = exc
    finally:
        globals()["fixture_read_process_record"] = original_reader
        os.close = original_close
        os.open = original_open
    if (
        map_caught is not map_cancellation
        or len(map_descriptors) != 1
        or map_close_calls != 2
        or "process record close failed" not in " ".join(
            getattr(map_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "dispatch process-map finalizer masked cancellation"
        ) from map_caught
    try:
        original_fstat(map_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        original_close(map_descriptors[0])
        raise SystemExit("dispatch process-map finalizer leaked its fd")

    applied_open_descriptors: list[int] = []
    applied_open_cancellation = KeyboardInterrupt(
        "dispatch fixture process-record open assignment cancellation"
    )
    applied_open_fired = False

    def apply_process_open_then_cancel(path, flags, *args, **kwargs):
        nonlocal applied_open_fired
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == f"/proc/{os.getpid()}/stat" and not applied_open_fired:
            applied_open_fired = True
            applied_open_descriptors.append(descriptor)
            raise applied_open_cancellation
        return descriptor

    os.open = apply_process_open_then_cancel
    applied_open_caught: BaseException | None = None
    try:
        try:
            fixture_process_map()
        except BaseException as exc:
            applied_open_caught = exc
    finally:
        os.open = original_open
    if (
        applied_open_caught is not applied_open_cancellation
        or len(applied_open_descriptors) != 1
    ):
        raise SystemExit(
            "dispatch fixture process-record open handoff drifted"
        ) from applied_open_caught
    try:
        original_fstat(applied_open_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        original_close(applied_open_descriptors[0])
        raise SystemExit("dispatch fixture process-record open handoff leaked fd")

    disappeared_descriptors: list[int] = []
    disappeared_fired = False

    def apply_process_open_then_disappear(path, flags, *args, **kwargs):
        nonlocal disappeared_fired
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == f"/proc/{os.getpid()}/stat" and not disappeared_fired:
            disappeared_fired = True
            disappeared_descriptors.append(descriptor)
            raise FileNotFoundError(errno.ENOENT, "injected applied disappearance")
        return descriptor

    os.open = apply_process_open_then_disappear
    disappearance_caught: BaseException | None = None
    try:
        try:
            fixture_process_map()
        except BaseException as exc:
            disappearance_caught = exc
    finally:
        os.open = original_open
    disappearance_leaked = False
    for descriptor in disappeared_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            disappearance_leaked = True
            original_close(descriptor)
    if (
        disappearance_caught is not None
        or len(disappeared_descriptors) != 1
        or disappearance_leaked
    ):
        raise SystemExit(
            "dispatch fixture applied-disappearance handoff drifted"
        ) from disappearance_caught

    original_scandir = os.scandir
    iterator_cancellation = KeyboardInterrupt(
        "dispatch fixture process-table iteration cancellation"
    )
    iterator_close_failure = OSError(
        "dispatch fixture process-table iterator close failure"
    )
    iterator_close_calls = 0

    class CancellingProcessIterator:
        def __init__(self, wrapped) -> None:
            self.wrapped = wrapped

        def __iter__(self):
            return self

        def __next__(self):
            raise iterator_cancellation

        def close(self) -> None:
            nonlocal iterator_close_calls
            iterator_close_calls += 1
            if iterator_close_calls == 1:
                raise iterator_close_failure
            self.wrapped.close()

    def cancelling_process_scandir(path):
        entries = original_scandir(path)
        if os.fspath(path) == "/proc":
            return CancellingProcessIterator(entries)
        return entries

    before_iterator_fds = fixture_open_descriptor_set()
    os.scandir = cancelling_process_scandir
    iterator_caught: BaseException | None = None
    try:
        try:
            fixture_process_map()
        except BaseException as exc:
            iterator_caught = exc
    finally:
        os.scandir = original_scandir
    if (
        iterator_caught is not iterator_cancellation
        or iterator_close_calls != 2
        or fixture_open_descriptor_set() != before_iterator_fds
        or "iterator close also failed"
        not in " ".join(getattr(iterator_caught, "__notes__", ()))
    ):
        raise SystemExit(
            "dispatch fixture process-table iterator custody drifted"
        ) from iterator_caught

    acquisition_cancellation = KeyboardInterrupt(
        "dispatch fixture process-table acquisition cancellation"
    )
    retained_process_iterators: list[object] = []

    def cancel_process_acquisition(path):
        entries = original_scandir(path)
        if os.fspath(path) == "/proc":
            retained_process_iterators.append(entries)
            raise acquisition_cancellation
        return entries

    acquisition_before = fixture_open_descriptor_set()
    os.scandir = cancel_process_acquisition
    acquisition_caught: BaseException | None = None
    try:
        try:
            fixture_process_map()
        except BaseException as exc:
            acquisition_caught = exc
    finally:
        os.scandir = original_scandir
    acquisition_residue = fixture_open_descriptor_set() != acquisition_before
    for entries in retained_process_iterators:
        try:
            entries.close()
        except OSError:
            pass
    if (
        acquisition_caught is not acquisition_cancellation
        or len(retained_process_iterators) != 1
        or acquisition_residue
    ):
        raise SystemExit(
            "dispatch fixture process-table acquisition custody drifted"
        ) from acquisition_caught

    original_open = os.open
    original_close = os.close
    acquired: list[int] = []
    close_injected = False

    def bounded_open(path, flags, *args, **kwargs):
        if os.fspath(path) == "/dev/null":
            if len(acquired) == 3:
                raise OSError("injected pidfd preflight allocation failure")
            descriptor = original_open(path, flags, *args, **kwargs)
            acquired.append(descriptor)
            return descriptor
        return original_open(path, flags, *args, **kwargs)

    def fail_first_preflight_close(descriptor: int) -> None:
        nonlocal close_injected
        if descriptor in acquired and not close_injected:
            close_injected = True
            raise OSError("injected nonapplied pidfd preflight close failure")
        original_close(descriptor)

    os.open = bounded_open
    os.close = fail_first_preflight_close
    preflight_error: BaseException | None = None
    try:
        try:
            fixture_preflight_pidfd_capacity()
        except BaseException as exc:
            preflight_error = exc
    finally:
        os.close = original_close
        os.open = original_open
    preflight_notes = getattr(preflight_error, "__notes__", ())
    if (
        not isinstance(preflight_error, FixtureCleanupError)
        or str(preflight_error) != "dispatch fixture has insufficient pidfd capacity"
        or "dispatch fixture pidfd preflight cleanup failed" not in preflight_notes
        or not close_injected
    ):
        raise SystemExit(
            "dispatch fixture preflight did not preserve cleanup evidence: "
            f"error={preflight_error!r} notes={preflight_notes!r} "
            f"close_injected={close_injected}"
        )
    for descriptor in acquired:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        else:
            original_close(descriptor)
            raise SystemExit("dispatch fixture preflight leaked a descriptor")

    preflight_handoff_cancellation = KeyboardInterrupt(
        "dispatch fixture preflight open handoff cancellation"
    )
    preflight_handoff_descriptors: list[int] = []

    def cancel_preflight_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == "/dev/null" and not preflight_handoff_descriptors:
            preflight_handoff_descriptors.append(descriptor)
            raise preflight_handoff_cancellation
        return descriptor

    os.open = cancel_preflight_open
    preflight_handoff_caught: BaseException | None = None
    try:
        try:
            fixture_preflight_pidfd_capacity()
        except BaseException as exc:
            preflight_handoff_caught = exc
    finally:
        os.open = original_open
    preflight_handoff_leaked = False
    for descriptor in preflight_handoff_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            preflight_handoff_leaked = True
            original_close(descriptor)
    if (
        preflight_handoff_caught is not preflight_handoff_cancellation
        or len(preflight_handoff_descriptors) != 1
        or preflight_handoff_leaked
    ):
        raise SystemExit(
            "dispatch fixture preflight open handoff custody drifted"
        ) from preflight_handoff_caught

    original_owned = globals()["fixture_owned_processes"]
    original_reap = globals()["fixture_reap_owned"]
    original_sleep = time.sleep
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_close = os.close
    process_maps = [
        {101: 1001, 102: 1002, 103: 1003},
        {101: 1001, 102: 1002, 103: 1003},
        {104: 1004},
        {104: 1004},
        {},
    ]
    opened: dict[int, int] = {}
    open_attempts: list[int] = []
    signal_attempts: list[int] = []
    descendant_close_injected = False

    def model_owned(_baseline):
        if not process_maps:
            raise SystemExit("dispatch cleanup model exceeded its bounded waves")
        return process_maps.pop(0)

    def model_pidfd_open(pid: int, _flags: int) -> int:
        open_attempts.append(pid)
        if pid == 101:
            raise OSError("injected first-target pidfd open failure")
        descriptor = original_open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        opened[descriptor] = pid
        return descriptor

    def model_pidfd_signal(descriptor, signum, _info, _flags):
        pid = opened[descriptor]
        signal_attempts.append(pid)
        if signum != signal.SIGKILL:
            raise SystemExit("dispatch cleanup model changed its signal")
        if pid == 102:
            raise OSError("injected first-target pidfd signal failure")

    def model_close(descriptor: int) -> None:
        nonlocal descendant_close_injected
        if descriptor in opened and not descendant_close_injected:
            descendant_close_injected = True
            raise OSError("injected nonapplied descendant pidfd close failure")
        original_close(descriptor)

    globals()["fixture_owned_processes"] = model_owned
    globals()["fixture_reap_owned"] = lambda _pids: None
    time.sleep = lambda _seconds: None
    os.pidfd_open = model_pidfd_open
    signal.pidfd_send_signal = model_pidfd_signal
    os.close = model_close
    cleanup_error: BaseException | None = None
    try:
        try:
            fixture_cleanup_descendants(frozenset())
        except BaseException as exc:
            cleanup_error = exc
    finally:
        os.close = original_close
        signal.pidfd_send_signal = original_pidfd_signal
        os.pidfd_open = original_pidfd_open
        time.sleep = original_sleep
        globals()["fixture_reap_owned"] = original_reap
        globals()["fixture_owned_processes"] = original_owned
    if (
        not isinstance(cleanup_error, FixtureCleanupError)
        or str(cleanup_error)
        != "dispatch fixture descendant cleanup encountered errors"
        or open_attempts != [101, 102, 103, 104]
        or signal_attempts != [102, 103, 104]
        or process_maps
        or not descendant_close_injected
    ):
        raise SystemExit("dispatch fixture cleanup faults starved later targets or waves")
    for descriptor in opened:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        else:
            original_close(descriptor)
            raise SystemExit("dispatch fixture descendant cleanup leaked a pidfd")

    original_owned = globals()["fixture_owned_processes"]
    original_reap = globals()["fixture_reap_owned"]
    original_sleep = time.sleep
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_passes = FIXTURE_PROCESS_PASSES
    nonconvergent_cancellation = KeyboardInterrupt(
        "injected dispatch nonconvergent cleanup cancellation"
    )
    nonconvergent_descriptors: list[int] = []
    nonconvergent_owned_calls = 0
    nonconvergent_signal_calls = 0

    def nonconvergent_owned(_baseline):
        nonlocal nonconvergent_owned_calls
        nonconvergent_owned_calls += 1
        return {101: 1001}

    def nonconvergent_pidfd_open(_pid: int, _flags: int) -> int:
        descriptor = original_open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        nonconvergent_descriptors.append(descriptor)
        return descriptor

    def cancel_nonconvergent_signal(_descriptor, _signum, _info, _flags):
        nonlocal nonconvergent_signal_calls
        nonconvergent_signal_calls += 1
        raise nonconvergent_cancellation

    globals()["fixture_owned_processes"] = nonconvergent_owned
    globals()["fixture_reap_owned"] = lambda _pids: None
    globals()["FIXTURE_PROCESS_PASSES"] = 1
    time.sleep = lambda _seconds: None
    os.pidfd_open = nonconvergent_pidfd_open
    signal.pidfd_send_signal = cancel_nonconvergent_signal
    nonconvergent_caught: BaseException | None = None
    try:
        try:
            fixture_cleanup_descendants(frozenset())
        except BaseException as exc:
            nonconvergent_caught = exc
    finally:
        signal.pidfd_send_signal = original_pidfd_signal
        os.pidfd_open = original_pidfd_open
        time.sleep = original_sleep
        globals()["FIXTURE_PROCESS_PASSES"] = original_passes
        globals()["fixture_reap_owned"] = original_reap
        globals()["fixture_owned_processes"] = original_owned
    if (
        nonconvergent_caught is not nonconvergent_cancellation
        or nonconvergent_owned_calls != 3
        or nonconvergent_signal_calls != 1
        or not isinstance(
            nonconvergent_caught.__cause__,
            FixtureCleanupError,
        )
        or "did not converge" not in " ".join(
            getattr(nonconvergent_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "dispatch nonconvergent cleanup cancellation oracle drifted"
        ) from nonconvergent_caught
    for descriptor in nonconvergent_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        else:
            original_close(descriptor)
            raise SystemExit(
                "dispatch nonconvergent cleanup leaked a pidfd"
            )

    original_popen = subprocess.Popen
    original_pidfd_signal = signal.pidfd_send_signal
    original_cleanup = globals()["fixture_cleanup_descendants"]
    original_set_subreaper = globals()["fixture_set_subreaper"]
    initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(initial_subreaper)
    processes: list[subprocess.Popen[bytes]] = []
    root_signal_injected = False
    cleanup_calls = 0
    restore_injected = False
    subreaper_calls = 0

    def recording_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    def fail_root_signal_once(descriptor, signum, info, flags):
        nonlocal root_signal_injected
        if not root_signal_injected:
            root_signal_injected = True
            raise OSError("injected root pidfd signal failure")
        return original_pidfd_signal(descriptor, signum, info, flags)

    def fail_descendant_cleanup(_baseline):
        nonlocal cleanup_calls
        cleanup_calls += 1
        raise OSError("injected descendant cleanup failure")

    def fail_first_subreaper_restore(enabled: bool) -> bool:
        nonlocal restore_injected, subreaper_calls
        subreaper_calls += 1
        previous = original_set_subreaper(enabled)
        if subreaper_calls >= 2 and not restore_injected:
            restore_injected = True
            raise OSError("injected applied subreaper restore failure")
        return previous

    subprocess.Popen = recording_popen
    signal.pidfd_send_signal = fail_root_signal_once
    globals()["fixture_cleanup_descendants"] = fail_descendant_cleanup
    globals()["fixture_set_subreaper"] = fail_first_subreaper_restore
    combined_error: subprocess.TimeoutExpired | None = None
    try:
        try:
            run(
                "/usr/bin/python3",
                "-c",
                "import time;time.sleep(30)",
                cwd=cwd,
                timeout_seconds=0.05,
            )
        except subprocess.TimeoutExpired as exc:
            combined_error = exc
    finally:
        globals()["fixture_set_subreaper"] = original_set_subreaper
        globals()["fixture_cleanup_descendants"] = original_cleanup
        signal.pidfd_send_signal = original_pidfd_signal
        subprocess.Popen = original_popen
    observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(observed_subreaper)
    combined_notes = getattr(combined_error, "__notes__", ())
    if (
        combined_error is None
        or not root_signal_injected
        or cleanup_calls != 1
        or not restore_injected
        or observed_subreaper != initial_subreaper
        or len(processes) != 1
        or processes[0].poll() is None
        or not any("dispatch fixture root pidfd signal failed" in note for note in combined_notes)
        or not any("dispatch fixture descendant cleanup failed" in note for note in combined_notes)
        or not any("dispatch fixture subreaper restore failed" in note for note in combined_notes)
    ):
        raise SystemExit("dispatch fixture cleanup faults masked a primary or leaked state")

    cancellation_processes: list[subprocess.Popen[bytes]] = []
    cancellation_cleanup_calls = 0
    cleanup_cancellation = KeyboardInterrupt(
        "injected dispatch fixture cleanup cancellation"
    )

    def record_cancellation_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        cancellation_processes.append(process)
        return process

    def cancel_descendant_cleanup(_baseline):
        nonlocal cancellation_cleanup_calls
        cancellation_cleanup_calls += 1
        raise cleanup_cancellation

    subprocess.Popen = record_cancellation_process
    globals()["fixture_cleanup_descendants"] = cancel_descendant_cleanup
    cancellation_caught: BaseException | None = None
    try:
        try:
            run(
                "/usr/bin/python3",
                "-c",
                "import time;time.sleep(30)",
                cwd=cwd,
                timeout_seconds=0.05,
            )
        except BaseException as exc:
            cancellation_caught = exc
    finally:
        globals()["fixture_cleanup_descendants"] = original_cleanup
        subprocess.Popen = original_popen
    cancellation_notes = getattr(cancellation_caught, "__notes__", ())
    if (
        cancellation_caught is not cleanup_cancellation
        or cancellation_cleanup_calls != 1
        or len(cancellation_processes) != 1
        or cancellation_processes[0].poll() is None
        or not any(
            "dispatch fixture descendant cleanup failed" in note
            for note in cancellation_notes
        )
        or not any("earlier fixture failure" in note for note in cancellation_notes)
    ):
        raise SystemExit(
            "dispatch fixture cleanup cancellation lost caller policy"
        ) from cancellation_caught

    original_popen = subprocess.Popen
    original_cleanup = globals()["fixture_cleanup_descendants"]
    poll_failure = OSError("injected dispatch fixture root poll failure")
    poll_failed = False
    poll_wait_bypassed = False
    poll_cleanup_calls = 0
    poll_processes: list[tuple[subprocess.Popen[str], object]] = []

    def fail_first_root_poll(*args, **kwargs):
        nonlocal poll_failed, poll_wait_bypassed
        process = original_popen(*args, **kwargs)
        original_poll = process.poll
        original_wait = process.wait

        def bypass_initial_wait(timeout=None):
            nonlocal poll_wait_bypassed
            if not poll_wait_bypassed:
                poll_wait_bypassed = True
                return 0
            return original_wait(timeout=timeout)

        def fault_poll():
            nonlocal poll_failed
            if not poll_failed:
                poll_failed = True
                raise poll_failure
            return original_poll()

        process.poll = fault_poll
        process.wait = bypass_initial_wait
        poll_processes.append((process, original_poll))
        return process

    def record_poll_cleanup(baseline):
        nonlocal poll_cleanup_calls
        poll_cleanup_calls += 1
        return original_cleanup(baseline)

    subprocess.Popen = fail_first_root_poll
    globals()["fixture_cleanup_descendants"] = record_poll_cleanup
    poll_caught: BaseException | None = None
    try:
        try:
            run(
                "/usr/bin/python3",
                "-c",
                "import time;time.sleep(30)",
                cwd=cwd,
                timeout_seconds=0.05,
            )
        except BaseException as exc:
            poll_caught = exc
    finally:
        globals()["fixture_cleanup_descendants"] = original_cleanup
        subprocess.Popen = original_popen
    poll_reaped = True
    for process, original_poll in poll_processes:
        if original_poll() is None:
            poll_reaped = False
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2.0)
            except BaseException:
                pass
    if (
        not poll_failed
        or not poll_wait_bypassed
        or len(poll_processes) != 1
        or poll_cleanup_calls != 1
        or not poll_reaped
        or not isinstance(poll_caught, SystemExit)
        or str(poll_caught) != "dispatch fixture root poll failed"
    ):
        raise SystemExit(
            "dispatch fixture root-poll custody oracle drifted: "
            f"cleanup_calls={poll_cleanup_calls} reaped={poll_reaped} "
            f"caught={poll_caught!r}"
        ) from poll_caught

    original_restore = globals()["fixture_restore_subreaper"]
    priority_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(priority_initial_subreaper)
    priority_processes: list[subprocess.Popen[str]] = []
    priority_cleanup_calls = 0
    priority_restore_calls = 0
    ordinary_cleanup = OSError("injected dispatch ordinary cleanup failure")
    priority_cancellation = KeyboardInterrupt(
        "injected dispatch cleanup-priority cancellation"
    )

    def record_priority_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        priority_processes.append(process)
        return process

    def fail_priority_cleanup(_baseline):
        nonlocal priority_cleanup_calls
        priority_cleanup_calls += 1
        raise ordinary_cleanup

    def cancel_priority_restore(_previous):
        nonlocal priority_restore_calls
        priority_restore_calls += 1
        applied_error = original_restore(_previous)
        if applied_error is not None:
            priority_cancellation.add_note(
                "dispatch fixture real subreaper restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return priority_cancellation

    subprocess.Popen = record_priority_process
    globals()["fixture_cleanup_descendants"] = fail_priority_cleanup
    globals()["fixture_restore_subreaper"] = cancel_priority_restore
    priority_caught: BaseException | None = None
    try:
        try:
            run("/usr/bin/true", cwd=cwd)
        except BaseException as exc:
            priority_caught = exc
    finally:
        globals()["fixture_restore_subreaper"] = original_restore
        globals()["fixture_cleanup_descendants"] = original_cleanup
        subprocess.Popen = original_popen
    priority_observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(priority_observed_subreaper)
    if (
        priority_caught is not priority_cancellation
        or priority_cleanup_calls != 1
        or priority_restore_calls != 1
        or len(priority_processes) != 1
        or priority_processes[0].poll() is None
        or priority_observed_subreaper != priority_initial_subreaper
        or not isinstance(priority_caught.__cause__, FixtureCleanupError)
        or priority_caught.__cause__.__cause__ is not ordinary_cleanup
        or "earlier fixture failure" not in " ".join(
            getattr(priority_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "dispatch fixture internal cleanup failure masked cancellation"
        ) from priority_caught

    assignment_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(assignment_initial_subreaper)
    assignment_cancellation = KeyboardInterrupt(
        "injected dispatch initial subreaper-assignment cancellation"
    )
    assignment_calls = 0
    assignment_popen_calls = 0

    def cancel_initial_subreaper_assignment(enabled: bool) -> bool:
        nonlocal assignment_calls
        assignment_calls += 1
        previous = original_set_subreaper(enabled)
        if assignment_calls == 1:
            raise assignment_cancellation
        return previous

    def count_assignment_popen(*args, **kwargs):
        nonlocal assignment_popen_calls
        assignment_popen_calls += 1
        return original_popen(*args, **kwargs)

    globals()["fixture_set_subreaper"] = cancel_initial_subreaper_assignment
    subprocess.Popen = count_assignment_popen
    assignment_caught: BaseException | None = None
    try:
        try:
            run("/usr/bin/true", cwd=cwd)
        except BaseException as exc:
            assignment_caught = exc
    finally:
        subprocess.Popen = original_popen
        globals()["fixture_set_subreaper"] = original_set_subreaper
    assignment_observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(assignment_observed_subreaper)
    if (
        assignment_caught is not assignment_cancellation
        or assignment_calls != 2
        or assignment_popen_calls
        or assignment_observed_subreaper != assignment_initial_subreaper
    ):
        raise SystemExit(
            "dispatch initial subreaper assignment leaked state"
        ) from assignment_caught

    timeout_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(timeout_initial_subreaper)
    timeout_processes: list[subprocess.Popen[bytes]] = []
    timeout_restore_calls = 0
    timeout_cancellation = KeyboardInterrupt(
        "injected dispatch timeout-restore cancellation"
    )

    def record_timeout_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        timeout_processes.append(process)
        return process

    def cancel_timeout_restore(previous):
        nonlocal timeout_restore_calls
        timeout_restore_calls += 1
        applied_error = original_restore(previous)
        if applied_error is not None:
            timeout_cancellation.add_note(
                "dispatch fixture real timeout subreaper restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return timeout_cancellation

    subprocess.Popen = record_timeout_process
    globals()["fixture_restore_subreaper"] = cancel_timeout_restore
    timeout_caught: BaseException | None = None
    try:
        try:
            run(
                "/usr/bin/python3",
                "-c",
                "import time;time.sleep(30)",
                cwd=cwd,
                timeout_seconds=0.05,
            )
        except BaseException as exc:
            timeout_caught = exc
    finally:
        globals()["fixture_restore_subreaper"] = original_restore
        subprocess.Popen = original_popen
    timeout_observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(timeout_observed_subreaper)
    if (
        timeout_caught is not timeout_cancellation
        or timeout_restore_calls != 1
        or len(timeout_processes) != 1
        or timeout_processes[0].poll() is None
        or timeout_observed_subreaper != timeout_initial_subreaper
        or not isinstance(timeout_caught.__cause__, subprocess.TimeoutExpired)
    ):
        raise SystemExit(
            "dispatch timeout restore masked caller cancellation"
        ) from timeout_caught

    original_process_map = globals()["fixture_process_map"]
    setup_popen_calls = 0

    def count_setup_popen(*args, **kwargs):
        nonlocal setup_popen_calls
        setup_popen_calls += 1
        return original_popen(*args, **kwargs)

    subprocess.Popen = count_setup_popen
    setup_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(setup_initial_subreaper)
    setup_error = OSError("injected dispatch setup process-map failure")
    setup_cancellation = KeyboardInterrupt(
        "injected dispatch setup-restore cancellation"
    )
    setup_restore_calls = 0

    def fail_setup_process_map():
        raise setup_error

    def cancel_setup_restore(previous):
        nonlocal setup_restore_calls
        setup_restore_calls += 1
        applied_error = original_restore(previous)
        if applied_error is not None:
            setup_cancellation.add_note(
                "dispatch fixture real setup subreaper restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return setup_cancellation

    globals()["fixture_process_map"] = fail_setup_process_map
    globals()["fixture_restore_subreaper"] = cancel_setup_restore
    setup_caught: BaseException | None = None
    try:
        try:
            run("/usr/bin/true", cwd=cwd)
        except BaseException as exc:
            setup_caught = exc
    finally:
        globals()["fixture_restore_subreaper"] = original_restore
        globals()["fixture_process_map"] = original_process_map
    setup_observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(setup_observed_subreaper)
    if (
        setup_caught is not setup_cancellation
        or setup_cancellation.__cause__ is not setup_error
        or setup_restore_calls != 1
        or setup_popen_calls
        or setup_observed_subreaper != setup_initial_subreaper
    ):
        subprocess.Popen = original_popen
        raise SystemExit(
            "dispatch setup restore masked caller cancellation"
        ) from setup_caught

    inherited_cancellation = KeyboardInterrupt(
        "injected dispatch inherited-child restore cancellation"
    )
    inherited_restore_calls = 0

    def inherited_process_map():
        return {81001: (os.getpid(), 91001)}

    def cancel_inherited_restore(previous):
        nonlocal inherited_restore_calls
        inherited_restore_calls += 1
        applied_error = original_restore(previous)
        if applied_error is not None:
            inherited_cancellation.add_note(
                "dispatch fixture real inherited-child restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return inherited_cancellation

    globals()["fixture_process_map"] = inherited_process_map
    globals()["fixture_restore_subreaper"] = cancel_inherited_restore
    inherited_caught: BaseException | None = None
    try:
        try:
            run("/usr/bin/true", cwd=cwd)
        except BaseException as exc:
            inherited_caught = exc
    finally:
        globals()["fixture_restore_subreaper"] = original_restore
        globals()["fixture_process_map"] = original_process_map
    inherited_observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(inherited_observed_subreaper)
    if (
        inherited_caught is not inherited_cancellation
        or inherited_restore_calls != 1
        or not isinstance(inherited_caught.__cause__, FixtureCleanupError)
        or setup_popen_calls
        or inherited_observed_subreaper != setup_initial_subreaper
    ):
        subprocess.Popen = original_popen
        raise SystemExit(
            "dispatch inherited-child policy masked caller cancellation"
        ) from inherited_caught

    baseline_cancellation = KeyboardInterrupt(
        "injected dispatch baseline-derivation cancellation"
    )

    class CancellingBaseline(dict[int, tuple[int, int]]):
        def items(self):
            raise baseline_cancellation

    globals()["fixture_process_map"] = lambda: CancellingBaseline()
    baseline_caught: BaseException | None = None
    try:
        try:
            run("/usr/bin/true", cwd=cwd)
        except BaseException as exc:
            baseline_caught = exc
    finally:
        globals()["fixture_process_map"] = original_process_map
        subprocess.Popen = original_popen
    baseline_observed_subreaper = original_set_subreaper(True)
    original_set_subreaper(baseline_observed_subreaper)
    if (
        baseline_caught is not baseline_cancellation
        or setup_popen_calls
        or baseline_observed_subreaper != setup_initial_subreaper
    ):
        raise SystemExit(
            "dispatch baseline cancellation leaked subreaper state"
        ) from baseline_caught


def require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise SystemExit(f"{label} failed: {result.stderr.strip()}")


def wait_fixture_child(
    child: int,
    label: str,
    *,
    terminate_immediately: bool = False,
) -> int:
    deadline = time.monotonic() + (0.0 if terminate_immediately else 20.0)
    timed_out = False
    status: int | None = None
    reaped = False
    primary: BaseException | None = None
    while True:
        try:
            waited, observed_status = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            failure = FixtureCleanupError(f"{label} lost child ownership")
            failure.__cause__ = exc
            primary = fixture_choose_failure(
                primary,
                failure,
                f"{label} child ownership also failed",
            )
            break
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} child wait also failed",
            )
            break
        if waited == child:
            status = observed_status
            reaped = True
            break
        if waited != 0:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(f"{label} waited for an unexpected child"),
                f"{label} child wait also diverged",
            )
            break
        if time.monotonic() >= deadline:
            timed_out = True
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} child kill also failed",
                )
            deadline = time.monotonic() + 1.0
        try:
            time.sleep(0.01)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} child wait sleep also failed",
            )
            break
    if not reaped:
        cleanup_deadline = time.monotonic() + 2.0
        while time.monotonic() < cleanup_deadline and not reaped:
            try:
                waited, observed_status = os.waitpid(child, os.WNOHANG)
            except InterruptedError:
                continue
            except ChildProcessError as exc:
                failure = FixtureCleanupError(
                    f"{label} lost child ownership during cleanup"
                )
                failure.__cause__ = exc
                primary = fixture_choose_failure(
                    primary,
                    failure,
                    f"{label} child cleanup also lost ownership",
                )
                break
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} child cleanup wait also failed",
                )
                continue
            if waited == child:
                status = observed_status
                reaped = True
                break
            if waited != 0:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(
                        f"{label} cleanup waited for an unexpected child"
                    ),
                    f"{label} child cleanup wait also diverged",
                )
                break
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} child cleanup kill also failed",
                )
            try:
                time.sleep(0.01)
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} child cleanup sleep also failed",
                )
    if not reaped:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{label} child cleanup did not converge"),
            f"{label} child cleanup also did not converge",
        )
    if timed_out:
        timeout_failure = FixtureCleanupError(
            f"{label} exceeded its fixture deadline"
        )
        primary = fixture_choose_failure(
            primary,
            timeout_failure,
            f"{label} timeout also occurred",
        )
    if primary is not None:
        fixture_raise_selected_failure(primary)
    if status is None:
        raise FixtureCleanupError(f"{label} child status is unavailable")
    return status


def spawn_fixture_child(
    owner: FixtureChildOwner,
    child_main,
    label: str,
) -> None:
    if owner.pid > 0:
        raise FixtureCleanupError(f"{label} owner is already populated")
    caller_pid = os.getpid()
    baseline = fixture_process_map()
    latch = FixtureSignalLatch()
    latch.enter()
    primary: BaseException | None = None
    discovered: list[int] = []
    try:
        owner.pid = os.fork()
        if owner.pid == 0:
            try:
                for signum in reversed(latch.installed_handlers):
                    signal.signal(signum, latch.previous_handlers[signum])
                if latch.original_mask is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, latch.original_mask)
                status = child_main()
                if type(status) is not int or not 0 <= status <= 255:
                    status = 125
            except BaseException:
                os._exit(125)
            os._exit(status)
    except BaseException as exc:
        if os.getpid() != caller_pid:
            os._exit(125)
        primary = exc
        try:
            after = fixture_process_map()
            discovered = sorted(
                pid
                for pid, (parent, _start_time) in after.items()
                if parent == caller_pid and pid not in baseline
            )
        except BaseException as discovery_exc:
            primary = fixture_choose_failure(
                primary,
                discovery_exc,
                f"{label} applied-fork discovery also failed",
            )
    selected = latch.close(primary)
    if selected is not None:
        cleanup_children = ([owner.pid] if owner.pid > 0 else []) + discovered
        for owned_child in dict.fromkeys(cleanup_children):
            try:
                selected, _status, reaped = settle_owned_fixture_child_pid(
                    owned_child,
                    selected,
                    f"{label} handoff child",
                )
            except BaseException as cleanup_exc:
                selected = fixture_choose_failure(
                    selected,
                    cleanup_exc,
                    f"{label} handoff cleanup also failed",
                )
            else:
                if reaped and owned_child == owner.pid:
                    owner.pid = -1
        fixture_raise_selected_failure(selected)
    if owner.pid <= 0:
        raise FixtureCleanupError(f"{label} child identity was not published")


def spawn_fixture_popen(
    owner: FixturePopenOwner,
    arguments: list[str],
    *,
    cwd: pathlib.Path,
    label: str,
) -> None:
    if owner.process is not None:
        raise FixtureCleanupError(f"{label} owner is already populated")
    before = fixture_process_map()
    baseline_children = frozenset(
        pid for pid, (parent, _start_time) in before.items() if parent == os.getpid()
    )
    latch = FixtureSignalLatch()
    latch.enter()
    primary: BaseException | None = None
    try:
        owner.process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": str(cwd / "home"),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except BaseException as exc:
        primary = exc
    selected = latch.close(primary)
    if selected is not None:
        try:
            if owner.process is not None:
                selected = settle_fixture_popen_owner(
                    owner,
                    selected,
                    f"{label} handoff target",
                )
            else:
                fixture_cleanup_descendants(baseline_children)
        except BaseException as cleanup_exc:
            selected = fixture_choose_failure(
                selected,
                cleanup_exc,
                f"{label} handoff cleanup also failed",
            )
        fixture_raise_selected_failure(selected)
    if owner.process is None:
        raise FixtureCleanupError(f"{label} process identity was not published")


def settle_owned_fixture_child_pid(
    pid: int,
    primary: BaseException | None,
    label: str,
) -> tuple[BaseException | None, int | None, bool]:
    status: int | None = None
    reaped = False
    signal_attempts = 0
    for attempt in range(201):
        try:
            waited, observed_status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            waited = 0
        except ChildProcessError:
            reaped = True
            break
        except BaseException as exc:
            waited = 0
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} wait also failed",
            )
        else:
            if waited == pid:
                status = observed_status
                reaped = True
                break
            if waited != 0:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(
                        f"{label} waited for an unexpected child"
                    ),
                    f"{label} wait also diverged",
                )
                break
        if signal_attempts < 3:
            signal_attempts += 1
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} signal also failed",
                )
        if attempt < 200:
            try:
                time.sleep(0.01)
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} cleanup sleep also failed",
                )
    if not reaped:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{label} cleanup did not converge"),
            f"{label} cleanup also did not converge",
        )
    return primary, status, reaped


def settle_fixture_child_owner(
    owner: FixtureChildOwner,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    if owner.pid <= 0:
        return primary
    primary, _status, reaped = settle_owned_fixture_child_pid(
        owner.pid,
        primary,
        label,
    )
    if reaped:
        owner.pid = -1
    return primary


def settle_fixture_popen_owner(
    owner: FixturePopenOwner,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    if owner.process is None:
        return primary
    primary, status, reaped = settle_owned_fixture_child_pid(
        owner.process.pid,
        primary,
        label,
    )
    if reaped:
        if status is not None:
            try:
                owner.process.returncode = os.waitstatus_to_exitcode(status)
            except ValueError as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} exit-status conversion also failed",
                )
        if owner.process.returncode is None:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(f"{label} Popen status is unavailable"),
                f"{label} Popen settlement also lacked status",
            )
        else:
            owner.process = None
    return primary


def fixture_owner_is_populated(
    owner: FixtureDescriptorOwner | FixtureChildOwner | FixturePopenOwner,
) -> bool:
    if isinstance(owner, FixtureDescriptorOwner):
        return owner.descriptor >= 0
    if isinstance(owner, FixtureChildOwner):
        return owner.pid > 0
    return owner.process is not None


def settle_fixture_registered_owner(
    owner: FixtureDescriptorOwner | FixtureChildOwner | FixturePopenOwner,
    primary: BaseException | None,
    label: str,
    *,
    attempts: int = 3,
) -> BaseException | None:
    if fixture_owner_is_populated(owner) and primary is None:
        if isinstance(owner, FixtureDescriptorOwner):
            kind = "descriptor"
        elif isinstance(owner, FixtureChildOwner):
            kind = "child"
        else:
            kind = "Popen"
        primary = FixtureCleanupError(f"{label} {kind} outlived its scope")
    if attempts < 1:
        raise ValueError("fixture owner settlement attempts must be positive")
    for _ in range(attempts):
        try:
            if isinstance(owner, FixtureDescriptorOwner):
                primary = settle_fixture_descriptor_owner(owner, primary, label)
            elif isinstance(owner, FixtureChildOwner):
                primary = settle_fixture_child_owner(owner, primary, label)
            else:
                primary = settle_fixture_popen_owner(owner, primary, label)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} settlement also failed",
            )
        if not fixture_owner_is_populated(owner):
            return primary
    return fixture_choose_failure(
        primary,
        FixtureCleanupError(f"{label} settlement did not converge"),
        f"{label} custody also did not converge",
    )


@contextlib.contextmanager
def fixture_owner_lifetime(label: str):
    signal_latch = FixtureOwnerSignalLatch()
    owners: list[
        FixtureDescriptorOwner | FixtureChildOwner | FixturePopenOwner
    ] = []
    primary: BaseException | None = None
    scope_registered = False
    try:
        signal_latch.enter()
        _FIXTURE_OWNER_SCOPES.append(owners)
        scope_registered = True
        yield
    except BaseException as exc:
        if isinstance(exc, FixtureOwnerCancellation):
            primary = exc.caller_policy
        else:
            primary = exc
    finally:
        try:
            signal_latch.begin_finalizer()
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} finalizer transition also failed",
            )
        try:
            if scope_registered and (
                not _FIXTURE_OWNER_SCOPES
                or _FIXTURE_OWNER_SCOPES[-1] is not owners
            ):
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(f"{label} owner scope stack diverged"),
                    f"{label} owner scope also diverged",
                )
                _FIXTURE_OWNER_SCOPES.append(owners)
            pending = list(reversed(owners))
            known_owner_ids = {id(owner) for owner in owners}
            settlement_counts: dict[int, int] = {}
            drained = 0

            def remove_settled_owner(owner) -> None:
                for index, registered in enumerate(owners):
                    if registered is owner:
                        del owners[index]
                        known_owner_ids.discard(id(owner))
                        return

            while (
                scope_registered
                and pending
                and drained < FIXTURE_OWNER_DRAIN_LIMIT
            ):
                owner = pending.pop(0)
                owner_id = id(owner)
                if fixture_owner_is_populated(owner):
                    settlement_counts[owner_id] = (
                        settlement_counts.get(owner_id, 0) + 1
                    )
                    try:
                        primary = settle_fixture_registered_owner(
                            owner,
                            primary,
                            f"{label} settlement {drained}",
                            attempts=1,
                        )
                    except BaseException as exc:
                        primary = fixture_choose_failure(
                            primary,
                            exc,
                            f"{label} settlement return also failed",
                        )
                    if fixture_owner_is_populated(owner):
                        if (
                            settlement_counts[owner_id]
                            < FIXTURE_OWNER_SETTLEMENT_ROUNDS
                        ):
                            pending.append(owner)
                    else:
                        remove_settled_owner(owner)
                else:
                    remove_settled_owner(owner)

                # A settlement callback may register a new owner. Publish it
                # into the same bounded round-robin queue before moving on.
                for candidate in tuple(owners):
                    candidate_id = id(candidate)
                    if candidate_id not in known_owner_ids:
                        known_owner_ids.add(candidate_id)
                        if fixture_owner_is_populated(candidate):
                            pending.append(candidate)
                drained += 1

            for candidate in tuple(owners):
                if not fixture_owner_is_populated(candidate):
                    remove_settled_owner(candidate)
            residual_owners = [
                candidate for candidate in owners
                if fixture_owner_is_populated(candidate)
            ]
            if pending or residual_owners:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(
                        f"{label} owner drain retained "
                        f"{len(residual_owners)} residual owner(s)"
                    ),
                    f"{label} owner custody remains registered",
                )
                # Keep this exact scope registered while any owner is live;
                # callers can inspect the residual custody after failure.
                if not any(
                    candidate is owners for candidate in _FIXTURE_OWNER_SCOPES
                ):
                    _FIXTURE_OWNER_SCOPES.append(owners)
            else:
                residual_scope_indexes = [
                    index
                    for index, candidate in enumerate(_FIXTURE_OWNER_SCOPES)
                    if candidate is owners
                ]
                if not residual_scope_indexes:
                    primary = fixture_choose_failure(
                        primary,
                        FixtureCleanupError(
                            f"{label} owner scope changed during settlement"
                        ),
                        f"{label} owner scope also changed during settlement",
                    )
                else:
                    for index in reversed(residual_scope_indexes):
                        del _FIXTURE_OWNER_SCOPES[index]
                    scope_registered = False
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} owner finalizer also failed",
            )
        finally:
            primary = signal_latch.close(primary)
    if primary is not None:
        fixture_raise_selected_failure(primary)


def test_fixture_owner_finalizer_cancellation(cwd: pathlib.Path) -> None:
    if _FIXTURE_OWNER_SCOPES:
        raise SystemExit("dispatch fixture owner-scope oracle did not start empty")
    original_settle_descriptor = globals()["settle_fixture_descriptor_owner"]
    original_begin_finalizer = FixtureOwnerSignalLatch.begin_finalizer

    def run_case(mode: str) -> None:
        scope_before = tuple(_FIXTURE_OWNER_SCOPES)
        descriptors_before = fixture_open_descriptor_set()
        mask_before = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
        handlers_before = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }
        descriptor_owner: FixtureDescriptorOwner | None = None
        child_owner: FixtureChildOwner | None = None
        popen_owner: FixturePopenOwner | None = None
        descriptor = -1
        child = -1
        process: subprocess.Popen[bytes] | None = None
        inner_scope: list[
            FixtureDescriptorOwner | FixtureChildOwner | FixturePopenOwner
        ] | None = None
        fired = False
        post_signal_calls = 0
        direct_cancellation = (
            SystemExit("injected dispatch owner-finalizer SystemExit")
            if mode == "body-system-exit"
            else KeyboardInterrupt(
                "injected dispatch owner-finalizer direct cancellation"
            )
        )
        ordinary_body_failure = RuntimeError(
            "injected dispatch owner-finalizer ordinary failure"
        )
        signum = signal.SIGINT if mode != "term" else signal.SIGTERM

        def child_main() -> int:
            time.sleep(30)
            return 0

        def interrupt_first_settlement(
            owner: FixtureDescriptorOwner,
            primary: BaseException | None,
            label: str,
        ) -> BaseException | None:
            nonlocal fired
            if not fired:
                fired = True
                if mode == "python":
                    raise direct_cancellation
                if mode != "transition":
                    os.kill(os.getpid(), signum)
            selected = original_settle_descriptor(owner, primary, label)
            if mode == "return":
                raise direct_cancellation
            return selected

        def interrupt_finalizer_transition(latch: FixtureOwnerSignalLatch) -> None:
            nonlocal fired
            original_begin_finalizer(latch)
            if not fired:
                fired = True
                os.kill(os.getpid(), signal.SIGINT)

        globals()["settle_fixture_descriptor_owner"] = interrupt_first_settlement
        if mode == "transition":
            FixtureOwnerSignalLatch.begin_finalizer = interrupt_finalizer_transition
        caught: BaseException | None = None
        try:
            try:
                with fixture_owner_lifetime(
                    f"dispatch owner-finalizer {mode} oracle"
                ):
                    inner_scope = _FIXTURE_OWNER_SCOPES[-1]
                    popen_owner = FixturePopenOwner()
                    spawn_fixture_popen(
                        popen_owner,
                        ["/usr/bin/sleep", "30"],
                        cwd=cwd,
                        label=f"dispatch owner-finalizer {mode} Popen",
                    )
                    assert popen_owner.process is not None
                    process = popen_owner.process
                    child_owner = FixtureChildOwner()
                    spawn_fixture_child(
                        child_owner,
                        child_main,
                        f"dispatch owner-finalizer {mode} child",
                    )
                    child = child_owner.pid
                    descriptor_owner = FixtureDescriptorOwner()
                    metadata = os.stat("/dev/null", follow_symlinks=False)
                    acquire_existing_fixture_descriptor(
                        descriptor_owner,
                        "/dev/null",
                        os.O_RDONLY | os.O_CLOEXEC,
                        (metadata.st_dev, metadata.st_ino),
                        f"dispatch owner-finalizer {mode} descriptor",
                    )
                    descriptor = descriptor_owner.descriptor
                    if mode in (
                        "body-caller",
                        "body-system-exit",
                        "body-error",
                    ):
                        fired = True
                        try:
                            raise (
                                ordinary_body_failure
                                if mode == "body-error"
                                else direct_cancellation
                            )
                        except BaseException:
                            os.kill(os.getpid(), signal.SIGINT)
                            post_signal_calls += 1
                            os.fstat(descriptor)
                    if mode in ("body-int", "body-term"):
                        fired = True
                        os.kill(os.getpid(), signum)
                        post_signal_calls += 1
                        os.fstat(descriptor)
            except BaseException as exc:
                caught = exc
        finally:
            FixtureOwnerSignalLatch.begin_finalizer = original_begin_finalizer
            globals()["settle_fixture_descriptor_owner"] = original_settle_descriptor

        descriptor_closed = descriptor >= 0
        if descriptor >= 0:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                descriptor_closed = exc.errno == errno.EBADF
            else:
                descriptor_closed = False
                os.close(descriptor)

        def require_exact_reap(pid: int) -> bool:
            if pid <= 0:
                return False
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError as exc:
                return exc.errno == errno.ECHILD
            if waited == 0:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            return False

        child_reaped = require_exact_reap(child)
        process_returncode = process.returncode if process is not None else None
        process_reaped = require_exact_reap(process.pid if process is not None else -1)
        expected_failure = (
            caught is direct_cancellation
            if mode in (
                "python",
                "return",
                "body-caller",
                "body-system-exit",
            )
            else (
                isinstance(caught, FixturePublicFailure)
                and caught.code == 128 + signum
            )
        )
        if (
            not fired
            or post_signal_calls != 0
            or not expected_failure
            or descriptor_owner is None
            or descriptor_owner.descriptor != -1
            or not descriptor_closed
            or child_owner is None
            or child_owner.pid != -1
            or not child_reaped
            or popen_owner is None
            or popen_owner.process is not None
            or process_returncode is None
            or process_returncode != -signal.SIGKILL
            or not process_reaped
            or inner_scope is None
            or inner_scope
            or tuple(_FIXTURE_OWNER_SCOPES) != scope_before
            or fixture_open_descriptor_set() != descriptors_before
            or frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
            != mask_before
            or any(
                signal.getsignal(signum) is not handler
                for signum, handler in handlers_before.items()
            )
        ):
            raise SystemExit(
                f"dispatch owner-finalizer {mode} cancellation custody drifted"
            ) from caught

    for mode in (
        "int",
        "term",
        "python",
        "return",
        "body-int",
        "body-term",
        "body-caller",
        "body-system-exit",
        "body-error",
        "transition",
    ):
        run_case(mode)
    with fixture_owner_lifetime("dispatch owner-finalizer nested outer"):
        outer_scope = _FIXTURE_OWNER_SCOPES[-1]
        run_case("int")
        if (
            len(_FIXTURE_OWNER_SCOPES) != 1
            or _FIXTURE_OWNER_SCOPES[-1] is not outer_scope
            or outer_scope
        ):
            raise SystemExit("dispatch nested owner-scope identity drifted")
    if _FIXTURE_OWNER_SCOPES:
        raise SystemExit("dispatch fixture owner-scope oracle left stack residue")
    nested_signal_post_calls = 0
    nested_signal_caught: BaseException | None = None
    try:
        with fixture_owner_lifetime("dispatch nested-signal outer"):
            with fixture_owner_lifetime("dispatch nested-signal inner"):
                os.kill(os.getpid(), signal.SIGTERM)
                nested_signal_post_calls += 1
                FixtureDescriptorOwner()
    except BaseException as exc:
        nested_signal_caught = exc
    if (
        nested_signal_post_calls != 0
        or not isinstance(nested_signal_caught, FixturePublicFailure)
        or nested_signal_caught.code != 143
        or _FIXTURE_OWNER_SCOPES
    ):
        raise SystemExit(
            "dispatch nested owner-scope signal unwind drifted"
        ) from nested_signal_caught
    for caller_policy in (
        KeyboardInterrupt("dispatch owner caller KeyboardInterrupt"),
        SystemExit("dispatch owner caller SystemExit"),
    ):
        caller_post_signal_calls = 0
        caller_caught: BaseException | None = None
        try:
            with fixture_owner_lifetime("dispatch owner caller-priority"):
                try:
                    raise caller_policy
                finally:
                    os.kill(os.getpid(), signal.SIGTERM)
                    caller_post_signal_calls += 1
                    FixtureDescriptorOwner()
        except BaseException as exc:
            caller_caught = exc
        if (
            caller_caught is not caller_policy
            or caller_post_signal_calls != 0
            or _FIXTURE_OWNER_SCOPES
        ):
            raise SystemExit(
                "dispatch owner caller-policy signal priority drifted"
            ) from caller_caught
    direct_body_cancellation = KeyboardInterrupt(
        "injected dispatch nested owner-scope body cancellation"
    )
    outer_scope = None
    inner_scope = None
    direct_body_caught: BaseException | None = None
    try:
        with fixture_owner_lifetime("dispatch direct-body outer"):
            outer_scope = _FIXTURE_OWNER_SCOPES[-1]
            with fixture_owner_lifetime("dispatch direct-body inner"):
                inner_scope = _FIXTURE_OWNER_SCOPES[-1]
                raise direct_body_cancellation
    except BaseException as exc:
        direct_body_caught = exc
    if (
        direct_body_caught is not direct_body_cancellation
        or outer_scope is None
        or outer_scope
        or inner_scope is None
        or inner_scope
        or _FIXTURE_OWNER_SCOPES
    ):
        raise SystemExit(
            "dispatch nested owner-scope body cancellation drifted"
        ) from direct_body_caught


@fixture_owner_scoped
def test_fixture_owner_fairness_and_capacity() -> None:
    """Ensure one stubborn owner cannot starve earlier custody or bypass the cap."""
    if len(_FIXTURE_OWNER_SCOPES) != 1:
        raise SystemExit("dispatch fairness oracle did not start in one scope")
    outer_scope = _FIXTURE_OWNER_SCOPES[-1]
    before_descriptors = fixture_open_descriptor_set()
    original_settle = globals()["settle_fixture_descriptor_owner"]
    closable_owner: FixtureDescriptorOwner | None = None
    stubborn_owner: FixtureDescriptorOwner | None = None
    inner_scope: list[
        FixtureDescriptorOwner | FixtureChildOwner | FixturePopenOwner
    ] | None = None
    stubborn_calls = 0

    def stubborn_settle(
        owner: FixtureDescriptorOwner,
        primary: BaseException | None,
        label: str,
        **kwargs,
    ) -> BaseException | None:
        nonlocal stubborn_calls
        if owner is stubborn_owner:
            stubborn_calls += 1
            return fixture_choose_failure(
                primary,
                FixtureCleanupError("dispatch fairness stubborn owner"),
                f"{label} stubborn owner remained populated",
            )
        return original_settle(owner, primary, label, **kwargs)

    globals()["settle_fixture_descriptor_owner"] = stubborn_settle
    caught: BaseException | None = None
    try:
        try:
            with fixture_owner_lifetime("dispatch owner fairness"):
                inner_scope = _FIXTURE_OWNER_SCOPES[-1]
                closable_owner = FixtureDescriptorOwner()
                metadata = os.stat("/dev/null", follow_symlinks=False)
                acquire_existing_fixture_descriptor(
                    closable_owner,
                    "/dev/null",
                    os.O_RDONLY | os.O_CLOEXEC,
                    (metadata.st_dev, metadata.st_ino),
                    "dispatch fairness closable owner",
                )
                stubborn_owner = FixtureDescriptorOwner()
                acquire_existing_fixture_descriptor(
                    stubborn_owner,
                    "/dev/null",
                    os.O_RDONLY | os.O_CLOEXEC,
                    (metadata.st_dev, metadata.st_ino),
                    "dispatch fairness stubborn owner",
                )
        except BaseException as exc:
            caught = exc
    finally:
        globals()["settle_fixture_descriptor_owner"] = original_settle

    if (
        not isinstance(caught, FixturePublicFailure)
        or stubborn_calls <= 0
        or stubborn_calls > FIXTURE_OWNER_SETTLEMENT_ROUNDS
        or closable_owner is None
        or closable_owner.descriptor >= 0
        or inner_scope is None
        or stubborn_owner is None
        or stubborn_owner not in inner_scope
        or len(_FIXTURE_OWNER_SCOPES) != 2
        or _FIXTURE_OWNER_SCOPES[-2] is not outer_scope
        or _FIXTURE_OWNER_SCOPES[-1] is not inner_scope
    ):
        raise SystemExit(
            "dispatch owner fairness did not preserve bounded residual custody"
        ) from caught

    cleanup_primary = original_settle(
        stubborn_owner,
        None,
        "dispatch fairness residual cleanup",
    )
    if cleanup_primary is not None or stubborn_owner.descriptor >= 0:
        raise SystemExit("dispatch fairness residual cleanup failed") from cleanup_primary
    for index in range(len(inner_scope) - 1, -1, -1):
        if inner_scope[index] is stubborn_owner:
            del inner_scope[index]
    residual_scope_indexes = [
        index
        for index, candidate in enumerate(_FIXTURE_OWNER_SCOPES)
        if candidate is inner_scope
    ]
    for index in reversed(residual_scope_indexes):
        del _FIXTURE_OWNER_SCOPES[index]
    if any(candidate is inner_scope for candidate in _FIXTURE_OWNER_SCOPES):
        raise SystemExit("dispatch fairness residual scope was not removable")

    capacity_owners = [
        FixtureDescriptorOwner() for _ in range(FIXTURE_OWNER_LIMIT)
    ]
    acquisition_called = False
    original_acquire = globals()["acquire_existing_fixture_descriptor"]

    def forbidden_acquire(*args, **kwargs):
        nonlocal acquisition_called
        acquisition_called = True
        raise SystemExit("owner-cap rejection acquired a resource")

    globals()["acquire_existing_fixture_descriptor"] = forbidden_acquire
    capacity_caught: BaseException | None = None
    try:
        try:
            FixtureDescriptorOwner()
        except BaseException as exc:
            capacity_caught = exc
    finally:
        globals()["acquire_existing_fixture_descriptor"] = original_acquire
    if (
        not isinstance(capacity_caught, FixtureCleanupError)
        or "exceeds its bound" not in str(capacity_caught)
        or acquisition_called
        or fixture_open_descriptor_set() != before_descriptors
    ):
        raise SystemExit(
            "dispatch owner-cap rejection was not pre-acquisition and bounded"
        ) from capacity_caught


def wait_fixture_children(children: list[int], label: str) -> list[int]:
    statuses: list[int] = []
    primary: BaseException | None = None
    for index, child in enumerate(children):
        try:
            statuses.append(wait_fixture_child(child, f"{label} {index}"))
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} sibling cleanup also failed",
            )
    if primary is not None:
        fixture_raise_selected_failure(primary)
    return statuses


@fixture_owner_scoped
def test_direct_fork_custody() -> None:
    original_fork = os.fork
    created_children: list[int] = []
    assignment_cancellation = KeyboardInterrupt(
        "dispatch fixture fork-return assignment cancellation"
    )

    def fork_then_cancel() -> int:
        child = original_fork()
        if child > 0:
            created_children.append(child)
        raise assignment_cancellation

    os.fork = fork_then_cancel
    assignment_caught: BaseException | None = None
    assignment_owner = FixtureChildOwner()
    try:
        try:
            spawn_fixture_child(
                assignment_owner,
                lambda: 0,
                "dispatch applied-fork oracle",
            )
        except BaseException as exc:
            assignment_caught = exc
    finally:
        os.fork = original_fork
    if assignment_caught is not assignment_cancellation or len(created_children) != 1:
        raise SystemExit(
            "dispatch applied-fork custody oracle drifted"
        ) from assignment_caught
    try:
        os.waitpid(created_children[0], os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise SystemExit("dispatch applied-fork oracle left an unreaped child")

    created_kill_children: list[int] = []
    fork_failure = OSError("dispatch applied-fork ordinary handoff failure")
    kill_cancellation = KeyboardInterrupt(
        "dispatch applied-kill handoff cancellation"
    )
    original_kill = os.kill

    def fork_then_fail_parent() -> int:
        child = original_fork()
        if child == 0:
            return child
        created_kill_children.append(child)
        raise fork_failure

    def kill_then_cancel(pid: int, signum: int) -> None:
        original_kill(pid, signum)
        if pid in created_kill_children and signum == signal.SIGKILL:
            raise kill_cancellation

    os.fork = fork_then_fail_parent
    os.kill = kill_then_cancel
    kill_caught: BaseException | None = None
    kill_owner = FixtureChildOwner()
    try:
        try:
            spawn_fixture_child(
                kill_owner,
                lambda: (time.sleep(30.0), 0)[1],
                "dispatch applied-kill handoff oracle",
            )
        except BaseException as exc:
            kill_caught = exc
    finally:
        os.kill = original_kill
        os.fork = original_fork
    if kill_caught is not kill_cancellation or len(created_kill_children) != 1:
        for child in created_kill_children:
            try:
                original_kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
        raise SystemExit(
            "dispatch applied-kill handoff oracle drifted"
        ) from kill_caught
    try:
        remaining_child, _remaining_status = os.waitpid(
            created_kill_children[0],
            os.WNOHANG,
        )
    except ChildProcessError:
        pass
    else:
        if remaining_child == 0:
            original_kill(created_kill_children[0], signal.SIGKILL)
            os.waitpid(created_kill_children[0], 0)
        raise SystemExit("dispatch applied-kill handoff left an unreaped child")

    original_spawn = globals()["spawn_fixture_child"]
    returned_children: list[int] = []
    return_cancellation = KeyboardInterrupt(
        "dispatch fixture child-helper return cancellation"
    )

    def spawn_child_then_cancel(
        target_owner: FixtureChildOwner,
        child_main,
        label: str,
    ) -> None:
        original_spawn(target_owner, child_main, label)
        returned_children.append(target_owner.pid)
        raise return_cancellation

    returned_owner = FixtureChildOwner()
    globals()["spawn_fixture_child"] = spawn_child_then_cancel
    return_caught: BaseException | None = None
    try:
        try:
            spawn_fixture_child(
                returned_owner,
                lambda: (time.sleep(30.0), 0)[1],
                "dispatch returned-child oracle",
            )
        except BaseException as exc:
            return_caught = settle_fixture_child_owner(
                returned_owner,
                exc,
                "dispatch returned-child oracle",
            )
    finally:
        globals()["spawn_fixture_child"] = original_spawn
    return_reaped = False
    if len(returned_children) == 1:
        try:
            os.waitpid(returned_children[0], os.WNOHANG)
        except ChildProcessError:
            return_reaped = True
        if not return_reaped:
            try:
                original_kill(returned_children[0], signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(returned_children[0], 0)
            except ChildProcessError:
                pass
    if (
        return_caught is not return_cancellation
        or len(returned_children) != 1
        or not return_reaped
        or returned_owner.pid != -1
    ):
        raise SystemExit(
            "dispatch returned-child custody oracle drifted"
        ) from return_caught

    original_waitpid = os.waitpid
    for settlement_mode in ("signal", "wait"):
        settlement_owner = FixtureChildOwner()
        original_spawn(
            settlement_owner,
            lambda: (time.sleep(30.0), 0)[1],
            f"dispatch {settlement_mode}-settlement oracle spawn",
        )
        settlement_pid = settlement_owner.pid
        settlement_cancellation = KeyboardInterrupt(
            f"dispatch fixture applied-{settlement_mode} settlement cancellation"
        )
        settlement_fired = False

        def cancel_settlement_kill(pid: int, signum: int) -> None:
            nonlocal settlement_fired
            original_kill(pid, signum)
            if (
                settlement_mode == "signal"
                and pid == settlement_pid
                and signum == signal.SIGKILL
                and not settlement_fired
            ):
                settlement_fired = True
                raise settlement_cancellation

        def cancel_settlement_waitpid(pid: int, options: int):
            nonlocal settlement_fired
            result = original_waitpid(pid, options)
            if (
                settlement_mode == "wait"
                and pid == settlement_pid
                and result[0] == pid
                and not settlement_fired
            ):
                settlement_fired = True
                raise settlement_cancellation
            return result

        os.kill = cancel_settlement_kill
        os.waitpid = cancel_settlement_waitpid
        try:
            settlement_selected = settle_fixture_child_owner(
                settlement_owner,
                None,
                f"dispatch {settlement_mode}-settlement oracle",
            )
        finally:
            os.waitpid = original_waitpid
            os.kill = original_kill
        try:
            original_waitpid(settlement_pid, os.WNOHANG)
        except ChildProcessError:
            settlement_reaped = True
        else:
            settlement_reaped = False
            try:
                original_kill(settlement_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                original_waitpid(settlement_pid, 0)
            except ChildProcessError:
                pass
        if (
            settlement_selected is not settlement_cancellation
            or not settlement_fired
            or settlement_owner.pid != -1
            or not settlement_reaped
        ):
            raise SystemExit(
                f"dispatch applied-{settlement_mode} settlement custody drifted"
            ) from settlement_selected

    first_owner = FixtureChildOwner()
    second_owner = FixtureChildOwner()
    try:
        spawn_fixture_child(
            first_owner,
            lambda: 0,
            "dispatch sibling fork first",
        )
        first = first_owner.pid
        spawn_fixture_child(
            second_owner,
            lambda: (time.sleep(0.2), 0)[1],
            "dispatch sibling fork second",
        )
        second = second_owner.pid
    except BaseException as exc:
        selected: BaseException | None = exc
        selected = settle_fixture_child_owner(
            second_owner,
            selected,
            "dispatch sibling fork second",
        )
        selected = settle_fixture_child_owner(
            first_owner,
            selected,
            "dispatch sibling fork first",
        )
        assert selected is not None
        raise selected
    original_wait = globals()["wait_fixture_child"]
    wait_calls = 0
    sibling_cancellation = KeyboardInterrupt(
        "dispatch first-sibling wait cancellation"
    )

    def cancel_after_first_wait(child: int, label: str) -> int:
        nonlocal wait_calls
        status = original_wait(child, label)
        wait_calls += 1
        if wait_calls == 1:
            raise sibling_cancellation
        return status

    globals()["wait_fixture_child"] = cancel_after_first_wait
    sibling_caught: BaseException | None = None
    try:
        try:
            wait_fixture_children([first, second], "dispatch sibling oracle")
        except BaseException as exc:
            sibling_caught = exc
    finally:
        globals()["wait_fixture_child"] = original_wait
    if sibling_caught is not sibling_cancellation or wait_calls != 2:
        raise SystemExit(
            "dispatch sibling cleanup did not preserve caller cancellation"
        ) from sibling_caught
    for child in (first, second):
        try:
            os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            continue
        raise SystemExit("dispatch sibling cleanup left an unreaped child")
    first_owner.pid = -1
    second_owner.pid = -1


@fixture_owner_scoped
def test_direct_popen_custody(cwd: pathlib.Path) -> None:
    original_popen = subprocess.Popen
    created_processes: list[subprocess.Popen[bytes]] = []
    assignment_cancellation = KeyboardInterrupt(
        "dispatch fixture Popen-return assignment cancellation"
    )

    def popen_then_cancel(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        created_processes.append(process)
        raise assignment_cancellation

    owner = FixturePopenOwner()
    subprocess.Popen = popen_then_cancel
    assignment_caught: BaseException | None = None
    try:
        try:
            spawn_fixture_popen(
                owner,
                ["/usr/bin/sleep", "30"],
                cwd=cwd,
                label="dispatch applied-Popen oracle",
            )
        except BaseException as exc:
            assignment_caught = exc
            assignment_caught = settle_fixture_popen_owner(
                owner,
                assignment_caught,
                "dispatch applied-Popen oracle",
            )
    finally:
        subprocess.Popen = original_popen
    reaped_by_helper = False
    if len(created_processes) == 1:
        try:
            os.waitpid(created_processes[0].pid, os.WNOHANG)
        except ChildProcessError:
            reaped_by_helper = True
        if not reaped_by_helper:
            try:
                os.kill(created_processes[0].pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                created_processes[0].wait(timeout=2.0)
            except BaseException:
                pass
        else:
            created_processes[0].poll()
    if (
        assignment_caught is not assignment_cancellation
        or len(created_processes) != 1
        or not reaped_by_helper
        or owner.process is not None
    ):
        raise SystemExit(
            "dispatch applied-Popen custody oracle drifted"
        ) from assignment_caught

    original_spawn = globals()["spawn_fixture_popen"]
    returned_processes: list[subprocess.Popen[bytes]] = []
    return_cancellation = KeyboardInterrupt(
        "dispatch fixture Popen-helper return cancellation"
    )

    def spawn_then_cancel(
        target_owner: FixturePopenOwner,
        arguments: list[str],
        *,
        cwd: pathlib.Path,
        label: str,
    ) -> None:
        original_spawn(
            target_owner,
            arguments,
            cwd=cwd,
            label=label,
        )
        assert target_owner.process is not None
        returned_processes.append(target_owner.process)
        raise return_cancellation

    returned_owner = FixturePopenOwner()
    globals()["spawn_fixture_popen"] = spawn_then_cancel
    return_caught: BaseException | None = None
    try:
        try:
            spawn_fixture_popen(
                returned_owner,
                ["/usr/bin/sleep", "30"],
                cwd=cwd,
                label="dispatch returned-Popen oracle",
            )
        except BaseException as exc:
            return_caught = settle_fixture_popen_owner(
                returned_owner,
                exc,
                "dispatch returned-Popen oracle",
            )
    finally:
        globals()["spawn_fixture_popen"] = original_spawn
    return_reaped = False
    if len(returned_processes) == 1:
        try:
            os.waitpid(returned_processes[0].pid, os.WNOHANG)
        except ChildProcessError:
            return_reaped = True
        if not return_reaped:
            try:
                os.kill(returned_processes[0].pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                returned_processes[0].wait(timeout=2.0)
            except BaseException:
                pass
        else:
            returned_processes[0].poll()
    if (
        return_caught is not return_cancellation
        or len(returned_processes) != 1
        or not return_reaped
        or returned_owner.process is not None
    ):
        raise SystemExit(
            "dispatch returned-Popen custody oracle drifted"
        ) from return_caught

    settlement_owner = FixturePopenOwner()
    original_spawn(
        settlement_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="dispatch Popen signal-settlement oracle spawn",
    )
    assert settlement_owner.process is not None
    settlement_process = settlement_owner.process
    original_kill = os.kill
    settlement_cancellation = KeyboardInterrupt(
        "dispatch fixture Popen applied-signal settlement cancellation"
    )
    settlement_fired = False

    def cancel_popen_settlement_kill(pid: int, signum: int) -> None:
        nonlocal settlement_fired
        original_kill(pid, signum)
        if (
            pid == settlement_process.pid
            and signum == signal.SIGKILL
            and not settlement_fired
        ):
            settlement_fired = True
            raise settlement_cancellation

    os.kill = cancel_popen_settlement_kill
    try:
        settlement_selected = settle_fixture_popen_owner(
            settlement_owner,
            None,
            "dispatch Popen signal-settlement oracle",
        )
    finally:
        os.kill = original_kill
    try:
        os.waitpid(settlement_process.pid, os.WNOHANG)
    except ChildProcessError:
        settlement_reaped = True
    else:
        settlement_reaped = False
        try:
            original_kill(settlement_process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            settlement_process.wait(timeout=2.0)
        except BaseException:
            pass
    if (
        settlement_selected is not settlement_cancellation
        or not settlement_fired
        or settlement_owner.process is not None
        or settlement_process.returncode is None
        or not settlement_reaped
    ):
        raise SystemExit(
            "dispatch Popen signal-settlement custody drifted"
        ) from settlement_selected


def commit(repo: pathlib.Path, message: str) -> str:
    require_success(run("/usr/bin/git", "add", "-A", cwd=repo), "git add")
    require_success(
        run(
            "/usr/bin/git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            message,
            cwd=repo,
        ),
        "git commit",
    )
    result = run("/usr/bin/git", "rev-parse", "HEAD", cwd=repo)
    require_success(result, "git rev-parse")
    return result.stdout.strip()


def empty_commit(repo: pathlib.Path, message: str) -> str:
    require_success(
        run(
            "/usr/bin/git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            message,
            cwd=repo,
        ),
        "git empty commit",
    )
    result = run("/usr/bin/git", "rev-parse", "HEAD", cwd=repo)
    require_success(result, "git empty commit lookup")
    return result.stdout.strip()


def commit_tree(
    repo: pathlib.Path,
    tree: str,
    parents: tuple[str, ...],
    message: str,
) -> str:
    arguments = [
        "/usr/bin/git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit-tree",
        tree,
    ]
    for parent in parents:
        arguments.extend(("-p", parent))
    arguments.extend(("-m", message))
    result = run(*arguments, cwd=repo)
    require_success(result, "git commit-tree")
    candidate = result.stdout.strip()
    if len(candidate) != 40:
        raise SystemExit("git commit-tree returned a noncanonical object id")
    return candidate


def tree_id(repo: pathlib.Path, commit_id: str) -> str:
    result = run("/usr/bin/git", "show", "-s", "--format=%T", commit_id, cwd=repo)
    require_success(result, "git tree lookup")
    tree = result.stdout.strip()
    if len(tree) != 40:
        raise SystemExit("git tree lookup returned a noncanonical object id")
    return tree


def run_gate(repo: pathlib.Path, trusted: str, candidate: str) -> subprocess.CompletedProcess[str]:
    return run(
        "/usr/bin/python3",
        "-I",
        "-B",
        str(GATE),
        "--verify-only",
        "--repo-dir",
        str(repo),
        "--trusted-commit",
        trusted,
        "--candidate-commit",
        candidate,
        cwd=repo,
    )


def load_gate_module():
    spec = importlib.util.spec_from_file_location("haptics_workflow_gate", GATE)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load trusted workflow dispatch gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@fixture_owner_scoped
def test_running_gate_descriptor_close_custody(gate_module) -> None:
    gate_path = GATE.resolve(strict=True)
    gate_metadata = gate_path.stat()
    gate_identity = (gate_metadata.st_dev, gate_metadata.st_ino)
    gate_digest = hashlib.sha256(gate_path.read_bytes()).hexdigest()
    wrong_digest = "0" * 64 if gate_digest != "0" * 64 else "1" * 64

    def open_gate_descriptors() -> frozenset[int]:
        descriptors: set[int] = set()
        for descriptor in fixture_open_descriptor_set():
            try:
                metadata = os.fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
                continue
            if (metadata.st_dev, metadata.st_ino) == gate_identity:
                descriptors.add(descriptor)
        return frozenset(descriptors)

    baseline = open_gate_descriptors()
    mismatch_before = gate_module.bounded_gate_descriptor_set()
    mismatch_owner = FixtureDescriptorOwner()
    mismatch_metadata = os.stat("/dev/null", follow_symlinks=False)
    acquire_existing_fixture_descriptor(
        mismatch_owner,
        "/dev/null",
        os.O_RDONLY | os.O_CLOEXEC,
        (mismatch_metadata.st_dev, mismatch_metadata.st_ino),
        "workflow-gate mismatch oracle setup",
    )
    mismatch_descriptor = mismatch_owner.descriptor
    mismatch_cancellation = KeyboardInterrupt(
        "injected workflow-gate recovery mismatch cancellation"
    )
    mismatch_selected, mismatch_recovered = (
        gate_module.recover_gate_descriptor_handoff(
            mismatch_before,
            (0, 0),
            "workflow gate mismatch oracle",
            mismatch_cancellation,
        )
    )
    try:
        os.fstat(mismatch_descriptor)
    except OSError as exc:
        mismatch_closed = exc.errno == errno.EBADF
        if mismatch_closed:
            mismatch_owner.descriptor = -1
    else:
        mismatch_closed = False
        os.close(mismatch_descriptor)
    if (
        mismatch_selected is not mismatch_cancellation
        or mismatch_recovered
        or not mismatch_closed
        or "recovery identity also differed"
        not in " ".join(getattr(mismatch_selected, "__notes__", ()))
    ):
        raise SystemExit(
            "workflow-gate mismatch recovery custody drifted"
        ) from mismatch_selected

    original_open = gate_module.os.open
    open_cancellation = KeyboardInterrupt(
        "injected running-gate open handoff cancellation"
    )
    open_descriptors: list[int] = []

    def cancel_running_gate_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == os.fspath(gate_path) and not open_descriptors:
            open_descriptors.append(descriptor)
            raise open_cancellation
        return descriptor

    gate_module.os.open = cancel_running_gate_open
    open_caught: BaseException | None = None
    try:
        try:
            gate_module.attest_running_gate(gate_digest)
        except BaseException as exc:
            open_caught = exc
    finally:
        gate_module.os.open = original_open
    open_leaked = False
    for descriptor in open_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            open_leaked = True
            os.close(descriptor)
    if (
        open_caught is not open_cancellation
        or len(open_descriptors) != 1
        or open_leaked
        or open_gate_descriptors() != baseline
    ):
        raise SystemExit("running-gate open handoff custody drifted") from open_caught

    inherited_owner = FixtureDescriptorOwner()
    acquire_existing_fixture_descriptor(
        inherited_owner,
        gate_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        gate_identity,
        "running-gate inherited descriptor setup",
    )
    inherited_descriptor = inherited_owner.descriptor
    original_dup = gate_module.os.dup
    original_file = gate_module.__file__
    dup_cancellation = KeyboardInterrupt(
        "injected running-gate dup handoff cancellation"
    )
    duplicate_descriptors: list[int] = []

    def cancel_running_gate_dup(descriptor: int) -> int:
        duplicate = original_dup(descriptor)
        if descriptor == inherited_descriptor and not duplicate_descriptors:
            duplicate_descriptors.append(duplicate)
            raise dup_cancellation
        return duplicate

    gate_module.__file__ = f"/proc/self/fd/{inherited_descriptor}"
    gate_module.os.dup = cancel_running_gate_dup
    dup_caught: BaseException | None = None
    try:
        try:
            gate_module.attest_running_gate(gate_digest)
        except BaseException as exc:
            dup_caught = exc
    finally:
        gate_module.os.dup = original_dup
        gate_module.__file__ = original_file
        dup_caught = settle_fixture_descriptor_owner(
            inherited_owner,
            dup_caught,
            "running-gate inherited descriptor",
        )
    dup_leaked = False
    for descriptor in duplicate_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            dup_leaked = True
            os.close(descriptor)
    if (
        dup_caught is not dup_cancellation
        or len(duplicate_descriptors) != 1
        or inherited_owner.descriptor != -1
        or dup_leaked
        or open_gate_descriptors() != baseline
    ):
        raise SystemExit("running-gate dup handoff custody drifted") from dup_caught

    for applied, expected_digest in (
        (True, gate_digest),
        (False, wrong_digest),
    ):
        original_close = gate_module.os.close
        original_fstat = gate_module.os.fstat
        cancellation = KeyboardInterrupt(
            "injected applied running-gate close cancellation"
            if applied
            else "injected nonapplied running-gate close cancellation"
        )
        captured_descriptor = -1
        close_calls = 0

        def cancelling_close(descriptor: int) -> None:
            nonlocal captured_descriptor, close_calls
            metadata = original_fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != gate_identity:
                original_close(descriptor)
                return
            captured_descriptor = descriptor
            close_calls += 1
            if close_calls == 1:
                if applied:
                    original_close(descriptor)
                raise cancellation
            original_close(descriptor)

        observed: BaseException | None = None
        gate_module.os.close = cancelling_close
        try:
            try:
                gate_module.attest_running_gate(expected_digest)
            except BaseException as exc:
                observed = exc
        finally:
            gate_module.os.close = original_close

        if observed is not cancellation:
            raise SystemExit(
                "running-gate close custody did not preserve exact caller "
                f"cancellation for applied={applied}"
            )
        if captured_descriptor < 0 or close_calls != (1 if applied else 2):
            raise SystemExit(
                "running-gate close custody did not distinguish applied and "
                f"nonapplied close errors for applied={applied}"
            )
        try:
            original_fstat(captured_descriptor)
        except OSError as exc:
            descriptor_closed = exc.errno == errno.EBADF
        else:
            descriptor_closed = False
            original_close(captured_descriptor)
        if not descriptor_closed:
            raise SystemExit(
                "running-gate close custody retained its authenticated descriptor"
            )
        if applied:
            if cancellation.__cause__ is not None:
                raise SystemExit(
                    "successful running-gate attestation invented an earlier failure"
                )
        elif (
            not isinstance(cancellation.__cause__, gate_module.WorkflowGateError)
            or str(cancellation.__cause__)
            != "running gate source differs from its trusted digest"
        ):
            raise SystemExit(
                "running-gate close cancellation did not outrank and retain the "
                "earlier ordinary attestation failure"
            )
        if open_gate_descriptors() != baseline:
            raise SystemExit(
                "running-gate close custody left descriptor residue after "
                f"applied={applied}"
            )


@contextlib.contextmanager
def fixture_account_home(gate_module, home: pathlib.Path):
    original_lookup = gate_module.pwd.getpwuid
    account = list(original_lookup(os.geteuid()))
    account[5] = str(home)
    record = pwd.struct_passwd(account)

    def lookup(uid: int):
        if uid != os.geteuid():
            raise AssertionError("operator-home fixture queried an unexpected uid")
        return record

    gate_module.pwd.getpwuid = lookup
    try:
        yield
    finally:
        gate_module.pwd.getpwuid = original_lookup


@fixture_owner_scoped
def test_alternate_safe_home_rejected(gate_module, private: pathlib.Path) -> None:
    account_home = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir)
    alternate_home = private / "alternate-safe-home"
    alternate_home.mkdir(mode=0o700)
    previous_home = os.environ.get("HOME")
    try:
        os.environ["HOME"] = str(alternate_home)
        try:
            gate_module.require_operator_home()
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "workflow dispatch HOME differs from the account database":
                raise SystemExit(
                    f"alternate safe HOME was rejected at the wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit(
                "trusted gate accepted an alternate safe HOME instead of "
                f"the account home {account_home}"
            )
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


@fixture_owner_scoped
def test_dispatch_state_ancestry_policy(
    gate_module,
    private: pathlib.Path,
) -> None:
    home = private / "ancestry-home"
    parent = home / gate_module.DISPATCH_STATE_RELATIVE_DIRECTORY
    parent.mkdir(parents=True, mode=0o700)
    previous_home = os.environ.get("HOME")
    try:
        os.environ["HOME"] = str(home)
        with fixture_account_home(gate_module, home):
            if gate_module.require_operator_home() != home:
                raise SystemExit("account HOME did not remain canonical")
            gate_module.require_dispatch_state_ancestry(home, parent)
            paths = [home, home / ".local", home / ".local/state", parent]
            for path in paths:
                original_mode = path.stat().st_mode & 0o777
                path.chmod(original_mode | 0o020)
                try:
                    gate_module.require_dispatch_state_ancestry(home, parent)
                except gate_module.WorkflowGateError as exc:
                    expected = (
                        "workflow dispatch state directory ancestry differs from policy"
                    )
                    if str(exc) != expected:
                        raise SystemExit(
                            f"unsafe dispatch ancestor was rejected at the wrong boundary: {exc}"
                        ) from exc
                else:
                    raise SystemExit(
                        f"trusted gate accepted a group-writable dispatch ancestor: {path}"
                    )
                finally:
                    path.chmod(original_mode)
            real_parent = parent.with_name(f"{parent.name}.real")
            parent.rename(real_parent)
            parent.symlink_to(real_parent, target_is_directory=True)
            try:
                try:
                    gate_module.require_dispatch_state_ancestry(home, parent)
                except gate_module.WorkflowGateError as exc:
                    expected = (
                        "workflow dispatch state directory ancestry differs from policy"
                    )
                    if str(exc) != expected:
                        raise SystemExit(
                            f"symlink dispatch ancestor was rejected at the wrong boundary: {exc}"
                        ) from exc
                else:
                    raise SystemExit("trusted gate accepted a symlink dispatch ancestor")
            finally:
                parent.unlink()
                real_parent.rename(parent)
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


@fixture_owner_scoped
def test_corrupt_tree_rejected_before_validators(
    gate_module,
    repo: pathlib.Path,
    trusted: str,
    candidate: str,
    private: pathlib.Path,
) -> None:
    root_tree = tree_id(repo, candidate)
    loose_tree = repo / ".git/objects" / root_tree[:2] / root_tree[2:]
    if not loose_tree.is_file():
        raise SystemExit("corrupt-tree fixture object is not loose")
    compressed_tree = loose_tree.read_bytes()
    tree_object = zlib.decompress(compressed_tree)
    corrupted_tree_object = tree_object.replace(
        b"fixture-anchor\0",
        b"fixture-anchos\0",
        1,
    )
    if (
        corrupted_tree_object == tree_object
        or len(corrupted_tree_object) != len(tree_object)
    ):
        raise SystemExit("corrupt-tree fixture did not preserve object size")

    original_runner = gate_module.run_bounded_process
    validator_started = False
    deadline = time.monotonic() + 10.0

    def guarded_runner(arguments, **kwargs):
        nonlocal validator_started
        if arguments[0] == "/usr/bin/git":
            if kwargs["environment"].get("GIT_NO_LAZY_FETCH") != "1":
                raise AssertionError("tree authentication enabled lazy object fetching")
            if kwargs["deadline"] != deadline:
                raise AssertionError("tree authentication forked its absolute deadline")
        if kwargs.get("label") == "trusted workflow validator":
            validator_started = True
            raise AssertionError(
                "corrupt tree reached a trusted workflow validator"
            )
        return original_runner(arguments, **kwargs)

    loose_tree.chmod(0o600)
    loose_tree.write_bytes(zlib.compress(corrupted_tree_object))
    try:
        gate_module.run_bounded_process = guarded_runner
        try:
            gate_module.verify_candidate(
                repo,
                trusted,
                candidate,
                deadline=deadline,
            )
        except gate_module.WorkflowGateError as exc:
            expected = "candidate commit root tree bytes differ from its object id"
            if str(exc) != expected:
                raise SystemExit(
                    f"corrupt tree was rejected at the wrong boundary: {exc}"
                ) from exc
        except AssertionError as exc:
            raise SystemExit(
                "trusted gate reached a validator before authenticating the "
                f"candidate tree: {exc}"
            ) from exc
        else:
            raise SystemExit("trusted gate accepted a same-size corrupt loose tree")
        finally:
            gate_module.run_bounded_process = original_runner
        if validator_started:
            raise SystemExit("corrupt tree crossed the trusted-validator boundary")

        operator_home = private / "corrupt-tree-operator-home"
        state_parent = operator_home / gate_module.DISPATCH_STATE_RELATIVE_DIRECTORY
        state_parent.mkdir(parents=True, mode=0o700)
        state_path = state_parent / f"{candidate}.diagnostic.tsv"
        arguments = (
            "--dispatch",
            "--repo-dir",
            str(repo),
            "--trusted-commit",
            trusted,
            "--candidate-commit",
            candidate,
            "--repository",
            TEST_REPOSITORY,
            "--remote-ref",
            f"codex-dispatch/{candidate}",
            "--release-tag",
            "",
            "--dispatch-state",
            str(state_path),
        )
        previous_digest = os.environ.get("HAPTICS_TRUSTED_GATE_SHA256")
        try:
            os.environ["HAPTICS_TRUSTED_GATE_SHA256"] = hashlib.sha256(
                GATE.read_bytes()
            ).hexdigest()
            expect_main_rejected_without_remote_runner(
                gate_module,
                arguments,
                "candidate commit root tree bytes differ from its object id",
                operator_home=operator_home,
            )
        finally:
            if previous_digest is None:
                os.environ.pop("HAPTICS_TRUSTED_GATE_SHA256", None)
            else:
                os.environ["HAPTICS_TRUSTED_GATE_SHA256"] = previous_digest
    finally:
        gate_module.run_bounded_process = original_runner
        loose_tree.write_bytes(compressed_tree)


def run_dispatch_main(
    gate_module,
    repo: pathlib.Path,
    trusted: str,
    candidate: str,
    state_path: pathlib.Path,
    fake_gh,
    operator_home: pathlib.Path,
    release_tag: str = "",
) -> tuple[str, tuple[str, ...]]:
    arguments = (
        "--dispatch",
        "--repo-dir",
        str(repo),
        "--trusted-commit",
        trusted,
        "--candidate-commit",
        candidate,
        "--repository",
        TEST_REPOSITORY,
        "--remote-ref",
        TEST_REF,
        "--release-tag",
        release_tag,
        "--dispatch-state",
        str(state_path),
    )
    previous_argv = sys.argv
    previous_allow = os.environ.get("GH_ALLOW_DISPATCH")
    previous_gate_digest = os.environ.get("HAPTICS_TRUSTED_GATE_SHA256")
    previous_home = os.environ.get("HOME")
    previous_runner_factory = gate_module.real_gh_runner
    output = io.StringIO()
    try:
        sys.argv = [str(GATE), *arguments]
        os.environ["GH_ALLOW_DISPATCH"] = "1"
        os.environ["HOME"] = str(operator_home)
        os.environ["HAPTICS_TRUSTED_GATE_SHA256"] = hashlib.sha256(
            GATE.read_bytes()
        ).hexdigest()
        gate_module.real_gh_runner = lambda home: fake_gh
        with fixture_account_home(gate_module, operator_home):
            with contextlib.redirect_stdout(output):
                gate_module.main()
    finally:
        sys.argv = previous_argv
        gate_module.real_gh_runner = previous_runner_factory
        if previous_allow is None:
            os.environ.pop("GH_ALLOW_DISPATCH", None)
        else:
            os.environ["GH_ALLOW_DISPATCH"] = previous_allow
        if previous_gate_digest is None:
            os.environ.pop("HAPTICS_TRUSTED_GATE_SHA256", None)
        else:
            os.environ["HAPTICS_TRUSTED_GATE_SHA256"] = previous_gate_digest
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home
    return output.getvalue(), arguments


def expect_main_rejected_without_remote_runner(
    gate_module,
    arguments: tuple[str, ...],
    expected_error: str,
    *,
    operator_home: pathlib.Path | None = None,
    account_home: pathlib.Path | None = None,
) -> None:
    previous_argv = sys.argv
    previous_allow = os.environ.get("GH_ALLOW_DISPATCH")
    previous_home = os.environ.get("HOME")
    previous_runner_factory = gate_module.real_gh_runner
    try:
        sys.argv = [str(GATE), *arguments]
        os.environ["GH_ALLOW_DISPATCH"] = "1"
        if operator_home is not None:
            os.environ["HOME"] = str(operator_home)
        gate_module.real_gh_runner = lambda home: (_ for _ in ()).throw(
            AssertionError("rejected main route created a remote runner")
        )
        manager = (
            fixture_account_home(
                gate_module,
                account_home if account_home is not None else operator_home,
            )
            if operator_home is not None or account_home is not None
            else contextlib.nullcontext()
        )
        try:
            with manager:
                gate_module.main()
        except SystemExit as exc:
            if str(exc) != f"haptics workflow gate failed: {expected_error}":
                raise SystemExit(
                    f"production main rejected hostile argv at the wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("production main accepted hostile dispatch argv")
    finally:
        sys.argv = previous_argv
        gate_module.real_gh_runner = previous_runner_factory
        if previous_allow is None:
            os.environ.pop("GH_ALLOW_DISPATCH", None)
        else:
            os.environ["GH_ALLOW_DISPATCH"] = previous_allow
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


@fixture_owner_scoped
def test_main_cleanup_note_diagnostics(
    gate_module,
    repo: pathlib.Path,
    trusted: str,
    candidate: str,
) -> None:
    original_argv = sys.argv
    original_verify = gate_module.verify_candidate
    injected = gate_module.WorkflowGateError("injected production-main failure")
    injected.add_note("process-group TERM cleanup failed")
    injected.add_note("process-group TERM cleanup failed")
    injected.add_note("process leader reap cleanup failed")

    def failing_verify(*args, **kwargs):
        del args, kwargs
        raise injected

    try:
        sys.argv = [
            str(GATE),
            "--verify-only",
            "--repo-dir",
            str(repo),
            "--trusted-commit",
            trusted,
            "--candidate-commit",
            candidate,
        ]
        gate_module.verify_candidate = failing_verify
        try:
            gate_module.main()
        except SystemExit as exc:
            expected = (
                "haptics workflow gate failed: injected production-main failure\n"
                "haptics workflow gate cleanup: process-group TERM cleanup failed\n"
                "haptics workflow gate cleanup: process leader reap cleanup failed"
            )
            if str(exc) != expected:
                raise SystemExit(
                    f"production main lost fixed cleanup evidence: {exc}"
                ) from exc
        else:
            raise SystemExit("production main accepted injected cleanup evidence")
    finally:
        gate_module.verify_candidate = original_verify
        sys.argv = original_argv


@fixture_owner_scoped
def test_real_validators_through_dispatch_main(
    gate_module,
    root: pathlib.Path,
) -> None:
    global TEST_REF
    repo = root / "real-validator-repo"
    operator_home = root / "real-validator-operator-home"
    repo.mkdir()
    operator_home.mkdir(mode=0o700)
    (repo / "home").mkdir()
    require_success(run("/usr/bin/git", "init", "-q", cwd=repo), "real git init")
    workflow_target = repo / ".github/workflows/build.yml"
    workflow_target.parent.mkdir(parents=True)
    workflow_target.write_bytes(REAL_WORKFLOW.read_bytes())
    for relative in VALIDATORS:
        source = SCRIPT_DIR / pathlib.Path(relative).name
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o755 if relative == VALIDATORS[0] else 0o644)
    trusted = commit(repo, "real trusted validators")
    candidate = empty_commit(repo, "real validator candidate")
    previous_ref = TEST_REF
    dispatch_ref = f"codex-dispatch/{candidate}"
    TEST_REF = dispatch_ref
    state_directory = (
        operator_home / gate_module.DISPATCH_STATE_RELATIVE_DIRECTORY
    )
    state_directory.mkdir(parents=True, mode=0o700)
    fake_gh = FakeGhRunner(candidate)
    try:
        output, _ = run_dispatch_main(
            gate_module,
            repo,
            trusted,
            candidate,
            state_directory / f"{candidate}.diagnostic.tsv",
            fake_gh,
            operator_home,
        )
    finally:
        TEST_REF = previous_ref
    state_path = state_directory / f"{candidate}.diagnostic.tsv"
    expected_output = "".join(
        (
            "schema\ttb321fu.haptics-workflow-gate/v1\n",
            f"trusted-commit\t{trusted}\n",
            f"candidate-commit\t{candidate}\n",
            f"gate-sha256\t{hashlib.sha256(GATE.read_bytes()).hexdigest()}\n",
            f"workflow-sha256\t{hashlib.sha256(workflow_target.read_bytes()).hexdigest()}\n",
            *(
                f"validator-sha256\t{relative}\t"
                f"{hashlib.sha256((repo / relative).read_bytes()).hexdigest()}\n"
                for relative in VALIDATORS
            ),
            f"validator-mode\t{gate_module.VALIDATOR_MODE}\n",
            f"repository\t{TEST_REPOSITORY}\n",
            f"remote-ref\t{dispatch_ref}\n",
            "release-tag\t-\n",
            "run-id\t42\n",
            f"run-display-title\thaptics-dispatch-{fake_gh.dispatch_id}\n",
            f"run-head-branch\t{dispatch_ref}\n",
            f"run-head-sha\t{candidate}\n",
            f"run-url\thttps://github.com/{TEST_REPOSITORY}/actions/runs/42\n",
            f"dispatch-id\t{fake_gh.dispatch_id}\n",
            "input-sha256\t"
            f"{gate_module.dispatch_input_digest('', fake_gh.dispatch_id)}\n",
            "dispatch-state-sha256\t"
            f"{hashlib.sha256(state_path.read_bytes()).hexdigest()}\n",
            "HAPTICS_WORKFLOW_DISPATCH=PASS\n",
        )
    )
    if output != expected_output or fake_gh.dispatch_count != 1:
        raise SystemExit("real validators did not pass production dispatch main")


@fixture_owner_scoped
def test_candidate_relation(
    gate_module,
    repo: pathlib.Path,
    trusted: str,
    candidate: str,
    changed_tree: str,
) -> None:
    trusted_tree = tree_id(repo, trusted)
    direct_mutation = commit_tree(
        repo,
        changed_tree,
        (trusted,),
        "direct candidate tree mutation",
    )
    merge_candidate = commit_tree(
        repo,
        trusted_tree,
        (trusted, candidate),
        "merge candidate",
    )
    intermediate = commit_tree(
        repo,
        trusted_tree,
        (trusted,),
        "intermediate empty candidate",
    )
    grandchild = commit_tree(
        repo,
        trusted_tree,
        (intermediate,),
        "indirect empty candidate",
    )
    for label, hostile, expected in (
        (
            "tree mutation",
            direct_mutation,
            "candidate tree differs from the trusted commit",
        ),
        (
            "merge",
            merge_candidate,
            "candidate is not a canonical single-parent commit",
        ),
        (
            "intermediate parent",
            grandchild,
            "candidate is not the direct child of the trusted commit",
        ),
    ):
        try:
            gate_module.verify_candidate(
                repo,
                trusted,
                hostile,
                deadline=time.monotonic() + 10.0,
                require_unchanged_candidate=True,
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != expected:
                raise SystemExit(
                    f"candidate-relation {label} failed at the wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit(f"candidate-relation gate accepted {label}")
    try:
        gate_module.verify_candidate(
            repo,
            trusted,
            candidate,
            require_unchanged_candidate=1,
        )
    except gate_module.WorkflowGateError as exc:
        if str(exc) != "candidate relation policy is not canonical":
            raise SystemExit(
                f"candidate-relation type guard used the wrong diagnostic: {exc}"
            ) from exc
    else:
        raise SystemExit("candidate-relation gate accepted a non-boolean policy")


@fixture_owner_scoped
def test_dispatch_state_crash_publication(
    gate_module,
    state_directory: pathlib.Path,
    candidate: str,
    evidence,
) -> None:
    original_open = gate_module.os.open
    for role in ("parent", "existing", "temporary"):
        handoff_path = state_directory / f"open-handoff-{role}.tsv"
        if role == "existing":
            existing_id, existing_created = gate_module.reserve_dispatch_state(
                handoff_path,
                TEST_REPOSITORY,
                TEST_REF,
                candidate,
                "",
                evidence,
                lambda: TEST_DISPATCH_ID,
            )
            if existing_id != TEST_DISPATCH_ID or not existing_created:
                raise SystemExit("dispatch existing-open handoff setup drifted")
        cancellation = KeyboardInterrupt(
            f"injected dispatch {role} open handoff cancellation"
        )
        descriptors: list[int] = []

        def cancel_state_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            raw_path = os.fspath(path)
            selected = False
            if role == "parent":
                selected = pathlib.Path(raw_path) == state_directory
            elif role == "existing":
                selected = (
                    raw_path == handoff_path.name
                    and kwargs.get("dir_fd") is not None
                    and not flags & os.O_WRONLY
                )
            else:
                selected = (
                    raw_path.startswith(f".{handoff_path.name}.")
                    and raw_path.endswith(".tmp")
                    and bool(flags & os.O_EXCL)
                )
            if selected and not descriptors:
                descriptors.append(descriptor)
                raise cancellation
            return descriptor

        gate_module.os.open = cancel_state_open
        caught: BaseException | None = None
        try:
            try:
                gate_module.reserve_dispatch_state(
                    handoff_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda: TEST_DISPATCH_ID,
                )
            except BaseException as exc:
                caught = exc
        finally:
            gate_module.os.open = original_open
        leaked = False
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                leaked = True
                os.close(descriptor)
        residues = tuple(state_directory.glob(f".{handoff_path.name}.*.tmp"))
        expected_state = role == "existing"
        if (
            caught is not cancellation
            or len(descriptors) != 1
            or leaked
            or handoff_path.exists() != expected_state
            or residues
        ):
            for residue in residues:
                residue.unlink()
            if handoff_path.exists():
                handoff_path.unlink()
            raise SystemExit(
                f"dispatch {role} open handoff custody drifted"
            ) from caught
        if handoff_path.exists():
            handoff_path.unlink()

    original_fstat = gate_module.os.fstat
    replacement_raw = b"preserved dispatch-state replacement\n"
    for failure_kind in ("cancellation", "ordinary-error"):
        recovery_path = state_directory / f"existing-recovery-{failure_kind}.tsv"
        setup_id, setup_created = gate_module.reserve_dispatch_state(
            recovery_path,
            TEST_REPOSITORY,
            TEST_REF,
            candidate,
            "",
            evidence,
            lambda: TEST_DISPATCH_ID,
        )
        if setup_id != TEST_DISPATCH_ID or not setup_created:
            raise SystemExit("dispatch recovery-fstat setup drifted")
        recovery_caller = KeyboardInterrupt(
            f"injected dispatch existing-open {failure_kind} caller"
        )
        recovery_probe = (
            KeyboardInterrupt("injected dispatch recovery fstat cancellation")
            if failure_kind == "cancellation"
            else OSError(errno.EIO, "injected dispatch recovery fstat error")
        )
        recovery_descriptors: list[int] = []
        recovery_fstat_calls = 0

        def cancel_recovery_existing_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            if (
                os.fspath(path) == recovery_path.name
                and kwargs.get("dir_fd") is not None
                and not flags & os.O_WRONLY
                and not recovery_descriptors
            ):
                recovery_descriptors.append(descriptor)
                raise recovery_caller
            return descriptor

        def fail_recovery_identity_fstat(descriptor: int):
            nonlocal recovery_fstat_calls
            if descriptor in recovery_descriptors:
                recovery_fstat_calls += 1
                if recovery_fstat_calls == 3:
                    recovery_path.unlink()
                    recovery_path.write_bytes(replacement_raw)
                    recovery_path.chmod(0o600)
                    raise recovery_probe
            return original_fstat(descriptor)

        gate_module.os.open = cancel_recovery_existing_open
        gate_module.os.fstat = fail_recovery_identity_fstat
        recovery_caught: BaseException | None = None
        try:
            try:
                gate_module.reserve_dispatch_state(
                    recovery_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda: (_ for _ in ()).throw(
                        AssertionError("dispatch recovery regenerated its id")
                    ),
                )
            except BaseException as exc:
                recovery_caught = exc
        finally:
            gate_module.os.fstat = original_fstat
            gate_module.os.open = original_open
        recovery_live = False
        for descriptor in recovery_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                recovery_live = True
                os.close(descriptor)
        if (
            recovery_caught is not recovery_caller
            or len(recovery_descriptors) != 1
            or recovery_fstat_calls != 3
            or recovery_live
            or not recovery_path.is_file()
            or recovery_path.read_bytes() != replacement_raw
            or "recovery identity also became unknown"
            not in " ".join(getattr(recovery_caught, "__notes__", ()))
        ):
            if recovery_path.exists():
                recovery_path.unlink()
            raise SystemExit(
                f"dispatch {failure_kind} recovery-fstat custody drifted"
            ) from recovery_caught
        recovery_path.unlink()

    original_scandir = gate_module.os.scandir
    for failure_kind in ("cancellation", "ordinary-error"):
        partial_path = state_directory / f"existing-partial-{failure_kind}.tsv"
        setup_id, setup_created = gate_module.reserve_dispatch_state(
            partial_path,
            TEST_REPOSITORY,
            TEST_REF,
            candidate,
            "",
            evidence,
            lambda: TEST_DISPATCH_ID,
        )
        if setup_id != TEST_DISPATCH_ID or not setup_created:
            raise SystemExit("dispatch partial-scan setup drifted")
        partial_caller = KeyboardInterrupt(
            f"injected dispatch partial-scan {failure_kind} caller"
        )
        partial_failure = (
            KeyboardInterrupt("injected dispatch partial-scan cancellation")
            if failure_kind == "cancellation"
            else OSError(errno.EIO, "injected dispatch partial-scan error")
        )
        partial_descriptors: list[int] = []
        partial_injected = False

        class PartialGateDescriptorIterator:
            def __init__(self, wrapped) -> None:
                self.wrapped = wrapped
                self.fail_next = False

            def __iter__(self):
                return self

            def __next__(self):
                nonlocal partial_injected
                if self.fail_next:
                    partial_injected = True
                    partial_path.unlink()
                    partial_path.write_bytes(replacement_raw)
                    partial_path.chmod(0o600)
                    raise partial_failure
                entry = next(self.wrapped)
                if partial_descriptors and entry.name == str(partial_descriptors[0]):
                    self.fail_next = True
                return entry

            def close(self) -> None:
                self.wrapped.close()

        def cancel_partial_existing_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            if (
                os.fspath(path) == partial_path.name
                and kwargs.get("dir_fd") is not None
                and not flags & os.O_WRONLY
                and not partial_descriptors
            ):
                partial_descriptors.append(descriptor)
                raise partial_caller
            return descriptor

        def fail_partial_descriptor_scan(path):
            entries = original_scandir(path)
            if os.fspath(path) == "/proc/self/fd" and partial_descriptors:
                return PartialGateDescriptorIterator(entries)
            return entries

        gate_module.os.open = cancel_partial_existing_open
        gate_module.os.scandir = fail_partial_descriptor_scan
        partial_caught: BaseException | None = None
        try:
            try:
                gate_module.reserve_dispatch_state(
                    partial_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda: (_ for _ in ()).throw(
                        AssertionError("dispatch partial recovery regenerated its id")
                    ),
                )
            except BaseException as exc:
                partial_caught = exc
        finally:
            gate_module.os.scandir = original_scandir
            gate_module.os.open = original_open
        partial_live = False
        for descriptor in partial_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                partial_live = True
                os.close(descriptor)
        if (
            partial_caught is not partial_caller
            or len(partial_descriptors) != 1
            or not partial_injected
            or partial_live
            or not partial_path.is_file()
            or partial_path.read_bytes() != replacement_raw
            or "recovery scan also failed"
            not in " ".join(getattr(partial_caught, "__notes__", ()))
        ):
            if partial_path.exists():
                partial_path.unlink()
            raise SystemExit(
                f"dispatch {failure_kind} partial-scan recovery drifted"
            ) from partial_caught
        partial_path.unlink()

    state_path = state_directory / "crash-publication.tsv"
    def partial_write_child() -> int:
        gate_module.os.write = lambda *args, **kwargs: os._exit(73)
        gate_module.reserve_dispatch_state(
            state_path,
            TEST_REPOSITORY,
            TEST_REF,
            candidate,
            "",
            evidence,
            lambda: TEST_DISPATCH_ID,
        )
        return 74

    child_owner = FixtureChildOwner()
    try:
        spawn_fixture_child(
            child_owner,
            partial_write_child,
            "dispatch-state partial-write fork",
        )
        child = child_owner.pid
    except BaseException as exc:
        selected = settle_fixture_child_owner(
            child_owner,
            exc,
            "dispatch-state partial-write fork",
        )
        assert selected is not None
        raise selected
    status = wait_fixture_child(child, "dispatch-state partial-write child")
    child_owner.pid = -1
    waited = child
    if waited != child or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 73:
        raise SystemExit("dispatch-state crash fixture did not stop during its first write")
    if state_path.exists():
        state_path.unlink()
        raise SystemExit("dispatch state exposed a partial target before atomic publication")
    for residue in state_directory.glob(f".{state_path.name}.*.tmp"):
        residue.unlink()

    linked_crash_path = state_directory / "linked-crash.tsv"
    def linked_write_child() -> int:
        original_fsync = gate_module.os.fsync
        fsync_calls = 0

        def crash_after_link(descriptor: int) -> None:
            nonlocal fsync_calls
            original_fsync(descriptor)
            fsync_calls += 1
            if fsync_calls == 2:
                os._exit(75)

        gate_module.os.fsync = crash_after_link
        gate_module.reserve_dispatch_state(
            linked_crash_path,
            TEST_REPOSITORY,
            TEST_REF,
            candidate,
            "",
            evidence,
            lambda: TEST_DISPATCH_ID,
        )
        return 76

    linked_child_owner = FixtureChildOwner()
    try:
        spawn_fixture_child(
            linked_child_owner,
            linked_write_child,
            "dispatch-state linked fork",
        )
        linked_child = linked_child_owner.pid
    except BaseException as exc:
        selected = settle_fixture_child_owner(
            linked_child_owner,
            exc,
            "dispatch-state linked fork",
        )
        assert selected is not None
        raise selected
    status = wait_fixture_child(linked_child, "dispatch-state linked child")
    linked_child_owner.pid = -1
    waited = linked_child
    if (
        waited != linked_child
        or not os.WIFEXITED(status)
        or os.WEXITSTATUS(status) != 75
    ):
        raise SystemExit("dispatch-state linked-crash fixture missed publication")
    recovered_id, recovered_created = gate_module.reserve_dispatch_state(
        linked_crash_path,
        TEST_REPOSITORY,
        TEST_REF,
        candidate,
        "",
        evidence,
        lambda: (_ for _ in ()).throw(
            AssertionError("linked state recovery regenerated its dispatch id")
        ),
    )
    if recovered_id != TEST_DISPATCH_ID or recovered_created:
        raise SystemExit("dispatch state did not recover its published hardlink")
    if linked_crash_path.stat().st_nlink != 1 or tuple(
        state_directory.glob(f".{linked_crash_path.name}.*.tmp")
    ):
        raise SystemExit("dispatch state recovery retained a publication hardlink")

    for failure_kind in ("oserror", "cancellation"):
        first_fstat_path = state_directory / f"first-fstat-{failure_kind}.tsv"
        original_fstat = gate_module.os.fstat
        injected = False

        def fail_first_temporary_fstat(descriptor: int):
            nonlocal injected
            metadata = original_fstat(descriptor)
            if not injected and stat.S_ISREG(metadata.st_mode):
                injected = True
                if failure_kind == "cancellation":
                    raise KeyboardInterrupt("injected first-fstat cancellation")
                raise OSError("injected first-fstat failure")
            return metadata

        gate_module.os.fstat = fail_first_temporary_fstat
        try:
            try:
                gate_module.reserve_dispatch_state(
                    first_fstat_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda: TEST_DISPATCH_ID,
                )
            except KeyboardInterrupt as exc:
                if failure_kind != "cancellation" or str(exc) != (
                    "injected first-fstat cancellation"
                ):
                    raise
            except gate_module.WorkflowGateError as exc:
                if failure_kind != "oserror" or str(exc) != (
                    "cannot reserve workflow dispatch state: "
                    "injected first-fstat failure"
                ):
                    raise
            else:
                raise SystemExit(
                    f"dispatch state swallowed first-fstat {failure_kind}"
                )
        finally:
            gate_module.os.fstat = original_fstat
        residues = tuple(
            state_directory.glob(f".{first_fstat_path.name}.*.tmp")
        )
        if first_fstat_path.exists() or residues:
            for residue in residues:
                residue.unlink()
            if first_fstat_path.exists():
                first_fstat_path.unlink()
            raise SystemExit(
                f"dispatch state retained evidence after first-fstat {failure_kind}"
            )

    for boundary in ("temporary-close", "post-link", "parent-close"):
        cancel_path = state_directory / f"cancel-{boundary}.tsv"
        original_close = gate_module.os.close
        original_link = gate_module.os.link
        close_calls = 0

        def cancelling_close(descriptor: int) -> None:
            nonlocal close_calls
            close_calls += 1
            is_directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
            original_close(descriptor)
            if (
                (boundary == "temporary-close" and close_calls == 1)
                or (boundary == "parent-close" and is_directory)
            ):
                raise KeyboardInterrupt(f"injected {boundary} cancellation")

        def cancelling_link(*args, **kwargs):
            result = original_link(*args, **kwargs)
            raise KeyboardInterrupt("injected post-link cancellation")

        try:
            if boundary in {"temporary-close", "parent-close"}:
                gate_module.os.close = cancelling_close
            else:
                gate_module.os.link = cancelling_link
            try:
                gate_module.reserve_dispatch_state(
                    cancel_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda: TEST_DISPATCH_ID,
                )
            except KeyboardInterrupt as exc:
                if str(exc) != f"injected {boundary} cancellation":
                    raise
            else:
                raise SystemExit(
                    f"dispatch state swallowed {boundary} cancellation"
                )
        finally:
            gate_module.os.close = original_close
            gate_module.os.link = original_link
        residues = tuple(
            state_directory.glob(f".{cancel_path.name}.*.tmp")
        )
        if boundary == "parent-close":
            if not cancel_path.is_file() or residues:
                raise SystemExit(
                    "dispatch state lost its completed ledger during parent-close "
                    "cancellation"
                )
            cancel_path.unlink()
        elif cancel_path.exists() or residues:
            for residue in residues:
                residue.unlink()
            if cancel_path.exists():
                cancel_path.unlink()
            raise SystemExit(
                f"dispatch state retained evidence after {boundary} cancellation"
            )

    for role in ("temporary", "parent", "existing"):
        probe_path = state_directory / f"probe-close-{role}.tsv"
        if role == "existing":
            created_id, created = gate_module.reserve_dispatch_state(
                probe_path,
                TEST_REPOSITORY,
                TEST_REF,
                candidate,
                "",
                evidence,
                lambda: TEST_DISPATCH_ID,
            )
            if created_id != TEST_DISPATCH_ID or not created:
                raise SystemExit("dispatch state probe fixture setup drifted")
        original_close = gate_module.os.close
        original_fstat = gate_module.os.fstat
        parent_identity = (
            state_directory.stat().st_dev,
            state_directory.stat().st_ino,
        )
        existing_identity = (
            None
            if role != "existing"
            else (probe_path.stat().st_dev, probe_path.stat().st_ino)
        )
        target_descriptor = -1
        close_calls = 0
        probe_calls = 0
        close_failure = OSError(
            f"injected dispatch state {role} nonapplied close failure"
        )
        probe_cancellation = KeyboardInterrupt(
            f"injected dispatch state {role} custody-probe cancellation"
        )

        def is_probe_target(descriptor: int) -> bool:
            try:
                metadata = original_fstat(descriptor)
            except OSError:
                return False
            identity = (metadata.st_dev, metadata.st_ino)
            if role == "parent":
                return stat.S_ISDIR(metadata.st_mode) and identity == parent_identity
            if role == "existing":
                return stat.S_ISREG(metadata.st_mode) and identity == existing_identity
            return (
                stat.S_ISREG(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_nlink == 1
                and metadata.st_size > 0
            )

        def fail_state_close_once(descriptor: int) -> None:
            nonlocal target_descriptor, close_calls
            if is_probe_target(descriptor):
                target_descriptor = descriptor
                close_calls += 1
                if close_calls == 1:
                    raise close_failure
            original_close(descriptor)

        def cancel_state_probe_once(descriptor: int):
            nonlocal probe_calls
            if descriptor == target_descriptor and close_calls == 1:
                probe_calls += 1
                if probe_calls == 1:
                    raise probe_cancellation
            return original_fstat(descriptor)

        gate_module.os.close = fail_state_close_once
        gate_module.os.fstat = cancel_state_probe_once
        probe_caught: BaseException | None = None
        try:
            try:
                gate_module.reserve_dispatch_state(
                    probe_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda: (
                        (_ for _ in ()).throw(
                            AssertionError(
                                "existing probe state regenerated its dispatch id"
                            )
                        )
                        if role == "existing"
                        else TEST_DISPATCH_ID
                    ),
                )
            except BaseException as exc:
                probe_caught = exc
        finally:
            gate_module.os.fstat = original_fstat
            gate_module.os.close = original_close
        try:
            original_fstat(target_descriptor)
        except OSError as exc:
            target_closed = exc.errno == errno.EBADF
        else:
            target_closed = False
            if target_descriptor >= 0:
                original_close(target_descriptor)
        expected_state = role in {"parent", "existing"}
        residues = tuple(state_directory.glob(f".{probe_path.name}.*.tmp"))
        if (
            probe_caught is not probe_cancellation
            or not isinstance(probe_cancellation.__cause__, gate_module.WorkflowGateError)
            or probe_cancellation.__cause__.__cause__ is not close_failure
            or target_descriptor < 0
            or close_calls != 2
            or probe_calls != 1
            or not target_closed
            or probe_path.exists() != expected_state
            or residues
        ):
            for residue in residues:
                residue.unlink()
            if probe_path.exists():
                probe_path.unlink()
            raise SystemExit(
                f"dispatch state {role} close-probe custody drifted"
            ) from probe_caught
        if probe_path.exists():
            probe_path.unlink()

    race_path = state_directory / "competing.tsv"
    race_ids = ("0" * 32, "1" * 32)
    race_children: list[int] = []
    race_owners: list[FixtureChildOwner] = []
    race_outputs: list[pathlib.Path] = []
    try:
        for index, dispatch_id in enumerate(race_ids):
            output = state_directory / f"competing-{index}.out"
            race_outputs.append(output)
            def race_child_main(
                dispatch_id: str = dispatch_id,
                output: pathlib.Path = output,
            ) -> int:
                result_id, created = gate_module.reserve_dispatch_state(
                    race_path,
                    TEST_REPOSITORY,
                    TEST_REF,
                    candidate,
                    "",
                    evidence,
                    lambda dispatch_id=dispatch_id: dispatch_id,
                )
                output.write_text(
                    f"{result_id}\t{int(created)}\n",
                    encoding="ascii",
                )
                return 0

            owner = FixtureChildOwner()
            race_owners.append(owner)
            spawn_fixture_child(
                owner,
                race_child_main,
                f"competing dispatch-state fork {index}",
            )
            race_children.append(owner.pid)
    except BaseException as exc:
        selected: BaseException | None = exc
        for index, owner in reversed(tuple(enumerate(race_owners))):
            selected = settle_fixture_child_owner(
                owner,
                selected,
                f"competing dispatch-state fork {index}",
            )
        assert selected is not None
        raise selected
    race_statuses = wait_fixture_children(
        race_children,
        "competing dispatch-state child",
    )
    for owner in race_owners:
        owner.pid = -1
    for status in race_statuses:
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise SystemExit("competing dispatch-state publisher failed")
    race_results = tuple(
        output.read_text(encoding="ascii").strip().split("\t")
        for output in race_outputs
    )
    if (
        len({result[0] for result in race_results}) != 1
        or sum(result[1] == "1" for result in race_results) != 1
        or race_path.stat().st_nlink != 1
    ):
        raise SystemExit(f"competing dispatch-state results diverged: {race_results!r}")

    canonical_raw = gate_module.serialize_dispatch_state(
        TEST_REPOSITORY,
        TEST_REF,
        candidate,
        "",
        TEST_DISPATCH_ID,
        evidence,
    )

    def expect_existing_rejected(path: pathlib.Path, label: str) -> None:
        try:
            gate_module.reserve_dispatch_state(
                path,
                TEST_REPOSITORY,
                TEST_REF,
                candidate,
                "",
                evidence,
                lambda: (_ for _ in ()).throw(
                    AssertionError(f"{label} regenerated a dispatch id")
                ),
            )
        except gate_module.WorkflowGateError:
            return
        raise SystemExit(f"dispatch state accepted hostile existing state: {label}")

    partial_path = state_directory / "partial.tsv"
    partial_path.write_bytes(b"")
    partial_path.chmod(0o600)
    expect_existing_rejected(partial_path, "partial target")

    mode_path = state_directory / "mode.tsv"
    mode_path.write_bytes(canonical_raw)
    mode_path.chmod(0o644)
    expect_existing_rejected(mode_path, "mode drift")

    oversized_path = state_directory / "oversized.tsv"
    oversized_path.write_bytes(b"x" * (gate_module.MAX_DISPATCH_STATE_BYTES + 1))
    oversized_path.chmod(0o600)
    expect_existing_rejected(oversized_path, "oversized target")

    symlink_source = state_directory / "symlink-source.tsv"
    symlink_source.write_bytes(canonical_raw)
    symlink_source.chmod(0o600)
    symlink_path = state_directory / "symlink.tsv"
    symlink_path.symlink_to(symlink_source.name)
    expect_existing_rejected(symlink_path, "symlink target")

    hardlink_path = state_directory / "hardlink.tsv"
    hardlink_alias = state_directory / "hardlink-alias.tsv"
    hardlink_path.write_bytes(canonical_raw)
    hardlink_path.chmod(0o600)
    os.link(hardlink_path, hardlink_alias)
    expect_existing_rejected(hardlink_path, "unexpected hardlink")
    if not hardlink_alias.exists() or hardlink_alias.stat().st_nlink != 2:
        raise SystemExit("dispatch state removed an unrelated hardlink")

    short_read_path = state_directory / "short-read.tsv"
    short_read_path.write_bytes(canonical_raw)
    short_read_path.chmod(0o600)
    original_read = gate_module.os.read
    gate_module.os.read = lambda descriptor, amount: original_read(
        descriptor, min(amount, 1)
    )
    try:
        short_id, short_created = gate_module.reserve_dispatch_state(
            short_read_path,
            TEST_REPOSITORY,
            TEST_REF,
            candidate,
            "",
            evidence,
            lambda: (_ for _ in ()).throw(
                AssertionError("short-read replay regenerated its dispatch id")
            ),
        )
    finally:
        gate_module.os.read = original_read
    if short_id != TEST_DISPATCH_ID or short_created:
        raise SystemExit("dispatch state changed under one-byte reads")
    state_lines = short_read_path.read_text(encoding="ascii").splitlines()
    expected_input_digest = gate_module.dispatch_input_digest(
        "", TEST_DISPATCH_ID
    )
    if (
        state_lines[0] != "schema\ttb321fu.haptics-workflow-dispatch/v2"
        or f"trusted-commit\t{evidence.trusted_commit}" not in state_lines
        or f"gate-sha256\t{evidence.gate_sha256}" not in state_lines
        or f"workflow-sha256\t{evidence.workflow_sha256}" not in state_lines
        or f"input-sha256\t{expected_input_digest}" not in state_lines
    ):
        raise SystemExit("dispatch state omitted exact verification/input evidence")

    flipped_gate = ("0" if evidence.gate_sha256[0] != "0" else "1") + evidence.gate_sha256[1:]
    flipped_workflow = (
        ("0" if evidence.workflow_sha256[0] != "0" else "1")
        + evidence.workflow_sha256[1:]
    )
    first_validator = evidence.validators[0]
    flipped_validator_digest = (
        ("0" if first_validator[2][0] != "0" else "1")
        + first_validator[2][1:]
    )
    drifted_evidence = (
        gate_module.VerificationEvidence(
            "f" * 40,
            evidence.gate_sha256,
            evidence.workflow_sha256,
            evidence.validators,
        ),
        gate_module.VerificationEvidence(
            evidence.trusted_commit,
            flipped_gate,
            evidence.workflow_sha256,
            evidence.validators,
        ),
        gate_module.VerificationEvidence(
            evidence.trusted_commit,
            evidence.gate_sha256,
            flipped_workflow,
            evidence.validators,
        ),
        gate_module.VerificationEvidence(
            evidence.trusted_commit,
            evidence.gate_sha256,
            evidence.workflow_sha256,
            (
                (first_validator[0], first_validator[1], flipped_validator_digest),
                *evidence.validators[1:],
            ),
        ),
    )
    for index, drifted in enumerate(drifted_evidence):
        try:
            gate_module.reserve_dispatch_state(
                short_read_path,
                TEST_REPOSITORY,
                TEST_REF,
                candidate,
                "",
                drifted,
                lambda: (_ for _ in ()).throw(
                    AssertionError("evidence-drift replay regenerated its id")
                ),
            )
        except gate_module.WorkflowGateError:
            continue
        raise SystemExit(f"dispatch state accepted verification-evidence drift {index}")


def remote_ref_arguments() -> list[str]:
    return [
        "/usr/bin/gh",
        "api",
        "--method",
        "GET",
        (
            f"repos/{TEST_REPOSITORY}/git/ref/heads/"
            f"{urllib.parse.quote(TEST_REF, safe='')}"
        ),
        "--jq",
        "{object:{sha:.object.sha}}",
    ]


def authenticated_login_arguments() -> list[str]:
    return [
        "/usr/bin/gh",
        "api",
        "--method",
        "GET",
        "user",
        "--jq",
        "{login:.login}",
    ]


def workflow_run_ownership_arguments(run_id: int) -> list[str]:
    return [
        "/usr/bin/gh",
        "api",
        "--method",
        "GET",
        f"repos/{TEST_REPOSITORY}/actions/runs/{run_id}",
        "--jq",
        (
            "{runId:.id,headBranch:.head_branch,headSha:.head_sha,"
            "event:.event,path:.path,displayTitle:.display_title,"
            "workflowName:.name,workflowId:.workflow_id,"
            "actorLogin:.actor.login,"
            "triggeringActorLogin:.triggering_actor.login,"
            "repositoryFullName:.repository.full_name,"
            "headRepositoryFullName:.head_repository.full_name}"
        ),
    ]


def branch_protection_arguments() -> list[str]:
    return [
        "/usr/bin/gh",
        "api",
        "--method",
        "GET",
        (
            f"repos/{TEST_REPOSITORY}/branches/"
            f"{urllib.parse.quote(TEST_REF, safe='')}/protection"
        ),
        "--jq",
        (
            "{lockBranch:.lock_branch.enabled,"
            "allowForcePushes:.allow_force_pushes.enabled,"
            "allowDeletions:.allow_deletions.enabled,"
            "allowForkSyncing:(.allow_fork_syncing.enabled // false)}"
        ),
    ]


def workflow_inventory_arguments(candidate_commit: str) -> list[str]:
    return [
        "/usr/bin/gh",
        "run",
        "list",
        "--repo",
        TEST_REPOSITORY,
        "--workflow",
        "build.yml",
        "--event",
        "workflow_dispatch",
        "--branch",
        TEST_REF,
        "--commit",
        candidate_commit,
        "--limit",
        "100",
        "--json",
        "databaseId,displayTitle,headBranch,headSha,event,status,url,workflowName",
    ]


def workflow_dispatch_arguments() -> list[str]:
    return [
        "/usr/bin/gh",
        "workflow",
        "run",
        "build.yml",
        "--repo",
        TEST_REPOSITORY,
        "--ref",
        TEST_REF,
        "--json",
    ]


@fixture_owner_scoped
def test_bounded_process_runner(gate_module, private: pathlib.Path) -> None:
    environment = gate_module.clean_environment(private / "repo" / "home")
    if {
        name: environment.get(name)
        for name in (
            "GIT_NO_LAZY_FETCH",
            "GIT_TERMINAL_PROMPT",
            "GCM_INTERACTIVE",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_OPTIONAL_LOCKS",
        )
    } != {
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_OPTIONAL_LOCKS": "0",
    }:
        raise SystemExit("bounded Git environment permits prompting or optional locks")
    sigchld_popen_original = gate_module.subprocess.Popen
    sigchld_popen_calls = 0

    def count_sigchld_popen(*args, **kwargs):
        nonlocal sigchld_popen_calls
        sigchld_popen_calls += 1
        return sigchld_popen_original(*args, **kwargs)

    gate_module.subprocess.Popen = count_sigchld_popen
    try:
        for disposition in (signal.SIG_IGN, lambda _signum, _frame: None):
            previous_sigchld = signal.signal(signal.SIGCHLD, disposition)
            try:
                try:
                    gate_module.run_bounded_process(
                        ["/bin/sh", "-c", "exit 7"],
                        input_bytes=None,
                        environment=environment,
                        deadline=time.monotonic() + 5.0,
                        stdout_limit=64,
                        stderr_limit=64,
                        label="inherited gate SIGCHLD fixture",
                    )
                except gate_module.WorkflowGateError as exc:
                    if str(exc) != (
                        "inherited gate SIGCHLD fixture requires default SIGCHLD policy"
                    ):
                        raise
                else:
                    raise SystemExit("bounded gate accepted inherited SIGCHLD policy")
                if signal.getsignal(signal.SIGCHLD) is not disposition:
                    raise SystemExit("bounded gate changed inherited SIGCHLD policy")
            finally:
                signal.signal(signal.SIGCHLD, previous_sigchld)
    finally:
        gate_module.subprocess.Popen = sigchld_popen_original
    if sigchld_popen_calls:
        raise SystemExit("bounded gate spawned before rejecting SIGCHLD policy")

    exact_exit = gate_module.run_bounded_process(
        ["/bin/sh", "-c", "exit 7"],
        input_bytes=None,
        environment=environment,
        deadline=time.monotonic() + 5.0,
        stdout_limit=64,
        stderr_limit=64,
        label="exact gate exit-status fixture",
    )
    if exact_exit.returncode != 7 or exact_exit.stdout or exact_exit.stderr:
        raise SystemExit("bounded gate lost exact child exit status")

    normal = gate_module.run_bounded_process(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            (
                "import sys; data=sys.stdin.buffer.read(); "
                "sys.stdout.buffer.write(data.upper()); "
                "sys.stderr.buffer.write(b'noted')"
            ),
        ],
        input_bytes=b"bounded input",
        environment=environment,
        deadline=time.monotonic() + 5.0,
        stdout_limit=64,
        stderr_limit=64,
        label="normal bounded fixture",
    )
    if (
        normal.returncode != 0
        or normal.stdout != b"BOUNDED INPUT"
        or normal.stderr != b"noted"
    ):
        raise SystemExit("bounded runner changed exact stdin/stdout/stderr bytes")

    for stream, program in (
        ("stdout", "import os,time; os.write(1,b'x'*65536); time.sleep(60)"),
        ("stderr", "import os,time; os.write(2,b'x'*65536); time.sleep(60)"),
    ):
        started = time.monotonic()
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/python3", "-I", "-B", "-c", program],
                input_bytes=None,
                environment=environment,
                deadline=started + 5.0,
                stdout_limit=1024,
                stderr_limit=1024,
                label=f"{stream} flood fixture",
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != f"{stream} flood fixture {stream} exceeds its size bound":
                raise SystemExit(
                    f"bounded runner rejected {stream} flood at wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit(f"bounded runner accepted a {stream} flood")
        if time.monotonic() - started > 3.0:
            raise SystemExit(f"bounded runner took too long to stop a {stream} flood")

    child_marker = private / "bounded-child.pid"
    child_program = (
        "import os,pathlib,signal,sys,time\n"
        f"{PROCESS_IDENTITY_HELPER}"
        "child=os.fork(); "
        "record_identity(sys.argv[1]) if child==0 else None; "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        "time.sleep(60) if child==0 else None"
    )
    started = time.monotonic()
    try:
        gate_module.run_bounded_process(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                child_program,
                str(child_marker),
            ],
            input_bytes=None,
            environment=environment,
            deadline=started + 0.4,
            stdout_limit=1024,
            stderr_limit=1024,
            label="forked descriptor fixture",
        )
    except gate_module.WorkflowGateError as exc:
        if str(exc) != "forked descriptor fixture exceeded its deadline":
            raise SystemExit(f"bounded runner exposed wrong timeout error: {exc}") from exc
    else:
        raise SystemExit("bounded runner accepted a forked descriptor holder")
    if time.monotonic() - started > 3.0 or not child_marker.is_file():
        raise SystemExit("bounded runner did not bound forked-child cleanup")
    child_pid, child_start_time = read_fixture_process_identity(
        child_marker,
        "bounded runner child",
    )
    child_record = fixture_process_map().get(child_pid)
    if child_record is not None and child_record[1] == child_start_time:
        raise SystemExit("bounded runner left an owned descendant after timeout")


@fixture_owner_scoped
def test_process_group_ownership(gate_module, private: pathlib.Path) -> None:
    environment = gate_module.clean_environment(private / "repo" / "home")
    original_popen = gate_module.subprocess.Popen
    original_killpg = gate_module.os.killpg

    events: list[tuple[str, int]] = []

    def observed_popen(*arguments, **keywords):
        process = original_popen(*arguments, **keywords)
        original_wait = process.wait

        def observed_wait(*wait_arguments, **wait_keywords):
            events.append(("wait", process.pid))
            return original_wait(*wait_arguments, **wait_keywords)

        process.wait = observed_wait
        return process

    def observed_killpg(process_group: int, signal_number: int):
        if any(event == "wait" for event, _ in events):
            raise AssertionError("bounded runner signaled a process group after leader reap")
        events.append(("signal", signal_number))
        return original_killpg(process_group, signal_number)

    try:
        gate_module.subprocess.Popen = observed_popen
        gate_module.os.killpg = observed_killpg
        result = gate_module.run_bounded_process(
            ["/usr/bin/true"],
            input_bytes=None,
            environment=environment,
            deadline=time.monotonic() + 5.0,
            stdout_limit=16,
            stderr_limit=16,
            label="reap order fixture",
        )
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.os.killpg = original_killpg
    if result.returncode != 0 or not events or events[-1][0] != "wait":
        raise SystemExit("bounded runner did not reap exactly after its final group signal")
    if sum(event == "wait" for event, _ in events) != 1:
        raise SystemExit("bounded runner did not reap its process leader exactly once")

    original_waitid = gate_module.os.waitid
    reused_signals: list[int] = []
    try:
        gate_module.os.waitid = lambda *arguments: (_ for _ in ()).throw(
            ChildProcessError("simulated external reap and numeric PGID reuse")
        )
        gate_module.os.killpg = lambda process_group, signal_number: reused_signals.append(
            signal_number
        )
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/true"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="PID reuse fixture",
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "PID reuse fixture process leader was reaped outside the runner":
                raise SystemExit(f"bounded runner exposed wrong ownership error: {exc}") from exc
        else:
            raise SystemExit("bounded runner accepted lost process-group ownership")
    finally:
        gate_module.os.waitid = original_waitid
        gate_module.os.killpg = original_killpg
    if reused_signals:
        raise SystemExit("bounded runner signaled a numerically reused process group")

    ambiguous_process = None
    externally_reaped = False
    ambiguous_signals: list[int] = []

    def ambiguous_popen(*arguments, **keywords):
        nonlocal ambiguous_process
        ambiguous_process = original_popen(*arguments, **keywords)
        return ambiguous_process

    def externally_reaping_waitid(*arguments):
        nonlocal externally_reaped
        del arguments
        if ambiguous_process is not None and not externally_reaped:
            wait_fixture_child(ambiguous_process.pid, "ambiguous leader child")
            externally_reaped = True
        raise InterruptedError("injected indeterminate ownership probe")

    try:
        gate_module.subprocess.Popen = ambiguous_popen
        gate_module.os.waitid = externally_reaping_waitid
        gate_module.os.killpg = lambda process_group, signal_number: (
            ambiguous_signals.append(signal_number)
        )
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/true"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="indeterminate ownership fixture",
            )
        except BaseException:
            pass
        else:
            raise SystemExit("bounded runner accepted an indeterminate ownership probe")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.os.waitid = original_waitid
        gate_module.os.killpg = original_killpg
    if not externally_reaped:
        raise SystemExit("indeterminate ownership fixture did not release its leader")
    if ambiguous_signals:
        raise SystemExit(
            "bounded runner signaled after an indeterminate ownership probe: "
            f"{ambiguous_signals!r}"
        )

    term_process = None
    term_reaped = False
    signals_after_term_reap: list[int] = []

    def term_popen(*arguments, **keywords):
        nonlocal term_process
        term_process = original_popen(*arguments, **keywords)
        return term_process

    def reap_after_term(process_group: int, signal_number: int):
        nonlocal term_reaped
        if term_process is None or process_group != term_process.pid:
            raise AssertionError("TERM/KILL ownership fixture saw the wrong process group")
        if term_reaped:
            signals_after_term_reap.append(signal_number)
            raise ProcessLookupError
        if signal_number != gate_module.signal.SIGTERM:
            raise AssertionError("TERM/KILL ownership fixture expected TERM first")
        original_killpg(process_group, signal_number)
        wait_fixture_child(term_process.pid, "TERM-to-KILL leader child")
        term_reaped = True

    try:
        gate_module.subprocess.Popen = term_popen
        gate_module.os.killpg = reap_after_term
        try:
            gate_module.run_bounded_process(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    "import os,time; os.write(1,b'x'*4096); time.sleep(60)",
                ],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=64,
                stderr_limit=64,
                label="TERM ownership fixture",
            )
        except BaseException:
            pass
        else:
            raise SystemExit("bounded runner accepted the TERM ownership fixture")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.os.killpg = original_killpg
    if not term_reaped:
        raise SystemExit("TERM ownership fixture did not externally reap its leader")
    if signals_after_term_reap:
        raise SystemExit(
            "bounded runner signaled after TERM released leader ownership: "
            f"{signals_after_term_reap!r}"
        )

    original_read = gate_module.os.read
    cleanup_events: list[tuple[str, int]] = []
    injected = False

    def failing_read(descriptor: int, size: int) -> bytes:
        nonlocal injected
        if not injected:
            injected = True
            raise RuntimeError("injected selector read failure")
        return original_read(descriptor, size)

    def cleanup_popen(*arguments, **keywords):
        process = original_popen(*arguments, **keywords)
        gate_module.os.read = failing_read
        original_wait = process.wait

        def observed_wait(*wait_arguments, **wait_keywords):
            cleanup_events.append(("wait", process.pid))
            return original_wait(*wait_arguments, **wait_keywords)

        process.wait = observed_wait
        return process

    def cleanup_killpg(process_group: int, signal_number: int):
        if any(event == "wait" for event, _ in cleanup_events):
            raise AssertionError("cleanup signaled a process group after leader reap")
        cleanup_events.append(("signal", signal_number))
        return original_killpg(process_group, signal_number)

    try:
        gate_module.subprocess.Popen = cleanup_popen
        gate_module.os.killpg = cleanup_killpg
        try:
            gate_module.run_bounded_process(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    "import os,time; os.write(1,b'x'); time.sleep(60)",
                ],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="read failure fixture",
            )
        except RuntimeError as exc:
            if str(exc) != "injected selector read failure":
                raise
        else:
            raise SystemExit("bounded runner swallowed a selector read failure")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.os.killpg = original_killpg
        gate_module.os.read = original_read
    if (
        not cleanup_events
        or cleanup_events[-1][0] != "wait"
        or sum(event == "wait" for event, _ in cleanup_events) != 1
    ):
        raise SystemExit(
            "bounded runner cleanup did not signal before exactly one reap: "
            f"{cleanup_events!r}"
        )

    failed_term = False

    def fail_first_term(process_group: int, signal_number: int):
        nonlocal failed_term
        if signal_number == gate_module.signal.SIGTERM and not failed_term:
            failed_term = True
            raise OSError("injected process-group TERM failure")
        return original_killpg(process_group, signal_number)

    try:
        gate_module.os.killpg = fail_first_term
        try:
            gate_module.run_bounded_process(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    "import os; os.write(1,b'x'*4096)",
                ],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=64,
                stderr_limit=64,
                label="cleanup failure fixture",
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "cleanup failure fixture stdout exceeds its size bound":
                raise SystemExit(f"cleanup failure masked the primary error: {exc}") from exc
            if "process-group TERM cleanup failed" not in getattr(exc, "__notes__", ()):
                raise SystemExit("cleanup failure was not attached to the primary error")
        else:
            raise SystemExit("bounded runner accepted output overflow during cleanup failure")
    finally:
        gate_module.os.killpg = original_killpg


@fixture_owner_scoped
def test_post_popen_cancellation(gate_module, private: pathlib.Path) -> None:
    environment = gate_module.clean_environment(private / "repo" / "home")
    original_popen = gate_module.subprocess.Popen
    original_killpg = gate_module.os.killpg
    original_selector = gate_module.selectors.DefaultSelector
    spawned = None
    spawned_pidfd = FixtureDescriptorOwner()
    spawned_start_time = None

    def read_start_time(pid: int) -> int:
        try:
            return fixture_process_start_time(pid)
        except FixtureCleanupError as exc:
            raise SystemExit(
                "post-Popen fixture process identity is malformed"
            ) from exc

    def observed_popen(*arguments, **keywords):
        nonlocal spawned, spawned_start_time
        spawned = original_popen(*arguments, **keywords)
        spawned_start_time = read_start_time(spawned.pid)
        acquire_fixture_pidfd(
            spawned_pidfd,
            spawned.pid,
            "post-Popen fixture setup pidfd",
        )
        return spawned

    def cancelled_selector():
        if (
            spawned is None
            or spawned_pidfd.descriptor < 0
            or spawned_start_time is None
        ):
            raise SystemExit("post-Popen fixture injected before process ownership")
        raise KeyboardInterrupt("injected post-Popen selector cancellation")

    gate_module.subprocess.Popen = observed_popen
    gate_module.selectors.DefaultSelector = cancelled_selector
    try:
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/sleep", "30"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="post-Popen cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected post-Popen selector cancellation":
                raise
        else:
            raise SystemExit("bounded runner swallowed post-Popen cancellation")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.selectors.DefaultSelector = original_selector
    if (
        spawned is None
        or spawned_pidfd.descriptor < 0
        or spawned_start_time is None
    ):
        raise SystemExit("bounded runner post-Popen oracle never owned a child")
    oracle_primary: BaseException | None = None
    child_was_live = False
    try:
        current = fixture_process_map()
        child_was_live = (
            current.get(spawned.pid, (0, 0))[1] == spawned_start_time
        )
        if child_was_live:
            try:
                signal.pidfd_send_signal(
                    spawned_pidfd.descriptor,
                    signal.SIGKILL,
                    None,
                    0,
                )
            except ProcessLookupError:
                pass
            spawned.wait(timeout=2.0)
        if (
            fixture_process_map().get(spawned.pid, (0, 0))[1]
            == spawned_start_time
        ):
            raise SystemExit(
                "post-Popen fixture exact process identity remained live"
            )
        pidfd_ready = False
        for _ in range(3):
            try:
                readable, _, _ = select.select(
                    [spawned_pidfd.descriptor],
                    [],
                    [],
                    0.0,
                )
            except InterruptedError:
                continue
            pidfd_ready = spawned_pidfd.descriptor in readable
            break
        if not pidfd_ready:
            raise SystemExit("post-Popen fixture pidfd did not become readable")
    except BaseException as exc:
        oracle_primary = exc
    finally:
        oracle_primary = settle_fixture_descriptor_owner(
            spawned_pidfd,
            oracle_primary,
            "post-Popen fixture pidfd",
        )
    if oracle_primary is not None:
        raise oracle_primary
    if child_was_live:
        raise SystemExit("bounded runner left a child alive across post-Popen cancellation")

    cancelled_kill = False
    kill_attempts = 0
    kill_process = None
    kill_start_time = None

    def kill_popen(*arguments, **keywords):
        nonlocal kill_process, kill_start_time
        kill_process = original_popen(*arguments, **keywords)
        kill_start_time = read_start_time(kill_process.pid)
        return kill_process

    def cancelling_killpg(process_group: int, signal_number: int):
        nonlocal cancelled_kill, kill_attempts
        kill_attempts += 1
        if signal_number == gate_module.signal.SIGKILL and not cancelled_kill:
            cancelled_kill = True
            raise KeyboardInterrupt("injected KILL cleanup cancellation")
        return original_killpg(process_group, signal_number)

    try:
        gate_module.subprocess.Popen = kill_popen
        gate_module.os.killpg = cancelling_killpg
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/true"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="KILL cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected KILL cleanup cancellation":
                raise
        else:
            raise SystemExit("bounded runner swallowed KILL cleanup cancellation")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.os.killpg = original_killpg
    if (
        not cancelled_kill
        or kill_attempts != 2
        or kill_process is None
        or kill_start_time is None
        or fixture_process_map().get(kill_process.pid, (0, 0))[1]
        == kill_start_time
    ):
        raise SystemExit("bounded runner did not reap after KILL cleanup cancellation")

    wait_process = None
    wait_start_time = None
    wait_calls = 0

    def wait_popen(*arguments, **keywords):
        nonlocal wait_process, wait_start_time
        wait_process = original_popen(*arguments, **keywords)
        wait_start_time = read_start_time(wait_process.pid)
        original_wait = wait_process.wait

        def cancelling_wait(*wait_arguments, **wait_keywords):
            nonlocal wait_calls
            wait_calls += 1
            if wait_calls == 1:
                raise KeyboardInterrupt("injected wait cleanup cancellation")
            return original_wait(*wait_arguments, **wait_keywords)

        wait_process.wait = cancelling_wait
        return wait_process

    try:
        gate_module.subprocess.Popen = wait_popen
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/true"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="wait cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected wait cleanup cancellation":
                raise
        else:
            raise SystemExit("bounded runner swallowed wait cleanup cancellation")
    finally:
        gate_module.subprocess.Popen = original_popen
    if (
        wait_calls != 2
        or wait_process is None
        or wait_start_time is None
        or fixture_process_map().get(wait_process.pid, (0, 0))[1]
        == wait_start_time
    ):
        raise SystemExit("bounded runner did not retry and reap after wait cancellation")

    original_selector_factory = gate_module.selectors.DefaultSelector
    selector_process = None
    selector_start_time = None

    def selector_popen(*arguments, **keywords):
        nonlocal selector_process, selector_start_time
        selector_process = original_popen(*arguments, **keywords)
        selector_start_time = read_start_time(selector_process.pid)
        return selector_process

    def cancelled_selector():
        raise KeyboardInterrupt("injected selector setup cancellation")

    try:
        gate_module.subprocess.Popen = selector_popen
        gate_module.selectors.DefaultSelector = cancelled_selector
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/sleep", "30"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="selector cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected selector setup cancellation":
                raise
        else:
            raise SystemExit("bounded runner swallowed selector setup cancellation")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.selectors.DefaultSelector = original_selector_factory
    if (
        selector_process is None
        or selector_start_time is None
        or fixture_process_map().get(selector_process.pid, (0, 0))[1]
        == selector_start_time
    ):
        raise SystemExit("bounded runner did not reap after selector setup cancellation")

    register_process = None
    register_start_time = None

    class RegisterCancellingSelector:
        def __init__(self):
            self.inner = original_selector_factory()
            self.injected = False

        def register(self, *args, **kwargs):
            if not self.injected:
                self.injected = True
                raise KeyboardInterrupt("injected selector register cancellation")
            return self.inner.register(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    def register_popen(*arguments, **keywords):
        nonlocal register_process, register_start_time
        register_process = original_popen(*arguments, **keywords)
        register_start_time = read_start_time(register_process.pid)
        return register_process

    try:
        gate_module.subprocess.Popen = register_popen
        gate_module.selectors.DefaultSelector = RegisterCancellingSelector
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/sleep", "30"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="selector register cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected selector register cancellation":
                raise
        else:
            raise SystemExit("bounded runner swallowed selector register cancellation")
    finally:
        gate_module.subprocess.Popen = original_popen
        gate_module.selectors.DefaultSelector = original_selector_factory
    if (
        register_process is None
        or register_start_time is None
        or fixture_process_map().get(register_process.pid, (0, 0))[1]
        == register_start_time
    ):
        raise SystemExit("bounded runner did not reap after selector register cancellation")

    selector_close_calls = 0

    class CloseCancellingSelector:
        def __init__(self):
            self.inner = original_selector_factory()

        def close(self):
            nonlocal selector_close_calls
            selector_close_calls += 1
            if selector_close_calls == 1:
                raise KeyboardInterrupt("injected selector close cancellation")
            return self.inner.close()

        def __getattr__(self, name):
            return getattr(self.inner, name)

    try:
        gate_module.selectors.DefaultSelector = CloseCancellingSelector
        try:
            gate_module.run_bounded_process(
                ["/usr/bin/true"],
                input_bytes=None,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=16,
                stderr_limit=16,
                label="selector close cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected selector close cancellation":
                raise
        else:
            raise SystemExit("bounded runner swallowed selector close cancellation")
    finally:
        gate_module.selectors.DefaultSelector = original_selector_factory
    if selector_close_calls != 2:
        raise SystemExit("bounded runner did not retry selector close after cancellation")

    for boundary, expected_note in (
        ("fileno", "process stream descriptor cleanup failed"),
        ("unregister", "process stream unregister cleanup failed"),
        ("close", "process stream close cleanup failed"),
    ):
        stream_process = None
        stream_start_time = None
        stream_proxy = None
        unregister_injected = False

        class CancellingStream:
            def __init__(self, inner):
                self.inner = inner
                self.armed = False
                self.injected = False
                self.armed_fileno_calls = 0

            def fileno(self):
                if boundary == "fileno" and self.armed:
                    self.armed_fileno_calls += 1
                    if self.armed_fileno_calls == 2 and not self.injected:
                        self.injected = True
                        raise KeyboardInterrupt(
                            "injected final fileno cancellation"
                        )
                return self.inner.fileno()

            def close(self):
                if boundary == "close" and self.armed and not self.injected:
                    self.injected = True
                    raise KeyboardInterrupt("injected final close cancellation")
                return self.inner.close()

            def __getattr__(self, name):
                return getattr(self.inner, name)

        class StreamCancellingSelector:
            def __init__(self):
                self.inner = original_selector_factory()
                self.select_calls = 0

            def select(self, *args, **kwargs):
                self.select_calls += 1
                if stream_proxy is not None:
                    stream_proxy.armed = True
                if self.select_calls > 1:
                    return []
                return self.inner.select(*args, **kwargs)

            def unregister(self, *args, **kwargs):
                nonlocal unregister_injected
                if boundary == "unregister" and not unregister_injected:
                    unregister_injected = True
                    raise KeyboardInterrupt(
                        "injected final unregister cancellation"
                    )
                return self.inner.unregister(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        def stream_popen(*arguments, **keywords):
            nonlocal stream_process, stream_start_time, stream_proxy
            stream_process = original_popen(*arguments, **keywords)
            stream_start_time = read_start_time(stream_process.pid)
            stream_proxy = CancellingStream(stream_process.stdout)
            stream_process.stdout = stream_proxy
            return stream_process

        try:
            gate_module.subprocess.Popen = stream_popen
            gate_module.selectors.DefaultSelector = StreamCancellingSelector
            try:
                gate_module.run_bounded_process(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-c",
                        "import os;os.write(1,b'x'*4096)",
                    ],
                    input_bytes=None,
                    environment=environment,
                    deadline=time.monotonic() + 5.0,
                    stdout_limit=64,
                    stderr_limit=64,
                    label=f"stream {boundary} cancellation fixture",
                )
            except KeyboardInterrupt as exc:
                if str(exc) != f"injected final {boundary} cancellation":
                    raise SystemExit(
                        f"stream {boundary} cleanup lost exact cancellation: {exc}"
                    ) from exc
                if expected_note not in getattr(exc, "__notes__", ()):
                    raise SystemExit(
                        f"stream {boundary} cleanup omitted fixed evidence: "
                        f"{getattr(exc, '__notes__', ())!r}"
                    ) from exc
                cause = exc.__cause__
                if (
                    not isinstance(cause, gate_module.WorkflowGateError)
                    or str(cause)
                    != f"stream {boundary} cancellation fixture stdout "
                    "exceeds its size bound"
                ):
                    raise SystemExit(
                        f"stream {boundary} cleanup lost its ordinary cause"
                    ) from exc
            else:
                raise SystemExit(
                    f"stream {boundary} cleanup swallowed caller cancellation"
                )
        finally:
            gate_module.subprocess.Popen = original_popen
            gate_module.selectors.DefaultSelector = original_selector_factory
        if (
            stream_process is None
            or stream_start_time is None
            or fixture_process_map().get(stream_process.pid, (0, 0))[1]
            == stream_start_time
            or (
                boundary in {"fileno", "close"}
                and (stream_proxy is None or not stream_proxy.injected)
            )
            or (boundary == "unregister" and not unregister_injected)
        ):
            raise SystemExit(
                f"stream {boundary} cancellation skipped cleanup or reap"
            )


@fixture_owner_scoped
def test_real_gh_bounded_route(gate_module, private: pathlib.Path) -> None:
    calls: list[tuple[list[str], dict]] = []
    original_runner = gate_module.run_bounded_process
    controlled_home = private / "repo" / "home"
    controlled_proxy = {
        "http_proxy": "http://127.0.0.1:7897",
        "https_proxy": "https://proxy.example.invalid:443",
        "no_proxy": "localhost,127.0.0.1",
    }
    environment_names = (
        *controlled_proxy,
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "BASH_ENV",
        "GH_TOKEN",
    )
    saved_environment = {
        name: os.environ.get(name)
        for name in environment_names
    }

    def fake_bounded(arguments: list[str], **keywords):
        calls.append((arguments, keywords))
        return subprocess.CompletedProcess(arguments, 0, b'{"ok":true}', b"")

    try:
        os.environ.update(controlled_proxy)
        os.environ.update(
            {
                "HTTP_PROXY": "http://hostile-uppercase.invalid",
                "HTTPS_PROXY": "https://hostile-uppercase.invalid",
                "NO_PROXY": "hostile.invalid",
                "BASH_ENV": "/tmp/hostile-bash-env",
                "GH_TOKEN": "hostile-token-must-not-be-copied",
            }
        )
        gate_module.run_bounded_process = fake_bounded
        deadline = time.monotonic() + 5.0
        result = gate_module.real_gh_runner(controlled_home)(
            ["/usr/bin/gh", "api", "fixture"], "{}", deadline
        )
    finally:
        gate_module.run_bounded_process = original_runner
        for name, value in saved_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    if result.returncode or result.stdout != '{"ok":true}' or result.stderr:
        raise SystemExit("real gh runner changed bounded UTF-8 output")
    if len(calls) != 1:
        raise SystemExit("real gh runner did not use exactly one bounded process")
    arguments, keywords = calls[0]
    expected_environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(controlled_home),
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
        **controlled_proxy,
    }
    if arguments != ["/usr/bin/gh", "api", "fixture"] or keywords != {
        "input_bytes": b"{}",
        "environment": expected_environment,
        "deadline": deadline,
        "stdout_limit": gate_module.MAX_GH_OUTPUT_BYTES,
        "stderr_limit": gate_module.MAX_GH_OUTPUT_BYTES,
        "label": "GitHub CLI command",
    }:
        raise SystemExit("real gh runner did not forward exact bounded-process arguments")


@fixture_owner_scoped
def test_remote_response_boundaries(gate_module) -> None:
    arguments = ["/usr/bin/gh", "api", "fixture"]

    def invoke(
        stdout: object,
        *,
        stderr: object = "",
        returncode: object = 0,
    ) -> object:
        def runner(actual_arguments, input_text, deadline):
            if (
                actual_arguments != arguments
                or input_text is not None
                or deadline != 1.0
            ):
                raise AssertionError("remote-response fixture changed its runner inputs")
            return subprocess.CompletedProcess(
                actual_arguments, returncode, stdout, stderr
            )

        return gate_module.gh_json(
            runner,
            arguments,
            "remote response fixture",
            1.0,
        )

    def expect_rejected(
        label: str,
        stdout: object,
        expected: str,
        *,
        stderr: object = "",
        returncode: object = 0,
    ) -> None:
        try:
            invoke(stdout, stderr=stderr, returncode=returncode)
        except gate_module.WorkflowGateError as exc:
            if str(exc) != expected:
                raise SystemExit(
                    f"remote-response {label} used the wrong diagnostic: {exc}"
                )
        else:
            raise SystemExit(f"remote-response fixture accepted {label}")

    if (
        gate_module.MAX_GH_DIAGNOSTIC_BYTES,
        gate_module.MAX_GH_JSON_INTEGER_DIGITS,
        gate_module.MAX_GH_JSON_NESTING_DEPTH,
    ) != (4096, 64, 16):
        raise SystemExit("remote-response resource limits changed")
    exact_integer = "9" * gate_module.MAX_GH_JSON_INTEGER_DIGITS
    if invoke(exact_integer) != int(exact_integer):
        raise SystemExit("remote-response parser rejected its exact integer limit")
    exact_depth = (
        "[" * gate_module.MAX_GH_JSON_NESTING_DEPTH
        + "0"
        + "]" * gate_module.MAX_GH_JSON_NESTING_DEPTH
    )
    if not isinstance(invoke(exact_depth), list):
        raise SystemExit("remote-response parser rejected its exact nesting limit")
    if invoke('{"value":"[[[\\\""}') != {"value": '[[["'}:
        raise SystemExit("remote-response depth scanner interpreted string contents")
    invalid_json = "remote response fixture returned invalid JSON"
    for label, source in (
        ("invalid JSON", "{"),
        ("over-limit integer", "9" * (gate_module.MAX_GH_JSON_INTEGER_DIGITS + 1)),
        ("floating-point number", "1.0"),
        ("nonstandard number", "NaN"),
        ("duplicate object key", '{"sha":"a","sha":"b"}'),
    ):
        expect_rejected(label, source, invalid_json)
    expect_rejected(
        "over-nested JSON",
        "[" * (gate_module.MAX_GH_JSON_NESTING_DEPTH + 1)
        + "0"
        + "]" * (gate_module.MAX_GH_JSON_NESTING_DEPTH + 1),
        "remote response fixture returned over-nested JSON",
    )
    expect_rejected(
        "non-string stdout",
        b"{}",
        "remote response fixture result is not canonical",
    )
    expect_rejected(
        "boolean return code",
        "{}",
        "remote response fixture result is not canonical",
        returncode=True,
    )
    expect_rejected(
        "oversized stdout",
        "x" * (gate_module.MAX_GH_OUTPUT_BYTES + 1),
        "remote response fixture output exceeds its size bound",
    )
    expect_rejected(
        "oversized stderr",
        "",
        "remote response fixture error output exceeds its size bound",
        stderr="x" * (gate_module.MAX_GH_OUTPUT_BYTES + 1),
        returncode=1,
    )
    expect_rejected(
        "oversized diagnostic",
        "",
        "remote response fixture failed with an oversized diagnostic",
        stderr="x" * (gate_module.MAX_GH_DIAGNOSTIC_BYTES + 1),
        returncode=1,
    )
    exact_stdout = (
        '"'
        + "x" * (gate_module.MAX_GH_OUTPUT_BYTES - 2)
        + '"'
    )
    if len(exact_stdout.encode("utf-8")) != gate_module.MAX_GH_OUTPUT_BYTES:
        raise SystemExit("remote-response exact stdout oracle is malformed")
    if invoke(exact_stdout) != "x" * (gate_module.MAX_GH_OUTPUT_BYTES - 2):
        raise SystemExit("remote-response parser rejected its exact stdout limit")
    if invoke(
        "{}", stderr="x" * gate_module.MAX_GH_OUTPUT_BYTES
    ) != {}:
        raise SystemExit("remote-response parser rejected its exact stderr limit")
    exact_diagnostic = "x" * gate_module.MAX_GH_DIAGNOSTIC_BYTES
    exact_failure = subprocess.CompletedProcess(
        arguments, 1, "", exact_diagnostic
    )
    if gate_module.gh_failure_message(
        exact_failure, "remote response fixture"
    ) != f"remote response fixture failed: {exact_diagnostic}":
        raise SystemExit("remote-response renderer rejected its exact diagnostic limit")
    expect_rejected(
        "multiline diagnostic",
        "",
        "remote response fixture failed with a noncanonical diagnostic",
        stderr="forged PASS\nsecond line",
        returncode=1,
    )

    def inventory_runner(run_id: int):
        record = {
            "databaseId": run_id,
            "displayTitle": f"haptics-dispatch-{TEST_DISPATCH_ID}",
            "headBranch": TEST_REF,
            "headSha": "a" * 40,
            "event": "workflow_dispatch",
            "status": "queued",
            "url": (
                f"https://github.com/{TEST_REPOSITORY}/actions/runs/{run_id}"
            ),
            "workflowName": gate_module.WORKFLOW_NAME,
        }

        def runner(actual_arguments, input_text, deadline):
            del actual_arguments
            if input_text is not None or deadline != 1.0:
                raise AssertionError("database-id fixture changed runner inputs")
            return subprocess.CompletedProcess(
                arguments, 0, json.dumps([record]), ""
            )

        return runner

    accepted = gate_module.list_workflow_runs(
        inventory_runner(gate_module.MAX_GITHUB_DATABASE_ID),
        TEST_REPOSITORY,
        TEST_REF,
        "a" * 40,
        1.0,
    )
    if accepted[0].run_id != gate_module.MAX_GITHUB_DATABASE_ID:
        raise SystemExit("workflow-run inventory rejected its exact database-id limit")
    try:
        gate_module.list_workflow_runs(
            inventory_runner(gate_module.MAX_GITHUB_DATABASE_ID + 1),
            TEST_REPOSITORY,
            TEST_REF,
            "a" * 40,
            1.0,
        )
    except gate_module.WorkflowGateError as exc:
        if str(exc) != "workflow-run record is not canonical":
            raise SystemExit(
                f"database-id overflow failed at the wrong boundary: {exc}"
            ) from exc
    else:
        raise SystemExit("workflow-run inventory accepted an oversized database id")


@fixture_owner_scoped
def test_main_absolute_deadline(
    gate_module,
    repo: pathlib.Path,
    trusted: str,
    candidate: str,
    state_path: pathlib.Path,
    operator_home: pathlib.Path,
) -> None:
    deadlines: list[tuple[str, float]] = []
    runner_sentinel = object()
    original_verify = gate_module.verify_candidate
    original_dispatch = gate_module.dispatch_candidate
    original_runner_factory = gate_module.real_gh_runner
    previous_argv = sys.argv
    previous_allow = os.environ.get("GH_ALLOW_DISPATCH")
    previous_gate_digest = os.environ.get("HAPTICS_TRUSTED_GATE_SHA256")
    previous_home = os.environ.get("HOME")

    def fake_verify(
        repo_path,
        trusted_commit,
        candidate_commit,
        *,
        deadline,
        require_unchanged_candidate,
    ):
        if not require_unchanged_candidate:
            raise AssertionError("production main omitted the candidate relation gate")
        deadlines.append(("verify", deadline))
        return "0" * 64, tuple(
            (path, "1" * 64) for path in gate_module.VALIDATOR_PATHS
        )

    def fake_dispatch(
        repository,
        remote_ref,
        candidate_commit,
        release_tag,
        dispatch_state_path,
        gh_runner,
        *,
        evidence,
        deadline,
    ):
        if gh_runner is not runner_sentinel:
            raise AssertionError("main deadline fixture changed the gh runner")
        deadlines.append(("dispatch", deadline))
        dispatch_id = TEST_DISPATCH_ID
        return gate_module.DispatchResult(
            gate_module.DispatchRecord(
                42,
                f"haptics-dispatch-{dispatch_id}",
                TEST_REF,
                candidate,
                f"https://github.com/{TEST_REPOSITORY}/actions/runs/42",
            ),
            dispatch_id,
            gate_module.dispatch_input_digest(release_tag, dispatch_id),
            hashlib.sha256(
                gate_module.serialize_dispatch_state(
                    repository,
                    remote_ref,
                    candidate_commit,
                    release_tag,
                    dispatch_id,
                    evidence,
                )
            ).hexdigest(),
            gate_module.VALIDATOR_MODE,
        )

    started = time.monotonic()
    try:
        gate_module.verify_candidate = fake_verify
        gate_module.dispatch_candidate = fake_dispatch
        gate_module.real_gh_runner = lambda home: runner_sentinel
        os.environ["GH_ALLOW_DISPATCH"] = "1"
        os.environ["HOME"] = str(operator_home)
        os.environ["HAPTICS_TRUSTED_GATE_SHA256"] = hashlib.sha256(
            GATE.read_bytes()
        ).hexdigest()
        sys.argv = [
            str(GATE),
            "--dispatch",
            "--repo-dir",
            str(repo),
            "--trusted-commit",
            trusted,
            "--candidate-commit",
            candidate,
            "--repository",
            TEST_REPOSITORY,
            "--remote-ref",
            TEST_REF,
            "--dispatch-state",
            str(state_path),
        ]
        with fixture_account_home(gate_module, operator_home):
            with contextlib.redirect_stdout(io.StringIO()):
                gate_module.main()
    finally:
        gate_module.verify_candidate = original_verify
        gate_module.dispatch_candidate = original_dispatch
        gate_module.real_gh_runner = original_runner_factory
        sys.argv = previous_argv
        if previous_allow is None:
            os.environ.pop("GH_ALLOW_DISPATCH", None)
        else:
            os.environ["GH_ALLOW_DISPATCH"] = previous_allow
        if previous_gate_digest is None:
            os.environ.pop("HAPTICS_TRUSTED_GATE_SHA256", None)
        else:
            os.environ["HAPTICS_TRUSTED_GATE_SHA256"] = previous_gate_digest
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home
    if (
        tuple(name for name, _ in deadlines) != ("verify", "dispatch")
        or len({deadline for _, deadline in deadlines}) != 1
        or not started
        < deadlines[0][1]
        <= started + gate_module.GATE_TIMEOUT_SECONDS + 1.0
    ):
        raise SystemExit("production main did not route one absolute gate deadline")


class FakeGhRunner:
    def __init__(
        self,
        candidate_commit: str,
        *,
        fail_after_dispatch: bool = False,
        fail_inventory_after_dispatch_once: bool = False,
        run_branch: str | None = None,
        locked_branch: bool = True,
        allow_fork_syncing: bool = False,
        move_ref_on_query: int | None = None,
        move_ref_on_dispatch: bool = False,
        move_ref_on_inventory_after_dispatch: bool = False,
        unlock_on_protection_query: int | None = None,
        preexisting_same_sha: bool = False,
        preexisting_matching_title: bool = False,
        competing_after_dispatch: bool = False,
        duplicate_matching_after_dispatch: bool = False,
        authenticated_login: str = TEST_AUTHENTICATED_LOGIN,
        actor_login: str = TEST_AUTHENTICATED_LOGIN,
        triggering_actor_login: str | None = None,
        run_path: str = ".github/workflows/build.yml",
        run_workflow_name: str = "Build TB321FU Haptics Debs",
        run_workflow_id: int = 7,
        run_repository: str = TEST_REPOSITORY,
        run_head_repository: str = TEST_REPOSITORY,
    ) -> None:
        self.candidate_commit = candidate_commit
        self.fail_after_dispatch = fail_after_dispatch
        self.fail_inventory_after_dispatch_once = fail_inventory_after_dispatch_once
        self.run_branch = TEST_REF if run_branch is None else run_branch
        self.locked_branch = locked_branch
        self.allow_fork_syncing = allow_fork_syncing
        self.move_ref_on_query = move_ref_on_query
        self.move_ref_on_dispatch = move_ref_on_dispatch
        self.move_ref_on_inventory_after_dispatch = (
            move_ref_on_inventory_after_dispatch
        )
        self.unlock_on_protection_query = unlock_on_protection_query
        self.preexisting_same_sha = preexisting_same_sha
        self.preexisting_matching_title = preexisting_matching_title
        self.competing_after_dispatch = competing_after_dispatch
        self.duplicate_matching_after_dispatch = (
            duplicate_matching_after_dispatch
        )
        self.authenticated_login = authenticated_login
        self.actor_login = actor_login
        self.triggering_actor_login = (
            actor_login
            if triggering_actor_login is None
            else triggering_actor_login
        )
        self.run_path = run_path
        self.run_workflow_name = run_workflow_name
        self.run_workflow_id = run_workflow_id
        self.run_repository = run_repository
        self.run_head_repository = run_head_repository
        self.ref_target = candidate_commit
        self.ref_query_count = 0
        self.protection_query_count = 0
        self.dispatched = False
        self.dispatch_count = 0
        self.dispatch_id: str | None = None
        self.inputs: dict[str, object] | None = None
        self.transcript: list[tuple[tuple[str, ...], str | None]] = []
        self.deadlines: list[float] = []

    def run_detail(self, run_id: int) -> dict[str, object]:
        if run_id == 42:
            title = f"haptics-dispatch-{self.dispatch_id}"
        elif run_id == 41:
            title = f"haptics-dispatch-{TEST_DISPATCH_ID}"
        else:
            title = "haptics-dispatch-" + "e" * 32
        return {
            "runId": run_id,
            "headBranch": self.run_branch,
            "headSha": self.candidate_commit,
            "event": "workflow_dispatch",
            "path": self.run_path,
            "displayTitle": title,
            "workflowName": self.run_workflow_name,
            "workflowId": self.run_workflow_id,
            "actorLogin": self.actor_login,
            "triggeringActorLogin": self.triggering_actor_login,
            "repositoryFullName": self.run_repository,
            "headRepositoryFullName": self.run_head_repository,
        }

    def __call__(
        self, arguments: list[str], input_text: str | None, deadline: float
    ) -> subprocess.CompletedProcess[str]:
        self.transcript.append((tuple(arguments), input_text))
        self.deadlines.append(deadline)
        if arguments == authenticated_login_arguments():
            if input_text is not None:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "unexpected authenticated-user input"
                )
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps({"login": self.authenticated_login}),
                "",
            )
        if arguments == workflow_run_ownership_arguments(42):
            if input_text is not None:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "unexpected workflow-run detail input"
                )
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps(self.run_detail(42)),
                "",
            )
        if arguments == branch_protection_arguments():
            self.protection_query_count += 1
            if input_text is not None:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "unexpected branch-protection input"
                )
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps(
                    {
                        "lockBranch": (
                            self.locked_branch
                            and self.protection_query_count
                            != self.unlock_on_protection_query
                        ),
                        "allowForcePushes": False,
                        "allowDeletions": False,
                        "allowForkSyncing": self.allow_fork_syncing,
                    }
                ),
                "",
            )
        if arguments[1:3] == ["api", "--method"]:
            self.ref_query_count += 1
            expected = remote_ref_arguments()
            if arguments != expected or input_text is not None:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "unexpected remote-ref query command"
                )
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps(
                    {
                        "object": {
                            "sha": (
                                "f" * 40
                                if self.ref_query_count == self.move_ref_on_query
                                else self.ref_target
                            )
                        }
                    }
                ),
                "",
            )
        if arguments[1:3] == ["run", "list"]:
            expected = workflow_inventory_arguments(self.candidate_commit)
            if arguments != expected or input_text is not None:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "unexpected workflow-run inventory command"
                )
            if self.dispatched and self.fail_inventory_after_dispatch_once:
                self.fail_inventory_after_dispatch_once = False
                return subprocess.CompletedProcess(
                    arguments, 1, "", "simulated post-dispatch inventory failure"
                )
            if self.dispatched and self.move_ref_on_inventory_after_dispatch:
                self.ref_target = "e" * 40
                self.move_ref_on_inventory_after_dispatch = False
            def run_record(run_id: int, display_title: str) -> dict[str, object]:
                return {
                    "databaseId": run_id,
                    "displayTitle": display_title,
                    "headBranch": self.run_branch,
                    "headSha": self.candidate_commit,
                    "event": "workflow_dispatch",
                    "status": "queued",
                    "url": (
                        "https://github.com/GUF296/tb321fu-haptics-debs/"
                        f"actions/runs/{run_id}"
                    ),
                    "workflowName": "Build TB321FU Haptics Debs",
                }

            runs = []
            if self.preexisting_same_sha:
                runs.append(run_record(40, "haptics-dispatch-" + "e" * 32))
            if self.preexisting_matching_title:
                runs.append(
                    run_record(41, f"haptics-dispatch-{TEST_DISPATCH_ID}")
                )
            if self.dispatched:
                runs.append(
                    run_record(42, f"haptics-dispatch-{self.dispatch_id}")
                )
                if self.competing_after_dispatch:
                    runs.append(
                        run_record(43, "haptics-dispatch-" + "d" * 32)
                    )
                if self.duplicate_matching_after_dispatch:
                    runs.append(
                        run_record(44, f"haptics-dispatch-{self.dispatch_id}")
                    )
            return subprocess.CompletedProcess(arguments, 0, json.dumps(runs), "")
        if arguments[1:3] == ["workflow", "run"]:
            expected = workflow_dispatch_arguments()
            if arguments != expected or input_text is None:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "unexpected workflow dispatch command"
                )
            self.inputs = json.loads(input_text or "")
            self.dispatch_id = self.inputs.get("dispatch_id")
            self.dispatched = True
            self.dispatch_count += 1
            if self.move_ref_on_dispatch:
                self.ref_target = "d" * 40
            if self.fail_after_dispatch:
                return subprocess.CompletedProcess(
                    arguments, 1, "", "simulated applied transport failure"
                )
            return subprocess.CompletedProcess(arguments, 0, "", "")
        return subprocess.CompletedProcess(arguments, 1, "", "unexpected fake gh command")


@fixture_owner_scoped
def test_competing_full_main_dispatches(
    gate_module,
    repo: pathlib.Path,
    trusted: str,
    candidate: str,
    private: pathlib.Path,
    expected_output_factory,
) -> None:
    operator_home = private / "competing-main-home"
    state_directory = (
        operator_home / gate_module.DISPATCH_STATE_RELATIVE_DIRECTORY
    )
    state_directory.mkdir(parents=True, mode=0o700)
    state_path = state_directory / f"{candidate}.diagnostic.tsv"
    remote_state = private / "competing-main-remote"
    remote_state.mkdir(mode=0o700)
    counter_path = remote_state / "post-count"
    dispatch_id_path = remote_state / "dispatch-id"
    counter_path.write_text("0\n", encoding="ascii")

    class FileGhRunner:
        def __call__(self, arguments, input_text, deadline):
            del deadline
            if arguments == authenticated_login_arguments():
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    json.dumps({"login": TEST_AUTHENTICATED_LOGIN}),
                    "",
                )
            if arguments == remote_ref_arguments():
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    json.dumps({"object": {"sha": candidate}}),
                    "",
                )
            if arguments == branch_protection_arguments():
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    json.dumps(
                        {
                            "lockBranch": True,
                            "allowForcePushes": False,
                            "allowDeletions": False,
                            "allowForkSyncing": False,
                        }
                    ),
                    "",
                )
            if arguments == workflow_inventory_arguments(candidate):
                with counter_path.open("r+", encoding="ascii") as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX)
                    count = int(stream.read().strip())
                    dispatch_id = (
                        dispatch_id_path.read_text(encoding="ascii").strip()
                        if count
                        else ""
                    )
                    fcntl.flock(stream, fcntl.LOCK_UN)
                runs = []
                if count:
                    runs.append(
                        {
                            "databaseId": 42,
                            "displayTitle": f"haptics-dispatch-{dispatch_id}",
                            "headBranch": TEST_REF,
                            "headSha": candidate,
                            "event": "workflow_dispatch",
                            "status": "queued",
                            "url": (
                                f"https://github.com/{TEST_REPOSITORY}/"
                                "actions/runs/42"
                            ),
                            "workflowName": gate_module.WORKFLOW_NAME,
                        }
                    )
                return subprocess.CompletedProcess(
                    arguments, 0, json.dumps(runs), ""
                )
            if arguments == workflow_run_ownership_arguments(42):
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    json.dumps(
                        {
                            "runId": 42,
                            "headBranch": TEST_REF,
                            "headSha": candidate,
                            "event": "workflow_dispatch",
                            "path": ".github/workflows/build.yml",
                            "displayTitle": f"haptics-dispatch-{dispatch_id_path.read_text(encoding='ascii').strip()}",
                            "workflowName": gate_module.WORKFLOW_NAME,
                            "workflowId": 7,
                            "actorLogin": TEST_AUTHENTICATED_LOGIN,
                            "triggeringActorLogin": TEST_AUTHENTICATED_LOGIN,
                            "repositoryFullName": TEST_REPOSITORY,
                            "headRepositoryFullName": TEST_REPOSITORY,
                        }
                    ),
                    "",
                )
            if arguments == workflow_dispatch_arguments():
                inputs = json.loads(input_text)
                dispatch_id = inputs.get("dispatch_id")
                with counter_path.open("r+", encoding="ascii") as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX)
                    count = int(stream.read().strip()) + 1
                    stream.seek(0)
                    stream.truncate()
                    stream.write(f"{count}\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                    if count == 1:
                        dispatch_id_path.write_text(
                            f"{dispatch_id}\n", encoding="ascii"
                        )
                    fcntl.flock(stream, fcntl.LOCK_UN)
                return subprocess.CompletedProcess(arguments, 0, "", "")
            return subprocess.CompletedProcess(
                arguments, 1, "", "unexpected file-backed gh command"
            )

    children: list[int] = []
    child_owners: list[FixtureChildOwner] = []
    outputs: list[pathlib.Path] = []
    try:
        for index in range(2):
            output_path = remote_state / f"main-{index}.out"
            outputs.append(output_path)
            def full_main_child(
                output_path: pathlib.Path = output_path,
            ) -> int:
                try:
                    output, _ = run_dispatch_main(
                        gate_module,
                        repo,
                        trusted,
                        candidate,
                        state_path,
                        FileGhRunner(),
                        operator_home,
                    )
                    output_path.write_text(output, encoding="utf-8")
                except BaseException as exc:
                    output_path.write_text(
                        f"ERROR\t{type(exc).__name__}\t{exc}\n",
                        encoding="utf-8",
                    )
                    return 91
                return 0

            owner = FixtureChildOwner()
            child_owners.append(owner)
            spawn_fixture_child(
                owner,
                full_main_child,
                f"competing full main fork {index}",
            )
            children.append(owner.pid)
    except BaseException as exc:
        selected: BaseException | None = exc
        for index, owner in reversed(tuple(enumerate(child_owners))):
            selected = settle_fixture_child_owner(
                owner,
                selected,
                f"competing full main fork {index}",
            )
        assert selected is not None
        raise selected
    child_statuses = wait_fixture_children(children, "competing full main")
    for owner in child_owners:
        owner.pid = -1
    for index, status in enumerate(child_statuses):
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            detail = (
                outputs[index].read_text(encoding="utf-8")
                if outputs[index].exists()
                else "missing child output"
            )
            raise SystemExit(
                f"competing full main {index} failed: {detail}"
            )
    if int(counter_path.read_text(encoding="ascii").strip()) != 1:
        raise SystemExit("competing full main routes performed more than one POST")
    dispatch_id_raw = dispatch_id_path.read_bytes()
    if len(dispatch_id_raw) != 33 or not dispatch_id_raw.endswith(b"\n"):
        raise SystemExit("competing full main dispatch identity is not bounded")
    try:
        dispatch_id = dispatch_id_raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(
            "competing full main dispatch identity is not ASCII"
        ) from exc
    expected_output = expected_output_factory(dispatch_id, "", state_path)
    for index, output in enumerate(outputs):
        metadata = output.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > gate_module.MAX_GH_OUTPUT_BYTES
        ):
            raise SystemExit(
                f"competing full main {index} output is outside its bound"
            )
        raw_output = output.read_bytes()
        if len(raw_output) != metadata.st_size:
            raise SystemExit(
                f"competing full main {index} output changed during its read"
            )
        try:
            observed_output = raw_output.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(
                f"competing full main {index} output is not strict UTF-8"
            ) from exc
        if observed_output != expected_output:
            raise SystemExit(
                f"competing full main {index} transcript is not canonical"
            )
    if not state_path.is_file() or state_path.stat().st_nlink != 1:
        raise SystemExit("competing full main ledger did not converge")


@fixture_owner_scoped
def test_fixture_async_signal_custody(cwd: pathlib.Path) -> None:
    caller_mask = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
    caller_handlers = {
        signal.SIGINT: signal.getsignal(signal.SIGINT),
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
    }
    caller_subreaper = fixture_get_subreaper()
    original_atomic_block = globals()["fixture_atomic_capture_and_block"]
    assignment_cancellation = KeyboardInterrupt(
        "dispatch fixture atomic-mask assignment cancellation"
    )

    def cancel_after_atomic_block(signals, old_mask, applied):
        original_atomic_block(signals, old_mask, applied)
        raise assignment_cancellation

    globals()["fixture_atomic_capture_and_block"] = cancel_after_atomic_block
    assignment_caught: BaseException | None = None
    try:
        try:
            FixtureSignalLatch().enter()
        except BaseException as exc:
            assignment_caught = exc
    finally:
        globals()["fixture_atomic_capture_and_block"] = original_atomic_block
    if (
        assignment_caught is not assignment_cancellation
        or frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set())) != caller_mask
        or any(
            signal.getsignal(signum) is not handler
            for signum, handler in caller_handlers.items()
        )
    ):
        raise SystemExit(
            "dispatch fixture atomic-mask assignment custody drifted"
        ) from assignment_caught
    process_source = PROCESS_IDENTITY_HELPER + """
import os
import pathlib
import signal
import sys
import time

root_identity, child_identity, mode, supervisor = sys.argv[1:5]
record_identity(root_identity)
child = os.fork()
if child == 0:
    record_identity(child_identity)
    time.sleep(30)
    os._exit(0)
deadline = time.monotonic() + 2.0
while not pathlib.Path(child_identity).is_file() and time.monotonic() < deadline:
    time.sleep(0.01)
if mode == "signal-parent":
    os.kill(int(supervisor), signal.SIGTERM)
time.sleep(30)
"""
    cases = (
        ("popen", signal.SIGTERM, 143),
        ("wait", signal.SIGINT, 130),
        ("pidfd", signal.SIGINT, 130),
        ("timeout-pidfd", signal.SIGINT, 130),
        ("reap", signal.SIGINT, 130),
        ("descendant", signal.SIGINT, 130),
    )
    for boundary, boundary_signal, expected_code in cases:
        before_descriptors = fixture_open_descriptor_set()
        with tempfile.TemporaryDirectory(
            prefix=f"tb321fu-dispatch-signal-{boundary}."
        ) as raw:
            private = pathlib.Path(raw)
            root_identity = private / "root.identity"
            child_identity = private / "child.identity"
            original_popen = subprocess.Popen
            original_pidfd_send_signal = signal.pidfd_send_signal
            original_owned_processes = globals()["fixture_owned_processes"]
            processes: list[subprocess.Popen[bytes]] = []
            boundary_fired = False
            popen_returned = False

            def fire(signum: int) -> None:
                nonlocal boundary_fired
                if boundary_fired:
                    return
                boundary_fired = True
                os.kill(os.getpid(), signum)

            def signal_at_boundary(*args, **kwargs):
                nonlocal popen_returned
                process = original_popen(*args, **kwargs)
                processes.append(process)
                original_wait = process.wait

                def wait_with_signal(timeout=None):
                    if boundary == "wait":
                        fire(boundary_signal)
                    elif boundary == "reap" and popen_returned:
                        fire(boundary_signal)
                    return original_wait(timeout=timeout)

                process.wait = wait_with_signal
                ready_deadline = time.monotonic() + 2.0
                while (
                    not child_identity.is_file()
                    and time.monotonic() < ready_deadline
                ):
                    time.sleep(0.01)
                if not child_identity.is_file():
                    raise RuntimeError(
                        f"dispatch fixture {boundary} child did not publish identity"
                    )
                if boundary == "popen":
                    fire(signal.SIGTERM)
                elif boundary in ("reap", "descendant"):
                    os.kill(os.getpid(), signal.SIGTERM)
                popen_returned = True
                return process

            def pidfd_signal_with_signal(*args, **kwargs):
                if boundary in ("pidfd", "timeout-pidfd"):
                    fire(boundary_signal)
                return original_pidfd_send_signal(*args, **kwargs)

            def owned_wave_with_signal(*args, **kwargs):
                if boundary == "descendant" and popen_returned:
                    fire(boundary_signal)
                return original_owned_processes(*args, **kwargs)

            subprocess.Popen = signal_at_boundary
            signal.pidfd_send_signal = pidfd_signal_with_signal
            globals()["fixture_owned_processes"] = owned_wave_with_signal
            caught: BaseException | None = None
            try:
                try:
                    run(
                        "/usr/bin/python3",
                        "-c",
                        process_source,
                        str(root_identity),
                        str(child_identity),
                        "signal-parent" if boundary == "pidfd" else "wait",
                        str(os.getpid()),
                        cwd=cwd,
                        timeout_seconds=(0.05 if boundary == "timeout-pidfd" else 3.0),
                    )
                except BaseException as exc:
                    caught = exc
            finally:
                globals()["fixture_owned_processes"] = original_owned_processes
                signal.pidfd_send_signal = original_pidfd_send_signal
                subprocess.Popen = original_popen
                for process in processes:
                    if process.poll() is None:
                        try:
                            os.kill(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=2.0)
                        except BaseException:
                            pass
                try:
                    fixture_cleanup_descendants(frozenset())
                except BaseException:
                    pass
            identities: list[tuple[int, int]] = []
            for path in (root_identity, child_identity):
                identities.append(
                    read_fixture_process_identity(
                        path,
                        f"{boundary} signal-boundary",
                    )
                )
            current_processes = fixture_process_map()
            leaked = tuple(
                identity
                for identity in identities
                if current_processes.get(identity[0], (0, 0))[1] == identity[1]
            )
            if (
                not boundary_fired
                or not isinstance(caught, FixturePublicFailure)
                or caught.code != expected_code
                or leaked
                or fixture_get_subreaper() != caller_subreaper
                or frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
                != caller_mask
                or any(
                    signal.getsignal(signum) is not handler
                    for signum, handler in caller_handlers.items()
                )
                or fixture_open_descriptor_set() != before_descriptors
            ):
                raise SystemExit(
                    f"dispatch fixture {boundary} async-signal custody drifted: "
                    f"fired={boundary_fired} caught={caught!r} leaked={leaked!r}"
                ) from caught

    timeout_descriptors = fixture_open_descriptor_set()
    original_popen = subprocess.Popen
    original_pidfd_send_signal = signal.pidfd_send_signal
    original_sigmask = signal.pthread_sigmask
    timeout_processes: list[subprocess.Popen[bytes]] = []
    timeout_cleanup_started = False
    timeout_restore_injected = False

    def record_timeout_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        timeout_processes.append(process)
        return process

    def mark_timeout_cleanup(*args, **kwargs):
        nonlocal timeout_cleanup_started
        timeout_cleanup_started = True
        return original_pidfd_send_signal(*args, **kwargs)

    def fail_after_timeout_mask_restore(how, mask):
        nonlocal timeout_restore_injected
        previous = original_sigmask(how, mask)
        if (
            timeout_cleanup_started
            and not timeout_restore_injected
            and how == signal.SIG_SETMASK
            and frozenset(mask) == caller_mask
        ):
            timeout_restore_injected = True
            raise OSError("injected timeout terminal-mask restore failure")
        return previous

    subprocess.Popen = record_timeout_process
    signal.pidfd_send_signal = mark_timeout_cleanup
    signal.pthread_sigmask = fail_after_timeout_mask_restore
    timeout_caught: BaseException | None = None
    try:
        try:
            run(
                "/usr/bin/python3",
                "-c",
                "import time;time.sleep(30)",
                cwd=cwd,
                timeout_seconds=0.05,
            )
        except BaseException as exc:
            timeout_caught = exc
    finally:
        signal.pthread_sigmask = original_sigmask
        signal.pidfd_send_signal = original_pidfd_send_signal
        subprocess.Popen = original_popen
        for process in timeout_processes:
            if process.poll() is None:
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2.0)
                except BaseException:
                    pass
    timeout_notes = getattr(timeout_caught, "__notes__", ())
    if (
        not timeout_cleanup_started
        or not timeout_restore_injected
        or not isinstance(timeout_caught, FixturePublicFailure)
        or str(timeout_caught)
        != "dispatch fixture signal-custody cleanup failed after timeout"
        or not any("timeout occurred first" in note for note in timeout_notes)
        or len(timeout_processes) != 1
        or timeout_processes[0].poll() is None
        or fixture_get_subreaper() != caller_subreaper
        or frozenset(original_sigmask(signal.SIG_BLOCK, set())) != caller_mask
        or any(
            signal.getsignal(signum) is not handler
            for signum, handler in caller_handlers.items()
        )
        or fixture_open_descriptor_set() != timeout_descriptors
    ):
        raise SystemExit(
            "dispatch fixture timeout cleanup-error custody drifted"
        ) from timeout_caught


def _main() -> None:
    global TEST_REF
    if not GATE.is_file():
        raise SystemExit("trusted workflow dispatch gate is missing")
    workflow_source = REAL_WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "run-name: haptics-dispatch-${{ inputs.dispatch_id }}",
        "      dispatch_id:\n",
        "        required: true\n        type: string\n",
        "          INPUT_DISPATCH_ID: ${{ inputs.dispatch_id }}",
        '[[ "$INPUT_DISPATCH_ID" =~ ^[0-9a-f]{32}$ ]]',
    ):
        if required not in workflow_source:
            raise SystemExit(
                f"real workflow lacks the dispatch-identity contract: {required}"
            )
    test_fixture_owner_scope_ast()
    test_direct_fork_custody()
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-dispatch-gate-test.") as raw:
        test_direct_popen_custody(pathlib.Path(raw))
        test_fixture_cleanup_faults(pathlib.Path(raw))
        test_fixture_async_signal_custody(pathlib.Path(raw))
        test_fixture_subprocess_bounds(pathlib.Path(raw))
        repo = pathlib.Path(raw) / "repo"
        state_directory = pathlib.Path(raw) / "state"
        repo.mkdir()
        state_directory.mkdir(mode=0o700)
        (repo / "home").mkdir()
        require_success(run("/usr/bin/git", "init", "-q", cwd=repo), "git init")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / "scripts/ci").mkdir(parents=True)
        (repo / ".github/workflows/build.yml").write_text(
            SAFE_WORKFLOW, encoding="utf-8"
        )
        (repo / "fixture-anchor").write_text("anchor\n", encoding="ascii")
        for relative in VALIDATORS:
            path = repo / relative
            path.write_text(VALIDATOR_SOURCE, encoding="utf-8")
            path.chmod(0o755 if relative == VALIDATORS[0] else 0o644)
        trusted = commit(repo, "trusted gate")
        good = empty_commit(repo, "good candidate")
        TEST_REF = f"codex-dispatch/{good}"
        require_success(
            run(
                "/usr/bin/git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "tag",
                "-a",
                "-m",
                "annotated object fixture",
                "annotated-object-fixture",
                good,
                cwd=repo,
            ),
            "annotated tag fixture",
        )
        tag_object_result = run(
            "/usr/bin/git",
            "rev-parse",
            "annotated-object-fixture^{tag}",
            cwd=repo,
        )
        require_success(tag_object_result, "annotated tag object lookup")
        tag_object = tag_object_result.stdout.strip()
        for label, tag_trusted, tag_candidate in (
            ("trusted", tag_object, good),
            ("candidate", trusted, tag_object),
        ):
            tag_result = run_gate(repo, tag_trusted, tag_candidate)
            if tag_result.returncode == 0:
                raise SystemExit(
                    f"trusted gate accepted an annotated-tag object as {label} commit"
                )
        gate_module = load_gate_module()
        validator_digest = hashlib.sha256(VALIDATOR_SOURCE.encode("utf-8")).hexdigest()
        valid = run_gate(repo, trusted, good)
        require_success(valid, "valid trusted-gate verification")
        expected_verify_output = "".join(
            (
                "schema\ttb321fu.haptics-workflow-gate/v1\n",
                f"trusted-commit\t{trusted}\n",
                f"candidate-commit\t{good}\n",
                f"gate-sha256\t{hashlib.sha256(GATE.read_bytes()).hexdigest()}\n",
                f"workflow-sha256\t{hashlib.sha256(SAFE_WORKFLOW.encode('utf-8')).hexdigest()}\n",
                *(
                    f"validator-sha256\t{relative}\t{validator_digest}\n"
                    for relative in VALIDATORS
                ),
                f"validator-mode\t{gate_module.VALIDATOR_MODE}\n",
                "HAPTICS_WORKFLOW_GATE_VERIFY=PASS\n",
            )
        )
        if valid.stdout != expected_verify_output or valid.stderr:
            raise SystemExit("valid trusted gate evidence transcript is not exact")
        if not hasattr(gate_module, "dispatch_candidate"):
            raise SystemExit("trusted gate remote dispatch boundary is missing")
        test_running_gate_descriptor_close_custody(gate_module)
        test_corrupt_tree_rejected_before_validators(
            gate_module,
            repo,
            trusted,
            good,
            pathlib.Path(raw),
        )
        test_alternate_safe_home_rejected(gate_module, pathlib.Path(raw))
        test_dispatch_state_ancestry_policy(gate_module, pathlib.Path(raw))
        direct_evidence = gate_module.VerificationEvidence(
            trusted,
            hashlib.sha256(GATE.read_bytes()).hexdigest(),
            hashlib.sha256(SAFE_WORKFLOW.encode("utf-8")).hexdigest(),
            tuple(
                (
                    relative,
                    gate_module.REVIEWED_BLOB_MODES[relative],
                    validator_digest,
                )
                for relative in VALIDATORS
            ),
        )

        def expected_dispatch_output(
            dispatch_id: str,
            release_tag_value: str,
            state_path: pathlib.Path,
        ) -> str:
            return "".join(
                (
                    "schema\ttb321fu.haptics-workflow-gate/v1\n",
                    f"trusted-commit\t{trusted}\n",
                    f"candidate-commit\t{good}\n",
                    f"gate-sha256\t{direct_evidence.gate_sha256}\n",
                    f"workflow-sha256\t{direct_evidence.workflow_sha256}\n",
                    *(
                        f"validator-sha256\t{relative}\t{digest}\n"
                        for relative, _mode, digest in direct_evidence.validators
                    ),
                    f"validator-mode\t{gate_module.VALIDATOR_MODE}\n",
                    f"repository\t{TEST_REPOSITORY}\n",
                    f"remote-ref\t{TEST_REF}\n",
                    f"release-tag\t{release_tag_value or '-'}\n",
                    "run-id\t42\n",
                    f"run-display-title\thaptics-dispatch-{dispatch_id}\n",
                    f"run-head-branch\t{TEST_REF}\n",
                    f"run-head-sha\t{good}\n",
                    f"run-url\thttps://github.com/{TEST_REPOSITORY}/actions/runs/42\n",
                    f"dispatch-id\t{dispatch_id}\n",
                    "input-sha256\t"
                    f"{gate_module.dispatch_input_digest(release_tag_value, dispatch_id)}\n",
                    "dispatch-state-sha256\t"
                    f"{hashlib.sha256(state_path.read_bytes()).hexdigest()}\n",
                    "HAPTICS_WORKFLOW_DISPATCH=PASS\n",
                )
            )
        test_main_cleanup_note_diagnostics(gate_module, repo, trusted, good)
        test_dispatch_state_crash_publication(
            gate_module, state_directory, good, direct_evidence
        )
        test_bounded_process_runner(gate_module, pathlib.Path(raw))
        test_process_group_ownership(gate_module, pathlib.Path(raw))
        test_post_popen_cancellation(gate_module, pathlib.Path(raw))
        test_real_gh_bounded_route(gate_module, pathlib.Path(raw))
        test_remote_response_boundaries(gate_module)
        test_real_validators_through_dispatch_main(
            gate_module, pathlib.Path(raw)
        )
        operator_home = pathlib.Path(raw) / "operator-home"
        operator_home.mkdir(mode=0o700)
        operator_state_directory = (
            operator_home / gate_module.DISPATCH_STATE_RELATIVE_DIRECTORY
        )
        operator_state_directory.mkdir(parents=True, mode=0o700)
        test_competing_full_main_dispatches(
            gate_module,
            repo,
            trusted,
            good,
            pathlib.Path(raw),
            expected_dispatch_output,
        )
        main_state = operator_state_directory / f"{good}.diagnostic.tsv"
        release_tag = (
            "tb321fu-haptics-debs-"
            f"{gate_module.CANONICAL_INPUTS['haptics_deb_version']}"
        )
        release_state = operator_state_directory / f"{good}.release.tsv"
        if (
            gate_module.canonical_dispatch_state_path(
                operator_home, good, ""
            )
            != main_state
            or gate_module.canonical_dispatch_state_path(
                operator_home, good, release_tag
            )
            != release_state
        ):
            raise SystemExit("canonical dispatch profiles share or misname their ledgers")
        try:
            gate_module.canonical_dispatch_state_path(
                operator_home,
                good,
                "unreviewed-release",
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "workflow dispatch state identity is not canonical":
                raise SystemExit(
                    f"dispatch profile rejected an invalid tag at wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("dispatch profile accepted an unreviewed release tag")
        test_main_absolute_deadline(
            gate_module,
            repo,
            trusted,
            good,
            main_state,
            operator_home,
        )
        main_fake_gh = FakeGhRunner(good)
        main_output, main_argv = run_dispatch_main(
            gate_module,
            repo,
            trusted,
            good,
            main_state,
            main_fake_gh,
            operator_home,
        )
        expected_main_argv = (
            "--dispatch",
            "--repo-dir",
            str(repo),
            "--trusted-commit",
            trusted,
            "--candidate-commit",
            good,
            "--repository",
            TEST_REPOSITORY,
            "--remote-ref",
            TEST_REF,
            "--release-tag",
            "",
            "--dispatch-state",
            str(main_state),
        )
        if main_argv != expected_main_argv:
            raise SystemExit("production dispatch main used an incomplete argument contract")
        if (
            main_output
            != expected_dispatch_output(
                main_fake_gh.dispatch_id,
                "",
                main_state,
            )
            or main_fake_gh.dispatch_count != 1
            or main_fake_gh.inputs is None
        ):
            raise SystemExit("production dispatch main did not complete exactly one POST")
        alternate_main_home = pathlib.Path(raw) / "alternate-main-home"
        alternate_main_home.mkdir(mode=0o700)
        expect_main_rejected_without_remote_runner(
            gate_module,
            main_argv,
            "workflow dispatch HOME differs from the account database",
            operator_home=alternate_main_home,
            account_home=operator_home,
        )
        local_directory = operator_home / ".local"
        local_mode = local_directory.stat().st_mode & 0o777
        local_directory.chmod(local_mode | 0o020)
        try:
            expect_main_rejected_without_remote_runner(
                gate_module,
                main_argv,
                "workflow dispatch state directory ancestry differs from policy",
                operator_home=operator_home,
            )
        finally:
            local_directory.chmod(local_mode)
        expected_inputs = gate_module.canonical_workflow_inputs(
            "", main_fake_gh.dispatch_id
        )
        if main_fake_gh.inputs != expected_inputs:
            raise SystemExit("production dispatch main sent a noncanonical JSON body")
        expected_json = json.dumps(
            expected_inputs, sort_keys=True, separators=(",", ":")
        )
        expected_first_transcript = (
            (tuple(authenticated_login_arguments()), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
            (tuple(workflow_inventory_arguments(good)), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
            (tuple(workflow_dispatch_arguments()), expected_json),
            (tuple(workflow_inventory_arguments(good)), None),
            (tuple(workflow_run_ownership_arguments(42)), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
        )
        if tuple(main_fake_gh.transcript) != expected_first_transcript:
            raise SystemExit("production dispatch main command transcript is not exact")
        if (
            len(main_fake_gh.deadlines) != len(expected_first_transcript)
            or len(set(main_fake_gh.deadlines)) != 1
            or main_fake_gh.deadlines[0] <= time.monotonic()
        ):
            raise SystemExit("production dispatch main did not share one absolute deadline")
        first_dispatch_id = main_fake_gh.dispatch_id
        previous_token_hex = gate_module.secrets.token_hex
        try:
            gate_module.secrets.token_hex = lambda size: (_ for _ in ()).throw(
                AssertionError("production dispatch replay regenerated its id")
            )
            replay_output, replay_argv = run_dispatch_main(
                gate_module,
                repo,
                trusted,
                good,
                main_state,
                main_fake_gh,
                operator_home,
            )
        finally:
            gate_module.secrets.token_hex = previous_token_hex
        if (
            replay_argv != expected_main_argv
            or replay_output
            != expected_dispatch_output(first_dispatch_id, "", main_state)
            or main_fake_gh.dispatch_count != 1
            or main_fake_gh.dispatch_id != first_dispatch_id
        ):
            raise SystemExit("production dispatch main replay was not exactly-once")
        expected_replay_transcript = (
            (tuple(authenticated_login_arguments()), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
            (tuple(workflow_inventory_arguments(good)), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
            (tuple(workflow_inventory_arguments(good)), None),
            (tuple(workflow_run_ownership_arguments(42)), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
        )
        if tuple(main_fake_gh.transcript) != (
            *expected_first_transcript,
            *expected_replay_transcript,
        ):
            raise SystemExit("production dispatch replay command transcript is not exact")
        replay_deadlines = main_fake_gh.deadlines[len(expected_first_transcript) :]
        if (
            len(replay_deadlines) != len(expected_replay_transcript)
            or len(set(replay_deadlines)) != 1
        ):
            raise SystemExit("production dispatch replay did not share one absolute deadline")
        release_fake_gh = FakeGhRunner(good)
        release_output, release_argv = run_dispatch_main(
            gate_module,
            repo,
            trusted,
            good,
            release_state,
            release_fake_gh,
            operator_home,
            release_tag,
        )
        if (
            release_output
            != expected_dispatch_output(
                release_fake_gh.dispatch_id,
                release_tag,
                release_state,
            )
            or release_fake_gh.dispatch_count != 1
            or release_fake_gh.inputs is None
            or release_fake_gh.inputs.get("release_tag") != release_tag
            or release_argv[-4:] != (
                "--release-tag",
                release_tag,
                "--dispatch-state",
                str(release_state),
            )
            or not main_state.is_file()
            or not release_state.is_file()
        ):
            raise SystemExit("diagnostic and release dispatch profiles did not stay independent")
        release_replay, _ = run_dispatch_main(
            gate_module,
            repo,
            trusted,
            good,
            release_state,
            release_fake_gh,
            operator_home,
            release_tag,
        )
        expected_release_output = expected_dispatch_output(
            release_fake_gh.dispatch_id,
            release_tag,
            release_state,
        )
        release_inputs = gate_module.canonical_workflow_inputs(
            release_tag, release_fake_gh.dispatch_id
        )
        release_json = json.dumps(
            release_inputs,
            sort_keys=True,
            separators=(",", ":"),
        )
        expected_release_first_transcript = (
            (tuple(authenticated_login_arguments()), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
            (tuple(workflow_inventory_arguments(good)), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
            (tuple(workflow_dispatch_arguments()), release_json),
            (tuple(workflow_inventory_arguments(good)), None),
            (tuple(workflow_run_ownership_arguments(42)), None),
            (tuple(remote_ref_arguments()), None),
            (tuple(branch_protection_arguments()), None),
        )
        if (
            release_replay != expected_release_output
            or release_fake_gh.dispatch_count != 1
            or tuple(release_fake_gh.transcript)
            != (*expected_release_first_transcript, *expected_replay_transcript)
        ):
            raise SystemExit("release-profile replay performed a second POST")
        expect_main_rejected_without_remote_runner(
            gate_module,
            expected_main_argv[:-2],
            "remote dispatch requires a private dispatch state path",
        )
        expect_main_rejected_without_remote_runner(
            gate_module,
            (
                "--verify-only",
                "--repo-dir",
                str(repo),
                "--trusted-commit",
                trusted,
                "--candidate-commit",
                good,
                "--dispatch-state",
                str(main_state),
            ),
            "verify-only mode does not accept a dispatch state path",
        )
        relative_state_argv = (*expected_main_argv[:-1], "relative-state.tsv")
        expect_main_rejected_without_remote_runner(
            gate_module,
            relative_state_argv,
            "workflow dispatch state path is not canonical",
        )
        alternate_state_argv = (
            *expected_main_argv[:-1],
            str(state_directory / "alternate.tsv"),
        )
        expect_main_rejected_without_remote_runner(
            gate_module,
            alternate_state_argv,
            "workflow dispatch state path is not the unique candidate ledger",
            operator_home=operator_home,
        )
        no_remote_calls = 0

        def forbidden_remote(*args, **kwargs):
            nonlocal no_remote_calls
            del args, kwargs
            no_remote_calls += 1
            raise AssertionError("non-unique ref reached the remote boundary")

        try:
            gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                "codex-dispatch/not-the-candidate",
                good,
                "",
                state_directory / "non-unique-ref.tsv",
                forbidden_remote,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "remote workflow ref is not the unique candidate dispatch branch":
                raise SystemExit(
                    f"trusted gate rejected a non-unique ref at wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("trusted gate accepted a non-unique dispatch ref")
        if no_remote_calls:
            raise SystemExit("trusted gate queried GitHub for a non-unique dispatch ref")

        unlocked_gh = FakeGhRunner(good, locked_branch=False)
        unlocked_state = state_directory / "unlocked.tsv"
        try:
            gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                TEST_REF,
                good,
                "",
                unlocked_state,
                unlocked_gh,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != (
                "remote dispatch branch is not locked against updates and deletion"
            ):
                raise SystemExit(
                    f"trusted gate rejected unlocked ref at wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("trusted gate accepted an unlocked dispatch branch")
        if unlocked_gh.dispatch_count or unlocked_state.exists():
            raise SystemExit("unlocked dispatch branch crossed a durable/POST boundary")

        remote_race_cases = (
            (
                "fork-sync",
                {"allow_fork_syncing": True},
                "remote dispatch branch is not locked against updates and deletion",
                0,
            ),
            (
                "pre-post-movement",
                {"move_ref_on_query": 2},
                "remote ref changed immediately before workflow dispatch",
                0,
            ),
            (
                "movement-during-post",
                {"move_ref_on_dispatch": True},
                "remote ref changed during workflow dispatch",
                1,
            ),
            (
                "movement-after-post",
                {"move_ref_on_inventory_after_dispatch": True},
                "remote ref changed during workflow dispatch",
                1,
            ),
            (
                "final-unlock",
                {"unlock_on_protection_query": 3},
                "remote dispatch branch is not locked against updates and deletion",
                1,
            ),
        )
        for label, options, expected_error, expected_posts in remote_race_cases:
            race_gh = FakeGhRunner(good, **options)
            race_state = state_directory / f"remote-{label}.tsv"
            try:
                gate_module.dispatch_candidate(
                    TEST_REPOSITORY,
                    TEST_REF,
                    good,
                    "",
                    race_state,
                    race_gh,
                    evidence=direct_evidence,
                    dispatch_id_factory=lambda: TEST_DISPATCH_ID,
                )
            except gate_module.WorkflowGateError as exc:
                if str(exc) != expected_error:
                    raise SystemExit(
                        f"remote {label} failed at the wrong boundary: {exc}"
                    ) from exc
            else:
                raise SystemExit(f"remote {label} was accepted")
            if race_gh.dispatch_count != expected_posts:
                raise SystemExit(
                    f"remote {label} performed {race_gh.dispatch_count} POSTs"
                )
            if expected_posts == 0 and race_state.exists():
                raise SystemExit(
                    f"remote {label} left a durable no-POST reservation"
                )
            if expected_posts == 1 and not race_state.exists():
                raise SystemExit(
                    f"remote {label} lost its applied-POST reconciliation state"
                )
            if race_state.exists():
                race_state.unlink()
            for residue in state_directory.glob(f".{race_state.name}.*.tmp"):
                residue.unlink()

        fake_gh = FakeGhRunner(good)
        dispatched = gate_module.dispatch_candidate(
            TEST_REPOSITORY,
            TEST_REF,
            good,
            "",
            state_directory / "happy.tsv",
            fake_gh,
            evidence=direct_evidence,
            dispatch_id_factory=lambda: TEST_DISPATCH_ID,
        )
        if (
            dispatched.run_id != 42
            or dispatched.display_title
            != f"haptics-dispatch-{TEST_DISPATCH_ID}"
            or dispatched.head_branch != TEST_REF
            or dispatched.head_sha != good
        ):
            raise SystemExit("trusted gate did not bind the newly dispatched run")
        if fake_gh.inputs is None or fake_gh.inputs.get("release_tag") != "":
            raise SystemExit("trusted gate did not send the exact diagnostic inputs")
        for label, options in (
            ("preexisting different title", {"preexisting_same_sha": True}),
            (
                "preexisting matching title",
                {"preexisting_matching_title": True},
            ),
        ):
            inventory_gh = FakeGhRunner(good, **options)
            inventory_state = state_directory / (
                "inventory-" + label.replace(" ", "-") + ".tsv"
            )
            inventory_result = gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                TEST_REF,
                good,
                "",
                inventory_state,
                inventory_gh,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
            if inventory_result.run_id != 42 or inventory_gh.dispatch_count != 1:
                raise SystemExit(
                    f"dispatch did not exclude {label} from the new run set"
                )

        competitor_gh = FakeGhRunner(good, competing_after_dispatch=True)
        competitor_state = state_directory / "competing-same-sha-run.tsv"
        competitor_result = gate_module.dispatch_candidate(
            TEST_REPOSITORY,
            TEST_REF,
            good,
            "",
            competitor_state,
            competitor_gh,
            evidence=direct_evidence,
            dispatch_id_factory=lambda: TEST_DISPATCH_ID,
        )
        replayed_competitor = gate_module.dispatch_candidate(
            TEST_REPOSITORY,
            TEST_REF,
            good,
            "",
            competitor_state,
            competitor_gh,
            evidence=direct_evidence,
            dispatch_id_factory=lambda: (_ for _ in ()).throw(
                AssertionError("competing replay regenerated its id")
            ),
        )
        if (
            competitor_result.run_id != 42
            or replayed_competitor.run_id != 42
            or competitor_gh.dispatch_count != 1
        ):
            raise SystemExit("same-SHA competitor changed exactly-once replay")

        ambiguous_gh = FakeGhRunner(
            good, duplicate_matching_after_dispatch=True
        )
        ambiguous_state = state_directory / "ambiguous-same-title.tsv"
        try:
            gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                TEST_REF,
                good,
                "",
                ambiguous_state,
                ambiguous_gh,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "workflow dispatch produced an ambiguous run set":
                raise SystemExit(
                    f"ambiguous same-title runs failed at wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("dispatch accepted two new same-title runs")
        if ambiguous_gh.dispatch_count != 1:
            raise SystemExit("ambiguous same-title fixture changed POST count")
        wrong_branch_gh = FakeGhRunner(good, run_branch="codex/foreign-branch")
        try:
            gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                TEST_REF,
                good,
                "",
                state_directory / "wrong-branch.tsv",
                wrong_branch_gh,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
        except gate_module.WorkflowGateError as exc:
            if str(exc) != "workflow dispatch produced a run on an unexpected branch":
                raise SystemExit(
                    f"trusted gate rejected a foreign-branch run at the wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("trusted gate accepted a same-SHA run from another branch")
        applied_failure_gh = FakeGhRunner(good, fail_after_dispatch=True)
        applied_failure_state = state_directory / "applied-failure.tsv"
        try:
            gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                TEST_REF,
                good,
                "",
                applied_failure_state,
                applied_failure_gh,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
        except gate_module.WorkflowGateError as exc:
            expected = (
                "workflow dispatch failed; refusing to reconcile an unowned run: "
                "workflow dispatch failed: simulated applied transport failure"
            )
            if str(exc) != expected:
                raise SystemExit(
                    f"applied dispatch failure escaped at the wrong boundary: {exc}"
                ) from exc
        else:
            raise SystemExit("trusted gate reconciled a dispatch after a nonzero POST")
        if applied_failure_gh.dispatch_count != 1:
            raise SystemExit("trusted gate retried a failed dispatch POST")
        dispatch_positions = [
            index
            for index, (arguments, _input) in enumerate(applied_failure_gh.transcript)
            if arguments[1:3] == ("workflow", "run")
        ]
        if len(dispatch_positions) != 1 or any(
            arguments[1:3] == ("run", "list")
            for arguments, _input in applied_failure_gh.transcript[dispatch_positions[0] + 1 :]
        ):
            raise SystemExit(
                "trusted gate queried workflow runs after a nonzero dispatch POST"
            )
        replayed_after_failure = gate_module.dispatch_candidate(
            TEST_REPOSITORY,
            TEST_REF,
            good,
            "",
            applied_failure_state,
            applied_failure_gh,
            evidence=direct_evidence,
            dispatch_id_factory=lambda: (_ for _ in ()).throw(
                AssertionError("failed-POST replay regenerated its dispatch id")
            ),
        )
        if (
            replayed_after_failure.run_id != 42
            or applied_failure_gh.dispatch_count != 1
        ):
            raise SystemExit(
                "failed-POST replay did not use the authenticated run attestation"
            )

        for label, ownership_options in (
            ("actor", {"actor_login": "different-user"}),
            (
                "triggering actor",
                {"triggering_actor_login": "different-user"},
            ),
            ("run repository", {"run_repository": "GUF296/other-repository"}),
            (
                "head repository",
                {"run_head_repository": "GUF296/other-repository"},
            ),
        ):
            forged_gh = FakeGhRunner(
                good,
                fail_after_dispatch=True,
                **ownership_options,
            )
            forged_state = state_directory / f"failed-post-{label.replace(' ', '-')}.tsv"
            try:
                gate_module.dispatch_candidate(
                    TEST_REPOSITORY,
                    TEST_REF,
                    good,
                    "",
                    forged_state,
                    forged_gh,
                    evidence=direct_evidence,
                    dispatch_id_factory=lambda: TEST_DISPATCH_ID,
                )
            except gate_module.WorkflowGateError as exc:
                if not str(exc).startswith(
                    "workflow dispatch failed; refusing to reconcile an unowned run:"
                ):
                    raise SystemExit(
                        f"{label} failed-POST fixture crossed the wrong first boundary: {exc}"
                    ) from exc
            else:
                raise SystemExit(f"{label} failed-POST fixture unexpectedly succeeded")
            try:
                gate_module.dispatch_candidate(
                    TEST_REPOSITORY,
                    TEST_REF,
                    good,
                    "",
                    forged_state,
                    forged_gh,
                    evidence=direct_evidence,
                    dispatch_id_factory=lambda: (_ for _ in ()).throw(
                        AssertionError(f"{label} replay regenerated its dispatch id")
                    ),
                )
            except gate_module.WorkflowGateError as exc:
                if str(exc) != "workflow-run ownership details do not prove this dispatch":
                    raise SystemExit(
                        f"{label} failed-POST replay failed at the wrong boundary: {exc}"
                    ) from exc
            else:
                raise SystemExit(f"{label} forged failed-POST replay was accepted")
            if forged_gh.dispatch_count != 1:
                raise SystemExit(f"{label} failed-POST replay issued a second POST")

        interrupted_gh = FakeGhRunner(
            good, fail_inventory_after_dispatch_once=True
        )
        interrupted_state = state_directory / "interrupted.tsv"
        try:
            gate_module.dispatch_candidate(
                TEST_REPOSITORY,
                TEST_REF,
                good,
                "",
                interrupted_state,
                interrupted_gh,
                evidence=direct_evidence,
                dispatch_id_factory=lambda: TEST_DISPATCH_ID,
            )
        except gate_module.WorkflowGateError as exc:
            expected = (
                "workflow-run inventory failed: "
                "simulated post-dispatch inventory failure"
            )
            if str(exc) != expected:
                raise SystemExit(
                    f"trusted gate exposed the wrong interrupted-dispatch error: {exc}"
                ) from exc
        else:
            raise SystemExit("trusted gate did not expose the injected inventory failure")
        resumed = gate_module.dispatch_candidate(
            TEST_REPOSITORY,
            TEST_REF,
            good,
            "",
            interrupted_state,
            interrupted_gh,
            evidence=direct_evidence,
            dispatch_id_factory=lambda: (_ for _ in ()).throw(
                AssertionError("dispatch replay regenerated its id")
            ),
        )
        if resumed.run_id != 42 or interrupted_gh.dispatch_count != 1:
            raise SystemExit("trusted gate reposted an ambiguously applied dispatch")

        (repo / ".github/workflows/build.yml").write_text(
            SAFE_WORKFLOW + "# exit 0\n", encoding="utf-8"
        )
        hostile = commit(repo, "hostile workflow")
        test_candidate_relation(
            gate_module,
            repo,
            trusted,
            good,
            tree_id(repo, hostile),
        )
        rejected = run_gate(repo, trusted, hostile)
        if rejected.returncode == 0:
            raise SystemExit("trusted gate accepted a candidate workflow bypass")

        workflow_path = repo / ".github/workflows/build.yml"
        workflow_path.unlink()
        workflow_path.symlink_to(SAFE_WORKFLOW)
        symlink_workflow = commit(repo, "symlink workflow mode confusion")
        symlink_result = run_gate(repo, trusted, symlink_workflow)
        if symlink_result.returncode == 0:
            raise SystemExit("trusted gate accepted a workflow symlink blob")

        def require_mode_or_size_rejected(
            trusted_value: str,
            candidate_value: str,
            label: str,
        ) -> None:
            result = run_gate(repo, trusted_value, candidate_value)
            if result.returncode == 0:
                raise SystemExit(f"trusted gate accepted hostile blob policy: {label}")

        workflow_path.unlink()
        workflow_path.write_text(SAFE_WORKFLOW, encoding="utf-8")
        workflow_path.chmod(0o755)
        executable_workflow = commit(repo, "executable workflow mode")
        require_mode_or_size_rejected(
            trusted, executable_workflow, "executable workflow"
        )
        workflow_path.chmod(0o644)

        boundary_path = repo / VALIDATORS[0]
        isolation_path = repo / VALIDATORS[1]
        boundary_path.chmod(0o644)
        boundary_mode = commit(repo, "boundary validator mode drift")
        require_mode_or_size_rejected(
            boundary_mode, boundary_mode, "boundary validator mode"
        )
        boundary_path.chmod(0o755)
        isolation_path.chmod(0o755)
        isolation_mode = commit(repo, "isolation validator mode drift")
        require_mode_or_size_rejected(
            isolation_mode, isolation_mode, "isolation validator mode"
        )
        isolation_path.chmod(0o644)

        boundary_path.unlink()
        missing_validator = commit(repo, "missing trusted validator")
        require_mode_or_size_rejected(
            missing_validator, missing_validator, "missing validator"
        )
        boundary_path.write_text(VALIDATOR_SOURCE, encoding="utf-8")
        boundary_path.chmod(0o755)
        boundary_path.write_bytes(b"")
        empty_validator = commit(repo, "empty trusted validator")
        require_mode_or_size_rejected(
            empty_validator, empty_validator, "empty validator"
        )
        boundary_path.write_bytes(
            b"x" * (gate_module.MAX_VALIDATOR_BYTES + 1)
        )
        boundary_path.chmod(0o755)
        oversized_validator = commit(repo, "oversized trusted validator")
        require_mode_or_size_rejected(
            oversized_validator, oversized_validator, "oversized validator"
        )
        boundary_path.write_text(VALIDATOR_SOURCE, encoding="utf-8")
        boundary_path.chmod(0o755)
        restored_trusted = commit(repo, "restore trusted validators")

        workflow_path.unlink()
        missing_workflow = commit(repo, "missing candidate workflow")
        require_mode_or_size_rejected(
            restored_trusted, missing_workflow, "missing workflow"
        )
        workflow_path.write_bytes(b"")
        workflow_path.chmod(0o644)
        empty_workflow = commit(repo, "empty candidate workflow")
        require_mode_or_size_rejected(
            restored_trusted, empty_workflow, "empty workflow"
        )
        workflow_path.write_bytes(b"x" * (gate_module.MAX_WORKFLOW_BYTES + 1))
        workflow_path.chmod(0o644)
        oversized_workflow = commit(repo, "oversized candidate workflow")
        require_mode_or_size_rejected(
            restored_trusted, oversized_workflow, "oversized workflow"
        )

        corrupt_commit_candidate = commit_tree(
            repo,
            tree_id(repo, oversized_workflow),
            (oversized_workflow,),
            "corrupt commit object fixture",
        )
        loose_commit = (
            repo
            / ".git/objects"
            / corrupt_commit_candidate[:2]
            / corrupt_commit_candidate[2:]
        )
        if not loose_commit.is_file():
            raise SystemExit("corrupt-commit fixture object is not loose")
        commit_object = zlib.decompress(loose_commit.read_bytes())
        corrupted_commit_object = commit_object.replace(
            b"corrupt commit object fixture",
            b"Corrupt commit object fixture",
            1,
        )
        if (
            corrupted_commit_object == commit_object
            or len(corrupted_commit_object) != len(commit_object)
        ):
            raise SystemExit("corrupt-commit fixture did not preserve object size")
        loose_commit.chmod(0o600)
        loose_commit.write_bytes(zlib.compress(corrupted_commit_object))
        corrupt_commit_result = run_gate(
            repo,
            trusted,
            corrupt_commit_candidate,
        )
        if (
            corrupt_commit_result.returncode == 0
            or "candidate commit bytes differ from their object id"
            not in corrupt_commit_result.stderr
        ):
            raise SystemExit("trusted gate accepted corrupt commit-object bytes")

        workflow_path.write_text(
            SAFE_WORKFLOW + "# remotely hostile exit 0\n",
            encoding="utf-8",
        )
        corrupt_candidate = commit(repo, "corrupt local object fixture")
        corrupt_oid_result = run(
            "/usr/bin/git",
            "rev-parse",
            f"{corrupt_candidate}:.github/workflows/build.yml",
            cwd=repo,
        )
        require_success(corrupt_oid_result, "corrupt blob object lookup")
        corrupt_oid = corrupt_oid_result.stdout.strip()
        safe_raw = SAFE_WORKFLOW.encode("utf-8")
        replacement_object = (
            b"blob " + str(len(safe_raw)).encode("ascii") + b"\0" + safe_raw
        )
        replacement_oid = hashlib.sha1(replacement_object).hexdigest()
        if replacement_oid == corrupt_oid:
            raise SystemExit("corrupt-object fixture did not change the blob identity")
        loose_object = repo / ".git/objects" / corrupt_oid[:2] / corrupt_oid[2:]
        if not loose_object.is_file():
            raise SystemExit("corrupt-object fixture blob is not loose")
        loose_object.chmod(0o600)
        loose_object.write_bytes(zlib.compress(replacement_object))
        corrupt_result = run_gate(repo, trusted, corrupt_candidate)
        if corrupt_result.returncode == 0:
            raise SystemExit("trusted gate accepted a blob whose bytes mismatch its object id")

    print("HAPTICS_WORKFLOW_DISPATCH_GATE_FIXTURE=PASS")


def main() -> None:
    test_fixture_owner_finalizer_cancellation(pathlib.Path.cwd())
    test_fixture_owner_fairness_and_capacity()
    _main()


if __name__ == "__main__":
    main()
