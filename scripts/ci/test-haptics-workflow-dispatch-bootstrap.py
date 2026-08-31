#!/usr/bin/env python3
"""Synthetic P/C and poisoning fixtures for the external dispatch bootstrap."""

from __future__ import annotations

import ast
import argparse
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import contextlib
import io
import os
import pathlib
import pwd
import resource
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zlib


_ORIGINAL_SCANDIR = os.scandir


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
RENDERER = SCRIPT_DIR / "render-haptics-workflow-dispatch-bootstrap.py"
TEMPLATE = SCRIPT_DIR / "haptics-workflow-dispatch-bootstrap.py.in"
GATE_PATH = pathlib.Path("scripts/ci/dispatch-haptics-workflow.py")
WORKFLOW_PATH = pathlib.Path(".github/workflows/build.yml")
BOUNDARY_PATH = pathlib.Path("scripts/ci/check-workflow-input-boundaries.py")
ISOLATION_PATH = pathlib.Path("scripts/ci/test-haptics-release-job-isolation.py")
MAX_OUTPUT = 1024 * 1024
FIXTURE_FILE_LIMIT = 2 * 1024 * 1024
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
RENDERED_LAUNCHER_DIGESTS: dict[pathlib.Path, str] = {}


class FixtureCleanupError(Exception):
    """Internal fixture containment failure, never caller cancellation."""


def fixture_register_owner(owner) -> None:
    if not _FIXTURE_OWNER_SCOPES:
        raise FixtureCleanupError(
            "bootstrap fixture owner was created outside a lifetime scope"
        )
    scope = _FIXTURE_OWNER_SCOPES[-1]
    if len(scope) >= FIXTURE_OWNER_LIMIT:
        raise FixtureCleanupError("bootstrap fixture owner scope exceeds its bound")
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


class FixtureOwnerBodySignal(BaseException):
    """Private one-shot control transfer from an owner body to its finalizer."""

    def __init__(
        self,
        signum: int,
        caller_policy: BaseException | None,
    ) -> None:
        super().__init__(f"fixture owner body received signal {signum}")
        self.signum = signum
        self.caller_policy = caller_policy


def fixture_owner_scoped(function):
    def scoped(*args, **kwargs):
        with fixture_owner_lifetime(function.__name__):
            return function(*args, **kwargs)

    return scoped


def test_fixture_owner_scope_ast() -> None:
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    owner_calls = frozenset(
        {
            "FixtureDescriptorOwner",
            "FixtureChildOwner",
            "FixturePopenOwner",
            "acquire_existing_fixture_descriptor",
            "open_owned_fixture_pidfd",
            "spawn_fixture_child",
            "spawn_fixture_popen",
            "_fixture_local_descriptor_owner",
        }
    )
    raw_primitives = frozenset(
        {
            ("os", "fork"),
            ("os", "pidfd_open"),
            ("subprocess", "Popen"),
        }
    )
    raw_wrapper_allowlist = {
        ("os", "fork"): frozenset({"spawn_fixture_child"}),
        ("os", "pidfd_open"): frozenset({"open_owned_fixture_pidfd"}),
        ("subprocess", "Popen"): frozenset(
            {"spawn_fixture_popen", "fixture_run_process"}
        ),
    }
    raw_alias_allowlist = frozenset(
        {
            ("test_direct_spawn_handoffs", "original_fork", "os.fork"),
            ("test_direct_spawn_handoffs", "original_pidfd_open", "os.pidfd_open"),
            ("test_direct_spawn_handoffs", "original_popen", "subprocess.Popen"),
            ("test_fixture_cleanup_faults", "original_pidfd_open", "os.pidfd_open"),
            ("test_fixture_cleanup_faults", "original_popen", "subprocess.Popen"),
            ("test_fixture_cleanup_faults", "sigchld_popen_original", "subprocess.Popen"),
            ("test_launcher_production_primitives", "original_pidfd_open", "os.pidfd_open"),
            ("test_fixture_async_signal_custody", "original_popen", "subprocess.Popen"),
        }
    )
    raw_alias_call_allowlist = frozenset(
        {
            ("test_direct_spawn_handoffs", "popen_then_cancel", "original_popen"),
            ("test_direct_spawn_handoffs", "fork_then_cancel", "original_fork"),
            ("test_direct_spawn_handoffs", "pidfd_then_cancel", "original_pidfd_open"),
            ("test_direct_spawn_handoffs", "record_validation_pidfd", "original_pidfd_open"),
            ("test_direct_spawn_handoffs", "cancel_snapshot_pidfd", "original_pidfd_open"),
            ("test_fixture_cleanup_faults", "count_sigchld_popen", "sigchld_popen_original"),
            ("test_fixture_cleanup_faults", "record_helper_pidfd", "original_pidfd_open"),
            ("test_fixture_cleanup_faults", "recording_popen", "original_popen"),
            ("test_fixture_cleanup_faults", "record_cancellation_process", "original_popen"),
            ("test_fixture_cleanup_faults", "fail_first_root_poll", "original_popen"),
            ("test_fixture_cleanup_faults", "record_priority_process", "original_popen"),
            ("test_fixture_cleanup_faults", "count_assignment_popen", "original_popen"),
            ("test_fixture_cleanup_faults", "record_timeout_process", "original_popen"),
            ("test_fixture_cleanup_faults", "count_setup_popen", "original_popen"),
            ("test_launcher_production_primitives", "record_root_pidfd", "original_pidfd_open"),
            ("test_fixture_async_signal_custody", "signal_at_boundary", "original_popen"),
            ("test_fixture_async_signal_custody", "record_timeout_process", "original_popen"),
        }
    )
    dynamic_reference_allowlist = frozenset(
        {
            (
                "test_fixture_owner_fairness_and_capacity",
                "original_acquire",
                "acquire_existing_fixture_descriptor",
            ),
            (
                "test_direct_spawn_handoffs",
                "original_owned_pidfd",
                "open_owned_fixture_pidfd",
            ),
            (
                "test_fixture_cleanup_faults",
                "original_owned_pidfd",
                "open_owned_fixture_pidfd",
            ),
        }
    )
    nested_owner_allowlist = frozenset(
        {
            ("test_renderer_custody", "mutate_same_inode_after_output_close"),
            ("test_renderer_custody", "replace_parent_after_primary_close"),
            ("test_fixture_owner_finalizer_cancellation", "run_case"),
            ("test_launcher_process_containment", "signal_before_popen_return"),
            ("test_launcher_process_containment", "signal_before_failed_killpg"),
            ("test_launcher_process_containment", "signal_before_missing_root_pidfd"),
        }
    )

    def validate(candidate: str, label: str) -> None:
        tree = ast.parse(candidate, filename=label)
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        def ancestors(node):
            while node in parents:
                node = parents[node]
                yield node

        def enclosing_functions(node) -> list[ast.AST]:
            return [
                ancestor
                for ancestor in ancestors(node)
                if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]

        def top_function_name(node) -> str | None:
            functions = enclosing_functions(node)
            return functions[-1].name if functions else None

        def canonical_raw_attribute(node) -> tuple[str, str] | None:
            if not isinstance(node, ast.Attribute) or not isinstance(
                node.value, ast.Name
            ):
                return None
            module_name = module_aliases.get(node.value.id)
            if module_name is None:
                return None
            candidate_primitive = (module_name, node.attr)
            return (
                candidate_primitive
                if candidate_primitive in raw_primitives
                else None
            )

        def contains_dynamic_owner(node) -> bool:
            return any(
                isinstance(candidate_node, ast.Constant)
                and candidate_node.value in owner_calls
                for candidate_node in ast.walk(node)
            )

        top_level_functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        module_aliases = {"os": "os", "subprocess": "subprocess"}
        imported_primitive_aliases: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    if imported.name in module_aliases:
                        local_name = imported.asname or imported.name
                        module_aliases[local_name] = imported.name
            elif isinstance(node, ast.ImportFrom):
                for imported in node.names:
                    if imported.name in owner_calls:
                        raise SystemExit(
                            "bootstrap owner import alias is forbidden: "
                            f"{label}:{node.lineno}"
                        )
                    primitive = (node.module or "", imported.name)
                    if primitive in raw_primitives:
                        imported_primitive_aliases[
                            imported.asname or imported.name
                        ] = primitive

        raw_aliases: dict[tuple[str | None, str], tuple[str, str]] = {}
        for node in ast.walk(tree):
            if top_function_name(node) in {
                "test_fixture_owner_scope_ast",
                "_fixture_local_descriptor_owner",
            }:
                continue
            value = None
            target = None
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                target = node.targets[0].id
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target = node.target.id
                value = node.value
            elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                target = node.target.id
                value = node.value
            if target is None or value is None:
                continue
            if isinstance(value, ast.Name) and value.id in owner_calls:
                raise SystemExit(
                    f"bootstrap owner alias is forbidden: {label}:{node.lineno}"
                )
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in owner_calls
            ):
                continue
            if contains_dynamic_owner(value):
                dynamic_names = {
                    candidate_node.value
                    for candidate_node in ast.walk(value)
                    if isinstance(candidate_node, ast.Constant)
                    and candidate_node.value in owner_calls
                }
                if (
                    len(dynamic_names) != 1
                    or (
                        top_function_name(node),
                        target,
                        next(iter(dynamic_names)),
                    )
                    not in dynamic_reference_allowlist
                ):
                    raise SystemExit(
                        "bootstrap dynamic owner acquisition is forbidden: "
                        f"{label}:{node.lineno}"
                    )
            primitive = canonical_raw_attribute(value)
            if primitive is None:
                continue
            owner_name = top_function_name(node)
            primitive_name = ".".join(primitive)
            if (owner_name, target, primitive_name) not in raw_alias_allowlist:
                raise SystemExit(
                    "bootstrap raw primitive alias escaped its allowlist: "
                    f"{label}:{node.lineno}"
                )
            raw_aliases[(owner_name, target)] = primitive

        raw_resource_functions: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if top_function_name(node) == "test_fixture_owner_scope_ast":
                continue
            function_ancestors = enclosing_functions(node)
            owner_name = top_function_name(node)
            class_or_lambda = any(
                isinstance(ancestor, (ast.ClassDef, ast.Lambda))
                for ancestor in ancestors(node)
            )
            if isinstance(node.func, ast.Name) and node.func.id in owner_calls:
                if class_or_lambda:
                    raise SystemExit(
                        "bootstrap class/lambda owner acquisition is forbidden: "
                        f"{label}:{node.lineno}"
                    )
                if len(function_ancestors) > 1:
                    nested_name = function_ancestors[0].name
                    if (owner_name, nested_name) not in nested_owner_allowlist:
                        raise SystemExit(
                            "bootstrap nested owner acquisition escaped its allowlist: "
                            f"{label}:{node.lineno}"
                        )
            elif isinstance(node.func, ast.Attribute) and node.func.attr in owner_calls:
                raise SystemExit(
                    "bootstrap attribute owner acquisition is forbidden: "
                    f"{label}:{node.lineno}"
                )
            elif isinstance(node.func, (ast.Call, ast.Subscript)) and contains_dynamic_owner(
                node.func
            ):
                raise SystemExit(
                    "bootstrap dynamic owner call is forbidden: "
                    f"{label}:{node.lineno}"
                )

            primitive = canonical_raw_attribute(node.func)
            if primitive is not None:
                if node.func.value.id != primitive[0]:
                    raise SystemExit(
                        "bootstrap module import alias is forbidden: "
                        f"{label}:{node.lineno}"
                    )
                if owner_name not in raw_wrapper_allowlist[primitive]:
                    raise SystemExit(
                        "bootstrap raw primitive escaped its wrapper allowlist: "
                        f"{label}:{node.lineno}"
                    )
                raw_resource_functions.add(owner_name)
            elif isinstance(node.func, ast.Name):
                if node.func.id in imported_primitive_aliases:
                    raise SystemExit(
                        "bootstrap imported primitive alias is forbidden: "
                        f"{label}:{node.lineno}"
                    )
                alias_primitive = raw_aliases.get((owner_name, node.func.id))
                if alias_primitive is not None:
                    immediate_function = (
                        function_ancestors[0].name
                        if function_ancestors
                        else None
                    )
                    if (
                        owner_name,
                        immediate_function,
                        node.func.id,
                    ) not in raw_alias_call_allowlist:
                        raise SystemExit(
                            "bootstrap raw primitive alias call escaped its allowlist: "
                            f"{label}:{node.lineno}"
                        )
                    raw_resource_functions.add(owner_name)

            if isinstance(node.func, ast.Name):
                if node.func.id == "spawn_fixture_child" and len(node.args) < 3:
                    raise SystemExit(
                        "bootstrap fixture child spawn lacks caller owner: "
                        f"{label}:{node.lineno}"
                    )
                if node.func.id == "spawn_fixture_popen" and len(node.args) < 2:
                    raise SystemExit(
                        "bootstrap fixture Popen spawn lacks caller owner: "
                        f"{label}:{node.lineno}"
                    )

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
            if name in raw_resource_functions
            or any(
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

        local_owner_callers = {
            "settle_fixture_child_owner",
            "settle_fixture_popen_owner",
            "fixture_cleanup_descendants",
            "fixture_run_process",
            "run_pinned_launcher",
        }
        for name, function in top_level_functions.items():
            if any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_fixture_local_descriptor_owner"
                for node in ast.walk(function)
            ) and name not in local_owner_callers:
                raise SystemExit(
                    "bootstrap local owner factory escaped its allowlist: "
                    f"{name}"
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
                    "bootstrap async owner-bearing test requires an async lifetime"
                )
            if uses_owner and any(
                isinstance(node, (ast.Yield, ast.YieldFrom))
                for node in ast.walk(function)
            ):
                raise SystemExit(
                    "bootstrap deferred owner-bearing test is not permitted"
                )
            decorated = any(
                isinstance(decorator, ast.Name)
                and decorator.id == "fixture_owner_scoped"
                for decorator in function.decorator_list
            )
            explicit_scope = any(
                isinstance(node, ast.With)
                and enclosing_functions(node) == [function]
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
                    "bootstrap fixture owner-bearing test lacks lifetime scope: "
                    f"{function.name}"
                )

    validate(source, __file__)
    mutations = {
        "raw-fork": "def test_ast_mutant_raw_fork():\n    os.fork()\n",
        "raw-popen": "def test_ast_mutant_raw_popen():\n    subprocess.Popen(['/bin/true'])\n",
        "raw-pidfd": "def test_ast_mutant_raw_pidfd():\n    os.pidfd_open(1, 0)\n",
        "owner-alias": "OwnerAlias = FixtureDescriptorOwner\ndef test_ast_mutant_owner_alias():\n    OwnerAlias()\n",
        "module-import-alias": "import os as escaped_os\ndef test_ast_mutant_module_alias():\n    escaped_os.fork()\n",
        "primitive-import-alias": "from os import fork as escaped_fork\ndef test_ast_mutant_import_alias():\n    escaped_fork()\n",
        "getattr-owner": "def test_ast_mutant_getattr():\n    getattr(sys.modules[__name__], 'FixtureDescriptorOwner')()\n",
        "globals-owner": "def test_ast_mutant_globals():\n    globals()['FixtureDescriptorOwner']()\n",
        "nested-owner": "def test_ast_mutant_nested():\n    def acquire():\n        return FixtureDescriptorOwner()\n    acquire()\n",
        "method-owner": "class AstMutantFactory:\n    def acquire(self):\n        return FixtureDescriptorOwner()\n",
        "lambda-owner": "def test_ast_mutant_lambda():\n    acquire = lambda: FixtureDescriptorOwner()\n    acquire()\n",
        "attribute-owner": "def test_ast_mutant_attribute(holder):\n    holder.FixtureDescriptorOwner()\n",
    }
    for label, mutation in mutations.items():
        try:
            validate(f"{source}\n{mutation}", f"bootstrap AST mutation {label}")
        except SystemExit:
            continue
        raise SystemExit(f"bootstrap AST mutation escaped rejection: {label}")
    validate(
        source
        + "\n@fixture_owner_scoped\n"
        + "def test_ast_positive_direct_owner():\n"
        + "    owner = FixtureDescriptorOwner()\n"
        + "    owner.descriptor = -1\n",
        "bootstrap AST direct-owner positive control",
    )
    validate(
        source
        + "\ndef ast_positive_owner_helper():\n"
        + "    return FixtureDescriptorOwner()\n"
        + "\n@fixture_owner_scoped\n"
        + "def test_ast_positive_transitive_owner():\n"
        + "    owner = ast_positive_owner_helper()\n"
        + "    owner.descriptor = -1\n",
        "bootstrap AST transitive-owner positive control",
    )


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
                    "bootstrap fixture process record read did not converge"
                )
            continue
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > 4096:
            raise FixtureCleanupError(
                "bootstrap fixture process record exceeds its bound"
            )
    raise FixtureCleanupError("bootstrap fixture process record exceeds its bound")


def load_renderer_module():
    spec = importlib.util.spec_from_file_location("haptics_bootstrap_renderer", RENDERER)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load bootstrap renderer fixture module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_launcher_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("haptics_bootstrap_launcher", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load rendered bootstrap fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def renderer_arguments(
    output: pathlib.Path,
    trusted: str,
    candidate: str,
    digests: tuple[str, str, str, str],
) -> argparse.Namespace:
    return argparse.Namespace(
        output=str(output),
        trusted_commit=trusted,
        candidate_commit=candidate,
        gate_sha256=digests[0],
        workflow_sha256=digests[1],
        boundary_validator_sha256=digests[2],
        isolation_validator_sha256=digests[3],
    )


@fixture_owner_scoped
def test_renderer_custody(
    renderer,
    private: pathlib.Path,
    trusted: str,
    candidate: str,
    digests: tuple[str, str, str, str],
) -> None:
    renderer_scandir_original = renderer.os.scandir
    renderer_iterator_cancellation = KeyboardInterrupt(
        "renderer descriptor-table iteration cancellation"
    )
    renderer_iterator_close_failure = OSError(
        "renderer descriptor-table iterator close failure"
    )
    renderer_iterator_close_calls = 0

    class CancellingRendererIterator:
        def __init__(self, wrapped) -> None:
            self.wrapped = wrapped

        def __iter__(self):
            return self

        def __next__(self):
            raise renderer_iterator_cancellation

        def close(self) -> None:
            nonlocal renderer_iterator_close_calls
            renderer_iterator_close_calls += 1
            if renderer_iterator_close_calls == 1:
                raise renderer_iterator_close_failure
            self.wrapped.close()

    def cancelling_renderer_scandir(path):
        entries = renderer_scandir_original(path)
        if os.fspath(path) == "/proc/self/fd":
            return CancellingRendererIterator(entries)
        return entries

    renderer_before_descriptors = renderer.bounded_fd_snapshot()
    renderer.os.scandir = cancelling_renderer_scandir
    renderer_iterator_caught: BaseException | None = None
    try:
        try:
            renderer.bounded_fd_snapshot()
        except BaseException as exc:
            renderer_iterator_caught = exc
    finally:
        renderer.os.scandir = renderer_scandir_original
    if (
        renderer_iterator_caught is not renderer_iterator_cancellation
        or renderer_iterator_close_calls != 2
        or renderer.bounded_fd_snapshot() != renderer_before_descriptors
        or "iterator close also failed"
        not in " ".join(getattr(renderer_iterator_caught, "__notes__", ()))
    ):
        raise SystemExit(
            "bootstrap renderer scandir custody oracle drifted"
        ) from renderer_iterator_caught

    renderer_acquisition_cancellation = KeyboardInterrupt(
        "renderer descriptor-table acquisition cancellation"
    )
    retained_renderer_iterators: list[object] = []

    def cancelling_renderer_acquisition(path):
        entries = renderer_scandir_original(path)
        if os.fspath(path) == "/proc/self/fd":
            retained_renderer_iterators.append(entries)
            raise renderer_acquisition_cancellation
        return entries

    renderer.os.scandir = cancelling_renderer_acquisition
    renderer_acquisition_caught: BaseException | None = None
    try:
        try:
            renderer.bounded_fd_snapshot()
        except BaseException as exc:
            renderer_acquisition_caught = exc
    finally:
        renderer.os.scandir = renderer_scandir_original
    renderer_acquisition_residue = (
        renderer.bounded_fd_snapshot() != renderer_before_descriptors
    )
    for entries in retained_renderer_iterators:
        try:
            entries.close()
        except OSError:
            pass
    if (
        renderer_acquisition_caught is not renderer_acquisition_cancellation
        or len(retained_renderer_iterators) != 1
        or renderer_acquisition_residue
    ):
        raise SystemExit(
            "bootstrap renderer scandir acquisition custody drifted"
        ) from renderer_acquisition_caught

    canonical_parent = private / "render-raw-output-policy"
    canonical_parent.mkdir(mode=0o700)
    canonical_output = canonical_parent / "launcher.py"
    for raw_output in (
        f"{canonical_parent}/./launcher.py",
        f"{canonical_parent}//launcher.py",
        f"{canonical_output}/",
    ):
        raw_arguments = renderer_arguments(
            canonical_output,
            trusted,
            candidate,
            digests,
        )
        raw_arguments.output = raw_output
        try:
            renderer.render(raw_arguments)
        except renderer.RenderError as exc:
            if str(exc) != "bootstrap output path is not canonical":
                raise
        else:
            raise SystemExit("bootstrap renderer normalized a raw output path")
    if any(canonical_parent.iterdir()):
        raise SystemExit("bootstrap raw-output rejection created namespace residue")
    canonical_parent.rmdir()

    swap_parent = private / "render-parent-swap"
    swap_backup = private / "render-parent-original"
    swap_parent.mkdir(mode=0o700)
    swap_output = swap_parent / "launcher.py"
    original_open = renderer.os.open
    swapped = False

    def swap_parent_before_open(path, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == os.fspath(swap_parent):
            swap_parent.rename(swap_backup)
            swap_parent.mkdir(mode=0o700)
            swapped = True
        return original_open(path, *args, **kwargs)

    renderer.os.open = swap_parent_before_open
    try:
        try:
            renderer.render(
                renderer_arguments(
                    swap_output,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except renderer.RenderError as exc:
            if str(exc) != "bootstrap output parent changed before open":
                raise
        else:
            raise SystemExit("bootstrap renderer accepted a substituted output parent")
    finally:
        renderer.os.open = original_open
        if swap_output.exists():
            swap_output.unlink()
        swap_parent.rmdir()
        swap_backup.rename(swap_parent)
    if not swapped or any(swap_parent.iterdir()):
        raise SystemExit("bootstrap renderer parent-substitution fixture drifted")

    post_open_parent = private / "render-parent-post-open"
    displaced_parent = private / "render-parent-displaced"
    post_open_parent.mkdir(mode=0o700)
    post_open_output = post_open_parent / "launcher.py"
    hostile_output = b"#!/usr/bin/env python3\nprint('hostile replacement')\n"
    original_write = renderer.os.write
    post_open_swapped = False

    def swap_parent_after_open(descriptor: int, raw: bytes) -> int:
        nonlocal post_open_swapped
        written = original_write(descriptor, raw)
        if not post_open_swapped:
            post_open_parent.rename(displaced_parent)
            post_open_parent.mkdir(mode=0o700)
            post_open_output.write_bytes(hostile_output)
            post_open_output.chmod(0o500)
            post_open_swapped = True
        return written

    renderer.os.write = swap_parent_after_open
    try:
        try:
            renderer.render(
                renderer_arguments(
                    post_open_output,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except renderer.RenderError as exc:
            if str(exc) != "bootstrap output parent changed during publication":
                raise
        else:
            raise SystemExit(
                "bootstrap renderer accepted a post-open output-parent replacement"
            )
    finally:
        renderer.os.write = original_write
    displaced_output = displaced_parent / post_open_output.name
    if (
        not post_open_swapped
        or not post_open_output.is_file()
        or post_open_output.read_bytes() != hostile_output
        or displaced_output.exists()
    ):
        raise SystemExit("bootstrap renderer post-open custody fixture drifted")
    post_open_output.unlink()
    post_open_parent.rmdir()
    displaced_parent.rmdir()

    content_parent = private / "render-content-readback"
    content_parent.mkdir(mode=0o700)
    content_output = content_parent / "launcher.py"
    original_write = renderer.os.write
    corrupted = False

    def corrupt_published_content(descriptor: int, raw: bytes) -> int:
        nonlocal corrupted
        if not corrupted and raw:
            corrupted = True
            raw = bytes((raw[0] ^ 1,)) + raw[1:]
        return original_write(descriptor, raw)

    renderer.os.write = corrupt_published_content
    try:
        try:
            renderer.render(
                renderer_arguments(
                    content_output,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except renderer.RenderError as exc:
            if str(exc) != "bootstrap output content differs from policy":
                raise
        else:
            raise SystemExit("bootstrap renderer trusted intended content digest")
    finally:
        renderer.os.write = original_write
    if not corrupted or content_output.exists():
        if content_output.exists():
            content_output.unlink()
        raise SystemExit("bootstrap renderer content-readback fixture drifted")
    content_parent.rmdir()

    terminal_parent = private / "render-terminal-custody"
    terminal_parent.mkdir(mode=0o700)
    terminal_output = terminal_parent / "launcher.py"
    publication = renderer.render(
        renderer_arguments(terminal_output, trusted, candidate, digests)
    )
    evidence_output, evidence_digest = publication.evidence()
    if (
        evidence_output != terminal_output
        or evidence_digest != hashlib.sha256(terminal_output.read_bytes()).hexdigest()
    ):
        raise SystemExit("bootstrap renderer terminal evidence drifted")
    publication.release()
    try:
        publication.evidence()
    except renderer.RenderError as exc:
        if str(exc) != "bootstrap output terminal custody was released":
            raise
    else:
        raise SystemExit("bootstrap renderer trusted released terminal custody")
    terminal_output.unlink()
    terminal_parent.rmdir()

    release_parent = private / "render-custody-release-priority"
    release_parent.mkdir(mode=0o700)
    release_output = release_parent / "launcher.py"
    release_publication = renderer.render(
        renderer_arguments(release_output, trusted, candidate, digests)
    )
    release_publication.evidence()
    release_output_descriptor = release_publication._output_descriptor
    release_parent_descriptor = release_publication._parent_descriptor
    original_close = renderer.os.close
    release_events: list[str] = []
    release_cancellation = KeyboardInterrupt(
        "injected renderer custody release cancellation"
    )

    def fail_release_boundaries(descriptor: int) -> None:
        original_close(descriptor)
        if descriptor == release_output_descriptor:
            release_events.append("output")
            raise OSError("injected renderer custody output release failure")
        if descriptor == release_parent_descriptor:
            release_events.append("parent")
            raise release_cancellation

    renderer.os.close = fail_release_boundaries
    release_caught: BaseException | None = None
    try:
        try:
            release_publication.release()
        except BaseException as exc:
            release_caught = exc
    finally:
        renderer.os.close = original_close
    if (
        release_caught is not release_cancellation
        or release_events != ["output", "parent"]
        or release_publication._output_descriptor >= 0
        or release_publication._parent_descriptor >= 0
        or "bootstrap output custody release also failed"
        not in getattr(release_caught, "__notes__", ())
    ):
        raise SystemExit(
            "bootstrap renderer custody release masked caller cancellation"
        ) from release_caught
    release_output.unlink()
    release_parent.rmdir()

    probe_release_parent = private / "render-custody-probe-priority"
    probe_release_parent.mkdir(mode=0o700)
    probe_release_output = probe_release_parent / "launcher.py"
    probe_release = renderer.render(
        renderer_arguments(probe_release_output, trusted, candidate, digests)
    )
    probe_output_descriptor = probe_release._output_descriptor
    probe_parent_descriptor = probe_release._parent_descriptor
    original_close = renderer.os.close
    original_fstat = renderer.os.fstat
    probe_close_calls = {probe_output_descriptor: 0, probe_parent_descriptor: 0}
    probe_fstat_calls = {probe_output_descriptor: 0, probe_parent_descriptor: 0}
    probe_output_close_failure = OSError(
        "injected renderer custody output nonapplied close failure"
    )
    probe_parent_close_failure = OSError(
        "injected renderer custody parent nonapplied close failure"
    )
    probe_release_cancellation = KeyboardInterrupt(
        "injected renderer custody-probe cancellation"
    )

    def fail_probe_release_close(descriptor: int) -> None:
        if descriptor in probe_close_calls:
            probe_close_calls[descriptor] += 1
            if probe_close_calls[descriptor] == 1:
                if descriptor == probe_output_descriptor:
                    raise probe_output_close_failure
                raise probe_parent_close_failure
        original_close(descriptor)

    def cancel_probe_release_fstat(descriptor: int):
        if descriptor in probe_fstat_calls:
            probe_fstat_calls[descriptor] += 1
            if (
                descriptor == probe_output_descriptor
                and probe_fstat_calls[descriptor] == 1
            ):
                raise probe_release_cancellation
        return original_fstat(descriptor)

    renderer.os.close = fail_probe_release_close
    renderer.os.fstat = cancel_probe_release_fstat
    probe_release_caught: BaseException | None = None
    try:
        try:
            probe_release.release()
        except BaseException as exc:
            probe_release_caught = exc
    finally:
        renderer.os.fstat = original_fstat
        renderer.os.close = original_close
    probe_release_leaks: list[int] = []
    for descriptor in (probe_output_descriptor, probe_parent_descriptor):
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        probe_release_leaks.append(descriptor)
        original_close(descriptor)
    if (
        probe_release_caught is not probe_release_cancellation
        or probe_release_cancellation.__cause__ is not probe_output_close_failure
        or probe_close_calls
        != {probe_output_descriptor: 2, probe_parent_descriptor: 2}
        or probe_fstat_calls
        != {probe_output_descriptor: 1, probe_parent_descriptor: 1}
        or probe_release._output_descriptor >= 0
        or probe_release._parent_descriptor >= 0
        or probe_release_leaks
    ):
        raise SystemExit(
            "bootstrap renderer custody-probe cancellation drifted"
        ) from probe_release_caught
    probe_release_output.unlink()
    probe_release_parent.rmdir()

    mutate_parent = private / "render-post-close-mutation"
    mutate_parent.mkdir(mode=0o700)
    mutate_output = mutate_parent / "launcher.py"
    original_close = renderer.os.close
    original_fstat = renderer.os.fstat
    post_close_mutated = False
    mutation_close_observations: list[tuple[int, int, int, int, int, int] | None] = []
    mutation_targets: list[bool] = []

    def mutate_same_inode_after_output_close(descriptor: int) -> None:
        nonlocal post_close_mutated
        metadata = original_fstat(descriptor)
        target = False
        try:
            namespace = mutate_output.stat(follow_symlinks=False)
        except FileNotFoundError:
            namespace = None
        mutation_close_observations.append(
            None
            if namespace is None
            else (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_size,
                namespace.st_dev,
                namespace.st_ino,
            )
        )
        if namespace is not None:
            target = (metadata.st_dev, metadata.st_ino) == (
                namespace.st_dev,
                namespace.st_ino,
            )
        mutation_targets.append(target)
        original_close(descriptor)
        if target and not post_close_mutated:
            os.chmod(mutate_output, 0o700, follow_symlinks=False)
            mutator_owner = FixtureDescriptorOwner()
            acquire_fixture_setup_descriptor(
                mutator_owner,
                mutate_output,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                None,
                original_close,
                "renderer mutation oracle descriptor",
            )
            mutator = mutator_owner.descriptor
            mutator_primary: BaseException | None = None
            try:
                first = os.pread(mutator, 1, 0)
                if len(first) != 1:
                    raise SystemExit("renderer mutation oracle found empty output")
                if os.pwrite(mutator, bytes((first[0] ^ 1,)), 0) != 1:
                    raise SystemExit("renderer mutation oracle made no progress")
                os.fchmod(mutator, 0o500)
                os.fsync(mutator)
            except BaseException as exc:
                mutator_primary = exc
            finally:
                mutator_primary = settle_fixture_descriptor_owner(
                    mutator_owner,
                    mutator_primary,
                    "renderer mutation oracle descriptor",
                    close_function=original_close,
                )
            if mutator_primary is not None:
                fixture_raise_selected_failure(mutator_primary)
            post_close_mutated = True

    renderer.os.close = mutate_same_inode_after_output_close
    mutation_error: renderer.RenderError | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(mutate_output, trusted, candidate, digests)
            )
        except renderer.RenderError as exc:
            mutation_error = exc
    finally:
        renderer.os.close = original_close
    mutation_exists = mutate_output.exists()
    if (
        mutation_error is None
        or not post_close_mutated
        or mutation_exists
    ):
        if mutation_exists:
            mutate_output.unlink()
        raise SystemExit(
            "bootstrap renderer accepted post-close same-inode mutation: "
            f"error={mutation_error!r} mutated={post_close_mutated!r} "
            f"exists={mutation_exists!r} closes={mutation_close_observations!r} "
            f"targets={mutation_targets!r}"
        )
    mutate_parent.rmdir()

    handoff_parent = private / "render-parent-close-handoff"
    displaced_handoff_parent = private / "render-parent-close-displaced"
    handoff_parent.mkdir(mode=0o700)
    handoff_output = handoff_parent / "launcher.py"
    hostile_output = b"#!/usr/bin/env python3\nprint('hostile replacement')\n"
    parent_identity = (
        handoff_parent.stat().st_dev,
        handoff_parent.stat().st_ino,
    )
    parent_close_swapped = False

    def replace_parent_after_primary_close(descriptor: int) -> None:
        nonlocal parent_close_swapped
        metadata = original_fstat(descriptor)
        target = (
            stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        )
        original_close(descriptor)
        if target and not parent_close_swapped:
            handoff_parent.rename(displaced_handoff_parent)
            handoff_parent.mkdir(mode=0o700)
            hostile_owner = FixtureDescriptorOwner()
            acquire_fixture_setup_descriptor(
                hostile_owner,
                handoff_output,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o500,
                original_close,
                "renderer parent-swap hostile descriptor",
            )
            hostile_descriptor = hostile_owner.descriptor
            hostile_primary: BaseException | None = None
            try:
                offset = 0
                while offset < len(hostile_output):
                    written = os.write(hostile_descriptor, hostile_output[offset:])
                    if written <= 0:
                        raise SystemExit("renderer parent-swap oracle made no progress")
                    offset += written
                os.fchmod(hostile_descriptor, 0o500)
                os.fsync(hostile_descriptor)
            except BaseException as exc:
                hostile_primary = exc
            finally:
                hostile_primary = settle_fixture_descriptor_owner(
                    hostile_owner,
                    hostile_primary,
                    "renderer parent-swap hostile descriptor",
                    close_function=original_close,
                )
            if hostile_primary is not None:
                fixture_raise_selected_failure(hostile_primary)
            parent_close_swapped = True

    renderer.os.close = replace_parent_after_primary_close
    handoff_error: renderer.RenderError | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(handoff_output, trusted, candidate, digests)
            )
        except renderer.RenderError as exc:
            handoff_error = exc
    finally:
        renderer.os.close = original_close
    displaced_output = displaced_handoff_parent / handoff_output.name
    if (
        handoff_error is None
        or not parent_close_swapped
        or not handoff_output.is_file()
        or handoff_output.read_bytes() != hostile_output
        or displaced_output.exists()
    ):
        raise SystemExit("bootstrap renderer accepted final-parent-close replacement")
    handoff_output.unlink()
    handoff_parent.rmdir()
    displaced_handoff_parent.rmdir()

    close_parent = private / "render-close-rollback"
    close_parent.mkdir(mode=0o700)
    original_close = renderer.os.close
    original_fstat = renderer.os.fstat
    for role in ("output", "parent"):
        for failure_kind in (
            "applied-error",
            "nonapplied-error",
            "cancellation",
            "error-then-cancellation",
            "probe-cancellation",
        ):
            output = close_parent / f"{role}-{failure_kind}.py"
            injected = 0
            probe_injected = False
            probe_cancellation = KeyboardInterrupt(
                f"injected renderer {role} close-probe cancellation"
            )
            parent_identity = (
                close_parent.stat().st_dev,
                close_parent.stat().st_ino,
            )

            def target_descriptor(descriptor: int) -> bool:
                try:
                    metadata = original_fstat(descriptor)
                except OSError:
                    return False
                identity = (metadata.st_dev, metadata.st_ino)
                if role == "parent":
                    return identity == parent_identity
                try:
                    output_metadata = output.stat(follow_symlinks=False)
                except FileNotFoundError:
                    return False
                return identity == (
                    output_metadata.st_dev,
                    output_metadata.st_ino,
                )

            def inject_close(descriptor: int) -> None:
                nonlocal injected
                if not target_descriptor(descriptor):
                    original_close(descriptor)
                    return
                if failure_kind == "probe-cancellation" and injected == 0:
                    injected += 1
                    raise OSError(
                        f"injected renderer {role} preliminary probe-close failure"
                    )
                if failure_kind == "error-then-cancellation":
                    if injected == 0:
                        injected += 1
                        raise OSError("injected renderer preliminary close failure")
                    if injected == 1:
                        injected += 1
                        original_close(descriptor)
                        raise KeyboardInterrupt(
                            "injected renderer close cancellation after error"
                        )
                if failure_kind == "nonapplied-error" and injected < 3:
                    injected += 1
                    raise OSError("injected renderer nonapplied close failure")
                if not injected:
                    injected += 1
                    original_close(descriptor)
                    if failure_kind == "cancellation":
                        raise KeyboardInterrupt(
                            "injected renderer close cancellation"
                        )
                    raise OSError("injected renderer applied close failure")
                original_close(descriptor)

            def inject_probe_fstat(descriptor: int):
                nonlocal probe_injected
                if (
                    failure_kind == "probe-cancellation"
                    and injected == 1
                    and not probe_injected
                    and target_descriptor(descriptor)
                ):
                    probe_injected = True
                    raise probe_cancellation
                return original_fstat(descriptor)

            renderer.os.close = inject_close
            renderer.os.fstat = inject_probe_fstat
            caught: BaseException | None = None
            successful_publication = None
            try:
                try:
                    successful_publication = renderer.render(
                        renderer_arguments(output, trusted, candidate, digests)
                    )
                except BaseException as exc:
                    caught = exc
            finally:
                renderer.os.fstat = original_fstat
                renderer.os.close = original_close
            if failure_kind == "applied-error":
                if (
                    caught is not None
                    or injected != 1
                    or not output.is_file()
                    or successful_publication is None
                ):
                    raise SystemExit(
                        f"bootstrap renderer {role} applied-close recovery drifted"
                    ) from caught
                successful_publication.evidence()
                successful_publication.release()
                output.unlink()
            elif failure_kind == "nonapplied-error":
                if (
                    not isinstance(caught, renderer.RenderError)
                    or str(caught) != "bootstrap output cleanup failed"
                    or injected != 3
                    or output.exists()
                ):
                    raise SystemExit(
                        f"bootstrap renderer {role} nonapplied-close rollback "
                        "drifted"
                    ) from caught
            elif failure_kind == "cancellation" and (
                not isinstance(caught, KeyboardInterrupt)
                or str(caught) != "injected renderer close cancellation"
                or injected != 1
                or output.exists()
            ):
                raise SystemExit(
                    f"bootstrap renderer {role} close cancellation rollback "
                    "drifted"
                ) from caught
            elif failure_kind == "error-then-cancellation" and (
                not isinstance(caught, KeyboardInterrupt)
                or str(caught)
                != "injected renderer close cancellation after error"
                or injected != 2
                or output.exists()
            ):
                raise SystemExit(
                    f"bootstrap renderer {role} close cancellation priority "
                    "drifted"
                ) from caught
            elif failure_kind == "probe-cancellation" and (
                caught is not probe_cancellation
                or not probe_injected
                or injected != 1
                or output.exists()
                or not isinstance(probe_cancellation.__cause__, OSError)
                or str(probe_cancellation.__cause__)
                != f"injected renderer {role} preliminary probe-close failure"
            ):
                raise SystemExit(
                    f"bootstrap renderer {role} close-probe cancellation "
                    "priority drifted"
                ) from caught
    close_parent.rmdir()

    first_fstat_parent = private / "render-first-fstat"
    first_fstat_parent.mkdir(mode=0o700)
    original_fstat = renderer.os.fstat
    for failure_kind in ("oserror", "cancellation"):
        output = first_fstat_parent / f"{failure_kind}.py"
        injected = False

        def fail_first_output_fstat(descriptor: int):
            nonlocal injected
            metadata = original_fstat(descriptor)
            if (
                not injected
                and (metadata.st_mode & 0o170000) == 0o100000
                and (metadata.st_mode & 0o777) == 0o500
                and metadata.st_size == 0
            ):
                injected = True
                if failure_kind == "cancellation":
                    raise KeyboardInterrupt("injected renderer first-fstat cancellation")
                raise OSError("injected renderer first-fstat failure")
            return metadata

        renderer.os.fstat = fail_first_output_fstat
        try:
            try:
                renderer.render(
                    renderer_arguments(output, trusted, candidate, digests)
                )
            except KeyboardInterrupt as exc:
                if failure_kind != "cancellation" or str(exc) != (
                    "injected renderer first-fstat cancellation"
                ):
                    raise
            except renderer.RenderError as exc:
                if failure_kind != "oserror" or str(exc) != (
                    "cannot publish bootstrap output"
                ):
                    raise
            else:
                raise SystemExit(
                    f"bootstrap renderer swallowed first-fstat {failure_kind}"
                )
        finally:
            renderer.os.fstat = original_fstat
        if not injected or output.exists():
            if output.exists():
                output.unlink()
            raise SystemExit(
                f"bootstrap renderer retained first-fstat {failure_kind} output"
            )

    handoff_parent = private / "renderer-handoff"
    handoff_parent.mkdir(mode=0o700)
    original_open = renderer.os.open
    original_dup = renderer.os.dup

    def require_handoff_closed(
        descriptors: list[int],
        caught: BaseException | None,
        cancellation: KeyboardInterrupt,
        label: str,
        output: pathlib.Path | None = None,
    ) -> None:
        closed = True
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                closed = False
                os.close(descriptor)
        if (
            caught is not cancellation
            or len(descriptors) != 1
            or not closed
            or (output is not None and output.exists())
        ):
            if output is not None and output.exists():
                output.unlink()
            raise SystemExit(f"renderer {label} handoff custody drifted") from caught

    template_cancellation = KeyboardInterrupt(
        "injected renderer template-open handoff cancellation"
    )
    template_descriptors: list[int] = []

    def cancel_template_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = (
            original_open(path, flags, mode)
            if dir_fd is None
            else original_open(path, flags, mode, dir_fd=dir_fd)
        )
        if pathlib.Path(path) == TEMPLATE and not template_descriptors:
            template_descriptors.append(descriptor)
            raise template_cancellation
        return descriptor

    renderer.os.open = cancel_template_open
    template_caught: BaseException | None = None
    try:
        try:
            renderer.read_template(TEMPLATE)
        except BaseException as exc:
            template_caught = exc
    finally:
        renderer.os.open = original_open
    require_handoff_closed(
        template_descriptors,
        template_caught,
        template_cancellation,
        "template-open",
    )

    parent_output = handoff_parent / "parent-open.py"
    parent_cancellation = KeyboardInterrupt(
        "injected renderer parent-open handoff cancellation"
    )
    parent_descriptors: list[int] = []

    def cancel_parent_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = (
            original_open(path, flags, mode)
            if dir_fd is None
            else original_open(path, flags, mode, dir_fd=dir_fd)
        )
        if pathlib.Path(path) == handoff_parent and not parent_descriptors:
            parent_descriptors.append(descriptor)
            raise parent_cancellation
        return descriptor

    renderer.os.open = cancel_parent_open
    parent_caught: BaseException | None = None
    try:
        try:
            renderer.require_output(parent_output)
        except BaseException as exc:
            parent_caught = exc
    finally:
        renderer.os.open = original_open
    require_handoff_closed(
        parent_descriptors,
        parent_caught,
        parent_cancellation,
        "parent-open",
        parent_output,
    )

    recovery_original_fstat = renderer.os.fstat
    replacement_raw = b"#!/usr/bin/env python3\nprint('preserved replacement')\n"
    for failure_kind in ("cancellation", "ordinary-error"):
        recovery_output = handoff_parent / f"parent-recovery-{failure_kind}.py"
        recovery_caller = KeyboardInterrupt(
            f"injected renderer parent-open {failure_kind} caller"
        )
        recovery_probe = (
            KeyboardInterrupt("injected renderer recovery fstat cancellation")
            if failure_kind == "cancellation"
            else OSError(errno.EIO, "injected renderer recovery fstat error")
        )
        recovery_descriptors: list[int] = []
        recovery_fstat_calls = 0

        def cancel_recovery_parent_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = (
                original_open(path, flags, mode)
                if dir_fd is None
                else original_open(path, flags, mode, dir_fd=dir_fd)
            )
            if pathlib.Path(path) == handoff_parent and not recovery_descriptors:
                recovery_descriptors.append(descriptor)
                raise recovery_caller
            return descriptor

        def fail_recovery_identity_fstat(descriptor: int):
            nonlocal recovery_fstat_calls
            if descriptor in recovery_descriptors:
                recovery_fstat_calls += 1
                if recovery_fstat_calls == 3:
                    recovery_output.write_bytes(replacement_raw)
                    recovery_output.chmod(0o500)
                    raise recovery_probe
            return recovery_original_fstat(descriptor)

        renderer.os.open = cancel_recovery_parent_open
        renderer.os.fstat = fail_recovery_identity_fstat
        recovery_caught: BaseException | None = None
        try:
            try:
                renderer.require_output(recovery_output)
            except BaseException as exc:
                recovery_caught = exc
        finally:
            renderer.os.fstat = recovery_original_fstat
            renderer.os.open = original_open
        recovery_live = False
        for descriptor in recovery_descriptors:
            try:
                recovery_original_fstat(descriptor)
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
            or not recovery_output.is_file()
            or recovery_output.read_bytes() != replacement_raw
            or "descriptor recovery identity also became unknown"
            not in " ".join(getattr(recovery_caught, "__notes__", ()))
        ):
            if recovery_output.exists():
                recovery_output.unlink()
            raise SystemExit(
                f"renderer {failure_kind} recovery-fstat custody drifted"
            ) from recovery_caught
        recovery_output.unlink()

    for failure_kind in ("cancellation", "ordinary-error"):
        partial_output = handoff_parent / f"parent-partial-{failure_kind}.py"
        partial_caller = KeyboardInterrupt(
            f"injected renderer partial-scan {failure_kind} caller"
        )
        partial_failure = (
            KeyboardInterrupt("injected renderer partial-scan cancellation")
            if failure_kind == "cancellation"
            else OSError(errno.EIO, "injected renderer partial-scan error")
        )
        partial_descriptors: list[int] = []
        partial_injected = False

        class PartialRendererDescriptorIterator:
            def __init__(self, wrapped) -> None:
                self.wrapped = wrapped
                self.fail_next = False

            def __iter__(self):
                return self

            def __next__(self):
                nonlocal partial_injected
                if self.fail_next:
                    partial_injected = True
                    partial_output.write_bytes(replacement_raw)
                    partial_output.chmod(0o500)
                    raise partial_failure
                entry = next(self.wrapped)
                if partial_descriptors and entry.name == str(partial_descriptors[0]):
                    self.fail_next = True
                return entry

            def close(self) -> None:
                self.wrapped.close()

        def cancel_partial_parent_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = (
                original_open(path, flags, mode)
                if dir_fd is None
                else original_open(path, flags, mode, dir_fd=dir_fd)
            )
            if pathlib.Path(path) == handoff_parent and not partial_descriptors:
                partial_descriptors.append(descriptor)
                raise partial_caller
            return descriptor

        def fail_partial_descriptor_scan(path):
            entries = renderer_scandir_original(path)
            if os.fspath(path) == "/proc/self/fd" and partial_descriptors:
                return PartialRendererDescriptorIterator(entries)
            return entries

        renderer.os.open = cancel_partial_parent_open
        renderer.os.scandir = fail_partial_descriptor_scan
        partial_caught: BaseException | None = None
        try:
            try:
                renderer.require_output(partial_output)
            except BaseException as exc:
                partial_caught = exc
        finally:
            renderer.os.scandir = renderer_scandir_original
            renderer.os.open = original_open
        partial_live = False
        for descriptor in partial_descriptors:
            try:
                recovery_original_fstat(descriptor)
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
            or not partial_output.is_file()
            or partial_output.read_bytes() != replacement_raw
            or "descriptor recovery scan also failed"
            not in " ".join(getattr(partial_caught, "__notes__", ()))
        ):
            if partial_output.exists():
                partial_output.unlink()
            raise SystemExit(
                f"renderer {failure_kind} partial-scan recovery drifted"
            ) from partial_caught
        partial_output.unlink()

    cleanup_dup_output = handoff_parent / "cleanup-dup.py"
    cleanup_dup_cancellation = KeyboardInterrupt(
        "injected renderer cleanup-dup handoff cancellation"
    )
    cleanup_dup_descriptors: list[int] = []

    def cancel_cleanup_dup(descriptor: int) -> int:
        duplicate = original_dup(descriptor)
        if not cleanup_dup_descriptors:
            cleanup_dup_descriptors.append(duplicate)
            raise cleanup_dup_cancellation
        return duplicate

    renderer.os.dup = cancel_cleanup_dup
    cleanup_dup_caught: BaseException | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(
                    cleanup_dup_output,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except BaseException as exc:
            cleanup_dup_caught = exc
    finally:
        renderer.os.dup = original_dup
    require_handoff_closed(
        cleanup_dup_descriptors,
        cleanup_dup_caught,
        cleanup_dup_cancellation,
        "cleanup-dup",
        cleanup_dup_output,
    )

    output_open_path = handoff_parent / "output-open.py"
    output_open_cancellation = KeyboardInterrupt(
        "injected renderer output-open handoff cancellation"
    )
    output_open_descriptors: list[int] = []

    def cancel_output_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = (
            original_open(path, flags, mode)
            if dir_fd is None
            else original_open(path, flags, mode, dir_fd=dir_fd)
        )
        if (
            dir_fd is not None
            and os.fspath(path) == output_open_path.name
            and not output_open_descriptors
        ):
            output_open_descriptors.append(descriptor)
            raise output_open_cancellation
        return descriptor

    renderer.os.open = cancel_output_open
    output_open_caught: BaseException | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(
                    output_open_path,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except BaseException as exc:
            output_open_caught = exc
    finally:
        renderer.os.open = original_open
    require_handoff_closed(
        output_open_descriptors,
        output_open_caught,
        output_open_cancellation,
        "output-open",
        output_open_path,
    )

    inspection_output_path = handoff_parent / "output-open-inspection.py"
    inspection_cancellation = KeyboardInterrupt(
        "injected renderer output-open inspection cancellation"
    )
    inspection_descriptors: list[int] = []
    original_stat = renderer.os.stat
    inspection_failed = False

    def cancel_inspection_output_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = (
            original_open(path, flags, mode)
            if dir_fd is None
            else original_open(path, flags, mode, dir_fd=dir_fd)
        )
        if (
            dir_fd is not None
            and os.fspath(path) == inspection_output_path.name
            and not inspection_descriptors
        ):
            inspection_descriptors.append(descriptor)
            raise inspection_cancellation
        return descriptor

    def fail_first_inspection_stat(path, *args, **kwargs):
        nonlocal inspection_failed
        if (
            inspection_descriptors
            and os.fspath(path) == inspection_output_path.name
            and kwargs.get("dir_fd") is not None
            and not inspection_failed
        ):
            inspection_failed = True
            raise OSError(errno.EIO, "injected output handoff inspection failure")
        return original_stat(path, *args, **kwargs)

    renderer.os.open = cancel_inspection_output_open
    renderer.os.stat = fail_first_inspection_stat
    inspection_caught: BaseException | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(
                    inspection_output_path,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except BaseException as exc:
            inspection_caught = exc
    finally:
        renderer.os.stat = original_stat
        renderer.os.open = original_open
    if not inspection_failed:
        raise SystemExit("renderer output-open inspection oracle did not inject")
    require_handoff_closed(
        inspection_descriptors,
        inspection_caught,
        inspection_cancellation,
        "output-open-inspection",
        inspection_output_path,
    )

    mismatch_output_path = handoff_parent / "output-open-mode-mismatch.py"
    mismatch_cancellation = KeyboardInterrupt(
        "injected renderer output-open mode-mismatch cancellation"
    )
    mismatch_descriptors: list[int] = []

    def cancel_mismatched_output_open(path, flags, mode=0o777, *, dir_fd=None):
        selected_mode = (
            0
            if dir_fd is not None
            and os.fspath(path) == mismatch_output_path.name
            else mode
        )
        descriptor = (
            original_open(path, flags, selected_mode)
            if dir_fd is None
            else original_open(
                path,
                flags,
                selected_mode,
                dir_fd=dir_fd,
            )
        )
        if (
            dir_fd is not None
            and os.fspath(path) == mismatch_output_path.name
            and not mismatch_descriptors
        ):
            mismatch_descriptors.append(descriptor)
            raise mismatch_cancellation
        return descriptor

    renderer.os.open = cancel_mismatched_output_open
    mismatch_caught: BaseException | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(
                    mismatch_output_path,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except BaseException as exc:
            mismatch_caught = exc
    finally:
        renderer.os.open = original_open
    require_handoff_closed(
        mismatch_descriptors,
        mismatch_caught,
        mismatch_cancellation,
        "output-open-mode-mismatch",
        mismatch_output_path,
    )
    if "descriptor recovery metadata also differed" not in " ".join(
        getattr(mismatch_caught, "__notes__", ())
    ):
        raise SystemExit("renderer mode-mismatch recovery lost containment evidence")

    custody_dup_output = handoff_parent / "custody-dup.py"
    custody_dup_cancellation = KeyboardInterrupt(
        "injected renderer custody-dup handoff cancellation"
    )
    custody_dup_descriptors: list[int] = []
    custody_dup_calls = 0

    def cancel_custody_dup(descriptor: int) -> int:
        nonlocal custody_dup_calls
        custody_dup_calls += 1
        duplicate = original_dup(descriptor)
        if custody_dup_calls == 2:
            custody_dup_descriptors.append(duplicate)
            raise custody_dup_cancellation
        return duplicate

    renderer.os.dup = cancel_custody_dup
    custody_dup_caught: BaseException | None = None
    try:
        try:
            renderer.render(
                renderer_arguments(
                    custody_dup_output,
                    trusted,
                    candidate,
                    digests,
                )
            )
        except BaseException as exc:
            custody_dup_caught = exc
    finally:
        renderer.os.dup = original_dup
    require_handoff_closed(
        custody_dup_descriptors,
        custody_dup_caught,
        custody_dup_cancellation,
        "custody-dup",
        custody_dup_output,
    )
    handoff_parent.rmdir()


def settle_fixture_descriptor_owner(
    owner: FixtureDescriptorOwner,
    primary: BaseException | None,
    label: str,
    *,
    close_function=None,
) -> BaseException | None:
    if owner.descriptor < 0:
        return primary
    close_error, closed = fixture_close_owned_descriptor(
        owner.descriptor,
        close_function=close_function,
    )
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


def acquire_fixture_setup_descriptor(
    owner: FixtureDescriptorOwner,
    path: os.PathLike[str] | str,
    flags: int,
    mode: int | None,
    close_function,
    label: str,
) -> None:
    if owner.descriptor >= 0:
        raise FixtureCleanupError(f"{label} owner is already populated")
    before = fixture_open_descriptor_set()
    primary: BaseException | None = None
    try:
        if mode is None:
            owner.descriptor = os.open(path, flags)
        else:
            owner.descriptor = os.open(path, flags, mode)
        metadata = os.fstat(owner.descriptor)
        namespace = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (namespace.st_dev, namespace.st_ino)
            or os.get_inheritable(owner.descriptor)
        ):
            raise FixtureCleanupError(f"{label} descriptor identity is invalid")
    except BaseException as exc:
        primary = exc
    if primary is None:
        return
    partial: set[int] = set()
    try:
        after = fixture_open_descriptor_set(partial)
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"{label} recovery scan also failed",
        )
        after = frozenset(partial)
    candidates = set(after - before)
    if owner.descriptor >= 0:
        candidates.add(owner.descriptor)
    for descriptor in sorted(candidates):
        close_error, closed = fixture_close_owned_descriptor(
            descriptor,
            close_function=close_function,
        )
        if close_error is not None:
            primary = fixture_choose_failure(
                primary,
                close_error,
                f"{label} recovery close also failed",
            )
        if not closed:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(f"{label} recovery close did not converge"),
                f"{label} recovery custody also did not converge",
            )
        if descriptor == owner.descriptor and closed:
            owner.descriptor = -1
    fixture_raise_selected_failure(primary)


def acquire_fixture_memfd(
    owner: FixtureDescriptorOwner,
    name: str,
    flags: int,
    label: str,
) -> None:
    if owner.descriptor >= 0:
        raise FixtureCleanupError(f"{label} owner is already populated")
    baseline = fixture_open_descriptor_set()
    try:
        owner.descriptor = os.memfd_create(name, flags)
        metadata = os.fstat(owner.descriptor)
        target = os.readlink(f"/proc/self/fd/{owner.descriptor}")
        if (
            target != f"/memfd:{name} (deleted)"
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 0
            or os.get_inheritable(owner.descriptor)
        ):
            raise FixtureCleanupError(f"{label} identity differs from policy")
    except BaseException as exc:
        selected: BaseException | None = exc
        if owner.descriptor >= 0:
            selected = settle_fixture_descriptor_owner(owner, selected, label)
        else:
            partial_descriptors: set[int] = set()
            try:
                after = fixture_open_descriptor_set(partial_descriptors)
            except BaseException as scan_exc:
                selected = fixture_choose_failure(
                    selected,
                    scan_exc,
                    f"{label} recovery scan also failed",
                )
                after = frozenset(partial_descriptors)
            matches = 0
            for descriptor in sorted(after - baseline):
                identity_matches = False
                try:
                    metadata = os.fstat(descriptor)
                    target = os.readlink(f"/proc/self/fd/{descriptor}")
                    identity_matches = (
                        target == f"/memfd:{name} (deleted)"
                        and stat.S_ISREG(metadata.st_mode)
                        and metadata.st_nlink == 0
                    )
                except BaseException as probe_exc:
                    selected = fixture_choose_failure(
                        selected,
                        probe_exc,
                        f"{label} recovery probe also failed",
                    )
                if identity_matches:
                    matches += 1
                else:
                    selected = fixture_choose_failure(
                        selected,
                        FixtureCleanupError(
                            f"{label} recovered an unexpected descriptor"
                        ),
                        f"{label} recovery identity also differed",
                    )
                selected = fixture_settle_owned_descriptor(
                    descriptor,
                    selected,
                    f"{label} recovery close failed",
                )
            if matches > 1:
                selected = fixture_choose_failure(
                    selected,
                    FixtureCleanupError(f"{label} recovery is ambiguous"),
                    f"{label} recovery also became ambiguous",
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


def process_start_time(pid: int) -> int | None:
    path = pathlib.Path(f"/proc/{pid}/stat")
    try:
        namespace = os.stat(path, follow_symlinks=False)
    except (FileNotFoundError, ProcessLookupError):
        return None
    owner = FixtureDescriptorOwner()
    raw = b""
    missing = False
    primary: BaseException | None = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        acquire_existing_fixture_descriptor(
            owner,
            path,
            flags,
            (namespace.st_dev, namespace.st_ino),
            "bootstrap fixture process identity open",
        )
        raw = fixture_read_process_record(owner.descriptor)
    except (FileNotFoundError, ProcessLookupError):
        missing = True
    except BaseException as exc:
        primary = exc
    finally:
        primary = settle_fixture_descriptor_owner(
            owner,
            primary,
            "bootstrap fixture process identity",
        )
    if primary is not None:
        raise primary
    if missing:
        return None
    closing = raw.rfind(b") ")
    fields = raw[closing + 2:].split() if closing > 0 else []
    if len(fields) < 20 or not fields[19].isascii() or not fields[19].isdigit():
        raise FixtureCleanupError("bootstrap fixture process record is malformed")
    return int(fields[19], 10)


def read_process_identity(path: pathlib.Path, label: str) -> tuple[int, int]:
    try:
        namespace = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(f"bootstrap {label} identity is unavailable") from exc
    if not stat.S_ISREG(namespace.st_mode) or namespace.st_size > 128:
        raise SystemExit(f"bootstrap {label} identity is malformed")
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
            f"bootstrap {label} identity open",
        )
        before = os.fstat(owner.descriptor)
        raw = read_bounded_fixture_descriptor(
            owner.descriptor,
            128,
            f"bootstrap {label} identity",
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
                f"bootstrap {label} identity changed during read"
            )
    except BaseException as exc:
        primary = exc
    finally:
        primary = settle_fixture_descriptor_owner(
            owner,
            primary,
            f"bootstrap {label} identity",
        )
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        if isinstance(primary, SystemExit):
            raise primary
        raise SystemExit(f"bootstrap {label} identity is malformed") from primary
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
        raise SystemExit(f"bootstrap {label} identity is malformed")
    pid = int(fields[0], 10)
    start_time = int(fields[1][:-1], 10)
    if pid <= 1 or start_time <= 0:
        raise SystemExit(f"bootstrap {label} identity is outside its bound")
    return pid, start_time


def settle_exact_fixture_process(
    pid: int,
    expected_start_time: int | None,
    owner: FixtureDescriptorOwner,
    primary: BaseException | None,
    label: str,
    *,
    trusted_child: bool,
) -> tuple[BaseException | None, bool, bool, int | None]:
    identity_matches: bool | None = None
    if expected_start_time is not None:
        try:
            observed_start_time = process_start_time(pid)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} initial identity probe also failed",
            )
        else:
            if observed_start_time != expected_start_time:
                return primary, True, False, None
            identity_matches = True

    settled = False
    reaped = False
    status: int | None = None
    child_custody = False
    signal_attempts = 0
    for attempt in range(201):
        try:
            waited, observed_status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            waited = 0
        except ChildProcessError as exc:
            waited = -1
            pidfd_ready = False
            if owner.descriptor >= 0:
                try:
                    waiter = select.poll()
                    waiter.register(owner.descriptor, select.POLLIN)
                    pidfd_ready = bool(waiter.poll(0))
                except BaseException as probe_exc:
                    primary = fixture_choose_failure(
                        primary,
                        probe_exc,
                        f"{label} lost-child pidfd probe also failed",
                    )
            if pidfd_ready:
                settled = True
                reaped = trusted_child
                break
            if expected_start_time is not None:
                try:
                    observed_start_time = process_start_time(pid)
                except BaseException as probe_exc:
                    identity_matches = None
                    primary = fixture_choose_failure(
                        primary,
                        probe_exc,
                        f"{label} lost-child identity probe also failed",
                    )
                else:
                    if observed_start_time != expected_start_time:
                        settled = True
                        break
                    identity_matches = True
            elif trusted_child:
                try:
                    observed_start_time = process_start_time(pid)
                except BaseException as probe_exc:
                    primary = fixture_choose_failure(
                        primary,
                        probe_exc,
                        f"{label} trusted-child disappearance probe also failed",
                    )
                else:
                    if observed_start_time is None:
                        settled = True
                        reaped = True
                        break
                    failure = FixtureCleanupError(
                        f"{label} lost exact child ownership"
                    )
                    failure.__cause__ = exc
                    primary = fixture_choose_failure(
                        primary,
                        failure,
                        f"{label} child ownership also failed",
                    )
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
                settled = True
                reaped = True
                break
            if waited == 0:
                child_custody = True
            else:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(
                        f"{label} waited for an unexpected child"
                    ),
                    f"{label} wait also diverged",
                )
                break

        if expected_start_time is not None and identity_matches is None:
            try:
                observed_start_time = process_start_time(pid)
            except BaseException as probe_exc:
                primary = fixture_choose_failure(
                    primary,
                    probe_exc,
                    f"{label} identity retry also failed",
                )
            else:
                if observed_start_time != expected_start_time:
                    settled = True
                    break
                identity_matches = True

        signal_authorized = identity_matches is True or (
            trusted_child and child_custody
        )
        if signal_authorized and signal_attempts < 3:
            signal_attempts += 1
            pidfd_signal_failed = owner.descriptor < 0
            if owner.descriptor >= 0:
                try:
                    signal.pidfd_send_signal(
                        owner.descriptor,
                        signal.SIGKILL,
                        None,
                        0,
                    )
                except ProcessLookupError:
                    pidfd_signal_failed = True
                except BaseException as exc:
                    pidfd_signal_failed = True
                    primary = fixture_choose_failure(
                        primary,
                        exc,
                        f"{label} pidfd signal also failed",
                    )
            if pidfd_signal_failed:
                raw_signal_authorized = child_custody
                if raw_signal_authorized:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except BaseException as exc:
                        primary = fixture_choose_failure(
                            primary,
                            exc,
                            f"{label} raw signal also failed",
                        )

        if attempt < 200 and not settled:
            try:
                time.sleep(0.01)
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} cleanup sleep also failed",
                )

    if not settled:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{label} cleanup did not converge"),
            f"{label} cleanup also did not converge",
        )
    return primary, settled, reaped, status


def require_process_identity_gone(
    pid: int,
    expected_start_time: int,
    label: str,
) -> None:
    def settle_acquisition_failure(
        owner: FixtureDescriptorOwner,
        primary: BaseException,
    ) -> None:
        try:
            primary, _settled, _reaped, _status = settle_exact_fixture_process(
                pid,
                expected_start_time,
                owner,
                primary,
                f"bootstrap fixture {label} acquisition-failure child",
                trusted_child=False,
            )
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"bootstrap fixture {label} failure settlement also failed",
            )
        finally:
            primary = settle_fixture_descriptor_owner(
                owner,
                primary,
                f"bootstrap fixture {label} failure pidfd",
            )
        assert primary is not None
        raise primary

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        owner = FixtureDescriptorOwner()
        try:
            open_owned_fixture_pidfd(
                owner,
                pid,
                f"bootstrap fixture {label} pidfd handoff",
                validate=False,
            )
        except ProcessLookupError:
            return
        except BaseException as exc:
            settle_acquisition_failure(owner, exc)
        primary: BaseException | None = None
        identity_matches = True
        ready = False
        try:
            if process_start_time(pid) != expected_start_time:
                identity_matches = False
            else:
                waiter = select.poll()
                waiter.register(owner.descriptor, select.POLLIN)
                ready = bool(waiter.poll(0))
        except BaseException as exc:
            primary = exc
        primary = settle_fixture_descriptor_owner(
            owner,
            primary,
            f"bootstrap fixture {label} pidfd",
        )
        if primary is not None:
            raise primary
        if not identity_matches:
            return
        if not ready:
            time.sleep(0.01)
            continue
        time.sleep(0.01)
    owner = FixtureDescriptorOwner()
    try:
        open_owned_fixture_pidfd(
            owner,
            pid,
            f"bootstrap fixture {label} terminal pidfd handoff",
            validate=False,
        )
    except ProcessLookupError:
        return
    except BaseException as exc:
        settle_acquisition_failure(owner, exc)
    primary: BaseException | None = None
    expected_process_remains = False
    try:
        observed_start_time = process_start_time(pid)
        if observed_start_time == expected_start_time:
            expected_process_remains = True
            primary = FixtureCleanupError(
                f"bootstrap fixture left {label} process {pid}"
            )
            primary, _settled, _reaped, _status = settle_exact_fixture_process(
                pid,
                expected_start_time,
                owner,
                primary,
                f"bootstrap fixture terminal {label}",
                trusted_child=False,
            )
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"bootstrap fixture {label} terminal settlement also failed",
        )
        try:
            primary, _settled, _reaped, _status = settle_exact_fixture_process(
                pid,
                expected_start_time,
                owner,
                primary,
                f"bootstrap fixture terminal-error {label}",
                trusted_child=False,
            )
        except BaseException as cleanup_exc:
            primary = fixture_choose_failure(
                primary,
                cleanup_exc,
                f"bootstrap fixture {label} terminal recovery also failed",
            )
    finally:
        primary = settle_fixture_descriptor_owner(
            owner,
            primary,
            f"bootstrap fixture {label} terminal pidfd",
        )
    if primary is not None:
        fixture_raise_selected_failure(primary)
    if expected_process_remains:
        raise FixturePublicFailure(
            f"bootstrap fixture left {label} process {pid}"
        )


def require_process_gone(path: pathlib.Path, label: str) -> None:
    pid, expected_start_time = read_process_identity(path, label)
    try:
        require_process_identity_gone(
            pid,
            expected_start_time,
            label,
        )
    except BaseException as exc:
        primary: BaseException | None = exc
        owner = FixtureDescriptorOwner()
        try:
            try:
                open_owned_fixture_pidfd(
                    owner,
                    pid,
                    f"bootstrap fixture {label} outer-settlement pidfd handoff",
                    validate=False,
                )
            except ProcessLookupError:
                pass
            except BaseException as acquisition_exc:
                primary = fixture_choose_failure(
                    primary,
                    acquisition_exc,
                    f"bootstrap fixture {label} outer pidfd acquisition also failed",
                )
            primary, _settled, _reaped, _status = settle_exact_fixture_process(
                pid,
                expected_start_time,
                owner,
                primary,
                f"bootstrap fixture outer settlement {label}",
                trusted_child=False,
            )
        except BaseException as cleanup_exc:
            primary = fixture_choose_failure(
                primary,
                cleanup_exc,
                f"bootstrap fixture {label} outer process settlement also failed",
            )
        finally:
            primary = settle_fixture_descriptor_owner(
                owner,
                primary,
                f"bootstrap fixture {label} outer-settlement pidfd",
            )
        assert primary is not None
        raise primary


def require_popen_reaped(process: subprocess.Popen[bytes], label: str) -> None:
    primary: BaseException | None = None
    poll_known = False
    root_running = True
    expected_start_time: int | None = None
    try:
        root_running = process.poll() is None
        poll_known = True
    except BaseException as exc:
        primary = exc
    if poll_known and not root_running:
        return
    try:
        expected_start_time = process_start_time(process.pid)
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"bootstrap fixture {label} initial identity also failed",
        )
    owner = FixtureDescriptorOwner()
    try:
        open_owned_fixture_pidfd(
            owner,
            process.pid,
            f"bootstrap fixture {label} pidfd handoff",
            validate=False,
        )
    except ProcessLookupError:
        pass
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"bootstrap fixture {label} pidfd open also failed",
        )
    if primary is None:
        primary = FixtureCleanupError(
            f"bootstrap fixture left {label} process {process.pid}"
        )
    try:
        primary, _settled, reaped, status = settle_exact_fixture_process(
            process.pid,
            expected_start_time,
            owner,
            primary,
            f"bootstrap fixture Popen {label}",
            trusted_child=True,
        )
        if reaped and status is not None:
            try:
                process.returncode = os.waitstatus_to_exitcode(status)
            except ValueError as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"bootstrap fixture {label} exit-status conversion also failed",
                )
        if reaped and process.returncode is None:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"bootstrap fixture {label} Popen status is unavailable"
                ),
                f"bootstrap fixture {label} Popen settlement also lacked status",
            )
    except BaseException as exc:
        primary = fixture_choose_failure(
            primary,
            exc,
            f"bootstrap fixture {label} exact reap also failed",
        )
    finally:
        primary = settle_fixture_descriptor_owner(
            owner,
            primary,
            f"bootstrap fixture {label} pidfd",
        )
    if primary is not None:
        fixture_raise_selected_failure(primary)
    raise FixturePublicFailure(
        f"bootstrap fixture left {label} process {process.pid}"
    )


def settle_pinned_popen(
    process: subprocess.Popen[bytes],
    descriptor: int,
    label: str,
) -> bool:
    primary: BaseException | None = None
    leaked = True
    expected_start_time: int | None = None
    owner = FixtureDescriptorOwner()
    owner.descriptor = descriptor
    try:
        leaked = process.poll() is None
    except BaseException as exc:
        primary = exc
    if leaked:
        try:
            expected_start_time = process_start_time(process.pid)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"bootstrap fixture {label} pinned identity also failed",
            )
        try:
            primary, _settled, reaped, status = settle_exact_fixture_process(
                process.pid,
                expected_start_time,
                owner,
                primary,
                f"bootstrap fixture pinned Popen {label}",
                trusted_child=True,
            )
            if reaped and status is not None:
                try:
                    process.returncode = os.waitstatus_to_exitcode(status)
                except ValueError as exc:
                    primary = fixture_choose_failure(
                        primary,
                        exc,
                        f"bootstrap fixture {label} pinned status conversion also failed",
                    )
            if reaped and process.returncode is None:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(
                        f"bootstrap fixture {label} pinned Popen status is unavailable"
                    ),
                    f"bootstrap fixture {label} pinned settlement also lacked status",
                )
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"bootstrap fixture {label} pinned settlement also failed",
            )
    primary = settle_fixture_descriptor_owner(
        owner,
        primary,
        f"bootstrap fixture {label} pinned pidfd",
    )
    if primary is not None:
        raise primary
    return leaked


def settle_pinned_fixture_owners(
    process_owner: FixturePopenOwner,
    descriptor_owner: FixtureDescriptorOwner,
    label: str,
) -> tuple[bool, bool]:
    if process_owner.process is None or descriptor_owner.descriptor < 0:
        return True, False
    process = process_owner.process
    descriptor = descriptor_owner.descriptor
    leaked = settle_pinned_popen(process, descriptor, label)
    try:
        os.fstat(descriptor)
    except OSError as exc:
        descriptor_closed = exc.errno == errno.EBADF
    else:
        descriptor_closed = False
    try:
        os.waitpid(process.pid, os.WNOHANG)
    except ChildProcessError as exc:
        process_reaped = exc.errno == errno.ECHILD
    else:
        process_reaped = False
    exact = (
        descriptor_closed
        and process_reaped
        and process.returncode is not None
    )
    if exact:
        descriptor_owner.descriptor = -1
        process_owner.process = None
    return leaked, exact


def fixture_get_subreaper() -> bool:
    current = ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
        raise FixtureCleanupError("bootstrap fixture cannot inspect subreaper state")
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
        raise FixtureCleanupError("bootstrap fixture cannot set subreaper state")
    return previous


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
            if count > 131072:
                raise FixtureCleanupError(
                    "bootstrap fixture process table exceeds its bound"
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
                            f"bootstrap fixture cannot inspect process record {pid}"
                        )
                        primary.__cause__ = exc
                    notes_before = tuple(getattr(primary, "__notes__", ()))
                    primary = fixture_recover_descriptor_handoff(
                        record_baseline,
                        (record_metadata.st_dev, record_metadata.st_ino),
                        primary,
                        "bootstrap fixture process-record open",
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
                            f"bootstrap fixture process record {pid} changed"
                        )
                    raw = fixture_read_process_record(descriptor)
            except (FileNotFoundError, ProcessLookupError):
                skipped = True
            except OSError as exc:
                primary = FixtureCleanupError(
                    f"bootstrap fixture cannot inspect process record {pid}"
                )
                primary.__cause__ = exc
            except BaseException as exc:
                primary = exc
            if descriptor >= 0:
                primary = fixture_settle_owned_descriptor(
                    descriptor,
                    primary,
                    "bootstrap fixture process record close failed",
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
                    f"bootstrap fixture process record {pid} is malformed"
                )
            processes[pid] = (int(fields[1], 10), int(fields[19], 10))
    except BaseException as exc:
        scan_primary = exc
        if entries is None:
            scan_primary = fixture_recover_descriptor_handoff(
                process_table_baseline,
                (process_table_metadata.st_dev, process_table_metadata.st_ino),
                scan_primary,
                "bootstrap fixture process-table iterator open",
            )
    if entries is not None:
        scan_primary = fixture_settle_scandir_iterator(
            entries,
            scan_primary,
            "bootstrap fixture process-table iterator",
        )
    if scan_primary is not None:
        raise scan_primary
    return processes


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
    *,
    close_function=None,
) -> tuple[BaseException | None, bool]:
    closer = os.close if close_function is None else close_function
    first_error: BaseException | None = None
    for _ in range(3):
        try:
            closer(descriptor)
        except BaseException as exc:
            first_error = fixture_choose_failure(
                first_error,
                exc,
                "bootstrap fixture descriptor close also failed",
            )
            try:
                os.fstat(descriptor)
            except BaseException as probe:
                if isinstance(probe, OSError) and probe.errno == errno.EBADF:
                    return first_error, True
                first_error = fixture_choose_failure(
                    first_error,
                    probe,
                    "bootstrap fixture descriptor custody probe also failed",
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
            "bootstrap fixture final descriptor custody probe also failed",
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
                    "bootstrap fixture descriptor table exceeds its bound"
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
            "trusted bootstrap fixture descriptor-table iterator",
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


def wait_exact_fixture_child(
    child: int,
    label: str,
    *,
    terminate: bool = True,
) -> int:
    deadline = time.monotonic() + 2.0
    status: int | None = None
    reaped = False
    primary: BaseException | None = None
    while time.monotonic() < deadline and not reaped:
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
            continue
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
        if terminate or time.monotonic() >= deadline - 0.1:
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
        try:
            time.sleep(0.01)
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} child cleanup sleep also failed",
            )
    if not reaped:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            primary = fixture_choose_failure(
                primary,
                exc,
                f"{label} final child kill also failed",
            )
        for _ in range(100):
            try:
                waited, observed_status = os.waitpid(child, os.WNOHANG)
            except InterruptedError:
                continue
            except ChildProcessError as exc:
                failure = FixtureCleanupError(
                    f"{label} lost child ownership during final cleanup"
                )
                failure.__cause__ = exc
                primary = fixture_choose_failure(
                    primary,
                    failure,
                    f"{label} final child ownership also failed",
                )
                break
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} final child wait also failed",
                )
                continue
            if waited == child:
                status = observed_status
                reaped = True
                break
            try:
                time.sleep(0.01)
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} final child sleep also failed",
                )
    if not reaped:
        primary = fixture_choose_failure(
            primary,
            FixtureCleanupError(f"{label} child cleanup did not converge"),
            f"{label} child cleanup also did not converge",
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
                if owned_child == owner.pid:
                    selected = settle_fixture_child_owner(
                        owner,
                        selected,
                        f"{label} handoff child",
                    )
                else:
                    wait_exact_fixture_child(
                        owned_child,
                        f"{label} discovered handoff child",
                    )
            except BaseException as cleanup_exc:
                selected = fixture_choose_failure(
                    selected,
                    cleanup_exc,
                    f"{label} handoff cleanup also failed",
                )
        fixture_raise_selected_failure(selected)
    if owner.pid <= 0:
        raise FixtureCleanupError(f"{label} child identity was not published")


def acquire_fixture_popen_call(
    owner: FixturePopenOwner,
    factory,
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
        owner.process = factory()
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


def spawn_fixture_popen(
    owner: FixturePopenOwner,
    arguments: list[str],
    *,
    cwd: pathlib.Path,
    label: str,
) -> None:
    def factory():
        return subprocess.Popen(
            arguments,
            cwd=cwd,
            env=fixture_environment(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )

    acquire_fixture_popen_call(owner, factory, label)


def settle_fixture_child_owner(
    owner: FixtureChildOwner,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    if owner.pid <= 0:
        return primary
    descriptor_owner = _fixture_local_descriptor_owner()
    primary, settled, reaped, _status = settle_exact_fixture_process(
        owner.pid,
        None,
        descriptor_owner,
        primary,
        label,
        trusted_child=True,
    )
    if settled and reaped:
        owner.pid = -1
    return primary


def settle_fixture_popen_owner(
    owner: FixturePopenOwner,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    if owner.process is None:
        return primary
    descriptor_owner = _fixture_local_descriptor_owner()
    primary, settled, reaped, status = settle_exact_fixture_process(
        owner.process.pid,
        None,
        descriptor_owner,
        primary,
        label,
        trusted_child=True,
    )
    if settled and reaped:
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
        if isinstance(exc, FixtureOwnerBodySignal):
            primary = exc.caller_policy
        else:
            primary = exc
    finally:
        for _ in range(3):
            if signal_latch.finalizing:
                break
            try:
                signal_latch.begin_finalizer()
            except FixtureOwnerBodySignal as exc:
                if exc.caller_policy is not None:
                    primary = fixture_choose_failure(
                        primary,
                        exc.caller_policy,
                        f"{label} finalizer transition also interrupted caller policy",
                    )
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    f"{label} finalizer transition also failed",
                )
        if not signal_latch.finalizing:
            # Preserve non-throwing containment even if a monkeypatched
            # transition never applies, while retaining the exact failure.
            signal_latch.finalizing = True
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"{label} finalizer transition did not converge"
                ),
                f"{label} finalizer transition also did not converge",
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
        raise SystemExit("bootstrap fixture owner-scope oracle did not start empty")
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
        post_signal_sentinel = False
        post_signal_acquisition_attempts = 0
        post_signal_spawn_attempts = 0
        direct_cancellation = KeyboardInterrupt(
            "injected bootstrap owner-finalizer direct cancellation"
        )
        signum = (
            signal.SIGTERM
            if mode in ("term", "body-term")
            else signal.SIGINT
        )

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
                    if mode == "priority":
                        os.kill(os.getpid(), signal.SIGTERM)
                        os.kill(os.getpid(), signal.SIGINT)
                    else:
                        os.kill(os.getpid(), signum)
            selected = original_settle_descriptor(owner, primary, label)
            if mode == "return":
                raise direct_cancellation
            return selected

        def interrupt_finalizer_transition(latch: FixtureOwnerSignalLatch) -> None:
            nonlocal fired
            if not fired:
                fired = True
                os.kill(os.getpid(), signal.SIGINT)
            original_begin_finalizer(latch)

        globals()["settle_fixture_descriptor_owner"] = interrupt_first_settlement
        if mode == "transition":
            FixtureOwnerSignalLatch.begin_finalizer = interrupt_finalizer_transition
        caught: BaseException | None = None
        try:
            try:
                with fixture_owner_lifetime(
                    f"bootstrap owner-finalizer {mode} oracle"
                ):
                    nonlocal_post_signal_owner = None
                    inner_scope = _FIXTURE_OWNER_SCOPES[-1]
                    popen_owner = FixturePopenOwner()
                    spawn_fixture_popen(
                        popen_owner,
                        ["/usr/bin/sleep", "30"],
                        cwd=cwd,
                        label=f"bootstrap owner-finalizer {mode} Popen",
                    )
                    assert popen_owner.process is not None
                    process = popen_owner.process
                    child_owner = FixtureChildOwner()
                    spawn_fixture_child(
                        child_owner,
                        child_main,
                        f"bootstrap owner-finalizer {mode} child",
                    )
                    child = child_owner.pid
                    descriptor_owner = FixtureDescriptorOwner()
                    metadata = os.stat("/dev/null", follow_symlinks=False)
                    acquire_existing_fixture_descriptor(
                        descriptor_owner,
                        "/dev/null",
                        os.O_RDONLY | os.O_CLOEXEC,
                        (metadata.st_dev, metadata.st_ino),
                        f"bootstrap owner-finalizer {mode} descriptor",
                    )
                    descriptor = descriptor_owner.descriptor
                    if mode == "body-caller":
                        fired = True
                        try:
                            raise direct_cancellation
                        except BaseException:
                            os.kill(os.getpid(), signal.SIGINT)
                            post_signal_sentinel = True
                    elif mode in ("body-int", "body-term"):
                        fired = True
                        os.kill(os.getpid(), signum)
                        post_signal_sentinel = True
                        post_signal_acquisition_attempts += 1
                        nonlocal_post_signal_owner = FixtureDescriptorOwner()
                        acquire_existing_fixture_descriptor(
                            nonlocal_post_signal_owner,
                            "/dev/null",
                            os.O_RDONLY | os.O_CLOEXEC,
                            (metadata.st_dev, metadata.st_ino),
                            f"bootstrap owner-finalizer {mode} unreachable descriptor",
                        )
                        post_signal_spawn_attempts += 1
                        unreachable_child_owner = FixtureChildOwner()
                        spawn_fixture_child(
                            unreachable_child_owner,
                            child_main,
                            f"bootstrap owner-finalizer {mode} unreachable child",
                        )
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
            if mode in ("python", "return", "body-caller")
            else (
                isinstance(caught, FixturePublicFailure)
                and caught.code == 128 + signum
            )
        )
        if (
            not fired
            or not expected_failure
            or post_signal_sentinel
            or post_signal_acquisition_attempts != 0
            or post_signal_spawn_attempts != 0
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
                f"bootstrap owner-finalizer {mode} cancellation custody drifted"
            ) from caught

    for mode in (
        "int",
        "term",
        "priority",
        "python",
        "return",
        "body-int",
        "body-term",
        "body-caller",
        "transition",
    ):
        run_case(mode)
    with fixture_owner_lifetime("bootstrap owner-finalizer nested outer"):
        outer_scope = _FIXTURE_OWNER_SCOPES[-1]
        run_case("body-int")
        run_case("body-term")
        if (
            len(_FIXTURE_OWNER_SCOPES) != 1
            or _FIXTURE_OWNER_SCOPES[-1] is not outer_scope
            or outer_scope
        ):
            raise SystemExit("bootstrap nested owner-scope identity drifted")
    if _FIXTURE_OWNER_SCOPES:
        raise SystemExit("bootstrap fixture owner-scope oracle left stack residue")
    direct_body_cancellation = KeyboardInterrupt(
        "injected bootstrap nested owner-scope body cancellation"
    )
    outer_scope = None
    inner_scope = None
    direct_body_caught: BaseException | None = None
    try:
        with fixture_owner_lifetime("bootstrap direct-body outer"):
            outer_scope = _FIXTURE_OWNER_SCOPES[-1]
            with fixture_owner_lifetime("bootstrap direct-body inner"):
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
            "bootstrap nested owner-scope body cancellation drifted"
        ) from direct_body_caught


@fixture_owner_scoped
def test_fixture_owner_fairness_and_capacity() -> None:
    """Ensure one stubborn owner cannot starve earlier custody or bypass the cap."""
    if len(_FIXTURE_OWNER_SCOPES) != 1:
        raise SystemExit("bootstrap fairness oracle did not start in one scope")
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
                FixtureCleanupError("bootstrap fairness stubborn owner"),
                f"{label} stubborn owner remained populated",
            )
        return original_settle(owner, primary, label, **kwargs)

    globals()["settle_fixture_descriptor_owner"] = stubborn_settle
    caught: BaseException | None = None
    try:
        try:
            with fixture_owner_lifetime("bootstrap owner fairness"):
                inner_scope = _FIXTURE_OWNER_SCOPES[-1]
                closable_owner = FixtureDescriptorOwner()
                metadata = os.stat("/dev/null", follow_symlinks=False)
                acquire_existing_fixture_descriptor(
                    closable_owner,
                    "/dev/null",
                    os.O_RDONLY | os.O_CLOEXEC,
                    (metadata.st_dev, metadata.st_ino),
                    "bootstrap fairness closable owner",
                )
                stubborn_owner = FixtureDescriptorOwner()
                acquire_existing_fixture_descriptor(
                    stubborn_owner,
                    "/dev/null",
                    os.O_RDONLY | os.O_CLOEXEC,
                    (metadata.st_dev, metadata.st_ino),
                    "bootstrap fairness stubborn owner",
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
            "bootstrap owner fairness did not preserve bounded residual custody"
        ) from caught

    cleanup_primary = original_settle(
        stubborn_owner,
        None,
        "bootstrap fairness residual cleanup",
    )
    if cleanup_primary is not None or stubborn_owner.descriptor >= 0:
        raise SystemExit("bootstrap fairness residual cleanup failed") from cleanup_primary
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
        raise SystemExit("bootstrap fairness residual scope was not removable")

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
            "bootstrap owner-cap rejection was not pre-acquisition and bounded"
        ) from capacity_caught


def open_owned_fixture_pidfd(
    owner: FixtureDescriptorOwner,
    pid: int,
    label: str,
    *,
    validate: bool = True,
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
                    f"{label} applied pidfd owner close also failed",
                )
            if not closed:
                primary = fixture_choose_failure(
                    primary,
                    FixtureCleanupError(
                        f"{label} applied pidfd owner close did not converge"
                    ),
                    f"{label} applied pidfd owner custody also did not converge",
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
                    f"{label} applied pidfd recovery scan also failed",
                )
                after = frozenset(partial_descriptors)
            for candidate in sorted(after - before):
                try:
                    target = os.readlink(f"/proc/self/fd/{candidate}")
                except BaseException as probe_exc:
                    primary = fixture_choose_failure(
                        primary,
                        probe_exc,
                        f"{label} applied pidfd recovery probe also failed",
                    )
                    target = None
                primary = fixture_settle_owned_descriptor(
                    candidate,
                    primary,
                    f"{label} applied pidfd recovery close failed",
                )
                if target != "anon_inode:[pidfd]":
                    primary = fixture_choose_failure(
                        primary,
                        FixtureCleanupError(
                            f"{label} recovered an unexpected descriptor"
                        ),
                        f"{label} applied pidfd recovery identity also differed",
                    )
        fixture_raise_selected_failure(primary)
    if not validate:
        return
    primary: BaseException | None = None
    try:
        if owner.descriptor in before or os.get_inheritable(owner.descriptor):
            primary = FixtureCleanupError(
                f"{label} pidfd handoff is not canonical"
            )
    except BaseException as exc:
        primary = exc
    if primary is not None:
        close_error, closed = fixture_close_owned_descriptor(owner.descriptor)
        if close_error is not None:
            primary = fixture_choose_failure(
                primary,
                close_error,
                f"{label} invalid pidfd close also failed",
            )
        if not closed:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    f"{label} invalid pidfd close did not converge"
                ),
                f"{label} invalid pidfd custody also did not converge",
            )
        else:
            owner.descriptor = -1
        assert primary is not None
        fixture_raise_selected_failure(primary)


@fixture_owner_scoped
def test_direct_spawn_handoffs(cwd: pathlib.Path) -> None:
    original_popen = subprocess.Popen
    created_processes: list[subprocess.Popen[bytes]] = []
    popen_cancellation = KeyboardInterrupt(
        "bootstrap direct Popen assignment cancellation"
    )

    def popen_then_cancel(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        created_processes.append(process)
        raise popen_cancellation

    subprocess.Popen = popen_then_cancel
    popen_caught: BaseException | None = None
    popen_owner = FixturePopenOwner()
    try:
        try:
            spawn_fixture_popen(
                popen_owner,
                ["/usr/bin/sleep", "30"],
                cwd=cwd,
                label="bootstrap direct Popen oracle",
            )
        except BaseException as exc:
            popen_caught = settle_fixture_popen_owner(
                popen_owner,
                exc,
                "bootstrap direct Popen oracle",
            )
    finally:
        subprocess.Popen = original_popen
    if popen_caught is not popen_cancellation or len(created_processes) != 1:
        raise SystemExit(
            "bootstrap direct Popen assignment oracle drifted"
        ) from popen_caught
    if created_processes[0].poll() is None:
        require_popen_reaped(
            created_processes[0],
            "bootstrap direct Popen emergency target",
        )
        raise SystemExit("bootstrap direct Popen oracle leaked its child")

    original_fork = os.fork
    created_children: list[int] = []
    fork_cancellation = KeyboardInterrupt(
        "bootstrap direct fork assignment cancellation"
    )

    def fork_then_cancel() -> int:
        child = original_fork()
        if child > 0:
            created_children.append(child)
        raise fork_cancellation

    os.fork = fork_then_cancel
    fork_caught: BaseException | None = None
    fork_owner = FixtureChildOwner()
    try:
        try:
            spawn_fixture_child(
                fork_owner,
                lambda: 0,
                "bootstrap direct fork oracle",
            )
        except BaseException as exc:
            fork_caught = settle_fixture_child_owner(
                fork_owner,
                exc,
                "bootstrap direct fork oracle",
            )
    finally:
        os.fork = original_fork
    if fork_caught is not fork_cancellation or len(created_children) != 1:
        raise SystemExit(
            "bootstrap direct fork assignment oracle drifted"
        ) from fork_caught
    try:
        os.waitpid(created_children[0], os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise SystemExit("bootstrap direct fork oracle left an unreaped child")

    pidfd_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        pidfd_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap direct pidfd oracle target",
    )
    assert pidfd_process_owner.process is not None
    pidfd_process = pidfd_process_owner.process
    original_pidfd_open = os.pidfd_open
    created_pidfds: list[int] = []
    pidfd_cancellation = KeyboardInterrupt(
        "bootstrap direct pidfd assignment cancellation"
    )

    def pidfd_then_cancel(pid: int, flags: int) -> int:
        descriptor = original_pidfd_open(pid, flags)
        created_pidfds.append(descriptor)
        raise pidfd_cancellation

    os.pidfd_open = pidfd_then_cancel
    pidfd_caught: BaseException | None = None
    pidfd_owner = FixtureDescriptorOwner()
    try:
        try:
            open_owned_fixture_pidfd(
                pidfd_owner,
                pidfd_process.pid,
                "bootstrap direct pidfd oracle",
            )
        except BaseException as exc:
            pidfd_caught = exc
    finally:
        os.pidfd_open = original_pidfd_open
        pidfd_caught = settle_fixture_popen_owner(
            pidfd_process_owner,
            pidfd_caught,
            "bootstrap direct pidfd oracle target",
        )
    if (
        pidfd_caught is not pidfd_cancellation
        or len(created_pidfds) != 1
        or pidfd_owner.descriptor != -1
    ):
        raise SystemExit(
            "bootstrap direct pidfd assignment oracle drifted"
        ) from pidfd_caught
    try:
        os.fstat(created_pidfds[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        os.close(created_pidfds[0])
        raise SystemExit("bootstrap direct pidfd oracle leaked its descriptor")

    validation_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        validation_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap pidfd validation oracle target",
    )
    assert validation_process_owner.process is not None
    validation_process = validation_process_owner.process
    original_get_inheritable = os.get_inheritable
    validation_pidfds: list[int] = []
    validation_cancellation = KeyboardInterrupt(
        "bootstrap pidfd validation cancellation"
    )

    def record_validation_pidfd(pid: int, flags: int) -> int:
        descriptor = original_pidfd_open(pid, flags)
        validation_pidfds.append(descriptor)
        return descriptor

    def cancel_validation(descriptor: int) -> bool:
        if descriptor in validation_pidfds:
            raise validation_cancellation
        return original_get_inheritable(descriptor)

    os.pidfd_open = record_validation_pidfd
    os.get_inheritable = cancel_validation
    validation_caught: BaseException | None = None
    validation_owner = FixtureDescriptorOwner()
    try:
        try:
            open_owned_fixture_pidfd(
                validation_owner,
                validation_process.pid,
                "bootstrap pidfd validation oracle",
            )
        except BaseException as exc:
            validation_caught = exc
    finally:
        os.get_inheritable = original_get_inheritable
        os.pidfd_open = original_pidfd_open
        validation_caught = settle_fixture_popen_owner(
            validation_process_owner,
            validation_caught,
            "bootstrap pidfd validation oracle target",
        )
    if (
        validation_caught is not validation_cancellation
        or len(validation_pidfds) != 1
        or validation_owner.descriptor != -1
    ):
        raise SystemExit(
            "bootstrap pidfd validation custody oracle drifted"
        ) from validation_caught
    try:
        os.fstat(validation_pidfds[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        os.close(validation_pidfds[0])
        raise SystemExit("bootstrap pidfd validation oracle leaked its descriptor")

    snapshot_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        snapshot_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap pidfd recovery-snapshot oracle target",
    )
    assert snapshot_process_owner.process is not None
    snapshot_process = snapshot_process_owner.process
    original_snapshot_fstat = os.fstat
    snapshot_pidfds: list[int] = []
    snapshot_fstat_failed = False
    snapshot_cancellation = KeyboardInterrupt(
        "bootstrap pidfd recovery-snapshot cancellation"
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
            open_owned_fixture_pidfd(
                snapshot_owner,
                snapshot_process.pid,
                "bootstrap pidfd recovery-snapshot oracle",
            )
        except BaseException as exc:
            snapshot_caught = exc
    finally:
        os.fstat = original_snapshot_fstat
        os.pidfd_open = original_pidfd_open
        snapshot_caught = settle_fixture_popen_owner(
            snapshot_process_owner,
            snapshot_caught,
            "bootstrap pidfd recovery-snapshot oracle target",
        )
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
            "bootstrap pidfd recovery-snapshot custody drifted"
        ) from snapshot_caught

    original_owned_pidfd = globals()["open_owned_fixture_pidfd"]
    owner_slot_descriptors: list[int] = []
    owner_slot_cancelled = False
    owner_slot_cancellation = KeyboardInterrupt(
        "bootstrap fixture root pidfd helper-return cancellation"
    )

    def cancel_root_after_owned_pidfd(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
        *,
        validate: bool = True,
    ) -> None:
        nonlocal owner_slot_cancelled
        original_owned_pidfd(owner, pid, label, validate=validate)
        if not owner_slot_cancelled and "root pidfd" in label:
            owner_slot_cancelled = True
            owner_slot_descriptors.append(owner.descriptor)
            raise owner_slot_cancellation

    globals()["open_owned_fixture_pidfd"] = cancel_root_after_owned_pidfd
    owner_slot_caught: BaseException | None = None
    try:
        try:
            fixture_run_process(
                ["/usr/bin/sleep", "30"],
                cwd,
                timeout=5.0,
            )
        except BaseException as exc:
            owner_slot_caught = exc
    finally:
        globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
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
    if (
        owner_slot_caught is not owner_slot_cancellation
        or not owner_slot_cancelled
        or len(owner_slot_descriptors) != 1
        or not owner_slot_closed
    ):
        raise SystemExit(
            "bootstrap fixture root pidfd owner-slot custody drifted"
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
    spawn_fixture_child(
        descendant_child_owner,
        descendant_child_main,
        "bootstrap fixture descendant pidfd target spawn",
    )
    descendant_child = descendant_child_owner.pid
    descendant_descriptors: list[int] = []
    descendant_cancelled = False
    descendant_cancellation = KeyboardInterrupt(
        "bootstrap fixture descendant pidfd helper-return cancellation"
    )

    def cancel_descendant_after_owned_pidfd(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
        *,
        validate: bool = True,
    ) -> None:
        nonlocal descendant_cancelled
        original_owned_pidfd(owner, pid, label, validate=validate)
        if pid == descendant_child and not descendant_cancelled:
            descendant_cancelled = True
            descendant_descriptors.append(owner.descriptor)
            raise descendant_cancellation

    globals()["open_owned_fixture_pidfd"] = cancel_descendant_after_owned_pidfd
    descendant_caught: BaseException | None = None
    try:
        try:
            fixture_cleanup_descendants(descendant_baseline)
        except BaseException as exc:
            descendant_caught = exc
    finally:
        globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
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
    except ChildProcessError as exc:
        if exc.errno != errno.ECHILD:
            raise
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
            "bootstrap fixture descendant pidfd owner-slot custody drifted"
        ) from descendant_caught


def fixture_restore_subreaper(previous: bool) -> BaseException | None:
    first_error: BaseException | None = None
    for _ in range(3):
        try:
            fixture_set_subreaper(previous)
        except BaseException as exc:
            first_error = fixture_choose_failure(
                first_error,
                exc,
                "bootstrap fixture subreaper restore also failed",
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
            "bootstrap fixture descendant cleanup also failed",
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
                    "bootstrap fixture descendant cleanup encountered errors"
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
                        open_owned_fixture_pidfd(
                            owner,
                            pid,
                            "bootstrap fixture descendant pidfd handoff",
                            validate=False,
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
                                    "bootstrap fixture descendant pidfd "
                                    "registration close also failed",
                                )
                            if not closed:
                                exc = fixture_choose_failure(
                                    exc,
                                    FixtureCleanupError(
                                        "bootstrap fixture descendant pidfd "
                                        "registration did not converge"
                                    ),
                                    "bootstrap fixture descendant pidfd "
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
                            descriptor, signal.SIGKILL, None, 0
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
            "bootstrap fixture descendant cleanup did not converge"
        )
        if cleanup_error is not None:
            selected = fixture_choose_failure(
                failure,
                cleanup_error,
                "bootstrap fixture descendant cleanup did not converge",
            )
            if selected is failure:
                failure.__cause__ = cleanup_error
            raise selected
        raise failure
    if remaining_unknown or cleanup_error is not None:
        if cleanup_error is not None and not isinstance(cleanup_error, Exception):
            raise cleanup_error
        failure = FixtureCleanupError(
            "bootstrap fixture descendant cleanup encountered errors"
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
                        "bootstrap fixture pidfd preflight handoff close failed",
                    )
                    descriptors[slot] = -1
                else:
                    selected = fixture_recover_descriptor_handoff(
                        baseline,
                        (null_metadata.st_dev, null_metadata.st_ino),
                        selected,
                        "bootstrap fixture pidfd preflight open",
                    )
                assert selected is not None
                fixture_raise_selected_failure(selected)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            primary = exc
        else:
            primary = FixtureCleanupError(
                "bootstrap fixture has insufficient pidfd capacity"
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
                        "bootstrap fixture pidfd preflight cleanup failed"
                    )
                    primary.__cause__ = close_error
            else:
                primary = fixture_choose_failure(
                    primary,
                    close_error,
                    "bootstrap fixture pidfd preflight cleanup failed",
                )
        if not closed:
            primary = fixture_choose_failure(
                primary,
                FixtureCleanupError(
                    "bootstrap fixture pidfd preflight cleanup did not converge"
                ),
                "bootstrap fixture pidfd preflight cleanup also failed",
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
        raise FixtureCleanupError("bootstrap fixture cannot initialize signal custody")
    for signum in signals:
        if libc.sigaddset(ctypes.byref(new_mask), int(signum)) != 0:
            raise FixtureCleanupError("bootstrap fixture cannot initialize signal custody")
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
                "bootstrap fixture requires bounded pending-signal custody"
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
            "bootstrap fixture pending-signal custody did not converge"
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
                "bootstrap fixture signal-custody setup failed",
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
                        "bootstrap fixture original signal-mask recovery failed",
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
                        "bootstrap fixture cancellation block failed",
                    )
                try:
                    current = frozenset(
                        signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    )
                except BaseException as exc:
                    primary = self.remember(
                        primary,
                        exc,
                        "bootstrap fixture cancellation state inspection failed",
                    )
                    continue
                if self.signals <= current:
                    cancellation_blocked = True
                    break
            if not cancellation_blocked:
                primary = self.remember(
                    primary,
                    FixtureCleanupError(
                        "bootstrap fixture cancellation block did not converge"
                    ),
                    "bootstrap fixture cancellation block did not converge",
                )
        if cancellation_blocked:
            try:
                self.consume_pending()
            except BaseException as exc:
                primary = self.remember(
                    primary,
                    exc,
                    "bootstrap fixture pending-signal cleanup failed",
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
                            "bootstrap fixture signal-handler restore failed",
                        )
                if not restored:
                    primary = self.remember(
                        primary,
                        FixtureCleanupError(
                            "bootstrap fixture signal-handler restore did not converge"
                        ),
                        "bootstrap fixture signal-handler restore did not converge",
                    )
            try:
                self.consume_pending()
            except BaseException as exc:
                primary = self.remember(
                    primary,
                    exc,
                    "bootstrap fixture pending-signal handoff failed",
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
                        "bootstrap fixture signal-mask restore failed",
                    )
            if not mask_restored:
                primary = self.remember(
                    primary,
                    FixtureCleanupError(
                        "bootstrap fixture signal-mask restore did not converge"
                    ),
                    "bootstrap fixture signal-mask restore did not converge",
                )
        self.closed = True
        if self.cleanup_failure is not None and isinstance(
            primary,
            subprocess.TimeoutExpired,
        ):
            failure = FixtureCleanupError(
                "bootstrap fixture signal-custody cleanup failed after timeout"
            )
            failure.__cause__ = self.cleanup_failure
            failure.add_note("bootstrap fixture subprocess timeout occurred first")
            primary = failure
        if self.signum is not None:
            policy = FixturePublicFailure(128 + self.signum)
            primary = fixture_choose_failure(
                primary,
                policy,
                "bootstrap fixture cancellation followed an earlier failure",
            )
        return primary


class FixtureOwnerSignalLatch(FixtureSignalLatch):
    """Interrupt an owner body once, then latch throughout its finalizer."""

    def __init__(self) -> None:
        super().__init__()
        self.finalizing = False
        self.body_unwind_started = False

    def record(self, signum: int, _frame=None) -> None:
        super().record(signum, _frame)
        if self.finalizing or self.body_unwind_started:
            return
        self.body_unwind_started = True
        interrupted = sys.exc_info()[1]
        caller_policy = (
            interrupted
            if interrupted is not None
            and not isinstance(interrupted, Exception)
            and not isinstance(
                interrupted,
                (FixtureOwnerBodySignal, FixturePublicFailure),
            )
            else None
        )
        raise FixtureOwnerBodySignal(signum, caller_policy)

    def begin_finalizer(self) -> None:
        # Python dispatches handlers between bytecodes, so this assignment is
        # the single atomic body/finalizer transition observed by record().
        self.finalizing = True

    def close(
        self,
        primary: BaseException | None,
    ) -> BaseException | None:
        if isinstance(primary, FixtureOwnerBodySignal):
            primary = primary.caller_policy
        return super().close(primary)


def fixture_open_descriptor_set(
    partial_descriptors: set[int] | None = None,
) -> frozenset[int]:
    table_path = "/proc/self/fd"
    table_metadata = os.stat(table_path, follow_symlinks=False)
    if not stat.S_ISDIR(table_metadata.st_mode):
        raise FixtureCleanupError(
            "bootstrap fixture descriptor table is not a directory"
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
                    "bootstrap fixture descriptor table exceeds its bound"
                )
            if not entry.name.isascii() or not entry.name.isdecimal():
                raise FixtureCleanupError(
                    "bootstrap fixture descriptor table is malformed"
                )
            descriptor = int(entry.name, 10)
            if str(descriptor) != entry.name:
                raise FixtureCleanupError(
                    "bootstrap fixture descriptor table is noncanonical"
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
                "bootstrap fixture descriptor-table acquisition",
            )
    if entries is not None:
        primary = fixture_settle_scandir_iterator(
            entries,
            primary,
            "bootstrap fixture descriptor-table iterator",
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
            "bootstrap fixture descriptor table changed during enumeration"
        )
    live: set[int] = set()
    for descriptor in sorted(parsed):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise FixtureCleanupError(
                "bootstrap fixture descriptor-table entry probe failed"
            ) from exc
        except BaseException:
            raise
        live.add(descriptor)
    return frozenset(live)


def fixture_environment(cwd: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(cwd / "home"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def fixture_gate_transcript(
    launcher_module,
    *,
    dispatch: bool = False,
    release_tag: str = "",
) -> bytes:
    lines = [
        "schema\ttb321fu.haptics-workflow-gate/v1",
        f"trusted-commit\t{launcher_module.TRUSTED_COMMIT}",
        f"candidate-commit\t{launcher_module.CANDIDATE_COMMIT}",
        f"gate-sha256\t{launcher_module.GATE_SHA256}",
        f"workflow-sha256\t{launcher_module.WORKFLOW_SHA256}",
        "validator-sha256\t"
        f"{launcher_module.BOUNDARY_VALIDATOR_PATH}\t"
        f"{launcher_module.BOUNDARY_VALIDATOR_SHA256}",
        "validator-sha256\t"
        f"{launcher_module.ISOLATION_VALIDATOR_PATH}\t"
        f"{launcher_module.ISOLATION_VALIDATOR_SHA256}",
        f"validator-mode\t{launcher_module.GATE_VALIDATOR_MODE}",
    ]
    if not dispatch:
        lines.append("HAPTICS_WORKFLOW_GATE_VERIFY=PASS")
    else:
        dispatch_id = "0123456789abcdef0123456789abcdef"
        run_id = "42"
        lines.extend(
            (
                f"repository\t{launcher_module.REPOSITORY}",
                f"remote-ref\t{launcher_module.REMOTE_REF}",
                f"release-tag\t{release_tag or '-'}",
                f"run-id\t{run_id}",
                f"run-display-title\thaptics-dispatch-{dispatch_id}",
                f"run-head-branch\t{launcher_module.REMOTE_REF}",
                f"run-head-sha\t{launcher_module.CANDIDATE_COMMIT}",
                "run-url\t"
                f"https://github.com/{launcher_module.REPOSITORY}/actions/runs/{run_id}",
                f"dispatch-id\t{dispatch_id}",
                f"input-sha256\t{'1' * 64}",
                f"dispatch-state-sha256\t{'2' * 64}",
                "HAPTICS_WORKFLOW_DISPATCH=PASS",
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def fixture_bootstrap_transcript(
    launcher_module,
    gate_transcript: bytes,
) -> str:
    return "".join(
        (
            "schema\ttb321fu.haptics-workflow-bootstrap/v1\n",
            f"trusted-commit\t{launcher_module.TRUSTED_COMMIT}\n",
            f"candidate-commit\t{launcher_module.CANDIDATE_COMMIT}\n",
            f"gate-sha256\t{launcher_module.GATE_SHA256}\n",
            f"workflow-sha256\t{launcher_module.WORKFLOW_SHA256}\n",
            "validator-sha256\t"
            f"{launcher_module.BOUNDARY_VALIDATOR_PATH}\t"
            f"{launcher_module.BOUNDARY_VALIDATOR_SHA256}\n",
            "validator-sha256\t"
            f"{launcher_module.ISOLATION_VALIDATOR_PATH}\t"
            f"{launcher_module.ISOLATION_VALIDATOR_SHA256}\n",
            gate_transcript.decode("utf-8"),
            "HAPTICS_WORKFLOW_BOOTSTRAP=PASS\n",
        )
    )


def test_gate_transcript_exactness(launcher_module) -> None:
    verify = fixture_gate_transcript(launcher_module).decode("utf-8")
    launcher_module.require_gate_transcript(
        verify,
        dispatch=False,
        release_tag="",
    )
    dispatch = fixture_gate_transcript(
        launcher_module,
        dispatch=True,
        release_tag=launcher_module.RELEASE_TAG,
    ).decode("utf-8")
    launcher_module.require_gate_transcript(
        dispatch,
        dispatch=True,
        release_tag=launcher_module.RELEASE_TAG,
    )
    hostile = (
        verify[:-1],
        verify.replace("\n", "\r\n"),
        verify + "extra\tline\n",
        verify + "HAPTICS_WORKFLOW_GATE_VERIFY=PASS\n",
        dispatch[:-1],
        dispatch.replace("\n", "\r\n"),
        dispatch + "extra\tline\n",
        dispatch + "HAPTICS_WORKFLOW_DISPATCH=PASS\n",
    )
    for output in hostile:
        try:
            launcher_module.require_gate_transcript(
                output,
                dispatch="HAPTICS_WORKFLOW_DISPATCH=PASS" in output,
                release_tag=launcher_module.RELEASE_TAG,
            )
        except launcher_module.BootstrapError:
            continue
        raise SystemExit("bootstrap accepted a non-canonical gate transcript")


def fixture_run_process(
    arguments: list[str],
    cwd: pathlib.Path,
    *,
    environment: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[bytes]:
    if (
        not arguments
        or timeout <= 0
        or type(pass_fds) is not tuple
        or any(type(descriptor) is not int or descriptor < 0 for descriptor in pass_fds)
        or len(set(pass_fds)) != len(pass_fds)
    ):
        raise SystemExit("bootstrap fixture process inputs are invalid")
    signal_latch = FixtureSignalLatch()
    signal_latch.enter()
    try:
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise FixturePublicFailure(
                "bootstrap fixture requires default SIGCHLD policy"
            )
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        previous_subreaper = fixture_get_subreaper()
    except BaseException as exc:
        selected = signal_latch.close(exc)
        assert selected is not None
        fixture_raise_selected_failure(selected)
    try:
        fixture_set_subreaper(True)
    except BaseException as exc:
        restore_error = fixture_restore_subreaper(previous_subreaper)
        if restore_error is not None:
            exc = fixture_choose_failure(
                exc,
                restore_error,
                "bootstrap fixture initial subreaper rollback also failed",
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
                "bootstrap fixture inherited pre-existing children"
            )
    except BaseException as exc:
        setup_primary = exc
    if setup_primary is not None:
        restore_error = fixture_restore_subreaper(previous_subreaper)
        if restore_error is not None:
            setup_primary = fixture_choose_failure(
                setup_primary,
                restore_error,
                "bootstrap fixture setup subreaper restore failed; an earlier "
                "fixture failure also occurred",
            )
        selected = signal_latch.close(setup_primary)
        assert selected is not None
        fixture_raise_selected_failure(selected)
    process: subprocess.Popen[bytes] | None = None
    # This owner is fully settled by fixture_run_process's own finally block;
    # it must not depend on a caller lifetime (git/run helpers are also used
    # by the fixture's unscoped repository-construction phase).
    root_pidfd = _fixture_local_descriptor_owner()
    timed_out = False
    leaked_descendants = False
    primary: BaseException | None = None
    containment_failed = False
    terminal_cancellation: BaseException | None = None

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

    def child_limits() -> None:
        limit = FIXTURE_FILE_LIMIT
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            fixture_preflight_pidfd_capacity()
            try:
                process = subprocess.Popen(
                    arguments,
                    cwd=cwd,
                    env=environment if environment is not None else fixture_environment(cwd),
                    stdin=(subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL),
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True,
                    pass_fds=pass_fds,
                    start_new_session=True,
                    preexec_fn=child_limits,
                )
                open_owned_fixture_pidfd(
                    root_pidfd,
                    process.pid,
                    "bootstrap fixture root pidfd handoff",
                    validate=False,
                )
                wait_deadline = time.monotonic() + timeout
                pending_input = input_bytes
                while process.returncode is None and signal_latch.signum is None:
                    remaining = wait_deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        primary = subprocess.TimeoutExpired(process.args, timeout)
                        break
                    try:
                        process.communicate(
                            input=pending_input,
                            timeout=min(remaining, FIXTURE_SIGNAL_POLL_SECONDS),
                        )
                    except subprocess.TimeoutExpired:
                        pending_input = None
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
                        remember_cleanup(exc, "bootstrap fixture root poll failed")
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
                                    "bootstrap fixture root pidfd signal failed",
                                )
                                numeric_fallback = poll_known
                        if numeric_fallback:
                            numeric_running = False
                            try:
                                numeric_running = process.poll() is None
                            except BaseException as exc:
                                remember_cleanup(
                                    exc,
                                    "bootstrap fixture root numeric custody poll failed",
                                )
                            if numeric_running:
                                # The direct child is unreaped, so its numeric PID
                                # cannot have been reused when pidfd acquisition failed.
                                try:
                                    os.kill(process.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                except BaseException as exc:
                                    remember_cleanup(
                                        exc,
                                        "bootstrap fixture root numeric signal failed",
                                    )
                        try:
                            process.wait(timeout=2.0)
                        except BaseException as exc:
                            remember_cleanup(
                                exc,
                                "bootstrap fixture root wait failed",
                            )
                try:
                    leaked_descendants = fixture_cleanup_descendants(
                        baseline_children
                    )
                except BaseException as exc:
                    remember_cleanup(
                        exc,
                        "bootstrap fixture descendant cleanup failed",
                    )
                if root_pidfd.descriptor >= 0:
                    close_error, closed = fixture_close_owned_descriptor(
                        root_pidfd.descriptor
                    )
                    if close_error is not None:
                        remember_cleanup(
                            close_error,
                            "bootstrap fixture root pidfd close failed",
                        )
                    if closed:
                        root_pidfd.descriptor = -1
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_OUTPUT + 1)
            stderr = stderr_file.read(MAX_OUTPUT + 1)
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
                            "bootstrap fixture root pidfd close also cancelled",
                        )
                        terminal_cancellation.add_note(
                            "bootstrap fixture root pidfd close failed"
                        )
                    else:
                        active.add_note("bootstrap fixture root pidfd close failed")
                else:
                    remember_cleanup(
                        close_error,
                        "bootstrap fixture root pidfd close failed",
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
                        "bootstrap fixture subreaper restore also cancelled",
                    )
                    terminal_cancellation.add_note(
                        "bootstrap fixture subreaper restore failed"
                    )
                else:
                    active.add_note(
                        "bootstrap fixture subreaper restore failed: "
                        f"{type(restore_error).__name__}: {restore_error}"
                    )
            elif primary is not None:
                containment_failed = True
                primary = fixture_choose_failure(
                    primary,
                    restore_error,
                    "bootstrap fixture subreaper restore failed; an earlier "
                    "fixture failure also occurred: "
                    f"{type(restore_error).__name__}: {restore_error}",
                )
            else:
                containment_failed = True
                if not isinstance(restore_error, Exception):
                    primary = restore_error
                else:
                    primary = FixtureCleanupError(
                        "bootstrap fixture subreaper restore failed"
                    )
                    primary.__cause__ = restore_error
        selected = active if active is not None else primary
        if terminal_cancellation is not None:
            selected = fixture_choose_failure(
                selected,
                terminal_cancellation,
                "bootstrap fixture terminal cleanup also cancelled",
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
        raise SystemExit("bootstrap fixture subprocess exceeded its deadline") from primary
    if process is None:
        raise SystemExit("bootstrap fixture process was not created")
    if leaked_descendants:
        raise SystemExit("bootstrap fixture subprocess left descendants")
    if (
        stdout_size > MAX_OUTPUT
        or stderr_size > MAX_OUTPUT
        or len(stdout) > MAX_OUTPUT
        or len(stderr) > MAX_OUTPUT
    ):
        raise SystemExit("bootstrap fixture subprocess output exceeded its bound")
    return subprocess.CompletedProcess(
        arguments,
        process.returncode,
        stdout,
        stderr,
    )


@fixture_owner_scoped
def test_fixture_cleanup_faults(cwd: pathlib.Path) -> None:
    original_scandir = os.scandir
    descriptor_baseline = fixture_open_descriptor_set()
    acquisition_cancellation = KeyboardInterrupt(
        "bootstrap fixture descriptor-table acquisition cancellation"
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
            "bootstrap fixture scandir acquisition custody drifted"
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
                    fixture_run_process(["/usr/bin/true"], cwd)
                except FixturePublicFailure as exc:
                    if str(exc) != (
                        "bootstrap fixture requires default SIGCHLD policy"
                    ):
                        raise
                else:
                    raise SystemExit(
                        "bootstrap fixture accepted inherited SIGCHLD policy"
                    )
                if signal.getsignal(signal.SIGCHLD) is not disposition:
                    raise SystemExit(
                        "bootstrap fixture changed inherited SIGCHLD policy"
                    )
            finally:
                signal.signal(signal.SIGCHLD, previous_sigchld)
    finally:
        subprocess.Popen = sigchld_popen_original
    if sigchld_popen_calls:
        raise SystemExit("bootstrap fixture spawned before SIGCHLD rejection")

    exact_exit = fixture_run_process(["/bin/sh", "-c", "exit 7"], cwd)
    if exact_exit.returncode != 7 or exact_exit.stdout or exact_exit.stderr:
        raise SystemExit("bootstrap fixture lost exact child exit status")

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
        raise SystemExit("bootstrap fixture process short-read oracle drifted")

    original_open = os.open
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
                    f"bootstrap fixture cannot inspect process record {os.getpid()}"
                ):
                    raise
            else:
                raise SystemExit(
                    "bootstrap fixture skipped a live process-record I/O fault"
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
                f"bootstrap fixture process record {os.getpid()} is malformed"
            ):
                raise
        else:
            raise SystemExit("bootstrap fixture accepted a malformed live record")
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
            raise SystemExit("bootstrap fixture exact process-record bound drifted")
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
        or str(overflow) != "bootstrap fixture process record exceeds its bound"
    ):
        raise SystemExit("bootstrap fixture process-record bound oracle drifted")

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
            "bootstrap fixture process-graph complexity oracle drifted"
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
        "bootstrap fixture descriptor-close probe setup",
    )
    probe_descriptor = probe_owner.descriptor
    probe_close_calls = 0
    probe_fstat_calls = 0
    probe_close_failure = OSError(
        "injected bootstrap descriptor nonapplied close failure"
    )
    probe_cancellation = KeyboardInterrupt(
        "injected bootstrap descriptor custody-probe cancellation"
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
        raise SystemExit("bootstrap descriptor-probe cancellation oracle drifted")

    original_open = os.open
    original_close = os.close
    original_reader = globals()["fixture_read_process_record"]
    identity_descriptors: list[int] = []
    identity_close_calls = 0
    identity_cancellation = KeyboardInterrupt(
        "injected bootstrap process-identity read cancellation"
    )

    def record_identity_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == f"/proc/{os.getpid()}/stat":
            identity_descriptors.append(descriptor)
        return descriptor

    def cancel_identity_read(descriptor: int) -> bytes:
        if descriptor in identity_descriptors:
            raise identity_cancellation
        return original_reader(descriptor)

    def fail_identity_close_once(descriptor: int) -> None:
        nonlocal identity_close_calls
        if descriptor in identity_descriptors:
            identity_close_calls += 1
            if identity_close_calls == 1:
                raise OSError(
                    "injected bootstrap process-identity close failure"
                )
        original_close(descriptor)

    os.open = record_identity_open
    os.close = fail_identity_close_once
    globals()["fixture_read_process_record"] = cancel_identity_read
    identity_caught: BaseException | None = None
    try:
        try:
            process_start_time(os.getpid())
        except BaseException as exc:
            identity_caught = exc
    finally:
        globals()["fixture_read_process_record"] = original_reader
        os.close = original_close
        os.open = original_open
    if (
        identity_caught is not identity_cancellation
        or len(identity_descriptors) != 1
        or identity_close_calls != 2
        or "process identity close failed" not in " ".join(
            getattr(identity_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "bootstrap process-identity finalizer masked cancellation"
        ) from identity_caught
    try:
        original_fstat(identity_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        original_close(identity_descriptors[0])
        raise SystemExit("bootstrap process-identity finalizer leaked its fd")

    identity_handoff_descriptors: list[int] = []
    identity_handoff_cancellation = KeyboardInterrupt(
        "injected bootstrap process-identity open handoff cancellation"
    )

    def cancel_identity_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == f"/proc/{os.getpid()}/stat":
            identity_handoff_descriptors.append(descriptor)
            raise identity_handoff_cancellation
        return descriptor

    os.open = cancel_identity_open
    identity_handoff_caught: BaseException | None = None
    try:
        try:
            process_start_time(os.getpid())
        except BaseException as exc:
            identity_handoff_caught = exc
    finally:
        os.open = original_open
    identity_handoff_closed = True
    for descriptor in identity_handoff_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                identity_handoff_closed = False
        else:
            identity_handoff_closed = False
            original_close(descriptor)
    if (
        identity_handoff_caught is not identity_handoff_cancellation
        or len(identity_handoff_descriptors) != 1
        or not identity_handoff_closed
    ):
        raise SystemExit(
            "bootstrap process-identity open handoff custody drifted"
        ) from identity_handoff_caught

    malformed_caught: BaseException | None = None
    globals()["fixture_read_process_record"] = lambda _descriptor: b"malformed"
    try:
        try:
            process_start_time(os.getpid())
        except BaseException as exc:
            malformed_caught = exc
    finally:
        globals()["fixture_read_process_record"] = original_reader
    if (
        not isinstance(malformed_caught, FixtureCleanupError)
        or str(malformed_caught) != "bootstrap fixture process record is malformed"
    ):
        raise SystemExit("bootstrap malformed process-record provenance drifted")

    oversized_identity = cwd / "oversized-process-identity.tsv"
    oversized_identity.write_bytes(b"1\t1\n" + b"x" * 125)
    oversized_caught: BaseException | None = None
    try:
        try:
            read_process_identity(oversized_identity, "oversized fixture")
        except BaseException as exc:
            oversized_caught = exc
    finally:
        oversized_identity.unlink()
    if (
        not isinstance(oversized_caught, SystemExit)
        or str(oversized_caught)
        != "bootstrap oversized fixture identity is malformed"
    ):
        raise SystemExit(
            "bootstrap oversized process-identity bound oracle drifted"
        ) from oversized_caught

    cancellable_identity = cwd / "cancellable-process-identity.tsv"
    cancellable_identity.write_bytes(b"123\t456\n")
    identity_baseline = fixture_open_descriptor_set()
    original_os_read = os.read
    bounded_identity_cancellation = KeyboardInterrupt(
        "injected bounded process-identity read cancellation"
    )

    def cancel_bounded_identity_read(_descriptor: int, _size: int) -> bytes:
        raise bounded_identity_cancellation

    os.read = cancel_bounded_identity_read
    bounded_identity_caught: BaseException | None = None
    try:
        try:
            read_process_identity(cancellable_identity, "cancellable fixture")
        except BaseException as exc:
            bounded_identity_caught = exc
    finally:
        os.read = original_os_read
        cancellable_identity.unlink()
    if (
        bounded_identity_caught is not bounded_identity_cancellation
        or fixture_open_descriptor_set() != identity_baseline
    ):
        raise SystemExit(
            "bootstrap bounded process-identity cancellation custody drifted"
        ) from bounded_identity_caught

    map_descriptors: list[int] = []
    map_close_calls = 0
    map_cancellation = KeyboardInterrupt(
        "injected bootstrap process-map read cancellation"
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
                raise OSError("injected bootstrap process-map close failure")
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
            "bootstrap process-map finalizer masked cancellation"
        ) from map_caught
    try:
        original_fstat(map_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        original_close(map_descriptors[0])
        raise SystemExit("bootstrap process-map finalizer leaked its fd")

    applied_open_descriptors: list[int] = []
    applied_open_cancellation = KeyboardInterrupt(
        "bootstrap fixture process-record open assignment cancellation"
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
            "bootstrap fixture process-record open handoff drifted"
        ) from applied_open_caught
    try:
        original_fstat(applied_open_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        original_close(applied_open_descriptors[0])
        raise SystemExit("bootstrap fixture process-record open handoff leaked fd")

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
            "bootstrap fixture applied-disappearance handoff drifted"
        ) from disappearance_caught

    original_scandir = os.scandir
    iterator_cancellation = KeyboardInterrupt(
        "bootstrap fixture process-table iteration cancellation"
    )
    iterator_close_failure = OSError(
        "bootstrap fixture process-table iterator close failure"
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
            "bootstrap fixture process-table iterator custody drifted"
        ) from iterator_caught

    acquisition_cancellation = KeyboardInterrupt(
        "bootstrap fixture process-table acquisition cancellation"
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
            "bootstrap fixture process-table acquisition custody drifted"
        ) from acquisition_caught

    helper_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        helper_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap poll-custody spawn",
    )
    assert helper_process_owner.process is not None
    helper_process = helper_process_owner.process
    helper_original_poll = helper_process.poll
    helper_descriptors: list[int] = []
    helper_close_calls = 0
    helper_poll_failure = OSError("injected bootstrap helper root poll failure")
    original_pidfd_open = os.pidfd_open

    def fail_helper_poll():
        raise helper_poll_failure

    def record_helper_pidfd(pid: int, flags: int) -> int:
        descriptor = original_pidfd_open(pid, flags)
        if pid == helper_process.pid:
            helper_descriptors.append(descriptor)
        return descriptor

    def fail_helper_close_once(descriptor: int) -> None:
        nonlocal helper_close_calls
        if descriptor in helper_descriptors:
            helper_close_calls += 1
            if helper_close_calls == 1:
                raise OSError("injected bootstrap helper pidfd close failure")
        original_close(descriptor)

    helper_process.poll = fail_helper_poll
    os.pidfd_open = record_helper_pidfd
    os.close = fail_helper_close_once
    helper_caught: BaseException | None = None
    try:
        try:
            require_popen_reaped(helper_process, "poll-custody target")
        except BaseException as exc:
            helper_caught = exc
    finally:
        os.close = original_close
        os.pidfd_open = original_pidfd_open
        helper_process.poll = helper_original_poll
    helper_reaped = helper_original_poll() is not None
    if not helper_reaped:
        try:
            os.kill(helper_process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        helper_process.wait(timeout=2.0)
    if helper_reaped:
        helper_process_owner.process = None
    if (
        helper_caught is not helper_poll_failure
        or not helper_reaped
        or len(helper_descriptors) != 1
        or helper_close_calls != 2
        or "pidfd close failed" not in " ".join(
            getattr(helper_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "bootstrap assertion-helper poll custody oracle drifted"
        ) from helper_caught
    try:
        original_fstat(helper_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        original_close(helper_descriptors[0])
        raise SystemExit("bootstrap assertion-helper leaked its pidfd")

    handoff_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        handoff_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap assertion-helper pidfd handoff spawn",
    )
    assert handoff_process_owner.process is not None
    handoff_process = handoff_process_owner.process
    original_owned_pidfd = globals()["open_owned_fixture_pidfd"]
    handoff_descriptors: list[int] = []
    handoff_cancelled = False
    handoff_cancellation = KeyboardInterrupt(
        "injected bootstrap assertion-helper pidfd handoff cancellation"
    )

    def cancel_assertion_pidfd_after_acquire(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
        *,
        validate: bool = True,
    ) -> None:
        nonlocal handoff_cancelled
        original_owned_pidfd(owner, pid, label, validate=validate)
        if pid == handoff_process.pid and not handoff_cancelled:
            handoff_cancelled = True
            handoff_descriptors.append(owner.descriptor)
            raise handoff_cancellation

    globals()["open_owned_fixture_pidfd"] = cancel_assertion_pidfd_after_acquire
    handoff_caught: BaseException | None = None
    try:
        try:
            require_popen_reaped(
                handoff_process,
                "pidfd handoff target",
            )
        except BaseException as exc:
            handoff_caught = exc
    finally:
        globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
    handoff_reaped = handoff_process.poll() is not None
    if not handoff_reaped:
        try:
            os.kill(handoff_process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        handoff_process.wait(timeout=2.0)
    if handoff_reaped:
        handoff_process_owner.process = None
    handoff_closed = True
    for descriptor in handoff_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                handoff_closed = False
        else:
            handoff_closed = False
            original_close(descriptor)
    if (
        handoff_caught is not handoff_cancellation
        or not handoff_cancelled
        or len(handoff_descriptors) != 1
        or not handoff_reaped
        or not handoff_closed
    ):
        raise SystemExit(
            "bootstrap assertion-helper pidfd handoff custody drifted"
        ) from handoff_caught

    gone_marker = cwd / "process-gone-pidfd-handoff.tsv"
    gone_program = (
        "import os,pathlib,sys,time\n"
        f"{PROCESS_IDENTITY_HELPER}"
        "record_identity(sys.argv[1])\n"
        "time.sleep(30)\n"
    )
    gone_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        gone_process_owner,
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            gone_program,
            str(gone_marker),
        ],
        cwd=cwd,
        label="bootstrap process-gone pidfd handoff spawn",
    )
    assert gone_process_owner.process is not None
    gone_process = gone_process_owner.process
    marker_deadline = time.monotonic() + 2.0
    while not gone_marker.is_file() and time.monotonic() < marker_deadline:
        time.sleep(0.01)
    if not gone_marker.is_file():
        require_popen_reaped(gone_process, "missing process-gone marker target")
        raise SystemExit("bootstrap process-gone handoff marker was not created")
    gone_descriptors: list[int] = []
    gone_cancelled = False
    gone_cancellation = KeyboardInterrupt(
        "injected bootstrap process-gone pidfd handoff cancellation"
    )

    def cancel_gone_pidfd_after_acquire(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
        *,
        validate: bool = True,
    ) -> None:
        nonlocal gone_cancelled
        original_owned_pidfd(owner, pid, label, validate=validate)
        if pid == gone_process.pid and not gone_cancelled:
            gone_cancelled = True
            gone_descriptors.append(owner.descriptor)
            raise gone_cancellation

    globals()["open_owned_fixture_pidfd"] = cancel_gone_pidfd_after_acquire
    gone_caught: BaseException | None = None
    try:
        try:
            require_process_gone(gone_marker, "pidfd handoff target")
        except BaseException as exc:
            gone_caught = exc
    finally:
        globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
    try:
        waited, _ = os.waitpid(gone_process.pid, os.WNOHANG)
    except ChildProcessError:
        gone_reaped = True
    else:
        gone_reaped = False
        if waited == 0:
            try:
                os.kill(gone_process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                gone_process.wait(timeout=2.0)
            except BaseException:
                pass
    if gone_reaped:
        gone_process.poll()
        if gone_process.returncode is not None:
            gone_process_owner.process = None
    gone_closed = True
    for descriptor in gone_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                gone_closed = False
        else:
            gone_closed = False
            original_close(descriptor)
    if gone_marker.exists():
        gone_marker.unlink()
    if (
        gone_caught is not gone_cancellation
        or not gone_cancelled
        or len(gone_descriptors) != 1
        or not gone_reaped
        or not gone_closed
    ):
        raise SystemExit(
            "bootstrap process-gone pidfd handoff custody drifted"
        ) from gone_caught

    original_pidfd_send_signal = signal.pidfd_send_signal
    original_kill = os.kill
    original_process_start_time = globals()["process_start_time"]
    for failure_mode in (
        "retry",
        "applied-then-raise",
        "identity-probe",
        "permanent",
    ):
        bounded_marker = cwd / f"process-gone-bounded-{failure_mode}.tsv"

        def bounded_reap_child_main() -> int:
            time.sleep(0.2 if failure_mode == "permanent" else 30)
            return 0

        bounded_child_owner = FixtureChildOwner()
        spawn_fixture_child(
            bounded_child_owner,
            bounded_reap_child_main,
            f"bootstrap bounded-reap {failure_mode} spawn",
        )
        bounded_child = bounded_child_owner.pid
        bounded_start_time = process_start_time(bounded_child)
        if bounded_start_time is None:
            wait_exact_fixture_child(
                bounded_child,
                f"bootstrap bounded-reap {failure_mode} missing identity",
            )
            raise SystemExit(
                "bootstrap bounded-reap child identity was unavailable"
            )
        bounded_marker.write_text(
            f"{bounded_child}\t{bounded_start_time}\n",
            encoding="ascii",
        )
        bounded_descriptors: list[int] = []
        bounded_handoff_triggered = False
        bounded_signal_calls = 0
        bounded_raw_signal_calls = 0
        bounded_identity_calls = 0
        bounded_handoff_cancellation = KeyboardInterrupt(
            f"injected bootstrap bounded-reap {failure_mode} handoff cancellation"
        )
        bounded_signal_cancellation = KeyboardInterrupt(
            f"injected bootstrap bounded-reap {failure_mode} signal cancellation"
        )

        def cancel_bounded_pidfd_after_acquire(
            owner: FixtureDescriptorOwner,
            pid: int,
            label: str,
            *,
            validate: bool = True,
        ) -> None:
            nonlocal bounded_handoff_triggered
            original_owned_pidfd(owner, pid, label, validate=validate)
            if pid == bounded_child and not bounded_handoff_triggered:
                bounded_handoff_triggered = True
                bounded_descriptors.append(owner.descriptor)
                raise bounded_handoff_cancellation

        def bounded_pidfd_signal(
            descriptor: int,
            signum: int,
            siginfo,
            flags: int,
        ) -> None:
            nonlocal bounded_signal_calls
            if descriptor not in bounded_descriptors:
                original_pidfd_send_signal(descriptor, signum, siginfo, flags)
                return
            bounded_signal_calls += 1
            if failure_mode == "retry" and bounded_signal_calls == 1:
                raise OSError(
                    "injected bootstrap bounded-reap nonapplied signal failure"
                )
            if failure_mode == "permanent":
                raise OSError(
                    "injected bootstrap bounded-reap permanent signal failure"
                )
            original_pidfd_send_signal(descriptor, signum, siginfo, flags)
            if failure_mode == "applied-then-raise":
                raise bounded_signal_cancellation

        def bounded_raw_signal(pid: int, signum: int) -> None:
            nonlocal bounded_raw_signal_calls
            if pid != bounded_child:
                original_kill(pid, signum)
                return
            bounded_raw_signal_calls += 1
            if failure_mode in ("retry", "permanent"):
                raise OSError(
                    f"injected bootstrap bounded-reap {failure_mode} raw signal failure"
                )
            original_kill(pid, signum)

        def bounded_process_start_time(pid: int) -> int | None:
            nonlocal bounded_identity_calls
            if pid == bounded_child and failure_mode == "identity-probe":
                bounded_identity_calls += 1
                if bounded_identity_calls == 1:
                    raise OSError(
                        "injected bootstrap bounded-reap identity probe failure"
                    )
            return original_process_start_time(pid)

        globals()["open_owned_fixture_pidfd"] = cancel_bounded_pidfd_after_acquire
        globals()["process_start_time"] = bounded_process_start_time
        signal.pidfd_send_signal = bounded_pidfd_signal
        os.kill = bounded_raw_signal
        bounded_caught: BaseException | None = None
        bounded_started = time.monotonic()
        try:
            try:
                require_process_gone(
                    bounded_marker,
                    f"bounded-reap {failure_mode} target",
                )
            except BaseException as exc:
                bounded_caught = exc
        finally:
            os.kill = original_kill
            signal.pidfd_send_signal = original_pidfd_send_signal
            globals()["process_start_time"] = original_process_start_time
            globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
        bounded_elapsed = time.monotonic() - bounded_started
        try:
            bounded_waited, _ = os.waitpid(bounded_child, os.WNOHANG)
        except ChildProcessError:
            bounded_reaped_by_helper = True
            bounded_child_owner.pid = -1
            bounded_waited = -1
        else:
            bounded_reaped_by_helper = False
        bounded_probe_waited = bounded_waited
        if not bounded_reaped_by_helper and bounded_waited == 0:
            wait_exact_fixture_child(
                bounded_child,
                f"bootstrap bounded-reap {failure_mode} emergency cleanup",
            )
        bounded_final_reaped = False
        try:
            os.waitpid(bounded_child, os.WNOHANG)
        except ChildProcessError:
            bounded_final_reaped = True
        bounded_closed = True
        for descriptor in bounded_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    bounded_closed = False
            else:
                bounded_closed = False
                original_close(descriptor)
        if bounded_marker.exists():
            bounded_marker.unlink()
        bounded_notes = " ".join(
            getattr(bounded_caught, "__notes__", ())
            if bounded_caught is not None
            else ()
        )
        if failure_mode == "retry":
            expected_signal_state = (
                bounded_signal_calls >= 2
                and bounded_raw_signal_calls == 1
                and bounded_reaped_by_helper
                and bounded_elapsed < 5.0
            )
        elif failure_mode == "applied-then-raise":
            expected_signal_state = (
                bounded_signal_calls >= 1
                and bounded_raw_signal_calls >= 1
                and bounded_reaped_by_helper
                and bounded_elapsed < 5.0
            )
        elif failure_mode == "identity-probe":
            expected_signal_state = (
                bounded_identity_calls >= 2
                and bounded_signal_calls >= 1
                and bounded_raw_signal_calls == 0
                and bounded_reaped_by_helper
                and bounded_elapsed < 5.0
                and "initial identity probe also failed" in bounded_notes
            )
        else:
            expected_signal_state = (
                bounded_signal_calls == 3
                and bounded_raw_signal_calls == 3
                and bounded_reaped_by_helper
                and bounded_elapsed < 5.0
                and "raw signal also failed" in bounded_notes
            )
        if (
            bounded_caught is not bounded_handoff_cancellation
            or not bounded_handoff_triggered
            or len(bounded_descriptors) != 1
            or not bounded_closed
            or not bounded_final_reaped
            or not expected_signal_state
        ):
            raise SystemExit(
                f"bootstrap bounded-reap {failure_mode} custody drifted"
            ) from bounded_caught

    original_monotonic = time.monotonic
    for terminal_mode in ("ordinary", "applied-then-raise"):
        terminal_marker = cwd / f"process-gone-terminal-{terminal_mode}.tsv"

        def terminal_child_main() -> int:
            time.sleep(30)
            return 0

        terminal_child_owner = FixtureChildOwner()
        spawn_fixture_child(
            terminal_child_owner,
            terminal_child_main,
            f"bootstrap terminal-reap {terminal_mode} spawn",
        )
        terminal_child = terminal_child_owner.pid
        terminal_start_time = process_start_time(terminal_child)
        if terminal_start_time is None:
            wait_exact_fixture_child(
                terminal_child,
                f"bootstrap terminal-reap {terminal_mode} missing identity",
            )
            raise SystemExit(
                "bootstrap terminal-reap child identity was unavailable"
            )
        terminal_marker.write_text(
            f"{terminal_child}\t{terminal_start_time}\n",
            encoding="ascii",
        )
        terminal_descriptors: list[int] = []
        terminal_monotonic_calls = 0
        terminal_signal_calls = 0
        terminal_cancellation = KeyboardInterrupt(
            "injected bootstrap terminal-reap signal cancellation"
        )

        def skip_process_gone_poll() -> float:
            nonlocal terminal_monotonic_calls
            terminal_monotonic_calls += 1
            return 0.0 if terminal_monotonic_calls == 1 else 3.0

        def record_terminal_pidfd(
            owner: FixtureDescriptorOwner,
            pid: int,
            label: str,
            *,
            validate: bool = True,
        ) -> None:
            original_owned_pidfd(owner, pid, label, validate=validate)
            if pid == terminal_child:
                terminal_descriptors.append(owner.descriptor)

        def cancel_terminal_signal(
            descriptor: int,
            signum: int,
            siginfo,
            flags: int,
        ) -> None:
            nonlocal terminal_signal_calls
            original_pidfd_send_signal(descriptor, signum, siginfo, flags)
            if descriptor in terminal_descriptors:
                terminal_signal_calls += 1
                if terminal_mode == "applied-then-raise":
                    raise terminal_cancellation

        time.monotonic = skip_process_gone_poll
        globals()["open_owned_fixture_pidfd"] = record_terminal_pidfd
        signal.pidfd_send_signal = cancel_terminal_signal
        terminal_caught: BaseException | None = None
        try:
            try:
                require_process_gone(
                    terminal_marker,
                    f"terminal-reap {terminal_mode} target",
                )
            except BaseException as exc:
                terminal_caught = exc
        finally:
            signal.pidfd_send_signal = original_pidfd_send_signal
            globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
            time.monotonic = original_monotonic
        try:
            os.waitpid(terminal_child, os.WNOHANG)
        except ChildProcessError:
            terminal_reaped = True
            terminal_child_owner.pid = -1
        else:
            terminal_reaped = False
            wait_exact_fixture_child(
                terminal_child,
                f"bootstrap terminal-reap {terminal_mode} emergency cleanup",
            )
        terminal_closed = True
        for descriptor in terminal_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    terminal_closed = False
            else:
                terminal_closed = False
                original_close(descriptor)
        if terminal_marker.exists():
            terminal_marker.unlink()
        expected_terminal_failure = (
            terminal_caught is terminal_cancellation
            if terminal_mode == "applied-then-raise"
            else (
                isinstance(terminal_caught, FixturePublicFailure)
                and str(terminal_caught)
                == (
                    "bootstrap fixture left terminal-reap ordinary target "
                    f"process {terminal_child}"
                )
            )
        )
        if (
            not expected_terminal_failure
            or terminal_monotonic_calls != 2
            or terminal_signal_calls != 1
            or len(terminal_descriptors) != 1
            or not terminal_closed
            or not terminal_reaped
        ):
            raise SystemExit(
                f"bootstrap terminal-reap {terminal_mode} custody drifted"
            ) from terminal_caught

    wait_cancel_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        wait_cancel_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap Popen applied-wait cancellation spawn",
    )
    assert wait_cancel_process_owner.process is not None
    wait_cancel_process = wait_cancel_process_owner.process
    original_waitpid = os.waitpid
    wait_cancel_descriptors: list[int] = []
    wait_cancel_fired = False
    wait_cancellation = KeyboardInterrupt(
        "injected bootstrap Popen applied-wait cancellation"
    )

    def record_wait_cancel_pidfd(
        owner: FixtureDescriptorOwner,
        pid: int,
        label: str,
        *,
        validate: bool = True,
    ) -> None:
        original_owned_pidfd(owner, pid, label, validate=validate)
        if pid == wait_cancel_process.pid:
            wait_cancel_descriptors.append(owner.descriptor)

    def cancel_after_exact_waitpid(pid: int, options: int):
        nonlocal wait_cancel_fired
        result = original_waitpid(pid, options)
        if (
            pid == wait_cancel_process.pid
            and result[0] == pid
            and not wait_cancel_fired
        ):
            wait_cancel_fired = True
            raise wait_cancellation
        return result

    globals()["open_owned_fixture_pidfd"] = record_wait_cancel_pidfd
    os.waitpid = cancel_after_exact_waitpid
    wait_cancel_caught: BaseException | None = None
    try:
        try:
            require_popen_reaped(
                wait_cancel_process,
                "applied-wait cancellation target",
            )
        except BaseException as exc:
            wait_cancel_caught = exc
    finally:
        os.waitpid = original_waitpid
        globals()["open_owned_fixture_pidfd"] = original_owned_pidfd
    try:
        original_waitpid(wait_cancel_process.pid, os.WNOHANG)
    except ChildProcessError:
        wait_cancel_reaped = True
    else:
        wait_cancel_reaped = False
        if wait_cancel_process.poll() is None:
            try:
                original_kill(wait_cancel_process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wait_cancel_process.wait(timeout=2.0)
    wait_cancel_returncode = wait_cancel_process.poll()
    if wait_cancel_reaped and wait_cancel_returncode is not None:
        wait_cancel_process_owner.process = None
    wait_cancel_closed = True
    for descriptor in wait_cancel_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                wait_cancel_closed = False
        else:
            wait_cancel_closed = False
            original_close(descriptor)
    if (
        wait_cancel_caught is not wait_cancellation
        or not wait_cancel_fired
        or len(wait_cancel_descriptors) != 1
        or not wait_cancel_closed
        or not wait_cancel_reaped
        or wait_cancel_returncode is None
    ):
        raise SystemExit(
            "bootstrap Popen applied-wait cancellation custody drifted"
        ) from wait_cancel_caught

    pinned_process_owner = FixturePopenOwner()
    spawn_fixture_popen(
        pinned_process_owner,
        ["/usr/bin/sleep", "30"],
        cwd=cwd,
        label="bootstrap pinned-helper spawn",
    )
    assert pinned_process_owner.process is not None
    pinned_process = pinned_process_owner.process
    pinned_original_poll = pinned_process.poll
    pinned_owner = FixtureDescriptorOwner()
    try:
        open_owned_fixture_pidfd(
            pinned_owner,
            pinned_process.pid,
            "bootstrap pinned-helper",
        )
    except BaseException as exc:
        selected = exc
        if pinned_owner.descriptor >= 0:
            close_error, closed = fixture_close_owned_descriptor(
                pinned_owner.descriptor
            )
            if close_error is not None:
                selected = fixture_choose_failure(
                    selected,
                    close_error,
                    "bootstrap pinned-helper owner close also failed",
                )
            if closed:
                pinned_owner.descriptor = -1
        try:
            require_popen_reaped(
                pinned_process,
                "bootstrap pinned-helper pidfd handoff target",
            )
        except BaseException as cleanup_exc:
            selected = fixture_choose_failure(
                selected,
                cleanup_exc,
                "bootstrap pinned-helper process cleanup also failed",
            )
        fixture_raise_selected_failure(selected)
    pinned_descriptor = pinned_owner.descriptor
    pinned_poll_failure = OSError(
        "injected bootstrap pinned-helper root poll failure"
    )
    pinned_close_calls = 0

    def fail_pinned_poll():
        raise pinned_poll_failure

    def fail_pinned_close_once(descriptor: int) -> None:
        nonlocal pinned_close_calls
        if descriptor == pinned_descriptor:
            pinned_close_calls += 1
            if pinned_close_calls == 1:
                raise OSError(
                    "injected bootstrap pinned-helper pidfd close failure"
                )
        original_close(descriptor)

    pinned_process.poll = fail_pinned_poll
    os.close = fail_pinned_close_once
    pinned_caught: BaseException | None = None
    try:
        try:
            settle_pinned_popen(
                pinned_process,
                pinned_descriptor,
                "pinned-helper target",
            )
        except BaseException as exc:
            pinned_caught = exc
    finally:
        os.close = original_close
        pinned_process.poll = pinned_original_poll
    pinned_reaped = pinned_original_poll() is not None
    if not pinned_reaped:
        try:
            os.kill(pinned_process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        pinned_process.wait(timeout=2.0)
    if pinned_reaped:
        pinned_process_owner.process = None
    if (
        pinned_caught is not pinned_poll_failure
        or not pinned_reaped
        or pinned_close_calls != 2
        or "pinned pidfd close failed" not in " ".join(
            getattr(pinned_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "bootstrap pinned-helper poll custody oracle drifted"
        ) from pinned_caught
    try:
        original_fstat(pinned_descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        pinned_owner.descriptor = -1
    else:
        original_close(pinned_descriptor)
        raise SystemExit("bootstrap pinned-helper leaked its pidfd")

    boundary_launcher = cwd / "cleanup-boundary-launcher.py"
    boundary_raw = b"#!/usr/bin/env python3\n"
    boundary_launcher.write_bytes(boundary_raw)
    boundary_launcher.chmod(0o500)
    RENDERED_LAUNCHER_DIGESTS[boundary_launcher] = hashlib.sha256(
        boundary_raw
    ).hexdigest()
    original_open = os.open
    original_close = os.close
    original_write = os.write
    original_memfd_create = os.memfd_create
    boundary_launcher_descriptor = -1
    boundary_execution_descriptor = -1
    boundary_execution_close_calls = 0
    boundary_launcher_close_calls = 0
    boundary_write_failure = OSError(
        "injected bootstrap execution memfd write failure"
    )
    boundary_cancellation = KeyboardInterrupt(
        "injected bootstrap launcher-fd close cancellation"
    )

    def record_boundary_open(path, flags, *args, **kwargs):
        nonlocal boundary_launcher_descriptor
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == os.fspath(boundary_launcher):
            boundary_launcher_descriptor = descriptor
        return descriptor

    def record_boundary_memfd(name: str, flags: int) -> int:
        nonlocal boundary_execution_descriptor
        boundary_execution_descriptor = original_memfd_create(name, flags)
        return boundary_execution_descriptor

    def fail_boundary_write(descriptor: int, raw: bytes) -> int:
        if descriptor == boundary_execution_descriptor:
            raise boundary_write_failure
        return original_write(descriptor, raw)

    def fail_boundary_closes(descriptor: int) -> None:
        nonlocal boundary_execution_close_calls, boundary_launcher_close_calls
        if descriptor == boundary_execution_descriptor:
            boundary_execution_close_calls += 1
            if boundary_execution_close_calls == 1:
                raise OSError(
                    "injected bootstrap execution memfd nonapplied close failure"
                )
        if descriptor == boundary_launcher_descriptor:
            boundary_launcher_close_calls += 1
            if boundary_launcher_close_calls == 1:
                original_close(descriptor)
                raise boundary_cancellation
        original_close(descriptor)

    os.open = record_boundary_open
    os.memfd_create = record_boundary_memfd
    os.write = fail_boundary_write
    os.close = fail_boundary_closes
    boundary_caught: BaseException | None = None
    try:
        try:
            run_pinned_launcher(
                boundary_launcher,
                cwd,
                ["--verify-only", "--repo-dir", str(cwd)],
            )
        except BaseException as exc:
            boundary_caught = exc
    finally:
        os.close = original_close
        os.write = original_write
        os.memfd_create = original_memfd_create
        os.open = original_open
    boundary_leaked: list[int] = []
    for descriptor in (
        boundary_execution_descriptor,
        boundary_launcher_descriptor,
    ):
        if descriptor < 0:
            continue
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        boundary_leaked.append(descriptor)
        original_close(descriptor)
    RENDERED_LAUNCHER_DIGESTS.pop(boundary_launcher, None)
    boundary_launcher.unlink(missing_ok=True)
    if (
        boundary_caught is not boundary_cancellation
        or boundary_cancellation.__cause__ is not boundary_write_failure
        or boundary_execution_descriptor < 0
        or boundary_launcher_descriptor < 0
        or boundary_execution_close_calls != 2
        or boundary_launcher_close_calls != 1
        or boundary_leaked
        or "execution memfd close failed" not in " ".join(
            getattr(boundary_write_failure, "__notes__", ())
        )
    ):
        raise SystemExit(
            "bootstrap launcher cleanup-boundary oracle drifted: "
            f"leaked={boundary_leaked!r}"
        ) from boundary_caught

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
        or str(preflight_error) != "bootstrap fixture has insufficient pidfd capacity"
        or "bootstrap fixture pidfd preflight cleanup failed" not in preflight_notes
        or not close_injected
    ):
        raise SystemExit("bootstrap fixture preflight did not preserve cleanup evidence")
    for descriptor in acquired:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        else:
            original_close(descriptor)
            raise SystemExit("bootstrap fixture preflight leaked a descriptor")

    preflight_handoff_cancellation = KeyboardInterrupt(
        "bootstrap fixture preflight open handoff cancellation"
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
            "bootstrap fixture preflight open handoff custody drifted"
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
            raise SystemExit("bootstrap cleanup model exceeded its bounded waves")
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
            raise SystemExit("bootstrap cleanup model changed its signal")
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
        != "bootstrap fixture descendant cleanup encountered errors"
        or open_attempts != [101, 102, 103, 104]
        or signal_attempts != [102, 103, 104]
        or process_maps
        or not descendant_close_injected
    ):
        raise SystemExit("bootstrap fixture cleanup faults starved later targets or waves")
    for descriptor in opened:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        else:
            original_close(descriptor)
            raise SystemExit("bootstrap fixture descendant cleanup leaked a pidfd")

    original_owned = globals()["fixture_owned_processes"]
    original_reap = globals()["fixture_reap_owned"]
    original_sleep = time.sleep
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_passes = FIXTURE_PROCESS_PASSES
    nonconvergent_cancellation = KeyboardInterrupt(
        "injected bootstrap nonconvergent cleanup cancellation"
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
            "bootstrap nonconvergent cleanup cancellation oracle drifted"
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
                "bootstrap nonconvergent cleanup leaked a pidfd"
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
            fixture_run_process(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import time;time.sleep(30)",
                ],
                cwd,
                timeout=0.05,
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
        or not any("bootstrap fixture root pidfd signal failed" in note for note in combined_notes)
        or not any("bootstrap fixture descendant cleanup failed" in note for note in combined_notes)
        or not any("bootstrap fixture subreaper restore failed" in note for note in combined_notes)
    ):
        raise SystemExit("bootstrap fixture cleanup faults masked a primary or leaked state")

    cancellation_processes: list[subprocess.Popen[bytes]] = []
    cancellation_cleanup_calls = 0
    cleanup_cancellation = KeyboardInterrupt(
        "injected bootstrap fixture cleanup cancellation"
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
            fixture_run_process(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import time;time.sleep(30)",
                ],
                cwd,
                timeout=0.05,
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
            "bootstrap fixture descendant cleanup failed" in note
            for note in cancellation_notes
        )
        or not any("earlier fixture failure" in note for note in cancellation_notes)
    ):
        raise SystemExit(
            "bootstrap fixture cleanup cancellation lost caller policy"
        ) from cancellation_caught

    original_popen = subprocess.Popen
    original_cleanup = globals()["fixture_cleanup_descendants"]
    poll_failure = OSError("injected bootstrap fixture root poll failure")
    poll_failed = False
    poll_communicate_bypassed = False
    poll_cleanup_calls = 0
    poll_processes: list[tuple[subprocess.Popen[bytes], object]] = []

    def fail_first_root_poll(*args, **kwargs):
        nonlocal poll_failed, poll_communicate_bypassed
        process = original_popen(*args, **kwargs)
        original_poll = process.poll
        original_communicate = process.communicate

        def bypass_initial_communicate(input=None, timeout=None):
            nonlocal poll_communicate_bypassed
            if not poll_communicate_bypassed:
                poll_communicate_bypassed = True
                return (b"", b"")
            return original_communicate(input=input, timeout=timeout)

        def fault_poll():
            nonlocal poll_failed
            if not poll_failed:
                poll_failed = True
                raise poll_failure
            return original_poll()

        process.poll = fault_poll
        process.communicate = bypass_initial_communicate
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
            fixture_run_process(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import time;time.sleep(30)",
                ],
                cwd,
                timeout=0.05,
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
        or not poll_communicate_bypassed
        or len(poll_processes) != 1
        or poll_cleanup_calls != 1
        or not poll_reaped
        or not isinstance(poll_caught, SystemExit)
        or str(poll_caught) != "bootstrap fixture root poll failed"
        or poll_caught.__cause__ is not poll_failure
    ):
        raise SystemExit(
            "bootstrap fixture root-poll custody oracle drifted: "
            f"cleanup_calls={poll_cleanup_calls} reaped={poll_reaped} "
            f"caught={poll_caught!r}"
        ) from poll_caught

    original_restore = globals()["fixture_restore_subreaper"]
    priority_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(priority_initial_subreaper)
    priority_processes: list[subprocess.Popen[bytes]] = []
    priority_cleanup_calls = 0
    priority_restore_calls = 0
    ordinary_cleanup = OSError("injected bootstrap ordinary cleanup failure")
    priority_cancellation = KeyboardInterrupt(
        "injected bootstrap cleanup-priority cancellation"
    )

    def record_priority_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        priority_processes.append(process)
        return process

    def fail_priority_cleanup(_baseline):
        nonlocal priority_cleanup_calls
        priority_cleanup_calls += 1
        raise ordinary_cleanup

    def cancel_priority_restore(previous):
        nonlocal priority_restore_calls
        priority_restore_calls += 1
        applied_error = original_restore(previous)
        if applied_error is not None:
            priority_cancellation.add_note(
                "bootstrap fixture real subreaper restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return priority_cancellation

    subprocess.Popen = record_priority_process
    globals()["fixture_cleanup_descendants"] = fail_priority_cleanup
    globals()["fixture_restore_subreaper"] = cancel_priority_restore
    priority_caught: BaseException | None = None
    try:
        try:
            fixture_run_process(["/usr/bin/true"], cwd)
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
            "bootstrap fixture internal cleanup failure masked cancellation"
        ) from priority_caught

    assignment_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(assignment_initial_subreaper)
    assignment_cancellation = KeyboardInterrupt(
        "injected bootstrap initial subreaper-assignment cancellation"
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
            fixture_run_process(["/usr/bin/true"], cwd)
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
            "bootstrap initial subreaper assignment leaked state"
        ) from assignment_caught

    timeout_initial_subreaper = original_set_subreaper(True)
    original_set_subreaper(timeout_initial_subreaper)
    timeout_processes: list[subprocess.Popen[bytes]] = []
    timeout_restore_calls = 0
    timeout_cancellation = KeyboardInterrupt(
        "injected bootstrap timeout-restore cancellation"
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
                "bootstrap fixture real timeout subreaper restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return timeout_cancellation

    subprocess.Popen = record_timeout_process
    globals()["fixture_restore_subreaper"] = cancel_timeout_restore
    timeout_caught: BaseException | None = None
    try:
        try:
            fixture_run_process(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import time;time.sleep(30)",
                ],
                cwd,
                timeout=0.05,
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
            "bootstrap timeout restore masked caller cancellation"
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
    setup_error = OSError("injected bootstrap setup process-map failure")
    setup_cancellation = KeyboardInterrupt(
        "injected bootstrap setup-restore cancellation"
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
                "bootstrap fixture real setup subreaper restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return setup_cancellation

    globals()["fixture_process_map"] = fail_setup_process_map
    globals()["fixture_restore_subreaper"] = cancel_setup_restore
    setup_caught: BaseException | None = None
    try:
        try:
            fixture_run_process(["/usr/bin/true"], cwd)
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
            "bootstrap setup restore masked caller cancellation"
        ) from setup_caught

    inherited_cancellation = KeyboardInterrupt(
        "injected bootstrap inherited-child restore cancellation"
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
                "bootstrap fixture real inherited-child restore also failed: "
                f"{type(applied_error).__name__}: {applied_error}"
            )
        return inherited_cancellation

    globals()["fixture_process_map"] = inherited_process_map
    globals()["fixture_restore_subreaper"] = cancel_inherited_restore
    inherited_caught: BaseException | None = None
    try:
        try:
            fixture_run_process(["/usr/bin/true"], cwd)
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
            "bootstrap inherited-child policy masked caller cancellation"
        ) from inherited_caught

    baseline_cancellation = KeyboardInterrupt(
        "injected bootstrap baseline-derivation cancellation"
    )

    class CancellingBaseline(dict[int, tuple[int, int]]):
        def items(self):
            raise baseline_cancellation

    globals()["fixture_process_map"] = lambda: CancellingBaseline()
    baseline_caught: BaseException | None = None
    try:
        try:
            fixture_run_process(["/usr/bin/true"], cwd)
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
            "bootstrap baseline cancellation leaked subreaper state"
        ) from baseline_caught


@fixture_owner_scoped
def test_launcher_production_primitives(
    launcher_module,
    private: pathlib.Path,
    gate_raw: bytes,
) -> None:
    pidfd_target_owner = FixturePopenOwner()
    spawn_fixture_popen(
        pidfd_target_owner,
        ["/usr/bin/sleep", "30"],
        cwd=private,
        label="launcher pidfd handoff target spawn",
    )
    assert pidfd_target_owner.process is not None
    pidfd_target = pidfd_target_owner.process
    original_launcher_pidfd_open = launcher_module.os.pidfd_open
    handoff_pidfds: list[int] = []
    handoff_cancellation = KeyboardInterrupt(
        "injected launcher pidfd open handoff cancellation"
    )

    def cancel_launcher_pidfd_open(pid: int, flags: int) -> int:
        descriptor = original_launcher_pidfd_open(pid, flags)
        handoff_pidfds.append(descriptor)
        raise handoff_cancellation

    launcher_module.os.pidfd_open = cancel_launcher_pidfd_open
    handoff_caught: BaseException | None = None
    handoff_owner = launcher_module.DescriptorOwner()
    try:
        try:
            launcher_module.acquire_pidfd(
                handoff_owner,
                pidfd_target.pid,
                "launcher pidfd handoff oracle",
            )
        except BaseException as exc:
            handoff_caught = exc
    finally:
        launcher_module.os.pidfd_open = original_launcher_pidfd_open
        try:
            os.kill(pidfd_target.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        pidfd_target.wait(timeout=2.0)
    try:
        os.waitpid(pidfd_target.pid, os.WNOHANG)
    except ChildProcessError as exc:
        pidfd_target_reaped = exc.errno == errno.ECHILD
    else:
        pidfd_target_reaped = False
    if pidfd_target_reaped and pidfd_target.returncode is not None:
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
        or not pidfd_target_reaped
        or pidfd_target.returncode is None
    ):
        raise SystemExit("launcher pidfd open handoff custody drifted") from handoff_caught

    snapshot_target_owner = FixturePopenOwner()
    spawn_fixture_popen(
        snapshot_target_owner,
        ["/usr/bin/sleep", "30"],
        cwd=private,
        label="launcher pidfd recovery-snapshot target spawn",
    )
    assert snapshot_target_owner.process is not None
    snapshot_target = snapshot_target_owner.process
    original_launcher_fstat = launcher_module.os.fstat
    snapshot_pidfds: list[int] = []
    snapshot_fstat_failed = False
    snapshot_cancellation = KeyboardInterrupt(
        "injected launcher pidfd recovery-snapshot cancellation"
    )

    def cancel_pidfd_before_snapshot(pid: int, flags: int) -> int:
        descriptor = original_launcher_pidfd_open(pid, flags)
        snapshot_pidfds.append(descriptor)
        raise snapshot_cancellation

    def fail_pidfd_snapshot_fstat(descriptor: int):
        nonlocal snapshot_fstat_failed
        if descriptor in snapshot_pidfds and not snapshot_fstat_failed:
            snapshot_fstat_failed = True
            raise OSError(errno.EIO, "injected pidfd recovery snapshot failure")
        return original_launcher_fstat(descriptor)

    launcher_module.os.pidfd_open = cancel_pidfd_before_snapshot
    launcher_module.os.fstat = fail_pidfd_snapshot_fstat
    snapshot_owner = launcher_module.DescriptorOwner()
    snapshot_caught: BaseException | None = None
    try:
        try:
            launcher_module.acquire_pidfd(
                snapshot_owner,
                snapshot_target.pid,
                "launcher pidfd recovery-snapshot oracle",
            )
        except BaseException as exc:
            snapshot_caught = exc
    finally:
        launcher_module.os.fstat = original_launcher_fstat
        launcher_module.os.pidfd_open = original_launcher_pidfd_open
        try:
            os.kill(snapshot_target.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        snapshot_target.wait(timeout=2.0)
    try:
        os.waitpid(snapshot_target.pid, os.WNOHANG)
    except ChildProcessError as exc:
        snapshot_target_reaped = exc.errno == errno.ECHILD
    else:
        snapshot_target_reaped = False
    if snapshot_target_reaped and snapshot_target.returncode is not None:
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
        or not snapshot_target_reaped
        or snapshot_target.returncode is None
    ):
        raise SystemExit(
            "launcher pidfd recovery-snapshot custody drifted"
        ) from snapshot_caught

    original_launcher_acquire_pidfd = launcher_module.acquire_pidfd
    original_launcher_popen = launcher_module.subprocess.Popen
    owner_slot_processes: list[subprocess.Popen[bytes]] = []
    owner_slot_descriptors: list[int] = []
    owner_slot_cancelled = False
    owner_slot_cancellation = KeyboardInterrupt(
        "injected launcher root pidfd helper-return cancellation"
    )

    def record_owner_slot_process(*args, **kwargs):
        process = original_launcher_popen(*args, **kwargs)
        owner_slot_processes.append(process)
        return process

    def cancel_launcher_root_after_acquire(owner, pid: int, label: str) -> None:
        nonlocal owner_slot_cancelled
        original_launcher_acquire_pidfd(owner, pid, label)
        if not owner_slot_cancelled and "root pidfd" in label:
            owner_slot_cancelled = True
            owner_slot_descriptors.append(owner.descriptor)
            raise owner_slot_cancellation

    launcher_module.acquire_pidfd = cancel_launcher_root_after_acquire
    launcher_module.subprocess.Popen = record_owner_slot_process
    owner_slot_caught: BaseException | None = None
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/sleep", "30"],
                cwd=private,
                environment={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": str(private),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="launcher root pidfd owner-slot oracle",
            )
        except BaseException as exc:
            owner_slot_caught = exc
    finally:
        launcher_module.subprocess.Popen = original_launcher_popen
        launcher_module.acquire_pidfd = original_launcher_acquire_pidfd
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
    owner_slot_reaped = all(
        process.returncode is not None for process in owner_slot_processes
    )
    for process in owner_slot_processes:
        if process.returncode is None:
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
        or not owner_slot_closed
        or not owner_slot_reaped
    ):
        raise SystemExit("launcher root pidfd owner-slot custody drifted") from owner_slot_caught

    descendant_map = launcher_module.process_parent_map()
    descendant_baseline = frozenset(
        pid
        for pid, (parent, _) in descendant_map.items()
        if parent == os.getpid()
    )
    def launcher_descendant_child_main() -> int:
        time.sleep(30)
        return 0

    descendant_child_owner = FixtureChildOwner()
    spawn_fixture_child(
        descendant_child_owner,
        launcher_descendant_child_main,
        "launcher descendant pidfd target spawn",
    )
    descendant_child = descendant_child_owner.pid
    descendant_descriptors: list[int] = []
    descendant_cancelled = False
    descendant_cancellation = KeyboardInterrupt(
        "injected launcher descendant pidfd helper-return cancellation"
    )

    def cancel_launcher_descendant_after_acquire(owner, pid: int, label: str) -> None:
        nonlocal descendant_cancelled
        original_launcher_acquire_pidfd(owner, pid, label)
        if pid == descendant_child and not descendant_cancelled:
            descendant_cancelled = True
            descendant_descriptors.append(owner.descriptor)
            raise descendant_cancellation

    launcher_module.acquire_pidfd = cancel_launcher_descendant_after_acquire
    descendant_caught: BaseException | None = None
    try:
        try:
            launcher_module.cleanup_descendants(
                -1,
                descendant_baseline,
                exclude_unreaped_root=False,
            )
        except BaseException as exc:
            descendant_caught = exc
    finally:
        launcher_module.acquire_pidfd = original_launcher_acquire_pidfd
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
    except ChildProcessError as exc:
        if exc.errno != errno.ECHILD:
            raise
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
            "launcher descendant pidfd owner-slot custody drifted"
        ) from descendant_caught

    original_launcher_scandir = launcher_module.os.scandir
    launcher_descriptor_baseline = launcher_module.bounded_fd_snapshot()
    descriptor_acquisition_cancellation = KeyboardInterrupt(
        "launcher descriptor-table acquisition cancellation"
    )
    retained_descriptor_iterators: list[object] = []

    def cancel_launcher_descriptor_acquisition(path):
        entries = original_launcher_scandir(path)
        if os.fspath(path) == "/proc/self/fd":
            retained_descriptor_iterators.append(entries)
            raise descriptor_acquisition_cancellation
        return entries

    launcher_module.os.scandir = cancel_launcher_descriptor_acquisition
    descriptor_acquisition_caught: BaseException | None = None
    try:
        try:
            launcher_module.bounded_fd_snapshot()
        except BaseException as exc:
            descriptor_acquisition_caught = exc
    finally:
        launcher_module.os.scandir = original_launcher_scandir
    descriptor_acquisition_residue = (
        launcher_module.bounded_fd_snapshot() != launcher_descriptor_baseline
    )
    for entries in retained_descriptor_iterators:
        try:
            entries.close()
        except OSError:
            pass
    if (
        descriptor_acquisition_caught is not descriptor_acquisition_cancellation
        or len(retained_descriptor_iterators) != 1
        or descriptor_acquisition_residue
    ):
        raise SystemExit(
            "launcher descriptor-table acquisition custody drifted"
        ) from descriptor_acquisition_caught

    process_acquisition_cancellation = KeyboardInterrupt(
        "launcher process-table acquisition cancellation"
    )
    retained_process_iterators: list[object] = []

    def cancel_launcher_process_acquisition(path):
        entries = original_launcher_scandir(path)
        if os.fspath(path) == "/proc":
            retained_process_iterators.append(entries)
            raise process_acquisition_cancellation
        return entries

    process_descriptor_baseline = launcher_module.bounded_fd_snapshot()
    launcher_module.os.scandir = cancel_launcher_process_acquisition
    process_acquisition_caught: BaseException | None = None
    try:
        try:
            launcher_module.process_parent_map()
        except BaseException as exc:
            process_acquisition_caught = exc
    finally:
        launcher_module.os.scandir = original_launcher_scandir
    process_acquisition_residue = (
        launcher_module.bounded_fd_snapshot() != process_descriptor_baseline
    )
    for entries in retained_process_iterators:
        try:
            entries.close()
        except OSError:
            pass
    if (
        process_acquisition_caught is not process_acquisition_cancellation
        or len(retained_process_iterators) != 1
        or process_acquisition_residue
    ):
        raise SystemExit(
            "launcher process-table acquisition custody drifted"
        ) from process_acquisition_caught

    mismatch_before = launcher_module.bounded_fd_snapshot()
    mismatch_owner = FixtureDescriptorOwner()
    mismatch_metadata = os.stat("/dev/null", follow_symlinks=False)
    acquire_existing_fixture_descriptor(
        mismatch_owner,
        "/dev/null",
        os.O_RDONLY | os.O_CLOEXEC,
        (mismatch_metadata.st_dev, mismatch_metadata.st_ino),
        "launcher mismatch oracle setup",
    )
    mismatch_descriptor = mismatch_owner.descriptor
    mismatch_cancellation = KeyboardInterrupt(
        "injected launcher recovery mismatch cancellation"
    )
    mismatch_selected, mismatch_recovered = (
        launcher_module.recover_descriptor_handoff(
            mismatch_before,
            (0, 0),
            "launcher mismatch oracle",
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
        raise SystemExit("launcher mismatch recovery custody drifted") from mismatch_selected

    launcher_original_open = launcher_module.os.open
    launcher_original_fstat = launcher_module.os.fstat
    replacement_raw = b"#!/usr/bin/env python3\nprint('preserved replacement')\n"
    for failure_kind in ("cancellation", "ordinary-error"):
        recovery_private = private / f"launcher-recovery-fstat-{failure_kind}"
        recovery_private.mkdir(mode=0o700)
        recovery_path = recovery_private / "trusted-dispatch-gate.py"
        recovery_caller = KeyboardInterrupt(
            f"injected launcher reader-open {failure_kind} caller"
        )
        recovery_probe = (
            KeyboardInterrupt("injected launcher recovery fstat cancellation")
            if failure_kind == "cancellation"
            else OSError(errno.EIO, "injected launcher recovery fstat error")
        )
        recovery_descriptors: list[int] = []
        recovery_fstat_calls = 0

        def cancel_recovery_reader_open(path, flags, *args, **kwargs):
            descriptor = launcher_original_open(path, flags, *args, **kwargs)
            if (
                pathlib.Path(path) == recovery_path
                and flags & os.O_ACCMODE == os.O_RDONLY
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
                    recovery_path.chmod(0o500)
                    raise recovery_probe
            return launcher_original_fstat(descriptor)

        launcher_module.os.open = cancel_recovery_reader_open
        launcher_module.os.fstat = fail_recovery_identity_fstat
        recovery_caught: BaseException | None = None
        try:
            try:
                launcher_module.publish_private_gate(recovery_private, gate_raw)
            except BaseException as exc:
                recovery_caught = exc
        finally:
            launcher_module.os.fstat = launcher_original_fstat
            launcher_module.os.open = launcher_original_open
        recovery_live = False
        for descriptor in recovery_descriptors:
            try:
                launcher_original_fstat(descriptor)
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
            recovery_private.rmdir()
            raise SystemExit(
                f"launcher {failure_kind} recovery-fstat custody drifted"
            ) from recovery_caught
        recovery_path.unlink()
        recovery_private.rmdir()

    for failure_kind in ("cancellation", "ordinary-error"):
        partial_private = private / f"launcher-recovery-partial-{failure_kind}"
        partial_private.mkdir(mode=0o700)
        partial_path = partial_private / "trusted-dispatch-gate.py"
        partial_caller = KeyboardInterrupt(
            f"injected launcher partial-scan {failure_kind} caller"
        )
        partial_failure = (
            KeyboardInterrupt("injected launcher partial-scan cancellation")
            if failure_kind == "cancellation"
            else OSError(errno.EIO, "injected launcher partial-scan error")
        )
        partial_descriptors: list[int] = []
        partial_injected = False

        class PartialLauncherDescriptorIterator:
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
                    partial_path.chmod(0o500)
                    raise partial_failure
                entry = next(self.wrapped)
                if partial_descriptors and entry.name == str(partial_descriptors[0]):
                    self.fail_next = True
                return entry

            def close(self) -> None:
                self.wrapped.close()

        def cancel_partial_reader_open(path, flags, *args, **kwargs):
            descriptor = launcher_original_open(path, flags, *args, **kwargs)
            if (
                pathlib.Path(path) == partial_path
                and flags & os.O_ACCMODE == os.O_RDONLY
                and not partial_descriptors
            ):
                partial_descriptors.append(descriptor)
                raise partial_caller
            return descriptor

        def fail_partial_descriptor_scan(path):
            entries = original_launcher_scandir(path)
            if os.fspath(path) == "/proc/self/fd" and partial_descriptors:
                return PartialLauncherDescriptorIterator(entries)
            return entries

        launcher_module.os.open = cancel_partial_reader_open
        launcher_module.os.scandir = fail_partial_descriptor_scan
        partial_caught: BaseException | None = None
        try:
            try:
                launcher_module.publish_private_gate(partial_private, gate_raw)
            except BaseException as exc:
                partial_caught = exc
        finally:
            launcher_module.os.scandir = original_launcher_scandir
            launcher_module.os.open = launcher_original_open
        partial_live = False
        for descriptor in partial_descriptors:
            try:
                launcher_original_fstat(descriptor)
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
            partial_private.rmdir()
            raise SystemExit(
                f"launcher {failure_kind} partial-scan recovery drifted"
            ) from partial_caught
        partial_path.unlink()
        partial_private.rmdir()

    original_read = os.read
    short_payload = b"bootstrap-process-record"
    short_offset = 0
    short_requests: list[int] = []

    def short_read(_descriptor: int, size: int) -> bytes:
        nonlocal short_offset
        short_requests.append(size)
        if short_offset == len(short_payload):
            return b""
        chunk = short_payload[short_offset:short_offset + min(size, 3)]
        short_offset += len(chunk)
        return chunk

    os.read = short_read
    try:
        short_result = launcher_module.read_process_record(901)
    finally:
        os.read = original_read
    if (
        short_result != short_payload
        or len(short_requests) < 2
        or max(short_requests, default=0) > 4097
    ):
        raise SystemExit("bootstrap launcher process short-read oracle drifted")

    overflow_calls = 0

    def overflow_read(_descriptor: int, size: int) -> bytes:
        nonlocal overflow_calls
        overflow_calls += 1
        return b"x" * size

    os.read = overflow_read
    overflow_caught: BaseException | None = None
    try:
        try:
            launcher_module.read_process_record(902)
        except BaseException as exc:
            overflow_caught = exc
    finally:
        os.read = original_read
    if (
        not isinstance(overflow_caught, launcher_module.BootstrapError)
        or str(overflow_caught) != "bootstrap process record exceeds its bound"
        or overflow_calls != 1
    ):
        raise SystemExit("bootstrap launcher process overflow oracle drifted")

    class CountingSnapshot(dict[int, tuple[int, int]]):
        def __init__(self, pairs) -> None:
            super().__init__(pairs)
            self.item_calls = 0

        def items(self):
            self.item_calls += 1
            return super().items()

    chain_pairs: list[tuple[int, tuple[int, int]]] = []
    chain_parent = os.getpid()
    for index in range(128):
        chain_pid = 820000 + index
        chain_pairs.append((chain_pid, (chain_parent, 920000 + index)))
        chain_parent = chain_pid
    reverse_chain = CountingSnapshot(reversed(chain_pairs))
    original_parent_map = launcher_module.process_parent_map
    launcher_module.process_parent_map = lambda: reverse_chain
    try:
        chain_result = launcher_module.owned_descendants(
            chain_pairs[0][0],
            frozenset(),
            exclude_unreaped_root=False,
        )
    finally:
        launcher_module.process_parent_map = original_parent_map
    if (
        chain_result != {pid: state[1] for pid, state in chain_pairs}
        or reverse_chain.item_calls != 1
    ):
        raise SystemExit("bootstrap launcher reverse-chain oracle drifted")

    original_owned_descendants = launcher_module.owned_descendants
    original_pidfd_open = os.pidfd_open
    original_pidfd_signal = signal.pidfd_send_signal
    original_fstat = os.fstat
    start_time_targets = {830001: 930001, 830002: 930002}
    pidfd_owners: dict[int, int] = {}
    signalled: list[int] = []

    def identity_pidfd_open(pid: int, _flags: int) -> int:
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        pidfd_owners[descriptor] = pid
        return descriptor

    def refreshed_descendants(*_args, **_kwargs):
        return {830001: 930001, 830002: 999999}

    def record_pidfd_signal(descriptor: int, _signum, _info, _flags) -> None:
        signalled.append(pidfd_owners[descriptor])

    launcher_module.owned_descendants = refreshed_descendants
    os.pidfd_open = identity_pidfd_open
    signal.pidfd_send_signal = record_pidfd_signal
    try:
        identity_failure = launcher_module.kill_owned_descendants(
            start_time_targets,
            830000,
            frozenset(),
            exclude_unreaped_root=False,
        )
    finally:
        signal.pidfd_send_signal = original_pidfd_signal
        os.pidfd_open = original_pidfd_open
        launcher_module.owned_descendants = original_owned_descendants
    identity_leaks: list[int] = []
    for descriptor in pidfd_owners:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        identity_leaks.append(descriptor)
        os.close(descriptor)
    if identity_failure is not None or signalled != [830001] or identity_leaks:
        raise SystemExit("bootstrap launcher start-time confirmation oracle drifted")

    original_close = os.close
    probe_owner = FixtureDescriptorOwner()
    probe_metadata = os.stat("/dev/null", follow_symlinks=False)
    acquire_existing_fixture_descriptor(
        probe_owner,
        "/dev/null",
        os.O_RDONLY | os.O_CLOEXEC,
        (probe_metadata.st_dev, probe_metadata.st_ino),
        "launcher descriptor-close probe setup",
    )
    probe_descriptor = probe_owner.descriptor
    probe_close_calls = 0
    probe_fstat_calls = 0
    probe_close_failure = OSError("injected launcher nonapplied close failure")
    probe_cancellation = KeyboardInterrupt(
        "injected launcher custody-probe cancellation"
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
        probe_primary, probe_closed = launcher_module.close_owned_descriptor(
            probe_descriptor,
            "launcher probe fixture",
        )
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
        probe_primary is not probe_cancellation
        or not probe_closed
        or not probe_is_closed
        or probe_close_calls != 2
        or probe_fstat_calls != 1
        or not isinstance(probe_cancellation.__cause__, launcher_module.BootstrapError)
        or probe_cancellation.__cause__.__cause__ is not probe_close_failure
    ):
        raise SystemExit("bootstrap launcher custody-probe oracle drifted")

    original_set_subreaper = launcher_module.set_child_subreaper
    original_popen = launcher_module.subprocess.Popen
    original_int_handler = signal.getsignal(signal.SIGINT)
    original_term_handler = signal.getsignal(signal.SIGTERM)
    original_mask = frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
    synthetic_subreaper = False
    synthetic_transitions: list[bool] = []
    baseline_spawned = False

    def synthetic_set_subreaper(enabled: bool) -> bool:
        nonlocal synthetic_subreaper
        previous = synthetic_subreaper
        synthetic_subreaper = enabled
        synthetic_transitions.append(enabled)
        return previous

    def reject_baseline_spawn(*_args, **_kwargs):
        nonlocal baseline_spawned
        baseline_spawned = True
        raise AssertionError("baseline tuple oracle reached Popen")

    launcher_module.process_parent_map = lambda: {
        840001: (os.getpid(), 940001)
    }
    launcher_module.set_child_subreaper = synthetic_set_subreaper
    launcher_module.subprocess.Popen = reject_baseline_spawn
    baseline_caught: BaseException | None = None
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=private,
                environment={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                },
                deadline=time.monotonic() + 2.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="baseline tuple fixture",
            )
        except BaseException as exc:
            baseline_caught = exc
    finally:
        launcher_module.subprocess.Popen = original_popen
        launcher_module.set_child_subreaper = original_set_subreaper
        launcher_module.process_parent_map = original_parent_map
    if (
        not isinstance(baseline_caught, launcher_module.BootstrapError)
        or str(baseline_caught) != "baseline tuple fixture found pre-existing child processes"
        or baseline_spawned
        or synthetic_subreaper
        or synthetic_transitions != [True, False]
        or signal.getsignal(signal.SIGINT) is not original_int_handler
        or signal.getsignal(signal.SIGTERM) is not original_term_handler
        or frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set())) != original_mask
    ):
        raise SystemExit("bootstrap launcher tuple-baseline oracle drifted") from baseline_caught

    root_pidfd = -1
    root_close_calls = 0
    root_close_failure = OSError("injected launcher root pidfd close failure")
    synthetic_subreaper = False
    synthetic_transitions.clear()

    def record_root_pidfd(pid: int, flags: int) -> int:
        nonlocal root_pidfd
        root_pidfd = original_pidfd_open(pid, flags)
        return root_pidfd

    def fail_root_close_once(descriptor: int) -> None:
        nonlocal root_close_calls
        if descriptor == root_pidfd:
            root_close_calls += 1
            if root_close_calls == 1:
                raise root_close_failure
        original_close(descriptor)

    launcher_module.process_parent_map = lambda: {}
    launcher_module.set_child_subreaper = synthetic_set_subreaper
    os.pidfd_open = record_root_pidfd
    os.close = fail_root_close_once
    root_close_caught: BaseException | None = None
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=private,
                environment={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                },
                deadline=time.monotonic() + 2.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="root pidfd close fixture",
            )
        except BaseException as exc:
            root_close_caught = exc
    finally:
        os.close = original_close
        os.pidfd_open = original_pidfd_open
        launcher_module.set_child_subreaper = original_set_subreaper
        launcher_module.process_parent_map = original_parent_map
    if root_pidfd >= 0:
        try:
            original_fstat(root_pidfd)
        except OSError as exc:
            root_pidfd_closed = exc.errno == errno.EBADF
        else:
            root_pidfd_closed = False
            original_close(root_pidfd)
    else:
        root_pidfd_closed = False
    if (
        not isinstance(root_close_caught, launcher_module.BootstrapError)
        or not isinstance(root_close_caught.__cause__, OSError)
        or root_close_caught.__cause__ is not root_close_failure
        or root_close_calls != 2
        or not root_pidfd_closed
        or synthetic_subreaper
        or synthetic_transitions != [True, False]
    ):
        raise SystemExit("bootstrap launcher root-pidfd custody oracle drifted") from root_close_caught

    original_atomic_block = launcher_module.atomic_capture_and_block
    original_pthread_sigmask = signal.pthread_sigmask
    terminal_setup_failure = launcher_module.BootstrapError(
        "injected outer bootstrap setup failure"
    )
    terminal_restore_failure = OSError(
        "injected outer bootstrap nonapplied mask restore failure"
    )
    terminal_cancellation = KeyboardInterrupt(
        "injected outer bootstrap applied mask restore cancellation"
    )
    terminal_restore_calls = 0
    caller_mask = frozenset(
        original_pthread_sigmask(signal.SIG_BLOCK, set())
    )

    def fail_after_atomic_block(signals, capture) -> None:
        previous = original_pthread_sigmask(signal.SIG_BLOCK, signals)
        capture(frozenset(previous))
        raise terminal_setup_failure

    def cancel_terminal_restore(how, mask):
        nonlocal terminal_restore_calls
        if how == signal.SIG_SETMASK and frozenset(mask) == caller_mask:
            terminal_restore_calls += 1
            if terminal_restore_calls == 1:
                raise terminal_restore_failure
            if terminal_restore_calls == 2:
                original_pthread_sigmask(how, mask)
                raise terminal_cancellation
        return original_pthread_sigmask(how, mask)

    launcher_module.atomic_capture_and_block = fail_after_atomic_block
    signal.pthread_sigmask = cancel_terminal_restore
    terminal_caught: BaseException | None = None
    try:
        try:
            launcher_module.BootstrapCancellationGuard().__enter__()
        except BaseException as exc:
            terminal_caught = exc
    finally:
        signal.pthread_sigmask = original_pthread_sigmask
        launcher_module.atomic_capture_and_block = original_atomic_block
        original_pthread_sigmask(signal.SIG_SETMASK, caller_mask)
    if (
        terminal_caught is not terminal_cancellation
        or terminal_restore_calls != 2
        or frozenset(original_pthread_sigmask(signal.SIG_BLOCK, set())) != caller_mask
        or not any(
            "outer bootstrap setup failed before caller policy handoff" in note
            for note in getattr(terminal_caught, "__notes__", ())
        )
    ):
        raise SystemExit(
            "bootstrap terminal-mask cancellation oracle drifted: "
            f"caught={terminal_caught!r} calls={terminal_restore_calls!r} "
            f"mask={frozenset(original_pthread_sigmask(signal.SIG_BLOCK, set()))!r} "
            f"notes={getattr(terminal_caught, '__notes__', ())!r} "
            f"cause={getattr(terminal_caught, '__cause__', None)!r}"
        ) from terminal_caught

    gate_root = private / "production-private-gate-custody"
    gate_root.mkdir(mode=0o700)
    gate_path = gate_root / "trusted-dispatch-gate.py"
    original_open = os.open
    original_unlink = os.unlink
    gate_descriptors: dict[str, int] = {}
    gate_close_calls = {"writer": 0, "reader": 0}
    writer_close_failure = OSError("injected private writer nonapplied close failure")
    reader_close_cancellation = KeyboardInterrupt(
        "injected private reader applied close cancellation"
    )

    def track_gate_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == os.fspath(gate_path):
            role = "writer" if flags & os.O_WRONLY else "reader"
            gate_descriptors[role] = descriptor
        return descriptor

    def fail_gate_closes(descriptor: int) -> None:
        writer = gate_descriptors.get("writer")
        reader = gate_descriptors.get("reader")
        if descriptor == writer:
            gate_close_calls["writer"] += 1
            if gate_close_calls["writer"] == 1:
                raise writer_close_failure
        if descriptor == reader:
            gate_close_calls["reader"] += 1
            if gate_close_calls["reader"] == 1:
                original_close(descriptor)
                raise reader_close_cancellation
        original_close(descriptor)

    os.open = track_gate_open
    os.close = fail_gate_closes
    gate_caught: BaseException | None = None
    try:
        try:
            launcher_module.publish_private_gate(gate_root, gate_raw)
        except BaseException as exc:
            gate_caught = exc
    finally:
        os.close = original_close
        os.open = original_open
    gate_fd_leaks: list[int] = []
    for descriptor in gate_descriptors.values():
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        gate_fd_leaks.append(descriptor)
        original_close(descriptor)
    if gate_path.exists():
        original_unlink(gate_path)
        gate_namespace_absent = False
    else:
        gate_namespace_absent = True
    if (
        gate_caught is not reader_close_cancellation
        or not isinstance(reader_close_cancellation.__cause__, launcher_module.BootstrapError)
        or reader_close_cancellation.__cause__.__cause__ is not writer_close_failure
        or gate_close_calls != {"writer": 2, "reader": 1}
        or gate_fd_leaks
        or not gate_namespace_absent
    ):
        raise SystemExit("bootstrap private-gate close oracle drifted") from gate_caught

    namespace_path = gate_root / "namespace-applied-cancellation"
    namespace_path.write_bytes(b"owned")
    namespace_metadata = namespace_path.stat()
    namespace_primary = launcher_module.BootstrapError(
        "injected earlier private namespace failure"
    )
    namespace_cancellation = KeyboardInterrupt(
        "injected applied private namespace unlink cancellation"
    )
    namespace_unlink_calls = 0

    def cancel_after_namespace_unlink(path) -> None:
        nonlocal namespace_unlink_calls
        if os.fspath(path) == os.fspath(namespace_path):
            namespace_unlink_calls += 1
            original_unlink(path)
            raise namespace_cancellation
        original_unlink(path)

    os.unlink = cancel_after_namespace_unlink
    try:
        namespace_selected, namespace_clean = launcher_module.cleanup_owned_namespace(
            namespace_path,
            (namespace_metadata.st_dev, namespace_metadata.st_ino),
            "private namespace fixture",
            namespace_primary,
        )
    finally:
        os.unlink = original_unlink
    if (
        namespace_selected is not namespace_cancellation
        or namespace_cancellation.__cause__ is not namespace_primary
        or not namespace_clean
        or namespace_unlink_calls != 1
        or namespace_path.exists()
    ):
        raise SystemExit("bootstrap private namespace cleanup oracle drifted")


@fixture_owner_scoped
def test_launcher_process_containment(
    launcher_module,
    private: pathlib.Path,
) -> None:
    process_root = private / "process-containment"
    process_root.mkdir(mode=0o700)
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(process_root),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    sigchld_popen_original = launcher_module.subprocess.Popen
    sigchld_popen_calls = 0

    def count_sigchld_popen(*args, **kwargs):
        nonlocal sigchld_popen_calls
        sigchld_popen_calls += 1
        return sigchld_popen_original(*args, **kwargs)

    launcher_module.subprocess.Popen = count_sigchld_popen
    try:
        for disposition in (signal.SIG_IGN, lambda _signum, _frame: None):
            previous_sigchld = signal.signal(signal.SIGCHLD, disposition)
            try:
                try:
                    launcher_module.run_bounded(
                        ["/bin/sh", "-c", "exit 7"],
                        cwd=process_root,
                        environment=environment,
                        deadline=time.monotonic() + 5.0,
                        stdout_limit=4096,
                        stderr_limit=4096,
                        label="inherited SIGCHLD fixture",
                    )
                except launcher_module.BootstrapError as exc:
                    if str(exc) != (
                        "inherited SIGCHLD fixture requires default SIGCHLD policy"
                    ):
                        raise
                else:
                    raise SystemExit("bootstrap accepted inherited SIGCHLD policy")
                if signal.getsignal(signal.SIGCHLD) is not disposition:
                    raise SystemExit("bootstrap changed inherited SIGCHLD policy")
            finally:
                signal.signal(signal.SIGCHLD, previous_sigchld)
    finally:
        launcher_module.subprocess.Popen = sigchld_popen_original
    if sigchld_popen_calls:
        raise SystemExit("bootstrap spawned before rejecting SIGCHLD policy")

    exact_exit = launcher_module.run_bounded(
        ["/bin/sh", "-c", "exit 7"],
        cwd=process_root,
        environment=environment,
        deadline=time.monotonic() + 5.0,
        stdout_limit=4096,
        stderr_limit=4096,
        label="exact exit-status fixture",
    )
    if exact_exit.returncode != 7 or exact_exit.stdout or exact_exit.stderr:
        raise SystemExit("bootstrap lost exact child exit status")

    process_open_original = launcher_module.os.open
    target_record = f"/proc/{os.getpid()}/stat"
    for injected_errno in (errno.EMFILE, errno.EIO):
        def fail_process_open(path, flags, mode=0o777, *, dir_fd=None):
            if str(path) == target_record:
                raise OSError(injected_errno, os.strerror(injected_errno))
            if dir_fd is None:
                return process_open_original(path, flags, mode)
            return process_open_original(path, flags, mode, dir_fd=dir_fd)

        launcher_module.os.open = fail_process_open
        try:
            try:
                launcher_module.process_parent_map()
            except launcher_module.BootstrapError as exc:
                if str(exc) != (
                    f"cannot inspect bootstrap process record {os.getpid()}"
                ):
                    raise
            else:
                raise SystemExit("bootstrap skipped a live process-record I/O fault")
        finally:
            launcher_module.os.open = process_open_original

    malformed_reader, malformed_writer = os.pipe()
    os.write(malformed_writer, b"malformed")
    os.close(malformed_writer)
    malformed_supplied = False
    malformed_process_fstat_original = launcher_module.os.fstat
    malformed_process_metadata = os.stat(target_record, follow_symlinks=False)

    def malformed_process_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal malformed_supplied
        if str(path) == target_record and not malformed_supplied:
            malformed_supplied = True
            return malformed_reader
        if dir_fd is None:
            return process_open_original(path, flags, mode)
        return process_open_original(path, flags, mode, dir_fd=dir_fd)

    def malformed_launcher_fstat(descriptor: int):
        if descriptor == malformed_reader:
            return malformed_process_metadata
        return malformed_process_fstat_original(descriptor)

    launcher_module.os.open = malformed_process_open
    launcher_module.os.fstat = malformed_launcher_fstat
    try:
        try:
            launcher_module.process_parent_map()
        except launcher_module.BootstrapError as exc:
            if str(exc) != f"bootstrap process record {os.getpid()} is malformed":
                raise
        else:
            raise SystemExit("bootstrap accepted a malformed live process record")
    finally:
        launcher_module.os.fstat = malformed_process_fstat_original
        launcher_module.os.open = process_open_original
        try:
            os.close(malformed_reader)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise

    applied_launcher_descriptors: list[int] = []
    applied_launcher_cancellation = KeyboardInterrupt(
        "launcher process-record open assignment cancellation"
    )
    applied_launcher_fired = False

    def apply_launcher_open_then_cancel(path, flags, *args, **kwargs):
        nonlocal applied_launcher_fired
        descriptor = process_open_original(path, flags, *args, **kwargs)
        if str(path) == target_record and not applied_launcher_fired:
            applied_launcher_fired = True
            applied_launcher_descriptors.append(descriptor)
            raise applied_launcher_cancellation
        return descriptor

    launcher_module.os.open = apply_launcher_open_then_cancel
    applied_launcher_caught: BaseException | None = None
    try:
        try:
            launcher_module.process_parent_map()
        except BaseException as exc:
            applied_launcher_caught = exc
    finally:
        launcher_module.os.open = process_open_original
    if (
        applied_launcher_caught is not applied_launcher_cancellation
        or len(applied_launcher_descriptors) != 1
    ):
        raise SystemExit(
            "bootstrap launcher process-record open handoff drifted"
        ) from applied_launcher_caught
    try:
        os.fstat(applied_launcher_descriptors[0])
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        os.close(applied_launcher_descriptors[0])
        raise SystemExit("bootstrap launcher process-record open handoff leaked fd")

    disappeared_launcher_descriptors: list[int] = []
    disappeared_launcher_fired = False

    def apply_launcher_open_then_disappear(path, flags, *args, **kwargs):
        nonlocal disappeared_launcher_fired
        descriptor = process_open_original(path, flags, *args, **kwargs)
        if str(path) == target_record and not disappeared_launcher_fired:
            disappeared_launcher_fired = True
            disappeared_launcher_descriptors.append(descriptor)
            raise FileNotFoundError(errno.ENOENT, "injected launcher disappearance")
        return descriptor

    launcher_module.os.open = apply_launcher_open_then_disappear
    launcher_disappearance_caught: BaseException | None = None
    try:
        try:
            launcher_module.process_parent_map()
        except BaseException as exc:
            launcher_disappearance_caught = exc
    finally:
        launcher_module.os.open = process_open_original
    launcher_disappearance_leaked = False
    for descriptor in disappeared_launcher_descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            launcher_disappearance_leaked = True
            os.close(descriptor)
    if (
        launcher_disappearance_caught is not None
        or len(disappeared_launcher_descriptors) != 1
        or launcher_disappearance_leaked
    ):
        raise SystemExit(
            "bootstrap launcher applied-disappearance handoff drifted"
        ) from launcher_disappearance_caught

    launcher_scandir_original = launcher_module.os.scandir
    launcher_iterator_cancellation = KeyboardInterrupt(
        "launcher process-table iteration cancellation"
    )
    launcher_iterator_close_failure = OSError(
        "launcher process-table iterator close failure"
    )
    launcher_iterator_close_calls = 0

    class CancellingLauncherIterator:
        def __init__(self, wrapped) -> None:
            self.wrapped = wrapped

        def __iter__(self):
            return self

        def __next__(self):
            raise launcher_iterator_cancellation

        def close(self) -> None:
            nonlocal launcher_iterator_close_calls
            launcher_iterator_close_calls += 1
            if launcher_iterator_close_calls == 1:
                raise launcher_iterator_close_failure
            self.wrapped.close()

    def cancelling_launcher_scandir(path):
        entries = launcher_scandir_original(path)
        if os.fspath(path) == "/proc":
            return CancellingLauncherIterator(entries)
        return entries

    launcher_before_descriptors = launcher_module.bounded_fd_snapshot()
    launcher_module.os.scandir = cancelling_launcher_scandir
    launcher_iterator_caught: BaseException | None = None
    try:
        try:
            launcher_module.process_parent_map()
        except BaseException as exc:
            launcher_iterator_caught = exc
    finally:
        launcher_module.os.scandir = launcher_scandir_original
    if (
        launcher_iterator_caught is not launcher_iterator_cancellation
        or launcher_iterator_close_calls != 2
        or launcher_module.bounded_fd_snapshot() != launcher_before_descriptors
        or "iterator close also failed"
        not in " ".join(getattr(launcher_iterator_caught, "__notes__", ()))
    ):
        raise SystemExit(
            "bootstrap launcher process-table iterator custody drifted"
        ) from launcher_iterator_caught

    original_parent_map = launcher_module.process_parent_map
    launcher_module.process_parent_map = lambda: {5001: (4242, 15001)}
    try:
        if launcher_module.owned_descendants(
            4242,
            frozenset(),
            exclude_unreaped_root=False,
        ):
            raise SystemExit("bootstrap trusted a reused root PID ancestry")
    finally:
        launcher_module.process_parent_map = original_parent_map
    oversized_parent_map = {
        10000 + index: (os.getpid(), 20000 + index)
        for index in range(launcher_module.MAX_DESCENDANT_PROCESSES + 73)
    }
    launcher_module.process_parent_map = lambda: oversized_parent_map
    try:
        bounded_descendants = launcher_module.owned_descendants(
            9000,
            frozenset(),
            exclude_unreaped_root=False,
        )
    finally:
        launcher_module.process_parent_map = original_parent_map
    if len(bounded_descendants) != launcher_module.MAX_DESCENDANT_PROCESSES:
        raise SystemExit("bootstrap oversized descendant set was not bounded")

    reused_root_map = {
        10: (os.getpid(), 10010),
        42: (10, 10042),
    }
    launcher_module.process_parent_map = lambda: reused_root_map
    try:
        reused_root_descendants = launcher_module.owned_descendants(
            42,
            frozenset(),
            exclude_unreaped_root=False,
        )
        live_root_descendants = launcher_module.owned_descendants(
            42,
            frozenset(),
            exclude_unreaped_root=True,
        )
    finally:
        launcher_module.process_parent_map = original_parent_map
    if reused_root_descendants != {10: 10010, 42: 10042} or (
        live_root_descendants != {10: 10010}
    ):
        raise SystemExit("bootstrap reused-root descendant ownership drifted")

    direct_pids = tuple(
        range(50000, 50000 + FIXTURE_PROCESS_LIMIT)
    )
    later_pid = 70000
    first_fixture_wave = {
        pid: (os.getpid(), pid + 1)
        for pid in direct_pids
    }
    first_fixture_wave[later_pid] = (direct_pids[0], later_pid + 1)
    bounded_fixture_wave = fixture_owned_processes(
        frozenset(),
        process_map=first_fixture_wave,
    )
    later_fixture_wave = fixture_owned_processes(
        frozenset(),
        process_map={later_pid: (os.getpid(), later_pid + 1)},
    )
    if (
        len(bounded_fixture_wave) != FIXTURE_PROCESS_LIMIT
        or later_pid in bounded_fixture_wave
        or later_fixture_wave != {later_pid: later_pid + 1}
    ):
        raise SystemExit("bootstrap fixture descendant bound did not converge")

    fake_descendants = {
        pid: pid + 100000
        for pid in range(
            20000,
            20000 + launcher_module.PIDFD_BATCH_SIZE * 3 + 5,
        )
    }
    original_pidfd_open = launcher_module.os.pidfd_open
    original_pidfd_send_signal = launcher_module.signal.pidfd_send_signal
    original_close = launcher_module.os.close
    original_owned_descendants = launcher_module.owned_descendants
    fake_pidfds: dict[int, int] = {}
    signalled_descendants: set[int] = set()
    maximum_open_pidfds = 0

    def fake_pidfd_open(pid: int, _flags: int) -> int:
        nonlocal maximum_open_pidfds
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        fake_pidfds[descriptor] = pid
        maximum_open_pidfds = max(maximum_open_pidfds, len(fake_pidfds))
        return descriptor

    def fake_pidfd_send_signal(descriptor, signum, _info, _flags):
        if descriptor not in fake_pidfds or signum != signal.SIGKILL:
            raise SystemExit("bootstrap pidfd batch fixture signalled an unknown target")
        signalled_descendants.add(fake_pidfds[descriptor])

    def fake_close(descriptor: int) -> None:
        fake_pidfds.pop(descriptor, None)
        original_close(descriptor)

    launcher_module.os.pidfd_open = fake_pidfd_open
    launcher_module.signal.pidfd_send_signal = fake_pidfd_send_signal
    launcher_module.os.close = fake_close
    launcher_module.owned_descendants = lambda *_args, **_kwargs: dict(
        fake_descendants
    )
    try:
        launcher_module.kill_owned_descendants(
            dict(fake_descendants),
            9000,
            frozenset(),
            exclude_unreaped_root=False,
        )
    finally:
        launcher_module.owned_descendants = original_owned_descendants
        launcher_module.os.close = original_close
        launcher_module.signal.pidfd_send_signal = original_pidfd_send_signal
        launcher_module.os.pidfd_open = original_pidfd_open
    if (
        fake_pidfds
        or signalled_descendants != set(fake_descendants)
        or maximum_open_pidfds > launcher_module.PIDFD_BATCH_SIZE
    ):
        raise SystemExit("bootstrap descendant pidfds were not processed in batches")

    persistent_targets = {101: 1001, 102: 1002, 103: 1003}
    persistent_pidfds: dict[int, int] = {}
    persistent_attempts: list[int] = []

    def persistent_pidfd_open(pid: int, _flags: int) -> int:
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        persistent_pidfds[descriptor] = pid
        return descriptor

    def persistent_pidfd_signal(descriptor, signum, _info, _flags):
        pid = persistent_pidfds[descriptor]
        persistent_attempts.append(pid)
        if pid == min(persistent_targets):
            raise OSError("injected persistent first-target signal failure")
        if signum != signal.SIGKILL:
            raise SystemExit("bootstrap persistent-error oracle changed its signal")

    def persistent_close(descriptor: int) -> None:
        persistent_pidfds.pop(descriptor, None)
        original_close(descriptor)

    launcher_module.os.pidfd_open = persistent_pidfd_open
    launcher_module.signal.pidfd_send_signal = persistent_pidfd_signal
    launcher_module.os.close = persistent_close
    launcher_module.owned_descendants = lambda *_args, **_kwargs: dict(
        persistent_targets
    )
    try:
        persistent_error = launcher_module.kill_owned_descendants(
            dict(persistent_targets),
            9000,
            frozenset(),
            exclude_unreaped_root=False,
        )
    finally:
        launcher_module.owned_descendants = original_owned_descendants
        launcher_module.os.close = original_close
        launcher_module.signal.pidfd_send_signal = original_pidfd_send_signal
        launcher_module.os.pidfd_open = original_pidfd_open
    if (
        not persistent_error
        or persistent_pidfds
        or persistent_attempts != sorted(persistent_targets)
    ):
        raise SystemExit("bootstrap persistent pidfd error starved later targets")

    error_waves = iter(({201: 1201}, {202: 1202}, {}))
    error_kills: list[set[int]] = []
    error_reaps: list[set[int]] = []
    error_original_kill = launcher_module.kill_owned_descendants
    error_original_reap = launcher_module.reap_owned_children
    error_original_sleep = launcher_module.time.sleep
    launcher_module.owned_descendants = (
        lambda *_args, **_kwargs: dict(next(error_waves))
    )
    launcher_module.kill_owned_descendants = (
        lambda descendants, *_args, **_kwargs: (
            error_kills.append(set(descendants))
            or launcher_module.BootstrapError(
                "bootstrap descendant cleanup encountered errors"
            )
        )
    )
    launcher_module.reap_owned_children = (
        lambda descendants: error_reaps.append(set(descendants))
    )
    launcher_module.time.sleep = lambda _seconds: None
    wave_failure: BaseException | None = None
    try:
        try:
            launcher_module.cleanup_descendants(
                9000,
                frozenset(),
                exclude_unreaped_root=False,
            )
        except BaseException as exc:
            wave_failure = exc
    finally:
        launcher_module.time.sleep = error_original_sleep
        launcher_module.reap_owned_children = error_original_reap
        launcher_module.kill_owned_descendants = error_original_kill
        launcher_module.owned_descendants = original_owned_descendants
    if (
        not isinstance(wave_failure, launcher_module.BootstrapError)
        or str(wave_failure) != "bootstrap descendant cleanup encountered errors"
        or error_kills != [{201}, {202}]
        or error_reaps != [{201}, {202}]
    ):
        raise SystemExit("bootstrap persistent error starved later cleanup waves")

    first_wave = set(range(30000, 30000 + launcher_module.MAX_DESCENDANT_PROCESSES))
    second_wave = set(range(40000, 40073))
    convergence_waves = (
        {pid: pid + 100000 for pid in first_wave},
        {pid: pid + 100000 for pid in second_wave},
        {},
    )
    convergence_wave = 0
    convergence_owned_calls = [0, 0, 0]
    convergence_reaps: list[set[int]] = []
    original_reap_owned = launcher_module.reap_owned_children
    original_sleep = launcher_module.time.sleep
    original_pidfd_open = launcher_module.os.pidfd_open
    original_pidfd_send_signal = launcher_module.signal.pidfd_send_signal
    original_close = launcher_module.os.close
    convergence_pidfds: dict[int, int] = {}
    convergence_signalled: set[int] = set()
    convergence_maximum_open = 0

    def convergence_owned(*_args, **_kwargs):
        convergence_owned_calls[convergence_wave] += 1
        return dict(convergence_waves[convergence_wave])

    def convergence_pidfd_open(pid: int, _flags: int) -> int:
        nonlocal convergence_maximum_open
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        convergence_pidfds[descriptor] = pid
        convergence_maximum_open = max(
            convergence_maximum_open,
            len(convergence_pidfds),
        )
        return descriptor

    def convergence_pidfd_signal(descriptor, signum, _info, _flags):
        if descriptor not in convergence_pidfds or signum != signal.SIGKILL:
            raise SystemExit("bootstrap convergence fixture signalled an unknown pidfd")
        convergence_signalled.add(convergence_pidfds[descriptor])

    def convergence_close(descriptor: int) -> None:
        convergence_pidfds.pop(descriptor, None)
        original_close(descriptor)

    def convergence_reap(descendants: set[int]) -> None:
        nonlocal convergence_wave
        convergence_reaps.append(set(descendants))
        if set(convergence_waves[convergence_wave]) != set(descendants):
            raise SystemExit("bootstrap convergence fixture reaped the wrong wave")
        convergence_wave += 1

    launcher_module.owned_descendants = convergence_owned
    launcher_module.reap_owned_children = convergence_reap
    launcher_module.time.sleep = lambda _seconds: None
    launcher_module.os.pidfd_open = convergence_pidfd_open
    launcher_module.signal.pidfd_send_signal = convergence_pidfd_signal
    launcher_module.os.close = convergence_close
    try:
        converged = launcher_module.cleanup_descendants(
            9000,
            frozenset(),
            exclude_unreaped_root=False,
        )
    finally:
        launcher_module.os.close = original_close
        launcher_module.signal.pidfd_send_signal = original_pidfd_send_signal
        launcher_module.os.pidfd_open = original_pidfd_open
        launcher_module.time.sleep = original_sleep
        launcher_module.reap_owned_children = original_reap_owned
        launcher_module.owned_descendants = original_owned_descendants
    if (
        not converged
        or convergence_wave != 2
        or convergence_owned_calls
        != [
            1
            + (
                launcher_module.MAX_DESCENDANT_PROCESSES
                + launcher_module.PIDFD_BATCH_SIZE
                - 1
            )
            // launcher_module.PIDFD_BATCH_SIZE,
            1 + (len(second_wave) + launcher_module.PIDFD_BATCH_SIZE - 1)
            // launcher_module.PIDFD_BATCH_SIZE,
            1,
        ]
        or convergence_signalled != first_wave | second_wave
        or convergence_reaps != [first_wave, second_wave]
        or convergence_maximum_open > launcher_module.PIDFD_BATCH_SIZE
        or convergence_pidfds
    ):
        raise SystemExit("bootstrap multi-pass descendant convergence drifted")

    def baseline_child_main() -> int:
        time.sleep(0.2)
        return 0

    baseline_child_owner = FixtureChildOwner()
    spawn_fixture_child(
        baseline_child_owner,
        baseline_child_main,
        "bootstrap baseline-child fork",
    )
    baseline_child = baseline_child_owner.pid
    try:
        launcher_module.run_bounded(
            ["/usr/bin/sleep", "0.3"],
            cwd=process_root,
            environment=environment,
            deadline=time.monotonic() + 5.0,
            stdout_limit=4096,
            stderr_limit=4096,
            label="baseline child fixture",
        )
    except launcher_module.BootstrapError as exc:
        if str(exc) != "baseline child fixture found pre-existing child processes":
            raise
    else:
        raise SystemExit("bootstrap accepted a pre-existing child process")
    try:
        status = wait_exact_fixture_child(
            baseline_child,
            "bootstrap baseline child fixture",
            terminate=False,
        )
        baseline_child_owner.pid = -1
    except ChildProcessError as exc:
        raise SystemExit("bootstrap reaped a pre-existing baseline child") from exc
    if not os.WIFEXITED(status):
        raise SystemExit("bootstrap baseline child fixture did not exit deterministically")
    normal_script = process_root / "normal-descendant.py"
    normal_pid_path = process_root / "normal-descendant.pid"
    normal_script.write_text(
        "import os, pathlib, sys, time\n"
        + PROCESS_IDENTITY_HELPER
        + "read_fd, write_fd = os.pipe()\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    os.close(read_fd)\n"
        "    os.setsid()\n"
        "    record_identity(sys.argv[1])\n"
        "    os.write(write_fd, b'1')\n"
        "    while True: time.sleep(1)\n"
        "os.close(write_fd)\n"
        "os.read(read_fd, 1)\n",
        encoding="utf-8",
    )
    try:
        launcher_module.run_bounded(
            ["/usr/bin/python3", "-I", "-B", str(normal_script), str(normal_pid_path)],
            cwd=process_root,
            environment=environment,
            deadline=time.monotonic() + 5.0,
            stdout_limit=4096,
            stderr_limit=4096,
            label="normal descendant fixture",
        )
    except launcher_module.BootstrapError as exc:
        if str(exc) != "normal descendant fixture left descendant processes":
            raise
    else:
        raise SystemExit("bootstrap accepted a normal-exit descendant holder")
    if not normal_pid_path.is_file():
        raise SystemExit("bootstrap normal descendant fixture omitted its pid")
    require_process_gone(normal_pid_path, "normal descendant")

    cleanup_cancel_pid_path = process_root / "cleanup-cancel-descendant.pid"
    original_owned_descendants = launcher_module.owned_descendants
    cleanup_cancel_calls = 0

    def cancel_first_descendant_cleanup(*args, **kwargs):
        nonlocal cleanup_cancel_calls
        cleanup_cancel_calls += 1
        if cleanup_cancel_calls == 1:
            raise KeyboardInterrupt("injected descendant cleanup cancellation")
        return original_owned_descendants(*args, **kwargs)

    launcher_module.owned_descendants = cancel_first_descendant_cleanup
    try:
        try:
            launcher_module.run_bounded(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(normal_script),
                    str(cleanup_cancel_pid_path),
                ],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="cleanup cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected descendant cleanup cancellation":
                raise
        else:
            raise SystemExit("bootstrap swallowed descendant cleanup cancellation")
    finally:
        launcher_module.owned_descendants = original_owned_descendants
    if not cleanup_cancel_pid_path.is_file():
        raise SystemExit("bootstrap cleanup-cancellation fixture omitted its pid")
    require_process_gone(
        cleanup_cancel_pid_path,
        "cleanup-cancel descendant",
    )

    deferred_signal_pid_path = process_root / "deferred-signal-descendant.pid"
    deferred_signal_calls = 0

    def signal_during_descendant_cleanup(*args, **kwargs):
        nonlocal deferred_signal_calls
        deferred_signal_calls += 1
        if deferred_signal_calls == 1:
            os.kill(os.getpid(), signal.SIGINT)
        return original_owned_descendants(*args, **kwargs)

    launcher_module.owned_descendants = signal_during_descendant_cleanup
    try:
        try:
            launcher_module.run_bounded(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(normal_script),
                    str(deferred_signal_pid_path),
                ],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="deferred cleanup signal fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGINT:
                raise
        else:
            raise SystemExit("bootstrap swallowed a deferred cleanup signal")
    finally:
        launcher_module.owned_descendants = original_owned_descendants
    if deferred_signal_calls < 1 or not deferred_signal_pid_path.is_file():
        raise SystemExit("bootstrap deferred-signal fixture did not reach cleanup")
    require_process_gone(
        deferred_signal_pid_path,
        "deferred-signal descendant",
    )

    signal_script = process_root / "signal-launcher.py"
    signal_script.write_text(
        "import os, pathlib, signal, sys, time\n"
        + PROCESS_IDENTITY_HELPER
        + "read_fd, write_fd = os.pipe()\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    os.close(read_fd)\n"
        "    os.setsid()\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    record_identity(sys.argv[2])\n"
        "    os.write(write_fd, b'1')\n"
        "    while True: time.sleep(1)\n"
        "os.close(write_fd)\n"
        "record_identity(sys.argv[1])\n"
        "os.read(read_fd, 1)\n"
        "os.kill(os.getppid(), getattr(signal, sys.argv[3]))\n"
        "while True: time.sleep(1)\n",
        encoding="utf-8",
    )
    original_signal_handlers = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    for signal_name, signum in (
        ("SIGTERM", signal.SIGTERM),
        ("SIGINT", signal.SIGINT),
    ):
        if signum == signal.SIGINT:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        expected_signal_handlers = {
            candidate: signal.getsignal(candidate)
            for candidate in original_signal_handlers
        }
        signal_pid_path = process_root / f"{signal_name.lower()}-launcher.pid"
        descendant_pid_path = (
            process_root / f"{signal_name.lower()}-detached-descendant.pid"
        )
        try:
            try:
                launcher_module.run_bounded(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        str(signal_script),
                        str(signal_pid_path),
                        str(descendant_pid_path),
                        signal_name,
                    ],
                    cwd=process_root,
                    environment=environment,
                    deadline=time.monotonic() + 5.0,
                    stdout_limit=4096,
                    stderr_limit=4096,
                    label=f"{signal_name} fixture",
                )
            except launcher_module.BootstrapSignal as exc:
                if exc.signum != signum:
                    raise
            else:
                raise SystemExit(f"bootstrap swallowed launcher {signal_name}")
            if not signal_pid_path.is_file():
                raise SystemExit(f"bootstrap {signal_name} fixture omitted its pid")
            if not descendant_pid_path.is_file():
                raise SystemExit(
                    f"bootstrap {signal_name} fixture omitted its detached descendant"
                )
            require_process_gone(
                signal_pid_path,
                f"{signal_name} target",
            )
            require_process_gone(
                descendant_pid_path,
                f"{signal_name} detached descendant",
            )
            if any(
                signal.getsignal(candidate) != expected_signal_handlers[candidate]
                for candidate in expected_signal_handlers
            ):
                raise SystemExit("bootstrap did not restore launcher signal handlers")
        finally:
            if signum == signal.SIGINT:
                signal.signal(
                    signal.SIGINT,
                    original_signal_handlers[signal.SIGINT],
                )

    for signal_name, blocked_signals in (
        ("SIGINT", {signal.SIGINT}),
        ("SIGTERM", {signal.SIGTERM}),
        ("SIGINT+SIGTERM", {signal.SIGINT, signal.SIGTERM}),
    ):
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        expected_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        expected_handlers = {
            candidate: signal.getsignal(candidate)
            for candidate in original_signal_handlers
        }
        mask_popen_calls = 0
        mask_original_popen = launcher_module.subprocess.Popen

        def count_mask_popen(*args, **kwargs):
            nonlocal mask_popen_calls
            mask_popen_calls += 1
            return mask_original_popen(*args, **kwargs)

        launcher_module.subprocess.Popen = count_mask_popen
        try:
            try:
                launcher_module.run_bounded(
                    ["/usr/bin/true"],
                    cwd=process_root,
                    environment=environment,
                    deadline=time.monotonic() + 5.0,
                    stdout_limit=4096,
                    stderr_limit=4096,
                    label=f"blocked {signal_name} fixture",
                )
            except launcher_module.BootstrapError as exc:
                if str(exc) != (
                    f"blocked {signal_name} fixture inherited a blocked "
                    "SIGINT or SIGTERM"
                ):
                    raise
            else:
                raise SystemExit(
                    f"bootstrap accepted an inherited blocked {signal_name}"
                )
            if signal.pthread_sigmask(signal.SIG_BLOCK, set()) != expected_mask:
                raise SystemExit(
                    f"bootstrap changed the inherited {signal_name} mask"
                )
            if any(
                signal.getsignal(candidate) != expected_handlers[candidate]
                for candidate in expected_handlers
            ):
                raise SystemExit(
                    f"bootstrap changed handlers for blocked {signal_name}"
                )
        finally:
            launcher_module.subprocess.Popen = mask_original_popen
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if mask_popen_calls:
            raise SystemExit(
                f"bootstrap spawned with inherited blocked {signal_name}"
            )

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    try:
        result = launcher_module.run_bounded(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                (
                    "import signal,sys;"
                    "m=signal.pthread_sigmask(signal.SIG_BLOCK,set());"
                    "sys.exit(91) if signal.SIGINT in m or "
                    "signal.SIGTERM in m else None;"
                    "sys.exit(92) if signal.SIGUSR1 not in m else None;"
                    "print('CHILD_SIGNAL_MASK=PASS')"
                ),
            ],
            cwd=process_root,
            environment=environment,
            deadline=time.monotonic() + 5.0,
            stdout_limit=4096,
            stderr_limit=4096,
            label="non-cancellation mask fixture",
        )
        if (
            result.returncode != 0
            or result.stdout != b"CHILD_SIGNAL_MASK=PASS\n"
            or result.stderr
            or signal.SIGUSR1
            not in signal.pthread_sigmask(signal.SIG_BLOCK, set())
        ):
            raise SystemExit("bootstrap changed a non-cancellation signal mask")
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    assignment_popen_original = launcher_module.subprocess.Popen
    assignment_popen_calls = 0

    def count_assignment_popen(*args, **kwargs):
        nonlocal assignment_popen_calls
        assignment_popen_calls += 1
        return assignment_popen_original(*args, **kwargs)

    handler_assignment_original = launcher_module.signal.signal
    handler_assignment_injected = False

    def signal_after_handler_assignment(signum, handler):
        nonlocal handler_assignment_injected
        previous = handler_assignment_original(signum, handler)
        if (
            not handler_assignment_injected
            and signum == signal.SIGINT
            and callable(handler)
        ):
            handler_assignment_injected = True
            os.kill(os.getpid(), signal.SIGINT)
        return previous

    launcher_module.signal.signal = signal_after_handler_assignment
    launcher_module.subprocess.Popen = count_assignment_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="handler assignment fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGINT:
                raise
        else:
            raise SystemExit("bootstrap swallowed handler-assignment cancellation")
    finally:
        launcher_module.subprocess.Popen = assignment_popen_original
        launcher_module.signal.signal = handler_assignment_original
    if not handler_assignment_injected or assignment_popen_calls:
        raise SystemExit("bootstrap handler-assignment fixture drifted")

    restore_signal_original = launcher_module.signal.signal
    restore_signal_injected = False
    restore_signal_parent = os.getpid()
    restore_expected_handlers = {
        candidate: signal.getsignal(candidate)
        for candidate in original_signal_handlers
    }

    def signal_during_handler_restore(signum, handler):
        nonlocal restore_signal_injected
        previous = restore_signal_original(signum, handler)
        if (
            not restore_signal_injected
            and os.getpid() == restore_signal_parent
            and signum == signal.SIGTERM
            and handler == restore_expected_handlers[signal.SIGTERM]
        ):
            restore_signal_injected = True
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)
        return previous

    launcher_module.signal.signal = signal_during_handler_restore
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="handler restore signal fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGINT:
                raise
        else:
            raise SystemExit("bootstrap swallowed handler-restore cancellation")
    finally:
        launcher_module.signal.signal = restore_signal_original
    if (
        not restore_signal_injected
        or any(
            signal.getsignal(candidate) != restore_expected_handlers[candidate]
            for candidate in restore_expected_handlers
        )
    ):
        raise SystemExit("bootstrap handler-restore fixture drifted")

    assignment_popen_calls = 0
    subreaper_assignment_original = launcher_module.set_child_subreaper
    subreaper_assignment_injected = False
    subreaper_assignment_calls = 0

    def signal_after_subreaper_assignment(enabled: bool):
        nonlocal subreaper_assignment_calls, subreaper_assignment_injected
        subreaper_assignment_calls += 1
        previous = subreaper_assignment_original(enabled)
        if enabled and not subreaper_assignment_injected:
            subreaper_assignment_injected = True
            os.kill(os.getpid(), signal.SIGTERM)
        return previous

    launcher_module.set_child_subreaper = signal_after_subreaper_assignment
    launcher_module.subprocess.Popen = count_assignment_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="subreaper assignment fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGTERM:
                raise
        else:
            raise SystemExit("bootstrap swallowed subreaper-assignment cancellation")
    finally:
        launcher_module.subprocess.Popen = assignment_popen_original
        launcher_module.set_child_subreaper = subreaper_assignment_original
    if (
        not subreaper_assignment_injected
        or subreaper_assignment_calls < 2
        or assignment_popen_calls
    ):
        raise SystemExit("bootstrap subreaper-assignment fixture drifted")

    assignment_popen_calls = 0
    mask_assignment_original = launcher_module.signal.pthread_sigmask
    mask_assignment_injected = False
    mask_assignment_before = mask_assignment_original(signal.SIG_BLOCK, set())

    def signal_after_mask_assignment(how, mask):
        nonlocal mask_assignment_injected
        previous = mask_assignment_original(how, mask)
        if (
            not mask_assignment_injected
            and how == signal.SIG_BLOCK
            and set(mask) == {signal.SIGINT, signal.SIGTERM}
        ):
            mask_assignment_injected = True
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)
        return previous

    launcher_module.signal.pthread_sigmask = signal_after_mask_assignment
    launcher_module.subprocess.Popen = count_assignment_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="mask assignment fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGINT:
                raise
        else:
            raise SystemExit("bootstrap swallowed mask-assignment cancellation")
    finally:
        launcher_module.subprocess.Popen = assignment_popen_original
        launcher_module.signal.pthread_sigmask = mask_assignment_original
    if (
        not mask_assignment_injected
        or assignment_popen_calls
        or mask_assignment_original(signal.SIG_BLOCK, set())
        != mask_assignment_before
    ):
        raise SystemExit("bootstrap mask-assignment fixture drifted")

    applied_popen_calls = 0

    def count_applied_popen(*args, **kwargs):
        nonlocal applied_popen_calls
        applied_popen_calls += 1
        return assignment_popen_original(*args, **kwargs)

    applied_handler_original = launcher_module.signal.signal
    applied_handler_before = {
        signum: signal.getsignal(signum) for signum in original_signal_handlers
    }
    applied_handler_error = KeyboardInterrupt(
        "injected applied handler-assignment cancellation"
    )
    applied_handler_injected = False

    def fail_after_handler_apply(signum, handler):
        nonlocal applied_handler_injected
        previous = applied_handler_original(signum, handler)
        if (
            not applied_handler_injected
            and signum == signal.SIGINT
            and callable(handler)
        ):
            applied_handler_injected = True
            raise applied_handler_error
        return previous

    launcher_module.signal.signal = fail_after_handler_apply
    launcher_module.subprocess.Popen = count_applied_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="applied handler assignment fixture",
            )
        except KeyboardInterrupt as exc:
            if exc is not applied_handler_error:
                raise
        else:
            raise SystemExit(
                "bootstrap swallowed applied handler-assignment cancellation"
            )
    finally:
        launcher_module.subprocess.Popen = assignment_popen_original
        launcher_module.signal.signal = applied_handler_original
    if (
        not applied_handler_injected
        or applied_popen_calls
        or any(
            signal.getsignal(signum) != handler
            for signum, handler in applied_handler_before.items()
        )
    ):
        raise SystemExit("bootstrap applied handler assignment leaked state")

    applied_popen_calls = 0
    applied_subreaper_original = launcher_module.set_child_subreaper
    applied_subreaper_before = launcher_module.get_child_subreaper()
    applied_subreaper_error = KeyboardInterrupt(
        "injected applied subreaper-assignment cancellation"
    )
    applied_subreaper_injected = False

    def fail_after_subreaper_apply(enabled: bool):
        nonlocal applied_subreaper_injected
        previous = applied_subreaper_original(enabled)
        if enabled and not applied_subreaper_injected:
            applied_subreaper_injected = True
            raise applied_subreaper_error
        return previous

    launcher_module.set_child_subreaper = fail_after_subreaper_apply
    launcher_module.subprocess.Popen = count_applied_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="applied subreaper assignment fixture",
            )
        except KeyboardInterrupt as exc:
            if exc is not applied_subreaper_error:
                raise
        else:
            raise SystemExit(
                "bootstrap swallowed applied subreaper-assignment cancellation"
            )
    finally:
        launcher_module.subprocess.Popen = assignment_popen_original
        launcher_module.set_child_subreaper = applied_subreaper_original
    if (
        not applied_subreaper_injected
        or applied_popen_calls
        or launcher_module.get_child_subreaper() != applied_subreaper_before
    ):
        raise SystemExit("bootstrap applied subreaper assignment leaked state")

    applied_popen_calls = 0
    applied_mask_original = launcher_module.signal.pthread_sigmask
    applied_mask_before = frozenset(
        applied_mask_original(signal.SIG_BLOCK, set())
    )
    applied_mask_error = KeyboardInterrupt(
        "injected applied mask-assignment cancellation"
    )
    applied_mask_injected = False

    def fail_after_mask_apply(how, mask):
        nonlocal applied_mask_injected
        previous = applied_mask_original(how, mask)
        if (
            not applied_mask_injected
            and how == signal.SIG_BLOCK
            and set(mask) == {signal.SIGINT, signal.SIGTERM}
        ):
            applied_mask_injected = True
            raise applied_mask_error
        return previous

    launcher_module.signal.pthread_sigmask = fail_after_mask_apply
    launcher_module.subprocess.Popen = count_applied_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="applied mask assignment fixture",
            )
        except KeyboardInterrupt as exc:
            if exc is not applied_mask_error:
                raise
        else:
            raise SystemExit(
                "bootstrap swallowed applied mask-assignment cancellation"
            )
    finally:
        launcher_module.subprocess.Popen = assignment_popen_original
        launcher_module.signal.pthread_sigmask = applied_mask_original
    if (
        not applied_mask_injected
        or applied_popen_calls
        or frozenset(applied_mask_original(signal.SIG_BLOCK, set()))
        != applied_mask_before
    ):
        raise SystemExit("bootstrap applied mask assignment leaked state")

    handler_install_original = launcher_module.signal.signal
    handler_popen_original = launcher_module.subprocess.Popen
    handler_install_injected = False
    handler_popen_calls = 0
    handlers_before_partial_install = {
        candidate: signal.getsignal(candidate)
        for candidate in original_signal_handlers
    }
    mask_before_partial_install = signal.pthread_sigmask(signal.SIG_BLOCK, set())

    def fail_term_handler_install(signum, handler):
        nonlocal handler_install_injected
        if (
            not handler_install_injected
            and signum == signal.SIGTERM
            and callable(handler)
        ):
            handler_install_injected = True
            raise OSError("injected SIGTERM handler installation failure")
        return handler_install_original(signum, handler)

    def count_handler_popen(*args, **kwargs):
        nonlocal handler_popen_calls
        handler_popen_calls += 1
        return handler_popen_original(*args, **kwargs)

    launcher_module.signal.signal = fail_term_handler_install
    launcher_module.subprocess.Popen = count_handler_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="partial handler installation fixture",
            )
        except OSError as exc:
            if str(exc) != "injected SIGTERM handler installation failure":
                raise
        else:
            raise SystemExit("bootstrap swallowed partial handler installation failure")
    finally:
        launcher_module.subprocess.Popen = handler_popen_original
        launcher_module.signal.signal = handler_install_original
    if (
        not handler_install_injected
        or handler_popen_calls
        or signal.pthread_sigmask(signal.SIG_BLOCK, set())
        != mask_before_partial_install
        or any(
            signal.getsignal(candidate) != handlers_before_partial_install[candidate]
            for candidate in handlers_before_partial_install
        )
    ):
        raise SystemExit("bootstrap did not roll back partial handler installation")

    restore_failure_original = launcher_module.signal.signal
    restore_failure_injected = False
    restore_failure_parent = os.getpid()
    restore_failure_expected = signal.getsignal(signal.SIGTERM)

    def fail_term_handler_restore_once(signum, handler):
        nonlocal restore_failure_injected
        previous = restore_failure_original(signum, handler)
        if (
            not restore_failure_injected
            and os.getpid() == restore_failure_parent
            and signum == signal.SIGTERM
            and handler == restore_failure_expected
        ):
            restore_failure_injected = True
            raise OSError("injected SIGTERM handler restore failure")
        return previous

    launcher_module.signal.signal = fail_term_handler_restore_once
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="handler restore failure fixture",
            )
        except OSError as exc:
            if str(exc) != "injected SIGTERM handler restore failure":
                raise
        else:
            raise SystemExit("bootstrap swallowed handler restore failure")
    finally:
        launcher_module.signal.signal = restore_failure_original
    if (
        not restore_failure_injected
        or signal.getsignal(signal.SIGTERM) != restore_failure_expected
    ):
        raise SystemExit("bootstrap did not retry SIGTERM handler restoration")

    mask_restore_original = launcher_module.signal.pthread_sigmask
    mask_restore_parent = os.getpid()
    mask_restore_calls = 0
    mask_restore_injected = False
    mask_restore_expected = mask_restore_original(signal.SIG_BLOCK, set())

    def fail_parent_mask_restore_once(how, mask):
        nonlocal mask_restore_calls, mask_restore_injected
        previous = mask_restore_original(how, mask)
        if os.getpid() == mask_restore_parent and how == signal.SIG_SETMASK:
            mask_restore_calls += 1
            if mask_restore_calls == 2:
                mask_restore_injected = True
                raise OSError("injected signal-mask restore failure")
        return previous

    launcher_module.signal.pthread_sigmask = fail_parent_mask_restore_once
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="signal-mask restore failure fixture",
            )
        except OSError as exc:
            if str(exc) != "injected signal-mask restore failure":
                raise
        else:
            raise SystemExit("bootstrap swallowed signal-mask restore failure")
    finally:
        launcher_module.signal.pthread_sigmask = mask_restore_original
    if (
        not mask_restore_injected
        or mask_restore_original(signal.SIG_BLOCK, set())
        != mask_restore_expected
    ):
        raise SystemExit("bootstrap did not retry signal-mask restoration")

    subreaper_restore_original = launcher_module.set_child_subreaper
    subreaper_restore_calls: list[tuple[bool, bool]] = []
    subreaper_restore_injected = False

    def fail_subreaper_restore_once(enabled: bool) -> bool:
        nonlocal subreaper_restore_injected
        previous = subreaper_restore_original(enabled)
        subreaper_restore_calls.append((enabled, previous))
        if len(subreaper_restore_calls) == 2 and not subreaper_restore_injected:
            subreaper_restore_injected = True
            raise OSError("injected subreaper restore failure")
        return previous

    launcher_module.set_child_subreaper = fail_subreaper_restore_once
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="subreaper restore failure fixture",
            )
        except OSError as exc:
            if str(exc) != "injected subreaper restore failure":
                raise
        else:
            raise SystemExit("bootstrap swallowed subreaper restore failure")
    finally:
        launcher_module.set_child_subreaper = subreaper_restore_original
    if len(subreaper_restore_calls) < 3 or not subreaper_restore_injected:
        raise SystemExit("bootstrap did not retry subreaper restoration")
    expected_subreaper = subreaper_restore_calls[0][1]
    observed_subreaper = subreaper_restore_original(True)
    subreaper_restore_original(observed_subreaper)
    if observed_subreaper != expected_subreaper:
        raise SystemExit("bootstrap leaked child-subreaper state")
    if (
        signal.pthread_sigmask(signal.SIG_BLOCK, set())
        & {signal.SIGINT, signal.SIGTERM}
        or any(
            signal.getsignal(candidate) != original_signal_handlers[candidate]
            for candidate in original_signal_handlers
        )
    ):
        raise SystemExit("bootstrap signal fixture leaked process signal state")

    timeout_script = process_root / "timeout-descendant.py"
    timeout_pid_path = process_root / "timeout-descendant.pid"
    timeout_script.write_text(
        "import os, pathlib, signal, sys, time\n"
        + PROCESS_IDENTITY_HELPER
        + "read_fd, write_fd = os.pipe()\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    os.close(read_fd)\n"
        "    os.setsid()\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    record_identity(sys.argv[1])\n"
        "    os.write(write_fd, b'1')\n"
        "    while True: time.sleep(1)\n"
        "os.close(write_fd)\n"
        "os.read(read_fd, 1)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "while True: time.sleep(1)\n",
        encoding="utf-8",
    )
    try:
        launcher_module.run_bounded(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(timeout_script),
                str(timeout_pid_path),
            ],
            cwd=process_root,
            environment=environment,
            deadline=time.monotonic() + 0.25,
            stdout_limit=4096,
            stderr_limit=4096,
            label="timeout descendant fixture",
        )
    except launcher_module.BootstrapError as exc:
        if str(exc) != "timeout descendant fixture exceeded its deadline":
            raise
    else:
        raise SystemExit("bootstrap accepted a timeout descendant")
    if not timeout_pid_path.is_file():
        raise SystemExit("bootstrap timeout descendant fixture omitted its pid")
    require_process_gone(timeout_pid_path, "timeout descendant")

    flood_script = process_root / "stdout-flood.py"
    flood_script.write_text(
        "import os\n"
        "chunk = b'x' * 8192\n"
        "while True: os.write(1, chunk)\n",
        encoding="utf-8",
    )
    try:
        launcher_module.run_bounded(
            ["/usr/bin/python3", "-I", "-B", str(flood_script)],
            cwd=process_root,
            environment=environment,
            deadline=time.monotonic() + 5.0,
            stdout_limit=1024,
            stderr_limit=4096,
            label="stdout flood fixture",
        )
    except launcher_module.BootstrapError as exc:
        if str(exc) != "stdout flood fixture stdout exceeds its size bound":
            raise
    else:
        raise SystemExit("bootstrap accepted an output flood")

    original_popen = launcher_module.subprocess.Popen
    spawned_processes = []

    for signal_name, delivered_signals, expected_signum in (
        ("SIGINT", (signal.SIGINT,), signal.SIGINT),
        ("SIGTERM", (signal.SIGTERM,), signal.SIGTERM),
        (
            "SIGINT+SIGTERM",
            (signal.SIGTERM, signal.SIGINT),
            signal.SIGINT,
        ),
    ):
        pre_return_processes: list[
            tuple[FixturePopenOwner, FixtureDescriptorOwner]
        ] = []

        def signal_before_popen_return(*args, **kwargs):
            process_owner = FixturePopenOwner()
            acquire_fixture_popen_call(
                process_owner,
                lambda: original_popen(*args, **kwargs),
                f"pre-return {signal_name} fixture setup",
            )
            assert process_owner.process is not None
            descriptor_owner = FixtureDescriptorOwner()
            open_owned_fixture_pidfd(
                descriptor_owner,
                process_owner.process.pid,
                f"pre-return {signal_name} fixture pidfd",
            )
            pre_return_processes.append((process_owner, descriptor_owner))
            for delivered_signum in delivered_signals:
                os.kill(os.getpid(), delivered_signum)
            return process_owner.process

        launcher_module.subprocess.Popen = signal_before_popen_return
        caught_signal = False
        try:
            try:
                launcher_module.run_bounded(
                    ["/usr/bin/sleep", "10"],
                    cwd=process_root,
                    environment=environment,
                    deadline=time.monotonic() + 5.0,
                    stdout_limit=4096,
                    stderr_limit=4096,
                    label=f"pre-return {signal_name} fixture",
                )
            except launcher_module.BootstrapSignal as exc:
                if exc.signum != expected_signum:
                    raise
                caught_signal = True
            else:
                raise SystemExit(
                    f"bootstrap swallowed pre-return {signal_name}"
                )
        finally:
            launcher_module.subprocess.Popen = original_popen
        if len(pre_return_processes) != 1:
            raise SystemExit(
                f"bootstrap pre-return {signal_name} process count drifted"
            )
        process_owner, descriptor_owner = pre_return_processes[0]
        leaked, exact = settle_pinned_fixture_owners(
            process_owner,
            descriptor_owner,
            f"pre-return {signal_name} target",
        )
        if not caught_signal or leaked or not exact:
            raise SystemExit(
                f"bootstrap lost a child before Popen returned on {signal_name}"
            )

    original_killpg = launcher_module.os.killpg
    killpg_failure_processes: list[
        tuple[FixturePopenOwner, FixtureDescriptorOwner]
    ] = []

    def signal_before_failed_killpg(*args, **kwargs):
        process_owner = FixturePopenOwner()
        acquire_fixture_popen_call(
            process_owner,
            lambda: original_popen(*args, **kwargs),
            "root pidfd fallback fixture setup",
        )
        assert process_owner.process is not None
        descriptor_owner = FixtureDescriptorOwner()
        open_owned_fixture_pidfd(
            descriptor_owner,
            process_owner.process.pid,
            "root pidfd fallback fixture pidfd",
        )
        killpg_failure_processes.append((process_owner, descriptor_owner))
        os.kill(os.getpid(), signal.SIGINT)
        return process_owner.process

    def fail_all_killpg(*_args, **_kwargs):
        raise OSError("injected process-group signal failure")

    launcher_module.subprocess.Popen = signal_before_failed_killpg
    launcher_module.os.killpg = fail_all_killpg
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/sleep", "10"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="root pidfd fallback fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGINT:
                raise
        else:
            raise SystemExit("bootstrap swallowed root pidfd fallback cancellation")
    finally:
        launcher_module.os.killpg = original_killpg
        launcher_module.subprocess.Popen = original_popen
    if len(killpg_failure_processes) != 1:
        raise SystemExit("bootstrap root pidfd fallback process count drifted")
    process_owner, descriptor_owner = killpg_failure_processes[0]
    leaked, exact = settle_pinned_fixture_owners(
        process_owner,
        descriptor_owner,
        "root pidfd fallback target",
    )
    if leaked or not exact:
        raise SystemExit("bootstrap root pidfd fallback left its process alive")

    root_pidfd_open_original = launcher_module.os.pidfd_open
    raw_root_fallback_processes: list[FixturePopenOwner] = []

    def signal_before_missing_root_pidfd(*args, **kwargs):
        process_owner = FixturePopenOwner()
        acquire_fixture_popen_call(
            process_owner,
            lambda: original_popen(*args, **kwargs),
            "raw-root fallback fixture setup",
        )
        assert process_owner.process is not None
        raw_root_fallback_processes.append(process_owner)
        os.kill(os.getpid(), signal.SIGINT)
        return process_owner.process

    def fail_root_pidfd_open(_pid: int, _flags: int) -> int:
        raise OSError("injected root pidfd open failure")

    launcher_module.subprocess.Popen = signal_before_missing_root_pidfd
    launcher_module.os.pidfd_open = fail_root_pidfd_open
    launcher_module.os.killpg = fail_all_killpg
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/sleep", "10"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="raw root fallback fixture",
            )
        except launcher_module.BootstrapSignal as exc:
            if exc.signum != signal.SIGINT:
                raise
        else:
            raise SystemExit("bootstrap swallowed raw-root fallback cancellation")
    finally:
        launcher_module.os.killpg = original_killpg
        launcher_module.os.pidfd_open = root_pidfd_open_original
        launcher_module.subprocess.Popen = original_popen
    if len(raw_root_fallback_processes) != 1:
        raise SystemExit("bootstrap raw-root fallback process count drifted")
    raw_root_owner = raw_root_fallback_processes[0]
    assert raw_root_owner.process is not None
    raw_root_process = raw_root_owner.process
    require_popen_reaped(
        raw_root_process,
        "raw-root fallback target",
    )
    try:
        os.waitpid(raw_root_process.pid, os.WNOHANG)
    except ChildProcessError as exc:
        raw_root_reaped = exc.errno == errno.ECHILD
    else:
        raw_root_reaped = False
    if raw_root_process.returncode is None or not raw_root_reaped:
        raise SystemExit("bootstrap raw-root fallback owner settlement drifted")
    raw_root_owner.process = None

    class CancellingProcess:
        def __init__(self, process):
            self.process = process
            self.cancelled = False

        def __getattr__(self, name):
            return getattr(self.process, name)

        def wait(self, *args, **kwargs):
            if not self.cancelled:
                self.cancelled = True
                raise KeyboardInterrupt("injected launcher wait cancellation")
            return self.process.wait(*args, **kwargs)

    def cancelling_popen(*args, **kwargs):
        wrapped = CancellingProcess(original_popen(*args, **kwargs))
        spawned_processes.append(wrapped)
        return wrapped

    launcher_module.subprocess.Popen = cancelling_popen
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/sleep", "10"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="cancellation fixture",
            )
        except KeyboardInterrupt as exc:
            if str(exc) != "injected launcher wait cancellation":
                raise
        else:
            raise SystemExit("bootstrap swallowed launcher cancellation")
    finally:
        launcher_module.subprocess.Popen = original_popen
    if len(spawned_processes) != 1:
        raise SystemExit("bootstrap cancellation fixture process count drifted")
    require_popen_reaped(spawned_processes[0].process, "cancelled target")

    original_monotonic = launcher_module.time.monotonic
    clock_values = iter((100.0, 100.5, 102.0))
    launcher_module.time.monotonic = lambda: next(clock_values, 102.0)
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/sleep", "10"],
                cwd=process_root,
                environment=environment,
                deadline=101.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="post-spawn deadline fixture",
            )
        except launcher_module.BootstrapError as exc:
            if str(exc) != "post-spawn deadline fixture exceeded its deadline":
                raise
        else:
            raise SystemExit("bootstrap reused a stale pre-spawn timeout")
    finally:
        launcher_module.time.monotonic = original_monotonic


def test_owned_private_directory_entry_custody(launcher_module) -> None:
    original_mkdtemp = launcher_module.tempfile.mkdtemp
    original_open = launcher_module.os.open
    original_stat = launcher_module.os.stat
    original_fstat = launcher_module.os.fstat
    original_fchmod = launcher_module.os.fchmod

    def _path_exists_with(stat_operation, path: pathlib.Path) -> bool:
        try:
            stat_operation(path, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    for role in ("initial-stat", "open-applied", "fstat", "fchmod"):
        created: list[pathlib.Path] = []
        target_descriptors: list[int] = []
        injected = False
        cancellation = KeyboardInterrupt(
            f"private root {role} initialization cancellation"
        )

        def record_mkdtemp(*args, **kwargs):
            path = pathlib.Path(original_mkdtemp(*args, **kwargs))
            created.append(path)
            return os.fspath(path)

        def stat_with_cancellation(path, *args, **kwargs):
            nonlocal injected
            if (
                role == "initial-stat"
                and not injected
                and created
                and pathlib.Path(path) == created[0]
            ):
                injected = True
                raise cancellation
            return original_stat(path, *args, **kwargs)

        def open_with_cancellation(path, flags, *args, **kwargs):
            nonlocal injected
            descriptor = original_open(path, flags, *args, **kwargs)
            if created and pathlib.Path(path) == created[0]:
                target_descriptors.append(descriptor)
                if role == "open-applied" and not injected:
                    injected = True
                    raise cancellation
            return descriptor

        def fstat_with_cancellation(descriptor):
            nonlocal injected
            if role == "fstat" and not injected and descriptor in target_descriptors:
                injected = True
                raise cancellation
            return original_fstat(descriptor)

        def fchmod_with_cancellation(descriptor, mode):
            nonlocal injected
            result = original_fchmod(descriptor, mode)
            if role == "fchmod" and not injected and descriptor in target_descriptors:
                injected = True
                raise cancellation
            return result

        launcher_module.tempfile.mkdtemp = record_mkdtemp
        launcher_module.os.stat = stat_with_cancellation
        launcher_module.os.open = open_with_cancellation
        launcher_module.os.fstat = fstat_with_cancellation
        launcher_module.os.fchmod = fchmod_with_cancellation
        caught: BaseException | None = None
        try:
            try:
                launcher_module.OwnedPrivateDirectory(
                    f"tb321fu-private-enter-{role}."
                ).__enter__()
            except BaseException as exc:
                caught = exc
        finally:
            launcher_module.os.fchmod = original_fchmod
            launcher_module.os.fstat = original_fstat
            launcher_module.os.open = original_open
            launcher_module.os.stat = original_stat
            launcher_module.tempfile.mkdtemp = original_mkdtemp
        preserved = tuple(
            path
            for path in created
            if _path_exists_with(original_stat, path)
        )
        descriptors_closed = True
        for descriptor in target_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    descriptors_closed = False
            else:
                descriptors_closed = False
        for path in preserved:
            path.rmdir()
        expected_preserved = role == "initial-stat"
        if (
            caught is not cancellation
            or not injected
            or len(created) != 1
            or bool(preserved) != expected_preserved
            or not descriptors_closed
        ):
            raise SystemExit(
                f"private root {role} entry custody drifted: "
                f"caught={caught!r} created={created!r} preserved={preserved!r} "
                f"descriptors={target_descriptors!r}"
            ) from caught

    created: list[pathlib.Path] = []
    target_descriptors: list[int] = []
    displaced: pathlib.Path | None = None
    replacement_identity: tuple[int, int] | None = None
    replacement_mode = 0
    replacement_bytes = b"replacement-owned-by-fixture\n"
    def record_identity_mkdtemp(*args, **kwargs):
        path = pathlib.Path(original_mkdtemp(*args, **kwargs))
        created.append(path)
        return os.fspath(path)

    def replace_before_open(path, flags, *args, **kwargs):
        nonlocal displaced, replacement_identity, replacement_mode
        target = pathlib.Path(path)
        if created and target == created[0] and displaced is None:
            displaced = target.with_name(f"{target.name}.displaced")
            target.rename(displaced)
            target.mkdir(mode=0o711)
            (target / "sentinel").write_bytes(replacement_bytes)
            metadata = original_stat(target, follow_symlinks=False)
            replacement_identity = (metadata.st_dev, metadata.st_ino)
            replacement_mode = stat.S_IMODE(metadata.st_mode)
        descriptor = original_open(path, flags, *args, **kwargs)
        if created and target == created[0]:
            target_descriptors.append(descriptor)
        return descriptor

    launcher_module.tempfile.mkdtemp = record_identity_mkdtemp
    launcher_module.os.open = replace_before_open
    identity_caught: BaseException | None = None
    try:
        try:
            launcher_module.OwnedPrivateDirectory(
                "tb321fu-private-enter-replacement."
            ).__enter__()
        except BaseException as exc:
            identity_caught = exc
    finally:
        launcher_module.os.open = original_open
        launcher_module.tempfile.mkdtemp = original_mkdtemp
    target = created[0] if created else None
    current = (
        original_stat(target, follow_symlinks=False)
        if target is not None and target.exists()
        else None
    )
    replacement_preserved = (
        target is not None
        and current is not None
        and replacement_identity == (current.st_dev, current.st_ino)
        and stat.S_IMODE(current.st_mode) == replacement_mode
        and (target / "sentinel").read_bytes() == replacement_bytes
    )
    replacement_descriptors_closed = True
    for descriptor in target_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                replacement_descriptors_closed = False
        else:
            replacement_descriptors_closed = False
    if target is not None and target.exists():
        sentinel = target / "sentinel"
        if sentinel.exists():
            sentinel.unlink()
        target.rmdir()
    if displaced is not None and displaced.exists():
        displaced.rmdir()
    if (
        not isinstance(identity_caught, launcher_module.BootstrapError)
        or len(created) != 1
        or displaced is None
        or not replacement_preserved
        or not replacement_descriptors_closed
    ):
        raise SystemExit(
            "private root open-time replacement custody drifted"
        ) from identity_caught


@fixture_owner_scoped
def test_signal_custody_regressions(
    launcher_module,
    private: pathlib.Path,
) -> None:
    process_root = private / "signal-custody-regressions"
    process_root.mkdir(mode=0o700)
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(process_root),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    original_mask = launcher_module.signal.pthread_sigmask
    original_preflight = launcher_module.require_pidfd_capacity
    original_popen = launcher_module.subprocess.Popen
    mask_before = frozenset(original_mask(signal.SIG_BLOCK, set()))
    handlers_before = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    subreaper_before = launcher_module.get_child_subreaper()
    preflight_error = launcher_module.BootstrapError(
        "injected pre-spawn cleanup-block primary"
    )
    cleanup_block_error = OSError(
        "injected applied cleanup-block failure"
    )
    cleanup_started = False
    cleanup_block_calls = 0
    cleanup_probe_calls = 0
    mask_restore_calls = 0
    popen_calls = 0
    observed_mask: frozenset[int] | None = None
    observed_handlers: dict[int, object] = {}

    def fail_preflight() -> None:
        nonlocal cleanup_started
        cleanup_started = True
        raise preflight_error

    def fail_after_cleanup_block(how, mask):
        nonlocal cleanup_block_calls, cleanup_probe_calls, mask_restore_calls
        if (
            cleanup_started
            and how == signal.SIG_BLOCK
            and set(mask) == {signal.SIGINT, signal.SIGTERM}
        ):
            cleanup_block_calls += 1
            original_mask(how, mask)
            raise cleanup_block_error
        if cleanup_started and how == signal.SIG_BLOCK and not set(mask):
            cleanup_probe_calls += 1
            raise OSError("injected cleanup-block state-probe failure")
        if (
            cleanup_started
            and how == signal.SIG_SETMASK
            and frozenset(mask) == mask_before
        ):
            mask_restore_calls += 1
        return original_mask(how, mask)

    def count_popen(*args, **kwargs):
        nonlocal popen_calls
        popen_calls += 1
        return original_popen(*args, **kwargs)

    launcher_module.require_pidfd_capacity = fail_preflight
    launcher_module.signal.pthread_sigmask = fail_after_cleanup_block
    launcher_module.subprocess.Popen = count_popen
    caught: BaseException | None = None
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/true"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="cleanup block fixture",
            )
        except BaseException as exc:
            caught = exc
        observed_mask = frozenset(original_mask(signal.SIG_BLOCK, set()))
        observed_handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }
    finally:
        launcher_module.subprocess.Popen = original_popen
        launcher_module.signal.pthread_sigmask = original_mask
        launcher_module.require_pidfd_capacity = original_preflight
        for signum, handler in handlers_before.items():
            signal.signal(signum, handler)
        original_mask(signal.SIG_SETMASK, mask_before)
    if (
        caught is not preflight_error
        or cleanup_block_calls != 3
        or cleanup_probe_calls != 3
        or mask_restore_calls != 1
        or popen_calls
        or observed_mask != mask_before
        or launcher_module.get_child_subreaper() != subreaper_before
        or any(
            observed_handlers.get(signum) == handler
            for signum, handler in handlers_before.items()
        )
    ):
        raise SystemExit(
            "bootstrap cleanup-block failure did not restore the known mask safely"
        ) from caught

    outer_mask_before = frozenset(original_mask(signal.SIG_BLOCK, set()))
    outer_handlers_before = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    outer_cancellation = KeyboardInterrupt(
        "injected outer caller cancellation with latched TERM"
    )
    outer_caught: BaseException | None = None
    try:
        with launcher_module.BootstrapCancellationGuard() as guard:
            guard.signum = signal.SIGTERM
            raise outer_cancellation
    except BaseException as exc:
        outer_caught = exc
    if (
        outer_caught is not outer_cancellation
        or frozenset(original_mask(signal.SIG_BLOCK, set())) != outer_mask_before
        or any(
            signal.getsignal(signum) != handler
            for signum, handler in outer_handlers_before.items()
        )
    ):
        raise SystemExit("outer bootstrap masked exact caller cancellation") from outer_caught

    waitpid_original = launcher_module.os.waitpid
    sleep_original = launcher_module.time.sleep
    pidfd_open_original = launcher_module.os.pidfd_open
    spawned_inner: subprocess.Popen[bytes] | None = None
    wrapped_process = None
    recorded_pidfds: list[int] = []
    fallback_started = False
    fallback_zero_returned = False
    fallback_sleep_injected = False
    fallback_cancellation = KeyboardInterrupt(
        "injected fallback exact-reap sleep cancellation"
    )

    class TimeoutProcess:
        def __init__(self, inner) -> None:
            self.inner = inner
            self.pid = inner.pid
            self.returncode = None

        def wait(self, timeout=None):
            if self.returncode is not None:
                return self.returncode
            raise subprocess.TimeoutExpired(self.inner.args, timeout)

    def timeout_popen(*args, **kwargs):
        nonlocal spawned_inner, wrapped_process
        spawned_inner = original_popen(*args, **kwargs)
        wrapped_process = TimeoutProcess(spawned_inner)
        return wrapped_process

    def record_pidfd(pid: int, flags: int) -> int:
        descriptor = pidfd_open_original(pid, flags)
        recorded_pidfds.append(descriptor)
        return descriptor

    def delay_first_fallback_wait(pid: int, options: int):
        nonlocal fallback_started, fallback_zero_returned
        if wrapped_process is not None and pid == wrapped_process.pid:
            fallback_started = True
            if not fallback_zero_returned:
                fallback_zero_returned = True
                return 0, 0
        return waitpid_original(pid, options)

    def cancel_fallback_sleep(seconds: float) -> None:
        nonlocal fallback_sleep_injected
        if fallback_started and not fallback_sleep_injected:
            fallback_sleep_injected = True
            raise fallback_cancellation
        sleep_original(seconds)

    launcher_module.subprocess.Popen = timeout_popen
    launcher_module.os.pidfd_open = record_pidfd
    launcher_module.os.waitpid = delay_first_fallback_wait
    launcher_module.time.sleep = cancel_fallback_sleep
    fallback_caught: BaseException | None = None
    try:
        try:
            launcher_module.run_bounded(
                ["/usr/bin/sleep", "10"],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 0.05,
                stdout_limit=4096,
                stderr_limit=4096,
                label="fallback reap fixture",
            )
        except BaseException as exc:
            fallback_caught = exc
    finally:
        launcher_module.time.sleep = sleep_original
        launcher_module.os.waitpid = waitpid_original
        launcher_module.os.pidfd_open = pidfd_open_original
        launcher_module.subprocess.Popen = original_popen
        if spawned_inner is not None:
            try:
                os.kill(spawned_inner.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                waitpid_original(spawned_inner.pid, 0)
            except ChildProcessError:
                pass
        original_mask(signal.SIG_SETMASK, mask_before)
    pidfds_closed = True
    for descriptor in recorded_pidfds:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            pidfds_closed = False
            os.close(descriptor)
    if (
        fallback_caught is not fallback_cancellation
        or not fallback_started
        or not fallback_zero_returned
        or not fallback_sleep_injected
        or wrapped_process is None
        or wrapped_process.returncode is None
        or not pidfds_closed
        or launcher_module.get_child_subreaper() != subreaper_before
        or frozenset(original_mask(signal.SIG_BLOCK, set())) != mask_before
        or any(
            signal.getsignal(signum) != handler
            for signum, handler in handlers_before.items()
        )
    ):
        raise SystemExit("bootstrap fallback reap abandoned cleanup custody") from fallback_caught

    assignment_marker = process_root / "popen-assignment-child.tsv"
    assignment_program = (
        "import os,pathlib,signal,sys,time\n"
        f"{PROCESS_IDENTITY_HELPER}"
        "child=os.fork()\n"
        "if child == 0:\n"
        "    record_identity(sys.argv[1])\n"
        "    time.sleep(10)\n"
        "time.sleep(10)\n"
    )
    assignment_cancellation = KeyboardInterrupt(
        "injected Popen applied-before-assignment cancellation"
    )
    assignment_processes: list[subprocess.Popen[bytes]] = []
    assignment_root_identity: tuple[int, int] | None = None
    assignment_pidfds: list[int] = []

    def cancel_after_popen(*args, **kwargs):
        nonlocal assignment_root_identity
        inner = original_popen(*args, **kwargs)
        assignment_processes.append(inner)
        marker_deadline = time.monotonic() + 2.0
        while not assignment_marker.is_file() and time.monotonic() < marker_deadline:
            sleep_original(0.01)
        root_record = fixture_process_map().get(inner.pid)
        if root_record is None or not assignment_marker.is_file():
            raise FixtureCleanupError(
                "Popen assignment oracle did not create its process tree"
            )
        assignment_root_identity = (inner.pid, root_record[1])
        raise assignment_cancellation

    def record_assignment_pidfd(pid: int, flags: int) -> int:
        descriptor = pidfd_open_original(pid, flags)
        assignment_pidfds.append(descriptor)
        return descriptor

    launcher_module.subprocess.Popen = cancel_after_popen
    launcher_module.os.pidfd_open = record_assignment_pidfd
    assignment_caught: BaseException | None = None
    residual_assignment_identities: set[tuple[int, int]] = set()
    child_identity: tuple[int, int] | None = None
    try:
        try:
            launcher_module.run_bounded(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    assignment_program,
                    str(assignment_marker),
                ],
                cwd=process_root,
                environment=environment,
                deadline=time.monotonic() + 5.0,
                stdout_limit=4096,
                stderr_limit=4096,
                label="Popen assignment fixture",
            )
        except BaseException as exc:
            assignment_caught = exc
    finally:
        launcher_module.os.pidfd_open = pidfd_open_original
        launcher_module.subprocess.Popen = original_popen
        if assignment_marker.is_file():
            child_identity = read_process_identity(
                assignment_marker,
                "Popen assignment child",
            )
        identities = tuple(
            identity
            for identity in (assignment_root_identity, child_identity)
            if identity is not None
        )
        snapshot = fixture_process_map()
        residual_assignment_identities = {
            identity
            for identity in identities
            if snapshot.get(identity[0], (0, -1))[1] == identity[1]
        }
        for pid, _start_time in residual_assignment_identities:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid, _start_time in identities:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        original_mask(signal.SIG_SETMASK, mask_before)
    assignment_pidfds_closed = True
    for descriptor in assignment_pidfds:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            assignment_pidfds_closed = False
            os.close(descriptor)
    if (
        assignment_caught is not assignment_cancellation
        or len(assignment_processes) != 1
        or assignment_root_identity is None
        or child_identity is None
        or residual_assignment_identities
        or not assignment_pidfds
        or not assignment_pidfds_closed
        or launcher_module.get_child_subreaper() != subreaper_before
        or frozenset(original_mask(signal.SIG_BLOCK, set())) != mask_before
        or any(
            signal.getsignal(signum) != handler
            for signum, handler in handlers_before.items()
        )
    ):
        raise SystemExit("bootstrap abandoned an unassigned Popen process") from assignment_caught


def test_private_gate_open_handoffs(
    launcher_module,
    private: pathlib.Path,
    gate_raw: bytes,
) -> None:
    original_open = launcher_module.os.open
    for role in ("writer", "reader"):
        gate_root = private / f"private-gate-{role}-open-handoff"
        gate_root.mkdir(mode=0o700)
        gate_path = gate_root / "trusted-dispatch-gate.py"
        cancellation = KeyboardInterrupt(
            f"injected private gate {role} open handoff cancellation"
        )
        descriptors: list[int] = []

        def cancel_gate_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            is_writer = bool(flags & os.O_WRONLY)
            selected_role = "writer" if is_writer else "reader"
            if (
                os.fspath(path) == os.fspath(gate_path)
                and selected_role == role
                and not descriptors
            ):
                descriptors.append(descriptor)
                raise cancellation
            return descriptor

        launcher_module.os.open = cancel_gate_open
        caught: BaseException | None = None
        try:
            try:
                launcher_module.publish_private_gate(gate_root, gate_raw)
            except BaseException as exc:
                caught = exc
        finally:
            launcher_module.os.open = original_open
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
        namespace_present = gate_path.exists()
        if namespace_present:
            gate_path.unlink()
        gate_root.rmdir()
        if (
            caught is not cancellation
            or len(descriptors) != 1
            or leaked
            or namespace_present
        ):
            raise SystemExit(
                f"private gate {role} open handoff custody drifted"
            ) from caught


def test_private_gate_fd_race(
    launcher_module,
    private: pathlib.Path,
    gate_raw: bytes,
) -> None:
    gate_root = private / "private-gate-race"
    gate_root.mkdir(mode=0o700)
    gate = launcher_module.publish_private_gate(gate_root, gate_raw)
    try:
        launcher_module.verify_private_gate(gate)
        gate.path.unlink()
        gate.path.write_text(
            "raise SystemExit('PRIVATE_REPLACEMENT_EXECUTED')\n",
            encoding="utf-8",
        )
        gate.path.chmod(0o500)
        result = launcher_module.run_bounded(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                f"/proc/self/fd/{gate.descriptor}",
                "--verify-only",
                "--repo-dir",
                str(gate_root),
                "--trusted-commit",
                launcher_module.TRUSTED_COMMIT,
                "--candidate-commit",
                launcher_module.CANDIDATE_COMMIT,
            ],
            cwd=gate_root,
            environment={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": str(gate_root),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            deadline=time.monotonic() + 5.0,
            stdout_limit=4096,
            stderr_limit=4096,
            label="private gate replacement fixture",
            pass_fds=(gate.descriptor,),
        )
        if (
            result.returncode
            or result.stderr
            or result.stdout != fixture_gate_transcript(launcher_module)
            or b"PRIVATE_REPLACEMENT_EXECUTED" in result.stdout + result.stderr
        ):
            raise FixtureCleanupError(
                "bootstrap executed a replaced private gate namespace"
            )
    finally:
        active = sys.exception()
        cleanup_primary = fixture_settle_owned_descriptor(
            gate.descriptor,
            active,
            "bootstrap private-gate descriptor close failed",
        )
        try:
            gate.path.unlink()
        except FileNotFoundError:
            pass
        except BaseException as exc:
            if not isinstance(exc, Exception):
                candidate = exc
            else:
                candidate = FixtureCleanupError(
                    "bootstrap private-gate namespace cleanup failed"
                )
                candidate.__cause__ = exc
            cleanup_primary = fixture_choose_failure(
                cleanup_primary,
                candidate,
                "bootstrap private-gate namespace cleanup also failed",
            )
        if cleanup_primary is not None and (
            active is None
            or cleanup_primary is not active
            or isinstance(active, FixtureCleanupError)
        ):
            fixture_raise_selected_failure(cleanup_primary)


def test_private_gate_main_settlement(
    launcher_module,
    launcher: pathlib.Path,
    repo: pathlib.Path,
    gate_raw: bytes,
) -> None:
    original_authenticate = launcher_module.authenticate_source
    original_publish = launcher_module.publish_private_gate
    original_run_bounded = launcher_module.run_bounded
    original_argv = list(sys.argv)

    expected_success_output = fixture_bootstrap_transcript(
        launcher_module,
        fixture_gate_transcript(launcher_module),
    )

    def observe_closed_descriptor(descriptor: int) -> bool:
        primary: BaseException | None = None
        for _ in range(3):
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    return True
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    "bootstrap settlement descriptor probe also failed",
                )
                continue
            except BaseException as exc:
                primary = fixture_choose_failure(
                    primary,
                    exc,
                    "bootstrap settlement descriptor probe also failed",
                )
                continue
            break
        cleanup_primary = fixture_settle_owned_descriptor(
            descriptor,
            primary,
            "bootstrap settlement emergency descriptor cleanup failed",
        )
        if cleanup_primary is not None:
            fixture_raise_selected_failure(cleanup_primary)
        return False

    for mode in ("normal", "failure", "replacement", "cancellation"):
        captured_gates = []
        replacement_bytes = b"replacement namespace\n"

        def capture_gate(private, raw):
            gate = original_publish(private, raw)
            captured_gates.append(gate)
            return gate

        def settled_run(*_args, **_kwargs):
            if mode == "replacement":
                gate = captured_gates[-1]
                gate.path.unlink()
                gate.path.write_bytes(replacement_bytes)
                gate.path.chmod(0o500)
            if mode == "cancellation":
                raise launcher_module.BootstrapSignal(signal.SIGTERM)
            if mode == "failure":
                return launcher_module.BoundedResult(
                    7,
                    b"",
                    b"ordinary gate failure\n",
                )
            return launcher_module.BoundedResult(
                0,
                fixture_gate_transcript(launcher_module),
                b"",
            )

        launcher_module.authenticate_source = (
            lambda _repo, _private, _deadline: gate_raw
        )
        launcher_module.publish_private_gate = capture_gate
        launcher_module.run_bounded = settled_run
        sys.argv = [str(launcher), "--verify-only", "--repo-dir", str(repo)]
        output = io.StringIO()
        caught: BaseException | None = None
        try:
            try:
                with contextlib.redirect_stdout(output):
                    launcher_module.main()
            except BaseException as exc:
                caught = exc
        finally:
            launcher_module.run_bounded = original_run_bounded
            launcher_module.publish_private_gate = original_publish
            launcher_module.authenticate_source = original_authenticate
            sys.argv = list(original_argv)
        if len(captured_gates) != 1:
            raise SystemExit("bootstrap main settlement gate count drifted")
        gate = captured_gates[0]
        descriptor_closed = observe_closed_descriptor(gate.descriptor)
        if mode == "replacement":
            if (
                not isinstance(caught, SystemExit)
                or "private gate namespace changed before cleanup" not in str(caught)
                or output.getvalue()
                or not descriptor_closed
                or not gate.path.is_file()
                or gate.path.read_bytes() != replacement_bytes
                or stat.S_IMODE(gate.path.stat().st_mode) != 0o500
            ):
                raise SystemExit(
                    "bootstrap main did not preserve a replacement namespace"
                ) from caught
            gate.path.unlink()
            gate.path.parent.rmdir()
        elif mode == "cancellation":
            if (
                not isinstance(caught, SystemExit)
                or caught.code != 143
                or output.getvalue()
                or not descriptor_closed
                or gate.path.exists()
                or gate.path.parent.exists()
            ):
                raise SystemExit(
                    "bootstrap main did not settle its cancelled private gate"
                ) from caught
        elif mode == "failure":
            if (
                not isinstance(caught, SystemExit)
                or "private trusted workflow gate rejected the request"
                not in str(caught)
                or output.getvalue()
                or not descriptor_closed
                or gate.path.exists()
                or gate.path.parent.exists()
            ):
                raise SystemExit(
                    "bootstrap main did not settle its failed private gate"
                ) from caught
        elif (
            caught is not None
            or output.getvalue() != expected_success_output
            or not descriptor_closed
            or gate.path.exists()
            or gate.path.parent.exists()
        ):
            raise SystemExit(
                "bootstrap main did not settle its successful private gate"
            ) from caught


@fixture_owner_scoped
def test_launcher_cli_signals(
    private: pathlib.Path,
    external: pathlib.Path,
) -> None:
    for signal_name, expected_returncode in (("SIGINT", 130), ("SIGTERM", 143)):
        repo = private / f"cli-{signal_name.lower()}-repo"
        repo.mkdir(mode=0o700)
        (repo / "home").mkdir(mode=0o700)
        root_identity = private / f"cli-{signal_name.lower()}-root.identity"
        descendant_identity = (
            private / f"cli-{signal_name.lower()}-descendant.identity"
        )
        gate_source = (
            "#!/usr/bin/env python3\n"
            "import os, pathlib, signal, time\n"
            + PROCESS_IDENTITY_HELPER
            + f"ROOT_IDENTITY = {str(root_identity)!r}\n"
            f"DESCENDANT_IDENTITY = {str(descendant_identity)!r}\n"
            "read_fd, write_fd = os.pipe()\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.close(read_fd)\n"
            "    os.setsid()\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    record_identity(DESCENDANT_IDENTITY)\n"
            "    os.write(write_fd, b'1')\n"
            "    while True: time.sleep(1)\n"
            "os.close(write_fd)\n"
            "record_identity(ROOT_IDENTITY)\n"
            "os.read(read_fd, 1)\n"
            f"os.kill(os.getppid(), signal.{signal_name})\n"
            "while True: time.sleep(1)\n"
        ).encode("utf-8")
        for relative in (GATE_PATH, WORKFLOW_PATH, BOUNDARY_PATH, ISOLATION_PATH):
            (repo / relative).parent.mkdir(parents=True, exist_ok=True)
        (repo / GATE_PATH).write_bytes(gate_source)
        (repo / GATE_PATH).chmod(0o644)
        (repo / WORKFLOW_PATH).write_text(
            "name: cli signal fixture\n",
            encoding="utf-8",
        )
        (repo / WORKFLOW_PATH).chmod(0o644)
        (repo / BOUNDARY_PATH).write_text(
            "#!/usr/bin/env python3\nprint('BOUNDARY=PASS')\n",
            encoding="utf-8",
        )
        (repo / BOUNDARY_PATH).chmod(0o755)
        (repo / ISOLATION_PATH).write_text(
            "#!/usr/bin/env python3\nprint('ISOLATION=PASS')\n",
            encoding="utf-8",
        )
        (repo / ISOLATION_PATH).chmod(0o644)
        git(repo, "init", "-q")
        git(repo, "add", "-A")
        git(
            repo,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            f"cli {signal_name} P",
        )
        trusted = git(repo, "rev-parse", "HEAD")
        git(
            repo,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            f"cli {signal_name} C",
        )
        candidate = git(repo, "rev-parse", "HEAD")
        digests = tuple(
            sha256(repo / relative)
            for relative in (
                GATE_PATH,
                WORKFLOW_PATH,
                BOUNDARY_PATH,
                ISOLATION_PATH,
            )
        )
        launcher = render_launcher(
            repo,
            external,
            f"cli-{signal_name.lower()}-bootstrap.py",
            trusted,
            candidate,
            digests,
        )
        result = run_pinned_launcher(
            launcher,
            repo,
            [
                "--verify-only",
                "--repo-dir",
                str(repo),
            ],
            environment=fixture_environment(repo),
            timeout=15.0,
        )
        if (
            result.returncode != expected_returncode
            or result.stdout
            or len(result.stderr) > MAX_OUTPUT
        ):
            raise SystemExit(
                f"bootstrap CLI {signal_name} returned {result.returncode}, "
                f"expected {expected_returncode}"
            )
        if not root_identity.is_file() or not descendant_identity.is_file():
            raise SystemExit(
                f"bootstrap CLI {signal_name} omitted process identities"
            )
        require_process_gone(root_identity, f"CLI {signal_name} gate root")
        require_process_gone(
            descendant_identity,
            f"CLI {signal_name} detached descendant",
        )


def test_outer_signal_windows(
    launcher_module,
    launcher: pathlib.Path,
    repo: pathlib.Path,
    gate_raw: bytes,
) -> None:
    original_authenticate = launcher_module.authenticate_source
    original_verify = launcher_module.verify_private_gate
    original_run = launcher_module.run_bounded
    original_argv = sys.argv
    original_handlers = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    signal_cases = (
        ("SIGTERM", (signal.SIGTERM,), 143),
        ("SIGINT", (signal.SIGINT,), 130),
        ("SIGTERM-SIGINT", (signal.SIGTERM, signal.SIGINT), 130),
    )
    for stage in ("authentication", "pre-run", "post-run"):
        for signal_label, signals_to_send, expected_status in signal_cases:
            private_paths: list[pathlib.Path] = []

            def send_fixture_signals() -> None:
                for signum in signals_to_send:
                    os.kill(os.getpid(), signum)

            def fixture_authenticate(_repo, private, _deadline):
                private_paths.append(private)
                if stage == "authentication":
                    send_fixture_signals()
                return gate_raw

            def fixture_verify(_gate) -> None:
                if stage == "pre-run":
                    send_fixture_signals()

            def fixture_run(*_args, **_kwargs):
                if stage == "post-run":
                    send_fixture_signals()
                return launcher_module.BoundedResult(
                    0,
                    fixture_gate_transcript(launcher_module),
                    b"",
                )

            launcher_module.authenticate_source = fixture_authenticate
            launcher_module.verify_private_gate = fixture_verify
            launcher_module.run_bounded = fixture_run
            sys.argv = [
                str(launcher),
                "--verify-only",
                "--repo-dir",
                str(repo),
            ]
            output = io.StringIO()
            caught: SystemExit | None = None
            try:
                with contextlib.redirect_stdout(output):
                    launcher_module.main()
            except SystemExit as exc:
                caught = exc
            finally:
                sys.argv = original_argv
                launcher_module.authenticate_source = original_authenticate
                launcher_module.verify_private_gate = original_verify
                launcher_module.run_bounded = original_run
            if (
                caught is None
                or caught.code != expected_status
                or output.getvalue()
            ):
                raise SystemExit(
                    f"bootstrap outer {stage} {signal_label} boundary drifted: "
                    f"caught={caught!r} output={output.getvalue()!r}"
                ) from caught
            if len(private_paths) != 1 or private_paths[0].exists():
                raise SystemExit(
                    f"bootstrap outer {stage} {signal_label} left its private "
                    "directory"
                )
            if any(
                signal.getsignal(signum) != original_handlers[signum]
                for signum in original_handlers
            ) or signal.pthread_sigmask(signal.SIG_BLOCK, set()) != original_mask:
                raise SystemExit(
                    f"bootstrap outer {stage} {signal_label} changed caller "
                    "signal state"
                )

    sys.argv = [str(launcher), "--verify-only", "--repo-dir", str(repo)]
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    try:
        blocked_caught: SystemExit | None = None
        blocked_output = io.StringIO()
        try:
            with contextlib.redirect_stdout(blocked_output):
                launcher_module.main()
        except SystemExit as exc:
            blocked_caught = exc
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        sys.argv = original_argv
    if (
        blocked_caught is None
        or str(blocked_caught)
        != "haptics workflow bootstrap failed: bootstrap inherited a blocked "
        "SIGINT or SIGTERM"
        or blocked_output.getvalue()
    ):
        raise SystemExit("bootstrap outer inherited-mask boundary drifted")

    original_signal = launcher_module.signal.signal
    handler_injected = False

    def handler_apply_then_fail(signum, handler):
        nonlocal handler_injected
        result = original_signal(signum, handler)
        if (
            not handler_injected
            and signum == signal.SIGINT
            and isinstance(
                getattr(handler, "__self__", None),
                launcher_module.BootstrapCancellationGuard,
            )
        ):
            handler_injected = True
            raise OSError("injected outer handler installation failure")
        return result

    launcher_module.signal.signal = handler_apply_then_fail
    sys.argv = [str(launcher), "--verify-only", "--repo-dir", str(repo)]
    try:
        handler_caught: SystemExit | None = None
        try:
            launcher_module.main()
        except SystemExit as exc:
            handler_caught = exc
    finally:
        sys.argv = original_argv
        launcher_module.signal.signal = original_signal
    if (
        not handler_injected
        or handler_caught is None
        or str(handler_caught)
        != "haptics workflow bootstrap failed: cannot install outer bootstrap "
        "cancellation state"
        or any(
            signal.getsignal(signum) != original_handlers[signum]
            for signum in original_handlers
        )
        or signal.pthread_sigmask(signal.SIG_BLOCK, set()) != original_mask
    ):
        raise SystemExit("bootstrap outer handler applied-error recovery drifted")

    original_atomic_capture = launcher_module.atomic_capture_and_block
    for inherited_mask in (
        frozenset(),
        frozenset((signal.SIGINT,)),
        frozenset((signal.SIGTERM,)),
        frozenset((signal.SIGINT, signal.SIGTERM)),
        frozenset((signal.SIGUSR1, signal.SIGTERM)),
    ):
        mask_injected = False
        mask_calls: list[frozenset[signal.Signals]] = []

        def mask_apply_then_fail(signals, capture):
            nonlocal mask_injected
            mask_calls.append(frozenset(signals))
            original_atomic_capture(signals, capture)
            if not mask_injected:
                mask_injected = True
                raise OSError("injected outer mask installation failure")

        previous_inherited = signal.pthread_sigmask(
            signal.SIG_SETMASK,
            inherited_mask,
        )
        launcher_module.atomic_capture_and_block = mask_apply_then_fail
        sys.argv = [str(launcher), "--verify-only", "--repo-dir", str(repo)]
        try:
            mask_caught: SystemExit | None = None
            try:
                launcher_module.main()
            except SystemExit as exc:
                mask_caught = exc
            restored_inherited = frozenset(
                signal.pthread_sigmask(signal.SIG_BLOCK, set())
            )
        finally:
            sys.argv = original_argv
            launcher_module.atomic_capture_and_block = original_atomic_capture
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_inherited)
        if (
            not mask_injected
            or mask_calls
            != [frozenset((signal.SIGINT, signal.SIGTERM))]
            or mask_caught is None
            or str(mask_caught)
            != "haptics workflow bootstrap failed: cannot install outer bootstrap "
            "cancellation state"
            or any(
                signal.getsignal(signum) != original_handlers[signum]
                for signum in original_handlers
            )
            or restored_inherited != inherited_mask
        ):
            raise SystemExit(
                "bootstrap outer mask applied-error recovery drifted: "
                f"inherited={inherited_mask!r} injected={mask_injected!r} "
                f"calls={mask_calls!r} caught={mask_caught!r} "
                f"restored={restored_inherited!r}"
            )

    original_exit = launcher_module.BootstrapCancellationGuard.__exit__

    def exit_then_cancel(self, kind, value, traceback):
        original_exit(self, kind, value, traceback)
        raise launcher_module.BootstrapSignal(signal.SIGTERM)

    launcher_module.authenticate_source = lambda _repo, _private, _deadline: gate_raw
    launcher_module.verify_private_gate = lambda _gate: None
    launcher_module.run_bounded = lambda *_args, **_kwargs: launcher_module.BoundedResult(
        0,
        fixture_gate_transcript(launcher_module),
        b"",
    )
    launcher_module.BootstrapCancellationGuard.__exit__ = exit_then_cancel
    sys.argv = [str(launcher), "--verify-only", "--repo-dir", str(repo)]
    post_evidence_output = io.StringIO()
    post_evidence_caught: SystemExit | None = None
    try:
        with contextlib.redirect_stdout(post_evidence_output):
            launcher_module.main()
    except SystemExit as exc:
        post_evidence_caught = exc
    finally:
        sys.argv = original_argv
        launcher_module.authenticate_source = original_authenticate
        launcher_module.verify_private_gate = original_verify
        launcher_module.run_bounded = original_run
        launcher_module.BootstrapCancellationGuard.__exit__ = original_exit
    if (
        post_evidence_caught is None
        or post_evidence_caught.code != 143
        or post_evidence_output.getvalue()
        or any(
            signal.getsignal(signum) != original_handlers[signum]
            for signum in original_handlers
        )
        or signal.pthread_sigmask(signal.SIG_BLOCK, set()) != original_mask
    ):
        raise SystemExit(
            "bootstrap post-evidence cancellation boundary drifted: "
            f"caught={post_evidence_caught!r} "
            f"output={post_evidence_output.getvalue()!r}"
        ) from post_evidence_caught

    handoff_events: list[int] = []

    def caller_term_handler(signum, _frame) -> None:
        handoff_events.append(signum)

    signal.signal(signal.SIGTERM, caller_term_handler)
    handoff_guard = launcher_module.BootstrapCancellationGuard()
    handoff_guard.__enter__()
    handoff_original_mask = handoff_guard.original_mask
    handoff_original_sigmask = launcher_module.signal.pthread_sigmask
    handoff_injected = False

    def inject_at_mask_handoff(how, mask):
        nonlocal handoff_injected
        if (
            not handoff_injected
            and how == signal.SIG_SETMASK
            and frozenset(mask) == handoff_original_mask
        ):
            handoff_injected = True
            os.kill(os.getpid(), signal.SIGTERM)
        return handoff_original_sigmask(how, mask)

    launcher_module.signal.pthread_sigmask = inject_at_mask_handoff
    handoff_result = None
    try:
        handoff_result = handoff_guard.__exit__(None, None, None)
    finally:
        launcher_module.signal.pthread_sigmask = handoff_original_sigmask
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    if (
        not handoff_injected
        or handoff_events != [signal.SIGTERM]
        or handoff_result is not False
        or handoff_guard.signum is not None
    ):
        raise SystemExit(
            "bootstrap final signal-handoff boundary drifted: "
            f"injected={handoff_injected!r} events={handoff_events!r} "
            f"result={handoff_result!r} selected={handoff_guard.signum!r}"
        )

    default_int_sigmask = launcher_module.signal.pthread_sigmask
    default_int_injected = False
    default_int_masks: list[frozenset[signal.Signals]] = []

    def inject_default_int_handoff(how, mask):
        nonlocal default_int_injected
        should_inject = (
            not default_int_injected
            and how == signal.SIG_SETMASK
            and frozenset(mask) == frozenset(original_mask)
            and signal.getsignal(signal.SIGINT) == signal.default_int_handler
        )
        result = default_int_sigmask(how, mask)
        if should_inject:
            default_int_injected = True
            default_int_masks.append(
                frozenset(default_int_sigmask(signal.SIG_BLOCK, set()))
            )
            signal.default_int_handler(signal.SIGINT, None)
        return result

    launcher_module.authenticate_source = lambda _repo, _private, _deadline: gate_raw
    launcher_module.verify_private_gate = lambda _gate: None
    launcher_module.run_bounded = lambda *_args, **_kwargs: launcher_module.BoundedResult(
        0,
        fixture_gate_transcript(launcher_module),
        b"",
    )
    launcher_module.signal.pthread_sigmask = inject_default_int_handoff
    signal.signal(signal.SIGINT, signal.default_int_handler)
    sys.argv = [str(launcher), "--verify-only", "--repo-dir", str(repo)]
    default_int_output = io.StringIO()
    default_int_caught: SystemExit | None = None
    try:
        try:
            with contextlib.redirect_stdout(default_int_output):
                launcher_module.main()
        except SystemExit as exc:
            default_int_caught = exc
    finally:
        sys.argv = original_argv
        launcher_module.signal.pthread_sigmask = default_int_sigmask
        launcher_module.authenticate_source = original_authenticate
        launcher_module.verify_private_gate = original_verify
        launcher_module.run_bounded = original_run
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    if (
        not default_int_injected
        or default_int_caught is None
        or default_int_caught.code != 130
        or default_int_masks != [frozenset()]
        or default_int_output.getvalue()
    ):
        raise SystemExit(
            "bootstrap default-SIGINT handoff boundary drifted: "
            f"injected={default_int_injected!r} caught={default_int_caught!r} "
            f"masks={default_int_masks!r} output={default_int_output.getvalue()!r}"
        ) from default_int_caught

    class CallerHandoffError(RuntimeError):
        pass

    raising_events: list[int] = []

    def raising_term_handler(signum, _frame) -> None:
        raising_events.append(signum)
        raise CallerHandoffError("caller TERM policy")

    signal.signal(signal.SIGTERM, raising_term_handler)
    raising_guard = launcher_module.BootstrapCancellationGuard()
    raising_guard.__enter__()
    raising_original_mask = raising_guard.original_mask
    raising_original_sigmask = launcher_module.signal.pthread_sigmask
    raising_injected = False
    raising_setmask_calls = 0

    def inject_raising_handoff(how, mask):
        nonlocal raising_injected, raising_setmask_calls
        if how == signal.SIG_SETMASK and frozenset(mask) == raising_original_mask:
            raising_setmask_calls += 1
            if not raising_injected:
                raising_injected = True
                result = raising_original_sigmask(how, mask)
                raising_term_handler(signal.SIGTERM, None)
                return result
        return raising_original_sigmask(how, mask)

    launcher_module.signal.pthread_sigmask = inject_raising_handoff
    raising_caught: BaseException | None = None
    try:
        try:
            raising_guard.__exit__(None, None, None)
        except BaseException as exc:
            raising_caught = exc
    finally:
        launcher_module.signal.pthread_sigmask = raising_original_sigmask
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    if (
        not raising_injected
        or raising_setmask_calls != 1
        or raising_events != [signal.SIGTERM]
        or not isinstance(raising_caught, CallerHandoffError)
        or str(raising_caught) != "caller TERM policy"
    ):
        raise SystemExit(
            "bootstrap raising-handler handoff boundary drifted: "
            f"injected={raising_injected!r} calls={raising_setmask_calls!r} "
            f"events={raising_events!r} caught={raising_caught!r}"
        ) from raising_caught


@fixture_owner_scoped
def test_real_dispatcher_through_launcher(
    private: pathlib.Path,
    external: pathlib.Path,
) -> None:
    source_root = SCRIPT_DIR.parents[1]
    real_repo = private / "real-dispatcher-repo"
    real_repo.mkdir(mode=0o700)
    (real_repo / "home").mkdir(mode=0o700)
    git(real_repo, "init", "-q")
    for relative, mode in (
        (GATE_PATH, 0o644),
        (WORKFLOW_PATH, 0o644),
        (BOUNDARY_PATH, 0o755),
        (ISOLATION_PATH, 0o644),
    ):
        target = real_repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / relative).read_bytes())
        target.chmod(mode)
    git(real_repo, "add", "-A")
    git(
        real_repo,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "real dispatcher P",
    )
    trusted = git(real_repo, "rev-parse", "HEAD")
    git(
        real_repo,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "real dispatcher C",
    )
    candidate = git(real_repo, "rev-parse", "HEAD")
    digests = tuple(
        sha256(real_repo / relative)
        for relative in (GATE_PATH, WORKFLOW_PATH, BOUNDARY_PATH, ISOLATION_PATH)
    )
    launcher = render_launcher(
        real_repo,
        external,
        "real-dispatcher-bootstrap.py",
        trusted,
        candidate,
        digests,
    )
    result = run_launcher(launcher, real_repo)
    production_result = run_production_launcher(launcher, real_repo)
    expected_lines = [
        "schema\ttb321fu.haptics-workflow-bootstrap/v1",
        f"trusted-commit\t{trusted}",
        f"candidate-commit\t{candidate}",
        f"gate-sha256\t{digests[0]}",
        f"workflow-sha256\t{digests[1]}",
        f"validator-sha256\t{BOUNDARY_PATH.as_posix()}\t{digests[2]}",
        f"validator-sha256\t{ISOLATION_PATH.as_posix()}\t{digests[3]}",
        "schema\ttb321fu.haptics-workflow-gate/v1",
        f"trusted-commit\t{trusted}",
        f"candidate-commit\t{candidate}",
        f"gate-sha256\t{digests[0]}",
        f"workflow-sha256\t{digests[1]}",
        f"validator-sha256\t{BOUNDARY_PATH.as_posix()}\t{digests[2]}",
        f"validator-sha256\t{ISOLATION_PATH.as_posix()}\t{digests[3]}",
        "validator-mode\ttrusted-commit-blobs/v1",
        "HAPTICS_WORKFLOW_GATE_VERIFY=PASS",
        "HAPTICS_WORKFLOW_BOOTSTRAP=PASS",
    ]
    expected_output = "\n".join(expected_lines) + "\n"
    if result.returncode or result.stderr or result.stdout != expected_output:
        raise SystemExit(
            "real dispatcher did not pass through the rendered external launcher: "
            f"returncode={result.returncode} stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )
    if (
        production_result.returncode
        or production_result.stderr
        or production_result.stdout != expected_output
    ):
        raise SystemExit(
            "production runner did not pass through the rendered external launcher: "
            f"returncode={production_result.returncode} "
            f"stdout={production_result.stdout!r} stderr={production_result.stderr!r}"
        )


def test_launcher_profile_wiring(
    launcher_module,
    launcher: pathlib.Path,
    repo: pathlib.Path,
    private: pathlib.Path,
    gate_raw: bytes,
) -> None:
    profile_home = private / "profile-home"
    profile_home.mkdir(mode=0o700)
    state_parent = profile_home / "state"
    state_parent.mkdir(mode=0o700)
    original_authenticate = launcher_module.authenticate_source
    original_home = launcher_module.require_operator_home
    original_run_bounded = launcher_module.run_bounded
    original_argv = sys.argv
    original_monotonic = launcher_module.time.monotonic
    fixed_monotonic = 1234.5
    expected_outer_deadline = (
        fixed_monotonic + launcher_module.BOOTSTRAP_TIMEOUT_SECONDS
    )
    expected_gate_deadline = min(
        fixed_monotonic + launcher_module.GATE_TIMEOUT_SECONDS,
        expected_outer_deadline - launcher_module.BOOTSTRAP_CLEANUP_GRACE_SECONDS,
    )
    proxy_values = {
        "http_proxy": "http://127.0.0.1:18080",
        "https_proxy": "http://127.0.0.1:18443",
        "no_proxy": "127.0.0.1,localhost",
    }
    previous_proxies = {name: os.environ.get(name) for name in proxy_values}
    captures: list[
        tuple[list[str], dict[str, str], tuple[int, ...], float]
    ] = []

    def fixture_home(profile: str):
        return (
            profile_home,
            state_parent
            / f"{launcher_module.CANDIDATE_COMMIT}.{profile}.tsv",
        )

    def fixture_run_bounded(arguments, **kwargs):
        pass_fds = kwargs.get("pass_fds", ())
        environment = kwargs.get("environment")
        deadline = kwargs.get("deadline")
        if (
            type(environment) is not dict
            or len(pass_fds) != 1
            or arguments[3] != f"/proc/self/fd/{pass_fds[0]}"
            or environment.get("GH_ALLOW_DISPATCH") != "1"
            or deadline != expected_outer_deadline
        ):
            raise SystemExit("bootstrap profile fixture lost trusted execution custody")
        captures.append(
            (list(arguments), dict(environment), tuple(pass_fds), deadline)
        )
        release_tag = ""
        if "--release-tag" in arguments:
            release_index = arguments.index("--release-tag") + 1
            release_tag = arguments[release_index]
        return launcher_module.BoundedResult(
            0,
            fixture_gate_transcript(
                launcher_module,
                dispatch=True,
                release_tag=release_tag,
            ),
            b"",
        )

    launcher_module.authenticate_source = lambda *args, **kwargs: gate_raw
    launcher_module.require_operator_home = fixture_home
    launcher_module.run_bounded = fixture_run_bounded
    launcher_module.time.monotonic = lambda: fixed_monotonic
    os.environ.update(proxy_values)
    profiles = ("diagnostic", "diagnostic", "release", "release")
    try:
        for profile in profiles:
            sys.argv = [
                str(launcher),
                "--profile",
                profile,
                "--repo-dir",
                str(repo),
            ]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                launcher_module.main()
            release_tag = (
                launcher_module.RELEASE_TAG if profile == "release" else ""
            )
            expected_output = fixture_bootstrap_transcript(
                launcher_module,
                fixture_gate_transcript(
                    launcher_module,
                    dispatch=True,
                    release_tag=release_tag,
                ),
            )
            if output.getvalue() != expected_output:
                raise SystemExit(
                    f"bootstrap {profile} profile evidence transcript is not exact"
                )
    finally:
        sys.argv = original_argv
        launcher_module.authenticate_source = original_authenticate
        launcher_module.require_operator_home = original_home
        launcher_module.run_bounded = original_run_bounded
        launcher_module.time.monotonic = original_monotonic
        for name, value in previous_proxies.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    if len(captures) != 4:
        raise SystemExit("bootstrap profile fixture capture count drifted")
    states: list[str] = []
    for index, (arguments, environment, pass_fds, deadline) in enumerate(captures):
        profile = profiles[index]
        release_tag = launcher_module.RELEASE_TAG if profile == "release" else ""
        state = state_parent / f"{launcher_module.CANDIDATE_COMMIT}.{profile}.tsv"
        expected_arguments = [
            "/usr/bin/python3",
            "-I",
            "-B",
            f"/proc/self/fd/{pass_fds[0]}",
            "--dispatch",
            "--repo-dir",
            str(repo),
            "--trusted-commit",
            launcher_module.TRUSTED_COMMIT,
            "--candidate-commit",
            launcher_module.CANDIDATE_COMMIT,
            "--repository",
            launcher_module.REPOSITORY,
            "--remote-ref",
            launcher_module.REMOTE_REF,
        ]
        if release_tag:
            expected_arguments.extend(("--release-tag", release_tag))
        expected_arguments.extend(("--dispatch-state", str(state)))
        fixed_environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(profile_home),
            "PYTHONDONTWRITEBYTECODE": "1",
            "HAPTICS_TRUSTED_GATE_SHA256": launcher_module.GATE_SHA256,
            "HAPTICS_WORKFLOW_DEADLINE_NS": str(
                int(expected_gate_deadline * 1_000_000_000)
            ),
            "GH_HOST": "github.com",
            "GH_PROMPT_DISABLED": "1",
            "GH_PAGER": "cat",
            "NO_COLOR": "1",
            "GH_ALLOW_DISPATCH": "1",
            **proxy_values,
        }
        if (
            arguments != expected_arguments
            or environment != fixed_environment
            or deadline != expected_outer_deadline
        ):
            raise SystemExit(
                f"bootstrap {profile} exact dispatch wiring drifted: {arguments!r}"
            )
        states.append(str(state))
    if states[0] != states[1] or states[2] != states[3] or states[0] == states[2]:
        raise SystemExit("bootstrap diagnostic/release replay wiring drifted")


def run(
    arguments: list[str],
    cwd: pathlib.Path,
    *,
    environment: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    result = fixture_run_process(
        arguments,
        cwd,
        environment=environment,
        pass_fds=pass_fds,
        timeout=timeout,
    )
    try:
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("bootstrap fixture subprocess output must be UTF-8") from exc
    return subprocess.CompletedProcess(
        arguments,
        result.returncode,
        stdout,
        stderr,
    )


def git(repo: pathlib.Path, *arguments: str) -> str:
    result = run(["/usr/bin/git", "-C", str(repo), *arguments], repo)
    if result.returncode:
        raise SystemExit(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def hash_object(
    repo: pathlib.Path,
    object_type: str,
    raw: bytes,
) -> str:
    result = fixture_run_process(
        [
            "/usr/bin/git",
            "-C",
            str(repo),
            "hash-object",
            "-t",
            object_type,
            "-w",
            "--stdin",
            "--literally",
        ],
        repo,
        input_bytes=raw,
        timeout=10.0,
    )
    if (
        result.returncode
        or len(result.stdout) != 41
        or result.stdout[-1:] != b"\n"
        or any(byte not in b"0123456789abcdef" for byte in result.stdout[:-1])
        or len(result.stderr) > MAX_OUTPUT
    ):
        raise SystemExit(f"cannot create fixture {object_type} object")
    return result.stdout[:-1].decode("ascii")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_launcher(
    repo: pathlib.Path,
    external: pathlib.Path,
    name: str,
    trusted: str,
    candidate: str,
    digests: tuple[str, str, str, str],
) -> pathlib.Path:
    output = external / name
    result = run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(RENDERER),
            "--output",
            str(output),
            "--trusted-commit",
            trusted,
            "--candidate-commit",
            candidate,
            "--gate-sha256",
            digests[0],
            "--workflow-sha256",
            digests[1],
            "--boundary-validator-sha256",
            digests[2],
            "--isolation-validator-sha256",
            digests[3],
        ],
        repo,
    )
    if result.returncode or "HAPTICS_WORKFLOW_BOOTSTRAP_RENDER=PASS" not in result.stdout:
        raise SystemExit(f"bootstrap render failed: {result.stderr.strip()}")
    if (
        not output.is_file()
        or stat_mode(output) != 0o500
        or output.stat().st_nlink != 1
        or b"@@" in output.read_bytes()
    ):
        raise SystemExit("rendered bootstrap metadata differs from policy")
    expected_evidence = [
        "schema\ttb321fu.haptics-workflow-bootstrap-render/v1",
        f"output\t{output}",
        f"sha256\t{sha256(output)}",
        "HAPTICS_WORKFLOW_BOOTSTRAP_RENDER=PASS",
    ]
    expected_output = "\n".join(expected_evidence) + "\n"
    if result.stderr or result.stdout != expected_output:
        raise SystemExit("bootstrap renderer evidence differs from published output")
    RENDERED_LAUNCHER_DIGESTS[output] = expected_evidence[2].split("\t", 1)[1]
    return output


def stat_mode(path: pathlib.Path) -> int:
    return path.stat().st_mode & 0o777


def run_pinned_launcher(
    launcher: pathlib.Path,
    repo: pathlib.Path,
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    expected_digest = RENDERED_LAUNCHER_DIGESTS.get(launcher)
    if expected_digest is None:
        raise SystemExit("bootstrap fixture lacks the rendered launcher digest")
    # Both descriptors are transferred and settled by this function's own
    # finally block; callers may invoke run_pinned_launcher during fixture
    # repository construction before a test lifetime is registered.
    launcher_owner = _fixture_local_descriptor_owner()
    execution_owner = _fixture_local_descriptor_owner()
    try:
        initial_namespace = os.stat(launcher, follow_symlinks=False)
        acquire_existing_fixture_descriptor(
            launcher_owner,
            launcher,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            (initial_namespace.st_dev, initial_namespace.st_ino),
            "bootstrap fixture launcher fd handoff",
        )
        descriptor = launcher_owner.descriptor
        before = os.fstat(descriptor)
        namespace = os.stat(launcher, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o500
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 256 * 1024
            or (before.st_dev, before.st_ino)
            != (namespace.st_dev, namespace.st_ino)
        ):
            raise FixtureCleanupError(
                "bootstrap fixture launcher metadata differs from policy"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise FixtureCleanupError(
                    "bootstrap fixture launcher ended during attestation"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise FixtureCleanupError(
                "bootstrap fixture launcher exceeds its size bound"
            )
        after = os.fstat(descriptor)
        if (
            hashlib.sha256(b"".join(chunks)).hexdigest() != expected_digest
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
        ):
            raise FixtureCleanupError(
                "bootstrap fixture launcher changed during attestation"
            )
        raw = b"".join(chunks)
        required_memfd_flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        acquire_fixture_memfd(
            execution_owner,
            "tb321fu-haptics-bootstrap",
            required_memfd_flags,
            "bootstrap fixture execution memfd handoff",
        )
        execution_descriptor = execution_owner.descriptor
        offset = 0
        while offset < len(raw):
            written = os.write(execution_descriptor, raw[offset:])
            if written <= 0:
                raise FixtureCleanupError(
                    "bootstrap fixture memfd write made no progress"
                )
            offset += written
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(execution_descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(execution_descriptor, fcntl.F_GET_SEALS) & seals != seals:
            raise FixtureCleanupError(
                "bootstrap fixture memfd sealing did not complete"
            )
        os.lseek(execution_descriptor, 0, os.SEEK_SET)
        return run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                f"/proc/self/fd/{execution_descriptor}",
                *arguments,
            ],
            repo,
            environment=environment,
            pass_fds=(execution_descriptor,),
            timeout=timeout,
        )
    finally:
        active = sys.exception()
        cleanup_primary = active
        cleanup_primary = settle_fixture_descriptor_owner(
            execution_owner,
            cleanup_primary,
            "bootstrap fixture execution memfd",
        )
        cleanup_primary = settle_fixture_descriptor_owner(
            launcher_owner,
            cleanup_primary,
            "bootstrap fixture launcher fd",
        )
        if cleanup_primary is not None and (
            active is None
            or cleanup_primary is not active
            or isinstance(active, FixtureCleanupError)
        ):
            fixture_raise_selected_failure(cleanup_primary)


def run_launcher(
    launcher: pathlib.Path, repo: pathlib.Path
) -> subprocess.CompletedProcess[str]:
    return run_pinned_launcher(
        launcher,
        repo,
        ["--verify-only", "--repo-dir", str(repo)],
    )


def run_production_launcher(
    launcher: pathlib.Path,
    repo: pathlib.Path,
    *,
    digest: str | None = None,
) -> subprocess.CompletedProcess[str]:
    account_home = pwd.getpwuid(os.geteuid()).pw_dir
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": account_home,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(SCRIPT_DIR / "run-haptics-workflow-dispatch-bootstrap.py"),
            "--launcher",
            str(launcher),
            "--launcher-sha256",
            digest if digest is not None else sha256(launcher),
            "--repo-dir",
            str(repo),
            "--timeout-seconds",
            "30",
            "--verify-only",
        ],
        repo,
        environment=environment,
        timeout=45.0,
    )


@fixture_owner_scoped
def test_run_pinned_launcher_handoffs(
    launcher: pathlib.Path,
    repo: pathlib.Path,
) -> None:
    original_open = os.open
    original_memfd_create = os.memfd_create
    original_fstat = os.fstat
    original_close = os.close

    open_descriptors: list[int] = []
    open_cancellation = KeyboardInterrupt(
        "injected pinned launcher open handoff cancellation"
    )

    def cancel_launcher_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if os.fspath(path) == os.fspath(launcher):
            open_descriptors.append(descriptor)
            raise open_cancellation
        return descriptor

    os.open = cancel_launcher_open
    open_caught: BaseException | None = None
    try:
        try:
            run_launcher(launcher, repo)
        except BaseException as exc:
            open_caught = exc
    finally:
        os.open = original_open
    open_closed = True
    for descriptor in open_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                open_closed = False
        else:
            open_closed = False
            original_close(descriptor)
    if (
        open_caught is not open_cancellation
        or len(open_descriptors) != 1
        or not open_closed
    ):
        raise SystemExit("pinned launcher open handoff custody drifted") from open_caught

    memfd_descriptors: list[int] = []
    memfd_cancellation = KeyboardInterrupt(
        "injected pinned launcher memfd handoff cancellation"
    )

    def cancel_launcher_memfd(name: str, flags: int) -> int:
        descriptor = original_memfd_create(name, flags)
        if name == "tb321fu-haptics-bootstrap":
            memfd_descriptors.append(descriptor)
            raise memfd_cancellation
        return descriptor

    os.memfd_create = cancel_launcher_memfd
    memfd_caught: BaseException | None = None
    try:
        try:
            run_launcher(launcher, repo)
        except BaseException as exc:
            memfd_caught = exc
    finally:
        os.memfd_create = original_memfd_create
    memfd_closed = True
    for descriptor in memfd_descriptors:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                memfd_closed = False
        else:
            memfd_closed = False
            original_close(descriptor)
    if (
        memfd_caught is not memfd_cancellation
        or len(memfd_descriptors) != 1
        or not memfd_closed
    ):
        raise SystemExit("pinned launcher memfd handoff custody drifted") from memfd_caught


def commit_tree(
    repo: pathlib.Path, tree: str, parents: tuple[str, ...], message: str
) -> str:
    arguments = [
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
    return git(repo, *arguments)


def expect_launcher_rejected(
    launcher: pathlib.Path,
    repo: pathlib.Path,
    label: str,
    expected: str,
) -> None:
    result = run_launcher(launcher, repo)
    if result.returncode == 0 or expected not in result.stderr or result.stdout:
        raise SystemExit(
            f"bootstrap accepted {label} or failed at wrong boundary: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def expect_corrupt_object_rejected(
    repo: pathlib.Path,
    launcher: pathlib.Path,
    oid: str,
    object_type: str,
    label: str,
) -> None:
    loose = repo / ".git/objects" / oid[:2] / oid[2:]
    compressed = loose.read_bytes()
    raw = bytearray(zlib.decompress(compressed))
    if not raw:
        raise SystemExit(f"bootstrap {label} corruption oracle is empty")
    raw[-1] ^= 1
    loose.chmod(0o600)
    loose.write_bytes(zlib.compress(bytes(raw)))
    try:
        expect_launcher_rejected(
            launcher,
            repo,
            label,
            f"pinned {object_type} bytes differ from their object id",
        )
    finally:
        loose.write_bytes(compressed)


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
        "bootstrap fixture atomic-mask assignment cancellation"
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
            "bootstrap fixture atomic-mask assignment custody drifted"
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
            prefix=f"tb321fu-bootstrap-signal-{boundary}."
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
                original_communicate = process.communicate
                original_wait = process.wait

                def communicate_with_signal(input=None, timeout=None):
                    if boundary == "wait":
                        fire(boundary_signal)
                    return original_communicate(input=input, timeout=timeout)

                def wait_with_signal(timeout=None):
                    if boundary == "reap" and popen_returned:
                        fire(boundary_signal)
                    return original_wait(timeout=timeout)

                process.communicate = communicate_with_signal
                process.wait = wait_with_signal
                ready_deadline = time.monotonic() + 2.0
                while (
                    not child_identity.is_file()
                    and time.monotonic() < ready_deadline
                ):
                    time.sleep(0.01)
                if not child_identity.is_file():
                    raise RuntimeError(
                        f"bootstrap fixture {boundary} child did not publish identity"
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
                    fixture_run_process(
                        [
                            "/usr/bin/python3",
                            "-c",
                            process_source,
                            str(root_identity),
                            str(child_identity),
                            "signal-parent" if boundary == "pidfd" else "wait",
                            str(os.getpid()),
                        ],
                        cwd,
                        timeout=(0.05 if boundary == "timeout-pidfd" else 3.0),
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
                    read_process_identity(path, f"{boundary} signal-boundary")
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
                    f"bootstrap fixture {boundary} async-signal custody drifted: "
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
            fixture_run_process(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import time;time.sleep(30)",
                ],
                cwd,
                timeout=0.05,
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
        != "bootstrap fixture signal-custody cleanup failed after timeout"
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
            "bootstrap fixture timeout cleanup-error custody drifted"
        ) from timeout_caught


def main() -> None:
    test_fixture_owner_scope_ast()
    test_fixture_owner_finalizer_cancellation(pathlib.Path.cwd())
    test_fixture_owner_fairness_and_capacity()
    for path in (RENDERER, TEMPLATE):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    with tempfile.TemporaryDirectory(
        prefix="tb321fu-haptics-bootstrap-fixture."
    ) as raw:
        private = pathlib.Path(raw)
        repo = private / "repo"
        external = private / "external"
        repo.mkdir(mode=0o700)
        external.mkdir(mode=0o700)
        (repo / "home").mkdir(mode=0o700)
        test_fixture_cleanup_faults(repo)
        test_direct_spawn_handoffs(repo)
        test_fixture_async_signal_custody(repo)
        git(repo, "init", "-q")
        for relative in (GATE_PATH, WORKFLOW_PATH, BOUNDARY_PATH, ISOLATION_PATH):
            (repo / relative).parent.mkdir(parents=True, exist_ok=True)
        workflow_raw = b"name: synthetic trusted workflow\n"
        boundary_raw = b"#!/usr/bin/env python3\nprint('BOUNDARY=PASS')\n"
        isolation_raw = b"#!/usr/bin/env python3\nprint('ISOLATION=PASS')\n"
        gate_raw = (
            "#!/usr/bin/env python3\n"
            "import argparse\n"
            "import hashlib\n"
            "import pathlib\n"
            "import re\n"
            "parser = argparse.ArgumentParser(add_help=False)\n"
            "parser.add_argument('--verify-only', action='store_true')\n"
            "parser.add_argument('--repo-dir', required=True)\n"
            "parser.add_argument('--trusted-commit', required=True)\n"
            "parser.add_argument('--candidate-commit', required=True)\n"
            "arguments = parser.parse_args()\n"
            "if not arguments.verify_only or "
            "re.fullmatch(r'/proc/self/fd/[1-9][0-9]*', __file__) is None:\n"
            "    raise SystemExit('SYNTHETIC_GATE_WAS_NOT_FD_PINNED')\n"
            "gate_sha256 = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()\n"
            "print('schema\\ttb321fu.haptics-workflow-gate/v1')\n"
            "print(f'trusted-commit\\t{arguments.trusted_commit}')\n"
            "print(f'candidate-commit\\t{arguments.candidate_commit}')\n"
            "print(f'gate-sha256\\t{gate_sha256}')\n"
            f"print('workflow-sha256\\t{hashlib.sha256(workflow_raw).hexdigest()}')\n"
            "print('validator-sha256\\t"
            f"{BOUNDARY_PATH.as_posix()}\\t{hashlib.sha256(boundary_raw).hexdigest()}')\n"
            "print('validator-sha256\\t"
            f"{ISOLATION_PATH.as_posix()}\\t{hashlib.sha256(isolation_raw).hexdigest()}')\n"
            "print('validator-mode\\ttrusted-commit-blobs/v1')\n"
            "print('HAPTICS_WORKFLOW_GATE_VERIFY=PASS')\n"
        ).encode("utf-8")
        (repo / GATE_PATH).write_bytes(gate_raw)
        (repo / GATE_PATH).chmod(0o644)
        (repo / WORKFLOW_PATH).write_bytes(workflow_raw)
        (repo / WORKFLOW_PATH).chmod(0o644)
        (repo / BOUNDARY_PATH).write_bytes(boundary_raw)
        (repo / BOUNDARY_PATH).chmod(0o755)
        (repo / ISOLATION_PATH).write_bytes(isolation_raw)
        (repo / ISOLATION_PATH).chmod(0o644)
        (repo / "fixture-anchor").write_text("anchor\n", encoding="ascii")
        git(repo, "add", "-A")
        git(
            repo,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "trusted P",
        )
        trusted = git(repo, "rev-parse", "HEAD")
        trusted_tree = git(repo, "show", "-s", "--format=%T", trusted)
        git(
            repo,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "candidate C",
        )
        candidate = git(repo, "rev-parse", "HEAD")
        digests = (
            hashlib.sha256(gate_raw).hexdigest(),
            sha256(repo / WORKFLOW_PATH),
            sha256(repo / BOUNDARY_PATH),
            sha256(repo / ISOLATION_PATH),
        )
        test_renderer_custody(
            load_renderer_module(),
            private,
            trusted,
            candidate,
            digests,
        )
        launcher = render_launcher(
            repo, external, "trusted-bootstrap.py", trusted, candidate, digests
        )
        launcher_module = load_launcher_module(launcher)
        test_run_pinned_launcher_handoffs(launcher, repo)
        test_gate_transcript_exactness(launcher_module)
        test_owned_private_directory_entry_custody(launcher_module)
        test_launcher_production_primitives(launcher_module, private, gate_raw)
        test_launcher_process_containment(launcher_module, private)
        test_signal_custody_regressions(launcher_module, private)
        test_launcher_cli_signals(private, external)
        test_outer_signal_windows(launcher_module, launcher, repo, gate_raw)
        test_private_gate_open_handoffs(launcher_module, private, gate_raw)
        test_private_gate_fd_race(launcher_module, private, gate_raw)
        test_private_gate_main_settlement(
            launcher_module,
            launcher,
            repo,
            gate_raw,
        )
        test_launcher_profile_wiring(
            launcher_module,
            launcher,
            repo,
            private,
            gate_raw,
        )
        expected_accepted_output = fixture_bootstrap_transcript(
            launcher_module,
            fixture_gate_transcript(launcher_module),
        )
        accepted = run_launcher(launcher, repo)
        if (
            accepted.returncode
            or accepted.stdout != expected_accepted_output
            or accepted.stderr
        ):
            raise SystemExit(f"valid external bootstrap failed: {accepted.stderr}")

        (repo / GATE_PATH).write_text(
            "raise SystemExit('POISON_WORKTREE_GATE_EXECUTED')\n",
            encoding="utf-8",
        )
        poisoned = run_launcher(launcher, repo)
        if (
            poisoned.returncode
            or poisoned.stdout != expected_accepted_output
            or poisoned.stderr
            or "POISON_WORKTREE_GATE_EXECUTED" in poisoned.stdout + poisoned.stderr
        ):
            raise SystemExit("mutable worktree gate influenced external bootstrap")
        (repo / GATE_PATH).unlink()

        alternate_identity = run_pinned_launcher(
            launcher,
            repo,
            [
                "--verify-only",
                "--repo-dir",
                str(repo),
                "--trusted-commit",
                trusted,
            ],
        )
        if alternate_identity.returncode == 0 or alternate_identity.stdout:
            raise SystemExit("bootstrap accepted a caller-supplied trusted identity")
        missing = run_launcher(launcher, repo)
        if (
            missing.returncode
            or missing.stdout != expected_accepted_output
            or missing.stderr
        ):
            raise SystemExit("external bootstrap depended on a worktree gate")
        os.symlink("/nonexistent/poisoned-gate", repo / GATE_PATH)
        symlinked = run_launcher(launcher, repo)
        if (
            symlinked.returncode
            or symlinked.stdout != expected_accepted_output
            or symlinked.stderr
        ):
            raise SystemExit("symlinked worktree gate influenced external bootstrap")
        (repo / GATE_PATH).unlink()

        if run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(RENDERER),
                "--output",
                str(launcher),
                "--trusted-commit",
                trusted,
                "--candidate-commit",
                candidate,
                "--gate-sha256",
                digests[0],
                "--workflow-sha256",
                digests[1],
                "--boundary-validator-sha256",
                digests[2],
                "--isolation-validator-sha256",
                digests[3],
            ],
            repo,
        ).returncode == 0:
            raise SystemExit("bootstrap renderer overwrote an existing launcher")

        (repo / GATE_PATH).write_text("changed candidate gate\n", encoding="utf-8")
        git(repo, "add", "-A")
        changed_tree = git(repo, "write-tree")
        changed_candidate = commit_tree(
            repo, changed_tree, (trusted,), "changed direct candidate"
        )
        changed_launcher = render_launcher(
            repo,
            external,
            "changed-bootstrap.py",
            trusted,
            changed_candidate,
            digests,
        )
        expect_launcher_rejected(
            changed_launcher, repo, "changed candidate tree", "candidate tree differs"
        )
        git(repo, "read-tree", trusted)
        extra_oid = hash_object(repo, "blob", b"candidate extra file\n")
        git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{extra_oid},candidate-extra-file",
        )
        extra_tree = git(repo, "write-tree")
        extra_candidate = commit_tree(
            repo,
            extra_tree,
            (trusted,),
            "extra-file candidate",
        )
        extra_launcher = render_launcher(
            repo,
            external,
            "extra-file-bootstrap.py",
            trusted,
            extra_candidate,
            digests,
        )
        expect_launcher_rejected(
            extra_launcher,
            repo,
            "extra-file candidate tree",
            "candidate tree differs",
        )
        git(repo, "read-tree", trusted)
        merge_candidate = commit_tree(
            repo, trusted_tree, (trusted, candidate), "merge candidate"
        )
        merge_launcher = render_launcher(
            repo, external, "merge-bootstrap.py", trusted, merge_candidate, digests
        )
        expect_launcher_rejected(
            merge_launcher, repo, "merge candidate", "direct single-parent child"
        )
        indirect_candidate = commit_tree(
            repo, trusted_tree, (candidate,), "indirect candidate"
        )
        indirect_launcher = render_launcher(
            repo,
            external,
            "indirect-bootstrap.py",
            trusted,
            indirect_candidate,
            digests,
        )
        expect_launcher_rejected(
            indirect_launcher, repo, "indirect candidate", "direct single-parent child"
        )

        loose_tree = repo / ".git/objects" / trusted_tree[:2] / trusted_tree[2:]
        compressed_tree = loose_tree.read_bytes()
        tree_object = zlib.decompress(compressed_tree)
        corrupted_tree = tree_object.replace(
            b"fixture-anchor\0", b"fixture-anchos\0", 1
        )
        if corrupted_tree == tree_object or len(corrupted_tree) != len(tree_object):
            raise SystemExit("bootstrap corrupt-tree oracle is malformed")
        loose_tree.chmod(0o600)
        loose_tree.write_bytes(zlib.compress(corrupted_tree))
        try:
            expect_launcher_rejected(
                launcher, repo, "corrupt tree", "tree bytes differ from their object id"
            )
        finally:
            loose_tree.write_bytes(compressed_tree)

        gate_oid = git(repo, "rev-parse", f"{trusted}:{GATE_PATH}")
        loose_blob = repo / ".git/objects" / gate_oid[:2] / gate_oid[2:]
        compressed_blob = loose_blob.read_bytes()
        blob_object = zlib.decompress(compressed_blob)
        corrupted_blob = blob_object.replace(b"SYNTHETIC", b"SYNTHETJD", 1)
        if corrupted_blob == blob_object or len(corrupted_blob) != len(blob_object):
            raise SystemExit("bootstrap corrupt-blob oracle is malformed")
        loose_blob.chmod(0o600)
        loose_blob.write_bytes(zlib.compress(corrupted_blob))
        try:
            expect_launcher_rejected(
                launcher, repo, "corrupt gate blob", "blob bytes differ from their object id"
            )
        finally:
            loose_blob.write_bytes(compressed_blob)

        for oid, object_type, label in (
            (trusted, "commit", "corrupt trusted commit"),
            (candidate, "commit", "corrupt candidate commit"),
            *(
                (
                    git(repo, "rev-parse", f"{trusted}:{relative}"),
                    "tree",
                    f"corrupt intermediate tree {relative}",
                )
                for relative in (".github", ".github/workflows", "scripts", "scripts/ci")
            ),
            *(
                (
                    git(repo, "rev-parse", f"{trusted}:{relative.as_posix()}"),
                    "blob",
                    f"corrupt final blob {relative.as_posix()}",
                )
                for relative in (WORKFLOW_PATH, BOUNDARY_PATH, ISOLATION_PATH)
            ),
        ):
            expect_corrupt_object_rejected(
                repo,
                launcher,
                oid,
                object_type,
                label,
            )

        wrong_digest_launcher = render_launcher(
            repo,
            external,
            "wrong-digest-bootstrap.py",
            trusted,
            candidate,
            ("0" * 64, *digests[1:]),
        )
        expect_launcher_rejected(
            wrong_digest_launcher,
            repo,
            "wrong embedded digest",
            f"pinned path SHA-256 differs: {GATE_PATH.as_posix()}",
        )

        for index, (relative, expected_mode) in enumerate(
            (
                (GATE_PATH, 0o644),
                (WORKFLOW_PATH, 0o644),
                (BOUNDARY_PATH, 0o755),
                (ISOLATION_PATH, 0o644),
            )
        ):
            git(repo, "read-tree", trusted)
            git(
                repo,
                "update-index",
                "--chmod=-x" if expected_mode == 0o755 else "--chmod=+x",
                relative.as_posix(),
            )
            wrong_mode_tree = git(repo, "write-tree")
            wrong_mode_trusted = commit_tree(
                repo,
                wrong_mode_tree,
                (),
                f"wrong mode P {index}",
            )
            wrong_mode_candidate = commit_tree(
                repo,
                wrong_mode_tree,
                (wrong_mode_trusted,),
                f"wrong mode C {index}",
            )
            wrong_mode_launcher = render_launcher(
                repo,
                external,
                f"wrong-mode-{index}.py",
                wrong_mode_trusted,
                wrong_mode_candidate,
                digests,
            )
            expect_launcher_rejected(
                wrong_mode_launcher,
                repo,
                f"wrong mode {relative.as_posix()}",
                f"pinned path mode differs from policy: {relative.as_posix()}",
            )

            git(repo, "read-tree", trusted)
            git(repo, "update-index", "--force-remove", relative.as_posix())
            missing_tree = git(repo, "write-tree")
            missing_trusted = commit_tree(
                repo,
                missing_tree,
                (),
                f"missing path P {index}",
            )
            missing_candidate = commit_tree(
                repo,
                missing_tree,
                (missing_trusted,),
                f"missing path C {index}",
            )
            missing_launcher = render_launcher(
                repo,
                external,
                f"missing-path-{index}.py",
                missing_trusted,
                missing_candidate,
                digests,
            )
            expect_launcher_rejected(
                missing_launcher,
                repo,
                f"missing path {relative.as_posix()}",
                f"pinned path is absent: {relative.as_posix()}",
            )
        git(repo, "read-tree", trusted)

        sha256_repo = private / "sha256-repo"
        sha256_repo.mkdir(mode=0o700)
        (sha256_repo / "home").mkdir(mode=0o700)
        init_sha256 = run(
            ["/usr/bin/git", "init", "-q", "--object-format=sha256", str(sha256_repo)],
            private,
        )
        if init_sha256.returncode:
            raise SystemExit("bootstrap fixture cannot create a SHA-256 repository")
        non_sha1 = run_launcher(launcher, sha256_repo)
        if (
            non_sha1.returncode == 0
            or "repository object format must be exactly sha1" not in non_sha1.stderr
            or non_sha1.stdout
        ):
            raise SystemExit("bootstrap accepted a non-SHA-1 repository")

        trusted_tree_loose = (
            repo / ".git/objects" / trusted_tree[:2] / trusted_tree[2:]
        )
        trusted_tree_object = zlib.decompress(trusted_tree_loose.read_bytes())
        _, separator, trusted_tree_raw = trusted_tree_object.partition(b"\0")
        first_space = trusted_tree_raw.find(b" ")
        first_nul = trusted_tree_raw.find(b"\0", first_space + 1)
        first_end = first_nul + 21
        if (
            not separator
            or first_space <= 0
            or first_nul <= first_space
            or first_end > len(trusted_tree_raw)
        ):
            raise SystemExit("bootstrap duplicate-tree oracle cannot parse root tree")
        duplicate_tree = hash_object(
            repo,
            "tree",
            trusted_tree_raw + trusted_tree_raw[:first_end],
        )
        identity = "Fixture <fixture@example.invalid> 0 +0000"
        duplicate_trusted = hash_object(
            repo,
            "commit",
            (
                f"tree {duplicate_tree}\n"
                f"author {identity}\n"
                f"committer {identity}\n\n"
                "duplicate tree P\n"
            ).encode("ascii"),
        )
        duplicate_candidate = hash_object(
            repo,
            "commit",
            (
                f"tree {duplicate_tree}\n"
                f"parent {duplicate_trusted}\n"
                f"author {identity}\n"
                f"committer {identity}\n\n"
                "duplicate tree C\n"
            ).encode("ascii"),
        )
        duplicate_launcher = render_launcher(
            repo,
            external,
            "duplicate-tree-bootstrap.py",
            duplicate_trusted,
            duplicate_candidate,
            digests,
        )
        expect_launcher_rejected(
            duplicate_launcher,
            repo,
            "duplicate tree entry",
            "pinned tree entry is not canonical",
        )

        test_real_dispatcher_through_launcher(private, external)

        if any(
            path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
            for path in private.rglob("*")
        ):
            raise SystemExit("bootstrap fixture created Python cache residue")
    print("HAPTICS_WORKFLOW_BOOTSTRAP_FIXTURE=PASS")


if __name__ == "__main__":
    main()
