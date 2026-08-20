#!/usr/bin/env python3
"""Reject GitHub input expressions embedded directly in workflow shell blocks."""

from __future__ import annotations

import os
import pathlib
import re
import stat
import subprocess
import sys
from collections import Counter

import yaml


MAX_CANONICAL_INTEGER_DIGITS = 64
MAX_YAML_COMPOSE_DEPTH = 64
MAX_YAML_COMPOSE_NODES = 16384
MAX_YAML_SCALAR_NODES = 12288
MAX_YAML_COLLECTION_NODES = 8192
MAX_WORKFLOW_SOURCE_BYTES = 1024 * 1024
MAX_DIAGNOSTIC_EXAMPLES = 8
MAX_CLI_DIAGNOSTIC_BYTES = 4096


class BoundedMatches:
    __slots__ = ("total", "examples")

    def __init__(self) -> None:
        self.total = 0
        self.examples: list[str] = []

    def add(self, example: str) -> None:
        self.total += 1
        if len(self.examples) < MAX_DIAGNOSTIC_EXAMPLES:
            self.examples.append(example)

    def __bool__(self) -> bool:
        return self.total != 0

    def render(self) -> str:
        return f"count={self.total} examples={self.examples!r}"


class BoundaryLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._compose_depth = 0
        self._compose_nodes = 0
        self._scalar_nodes = 0
        self._collection_nodes = 0

    def compose_node(self, parent, index):
        previous_depth = self._compose_depth
        event = self.peek_event()
        if previous_depth >= MAX_YAML_COMPOSE_DEPTH:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                (
                    "YAML compose depth exceeds the reviewed limit of "
                    f"{MAX_YAML_COMPOSE_DEPTH}"
                ),
                event.start_mark,
            )
        self._compose_depth = previous_depth + 1
        try:
            if isinstance(event, yaml.events.AliasEvent):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML aliases are not allowed",
                    event.start_mark,
                )
            scalar = isinstance(event, yaml.events.ScalarEvent)
            collection = isinstance(
                event,
                (yaml.events.SequenceStartEvent, yaml.events.MappingStartEvent),
            )
            next_nodes = self._compose_nodes + 1
            next_scalars = self._scalar_nodes + int(scalar)
            next_collections = self._collection_nodes + int(collection)
            if (
                next_nodes > MAX_YAML_COMPOSE_NODES
                or next_scalars > MAX_YAML_SCALAR_NODES
                or next_collections > MAX_YAML_COLLECTION_NODES
            ):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML node inventory exceeds the reviewed limit",
                    event.start_mark,
                )
            self._compose_nodes = next_nodes
            self._scalar_nodes = next_scalars
            self._collection_nodes = next_collections
            return super().compose_node(parent, index)
        finally:
            self._compose_depth = previous_depth


CANONICAL_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
CANONICAL_BOOLEAN = re.compile(
    r"(?:true|false)\Z",
    re.IGNORECASE | re.ASCII,
)
BoundaryLoader.yaml_implicit_resolvers = {
    first: list(resolvers)
    for first, resolvers in BoundaryLoader.yaml_implicit_resolvers.items()
}
for first, resolvers in list(BoundaryLoader.yaml_implicit_resolvers.items()):
    BoundaryLoader.yaml_implicit_resolvers[first] = [
        item
        for item in resolvers
        if item[0] not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:int"}
    ]
BoundaryLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    CANONICAL_BOOLEAN,
    list("tTfF"),
)
BoundaryLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    CANONICAL_INTEGER,
    list("-0123456789"),
)


def construct_canonical_boolean(
    loader: BoundaryLoader,
    node: yaml.nodes.ScalarNode,
) -> bool:
    value = loader.construct_scalar(node)
    if CANONICAL_BOOLEAN.fullmatch(value) is None:
        raise yaml.constructor.ConstructorError(
            "while constructing a boolean",
            node.start_mark,
            "boolean scalars must use true or false",
            node.start_mark,
        )
    return value.lower() == "true"


def construct_canonical_integer(
    loader: BoundaryLoader,
    node: yaml.nodes.ScalarNode,
) -> int:
    value = loader.construct_scalar(node)
    if CANONICAL_INTEGER.fullmatch(value) is None:
        raise yaml.constructor.ConstructorError(
            "while constructing an integer",
            node.start_mark,
            "integer scalars must use canonical decimal syntax",
            node.start_mark,
        )
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_CANONICAL_INTEGER_DIGITS:
        raise yaml.constructor.ConstructorError(
            "while constructing an integer",
            node.start_mark,
            (
                "integer scalars must contain at most "
                f"{MAX_CANONICAL_INTEGER_DIGITS} decimal digits"
            ),
            node.start_mark,
        )
    return int(value, 10)


def construct_unique_mapping(
    loader: BoundaryLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict:
    if not isinstance(node, yaml.nodes.MappingNode):
        raise yaml.constructor.ConstructorError(
            None, None, "expected a mapping node", node.start_mark
        )
    mapping_value: dict = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "YAML merge keys are not allowed",
                key_node.start_mark,
            )
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping_value
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping key is not hashable",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "duplicate mapping key",
                key_node.start_mark,
            )
        mapping_value[key] = loader.construct_object(value_node, deep=deep)
    return mapping_value


BoundaryLoader.add_constructor(
    "tag:yaml.org,2002:bool",
    construct_canonical_boolean,
)
BoundaryLoader.add_constructor(
    "tag:yaml.org,2002:int",
    construct_canonical_integer,
)
BoundaryLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)

BRACKET_KEY = re.compile(r"\[\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1\s*\]")
MAX_EXPRESSION_SCALAR_CHARS = 16384
MAX_EXPRESSION_BODY_CHARS = 4096
MAX_EXPRESSIONS_PER_SCALAR = 64
EXPECTED_EXPRESSIONS = Counter({
    "github.repository": 1,
    "inputs.release_tag!=''&&inputs.release_tag||inputs.dispatch_id": 1,
    "inputs.dispatch_id": 2,
    "inputs.release_tag": 1,
    "inputs.prerelease&&'1'||'0'": 1,
    "inputs.haptics_deb_version": 2,
    "inputs.kernel_source_commit": 1,
    "inputs.kernel_build_archive": 1,
    "inputs.kernel_build_archive_sha256": 1,
    "inputs.kernel_bundle_metadata": 1,
    "inputs.kernel_bundle_metadata_sha256": 1,
    "inputs.kernel_sdk_manifest": 1,
    "inputs.kernel_toolchain_manifest": 1,
    "github.run_attempt": 2,
    "inputs.release_tag!=''": 2,
    "inputs.release_tag==''": 1,
    "github.run_id": 1,
})


def fail(message: str) -> None:
    prefix = "workflow input boundary check failed: "
    raw = (prefix + message).encode("utf-8", "replace")
    maximum = MAX_CLI_DIAGNOSTIC_BYTES - 1
    if len(raw) > maximum:
        suffix = b"...[truncated]"
        raw = raw[: maximum - len(suffix)]
        while True:
            try:
                bounded = raw.decode("utf-8")
                break
            except UnicodeDecodeError as exc:
                raw = raw[: exc.start]
        message_text = bounded + suffix.decode("ascii")
    else:
        message_text = raw.decode("utf-8")
    raise SystemExit(message_text)


def read_workflow_source(path: pathlib.Path) -> str:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("workflow source must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(MAX_WORKFLOW_SOURCE_BYTES + 1)
    except OSError:
        fail("cannot read workflow source")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_WORKFLOW_SOURCE_BYTES:
        fail("workflow source exceeds the reviewed size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("workflow source must be valid UTF-8")


def load_workflow_yaml(source: str) -> object:
    try:
        return yaml.load(source, Loader=BoundaryLoader)
    except Exception:
        fail("invalid workflow YAML")


def assert_cli_rejects_invalid_source(raw: bytes, label: str) -> None:
    fd = os.memfd_create("workflow-boundary-hostile", os.MFD_CLOEXEC)
    try:
        os.write(fd, raw)
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            result = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(pathlib.Path(__file__).resolve()),
                    f"/proc/self/fd/{fd}",
                ],
                check=False,
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                pass_fds=(fd,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            fail(f"self-test could not run hostile CLI case {label}")
    finally:
        os.close(fd)
    if (
        result.returncode == 0
        or result.stdout
        or b"Traceback" in result.stderr
        or not result.stderr.startswith(b"workflow input boundary check failed: ")
        or len(result.stderr) > 4096
    ):
        fail(f"self-test CLI did not bound hostile {label} diagnostics")


def expression_bodies(text: str) -> tuple[str, ...]:
    if len(text) > MAX_EXPRESSION_SCALAR_CHARS:
        fail("workflow expression scalar exceeds the reviewed size limit")
    bodies: list[str] = []
    offset = 0
    while True:
        opening = text.find("${{", offset)
        if opening < 0:
            return tuple(bodies)
        body_start = opening + 3
        closing = text.find("}}", body_start)
        if closing < 0:
            return tuple(bodies)
        body = text[body_start:closing]
        if len(body) > MAX_EXPRESSION_BODY_CHARS:
            fail("workflow expression body exceeds the reviewed size limit")
        bodies.append(body)
        if len(bodies) > MAX_EXPRESSIONS_PER_SCALAR:
            fail("workflow expression count exceeds the reviewed limit")
        offset = closing + 2


def has_workflow_expression(text: str) -> bool:
    return bool(expression_bodies(text))


def normalized_expressions(text: str):
    for body in expression_bodies(text):
        expression = BRACKET_KEY.sub(lambda item: f".{item.group(2)}", body)
        yield re.sub(r"\s+", "", expression).lower()


def references_direct_input(text: str) -> bool:
    for expression in normalized_expressions(text):
        if re.search(r"(?<![a-z0-9_.])inputs(?![a-z0-9_])", expression):
            return True
        if re.search(r"(?<![a-z0-9_.])github\.event\.inputs(?![a-z0-9_])", expression):
            return True
    return False


def credential_references(value: object) -> BoundedMatches:
    unsafe = BoundedMatches()

    def visit(child: object, label: str) -> None:
        if isinstance(child, dict):
            for index, (key, item) in enumerate(child.items(), start=1):
                visit(key, f"{label}.keys[{index}]")
                visit(item, f"{label}.values[{index}]")
        elif isinstance(child, list):
            for index, item in enumerate(child, start=1):
                visit(item, f"{label}.items[{index}]")
        elif isinstance(child, str):
            for expression in normalized_expressions(child):
                if re.search(r"(?<![a-z0-9_.])secrets(?![a-z0-9_])", expression):
                    unsafe.add(f"{label}:secrets")
                if re.search(r"(?<![a-z0-9_.])github\.token(?![a-z0-9_])", expression):
                    unsafe.add(f"{label}:github.token")
                if re.search(r"(?<![a-z0-9_.])github(?![a-z0-9_.])", expression):
                    unsafe.add(f"{label}:github")

    visit(value, "build")
    return unsafe


def direct_input_lines(lines: list[str]) -> BoundedMatches:
    direct_inputs = BoundedMatches()

    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*(.*)$", line)
        if not match:
            index += 1
            continue

        scalar = match.group(2)
        if not scalar.startswith(("|", ">")):
            if references_direct_input(scalar):
                direct_inputs.add(f"lines[{index + 1}]")
            index += 1
            continue

        block_indent = len(match.group(1))
        index += 1
        while index < len(lines):
            body = lines[index]
            if body.strip() and len(body) - len(body.lstrip()) <= block_indent:
                break
            if references_direct_input(body):
                direct_inputs.add(f"lines[{index + 1}]")
            index += 1
    return direct_inputs


def direct_input_steps(data: object) -> BoundedMatches:
    if not isinstance(data, dict):
        fail("workflow root must be a mapping")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        fail("workflow jobs must be a mapping")
    unsafe = BoundedMatches()
    for job_index, job in enumerate(jobs.values(), start=1):
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if isinstance(run, str) and references_direct_input(run):
                unsafe.add(f"jobs[{job_index}].steps[{index}]")
    return unsafe


def workflow_expression_steps(data: object) -> BoundedMatches:
    unsafe = BoundedMatches()
    if not isinstance(data, dict):
        return unsafe
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return unsafe
    for job_index, job in enumerate(jobs.values(), start=1):
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        for step_index, step in enumerate(job["steps"], start=1):
            if (
                isinstance(step, dict)
                and isinstance(step.get("run"), str)
                and has_workflow_expression(step["run"])
            ):
                unsafe.add(f"jobs[{job_index}].steps[{step_index}]")
    return unsafe


def expression_inventory(value: object) -> Counter[str]:
    inventory: Counter[str] = Counter()

    def visit(child: object) -> None:
        if isinstance(child, dict):
            for key, item in child.items():
                visit(key)
                visit(item)
        elif isinstance(child, list):
            for item in child:
                visit(item)
        elif isinstance(child, str):
            inventory.update(normalized_expressions(child))

    visit(value)
    return inventory


def named_step(data: dict, name: str) -> dict:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not isinstance(jobs.get("build"), dict):
        fail("workflow must contain one build job")
    steps = jobs["build"].get("steps")
    if not isinstance(steps, list):
        fail("build job must contain steps")
    matches = [step for step in steps if isinstance(step, dict) and step.get("name") == name]
    if len(matches) != 1:
        fail(f"workflow must contain exactly one {name!r} step")
    return matches[0]


def executable_text(run: object, label: str) -> str:
    if not isinstance(run, str):
        fail(f"{label} must contain a run scalar")
    lines = [line for line in run.splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(lines)


def self_test() -> None:
    def require_matches(
        actual: BoundedMatches,
        total: int,
        examples: tuple[str, ...],
        label: str,
    ) -> None:
        if actual.total != total or tuple(actual.examples) != examples:
            fail(
                f"self-test match summary drifted for {label}: "
                f"total={actual.total} examples={actual.examples!r}"
            )

    if (MAX_DIAGNOSTIC_EXAMPLES, MAX_CLI_DIAGNOSTIC_BYTES) != (8, 4096):
        fail("self-test diagnostic limits changed")
    try:
        fail("é" * 5000)
    except SystemExit as exc:
        rendered = (str(exc) + "\n").encode("utf-8")
        if len(rendered) > 4096 or not str(exc).endswith("...[truncated]"):
            fail("self-test CLI failure did not enforce its UTF-8 byte limit")
    else:
        fail("self-test CLI failure boundary returned")
    for label, duplicate_source in (
        (
            "run",
            "steps:\n  - run: echo unreviewed\n    run: echo reviewed\n",
        ),
        (
            "if",
            "steps:\n  - if: false\n    if: true\n    run: true\n",
        ),
        (
            "input metadata",
            "inputs:\n  value:\n    required: false\n    required: true\n",
        ),
    ):
        try:
            yaml.load(duplicate_source, Loader=BoundaryLoader)
        except yaml.YAMLError:
            continue
        fail(f"self-test loader accepted duplicate {label} key")
    expression_cases = (
        ("plain text", ()),
        ("${{ inputs.value }}", (" inputs.value ",)),
        ("${{ one\ntwo }}", (" one\ntwo ",)),
        (
            "before ${{ one }} between ${{ two }} after",
            (" one ", " two "),
        ),
        ("${{ outer ${{ inner }}", (" outer ${{ inner ",)),
        ("${{}}", ("",)),
        ("${{ unterminated ${{ nested", ()),
    )
    for expression_source, expected_bodies in expression_cases:
        if tuple(expression_bodies(expression_source)) != expected_bodies:
            fail(f"self-test expression scanner changed semantics for {expression_source!r}")
        if has_workflow_expression(expression_source) != bool(expected_bodies):
            fail(f"self-test expression predicate changed semantics for {expression_source!r}")

    class MeteredExpressionText(str):
        def __new__(cls, value: str):
            instance = super().__new__(cls, value)
            instance.find_calls = 0
            instance.examined = 0
            return instance

        def find(self, substring: str, start: int = 0, end: int | None = None) -> int:
            self.find_calls += 1
            stop = len(self) if end is None else end
            result = super().find(substring, start, stop)
            self.examined += (
                stop - start if result < 0 else result - start + len(substring)
            )
            return result

    hostile_expressions = MeteredExpressionText("${{" * 4096)
    if tuple(expression_bodies(hostile_expressions)):
        fail("self-test expression scanner accepted an unterminated expression")
    if hostile_expressions.find_calls != 2 or hostile_expressions.examined != len(hostile_expressions):
        fail("self-test expression scanner did not use its exact linear search budget")
    if (
        MAX_EXPRESSION_SCALAR_CHARS,
        MAX_EXPRESSION_BODY_CHARS,
        MAX_EXPRESSIONS_PER_SCALAR,
    ) != (16384, 4096, 64):
        fail("self-test expression scanner limits changed")
    exact_body = "x" * MAX_EXPRESSION_BODY_CHARS
    for label, exact_expression, expected_bodies in (
        ("scalar", "x" * MAX_EXPRESSION_SCALAR_CHARS, ()),
        ("body", "${{" + exact_body + "}}", (exact_body,)),
        ("count", "${{x}}" * MAX_EXPRESSIONS_PER_SCALAR, ("x",) * 64),
    ):
        if expression_bodies(exact_expression) != expected_bodies:
            fail(f"self-test expression scanner rejected its exact {label} limit")
        if has_workflow_expression(exact_expression) != bool(expected_bodies):
            fail(f"self-test expression predicate rejected its exact {label} limit")
    for label, hostile_expression in (
        ("scalar", "x" * (MAX_EXPRESSION_SCALAR_CHARS + 1)),
        ("body", "${{" + "x" * (MAX_EXPRESSION_BODY_CHARS + 1) + "}}"),
        ("count", "${{x}}" * (MAX_EXPRESSIONS_PER_SCALAR + 1)),
    ):
        try:
            tuple(expression_bodies(hostile_expression))
        except SystemExit:
            continue
        fail(f"self-test expression scanner accepted an oversized {label}")
    for integer_source in ("0132", "1:30"):
        parsed_integer = yaml.load(
            f"value: {integer_source}\n", Loader=BoundaryLoader
        )
        if not isinstance(parsed_integer, dict) or type(parsed_integer.get("value")) is not str:
            fail(f"self-test loader applied YAML 1.1 integer semantics to {integer_source}")
    for integer_source in (
        "!!int 0132",
        "!!int 1:30",
        "!!int +90",
        "!!int 0x5a",
        "!!int 9_0",
        "!!int 0b1011010",
        "!!int 0o132",
        "!!int -0",
        "!!int true",
    ):
        try:
            yaml.load(f"value: {integer_source}\n", Loader=BoundaryLoader)
        except yaml.YAMLError:
            continue
        fail(f"self-test loader accepted noncanonical explicit integer {integer_source}")
    for integer_source, expected_integer in (
        ("0", 0),
        ("90", 90),
        ("-90", -90),
        ("!!int 0", 0),
        ("!!int 90", 90),
        ("!!int -90", -90),
    ):
        parsed_integer = yaml.load(
            f"value: {integer_source}\n", Loader=BoundaryLoader
        )
        actual_integer = parsed_integer.get("value") if isinstance(parsed_integer, dict) else None
        if type(actual_integer) is not int or actual_integer != expected_integer:
            fail(f"self-test loader changed canonical integer {integer_source}")
    for boolean_source in ("on", "On", "ON", "off", "yes", "no", "fal\u017fe"):
        parsed_boolean = yaml.load(
            f"value: {boolean_source}\n", Loader=BoundaryLoader
        )
        if type(parsed_boolean.get("value")) is not str:
            fail(f"self-test loader applied YAML 1.1 boolean semantics to {boolean_source}")
    for boolean_source in (
        "!!bool on",
        "!!bool off",
        "!!bool yes",
        "!!bool no",
        "!!bool invalid",
        "!!bool fal\u017fe",
    ):
        try:
            yaml.load(f"value: {boolean_source}\n", Loader=BoundaryLoader)
        except yaml.constructor.ConstructorError:
            continue
        fail(f"self-test loader accepted noncanonical explicit boolean {boolean_source}")
    for boolean_source, expected_boolean in (
        ("true", True),
        ("TRUE", True),
        ("False", False),
        ("!!bool true", True),
        ("!!bool FALSE", False),
    ):
        parsed_boolean = yaml.load(
            f"value: {boolean_source}\n", Loader=BoundaryLoader
        )
        actual_boolean = parsed_boolean.get("value")
        if type(actual_boolean) is not bool or actual_boolean is not expected_boolean:
            fail(f"self-test loader changed canonical boolean {boolean_source}")
    if (
        MAX_CANONICAL_INTEGER_DIGITS,
        MAX_YAML_COMPOSE_DEPTH,
        MAX_YAML_COMPOSE_NODES,
        MAX_YAML_SCALAR_NODES,
        MAX_YAML_COLLECTION_NODES,
    ) != (64, 64, 16384, 12288, 8192):
        fail("self-test loader limits changed")
    exact_integer = "9" * MAX_CANONICAL_INTEGER_DIGITS
    for label, integer_source in (
        ("implicit positive", exact_integer),
        ("implicit negative", f"-{exact_integer}"),
        ("explicit positive", f"!!int {exact_integer}"),
        ("explicit negative", f"!!int -{exact_integer}"),
    ):
        parsed_integer = yaml.load(
            f"value: {integer_source}\n", Loader=BoundaryLoader
        )
        actual_integer = parsed_integer.get("value") if isinstance(parsed_integer, dict) else None
        if type(actual_integer) is not int or str(abs(actual_integer)) != exact_integer:
            fail(f"self-test loader rejected exact-limit {label} integer")
    oversized_integer = "9" * (MAX_CANONICAL_INTEGER_DIGITS + 1)
    for label, integer_source in (
        ("implicit positive", oversized_integer),
        ("implicit negative", f"-{oversized_integer}"),
        ("explicit positive", f"!!int {oversized_integer}"),
        ("explicit negative", f"!!int -{oversized_integer}"),
    ):
        try:
            yaml.load(f"value: {integer_source}\n", Loader=BoundaryLoader)
        except yaml.constructor.ConstructorError:
            continue
        fail(f"self-test loader accepted over-limit {label} integer")
    for label, alias_source in (
        ("ordinary alias", "value: &value safe\nalias: *value\n"),
        ("recursive alias", "value: &value [*value]\n"),
    ):
        try:
            yaml.load(alias_source, Loader=BoundaryLoader)
        except yaml.YAMLError:
            continue
        fail(f"self-test loader accepted {label}")
    exact_scalar_depth = (
        "[" * (MAX_YAML_COMPOSE_DEPTH - 1)
        + "0"
        + "]" * (MAX_YAML_COMPOSE_DEPTH - 1)
    )
    exact_self_closing_depth = (
        "[" * MAX_YAML_COMPOSE_DEPTH + "]" * MAX_YAML_COMPOSE_DEPTH
    )
    for label, depth_source in (
        ("scalar-terminal", exact_scalar_depth),
        ("self-closing", exact_self_closing_depth),
    ):
        yaml.load(depth_source, Loader=BoundaryLoader)
    for label, depth_source in (
        ("scalar-terminal", f"[{exact_scalar_depth}]"),
        ("self-closing", f"[{exact_self_closing_depth}]"),
    ):
        loader = BoundaryLoader(depth_source)
        try:
            try:
                loader.get_single_data()
            except yaml.constructor.ConstructorError:
                pass
            else:
                fail(f"self-test loader accepted over-limit {label} compose depth")
            if loader._compose_depth != 0:
                fail("self-test loader leaked compose depth after rejection")
        finally:
            loader.dispose()
    reset_loader = BoundaryLoader("[0]")
    try:
        if reset_loader.get_single_data() != [0] or reset_loader._compose_depth != 0:
            fail("self-test loader did not reset compose depth after success")
    finally:
        reset_loader.dispose()
    scalar_exact = "[" + ",".join(
        "0" for _ in range(MAX_YAML_SCALAR_NODES)
    ) + "]"
    collection_exact = "[" + ",".join(
        "[]" for _ in range(MAX_YAML_COLLECTION_NODES - 1)
    ) + "]"
    total_exact = "[" + ",".join(
        ["[]"] * (MAX_YAML_COLLECTION_NODES - 1)
        + ["0"] * (MAX_YAML_COMPOSE_NODES - MAX_YAML_COLLECTION_NODES)
    ) + "]"
    for label, source_text, expected_counts in (
        (
            "scalar",
            scalar_exact,
            (MAX_YAML_SCALAR_NODES + 1, MAX_YAML_SCALAR_NODES, 1),
        ),
        (
            "collection",
            collection_exact,
            (MAX_YAML_COLLECTION_NODES, 0, MAX_YAML_COLLECTION_NODES),
        ),
        (
            "total",
            total_exact,
            (
                MAX_YAML_COMPOSE_NODES,
                MAX_YAML_COMPOSE_NODES - MAX_YAML_COLLECTION_NODES,
                MAX_YAML_COLLECTION_NODES,
            ),
        ),
    ):
        loader = BoundaryLoader(source_text)
        try:
            loader.get_single_data()
            actual_counts = (
                loader._compose_nodes,
                loader._scalar_nodes,
                loader._collection_nodes,
            )
            if actual_counts != expected_counts:
                fail(f"self-test loader changed exact {label} node inventory")
        finally:
            loader.dispose()
    over_limit_sources = (
        (
            "scalar",
            "[" + ",".join(
                "0" for _ in range(MAX_YAML_SCALAR_NODES + 1)
            ) + "]",
        ),
        (
            "collection",
            "[" + ",".join(
                "[]" for _ in range(MAX_YAML_COLLECTION_NODES)
            ) + "]",
        ),
        (
            "total",
            "[" + ",".join(
                ["[]"] * (MAX_YAML_COLLECTION_NODES - 1)
                + ["0"]
                * (MAX_YAML_COMPOSE_NODES - MAX_YAML_COLLECTION_NODES + 1)
            ) + "]",
        ),
    )
    for label, source_text in over_limit_sources:
        try:
            yaml.load(source_text, Loader=BoundaryLoader)
        except yaml.constructor.ConstructorError as exc:
            if "YAML node inventory exceeds the reviewed limit" not in str(exc):
                raise
        else:
            fail(f"self-test loader accepted over-limit {label} node inventory")
    safe = [
        "jobs:",
        "  build:",
        "    env:",
        "      INPUT_VALUE: ${{ inputs.value }}",
        "    run: |",
        '      printf "%s\\n" "$INPUT_VALUE"',
    ]
    unsafe = ["jobs:", "  build:", "    run: |", "      echo '${{ inputs.value }}'"]
    unsafe_inline = ["jobs:", "  build:", '    run: echo "${{ inputs.value }}"']
    unsafe_bracket = ["jobs:", "  build:", "    run: echo ${{ inputs['value'] }}"]
    unsafe_event = ["jobs:", "  build:", "    run: echo ${{ github.event.inputs.value }}"]
    unsafe_event_bracket = [
        "jobs:",
        "  build:",
        "    run: echo ${{ github.event['inputs']['value'] }}",
    ]
    unsafe_github_bracket = [
        "jobs:",
        "  build:",
        "    run: echo ${{ github['event']['inputs']['value'] }}",
    ]
    unsafe_whole_inputs = [
        "jobs:",
        "  build:",
        "    run: echo ${{ toJSON(inputs) }}",
    ]
    if direct_input_lines(safe):
        fail("self-test rejected an env-mediated input")
    for label, source in (
        ("direct input", unsafe),
        ("inline direct input", unsafe_inline),
        ("bracket input notation", unsafe_bracket),
        ("github.event.inputs", unsafe_event),
        ("bracketed github.event inputs", unsafe_event_bracket),
        ("bracketed github context inputs", unsafe_github_bracket),
        ("whole inputs context", unsafe_whole_inputs),
    ):
        expected_line = 4 if label == "direct input" else 3
        require_matches(
            direct_input_lines(source),
            1,
            (f"lines[{expected_line}]",),
            label,
        )
    for label, value, expected in (
        (
            "bracketed github.token",
            {"env": "${{ github['token'] }}"},
            "build.values[1]:github.token",
        ),
        (
            "embedded secrets context",
            {"env": "${{ format('{0}', secrets['TOKEN']) }}"},
            "build.values[1]:secrets",
        ),
        (
            "whole secrets context",
            {"env": "${{ toJSON(secrets) }}"},
            "build.values[1]:secrets",
        ),
        (
            "whole github context",
            {"env": "${{ toJSON(github) }}"},
            "build.values[1]:github",
        ),
        (
            "github.token before a function suffix",
            {"env": "${{ format('{0}', github['token']) }}"},
            "build.values[1]:github.token",
        ),
    ):
        require_matches(credential_references(value), 1, (expected,), label)
    if "required-token" in executable_text("# required-token\ntrue", "fixture"):
        fail("self-test treated a comment as executable validation")
    parsed = yaml.load("\n".join((
        "jobs:",
        "  build:",
        "    steps:",
        "      - run: >-",
        "          echo '${{ inputs.value }}'",
    )), Loader=BoundaryLoader)
    require_matches(
        direct_input_steps(parsed),
        1,
        ("jobs[1].steps[1]",),
        "parsed folded run scalar",
    )

    hostile_count = 200
    hostile_job_name = "j" * 1000
    hostile_steps = [{"run": "${{ inputs.value }}"} for _ in range(hostile_count)]
    expected_examples = tuple(
        f"jobs[1].steps[{index}]"
        for index in range(1, MAX_DIAGNOSTIC_EXAMPLES + 1)
    )
    require_matches(
        direct_input_steps(
            {"jobs": {hostile_job_name: {"steps": hostile_steps}}}
        ),
        hostile_count,
        expected_examples,
        "long shared job name direct-input amplification",
    )
    require_matches(
        workflow_expression_steps(
            {"jobs": {hostile_job_name: {"steps": hostile_steps}}}
        ),
        hostile_count,
        expected_examples,
        "long shared job name expression amplification",
    )
    credential_map = {
        ("k" * 1000) + str(index): "${{ secrets.TOKEN }}"
        for index in range(hostile_count)
    }
    require_matches(
        credential_references(credential_map),
        hostile_count,
        tuple(
            f"build.values[{index}]:secrets"
            for index in range(1, MAX_DIAGNOSTIC_EXAMPLES + 1)
        ),
        "long mapping key credential amplification",
    )
    hostile_cli = ["jobs:", f"  {hostile_job_name}:", "    steps:"]
    hostile_cli.extend(
        "      - run: echo '${{ inputs.value }}'" for _ in range(hostile_count)
    )
    assert_cli_rejects_invalid_source(
        ("\n".join(hostile_cli) + "\n").encode("utf-8"),
        "many-step diagnostic amplification",
    )
    real_workflow = pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/build.yml"
    real_source = read_workflow_source(real_workflow)
    if real_source.count("\non:\n") != 1:
        fail("self-test real workflow trigger anchor changed")
    assert_cli_rejects_invalid_source(
        real_source.replace("\non:\n", "\n!!bool on:\n", 1).encode("utf-8"),
        "explicit boolean workflow trigger",
    )
    for label, hostile_source in (
        ("float constructor", b"value: !!float invalid\n"),
        ("timestamp constructor", b"value: !!timestamp invalid\n"),
        ("boolean constructor on", b"value: !!bool on\n"),
        ("boolean constructor yes", b"value: !!bool yes\n"),
        ("boolean constructor no", b"value: !!bool no\n"),
        ("boolean constructor invalid", b"value: !!bool invalid\n"),
        (
            "boolean constructor Unicode fold",
            "value: !!bool fal\u017fe\n".encode("utf-8"),
        ),
        ("UTF-8", b"name: \xff\n"),
    ):
        assert_cli_rejects_invalid_source(hostile_source, label)
    print("workflow input boundary self-test: PASS")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) != 2:
        fail("usage: check-workflow-input-boundaries.py WORKFLOW|--self-test")

    workflow = pathlib.Path(sys.argv[1])
    source = read_workflow_source(workflow)
    lines = source.splitlines()
    direct_inputs = direct_input_lines(lines)

    if direct_inputs:
        fail(f"direct input expression in run block: {direct_inputs.render()}")
    data = load_workflow_yaml(source)
    direct_steps = direct_input_steps(data)
    if direct_steps:
        fail(f"direct input expression in run steps: {direct_steps.render()}")
    expression_steps = workflow_expression_steps(data)
    if expression_steps:
        fail(
            "workflow expressions are forbidden in run steps: "
            + expression_steps.render()
        )
    actual_expressions = expression_inventory(data)
    if actual_expressions != EXPECTED_EXPRESSIONS:
        missing_expressions = EXPECTED_EXPRESSIONS - actual_expressions
        unexpected_expressions = actual_expressions - EXPECTED_EXPRESSIONS
        fail(
            "workflow expression inventory differs from the reviewed contract: "
            f"expected_total={sum(EXPECTED_EXPRESSIONS.values())} "
            f"actual_total={sum(actual_expressions.values())} "
            f"missing_total={sum(missing_expressions.values())} "
            f"unexpected_total={sum(unexpected_expressions.values())} "
            f"expected_unique={len(EXPECTED_EXPRESSIONS)} "
            f"actual_unique={len(actual_expressions)}"
        )
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not isinstance(jobs.get("build"), dict):
        fail("workflow must contain one build job")
    unsafe_credentials = credential_references(jobs["build"])
    if unsafe_credentials:
        fail(
            "build job references a secret or GitHub token context: "
            + unsafe_credentials.render()
        )

    validation_step = named_step(data, "Validate build inputs")
    expected_env = {
        "INPUT_DISPATCH_ID": "${{ inputs.dispatch_id }}",
        "INPUT_RELEASE_TAG": "${{ inputs.release_tag }}",
        "INPUT_PRERELEASE": "${{ inputs.prerelease && '1' || '0' }}",
        "INPUT_HAPTICS_DEB_VERSION": "${{ inputs.haptics_deb_version }}",
        "INPUT_KERNEL_SOURCE_COMMIT": "${{ inputs.kernel_source_commit }}",
        "INPUT_KERNEL_BUILD_ARCHIVE": "${{ inputs.kernel_build_archive }}",
        "INPUT_KERNEL_BUILD_ARCHIVE_SHA256": "${{ inputs.kernel_build_archive_sha256 }}",
        "INPUT_KERNEL_BUNDLE_METADATA": "${{ inputs.kernel_bundle_metadata }}",
        "INPUT_KERNEL_BUNDLE_METADATA_SHA256": "${{ inputs.kernel_bundle_metadata_sha256 }}",
        "INPUT_KERNEL_SDK_MANIFEST": "${{ inputs.kernel_sdk_manifest }}",
        "INPUT_KERNEL_TOOLCHAIN_MANIFEST": "${{ inputs.kernel_toolchain_manifest }}",
    }
    if validation_step.get("env") != expected_env:
        fail("Validate build inputs must expose the exact env-mediated input map")
    validation_text = executable_text(validation_step.get("run"), "Validate build inputs")
    required_validation = (
        '[[ "$INPUT_DISPATCH_ID" =~ ^[0-9a-f]{32}$ ]]',
        'if [ -n "$INPUT_RELEASE_TAG" ] && [ "$INPUT_PRERELEASE" != 1 ]; then',
        '[[ "$INPUT_HAPTICS_DEB_VERSION" =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]]',
        'dpkg --validate-version "$INPUT_HAPTICS_DEB_VERSION"',
        '[[ "$INPUT_KERNEL_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$INPUT_KERNEL_BUILD_ARCHIVE" =~ ^https://[^[:space:]]{1,2048}$ ]]',
        '[[ "$INPUT_KERNEL_BUILD_ARCHIVE_SHA256" =~ ^[0-9A-Fa-f]{64}$ ]]',
        '[[ "$INPUT_KERNEL_BUNDLE_METADATA" =~ ^https://[^[:space:]]{1,2048}$ ]]',
        '[[ "$INPUT_KERNEL_BUNDLE_METADATA_SHA256" =~ ^[0-9A-Fa-f]{64}$ ]]',
        '[[ "$INPUT_KERNEL_SDK_MANIFEST" =~ ^https://[^[:space:]]{1,2048}$ ]]',
        '[[ "$INPUT_KERNEL_TOOLCHAIN_MANIFEST" =~ ^https://[^[:space:]]{1,2048}$ ]]',
        '[[ "$INPUT_HAPTICS_DEB_VERSION" =~ ^[0-9][0-9A-Za-z._-]{0,63}$ ]]',
        "printf 'HAPTICS_DEB_VERSION=%s\\n' \"$INPUT_HAPTICS_DEB_VERSION\"",
        "printf 'KERNEL_SOURCE_COMMIT=%s\\n' \"$INPUT_KERNEL_SOURCE_COMMIT\"",
        "printf 'KERNEL_BUILD_ARCHIVE=%s\\n' \"$INPUT_KERNEL_BUILD_ARCHIVE\"",
        "printf 'KERNEL_BUILD_ARCHIVE_SHA256=%s\\n' \"${INPUT_KERNEL_BUILD_ARCHIVE_SHA256,,}\"",
        "printf 'KERNEL_BUNDLE_METADATA=%s\\n' \"$INPUT_KERNEL_BUNDLE_METADATA\"",
        "printf 'KERNEL_BUNDLE_METADATA_SHA256=%s\\n' \"${INPUT_KERNEL_BUNDLE_METADATA_SHA256,,}\"",
        "printf 'KERNEL_SDK_MANIFEST=%s\\n' \"$INPUT_KERNEL_SDK_MANIFEST\"",
        "printf 'KERNEL_TOOLCHAIN_MANIFEST=%s\\n' \"$INPUT_KERNEL_TOOLCHAIN_MANIFEST\"",
        '[ "$INPUT_HAPTICS_DEB_VERSION" = "$reference_version" ]',
        '[ "$INPUT_RELEASE_TAG" = "tb321fu-haptics-debs-$INPUT_HAPTICS_DEB_VERSION" ]',
    )
    for token in required_validation:
        if token not in validation_text:
            fail(f"Validate build inputs is missing executable boundary token: {token}")

    build_step = named_step(data, "Build haptics deb")
    build_text = executable_text(build_step.get("run"), "Build haptics deb")
    required_handoff = (
        'KERNEL_SOURCE_COMMIT="$KERNEL_SOURCE_COMMIT"',
        'KERNEL_BUILD_ARCHIVE="$KERNEL_BUILD_ARCHIVE"',
        'KERNEL_BUILD_ARCHIVE_SHA256="$KERNEL_BUILD_ARCHIVE_SHA256"',
        'KERNEL_BUNDLE_METADATA="$KERNEL_BUNDLE_METADATA"',
        'KERNEL_BUNDLE_METADATA_SHA256="$KERNEL_BUNDLE_METADATA_SHA256"',
        'KERNEL_SDK_MANIFEST="$KERNEL_SDK_MANIFEST"',
        'KERNEL_TOOLCHAIN_MANIFEST="$KERNEL_TOOLCHAIN_MANIFEST"',
        "HAPTICS_RELEASE_MODE=1",
    )
    for token in required_handoff:
        if token not in build_text:
            fail(f"Build haptics deb is missing executable handoff token: {token}")

    print("workflow input boundary check: PASS")


if __name__ == "__main__":
    main()
