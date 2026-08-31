#!/usr/bin/env python3
"""Keep GitHub Actions read-only and release publication operator-local."""

from __future__ import annotations

import copy
import hashlib
import itertools
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


class WorkflowLoader(yaml.SafeLoader):
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
WorkflowLoader.yaml_implicit_resolvers = {
    first: list(resolvers)
    for first, resolvers in WorkflowLoader.yaml_implicit_resolvers.items()
}
for first, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
    WorkflowLoader.yaml_implicit_resolvers[first] = [
        item
        for item in resolvers
        if item[0] not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:int"}
    ]
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    CANONICAL_BOOLEAN,
    list("tTfF"),
)
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    CANONICAL_INTEGER,
    list("-0123456789"),
)


def construct_canonical_integer(
    loader: WorkflowLoader,
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
    loader: WorkflowLoader,
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


def construct_canonical_boolean(
    loader: WorkflowLoader, node: yaml.nodes.ScalarNode
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


WorkflowLoader.add_constructor(
    "tag:yaml.org,2002:bool", construct_canonical_boolean
)
WorkflowLoader.add_constructor(
    "tag:yaml.org,2002:int", construct_canonical_integer
)
WorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


CHECKOUT = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
ARTIFACT = "release-staging-" + "$" + "{{ github.run_id }}-" + "$" + "{{ github.run_attempt }}"
GENERAL_ARTIFACT = (
    "diagnostic-tb321fu-haptics-" + "$" + "{{ inputs.haptics_deb_version }}-arm64-"
    + "$" + "{{ github.run_attempt }}"
)
RELEASE_GUARD = "$" + "{{ inputs.release_tag != '' }}"
DIAGNOSTIC_GUARD = "$" + "{{ inputs.release_tag == '' }}"
GITHUB_TOKEN = "$" + "{{ github.token }}"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
BRACKET_KEY = re.compile(r"\[\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1\s*\]")
MAX_EXPRESSION_SCALAR_CHARS = 16384
MAX_EXPRESSION_BODY_CHARS = 4096
MAX_EXPRESSIONS_PER_SCALAR = 64
PACKAGE_MUTATION = re.compile(
    r"(?m)(?:\bsudo\b|"
    r"(?<![A-Za-z0-9_.-])(?:/usr/bin/)?(?:apt|apt-get|aptitude)"
    r"[^\n;&|]{0,256}\b(?:install|remove|purge|upgrade|dist-upgrade|full-upgrade)\b|"
    r"(?<![A-Za-z0-9_.-])(?:/usr/bin/)?dpkg[^\n;&|]{0,128}"
    r"(?:\s-i\b|\s--install\b|\s--remove\b|\s--purge\b)|"
    r"(?<![A-Za-z0-9_.-])(?:/usr/bin/)?(?:snap|apt-mark|update-alternatives)\b)"
)
ALLOWED_VALIDATION_PRIVILEGE = (
    "/usr/bin/sudo /bin/bash -p scripts/ci/test-haptics-live-build-tools.sh"
)
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
CANONICAL_RUNNER = "ubuntu-24.04"
WORKFLOW_NAME = "Build TB321FU Haptics Debs"
WORKFLOW_RUN_NAME = "haptics-dispatch-${{ inputs.dispatch_id }}"
WORKFLOW_INPUTS = (
    "dispatch_id",
    "release_tag",
    "prerelease",
    "haptics_deb_version",
    "kernel_source_commit",
    "kernel_build_archive",
    "kernel_build_archive_sha256",
    "kernel_bundle_metadata",
    "kernel_bundle_metadata_sha256",
    "kernel_sdk_manifest",
    "kernel_toolchain_manifest",
)
WORKFLOW_INPUT_DESCRIPTIONS = {
    "dispatch_id": "Unique 128-bit lowercase-hex trusted dispatch identity.",
    "release_tag": "Release tag to validate and stage. Empty disables release staging.",
    "prerelease": "Require the staged release contract to remain prerelease-only.",
    "haptics_deb_version": "Debian package version",
    "kernel_source_commit": (
        "Exact 40-hex GUF296/linux commit paired with the kernel SDK."
    ),
    "kernel_build_archive": "Kernel build SDK archive URL",
    "kernel_build_archive_sha256": (
        "SHA-256 of the exact kernel build SDK archive."
    ),
    "kernel_bundle_metadata": (
        "HTTPS KERNEL-BUNDLE.tsv v2 URL paired with the source and SDK archive."
    ),
    "kernel_bundle_metadata_sha256": (
        "SHA-256 of the paired KERNEL-BUNDLE.tsv v2."
    ),
    "kernel_sdk_manifest": (
        "HTTPS KERNEL-SDK-MANIFEST.tsv URL paired with the kernel SDK archive."
    ),
    "kernel_toolchain_manifest": (
        "HTTPS KERNEL-TOOLCHAIN.tsv v2 URL bound by KERNEL-BUNDLE.tsv."
    ),
}
CANONICAL_PROFILE_DEFAULTS = {
    "haptics_deb_version": "20260730.2",
    "kernel_source_commit": "570b90203d97f67321fa0fb2d0af73c31d7111af",
    "kernel_build_archive": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/"
        "tb321fu-kernel-build-sdk-7.1.1-00009-g570b90203d97.tar.gz"
    ),
    "kernel_build_archive_sha256": (
        "7f9b12bd02c1155c9900a33c823d088e1a9f72689dea28c8ee582a31304c7c49"
    ),
    "kernel_bundle_metadata": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/KERNEL-BUNDLE.tsv"
    ),
    "kernel_bundle_metadata_sha256": (
        "9b11d12fab79eb4f10acb7eddf9c5e11e3f4242f2877658627ff3b11dd231998"
    ),
    "kernel_sdk_manifest": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/KERNEL-SDK-MANIFEST.tsv"
    ),
    "kernel_toolchain_manifest": (
        "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
        "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/KERNEL-TOOLCHAIN.tsv"
    ),
}
REVIEWED_RUN_SHA256 = {
    "Validate workflow and lifecycle boundaries": (
        "6867c5654b84bac9f8c21eedacb254543b47b29a06b34bc6df78f70ca10f3762"
    ),
    "Validate build inputs": (
        "53620abb19b0354f1740f33345439bfa5f14d70aedd8f8587680bdfdff5b9fdc"
    ),
    "Build haptics deb": (
        "d83334c6946b136e652681cd4fb826c62ab0c888556fdd9c02680353616de7be"
    ),
}
BUILD_STEP_KEYS = {
    "Checkout": frozenset({"name", "uses", "with"}),
    "Install dependencies": frozenset({"name", "run"}),
    "Validate workflow and lifecycle boundaries": frozenset({"name", "env", "run"}),
    "Validate build inputs": frozenset({"name", "env", "run"}),
    "Build haptics deb": frozenset({"name", "run"}),
    "Upload diagnostic build output": frozenset({"name", "if", "uses", "with"}),
    "Stage release assets": frozenset({"name", "if", "run"}),
    "Upload staged release payload": frozenset({"name", "if", "uses", "with"}),
}
STAGING_RUN = "\n".join((
    "set -euo pipefail",
    "/bin/bash -p scripts/ci/stage-haptics-release-assets.sh \\",
    "  out/tb321fu-haptics-debs \\",
    "  out/tb321fu-haptics-release/release-staging \\",
    '  "$HAPTICS_DEB_VERSION" \\',
    '  "$KERNEL_SOURCE_COMMIT" \\',
    '  "$KERNEL_BUILD_ARCHIVE" \\',
    '  "$KERNEL_BUILD_ARCHIVE_SHA256" \\',
    '  "$KERNEL_BUNDLE_METADATA" \\',
    '  "$KERNEL_BUNDLE_METADATA_SHA256" \\',
    '  "$KERNEL_SDK_MANIFEST" \\',
    '  "$KERNEL_TOOLCHAIN_MANIFEST" \\',
    '  "$GITHUB_SHA" \\',
    '  "$GITHUB_RUN_ID"',
))
DEPENDENCY_RUN = "\n".join((
    "set -euo pipefail",
    "/usr/bin/sudo /bin/bash -p scripts/ci/test-haptics-dpkg-host-rejection.sh \\",
    "  scripts/ci/HAPTICS-BUILD-PACKAGES.tsv",
    "# GitHub-hosted ubuntu-24.04 images change their preinstalled package",
    "# versions and maintainer scripts. Capture the verified host state on",
    "# this runner immediately before the transaction instead of binding",
    "# the build to a different runner image.",
    'reference="$RUNNER_TEMP/HAPTICS-DPKG-HOST-REFERENCE.tsv"',
    'checksum="$RUNNER_TEMP/HAPTICS-DPKG-HOST-REFERENCE.sha256"',
    "/usr/bin/sudo /usr/bin/python3 -I -B scripts/ci/verify-haptics-dpkg-state.py \\",
    "  --capture-host-reference /var/lib/dpkg 0 0 > \"$reference\"",
    "/usr/bin/sudo /usr/bin/chmod 0600 \"$reference\"",
    "/usr/bin/sudo /usr/bin/chown 0:0 \"$reference\"",
    "/usr/bin/sudo /usr/bin/python3 -I -B scripts/ci/verify-haptics-dpkg-state.py \\",
    "  --verify-host-reference /var/lib/dpkg 0 0 \"$reference\"",
    "/usr/bin/sudo /usr/bin/sha256sum -- \"$reference\" > \"$checksum\"",
    "/usr/bin/sudo /usr/bin/chmod 0600 \"$checksum\"",
    "/usr/bin/sudo /usr/bin/sha256sum -c -- \"$checksum\"",
    "/usr/bin/sudo /usr/bin/chmod 0644 \"$reference\"",
    "/usr/bin/sudo /bin/bash -p scripts/ci/install-haptics-build-dependencies.sh \\",
    "  scripts/ci/HAPTICS-BUILD-PACKAGES.tsv \\",
    "  scripts/ci/HAPTICS-BUILD-TOOLS-REFERENCE.tsv \\",
    "  scripts/ci/HAPTICS-RELEASE-REFERENCE.tsv \\",
    "  \"$reference\"",
    "/usr/bin/sudo /usr/bin/python3 -I -B scripts/ci/test-haptics-apt-sandbox.py",
    "/usr/bin/sudo /usr/bin/python3 -I -B scripts/ci/test-haptics-apt-hook.py",
    "/usr/bin/sudo /usr/bin/python3 -I -B scripts/ci/test-haptics-apt-eipp-canary.py",
))
VALIDATION_RUN_FIXTURE = "\n".join((
    "set -euo pipefail",
    "/usr/bin/python3 -I -B scripts/ci/check-workflow-input-boundaries.py --self-test",
    "/usr/bin/python3 -I -B scripts/ci/check-workflow-input-boundaries.py .github/workflows/build.yml",
    "/usr/bin/python3 -I -B scripts/ci/check-action-pins.py --self-test",
    "/usr/bin/python3 -I -B scripts/ci/check-action-pins.py .github/workflows/build.yml",
    "/usr/bin/python3 -I -B scripts/ci/test-kernel-bundle-metadata.py",
    "/usr/bin/python3 -I -B scripts/ci/test-kernel-config-drift.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-release-reference.py",
    "/usr/bin/python3 -I -B scripts/ci/verify-haptics-build-packages.py --self-test",
    "/usr/bin/python3 -I -B scripts/ci/verify-haptics-build-packages.py \\",
    "  scripts/ci/HAPTICS-BUILD-PACKAGES.tsv",
    "/bin/bash -p scripts/ci/test-haptics-cross-link-closure.sh \\",
    "  scripts/ci/HAPTICS-BUILD-PACKAGES.tsv",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-dpkg-configuration.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-package-transaction.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-apt-transaction.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-apt-preparation.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-dpkg-state.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-dpkg-host-reference-workflow.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-apt-archive.py",
    "/usr/bin/python3 -I -B scripts/ci/test-run-haptics-workflow-dispatch-bootstrap.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-workflow-dispatch-gate.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-workflow-dispatch-bootstrap.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-publication-snapshot.py",
    "/usr/bin/python3 -I -B scripts/ci/test-bounded-file-readers.py",
    "/bin/bash -p scripts/ci/test-haptics-release-archive.sh",
    "/usr/bin/python3 -I -B scripts/ci/test-kernel-sdk-verifier.py",
    "/usr/bin/python3 -I -B scripts/ci/test-safe-extract-archive.py",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-release-job-isolation.py --self-test",
    "/usr/bin/python3 -I -B scripts/ci/test-haptics-release-job-isolation.py .github/workflows/build.yml",
    "/bin/bash -p -n scripts/ci/install-haptics-build-dependencies.sh",
    "/bin/bash -p -n scripts/ci/test-haptics-dpkg-host-rejection.sh",
    "/bin/bash -p -n scripts/ci/verify-haptics-compat-package.sh",
    "/bin/bash -p scripts/ci/test-haptics-compat-package.sh",
    "/bin/bash -p -n scripts/ci/verify-haptics-live-build-tools.sh",
    "/usr/bin/sudo /bin/bash -p scripts/ci/test-haptics-live-build-tools.sh",
    "/bin/bash -p -n scripts/ci/stage-haptics-release-assets.sh",
    "/bin/bash -p scripts/ci/test-haptics-lifecycle.sh",
    "/bin/bash -p scripts/ci/test-haptics-provenance.sh",
    "/bin/bash -p scripts/ci/test-haptics-build-environment.sh",
    "/bin/bash -p scripts/ci/test-haptics-epoch-contract.sh",
    "/bin/bash -p scripts/ci/test-haptics-deb-contract.sh",
    "/bin/bash -p scripts/ci/test-haptics-kernel-sdk-contract.sh",
    "/usr/bin/python3 -I -B scripts/ci/run-bounded-publication-fixture.py --self-test",
    "/usr/bin/python3 -I -B scripts/ci/run-bounded-publication-fixture.py",
    "python_residue=$(/usr/bin/find scripts/ci \\",
    "  \\( -type d -name __pycache__ -o -type f -name '*.py[co]' \\) \\",
    "  -print -quit)",
    "[ -z \"$python_residue\" ] || {",
    "  echo \"workflow validation left Python cache residue: $python_residue\" >&2",
    "  exit 1",
    "}",
)) + "\n"
INPUT_VALIDATION_RUN_FIXTURE = "\n".join((
    "set -euo pipefail",
    ". scripts/ci/common.sh",
    '[[ "$INPUT_DISPATCH_ID" =~ ^[0-9a-f]{32}$ ]] || {',
    "  echo 'dispatch_id must be exactly 32 lowercase hex characters' >&2",
    "  exit 1",
    "}",
    'if [ -n "$INPUT_RELEASE_TAG" ] && [ "$INPUT_PRERELEASE" != 1 ]; then',
    "  echo 'Remediation releases must set prerelease=true.' >&2",
    "  exit 1",
    "fi",
    '[[ "$INPUT_HAPTICS_DEB_VERSION" =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]] || {',
    "  echo 'unsafe haptics_deb_version' >&2",
    "  exit 1",
    "}",
    'dpkg --validate-version "$INPUT_HAPTICS_DEB_VERSION"',
    '[[ "$INPUT_KERNEL_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {',
    "  echo 'kernel_source_commit must be 40 lowercase hex characters' >&2",
    "  exit 1",
    "}",
    '[[ "$INPUT_KERNEL_BUILD_ARCHIVE" =~ ^https://[^[:space:]]{1,2048}$ ]] || {',
    "  echo 'kernel_build_archive must be a bounded HTTPS URL' >&2",
    "  exit 1",
    "}",
    '[[ "$INPUT_KERNEL_BUILD_ARCHIVE_SHA256" =~ ^[0-9A-Fa-f]{64}$ ]] || {',
    "  echo 'invalid kernel_build_archive_sha256' >&2",
    "  exit 1",
    "}",
    '[[ "$INPUT_KERNEL_BUNDLE_METADATA" =~ ^https://[^[:space:]]{1,2048}$ ]] || {',
    "  echo 'kernel_bundle_metadata must be a bounded HTTPS URL' >&2",
    "  exit 1",
    "}",
    '[[ "$INPUT_KERNEL_BUNDLE_METADATA_SHA256" =~ ^[0-9A-Fa-f]{64}$ ]] || {',
    "  echo 'invalid kernel_bundle_metadata_sha256' >&2",
    "  exit 1",
    "}",
    '[[ "$INPUT_KERNEL_SDK_MANIFEST" =~ ^https://[^[:space:]]{1,2048}$ ]] || {',
    "  echo 'kernel_sdk_manifest must be a bounded HTTPS URL' >&2",
    "  exit 1",
    "}",
    '[[ "$INPUT_KERNEL_TOOLCHAIN_MANIFEST" =~ ^https://[^[:space:]]{1,2048}$ ]] || {',
    "  echo 'kernel_toolchain_manifest must be a bounded HTTPS URL' >&2",
    "  exit 1",
    "}",
    'if [ -n "$INPUT_RELEASE_TAG" ]; then',
    '  [[ "$INPUT_HAPTICS_DEB_VERSION" =~ ^[0-9][0-9A-Za-z._-]{0,63}$ ]] || {',
    "    echo 'tagged haptics_deb_version contains a release-tag-unsafe character' >&2",
    "    exit 1",
    "  }",
    "  /usr/bin/python3 -I -B scripts/ci/verify-haptics-release-reference.py \\",
    "    scripts/ci/HAPTICS-RELEASE-REFERENCE.tsv",
    "  reference_version=$(awk -F '\\t' \\",
    '    \'$1 == "package-version" { print $2 }\' \\',
    "    scripts/ci/HAPTICS-RELEASE-REFERENCE.tsv)",
    '  [ "$INPUT_HAPTICS_DEB_VERSION" = "$reference_version" ] || {',
    "    echo 'tagged package version differs from the trusted release reference' >&2",
    "    exit 1",
    "  }",
    '  [ "$INPUT_RELEASE_TAG" = "tb321fu-haptics-debs-$INPUT_HAPTICS_DEB_VERSION" ] || {',
    "    echo 'release_tag must equal tb321fu-haptics-debs-<haptics_deb_version>' >&2",
    "    exit 1",
    "  }",
    "fi",
    'printf \'HAPTICS_DEB_VERSION=%s\\n\' "$INPUT_HAPTICS_DEB_VERSION" >> "$GITHUB_ENV"',
    'printf \'KERNEL_SOURCE_COMMIT=%s\\n\' "$INPUT_KERNEL_SOURCE_COMMIT" >> "$GITHUB_ENV"',
    'printf \'KERNEL_BUILD_ARCHIVE=%s\\n\' "$INPUT_KERNEL_BUILD_ARCHIVE" >> "$GITHUB_ENV"',
    'printf \'KERNEL_BUILD_ARCHIVE_SHA256=%s\\n\' "${INPUT_KERNEL_BUILD_ARCHIVE_SHA256,,}" >> "$GITHUB_ENV"',
    'printf \'KERNEL_BUNDLE_METADATA=%s\\n\' "$INPUT_KERNEL_BUNDLE_METADATA" >> "$GITHUB_ENV"',
    'printf \'KERNEL_BUNDLE_METADATA_SHA256=%s\\n\' "${INPUT_KERNEL_BUNDLE_METADATA_SHA256,,}" >> "$GITHUB_ENV"',
    'printf \'KERNEL_SDK_MANIFEST=%s\\n\' "$INPUT_KERNEL_SDK_MANIFEST" >> "$GITHUB_ENV"',
    'printf \'KERNEL_TOOLCHAIN_MANIFEST=%s\\n\' "$INPUT_KERNEL_TOOLCHAIN_MANIFEST" >> "$GITHUB_ENV"',
    'printf \'SOURCE_DATE_EPOCH=%s\\n\' "$(ci_git show -s --format=%ct HEAD)" >> "$GITHUB_ENV"',
)) + "\n"
BUILD_RUN_FIXTURE = "\n".join((
    "set -euo pipefail",
    "/usr/bin/env -i \\",
    "  PATH=/usr/sbin:/usr/bin:/sbin:/bin \\",
    "  LANG=C \\",
    "  LC_ALL=C \\",
    "  TZ=UTC \\",
    "  HOME=/nonexistent \\",
    "  TMPDIR=/tmp \\",
    '  http_proxy="${http_proxy:-${HTTP_PROXY:-}}" \\',
    '  https_proxy="${https_proxy:-${HTTPS_PROXY:-}}" \\',
    '  no_proxy="${no_proxy:-${NO_PROXY:-}}" \\',
    "  OUTPUT_DIR=out/tb321fu-haptics-debs \\",
    "  ARCH=arm64 \\",
    '  HAPTICS_DEB_VERSION="$HAPTICS_DEB_VERSION" \\',
    "  HAPTICS_STRIP=1 \\",
    "  HAPTICS_RELEASE_MODE=1 \\",
    '  HAPTICS_PRODUCER_COMMIT="$GITHUB_SHA" \\',
    '  KERNEL_SOURCE_COMMIT="$KERNEL_SOURCE_COMMIT" \\',
    '  KERNEL_BUILD_ARCHIVE="$KERNEL_BUILD_ARCHIVE" \\',
    '  KERNEL_BUILD_ARCHIVE_SHA256="$KERNEL_BUILD_ARCHIVE_SHA256" \\',
    '  KERNEL_BUNDLE_METADATA="$KERNEL_BUNDLE_METADATA" \\',
    '  KERNEL_BUNDLE_METADATA_SHA256="$KERNEL_BUNDLE_METADATA_SHA256" \\',
    '  KERNEL_SDK_MANIFEST="$KERNEL_SDK_MANIFEST" \\',
    '  KERNEL_TOOLCHAIN_MANIFEST="$KERNEL_TOOLCHAIN_MANIFEST" \\',
    '  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \\',
    "  /bin/bash scripts/ci/build-tb321fu-haptics-deb-from-kernel-sdk.sh",
)) + "\n"
BUILD_STEP_NAMES = tuple(BUILD_STEP_KEYS)


def fail(message: str) -> None:
    prefix = "haptics release job isolation check failed: "
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
        return yaml.load(source, Loader=WorkflowLoader)
    except Exception:
        fail("invalid workflow YAML")


def assert_cli_rejects_invalid_source(raw: bytes, label: str) -> None:
    fd = os.memfd_create("workflow-isolation-hostile", os.MFD_CLOEXEC)
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
        or not result.stderr.startswith(
            b"haptics release job isolation check failed: "
        )
        or len(result.stderr) > 4096
    ):
        fail(f"self-test CLI did not bound hostile {label} diagnostics")


def mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return value


def exactly_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            exactly_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, (list, tuple)):
        return len(actual) == len(expected) and all(
            exactly_equal(actual_value, expected_value)
            for actual_value, expected_value in zip(actual, expected, strict=True)
        )
    return actual == expected


def steps_for(job: dict, label: str) -> list[dict]:
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        fail(f"{label}.steps must be a non-empty list")
    return [mapping(step, f"{label}.steps[{index}]") for index, step in enumerate(steps)]


def named_step(steps: list[dict], name: str) -> dict:
    matches = [step for step in steps if step.get("name") == name]
    if len(matches) != 1:
        fail(f"expected exactly one step named {name!r}, found {len(matches)}")
    return matches[0]


def scalar_text(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from scalar_text(child)
    elif isinstance(value, list):
        for child in value:
            yield from scalar_text(child)
    elif isinstance(value, str):
        yield value


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


def credential_contexts(value: object) -> BoundedMatches:
    unsafe = BoundedMatches()
    for scalar in scalar_text(value):
        for expression in normalized_expressions(scalar):
            if re.search(r"(?<![a-z0-9_.])secrets(?![a-z0-9_])", expression):
                unsafe.add("secrets")
            if re.search(r"(?<![a-z0-9_.])github\.token(?![a-z0-9_])", expression):
                unsafe.add("github.token")
            if re.search(r"(?<![a-z0-9_.])github(?![a-z0-9_.])", expression):
                unsafe.add("github")
    return unsafe


def expression_inventory(value: object) -> Counter[str]:
    inventory: Counter[str] = Counter()
    for scalar in scalar_text(value):
        inventory.update(normalized_expressions(scalar))
    return inventory


def require_pinned_action(step: dict, expected: str, label: str) -> None:
    if step.get("uses") != expected or not PINNED_ACTION.fullmatch(expected):
        fail(f"{label} must use the pinned action {expected}")


def require_release_guard(value: dict, label: str) -> None:
    if value.get("if") != RELEASE_GUARD:
        fail(f"{label} must be guarded by a non-empty release tag")


def require_reviewed_run(step: dict, name: str) -> str:
    run = step.get("run")
    if not isinstance(run, str):
        fail(f"{name!r} must contain a run scalar")
    actual_sha256 = hashlib.sha256(run.encode("utf-8")).hexdigest()
    if actual_sha256 != REVIEWED_RUN_SHA256[name]:
        fail(f"{name!r} run body differs from the complete reviewed scalar")
    return run


def validate(data: dict) -> None:
    if set(data) != {
        "name",
        "run-name",
        "on",
        "concurrency",
        "defaults",
        "jobs",
    }:
        fail("workflow keys differ from the complete reviewed mapping")
    if data.get("name") != WORKFLOW_NAME:
        fail("workflow name differs from the reviewed contract")
    if data.get("run-name") != WORKFLOW_RUN_NAME:
        fail("workflow run-name differs from the trusted dispatch identity contract")
    if expression_inventory(data) != EXPECTED_EXPRESSIONS:
        fail("workflow expression inventory differs from the reviewed contract")
    if not exactly_equal(data.get("concurrency"), {
        "group": (
            "release-${{ github.repository }}-"
            "${{ inputs.release_tag != '' && inputs.release_tag || inputs.dispatch_id }}"
        ),
        "cancel-in-progress": False,
    }):
        fail("workflow concurrency differs from the reviewed repository/tag contract")
    if not exactly_equal(
        data.get("defaults"),
        {
            "run": {
                "shell": "/bin/bash --noprofile --norc -p -e -o pipefail {0}"
            }
        },
    ):
        fail("workflow run shell differs from the privileged fixed contract")
    triggers = mapping(data.get("on"), "on")
    if tuple(triggers) != ("workflow_dispatch",):
        fail("workflow must expose only workflow_dispatch")
    dispatch = mapping(triggers.get("workflow_dispatch"), "on.workflow_dispatch")
    if tuple(dispatch) != ("inputs",):
        fail("workflow_dispatch must contain only inputs")
    inputs = mapping(dispatch.get("inputs"), "on.workflow_dispatch.inputs")
    if tuple(inputs) != WORKFLOW_INPUTS:
        fail("workflow_dispatch must expose the exact ordered eleven-input contract")
    expected_inputs = {
        "dispatch_id": {
            "description": WORKFLOW_INPUT_DESCRIPTIONS["dispatch_id"],
            "required": True,
            "type": "string",
        },
        "release_tag": {
            "description": WORKFLOW_INPUT_DESCRIPTIONS["release_tag"],
            "required": False,
            "default": "",
            "type": "string",
        },
        "prerelease": {
            "description": WORKFLOW_INPUT_DESCRIPTIONS["prerelease"],
            "required": True,
            "default": True,
            "type": "boolean",
        },
        **{
            name: {
                "description": WORKFLOW_INPUT_DESCRIPTIONS[name],
                "required": True,
                "default": default,
                "type": "string",
            }
            for name, default in CANONICAL_PROFILE_DEFAULTS.items()
        },
    }
    for name, expected in expected_inputs.items():
        declared = mapping(inputs[name], f"{name} input")
        if not exactly_equal(declared, expected):
            fail(
                f"{name} input description/required/default/type differs "
                "from the reviewed contract"
            )
    jobs = mapping(data.get("jobs"), "jobs")
    if tuple(jobs) != ("build",):
        fail("workflow must contain only the read-only build/staging job")
    build = mapping(jobs.get("build"), "jobs.build")
    if set(build) != {"runs-on", "permissions", "timeout-minutes", "steps"}:
        fail("build job keys differ from the complete reviewed mapping")
    if build.get("runs-on") != CANONICAL_RUNNER:
        fail("build job must use the canonical x86_64 runner")
    if not exactly_equal(build.get("timeout-minutes"), 90):
        fail("build job must retain the reviewed 90-minute timeout")
    if not exactly_equal(build.get("permissions"), {"contents": "read"}):
        fail("build job must retain only contents: read")
    build_text = "\n".join(scalar_text(build))
    if any(
        token in build_text
        for token in (
            "RELEASE_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "github.token",
            "contents: write",
        )
    ):
        fail("build job references a release credential")
    contexts = credential_contexts(build)
    if contexts:
        fail(
            "build job references forbidden credential contexts: "
            + contexts.render()
        )
    if "publish-release.sh" in build_text:
        fail("build job invokes the release publisher")

    build_steps = steps_for(build, "jobs.build")
    if tuple(step.get("name") for step in build_steps) != BUILD_STEP_NAMES:
        fail("workflow build steps must equal the exact reviewed sequence")
    for step in build_steps:
        name = step["name"]
        if set(step) != BUILD_STEP_KEYS[name]:
            fail(f"{name!r} step keys differ from the complete reviewed mapping")
    expression_runs = [
        step.get("name", "<unnamed>")
        for step in build_steps
        if isinstance(step.get("run"), str) and has_workflow_expression(step["run"])
    ]
    if expression_runs:
        fail(f"workflow expressions are forbidden in run steps: {expression_runs}")
    checkout = named_step(build_steps, "Checkout")
    require_pinned_action(checkout, CHECKOUT, "build checkout")
    checkout_with = mapping(checkout.get("with"), "build checkout.with")
    if not exactly_equal(
        checkout_with, {"persist-credentials": False, "fetch-depth": 0}
    ):
        fail("build checkout inputs must disable credentials and fetch full history")
    dependencies = named_step(build_steps, "Install dependencies")
    validation = named_step(build_steps, "Validate workflow and lifecycle boundaries")
    if build_steps.index(dependencies) >= build_steps.index(validation):
        fail("declared test dependencies must be installed before validation")
    if mapping(validation.get("env"), "workflow validation.env") != {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }:
        fail("workflow validation environment differs from the fixed contract")
    validation_run = require_reviewed_run(
        validation, "Validate workflow and lifecycle boundaries"
    )
    if "test-kernel-config-drift.py" not in validation_run:
        fail("workflow validation must execute kernel config drift fixtures")
    if "test-haptics-release-reference.py" not in validation_run:
        fail("workflow validation must execute the release-reference hostile fixtures")
    if "test-haptics-release-archive.sh" not in validation_run:
        fail("workflow validation must execute the release-archive hostile fixtures")
    if "test-haptics-publication-snapshot.py" not in validation_run:
        fail("workflow validation must execute the publication-snapshot hostile fixtures")
    if "test-haptics-workflow-dispatch-bootstrap.py" not in validation_run:
        fail("workflow validation must execute the trusted dispatch bootstrap fixture")
    if "verify-haptics-build-packages.py --self-test" not in validation_run:
        fail("workflow validation must execute the package-lock hostile fixtures")
    if "scripts/ci/HAPTICS-BUILD-PACKAGES.tsv" not in validation_run:
        fail("workflow validation must validate the committed package lock")
    if "test-haptics-cross-link-closure.sh" not in validation_run:
        fail("workflow validation must execute the cross-link closure fixture")
    if "test-haptics-dpkg-configuration.py" not in validation_run:
        fail("workflow validation must execute native dpkg configuration fixtures")
    if "test-haptics-package-transaction.py" not in validation_run:
        fail("workflow validation must execute package transaction fixtures")
    if "test-haptics-live-build-tools.sh" not in validation_run:
        fail("workflow validation must execute the live build-tools reference fixtures")
    if "/bin/bash -p -n scripts/ci/install-haptics-build-dependencies.sh" not in validation_run:
        fail("workflow validation must syntax-check the dependency installer")
    if "/bin/bash -p -n scripts/ci/test-haptics-dpkg-host-rejection.sh" not in validation_run:
        fail("workflow validation must syntax-check the host dpkg rejection fixture")
    if "/bin/bash -p -n scripts/ci/verify-haptics-compat-package.sh" not in validation_run:
        fail("workflow validation must syntax-check the compatibility-package verifier")
    if "test-haptics-compat-package.sh" not in validation_run:
        fail("workflow validation must execute compatibility-package hostile fixtures")
    if "/bin/bash -p -n scripts/ci/verify-haptics-live-build-tools.sh" not in validation_run:
        fail("workflow validation must syntax-check the live build-tools verifier")
    if "/bin/bash -p -n scripts/ci/stage-haptics-release-assets.sh" not in validation_run:
        fail("workflow validation must syntax-check the staging entry point")
    if "/bin/bash -p scripts/ci/test-haptics-epoch-contract.sh" not in validation_run:
        fail("workflow validation must execute the split-epoch contract fixture")
    if (
        "/usr/bin/python3 -I -B "
        "scripts/ci/run-bounded-publication-fixture.py --self-test"
        not in validation_run
        or "/usr/bin/python3 -I -B "
        "scripts/ci/run-bounded-publication-fixture.py"
        not in validation_run
        or "/bin/bash -p scripts/ci/test-release-publication.sh" in validation_run
    ):
        fail("workflow validation must use only the bounded publication runner")
    if "__pycache__" not in validation_run or "*.py[co]" not in validation_run:
        fail("workflow validation must reject Python cache residue")
    require_reviewed_run(
        named_step(build_steps, "Validate build inputs"), "Validate build inputs"
    )
    require_reviewed_run(named_step(build_steps, "Build haptics deb"), "Build haptics deb")
    dependencies_run = dependencies.get("run")
    if not isinstance(dependencies_run, str):
        fail("dependency installation must have a shell body")
    if "test-haptics-dpkg-host-rejection.sh" not in dependencies_run:
        fail("dependency installation must execute the host dpkg rejection fixture")
    if dependencies_run.rstrip("\n") != DEPENDENCY_RUN:
        fail("dependency installation must invoke the exact reviewed entry point")
    for step in build_steps:
        if step is dependencies or not isinstance(step.get("run"), str):
            continue
        run_text = step["run"]
        if step is validation:
            run_text = run_text.replace(ALLOWED_VALIDATION_PRIVILEGE, "")
        if PACKAGE_MUTATION.search(run_text):
            fail(f"unreviewed package or privilege mutation in step: {step['name']}")
    generic_upload = named_step(build_steps, "Upload diagnostic build output")
    require_pinned_action(generic_upload, UPLOAD, "general workflow artifact upload")
    if generic_upload.get("if") != DIAGNOSTIC_GUARD:
        fail("general build output must be restricted to empty-tag diagnostics")
    if not exactly_equal(
        mapping(generic_upload.get("with"), "general workflow artifact upload.with"),
        {
        "name": GENERAL_ARTIFACT,
        "path": "out/tb321fu-haptics-debs/*",
        "if-no-files-found": "error",
        },
    ):
        fail("diagnostic workflow artifact must be attempt-unique and required")
    staging = named_step(build_steps, "Stage release assets")
    require_release_guard(staging, "release asset staging")
    staging_run = staging.get("run")
    if not isinstance(staging_run, str):
        fail("release asset staging must have a shell body")
    if staging_run.rstrip("\n") != STAGING_RUN:
        fail("release asset staging must invoke the exact reviewed entry point")
    upload = named_step(build_steps, "Upload staged release payload")
    require_release_guard(upload, "staged release artifact upload")
    if build_steps.index(staging) >= build_steps.index(upload):
        fail("release staging must precede artifact upload")
    require_pinned_action(upload, UPLOAD, "staged release artifact upload")
    if not exactly_equal(
        mapping(upload.get("with"), "staged release artifact upload.with"),
        {
        "name": ARTIFACT,
        "path": "out/tb321fu-haptics-release/release-staging",
        "if-no-files-found": "error",
        },
    ):
        fail("staged release artifact must be the closed staging directory")
    action_steps = [step for step in build_steps if "uses" in step]
    if action_steps != [checkout, generic_upload, upload]:
        fail("workflow must contain only the reviewed checkout and two artifact uploads")
    artifact_uploads = [
        step
        for step in build_steps
        if isinstance(step.get("uses"), str)
        and step["uses"].split("@", 1)[0].lower() == "actions/upload-artifact"
    ]
    if artifact_uploads != [generic_upload, upload]:
        fail("workflow must contain exactly the diagnostic and staged artifact uploads")

def fixture() -> dict:
    data = {
        "name": WORKFLOW_NAME,
        "run-name": WORKFLOW_RUN_NAME,
        "concurrency": {
            "group": (
                "release-${{ github.repository }}-"
                "${{ inputs.release_tag != '' && inputs.release_tag || inputs.dispatch_id }}"
            ),
            "cancel-in-progress": False,
        },
        "defaults": {
            "run": {
                "shell": "/bin/bash --noprofile --norc -p -e -o pipefail {0}"
            }
        },
        "on": {
            "workflow_dispatch": {
                "inputs": {
                    "dispatch_id": {
                        "required": True,
                        "type": "string",
                    },
                    "release_tag": {
                        "required": False,
                        "default": "",
                        "type": "string",
                    },
                    "prerelease": {
                        "required": True,
                        "default": True,
                        "type": "boolean",
                    },
                    "haptics_deb_version": {
                        "required": True,
                        "default": "20260730.2",
                        "type": "string",
                    },
                    "kernel_source_commit": {
                        "required": True,
                        "default": "570b90203d97f67321fa0fb2d0af73c31d7111af",
                        "type": "string",
                    },
                    "kernel_build_archive": {
                        "required": True,
                        "default": (
                            "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
                            "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/"
                            "tb321fu-kernel-build-sdk-7.1.1-00009-g570b90203d97.tar.gz"
                        ),
                        "type": "string",
                    },
                    "kernel_build_archive_sha256": {
                        "required": True,
                        "default": (
                            "7f9b12bd02c1155c9900a33c823d088e1a9f72689dea28c8ee582a31304c7c49"
                        ),
                        "type": "string",
                    },
                    "kernel_bundle_metadata": {
                        "required": True,
                        "default": (
                            "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
                            "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/KERNEL-BUNDLE.tsv"
                        ),
                        "type": "string",
                    },
                    "kernel_bundle_metadata_sha256": {
                        "required": True,
                        "default": (
                            "9b11d12fab79eb4f10acb7eddf9c5e11e3f4242f2877658627ff3b11dd231998"
                        ),
                        "type": "string",
                    },
                    "kernel_sdk_manifest": {
                        "required": True,
                        "default": (
                            "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
                            "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/"
                            "KERNEL-SDK-MANIFEST.tsv"
                        ),
                        "type": "string",
                    },
                    "kernel_toolchain_manifest": {
                        "required": True,
                        "default": (
                            "https://github.com/GUF296/ubuntu-y700-build-ci/releases/download/"
                            "tb321fu-kernel-bootstrap-570b90203d97-20260729.4/"
                            "KERNEL-TOOLCHAIN.tsv"
                        ),
                        "type": "string",
                    },
                },
            }
        },
        "jobs": {
            "build": {
                "runs-on": CANONICAL_RUNNER,
                "permissions": {"contents": "read"},
                "timeout-minutes": 90,
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": CHECKOUT,
                        "with": {"persist-credentials": False, "fetch-depth": 0},
                    },
                    {
                        "name": "Install dependencies",
                        "run": DEPENDENCY_RUN,
                    },
                    {
                        "name": "Validate workflow and lifecycle boundaries",
                        "env": {
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                        },
                        "run": VALIDATION_RUN_FIXTURE,
                    },
                    {
                        "name": "Validate build inputs",
                        "env": {
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
                        },
                        "run": INPUT_VALIDATION_RUN_FIXTURE,
                    },
                    {"name": "Build haptics deb", "run": BUILD_RUN_FIXTURE},
                    {
                            "name": "Upload diagnostic build output",
                            "if": DIAGNOSTIC_GUARD,
                            "uses": UPLOAD,
                            "with": {
                                "name": GENERAL_ARTIFACT,
                                "path": "out/tb321fu-haptics-debs/*",
                                "if-no-files-found": "error",
                            },
                    },
                    {
                        "name": "Stage release assets",
                        "if": RELEASE_GUARD,
                        "run": STAGING_RUN,
                    },
                    {
                        "name": "Upload staged release payload",
                        "if": RELEASE_GUARD,
                        "uses": UPLOAD,
                        "with": {
                            "name": ARTIFACT,
                            "path": "out/tb321fu-haptics-release/release-staging",
                            "if-no-files-found": "error",
                        },
                    },
                ],
            },
        }
    }
    inputs = data["on"]["workflow_dispatch"]["inputs"]
    for name, description in WORKFLOW_INPUT_DESCRIPTIONS.items():
        inputs[name]["description"] = description
    return data


def expect_rejected(candidate: dict, message: str) -> None:
    try:
        validate(candidate)
    except SystemExit:
        return
    fail(message)


def self_test() -> None:
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
            yaml.load(duplicate_source, Loader=WorkflowLoader)
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
    historical_expression = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
    for length in range(9):
        for symbols in itertools.product("${}a", repeat=length):
            expression_source = "".join(symbols)
            expected_bodies = tuple(
                match.group(1)
                for match in historical_expression.finditer(expression_source)
            )
            if expression_bodies(expression_source) != expected_bodies:
                fail(
                    "self-test expression scanner differs from the bounded historical oracle"
                )

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
            f"value: {integer_source}\n", Loader=WorkflowLoader
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
            yaml.load(f"value: {integer_source}\n", Loader=WorkflowLoader)
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
            f"value: {integer_source}\n", Loader=WorkflowLoader
        )
        actual_integer = parsed_integer.get("value") if isinstance(parsed_integer, dict) else None
        if type(actual_integer) is not int or actual_integer != expected_integer:
            fail(f"self-test loader changed canonical integer {integer_source}")
    for boolean_source in ("on", "On", "ON", "off", "yes", "no", "fal\u017fe"):
        parsed_boolean = yaml.load(
            f"value: {boolean_source}\n", Loader=WorkflowLoader
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
            yaml.load(f"value: {boolean_source}\n", Loader=WorkflowLoader)
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
            f"value: {boolean_source}\n", Loader=WorkflowLoader
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
            f"value: {integer_source}\n", Loader=WorkflowLoader
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
            yaml.load(f"value: {integer_source}\n", Loader=WorkflowLoader)
        except yaml.constructor.ConstructorError:
            continue
        fail(f"self-test loader accepted over-limit {label} integer")
    for label, alias_source in (
        ("ordinary alias", "value: &value safe\nalias: *value\n"),
        ("recursive alias", "value: &value [*value]\n"),
    ):
        try:
            yaml.load(alias_source, Loader=WorkflowLoader)
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
        yaml.load(depth_source, Loader=WorkflowLoader)
    for label, depth_source in (
        ("scalar-terminal", f"[{exact_scalar_depth}]"),
        ("self-closing", f"[{exact_self_closing_depth}]"),
    ):
        loader = WorkflowLoader(depth_source)
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
    reset_loader = WorkflowLoader("[0]")
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
        loader = WorkflowLoader(source_text)
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
            yaml.load(source_text, Loader=WorkflowLoader)
        except yaml.constructor.ConstructorError as exc:
            if "YAML node inventory exceeds the reviewed limit" not in str(exc):
                raise
        else:
            fail(f"self-test loader accepted over-limit {label} node inventory")
    contexts = credential_contexts(
        {"env": "${{ format('{0}', github['token']) }}"}
    )
    if contexts.total != 1 or contexts.examples != ["github.token"]:
        fail("self-test helper did not detect github.token before a function suffix")
    hostile_contexts = credential_contexts(
        {
            ("k" * 1000) + str(index): "${{ secrets.TOKEN }}"
            for index in range(200)
        }
    )
    if (
        hostile_contexts.total != 200
        or hostile_contexts.examples != ["secrets"] * MAX_DIAGNOSTIC_EXAMPLES
        or len(hostile_contexts.render().encode("utf-8")) > 256
    ):
        fail("self-test credential diagnostic summary is not bounded")
    parsed_types = yaml.load(
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      prerelease:\n"
        "        required: true\n"
        "        default: false\n",
        Loader=WorkflowLoader,
    )
    if tuple(parsed_types) != ("on",):
        fail("self-test loader did not preserve the GitHub Actions 'on' key")
    parsed_prerelease = parsed_types["on"]["workflow_dispatch"]["inputs"][
        "prerelease"
    ]
    if not exactly_equal(parsed_prerelease, {"required": True, "default": False}):
        fail("self-test loader did not preserve YAML boolean input metadata")

    valid = fixture()
    validate(valid)
    hostile_descriptions = (
        ("mapping", {"nested": "value"}),
        ("list", ["value"]),
        ("integer", 7),
        ("timestamp", yaml.load("value: 2026-08-09\n", Loader=WorkflowLoader)["value"]),
        ("binary", b"value"),
        ("wrong string", "unreviewed description"),
    )
    for label, hostile_description in hostile_descriptions:
        candidate = copy.deepcopy(valid)
        candidate["on"]["workflow_dispatch"]["inputs"]["dispatch_id"][
            "description"
        ] = hostile_description
        expect_rejected(
            candidate,
            f"self-test accepted a {label} workflow input description",
        )
    missing_run_name = copy.deepcopy(valid)
    del missing_run_name["run-name"]
    expect_rejected(missing_run_name, "self-test accepted a missing workflow run-name")
    wrong_run_name = copy.deepcopy(valid)
    wrong_run_name["run-name"] = "haptics-dispatch-${{ github.run_id }}"
    expect_rejected(wrong_run_name, "self-test accepted an unbound workflow run-name")
    missing_dispatch_input = copy.deepcopy(valid)
    del missing_dispatch_input["on"]["workflow_dispatch"]["inputs"]["dispatch_id"]
    expect_rejected(
        missing_dispatch_input,
        "self-test accepted a missing trusted dispatch identity input",
    )
    optional_dispatch_input = copy.deepcopy(valid)
    optional_dispatch_input["on"]["workflow_dispatch"]["inputs"]["dispatch_id"][
        "required"
    ] = False
    expect_rejected(
        optional_dispatch_input,
        "self-test accepted an optional trusted dispatch identity input",
    )
    default_dispatch_input = copy.deepcopy(valid)
    default_dispatch_input["on"]["workflow_dispatch"]["inputs"]["dispatch_id"][
        "default"
    ] = "0" * 32
    expect_rejected(
        default_dispatch_input,
        "self-test accepted a default trusted dispatch identity",
    )
    run_id_concurrency = copy.deepcopy(valid)
    run_id_concurrency["concurrency"]["group"] = (
        "release-${{ github.repository }}-"
        "${{ inputs.release_tag != '' && inputs.release_tag || github.run_id }}"
    )
    expect_rejected(
        run_id_concurrency,
        "self-test accepted concurrency detached from trusted dispatch identity",
    )
    missing_dispatch_env = copy.deepcopy(valid)
    validation_env = named_step(
        missing_dispatch_env["jobs"]["build"]["steps"], "Validate build inputs"
    )["env"]
    del validation_env["INPUT_DISPATCH_ID"]
    expect_rejected(
        missing_dispatch_env,
        "self-test accepted build validation without dispatch identity mediation",
    )
    reviewed_runs = {
        "Validate workflow and lifecycle boundaries": VALIDATION_RUN_FIXTURE,
        "Validate build inputs": INPUT_VALIDATION_RUN_FIXTURE,
        "Build haptics deb": BUILD_RUN_FIXTURE,
    }
    for step_name, reviewed_run in reviewed_runs.items():
        first_line, second_line, *remaining_lines = reviewed_run.splitlines()
        mutations = {
            "early exit 0": "exit 0\n" + reviewed_run,
            "unreachable wrapper": (
                "if false; then\n"
                + "\n".join(f"  {line}" for line in reviewed_run.splitlines())
                + "\nfi\ntrue\n"
            ),
            "command replacement": reviewed_run.replace(
                first_line, "printf '%s\\n' replaced-command", 1
            ),
            "command reorder": "\n".join(
                (second_line, first_line, *remaining_lines)
            ) + "\n",
            "appended command": reviewed_run + "true\n",
        }
        for mutation_name, hostile_run in mutations.items():
            candidate = copy.deepcopy(valid)
            step = named_step(candidate["jobs"]["build"]["steps"], step_name)
            step["run"] = hostile_run
            expect_rejected(
                candidate,
                f"self-test accepted {mutation_name} in {step_name!r}",
            )
        bypassed_shell = copy.deepcopy(valid)
        step = named_step(bypassed_shell["jobs"]["build"]["steps"], step_name)
        step["shell"] = "/usr/bin/true {0}"
        expect_rejected(
            bypassed_shell,
            f"self-test accepted a non-executing shell in {step_name!r}",
        )

    workflow_defaults = copy.deepcopy(valid)
    workflow_defaults["defaults"] = {"run": {"shell": "/usr/bin/true {0}"}}
    expect_rejected(
        workflow_defaults,
        "self-test accepted a workflow-level non-executing shell",
    )
    job_defaults = copy.deepcopy(valid)
    job_defaults["jobs"]["build"]["defaults"] = {
        "run": {"shell": "/usr/bin/true {0}"}
    }
    expect_rejected(
        job_defaults,
        "self-test accepted a job-level non-executing shell",
    )
    skipped_job = copy.deepcopy(valid)
    skipped_job["jobs"]["build"]["if"] = "false"
    expect_rejected(skipped_job, "self-test accepted a skipped build job")
    for step_name, key, value in (
        ("Checkout", "continue-on-error", True),
        ("Install dependencies", "shell", "/usr/bin/true {0}"),
        ("Upload diagnostic build output", "continue-on-error", True),
        ("Stage release assets", "shell", "/usr/bin/true {0}"),
        ("Upload staged release payload", "continue-on-error", True),
    ):
        candidate = copy.deepcopy(valid)
        step = named_step(candidate["jobs"]["build"]["steps"], step_name)
        step[key] = value
        expect_rejected(
            candidate,
            f"self-test accepted unreviewed {key!r} on {step_name!r}",
        )

    wrong_prerelease_type = copy.deepcopy(valid)
    wrong_prerelease_type["on"]["workflow_dispatch"]["inputs"]["prerelease"][
        "type"
    ] = "string"
    expect_rejected(wrong_prerelease_type, "self-test accepted prerelease type string")
    quoted_prerelease_required = copy.deepcopy(valid)
    quoted_prerelease_required["on"]["workflow_dispatch"]["inputs"]["prerelease"][
        "required"
    ] = "true"
    expect_rejected(
        quoted_prerelease_required,
        "self-test accepted quoted prerelease required true",
    )
    quoted_prerelease_default = copy.deepcopy(valid)
    quoted_prerelease_default["on"]["workflow_dispatch"]["inputs"]["prerelease"][
        "default"
    ] = "true"
    expect_rejected(
        quoted_prerelease_default,
        "self-test accepted quoted prerelease default true",
    )
    numeric_prerelease_default = copy.deepcopy(valid)
    numeric_prerelease_default["on"]["workflow_dispatch"]["inputs"]["prerelease"][
        "default"
    ] = 1
    expect_rejected(
        numeric_prerelease_default,
        "self-test accepted numeric prerelease default true",
    )
    numeric_release_required = copy.deepcopy(valid)
    numeric_release_required["on"]["workflow_dispatch"]["inputs"]["release_tag"][
        "required"
    ] = 0
    expect_rejected(
        numeric_release_required,
        "self-test accepted numeric release_tag required false",
    )
    false_prerelease_default = copy.deepcopy(valid)
    false_prerelease_default["on"]["workflow_dispatch"]["inputs"]["prerelease"][
        "default"
    ] = False
    expect_rejected(false_prerelease_default, "self-test accepted prerelease default false")
    tagged_by_default = copy.deepcopy(valid)
    tagged_by_default["on"]["workflow_dispatch"]["inputs"]["release_tag"][
        "default"
    ] = "unreviewed-release"
    expect_rejected(tagged_by_default, "self-test accepted a nonempty release_tag default")
    missing_required = copy.deepcopy(valid)
    del missing_required["on"]["workflow_dispatch"]["inputs"][
        "kernel_source_commit"
    ]["required"]
    expect_rejected(missing_required, "self-test accepted a missing required declaration")
    wrong_string_type = copy.deepcopy(valid)
    wrong_string_type["on"]["workflow_dispatch"]["inputs"][
        "kernel_build_archive"
    ]["type"] = "boolean"
    expect_rejected(wrong_string_type, "self-test accepted a wrong string-input type")
    wrong_profile_default = copy.deepcopy(valid)
    wrong_profile_default["on"]["workflow_dispatch"]["inputs"][
        "kernel_sdk_manifest"
    ]["default"] = "https://example.invalid/unreviewed.tsv"
    expect_rejected(wrong_profile_default, "self-test accepted a wrong profile default")
    equivalent_float_version = copy.deepcopy(valid)
    equivalent_float_version["on"]["workflow_dispatch"]["inputs"][
        "haptics_deb_version"
    ]["default"] = 20260730.20
    expect_rejected(
        equivalent_float_version,
        "self-test accepted a distinct version collapsed by floating-point parsing",
    )
    extra_trigger = copy.deepcopy(valid)
    extra_trigger["on"]["push"] = {}
    expect_rejected(extra_trigger, "self-test accepted an extra workflow trigger")
    extra_dispatch_key = copy.deepcopy(valid)
    extra_dispatch_key["on"]["workflow_dispatch"]["unexpected"] = "ignored"
    expect_rejected(
        extra_dispatch_key,
        "self-test accepted an extra workflow_dispatch key",
    )
    missing_timeout = copy.deepcopy(valid)
    del missing_timeout["jobs"]["build"]["timeout-minutes"]
    expect_rejected(missing_timeout, "self-test accepted a missing build timeout")
    wrong_timeout = copy.deepcopy(valid)
    wrong_timeout["jobs"]["build"]["timeout-minutes"] = 91
    expect_rejected(wrong_timeout, "self-test accepted a wrong build timeout")
    floating_timeout = copy.deepcopy(valid)
    floating_timeout["jobs"]["build"]["timeout-minutes"] = 90.0
    expect_rejected(floating_timeout, "self-test accepted a floating build timeout")
    missing_fetch_depth = copy.deepcopy(valid)
    checkout = named_step(missing_fetch_depth["jobs"]["build"]["steps"], "Checkout")
    del checkout["with"]["fetch-depth"]
    expect_rejected(missing_fetch_depth, "self-test accepted missing checkout fetch-depth")
    shallow_checkout = copy.deepcopy(valid)
    checkout = named_step(shallow_checkout["jobs"]["build"]["steps"], "Checkout")
    checkout["with"]["fetch-depth"] = 1
    expect_rejected(shallow_checkout, "self-test accepted shallow checkout history")
    boolean_fetch_depth = copy.deepcopy(valid)
    checkout = named_step(boolean_fetch_depth["jobs"]["build"]["steps"], "Checkout")
    checkout["with"]["fetch-depth"] = False
    expect_rejected(boolean_fetch_depth, "self-test accepted boolean checkout fetch-depth")
    extra_checkout_input = copy.deepcopy(valid)
    checkout = named_step(extra_checkout_input["jobs"]["build"]["steps"], "Checkout")
    checkout["with"]["path"] = "unreviewed"
    expect_rejected(extra_checkout_input, "self-test accepted an extra checkout input")

    leaked_token = copy.deepcopy(valid)
    leaked_token["jobs"]["build"]["steps"][0]["env"] = {"GH_TOKEN": GITHUB_TOKEN}
    try:
        validate(leaked_token)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a build-job token")
    bracketed_token = copy.deepcopy(valid)
    bracketed_token["jobs"]["build"]["steps"][0]["env"] = {
        "SAFE_NAME": "${{ github['token'] }}"
    }
    try:
        validate(bracketed_token)
    except SystemExit:
        pass
    else:
        fail("self-test accepted bracketed github.token")
    suffixed_token = copy.deepcopy(valid)
    suffixed_token["jobs"]["build"]["steps"][0]["env"] = {
        "SAFE_NAME": "${{ format('{0}', github['token']) }}"
    }
    try:
        validate(suffixed_token)
    except SystemExit:
        pass
    else:
        fail("self-test accepted github.token before a function suffix")
    bracketed_secret = copy.deepcopy(valid)
    bracketed_secret["jobs"]["build"]["steps"][0]["env"] = {
        "SAFE_NAME": "${{ secrets['ARBITRARY_NAME'] }}"
    }
    try:
        validate(bracketed_secret)
    except SystemExit:
        pass
    else:
        fail("self-test accepted an arbitrary secrets context")
    whole_inputs = copy.deepcopy(valid)
    whole_inputs["jobs"]["build"]["steps"][0]["env"] = {
        "SAFE_NAME": "${{ toJSON(inputs) }}"
    }
    try:
        validate(whole_inputs)
    except SystemExit:
        pass
    else:
        fail("self-test accepted the whole inputs context")
    whole_secrets = copy.deepcopy(valid)
    whole_secrets["jobs"]["build"]["steps"][0]["env"] = {
        "SAFE_NAME": "${{ toJSON(secrets) }}"
    }
    try:
        validate(whole_secrets)
    except SystemExit:
        pass
    else:
        fail("self-test accepted the whole secrets context")
    whole_github = copy.deepcopy(valid)
    whole_github["jobs"]["build"]["steps"][0]["env"] = {
        "SAFE_NAME": "${{ toJSON(github) }}"
    }
    try:
        validate(whole_github)
    except SystemExit:
        pass
    else:
        fail("self-test accepted the whole github context")
    bytecode_enabled = copy.deepcopy(valid)
    validation = named_step(
        bytecode_enabled["jobs"]["build"]["steps"],
        "Validate workflow and lifecycle boundaries",
    )
    validation["env"] = {}
    try:
        validate(bytecode_enabled)
    except SystemExit:
        pass
    else:
        fail("self-test accepted workflow validation with Python bytecode enabled")
    missing_cache_gate = copy.deepcopy(valid)
    validation = named_step(
        missing_cache_gate["jobs"]["build"]["steps"],
        "Validate workflow and lifecycle boundaries",
    )
    validation["run"] = validation["run"].replace("__pycache__", "ignored-cache")
    try:
        validate(missing_cache_gate)
    except SystemExit:
        pass
    else:
        fail("self-test accepted workflow validation without a cache-residue gate")
    late_dependencies = copy.deepcopy(valid)
    late_steps = late_dependencies["jobs"]["build"]["steps"]
    dependency_index = late_steps.index(named_step(late_steps, "Install dependencies"))
    validation_index = late_steps.index(
        named_step(late_steps, "Validate workflow and lifecycle boundaries")
    )
    late_steps[dependency_index], late_steps[validation_index] = (
        late_steps[validation_index],
        late_steps[dependency_index],
    )
    try:
        validate(late_dependencies)
    except SystemExit:
        pass
    else:
        fail("self-test accepted validation before dependency installation")
    wrong_runner = copy.deepcopy(valid)
    wrong_runner["jobs"]["build"]["runs-on"] = "ubuntu-24.04-arm"
    try:
        validate(wrong_runner)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a non-canonical build runner")
    missing_toolchain_input = copy.deepcopy(valid)
    del missing_toolchain_input["on"]["workflow_dispatch"]["inputs"][
        "kernel_toolchain_manifest"
    ]
    try:
        validate(missing_toolchain_input)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a missing toolchain-manifest input")
    missing_errexit = copy.deepcopy(valid)
    stage = named_step(missing_errexit["jobs"]["build"]["steps"], "Stage release assets")
    stage["run"] = stage["run"].replace("set -euo pipefail\n", "", 1)
    try:
        validate(missing_errexit)
    except SystemExit:
        pass
    else:
        fail("self-test accepted release staging without fail-fast shell mode")
    unreviewed_package_lock = copy.deepcopy(valid)
    dependency_step = named_step(
        unreviewed_package_lock["jobs"]["build"]["steps"], "Install dependencies"
    )
    dependency_step["run"] = dependency_step["run"].replace(
        "HAPTICS-BUILD-PACKAGES.tsv", "UNREVIEWED-PACKAGES.tsv"
    )
    try:
        validate(unreviewed_package_lock)
    except SystemExit:
        pass
    else:
        fail("self-test accepted an unreviewed package lock")
    extra_apt_command = copy.deepcopy(valid)
    dependency_step = named_step(
        extra_apt_command["jobs"]["build"]["steps"], "Install dependencies"
    )
    dependency_step["run"] += "\nsudo apt-get install unreviewed-package"
    try:
        validate(extra_apt_command)
    except SystemExit:
        pass
    else:
        fail("self-test accepted an extra dependency-install command")
    extra_install_step = copy.deepcopy(valid)
    extra_install_step["jobs"]["build"]["steps"].insert(
        2,
        {
            "name": "Install an unreviewed package",
            "run": "sudo apt-get install unreviewed-package",
        },
    )
    try:
        validate(extra_install_step)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a separate unreviewed dependency-install step")
    appended_install = copy.deepcopy(valid)
    validation = named_step(
        appended_install["jobs"]["build"]["steps"],
        "Validate workflow and lifecycle boundaries",
    )
    validation["run"] += "\nsudo apt-get -y install unreviewed-package"
    try:
        validate(appended_install)
    except SystemExit:
        pass
    else:
        fail("self-test accepted package installation in a non-dependency step")
    wrong_stage_entry = copy.deepcopy(valid)
    stage = named_step(wrong_stage_entry["jobs"]["build"]["steps"], "Stage release assets")
    stage["run"] = stage["run"].replace(
        "scripts/ci/stage-haptics-release-assets.sh", "scripts/ci/unreviewed-stage.sh"
    )
    try:
        validate(wrong_stage_entry)
    except SystemExit:
        pass
    else:
        fail("self-test accepted an unreviewed staging entry point")
    unreachable_gate = copy.deepcopy(valid)
    stage = named_step(unreachable_gate["jobs"]["build"]["steps"], "Stage release assets")
    stage["run"] += "\nif false; then bash scripts/ci/verify-haptics-publication-stage.sh; fi"
    try:
        validate(unreachable_gate)
    except SystemExit:
        pass
    else:
        fail("self-test accepted unreachable text appended to release staging")
    for label, guard in (
        ("unguarded", None),
        ("release-guarded", RELEASE_GUARD),
        ("diagnostic-guarded", DIAGNOSTIC_GUARD),
    ):
        extra_upload = copy.deepcopy(valid)
        hostile_step = {
            "name": f"Unexpected {label} artifact upload",
            "uses": UPLOAD,
            "with": {
                "name": f"unexpected-{label}",
                "path": "out/tb321fu-haptics-debs/*",
                "if-no-files-found": "error",
            },
        }
        if guard is not None:
            hostile_step["if"] = guard
        extra_upload["jobs"]["build"]["steps"].append(hostile_step)
        try:
            validate(extra_upload)
        except SystemExit:
            pass
        else:
            fail(f"self-test accepted an extra {label} artifact upload")
    unexpected_publish_job = copy.deepcopy(valid)
    unexpected_publish_job["jobs"]["publish"] = {
        "runs-on": CANONICAL_RUNNER,
        "permissions": {"contents": "write"},
        "steps": [{"name": "Publish", "run": "true"}],
    }
    try:
        validate(unexpected_publish_job)
    except SystemExit:
        pass
    else:
        fail("self-test accepted an Actions publication job")
    write_permission = copy.deepcopy(valid)
    write_permission["jobs"]["build"]["permissions"] = {"contents": "write"}
    try:
        validate(write_permission)
    except SystemExit:
        pass
    else:
        fail("self-test accepted contents: write")
    mutable_checkout = copy.deepcopy(valid)
    checkout = named_step(mutable_checkout["jobs"]["build"]["steps"], "Checkout")
    checkout["with"]["persist-credentials"] = True
    try:
        validate(mutable_checkout)
    except SystemExit:
        pass
    else:
        fail("self-test accepted persisted checkout credentials")
    real_workflow = pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/build.yml"
    real_source = read_workflow_source(real_workflow)
    if real_source.count("\non:\n") != 1:
        fail("self-test real workflow trigger anchor changed")
    assert_cli_rejects_invalid_source(
        real_source.replace("\non:\n", "\n!!bool on:\n", 1).encode("utf-8"),
        "explicit boolean workflow trigger",
    )
    false_anchor = "        required: false\n"
    if real_source.count(false_anchor) != 1:
        fail("self-test real workflow boolean anchor changed")
    assert_cli_rejects_invalid_source(
        real_source.replace(
            false_anchor,
            "        required: fal\u017fe\n",
            1,
        ).encode("utf-8"),
        "Unicode-folded workflow boolean",
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
    print("haptics release job isolation self-test: PASS")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) != 2:
        fail("usage: test-haptics-release-job-isolation.py WORKFLOW|--self-test")
    source = read_workflow_source(pathlib.Path(sys.argv[1]))
    data = load_workflow_yaml(source)
    validate(mapping(data, sys.argv[1]))
    print("HAPTICS_RELEASE_JOB_ISOLATION=PASS")


if __name__ == "__main__":
    main()
