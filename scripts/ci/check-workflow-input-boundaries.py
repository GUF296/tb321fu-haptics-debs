#!/usr/bin/env python3
"""Reject GitHub input expressions embedded directly in workflow shell blocks."""

from __future__ import annotations

import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"workflow input boundary check failed: {message}")


def direct_input_lines(lines: list[str]) -> list[int]:
    direct_inputs: list[int] = []

    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*[|>]", line)
        if not match:
            index += 1
            continue

        block_indent = len(match.group(1))
        index += 1
        while index < len(lines):
            body = lines[index]
            if body.strip() and len(body) - len(body.lstrip()) <= block_indent:
                break
            if "${{ inputs." in body:
                direct_inputs.append(index + 1)
            index += 1
    return direct_inputs


def self_test() -> None:
    safe = [
        "jobs:",
        "  build:",
        "    env:",
        "      INPUT_VALUE: ${{ inputs.value }}",
        "    run: |",
        '      printf "%s\\n" "$INPUT_VALUE"',
    ]
    unsafe = ["jobs:", "  build:", "    run: |", "      echo '${{ inputs.value }}'"]
    if direct_input_lines(safe):
        fail("self-test rejected an env-mediated input")
    if direct_input_lines(unsafe) != [4]:
        fail("self-test did not detect a direct input expression")
    print("workflow input boundary self-test: PASS")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) != 2:
        fail("usage: check-workflow-input-boundaries.py WORKFLOW|--self-test")

    workflow = pathlib.Path(sys.argv[1])
    lines = workflow.read_text(encoding="utf-8").splitlines()
    direct_inputs = direct_input_lines(lines)

    if direct_inputs:
        fail(f"direct input expression in run block at lines {direct_inputs}")

    text = "\n".join(lines)
    required = (
        "INPUT_RELEASE_TAG: ${{ inputs.release_tag }}",
        "INPUT_HAPTICS_DEB_VERSION: ${{ inputs.haptics_deb_version }}",
        "INPUT_KERNEL_SOURCE_COMMIT: ${{ inputs.kernel_source_commit }}",
        "INPUT_KERNEL_BUILD_ARCHIVE: ${{ inputs.kernel_build_archive }}",
        "INPUT_KERNEL_BUILD_ARCHIVE_SHA256: ${{ inputs.kernel_build_archive_sha256 }}",
        "INPUT_KERNEL_BUNDLE_METADATA: ${{ inputs.kernel_bundle_metadata }}",
        "INPUT_KERNEL_BUNDLE_METADATA_SHA256: ${{ inputs.kernel_bundle_metadata_sha256 }}",
        '[[ "$INPUT_HAPTICS_DEB_VERSION" =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]]',
        'dpkg --validate-version "$INPUT_HAPTICS_DEB_VERSION"',
        '[[ "$INPUT_KERNEL_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$INPUT_KERNEL_BUILD_ARCHIVE" =~ ^https://[^[:space:]]{1,2048}$ ]]',
        '[[ "$INPUT_KERNEL_BUILD_ARCHIVE_SHA256" =~ ^[0-9A-Fa-f]{64}$ ]]',
        '[[ "$INPUT_KERNEL_BUNDLE_METADATA" =~ ^https://[^[:space:]]{1,2048}$ ]]',
        '[[ "$INPUT_KERNEL_BUNDLE_METADATA_SHA256" =~ ^[0-9A-Fa-f]{64}$ ]]',
        'if [ -n "$INPUT_RELEASE_TAG" ] && [ -z "$INPUT_KERNEL_BUNDLE_METADATA" ]; then',
        "printf 'HAPTICS_DEB_VERSION=%s\\n' \"$INPUT_HAPTICS_DEB_VERSION\"",
        "printf 'KERNEL_SOURCE_COMMIT=%s\\n' \"$INPUT_KERNEL_SOURCE_COMMIT\"",
        "printf 'KERNEL_BUILD_ARCHIVE_SHA256=%s\\n' \"${INPUT_KERNEL_BUILD_ARCHIVE_SHA256,,}\"",
        "printf 'KERNEL_BUNDLE_METADATA_SHA256=%s\\n' \"${INPUT_KERNEL_BUNDLE_METADATA_SHA256,,}\"",
    )
    for token in required:
        if token not in text:
            fail(f"missing required boundary token: {token}")

    print("workflow input boundary check: PASS")


if __name__ == "__main__":
    main()
