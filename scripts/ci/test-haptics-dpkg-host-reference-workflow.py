#!/usr/bin/env python3
"""Validate the non-release GitHub runner dpkg host-reference diagnostic."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
WORKFLOW = ROOT / ".github/workflows/capture-dpkg-host-reference.yml"
ISOLATION_TEST = SCRIPT_DIR / "test-haptics-release-job-isolation.py"
CHECKOUT = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
CAPTURE_RUN = "\n".join(
    (
        "set -euo pipefail",
        'reference=\"$RUNNER_TEMP/HAPTICS-DPKG-HOST-REFERENCE.tsv\"',
        'checksum=\"$RUNNER_TEMP/HAPTICS-DPKG-HOST-REFERENCE.sha256\"',
        "sudo python3 -I -B scripts/ci/verify-haptics-dpkg-state.py \\",
        "  --capture-host-reference /var/lib/dpkg 0 0 > \"$reference\"",
        "chmod 0600 \"$reference\"",
        "sudo chown 0:0 \"$reference\"",
        "sudo python3 -I -B scripts/ci/verify-haptics-dpkg-state.py \\",
        "  --verify-host-reference /var/lib/dpkg 0 0 \"$reference\"",
        "sudo chown \"$(id -u):$(id -g)\" \"$reference\"",
        "sha256sum -- \"$reference\" | \\",
        "  sed 's#  .*#  HAPTICS-DPKG-HOST-REFERENCE.tsv#' > \"$checksum\"",
        "chmod 0600 \"$checksum\"",
        "sha256sum -c -- \"$checksum\"",
    )
) + "\n"


def fail(message: str) -> None:
    raise SystemExit(f"dpkg host-reference workflow check failed: {message}")


def load_yaml(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(
        "haptics_release_isolation_loader", ISOLATION_TEST
    )
    if spec is None or spec.loader is None:
        fail("cannot load the strict workflow YAML loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    try:
        return module.yaml.load(path.read_text(encoding="utf-8"), Loader=module.WorkflowLoader)
    except (OSError, module.yaml.YAMLError) as exc:
        fail(f"cannot parse workflow: {exc}")


def main() -> None:
    if not WORKFLOW.is_file():
        fail("diagnostic workflow is missing")
    data = load_yaml(WORKFLOW)
    if set(data) != {"name", "on", "permissions", "jobs"}:
        fail("top-level schema is not exact")
    if data["name"] != "Capture Haptics Dpkg Host Reference":
        fail("workflow name differs")
    if data["on"] != {"workflow_dispatch": None}:
        fail("workflow must be manual-only with no inputs")
    if data["permissions"] != {"contents": "read"}:
        fail("workflow permissions are not read-only")
    if set(data["jobs"]) != {"capture"}:
        fail("workflow must contain one capture job")
    job = data["jobs"]["capture"]
    if set(job) != {"runs-on", "permissions", "timeout-minutes", "steps"}:
        fail("capture job schema is not exact")
    if (
        job["runs-on"] != "ubuntu-24.04"
        or job["permissions"] != {"contents": "read"}
        or job["timeout-minutes"] != 10
    ):
        fail("capture runner, timeout or permissions differ")
    steps = job["steps"]
    if len(steps) != 3 or [step.get("name") for step in steps] != [
        "Checkout",
        "Capture and verify host reference",
        "Upload diagnostic reference",
    ]:
        fail("capture steps are not exact")
    checkout, capture, upload = steps
    if checkout != {
        "name": "Checkout",
        "uses": CHECKOUT,
        "with": {"persist-credentials": False, "fetch-depth": 1},
    }:
        fail("checkout is not pinned and credential-free")
    if capture != {
        "name": "Capture and verify host reference",
        "env": {"PYTHONDONTWRITEBYTECODE": "1"},
        "run": CAPTURE_RUN,
    }:
        fail("capture command differs from the reviewed scalar")
    if upload != {
        "name": "Upload diagnostic reference",
        "uses": UPLOAD,
        "with": {
            "name": "haptics-dpkg-host-reference",
            "path": "${{ runner.temp }}/HAPTICS-DPKG-HOST-REFERENCE.*",
            "if-no-files-found": "error",
            "retention-days": 7,
            "compression-level": 0,
        },
    }:
        fail("diagnostic upload is not exact")
    if re.search(
        r"(?:contents:\s*write|GITHUB_TOKEN|secrets\.|\bgh\b|\brelease\b|\btag\b|apt-get|dpkg\s+--(?:install|unpack|configure))",
        WORKFLOW.read_text(encoding="utf-8"),
        re.IGNORECASE,
    ):
        fail("workflow contains a release, credential or package-mutation path")
    print("HAPTICS_DPKG_HOST_REFERENCE_WORKFLOW=PASS")


if __name__ == "__main__":
    main()
