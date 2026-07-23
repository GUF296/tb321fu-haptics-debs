#!/usr/bin/env python3
"""Keep haptics package construction separate from release publication."""

from __future__ import annotations

import copy
import pathlib
import re
import sys

import yaml


class WorkflowLoader(yaml.SafeLoader):
    pass


for first, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
    WorkflowLoader.yaml_implicit_resolvers[first] = [
        item for item in resolvers if item[0] != "tag:yaml.org,2002:bool"
    ]


CHECKOUT = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
ARTIFACT = "release-staging-" + "$" + "{{ github.run_id }}-" + "$" + "{{ github.run_attempt }}"
RELEASE_GUARD = "$" + "{{ inputs.release_tag != '' }}"
EXACT_SHA = "$" + "{{ github.sha }}"
GITHUB_TOKEN = "$" + "{{ github.token }}"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"haptics release job isolation check failed: {message}")


def mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return value


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


def require_pinned_action(step: dict, expected: str, label: str) -> None:
    if step.get("uses") != expected or not PINNED_ACTION.fullmatch(expected):
        fail(f"{label} must use the pinned action {expected}")


def require_release_guard(value: dict, label: str) -> None:
    if value.get("if") != RELEASE_GUARD:
        fail(f"{label} must be guarded by a non-empty release tag")


def validate(data: dict) -> None:
    jobs = mapping(data.get("jobs"), "jobs")
    build = mapping(jobs.get("build"), "jobs.build")
    publish = mapping(jobs.get("publish"), "jobs.publish")
    if build.get("permissions") != {"contents": "read"}:
        fail("build job must retain only contents: read")
    build_text = "\n".join(scalar_text(build))
    if any(token in build_text for token in ("RELEASE_TOKEN", "GH_TOKEN", "github.token")):
        fail("build job references a release credential")
    if "publish-release.sh" in build_text:
        fail("build job invokes the release publisher")

    build_steps = steps_for(build, "jobs.build")
    staging = named_step(build_steps, "Stage release assets")
    require_release_guard(staging, "release asset staging")
    staging_run = staging.get("run")
    if not isinstance(staging_run, str):
        fail("release asset staging must have a shell body")
    for token in (
        "release_stage=out/tb321fu-haptics-release/release-staging",
        'release_dir="$release_stage/assets"',
        'notes="$release_dir/BUILD-PARAMETERS.md"',
        'echo "- Kernel bundle metadata: $KERNEL_BUNDLE_METADATA"',
        'echo "- Kernel bundle metadata SHA-256: $KERNEL_BUNDLE_METADATA_SHA256"',
        'echo "- Kernel SDK manifest: $KERNEL_SDK_MANIFEST"',
        "BUILD-PARAMETERS.md > SHA256SUMS.txt",
        "SHA256SUMS.txt",
    ):
        if token not in staging_run:
            fail(f"release asset staging is missing {token!r}")
    upload = named_step(build_steps, "Upload staged release payload")
    require_release_guard(upload, "staged release artifact upload")
    if build_steps.index(staging) >= build_steps.index(upload):
        fail("release staging must precede artifact upload")
    require_pinned_action(upload, UPLOAD, "staged release artifact upload")
    if mapping(upload.get("with"), "staged release artifact upload.with") != {
        "name": ARTIFACT,
        "path": "out/tb321fu-haptics-release/release-staging",
        "if-no-files-found": "error",
    }:
        fail("staged release artifact must be the closed staging directory")

    require_release_guard(publish, "publish job")
    if publish.get("needs") != "build" or publish.get("permissions") != {"contents": "write"}:
        fail("publish job must depend on build and have only contents: write")
    publish_job_env = publish.get("env")
    if publish_job_env is not None:
        publish_job_env_text = "\n".join(
            scalar_text(mapping(publish_job_env, "jobs.publish.env"))
        )
        if (
            "RELEASE_TOKEN" in publish_job_env_text
            or "GH_TOKEN" in publish_job_env_text
            or "github.token" in publish_job_env_text
        ):
            fail("publish job-level environment exposes a release credential")
    publish_steps = steps_for(publish, "jobs.publish")
    checkout = named_step(publish_steps, "Checkout exact release source")
    require_pinned_action(checkout, CHECKOUT, "publish checkout")
    checkout_with = mapping(checkout.get("with"), "publish checkout.with")
    if checkout_with.get("ref") != EXACT_SHA or str(
        checkout_with.get("persist-credentials", "")
    ).lower() != "false":
        fail("publish checkout must use the exact workflow commit without persisted credentials")
    download = named_step(publish_steps, "Download staged release payload")
    require_pinned_action(download, DOWNLOAD, "staged release artifact download")
    if mapping(download.get("with"), "staged release artifact download.with") != {
        "name": ARTIFACT,
        "path": "release-staging",
    }:
        fail("publish job must download only its exact staging artifact")
    publisher = named_step(publish_steps, "Publish immutable prerelease")
    if publisher is not publish_steps[-1] or publish_steps.index(download) >= publish_steps.index(publisher):
        fail("publisher must be the final step after staging download")
    if mapping(publisher.get("env"), "publisher env") != {
        "GH_TOKEN": GITHUB_TOKEN,
        "RELEASE_TAG": "$" + "{{ inputs.release_tag }}",
        "PRERELEASE": "$" + "{{ inputs.prerelease && '1' || '0' }}",
    }:
        fail("only the final publisher may receive github.token")
    publisher_run = publisher.get("run")
    if not isinstance(publisher_run, str):
        fail("publisher must have a shell body")
    for token in (
        '[ "$(git rev-parse HEAD)" = "$GITHUB_SHA" ]',
        "release_dir=release-staging/assets",
        "notes=release-staging/assets/BUILD-PARAMETERS.md",
        'bash scripts/ci/publish-release.sh "$RELEASE_TAG" "$release_dir" "$notes"',
    ):
        if token not in publisher_run:
            fail(f"publisher is missing {token!r}")
    for step in publish_steps:
        uses = step.get("uses")
        if uses is not None and uses not in (CHECKOUT, DOWNLOAD):
            fail("publish job must not invoke another action")
        if step is not publisher and "GH_TOKEN" in "\n".join(scalar_text(step)):
            fail("only the final publisher may reference GH_TOKEN")
        run = step.get("run")
        if isinstance(run, str) and re.search(r"\b(?:sudo|chroot|apt-get)\b", run):
            fail("publish job must not enter a privileged build environment")


def fixture() -> dict:
    return {
        "jobs": {
            "build": {
                "permissions": {"contents": "read"},
                "steps": [
                    {
                        "name": "Stage release assets",
                        "if": RELEASE_GUARD,
                        "run": "\n".join((
                            "release_stage=out/tb321fu-haptics-release/release-staging",
                            'release_dir="$release_stage/assets"',
                            'notes="$release_dir/BUILD-PARAMETERS.md"',
                            'echo "- Kernel bundle metadata: $KERNEL_BUNDLE_METADATA"',
                            'echo "- Kernel bundle metadata SHA-256: $KERNEL_BUNDLE_METADATA_SHA256"',
                            'echo "- Kernel SDK manifest: $KERNEL_SDK_MANIFEST"',
                            "BUILD-PARAMETERS.md > SHA256SUMS.txt",
                            "SHA256SUMS.txt",
                        )),
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
            "publish": {
                "if": RELEASE_GUARD,
                "needs": "build",
                "permissions": {"contents": "write"},
                "steps": [
                    {
                        "name": "Checkout exact release source",
                        "uses": CHECKOUT,
                        "with": {"ref": EXACT_SHA, "persist-credentials": False},
                    },
                    {
                        "name": "Download staged release payload",
                        "uses": DOWNLOAD,
                        "with": {"name": ARTIFACT, "path": "release-staging"},
                    },
                    {
                        "name": "Publish immutable prerelease",
                        "env": {
                            "GH_TOKEN": GITHUB_TOKEN,
                            "RELEASE_TAG": "$" + "{{ inputs.release_tag }}",
                            "PRERELEASE": "$" + "{{ inputs.prerelease && '1' || '0' }}",
                        },
                        "run": "\n".join((
                            '[ "$(git rev-parse HEAD)" = "$GITHUB_SHA" ]',
                            "release_dir=release-staging/assets",
                            "notes=release-staging/assets/BUILD-PARAMETERS.md",
                            'bash scripts/ci/publish-release.sh "$RELEASE_TAG" "$release_dir" "$notes"',
                        )),
                    },
                ],
            },
        }
    }


def self_test() -> None:
    valid = fixture()
    validate(valid)
    leaked_token = copy.deepcopy(valid)
    leaked_token["jobs"]["build"]["steps"][0]["env"] = {"GH_TOKEN": GITHUB_TOKEN}
    try:
        validate(leaked_token)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a build-job token")
    leaked_publish_job_token = copy.deepcopy(valid)
    leaked_publish_job_token["jobs"]["publish"]["env"] = {
        "GH_TOKEN": GITHUB_TOKEN
    }
    try:
        validate(leaked_publish_job_token)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a publish-job token")
    mutable_checkout = copy.deepcopy(valid)
    mutable_checkout["jobs"]["publish"]["steps"][0]["with"]["ref"] = "main"
    try:
        validate(mutable_checkout)
    except SystemExit:
        pass
    else:
        fail("self-test accepted a mutable publish checkout")
    unrelated_artifact = copy.deepcopy(valid)
    unrelated_artifact["jobs"]["publish"]["steps"][1]["with"]["name"] = "other"
    try:
        validate(unrelated_artifact)
    except SystemExit:
        pass
    else:
        fail("self-test accepted an unrelated artifact")
    print("haptics release job isolation self-test: PASS")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) != 2:
        fail("usage: test-haptics-release-job-isolation.py WORKFLOW|--self-test")
    try:
        data = yaml.load(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), Loader=WorkflowLoader)
    except yaml.YAMLError as exc:
        fail(f"invalid YAML: {exc}")
    validate(mapping(data, sys.argv[1]))
    print("HAPTICS_RELEASE_JOB_ISOLATION=PASS")


if __name__ == "__main__":
    main()
