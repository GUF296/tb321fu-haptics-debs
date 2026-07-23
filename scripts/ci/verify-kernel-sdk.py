#!/usr/bin/env python3
"""Verify a closed-world TB321FU Kbuild SDK archive and its manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import stat
import sys
import tarfile
from dataclasses import dataclass
from pathlib import PurePosixPath


MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 200_000
MAX_ARCHIVE_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000
SCHEMA = "tb321fu.kernel-sdk-manifest/v1"
REQUIRED_FILES = (
    "./.config",
    "./Module.symvers",
    "./include/config/kernel.release",
    "./include/generated/autoconf.h",
    "./include/generated/utsrelease.h",
)


class SDKError(ValueError):
    """Raised when an SDK archive violates the release contract."""


@dataclass(frozen=True)
class ManifestRecord:
    kind: str
    digest: str
    mode: int
    path: str


def canonical_path(value: str, *, label: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise SDKError(f"unsafe {label} path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or (path.parts and ":" in path.parts[0]):
        raise SDKError(f"unsafe absolute {label} path: {value!r}")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if ".." in parts:
        raise SDKError(f"unsafe parent traversal in {label} path: {value!r}")
    if not parts:
        raise SDKError(f"empty {label} path")
    return "./" + "/".join(parts)


def root_source_path(path: str) -> bool:
    return path == "./source" or path.startswith("./source/")


def parse_manifest(path: pathlib.Path) -> dict[str, ManifestRecord]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SDKError(f"cannot read SDK manifest {path}: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise SDKError(f"SDK manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    if not raw.endswith(b"\n"):
        raise SDKError("SDK manifest must end with LF")
    if b"\r" in raw or b"\0" in raw:
        raise SDKError("SDK manifest contains CR or NUL")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SDKError("SDK manifest must be ASCII") from exc

    lines = text.splitlines()
    if not lines or lines[0] != f"schema\t{SCHEMA}":
        raise SDKError(f"SDK manifest first record must be schema\\t{SCHEMA}")

    records: dict[str, ManifestRecord] = {}
    previous_path: str | None = None
    for number, line in enumerate(lines[1:], start=2):
        if line.count("\t") != 3:
            raise SDKError(f"SDK manifest record {number} must contain exactly four fields")
        kind, digest, mode_text, raw_path = line.split("\t")
        if kind not in {"file", "symlink"}:
            raise SDKError(f"SDK manifest record {number} has unsupported type: {kind!r}")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise SDKError(f"SDK manifest record {number} has invalid SHA-256")
        if len(mode_text) not in (3, 4) or any(character not in "01234567" for character in mode_text):
            raise SDKError(f"SDK manifest record {number} has invalid mode")
        if mode_text.startswith("0"):
            raise SDKError(f"SDK manifest record {number} mode must not have a leading zero")
        if not raw_path.startswith("./"):
            raise SDKError(f"SDK manifest record {number} path must begin with ./")
        record_path = canonical_path(raw_path, label="SDK manifest")
        if record_path != raw_path:
            raise SDKError(f"SDK manifest record {number} path is not canonical")
        if root_source_path(record_path):
            raise SDKError("SDK manifest must not describe ./source")
        if previous_path is not None and record_path <= previous_path:
            raise SDKError("SDK manifest records must be strictly sorted by path")
        previous_path = record_path
        if record_path in records:
            raise SDKError(f"SDK manifest has duplicate path: {record_path}")
        records[record_path] = ManifestRecord(kind, digest, int(mode_text, 8), record_path)

    for required in REQUIRED_FILES:
        record = records.get(required)
        if record is None or record.kind != "file":
            raise SDKError(f"SDK manifest is missing required regular file: {required}")
    return records


def digest_stream(source) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def digest_link_target(target: str, *, label: str) -> str:
    try:
        encoded = target.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SDKError(f"{label} symlink target is not UTF-8") from exc
    return hashlib.sha256(encoded).hexdigest()


def resolve_contained_symlink(path: str, target: str) -> str | None:
    if not target or "\x00" in target or "\\" in target:
        return None
    parsed = PurePosixPath(target)
    if parsed.is_absolute() or (parsed.parts and ":" in parsed.parts[0]):
        return None
    stack = list(PurePosixPath(path[2:]).parent.parts)
    for part in parsed.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return None
            stack.pop()
        else:
            stack.append(part)
    return "./" + "/".join(stack) if stack else "."


def parent_paths(path: str) -> set[str]:
    parts = PurePosixPath(path[2:]).parts
    return {"./" + "/".join(parts[:depth]) for depth in range(1, len(parts))}


def validate_archive_namespace(
    member_kinds: dict[str, str],
    records: dict[str, ManifestRecord],
    link_targets: dict[str, str],
) -> None:
    structural_directories: set[str] = set()
    for path in records:
        structural_directories.update(parent_paths(path))
    known_directories = structural_directories | {
        path for path, kind in member_kinds.items() if kind == "directory"
    }

    for path, kind in member_kinds.items():
        if kind == "directory":
            # The producer intentionally omits directories from the manifest.
            # Its deterministic tar stream includes empty Kbuild directories,
            # so directory metadata is structural rather than payload.
            continue
        for parent in parent_paths(path):
            parent_kind = member_kinds.get(parent)
            if parent_kind is not None and parent_kind != "directory":
                raise SDKError(
                    f"SDK archive member has a non-directory parent: {path} via {parent}"
                )

    for path, target in link_targets.items():
        resolved = resolve_contained_symlink(path, target)
        if resolved is None:
            raise SDKError(
                f"SDK archive symlink escapes the direct root: {path} -> {target!r}"
            )
        seen = {path}
        while True:
            if resolved == ".":
                break
            if resolved in known_directories:
                break
            record = records.get(resolved)
            if record is None:
                raise SDKError(
                    f"SDK archive symlink has a dangling target: {path} -> {target!r}"
                )
            if record.kind == "file":
                break
            if resolved in seen:
                raise SDKError(f"SDK archive has a symlink cycle through: {resolved}")
            seen.add(resolved)
            resolved = resolve_contained_symlink(resolved, link_targets[resolved])
            if resolved is None:
                raise SDKError(f"SDK archive symlink chain escapes the direct root: {path}")


def archive_records(archive: pathlib.Path) -> dict[str, ManifestRecord]:
    try:
        handle = tarfile.open(archive, mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise SDKError(f"cannot read SDK archive {archive}: {exc}") from exc

    with handle:
        records: dict[str, ManifestRecord] = {}
        candidates: set[str] = set()
        member_kinds: dict[str, str] = {}
        link_targets: dict[str, str] = {}
        total_bytes = 0
        member_count = 0
        for member in handle:
            member_count += 1
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise SDKError(f"SDK archive has too many members: {member_count}")
            if member.name in ("", ".", "./"):
                if member.isdir():
                    continue
                raise SDKError("SDK archive root must be a directory")
            if not member.name.startswith("./"):
                raise SDKError(f"SDK archive member must begin with ./: {member.name!r}")
            member_path = canonical_path(member.name, label="SDK archive")
            if member_path in candidates:
                raise SDKError(f"SDK archive has duplicate member: {member_path}")
            candidates.add(member_path)
            if root_source_path(member_path):
                raise SDKError("SDK archive must not contain ./source")
            if member.islnk() or member.ischr() or member.isblk() or member.isfifo() or member.isdev():
                raise SDKError(f"SDK archive has unsupported member type: {member_path}")
            if member.isdir():
                member_kinds[member_path] = "directory"
                continue
            if member_path != member.name:
                raise SDKError(f"SDK archive member path is not canonical: {member.name!r}")
            if member.isreg():
                if member.size < 0 or member.size > MAX_ARCHIVE_FILE_BYTES:
                    raise SDKError(f"SDK archive member exceeds size limit: {member_path}")
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                    raise SDKError("SDK archive expands beyond the total size limit")
                source = handle.extractfile(member)
                if source is None:
                    raise SDKError(f"cannot read SDK archive member: {member_path}")
                with source:
                    digest = digest_stream(source)
                kind = "file"
            elif member.issym():
                digest = digest_link_target(member.linkname, label="SDK archive")
                kind = "symlink"
                link_targets[member_path] = member.linkname
            else:
                raise SDKError(f"SDK archive has unsupported member type: {member_path}")
            records[member_path] = ManifestRecord(kind, digest, member.mode & 0o7777, member_path)
            member_kinds[member_path] = kind
        archive_bytes = archive.stat().st_size
        if total_bytes and archive_bytes == 0:
            raise SDKError("non-empty SDK archive has zero compressed bytes")
        if archive_bytes and total_bytes > archive_bytes * MAX_COMPRESSION_RATIO:
            raise SDKError("SDK archive compression ratio exceeds the safety limit")
        validate_archive_namespace(member_kinds, records, link_targets)
    return records


def direct_root_candidates(records: dict[str, ManifestRecord]) -> set[str]:
    paths = set(records)
    candidates: set[str] = set()
    for path in paths:
        parts = path[2:].split("/")
        for depth in range(len(parts)):
            prefix = parts[:depth]
            candidate = "./" + "/".join(prefix) if prefix else "."
            required = {
                "./" + "/".join((*prefix, required_path[2:]))
                for required_path in REQUIRED_FILES
            }
            if required <= paths:
                candidates.add(candidate)
    return candidates


def extracted_records(root: pathlib.Path) -> dict[str, ManifestRecord]:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise SDKError(f"cannot stat extracted SDK root {root}: {exc}") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise SDKError("extracted SDK root must be a real directory")

    records: dict[str, ManifestRecord] = {}
    for directory, names, files in os.walk(root, followlinks=False):
        current = pathlib.Path(directory)
        for name in sorted(names):
            candidate = current / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                names.remove(name)
                path = canonical_path(candidate.relative_to(root).as_posix(), label="extracted SDK")
                if root_source_path(path):
                    raise SDKError("extracted SDK must not contain ./source")
                target = os.readlink(candidate)
                if resolve_contained_symlink(path, target) is None:
                    raise SDKError(
                        f"extracted SDK symlink escapes the direct root: {path} -> {target!r}"
                    )
                records[path] = ManifestRecord(
                    "symlink", digest_link_target(target, label="extracted SDK"), mode & 0o7777, path
                )
            elif not stat.S_ISDIR(mode):
                raise SDKError(f"extracted SDK has unsupported directory entry: {candidate}")
        for name in sorted(files):
            candidate = current / name
            mode = candidate.lstat().st_mode
            path = canonical_path(candidate.relative_to(root).as_posix(), label="extracted SDK")
            if root_source_path(path):
                raise SDKError("extracted SDK must not contain ./source")
            if stat.S_ISLNK(mode):
                target = os.readlink(candidate)
                if resolve_contained_symlink(path, target) is None:
                    raise SDKError(
                        f"extracted SDK symlink escapes the direct root: {path} -> {target!r}"
                    )
                records[path] = ManifestRecord(
                    "symlink", digest_link_target(target, label="extracted SDK"), mode & 0o7777, path
                )
            elif stat.S_ISREG(mode):
                with candidate.open("rb") as source:
                    digest = digest_stream(source)
                records[path] = ManifestRecord("file", digest, mode & 0o7777, path)
            else:
                raise SDKError(f"extracted SDK has unsupported member type: {path}")
    return records


def require_identical_records(
    expected: dict[str, ManifestRecord], actual: dict[str, ManifestRecord], *, label: str
) -> None:
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing or extra:
        raise SDKError(f"{label} paths differ from SDK manifest: missing={missing!r} extra={extra!r}")
    for path, expected_record in expected.items():
        actual_record = actual[path]
        if actual_record != expected_record:
            raise SDKError(
                f"{label} record differs from SDK manifest: {path} "
                f"expected={expected_record.kind}:{expected_record.digest}:{expected_record.mode:o} "
                f"actual={actual_record.kind}:{actual_record.digest}:{actual_record.mode:o}"
            )


def verify_archive(archive: pathlib.Path, manifest: pathlib.Path) -> dict[str, ManifestRecord]:
    expected = parse_manifest(manifest)
    archived = archive_records(archive)
    roots = direct_root_candidates(archived)
    if roots != {"."}:
        raise SDKError(f"SDK archive must have exactly one direct Kbuild root, found {sorted(roots)!r}")
    require_identical_records(expected, archived, label="SDK archive")
    return expected


def verify(archive: pathlib.Path, manifest: pathlib.Path, extracted: pathlib.Path) -> None:
    expected = verify_archive(archive, manifest)
    require_identical_records(expected, extracted_records(extracted), label="extracted SDK")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a direct-root TB321FU Kbuild SDK archive against its external manifest."
    )
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("extracted_root", nargs="?", type=pathlib.Path)
    parser.add_argument(
        "--archive-only",
        action="store_true",
        help="verify the archive and manifest before extraction",
    )
    args = parser.parse_args()
    try:
        if args.archive_only:
            if args.extracted_root is not None:
                raise SDKError("--archive-only does not accept an extracted SDK root")
            verify_archive(args.archive, args.manifest)
        elif args.extracted_root is None:
            raise SDKError("an extracted SDK root is required without --archive-only")
        else:
            verify(args.archive, args.manifest, args.extracted_root)
    except SDKError as exc:
        print(f"kernel SDK verification failed: {exc}", file=sys.stderr)
        return 1
    print("KERNEL_SDK=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
