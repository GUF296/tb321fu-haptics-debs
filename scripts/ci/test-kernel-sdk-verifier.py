#!/usr/bin/env python3
"""Hostile fixtures for the closed-world TB321FU kernel SDK verifier."""

from __future__ import annotations

import hashlib
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VERIFY = SCRIPT_DIR / "verify-kernel-sdk.py"
EXTRACT = SCRIPT_DIR / "safe-extract-archive.py"
REQUIRED = {
    "./.config": b"CONFIG_TB321FU=y\n",
    "./Module.symvers": b"0x00000000\tfixture\n",
    "./include/config/kernel.release": b"7.1.1-fixture\n",
    "./include/generated/autoconf.h": b"#define CONFIG_TB321FU 1\n",
    "./include/generated/utsrelease.h": b'#define UTS_RELEASE "7.1.1-fixture"\n',
}


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    archive.addfile(info)


def add_regular(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    archive.addfile(info, io.BytesIO(data))


def add_symlink(archive: tarfile.TarFile, name: str, target: str, mode: int = 0o777) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.mode = mode
    archive.addfile(info)


def manifest_records(
    prefix: str = "", *, include_link: bool = True, link_target: str = "autoconf.h"
) -> list[tuple[str, str, int, str]]:
    records = [
        ("file", hashlib.sha256(data).hexdigest(), 0o644, f"./{prefix}{path[2:]}")
        for path, data in REQUIRED.items()
    ]
    if include_link:
        records.append(
            (
                "symlink",
                hashlib.sha256(link_target.encode("utf-8")).hexdigest(),
                0o777,
                f"./{prefix}include/generated/autoconf-link",
            )
        )
    return sorted(records, key=lambda record: record[3])


def write_manifest(path: pathlib.Path, records: list[tuple[str, str, int, str]]) -> None:
    lines = ["schema\ttb321fu.kernel-sdk-manifest/v1"]
    lines.extend(f"{kind}\t{digest}\t{mode:o}\t{name}" for kind, digest, mode, name in records)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def write_archive(
    path: pathlib.Path,
    *,
    prefix: str = "",
    extra: bool = False,
    source: bool = False,
    duplicate_root: bool = False,
    noncanonical_member: bool = False,
    link_target: str = "autoconf.h",
) -> None:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        add_directory(archive, "./")
        for directory in ("include", "include/config", "include/generated"):
            add_directory(archive, f"./{prefix}{directory}")
        for name, data in REQUIRED.items():
            archive_name = f"./{prefix}{name[2:]}"
            if noncanonical_member and name == "./.config":
                archive_name = f"./{prefix}./.config"
            add_regular(archive, archive_name, data)
        add_symlink(archive, f"./{prefix}include/generated/autoconf-link", link_target)
        if extra:
            add_regular(archive, f"./{prefix}unexpected", b"unexpected\n")
        if source:
            add_symlink(archive, "./source", "include")
        if duplicate_root:
            for directory in ("duplicate", "duplicate/include", "duplicate/include/config", "duplicate/include/generated"):
                add_directory(archive, f"./{directory}")
            for name, data in REQUIRED.items():
                add_regular(archive, f"./duplicate/{name[2:]}", data)
            add_symlink(archive, "./duplicate/include/generated/autoconf-link", "autoconf.h")


def write_parent_symlink_archive(path: pathlib.Path) -> None:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        add_directory(archive, "./")
        add_directory(archive, "./other")
        add_symlink(archive, "./include", "other")
        for name, data in REQUIRED.items():
            add_regular(archive, name, data)
        add_symlink(archive, "./include/generated/autoconf-link", "autoconf.h")


def run(*arguments: pathlib.Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFY), *(str(argument) for argument in arguments)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def extract(archive: pathlib.Path, destination: pathlib.Path) -> None:
    result = subprocess.run(
        [sys.executable, str(EXTRACT), str(archive), str(destination)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise SystemExit(f"fixture extraction failed: {result.stderr}")


def require_rejected(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"unsafe SDK fixture was accepted: {label}")


def validate_fixture(root: pathlib.Path, archive: pathlib.Path, manifest: pathlib.Path) -> None:
    preflight = run(archive, manifest, "--archive-only")
    if preflight.returncode or preflight.stdout.strip() != "KERNEL_SDK=PASS":
        raise SystemExit(f"valid SDK archive-only fixture failed: {preflight.stderr}")
    extracted = root / "extract"
    extract(archive, extracted)
    result = run(archive, manifest, extracted)
    if result.returncode or result.stdout.strip() != "KERNEL_SDK=PASS":
        raise SystemExit(f"valid SDK fixture failed: {result.stderr}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-kernel-sdk-verifier.") as raw:
        root = pathlib.Path(raw)
        good_archive = root / "good.tar.gz"
        good_manifest = root / "good.tsv"
        write_archive(good_archive)
        write_manifest(good_manifest, manifest_records())
        validate_fixture(root / "good", good_archive, good_manifest)

        wrapped_archive = root / "wrapped.tar.gz"
        wrapped_manifest = root / "wrapped.tsv"
        write_archive(wrapped_archive, prefix="wrapper/")
        write_manifest(wrapped_manifest, manifest_records("wrapper/"))
        wrapped_extract = root / "wrapped-extract"
        extract(wrapped_archive, wrapped_extract)
        require_rejected(run(wrapped_archive, wrapped_manifest, wrapped_extract), "enclosing root")

        ambiguous_archive = root / "ambiguous.tar.gz"
        ambiguous_manifest = root / "ambiguous.tsv"
        write_archive(ambiguous_archive, duplicate_root=True)
        write_manifest(
            ambiguous_manifest,
            manifest_records() + manifest_records("duplicate/"),
        )
        ambiguous_extract = root / "ambiguous-extract"
        extract(ambiguous_archive, ambiguous_extract)
        require_rejected(run(ambiguous_archive, ambiguous_manifest, ambiguous_extract), "ambiguous roots")

        source_archive = root / "source.tar.gz"
        source_manifest = root / "source.tsv"
        write_archive(source_archive, source=True)
        write_manifest(source_manifest, manifest_records())
        source_extract = root / "source-extract"
        extract(source_archive, source_extract)
        require_rejected(run(source_archive, source_manifest, source_extract), "source link")

        extra_archive = root / "extra.tar.gz"
        extra_manifest = root / "extra.tsv"
        write_archive(extra_archive, extra=True)
        write_manifest(extra_manifest, manifest_records())
        extra_extract = root / "extra-extract"
        extract(extra_archive, extra_extract)
        require_rejected(run(extra_archive, extra_manifest, extra_extract), "unmanifested archive member")

        noncanonical_archive = root / "noncanonical.tar.gz"
        noncanonical_manifest = root / "noncanonical.tsv"
        write_archive(noncanonical_archive, noncanonical_member=True)
        write_manifest(noncanonical_manifest, manifest_records())
        require_rejected(
            run(noncanonical_archive, noncanonical_manifest, "--archive-only"),
            "noncanonical archive member",
        )

        dangling_link_archive = root / "dangling-link.tar.gz"
        dangling_link_manifest = root / "dangling-link.tsv"
        write_archive(dangling_link_archive, link_target="missing")
        write_manifest(dangling_link_manifest, manifest_records(link_target="missing"))
        require_rejected(
            run(dangling_link_archive, dangling_link_manifest, "--archive-only"),
            "dangling symlink",
        )

        parent_link_archive = root / "parent-link.tar.gz"
        parent_link_manifest = root / "parent-link.tsv"
        write_parent_symlink_archive(parent_link_archive)
        write_manifest(parent_link_manifest, manifest_records())
        require_rejected(
            run(parent_link_archive, parent_link_manifest, "--archive-only"),
            "symlink parent collision",
        )

        bad_mode_manifest = root / "bad-mode.tsv"
        bad_mode = manifest_records()
        bad_mode[0] = (bad_mode[0][0], bad_mode[0][1], 0o755, bad_mode[0][3])
        write_manifest(bad_mode_manifest, bad_mode)
        mode_extract = root / "mode-extract"
        extract(good_archive, mode_extract)
        require_rejected(run(good_archive, bad_mode_manifest, mode_extract), "mode mismatch")

        unsorted_manifest = root / "unsorted.tsv"
        write_manifest(unsorted_manifest, list(reversed(manifest_records())))
        unsorted_extract = root / "unsorted-extract"
        extract(good_archive, unsorted_extract)
        require_rejected(run(good_archive, unsorted_manifest, unsorted_extract), "unsorted manifest")

        mutated_extract = root / "mutated-extract"
        extract(good_archive, mutated_extract)
        (mutated_extract / ".config").write_bytes(b"mutated\n")
        require_rejected(run(good_archive, good_manifest, mutated_extract), "extracted byte mutation")

        malformed_manifest = root / "malformed.tsv"
        malformed_manifest.write_text(
            "schema\ttb321fu.kernel-sdk-manifest/v1\nfile\t" + "0" * 64 + "\t0644\t./.config\n",
            encoding="ascii",
        )
        malformed_extract = root / "malformed-extract"
        extract(good_archive, malformed_extract)
        require_rejected(run(good_archive, malformed_manifest, malformed_extract), "leading-zero mode")

    print("KERNEL_SDK_VERIFIER=PASS")


if __name__ == "__main__":
    main()
