#!/usr/bin/env python3
"""Hostile fixtures for the closed-world TB321FU kernel SDK verifier."""

from __future__ import annotations

import hashlib
import io
import os
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
RELEASE = "7.1.1-fixture"


def add_directory(archive: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
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
    prefix: str = "",
    *,
    include_link: bool = True,
    link_target: str = "autoconf.h",
    required: dict[str, bytes] = REQUIRED,
    file_modes: dict[str, int] | None = None,
    link_mode: int = 0o777,
) -> list[tuple[str, str, int, str]]:
    file_modes = file_modes or {}
    records = [
        (
            "file",
            hashlib.sha256(data).hexdigest(),
            file_modes.get(path, 0o644),
            f"./{prefix}{path[2:]}",
        )
        for path, data in required.items()
    ]
    if include_link:
        records.append(
            (
                "symlink",
                hashlib.sha256(link_target.encode("utf-8")).hexdigest(),
                link_mode,
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
    compression: str = "w:gz",
    prefix: str = "",
    extra: bool = False,
    source: bool = False,
    duplicate_root: bool = False,
    noncanonical_member: bool = False,
    link_target: str = "autoconf.h",
    required: dict[str, bytes] = REQUIRED,
    directory_mode: int = 0o755,
    file_modes: dict[str, int] | None = None,
    link_mode: int = 0o777,
    long_component: bool = False,
    deep_path: bool = False,
    extra_directory: bool = False,
    omit_directory: str | None = None,
) -> None:
    file_modes = file_modes or {}
    with tarfile.open(path, compression, format=tarfile.GNU_FORMAT) as archive:
        add_directory(archive, "./", directory_mode)
        for directory in ("include", "include/config", "include/generated"):
            if directory != omit_directory:
                add_directory(archive, f"./{prefix}{directory}", directory_mode)
        for name, data in required.items():
            archive_name = f"./{prefix}{name[2:]}"
            if noncanonical_member and name == "./.config":
                archive_name = f"./{prefix}./.config"
            add_regular(archive, archive_name, data, file_modes.get(name, 0o644))
        add_symlink(
            archive,
            f"./{prefix}include/generated/autoconf-link",
            link_target,
            link_mode,
        )
        if long_component:
            add_regular(archive, "./" + "x" * 256, b"long\n")
        if deep_path:
            add_regular(archive, "./" + "/".join(["d"] * 129), b"deep\n")
        if extra:
            add_regular(archive, f"./{prefix}unexpected", b"unexpected\n")
        if extra_directory:
            add_directory(archive, f"./{prefix}unexpected-empty-directory")
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
        timeout=30,
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


def require_normalized_rejection(
    result: subprocess.CompletedProcess[str], label: str
) -> None:
    require_rejected(result, label)
    if "Traceback" in result.stderr:
        raise SystemExit(f"{label} leaked a Python traceback")
    if not result.stderr.startswith("kernel SDK verification failed: "):
        raise SystemExit(f"{label} did not use the verifier error boundary")


def validate_fixture(root: pathlib.Path, archive: pathlib.Path, manifest: pathlib.Path) -> None:
    preflight = run(archive, manifest, "--archive-only", "--kernel-release", RELEASE)
    if preflight.returncode or preflight.stdout.strip() != "KERNEL_SDK=PASS":
        raise SystemExit(f"valid SDK archive-only fixture failed: {preflight.stderr}")
    extracted = root / "extract"
    extract(archive, extracted)
    result = run(archive, manifest, extracted, "--kernel-release", RELEASE)
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

        require_rejected(
            run(good_archive, good_manifest, "--archive-only", "--kernel-release", "7.1.1-wrong"),
            "outer kernel release mismatch",
        )

        empty_symvers = dict(REQUIRED)
        empty_symvers["./Module.symvers"] = b""
        empty_symvers_archive = root / "empty-symvers.tar.gz"
        empty_symvers_manifest = root / "empty-symvers.tsv"
        write_archive(empty_symvers_archive, required=empty_symvers)
        write_manifest(empty_symvers_manifest, manifest_records(required=empty_symvers))
        require_rejected(
            run(
                empty_symvers_archive,
                empty_symvers_manifest,
                "--archive-only",
                "--kernel-release",
                RELEASE,
            ),
            "empty Module.symvers",
        )

        wrong_identity = dict(REQUIRED)
        wrong_identity["./include/config/kernel.release"] = b"7.1.1-wrong\n"
        wrong_identity["./include/generated/utsrelease.h"] = b'#define UTS_RELEASE "7.1.1-wrong"\n'
        wrong_identity_archive = root / "wrong-identity.tar.gz"
        wrong_identity_manifest = root / "wrong-identity.tsv"
        write_archive(wrong_identity_archive, required=wrong_identity)
        write_manifest(wrong_identity_manifest, manifest_records(required=wrong_identity))
        require_rejected(
            run(
                wrong_identity_archive,
                wrong_identity_manifest,
                "--archive-only",
                "--kernel-release",
                RELEASE,
            ),
            "synchronized SDK release mismatch",
        )

        required_mode = {"./include/config/kernel.release": 0o600}
        required_mode_archive = root / "required-mode.tar.gz"
        required_mode_manifest = root / "required-mode.tsv"
        write_archive(required_mode_archive, file_modes=required_mode)
        write_manifest(required_mode_manifest, manifest_records(file_modes=required_mode))
        require_rejected(
            run(required_mode_archive, required_mode_manifest, "--archive-only"),
            "synchronized required-file mode",
        )

        directory_mode_archive = root / "directory-mode.tar.gz"
        write_archive(directory_mode_archive, directory_mode=0o777)
        require_rejected(
            run(directory_mode_archive, good_manifest, "--archive-only"),
            "unsafe directory mode",
        )

        file_mode = {"./include/generated/autoconf.h": 0o666}
        file_mode_archive = root / "file-mode.tar.gz"
        file_mode_manifest = root / "file-mode.tsv"
        write_archive(file_mode_archive, file_modes=file_mode)
        write_manifest(file_mode_manifest, manifest_records(file_modes=file_mode))
        require_rejected(run(file_mode_archive, file_mode_manifest, "--archive-only"), "unsafe file mode")

        symlink_mode_archive = root / "symlink-mode.tar.gz"
        symlink_mode_manifest = root / "symlink-mode.tsv"
        write_archive(symlink_mode_archive, link_mode=0o755)
        write_manifest(symlink_mode_manifest, manifest_records(link_mode=0o755))
        require_rejected(
            run(symlink_mode_archive, symlink_mode_manifest, "--archive-only"),
            "unsafe symlink mode",
        )

        parent_target_archive = root / "parent-target.tar.gz"
        parent_target_manifest = root / "parent-target.tsv"
        write_archive(parent_target_archive, link_target="../generated/autoconf.h")
        write_manifest(
            parent_target_manifest,
            manifest_records(link_target="../generated/autoconf.h"),
        )
        require_rejected(
            run(parent_target_archive, parent_target_manifest, "--archive-only"),
            "symlink parent traversal",
        )

        long_component_archive = root / "long-component.tar.gz"
        write_archive(long_component_archive, long_component=True)
        require_rejected(
            run(long_component_archive, good_manifest, "--archive-only"),
            "overlong path component",
        )

        deep_path_archive = root / "deep-path.tar.gz"
        write_archive(deep_path_archive, deep_path=True)
        require_rejected(
            run(deep_path_archive, good_manifest, "--archive-only"),
            "overdeep archive path",
        )

        deep_manifest = root / "deep-manifest.tsv"
        deep_records = manifest_records()
        deep_records.append(("file", hashlib.sha256(b"deep\n").hexdigest(), 0o644, "./" + "/".join(["d"] * 129)))
        write_manifest(deep_manifest, sorted(deep_records, key=lambda record: record[3]))
        require_rejected(
            run(good_archive, deep_manifest, "--archive-only"),
            "overdeep manifest path",
        )

        oversized_manifest = root / "oversized.tsv"
        with oversized_manifest.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        require_rejected(
            run(good_archive, oversized_manifest, "--archive-only"),
            "oversized manifest",
        )

        symlink_manifest = root / "symlink-manifest.tsv"
        symlink_manifest.symlink_to(good_manifest.name)
        require_rejected(
            run(good_archive, symlink_manifest, "--archive-only"),
            "symlink manifest",
        )

        fifo_manifest = root / "fifo-manifest.tsv"
        fifo_manifest.unlink(missing_ok=True)
        fifo_manifest.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(fifo_manifest)
        require_rejected(
            run(good_archive, fifo_manifest, "--archive-only"),
            "FIFO manifest",
        )

        symlink_archive = root / "symlink-archive.tar.gz"
        symlink_archive.symlink_to(good_archive.name)
        require_rejected(
            run(symlink_archive, good_manifest, "--archive-only"),
            "symlink archive",
        )

        fifo_archive = root / "fifo-archive.tar.gz"
        os.mkfifo(fifo_archive)
        require_rejected(
            run(fifo_archive, good_manifest, "--archive-only"),
            "FIFO archive",
        )

        require_rejected(
            run(root, good_manifest, "--archive-only"),
            "directory archive",
        )

        oversized_archive = root / "oversized.tar.gz"
        with oversized_archive.open("wb") as stream:
            stream.truncate(2 * 1024 * 1024 * 1024 + 1)
        require_rejected(run(oversized_archive, good_manifest, "--archive-only"), "oversized archive")

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

        extra_directory_archive = root / "extra-directory.tar.gz"
        write_archive(extra_directory_archive, extra_directory=True)
        require_rejected(
            run(extra_directory_archive, good_manifest, "--archive-only"),
            "unmanifested empty archive directory",
        )

        corrupt_xz_archive = root / "corrupt.tar.xz"
        write_archive(corrupt_xz_archive, compression="w:xz")
        corrupt_xz_archive.write_bytes(corrupt_xz_archive.read_bytes()[:-64])
        corrupt_xz_result = run(corrupt_xz_archive, good_manifest, "--archive-only")
        require_normalized_rejection(corrupt_xz_result, "corrupt xz archive")

        corrupt_xz_crc_archive = root / "corrupt-crc.tar.xz"
        write_archive(corrupt_xz_crc_archive, compression="w:xz")
        corrupt_xz_crc = bytearray(corrupt_xz_crc_archive.read_bytes())
        corrupt_xz_crc[len(corrupt_xz_crc) // 2] ^= 1
        corrupt_xz_crc_archive.write_bytes(corrupt_xz_crc)
        corrupt_xz_crc_result = run(corrupt_xz_crc_archive, good_manifest, "--archive-only")
        require_normalized_rejection(corrupt_xz_crc_result, "corrupt xz CRC")

        missing_directory_archive = root / "missing-directory.tar.gz"
        write_archive(missing_directory_archive, omit_directory="include/config")
        require_rejected(
            run(missing_directory_archive, good_manifest, "--archive-only"),
            "missing structural archive directory",
        )

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

        directory_extract = root / "directory-extract"
        extract(good_archive, directory_extract)
        (directory_extract / "include").chmod(0o777)
        require_rejected(run(good_archive, good_manifest, directory_extract), "extracted directory mode")

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
