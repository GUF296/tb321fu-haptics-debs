#!/usr/bin/env python3
"""Regression tests for extraction containment and resource budgets."""

from __future__ import annotations

import io
import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import struct


def run(helper: pathlib.Path, archive: pathlib.Path, destination: pathlib.Path, **limits: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(limits)
    return subprocess.run(
        [sys.executable, str(helper), str(archive), str(destination)],
        check=False,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def require_rejected(result: subprocess.CompletedProcess[str], reason: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"unsafe archive was accepted: {reason}")


def add_directory(archive: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    archive.addfile(info)


def add_file(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def add_symlink(archive: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.mode = 0o777
    info.linkname = target
    archive.addfile(info)


def add_hardlink(archive: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE
    info.mode = 0o644
    info.linkname = target
    archive.addfile(info)


def add_zip_symlink(archive: zipfile.ZipFile, name: str, target: str) -> None:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive.writestr(info, target.encode("utf-8"))


def fd_snapshot() -> list[str] | None:
    proc_fds = pathlib.Path("/proc/self/fd")
    if not proc_fds.is_dir():
        return None
    targets: list[str] = []
    with os.scandir(proc_fds) as entries:
        for entry in entries:
            try:
                targets.append(os.readlink(entry.path))
            except FileNotFoundError:
                pass
    return sorted(targets)


def load_helper_module(helper: pathlib.Path):
    spec = importlib.util.spec_from_file_location("safe_extract_fd_test", helper)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load safe extractor for FD tests")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_fd_cleanup(helper: pathlib.Path) -> None:
    module = load_helper_module(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-fd-test.") as raw:
        root = pathlib.Path(raw)
        (root / "not-a-directory").write_text("regular")
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        tree = module.DestinationTree(root, os.dup(root_fd))
        tree.regular_identities[pathlib.PurePosixPath("not-a-directory/target")] = (0, 0)
        before = fd_snapshot()
        try:
            for _ in range(8):
                try:
                    tree.make_hardlink(
                        pathlib.PurePosixPath("output"),
                        pathlib.PurePosixPath("not-a-directory/target"),
                    )
                except (OSError, ValueError):
                    pass
            after = fd_snapshot()
            if before is not None and after != before:
                raise SystemExit("hardlink failure path leaked a directory FD")
        finally:
            tree.close()
            os.close(root_fd)

    with tempfile.NamedTemporaryFile(prefix="tb321fu-extract-stream-test.") as stream:
        before = fd_snapshot()
        original_fdopen = module.os.fdopen

        def fail_fdopen(fd, mode):
            os.close(fd)
            raise OSError("injected fdopen failure")

        module.os.fdopen = fail_fdopen
        try:
            try:
                module._dup_binary_stream(stream.fileno())
            except OSError as error:
                if "injected fdopen failure" not in str(error):
                    raise SystemExit(f"fdopen failure was masked: {error}")
            else:
                raise SystemExit("injected fdopen failure was accepted")
        finally:
            module.os.fdopen = original_fdopen
        after = fd_snapshot()
        if before is not None and after != before:
            raise SystemExit("dup/fdopen failure path leaked a file descriptor")


def check_supplied_archive_fd_contract(helper: pathlib.Path) -> None:
    module = load_helper_module(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-supplied-fd.") as raw:
        root = pathlib.Path(raw)
        archives = {
            "tar": root / "fixture.tar",
            "zip": root / "fixture.zip",
        }
        with tarfile.open(archives["tar"], "w") as archive:
            add_file(archive, "payload", b"tar-fd\n")
        with zipfile.ZipFile(archives["zip"], "w") as archive:
            archive.writestr("payload", "zip-fd\n")

        for kind, archive_path in archives.items():
            extract = module.extract_tar if kind == "tar" else module.extract_zip
            actual_size = archive_path.stat().st_size
            descriptor = os.open(archive_path, os.O_RDONLY)
            try:
                for supplied_size, expected in (
                    (None, "archive_size is required"),
                    (actual_size - 1, "does not match archive_size"),
                    (actual_size + 1, "does not match archive_size"),
                    (0, "exceeds compressed size limit"),
                    (module.MAX_ARCHIVE_BYTES + 1, "exceeds compressed size limit"),
                ):
                    try:
                        extract(
                            archive_path,
                            root / f"bad-{kind}-{supplied_size}",
                            archive_fd=descriptor,
                            archive_size=supplied_size,
                        )
                    except ValueError as error:
                        if expected not in str(error):
                            raise SystemExit(
                                f"{kind} supplied-FD failure was misclassified: {error}"
                            )
                    else:
                        raise SystemExit(
                            f"{kind} accepted invalid supplied archive_size {supplied_size!r}"
                        )
            finally:
                os.close(descriptor)

        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                module.extract_tar(
                    archives["tar"],
                    root / "bad-directory-fd",
                    archive_fd=directory_fd,
                    archive_size=1,
                )
            except ValueError as error:
                if "not a regular file" not in str(error):
                    raise SystemExit(f"directory FD failure was misclassified: {error}")
            else:
                raise SystemExit("directory archive FD was accepted")
        finally:
            os.close(directory_fd)


def check_parent_close_failure_cleanup(helper: pathlib.Path) -> None:
    module = load_helper_module(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-close-failure.") as raw:
        root = pathlib.Path(raw)
        baseline = fd_snapshot()
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        tree = module.DestinationTree(root, os.dup(root_fd))
        original_close = module.os.close
        failures = 1

        def fail_once(fd: int) -> None:
            nonlocal failures
            if failures:
                failures -= 1
                raise OSError("injected parent close failure")
            original_close(fd)

        module.os.close = fail_once
        try:
            try:
                tree.directory(("nested",))
            except (OSError, ValueError) as error:
                cause = error.__cause__
                if "injected parent close failure" not in str(error) and (
                    cause is None or "injected parent close failure" not in str(cause)
                ):
                    raise SystemExit(f"parent close failure was masked: {error}")
            else:
                raise SystemExit("injected parent close failure was accepted")
        finally:
            module.os.close = original_close
            tree.close()
            os.close(root_fd)
        after = fd_snapshot()
        if baseline is not None and after != baseline:
            raise SystemExit("parent close failure path leaked a directory FD")


def check_archive_byte_range_binding(helper: pathlib.Path) -> None:
    module = load_helper_module(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-range-test.") as raw:
        root = pathlib.Path(raw)
        archive = root / "fixture.tar"
        with tarfile.open(archive, "w") as handle:
            add_file(handle, "payload", b"range-safe\n")
        archive_size = archive.stat().st_size
        descriptor = os.open(archive, os.O_RDONLY)
        try:
            stream = module._dup_binary_stream(descriptor, limit=archive_size)
            try:
                with archive.open("ab") as changed:
                    changed.write(b"outside-range")
                if len(stream.read()) != archive_size:
                    raise SystemExit("bounded archive stream exposed appended bytes")
                try:
                    stream.seek(archive_size + 1)
                except ValueError:
                    pass
                else:
                    raise SystemExit("bounded archive stream allowed an out-of-range seek")
            finally:
                stream.close()
        finally:
            os.close(descriptor)

        # A size change after strict scanning must fail before the result is
        # reported as a successful extraction.
        with tarfile.open(archive, "w") as handle:
            add_file(handle, "payload", b"growth-check\n")
        original_strict = module.strict_tar_stream

        def scan_then_grow(fd: int, size: int) -> str:
            mode = original_strict(fd, size)
            with archive.open("ab") as changed:
                changed.write(b"post-scan-growth")
            return mode

        module.strict_tar_stream = scan_then_grow
        try:
            try:
                module.extract_tar(archive, root / "growth-out")
            except ValueError as error:
                if "does not match archive_size" not in str(error):
                    raise SystemExit(f"archive growth was misclassified: {error}")
            else:
                raise SystemExit("archive growth after scanning was accepted")
        finally:
            module.strict_tar_stream = original_strict


def check_sparse_tar_rejection(helper: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-sparse-test.") as raw:
        root = pathlib.Path(raw)
        old_sparse = root / "old-sparse.tar"
        info = tarfile.TarInfo("sparse")
        info.type = tarfile.GNUTYPE_SPARSE
        info.size = 1
        info._sparse_structs = ([(0, 1)], False, 1)
        with tarfile.open(old_sparse, "w") as archive:
            archive.addfile(info, io.BytesIO(b"x"))
        require_rejected(
            run(helper, old_sparse, root / "old-sparse-out"),
            "GNU sparse TAR member",
        )

        pax_sparse = root / "pax-sparse.tar"
        info = tarfile.TarInfo("payload")
        info.size = 1
        info.pax_headers = {"GNU.sparse.map": "0,1"}
        with tarfile.open(pax_sparse, "w", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(info, io.BytesIO(b"x"))
        require_rejected(
            run(helper, pax_sparse, root / "pax-sparse-out"),
            "PAX sparse TAR metadata",
        )


def check_format_probe_precedes_tar_parser(helper: pathlib.Path) -> None:
    """Keep raw TAR safety validation ahead of tarfile metadata parsing."""
    module = load_helper_module(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-probe-order.") as raw:
        root = pathlib.Path(raw)
        archive = root / "plain.tar"
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as handle:
            info = tarfile.TarInfo("payload")
            info.size = len(b"probe-order\n")
            info.pax_headers = {"comment": "probe-order"}
            handle.addfile(info, io.BytesIO(b"probe-order\n"))

        strict_seen = False
        original_strict = module.strict_tar_stream
        original_open = module.tarfile.open

        def wrapped_strict(descriptor: int, size: int) -> str:
            nonlocal strict_seen
            strict_seen = True
            return original_strict(descriptor, size)

        def wrapped_open(*args, **kwargs):
            if not strict_seen:
                raise SystemExit("tarfile parsed archive before strict stream validation")
            return original_open(*args, **kwargs)

        original_argv = sys.argv
        module.strict_tar_stream = wrapped_strict
        module.tarfile.open = wrapped_open
        sys.argv = [str(helper), str(archive), str(root / "out")]
        try:
            if module.main() != 0:
                raise SystemExit("format probe returned a non-zero status")
        finally:
            sys.argv = original_argv
            module.strict_tar_stream = original_strict
            module.tarfile.open = original_open
        if not strict_seen:
            raise SystemExit("format probe skipped strict TAR validation")


def check_zip_tail_short_reads(helper: pathlib.Path) -> None:
    """The EOCD parser must tolerate legal short reads from a regular FD."""
    module = load_helper_module(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-zip-read.") as raw:
        root = pathlib.Path(raw)
        archive = root / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("payload", "short-read-safe\n")
        size = archive.stat().st_size
        descriptor = os.open(archive, os.O_RDONLY)
        original_read = module.os.read
        calls = 0

        def short_read(fd: int, requested: int) -> bytes:
            nonlocal calls
            if fd == descriptor and requested > 1:
                calls += 1
                return original_read(fd, max(1, requested // 3))
            return original_read(fd, requested)

        module.os.read = short_read
        try:
            module.validate_zip_central_directory(descriptor, size)
        except Exception as exc:
            raise SystemExit(f"ZIP EOCD short-read fixture failed: {exc}") from exc
        finally:
            module.os.read = original_read
            os.close(descriptor)
        if calls < 2:
            raise SystemExit("ZIP short-read fixture did not force multiple reads")

        descriptor = os.open(archive, os.O_RDONLY)
        calls = 0

        def truncated_read(fd: int, requested: int) -> bytes:
            nonlocal calls
            if fd == descriptor:
                calls += 1
                if calls == 1:
                    return original_read(fd, max(1, requested // 3))
                if calls > 1:
                    return b""
            return original_read(fd, requested)

        module.os.read = truncated_read
        try:
            try:
                module.validate_zip_central_directory(descriptor, size)
            except ValueError as exc:
                if "central-directory tail" not in str(exc):
                    raise SystemExit(f"ZIP truncation was misclassified: {exc}") from exc
            else:
                raise SystemExit("truncated ZIP EOCD was accepted")
        finally:
            module.os.read = original_read
            os.close(descriptor)


def main() -> None:
    helper = pathlib.Path(__file__).with_name("safe-extract-archive.py")
    check_zip_tail_short_reads(helper)
    with tempfile.TemporaryDirectory(prefix="tb321fu-extract-test.") as raw:
        root = pathlib.Path(raw)

        good = root / "good.zip"
        with zipfile.ZipFile(good, "w") as archive:
            archive.writestr("payload/file.txt", "known-good\n")
        result = run(helper, good, root / "good-out")
        if result.returncode != 0:
            raise SystemExit(result.stderr)
        if (root / "good-out/payload/file.txt").read_text() != "known-good\n":
            raise SystemExit("valid ZIP payload changed")

        malformed_zip = root / "malformed-central.zip"
        malformed_bytes = bytearray(good.read_bytes())
        eocd = malformed_bytes.rfind(b"PK\x05\x06")
        if eocd < 0:
            raise SystemExit("test ZIP fixture has no EOCD")
        # Point the central directory into the EOCD itself; the bounded parser
        # must reject this before ZipFile materializes its entry list.
        struct.pack_into("<L", malformed_bytes, eocd + 16, len(malformed_bytes))
        malformed_zip.write_bytes(malformed_bytes)
        require_rejected(
            run(helper, malformed_zip, root / "malformed-central-out"),
            "ZIP central directory overlap",
        )

        # ``PK`` is a valid TAR filename prefix; format probing must not
        # classify an uncompressed TAR as ZIP solely from its first bytes.
        pk_tar = root / "pk-prefix.tar"
        with tarfile.open(pk_tar, "w") as archive:
            add_directory(archive, "PKdir")
            add_file(archive, "PKdir/payload", b"pk-prefix\n")
        pk_out = root / "pk-prefix-out"
        pk_result = run(helper, pk_tar, pk_out)
        if pk_result.returncode != 0:
            raise SystemExit(f"valid PK-prefixed TAR failed: {pk_result.stderr}")
        if (pk_out / "PKdir/payload").read_bytes() != b"pk-prefix\n":
            raise SystemExit("PK-prefixed TAR payload changed")

        bzip_magic_tar = root / "bzip-magic-prefix.tar"
        with tarfile.open(bzip_magic_tar, "w") as archive:
            add_file(archive, "BZh9payload", b"plain-tar\n")
        bzip_magic_out = root / "bzip-magic-prefix-out"
        bzip_magic_result = run(helper, bzip_magic_tar, bzip_magic_out)
        if bzip_magic_result.returncode != 0:
            raise SystemExit(
                "valid BZip2-magic-prefixed TAR failed: "
                f"{bzip_magic_result.stderr}"
            )
        if (bzip_magic_out / "BZh9payload").read_bytes() != b"plain-tar\n":
            raise SystemExit("BZip2-magic-prefixed TAR payload changed")

        bzip_tar = root / "valid.tar.bz2"
        with tarfile.open(bzip_tar, "w:bz2") as archive:
            add_file(archive, "payload", b"bzip2-tar\n")
        bzip_out = root / "bzip2-out"
        bzip_result = run(helper, bzip_tar, bzip_out)
        if bzip_result.returncode != 0:
            raise SystemExit(f"valid BZip2 TAR failed: {bzip_result.stderr}")
        if (bzip_out / "payload").read_bytes() != b"bzip2-tar\n":
            raise SystemExit("BZip2 TAR payload changed")

        mode_tar = root / "mode.tar"
        with tarfile.open(mode_tar, "w") as archive:
            add_directory(archive, "locked", 0o555)
            add_file(archive, "locked/child", b"mode-safe\n")
        mode_out = root / "mode-out"
        mode_result = run(helper, mode_tar, mode_out)
        if mode_result.returncode != 0:
            raise SystemExit(f"valid restrictive-directory tar failed: {mode_result.stderr}")
        if (mode_out / "locked/child").read_bytes() != b"mode-safe\n":
            raise SystemExit("restrictive-directory tar payload changed")
        if (mode_out / "locked").stat().st_mode & 0o777 != 0o555:
            raise SystemExit("restrictive directory mode was not preserved")

        hardlink_bad = root / "hardlink-bad.tar"
        with tarfile.open(hardlink_bad, "w") as archive:
            add_directory(archive, "target-dir")
            add_hardlink(archive, "copy", "target-dir")
        require_rejected(run(helper, hardlink_bad, root / "hardlink-bad-out"), "hardlink to directory")

        graph_bad = root / "symlink-graph-bad.tar"
        with tarfile.open(graph_bad, "w") as archive:
            add_directory(archive, "x")
            add_directory(archive, "y")
            add_symlink(archive, "x/a", "../y")
            add_symlink(archive, "b", "x/a/../../outside/secret")
        require_rejected(run(helper, graph_bad, root / "symlink-graph-bad-out"), "symlink graph escape")

        zip_graph_bad = root / "symlink-graph-bad.zip"
        with zipfile.ZipFile(zip_graph_bad, "w") as archive:
            add_zip_symlink(archive, "x/a", "../y")
            archive.writestr("y/present", "inside")
            add_zip_symlink(archive, "b", "x/a/../../outside")
        require_rejected(run(helper, zip_graph_bad, root / "symlink-graph-bad-zip-out"), "ZIP symlink graph escape")

        outside_victim = root / "outside-victim"
        outside_victim.write_text("ORIGINAL\n")
        hardlink_destination = root / "hardlink-destination"
        hardlink_destination.mkdir()
        os.link(outside_victim, hardlink_destination / "target")
        replacement = root / "replacement.tar"
        with tarfile.open(replacement, "w") as archive:
            add_file(archive, "target", b"REPLACED\n")
        replacement_result = run(helper, replacement, hardlink_destination)
        if replacement_result.returncode != 0:
            raise SystemExit(f"regular replacement failed: {replacement_result.stderr}")
        if outside_victim.read_text() != "ORIGINAL\n":
            raise SystemExit("replacement truncated an outside hardlink inode")
        if (hardlink_destination / "target").read_text() != "REPLACED\n":
            raise SystemExit("regular replacement payload changed")

        plain_trailing = root / "plain-trailing.tar"
        with tarfile.open(plain_trailing, "w") as archive:
            add_file(archive, "payload", b"plain\n")
        with plain_trailing.open("ab") as stream:
            stream.write(b"BAD")
        require_rejected(run(helper, plain_trailing, root / "plain-trailing-out"), "plain tar trailing data")

        gzip_trailing = root / "gzip-trailing.tar.gz"
        with tarfile.open(gzip_trailing, "w:gz") as archive:
            add_file(archive, "payload", b"gzip\n")
        with gzip_trailing.open("ab") as stream:
            stream.write(b"BAD")
        require_rejected(run(helper, gzip_trailing, root / "gzip-trailing-out"), "gzip tar trailing data")

        destination_alias_target = root / "destination-alias-target"
        destination_alias_target.mkdir()
        destination_alias = root / "destination-alias"
        destination_alias.symlink_to(destination_alias_target, target_is_directory=True)
        require_rejected(
            run(helper, good, destination_alias),
            "symlink destination root",
        )

        archive_alias = root / "archive-alias.zip"
        archive_alias.symlink_to(good)
        require_rejected(
            run(helper, archive_alias, root / "archive-alias-out"),
            "symlink archive input",
        )
        archive_parent = root / "archive-parent"
        archive_parent.mkdir()
        nested_archive = archive_parent / "nested.zip"
        nested_archive.write_bytes(good.read_bytes())
        archive_parent_alias = root / "archive-parent-alias"
        archive_parent_alias.symlink_to(archive_parent, target_is_directory=True)
        require_rejected(
            run(helper, archive_parent_alias / "nested.zip", root / "archive-parent-alias-out"),
            "symlink archive parent",
        )

        outside = root / "outside"
        outside.mkdir()
        destination = root / "symlink-out"
        destination.mkdir()
        (destination / "escape").symlink_to(outside, target_is_directory=True)
        hostile = root / "hostile-parent.zip"
        with zipfile.ZipFile(hostile, "w") as archive:
            archive.writestr("escape/created/file.txt", "must-not-exist")
        require_rejected(run(helper, hostile, destination), "pre-existing escaping symlink")
        if (outside / "created").exists():
            raise SystemExit("extractor created an external directory before containment validation")

        many = root / "many.zip"
        with zipfile.ZipFile(many, "w") as archive:
            for index in range(3):
                archive.writestr(f"{index}.txt", "x")
        require_rejected(
            run(helper, many, root / "many-out", SAFE_EXTRACT_MAX_MEMBERS="2"),
            "member limit",
        )

        large_tar = root / "large.tar"
        with tarfile.open(large_tar, "w") as archive:
            data = b"x" * 32
            info = tarfile.TarInfo("large.bin")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        require_rejected(
            run(
                helper,
                large_tar,
                root / "large-out",
                SAFE_EXTRACT_MAX_FILE_BYTES="16",
                SAFE_EXTRACT_MAX_TOTAL_BYTES="16",
            ),
            "tar file/total size limit",
        )

        ratio = root / "ratio.zip"
        with zipfile.ZipFile(ratio, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("zeros.bin", bytes(1024 * 1024))
        require_rejected(
            run(helper, ratio, root / "ratio-out", SAFE_EXTRACT_MAX_COMPRESSION_RATIO="2"),
            "compression ratio limit",
        )

        symlink_budget = root / "symlink-budget.zip"
        with zipfile.ZipFile(symlink_budget, "w") as archive:
            add_zip_symlink(archive, "link", "target")
        require_rejected(
            run(
                helper,
                symlink_budget,
                root / "symlink-budget-out",
                SAFE_EXTRACT_MAX_TOTAL_BYTES="1",
            ),
            "symlink target total size limit",
        )

        check_fd_cleanup(helper)
        check_supplied_archive_fd_contract(helper)
        check_parent_close_failure_cleanup(helper)
        check_archive_byte_range_binding(helper)
        check_sparse_tar_rejection(helper)
        check_format_probe_precedes_tar_parser(helper)

    print("safe archive extraction regressions: PASS")


if __name__ == "__main__":
    main()
