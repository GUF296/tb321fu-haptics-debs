#!/usr/bin/env python3
"""Fixtures for stable APT archive identity and DEB control metadata."""

from __future__ import annotations

import errno
import importlib.util
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"


def load_module():
    spec = importlib.util.spec_from_file_location("haptics_apt_transaction", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT transaction verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_deb(root: pathlib.Path) -> pathlib.Path:
    package_root = root / "package"
    control_dir = package_root / "DEBIAN"
    data_dir = package_root / "usr/share/example"
    control_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    (control_dir / "control").write_text(
        "Package: example\n"
        "Version: 1.0-1\n"
        "Architecture: amd64\n"
        "Multi-Arch: no\n"
        "Maintainer: Fixture <fixture@example.invalid>\n"
        "Description: APT transaction fixture\n"
        " This legal continuation must not enter the identity query.\n",
        encoding="ascii",
    )
    (data_dir / "payload").write_text("fixture\n", encoding="ascii")
    archive = root / "example_1.0-1_amd64.deb"
    result = subprocess.run(
        [
            "/usr/bin/dpkg-deb",
            "--build",
            "--root-owner-group",
            str(package_root),
            str(archive),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(root),
            "SOURCE_DATE_EPOCH": "1",
        },
    )
    if result.returncode:
        raise SystemExit("fixture DEB creation failed: " + result.stderr.strip())
    archive.chmod(0o644)
    return archive


def require_rejected(verifier, callback, label: str, expected: str) -> None:
    if not expected:
        raise SystemExit(f"empty rejection boundary for hostile fixture: {label}")
    try:
        callback()
    except verifier.AptTransactionError as exc:
        if expected not in str(exc):
            raise SystemExit(
                f"APT archive verifier rejected {label} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"APT archive verifier raised an unexpected exception for {label}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"APT archive verifier accepted hostile fixture: {label}")


def prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier) -> None:
    for sentinel in (
        ValueError("oracle sentinel"),
        OSError("oracle sentinel"),
        SystemExit("oracle sentinel"),
    ):
        try:
            require_rejected(
                verifier,
                lambda sentinel=sentinel: (_ for _ in ()).throw(sentinel),
                "oracle sentinel",
                "must not match",
            )
        except SystemExit as exc:
            if (
                "unexpected exception" not in str(exc)
                or f"{type(sentinel).__name__}: oracle sentinel" not in str(exc)
            ):
                raise SystemExit(
                    f"APT archive rejection oracle failed unclearly: {exc}"
                ) from exc
            continue
        raise SystemExit(
            "APT archive rejection oracle swallowed "
            f"{type(sentinel).__name__}"
        )


def verify_bounded_control_query(verifier) -> None:
    if not hasattr(verifier, "_bounded_command"):
        raise SystemExit("APT DEB control query has no bounded process runner")
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
    }
    returncode, stdout, stderr = verifier._bounded_command(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import os;os.write(1,b'o'*17);os.write(2,b'e'*19)",
        ],
        "DEB control exact-limit fixture",
        env=environment,
        timeout=2.0,
        max_stdout=17,
        max_stderr=19,
    )
    if (returncode, stdout, stderr) != (0, b"o" * 17, b"e" * 19):
        raise SystemExit("bounded DEB control query changed exact-limit bytes")
    for stream, code, expected in (
        ("stdout", "import os;os.write(1,b'o'*18)", "stdout exceeds its size bound"),
        ("stderr", "import os;os.write(2,b'e'*20)", "stderr exceeds its size bound"),
    ):
        require_rejected(
            verifier,
            lambda code=code: verifier._bounded_command(
                [sys.executable, "-I", "-B", "-c", code],
                f"DEB control {stream} overflow fixture",
                env=environment,
                timeout=2.0,
                max_stdout=17,
                max_stderr=19,
            ),
            f"DEB control {stream} limit+1",
            expected,
        )


def verify_pinned_control_query(verifier, root: pathlib.Path) -> None:
    archive = root / "pinned-control.deb"
    replacement = root / "replacement-control.deb"
    saved = root / "saved-control.deb"
    original_bytes = b"original archive inode\n"
    archive.write_bytes(original_bytes)
    replacement.write_bytes(b"replacement archive inode\n")
    archive.chmod(0o644)
    replacement.chmod(0o644)
    original_stat = archive.stat()
    calls = []
    original_runner = verifier._bounded_command

    def swap_restore_runner(
        arguments,
        label,
        *,
        env,
        timeout,
        max_stdout,
        max_stderr,
        pass_fds=(),
    ):
        calls.append(
            (
                arguments,
                label,
                env,
                timeout,
                max_stdout,
                max_stderr,
                pass_fds,
            )
        )
        if len(pass_fds) != 1:
            raise SystemExit("DEB control query did not inherit exactly one archive fd")
        descriptor = pass_fds[0]
        if arguments != [
            "/usr/bin/dpkg-deb",
            "-f",
            f"/proc/self/fd/{descriptor}",
            "Package",
            "Version",
            "Architecture",
            "Multi-Arch",
        ]:
            raise SystemExit(f"DEB control query did not use its pinned fd: {arguments!r}")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, len(original_bytes) + 1) != original_bytes:
            raise SystemExit("pinned DEB control descriptor changed before pathname swap")
        archive.rename(saved)
        replacement.rename(archive)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.read(descriptor, len(original_bytes) + 1) != original_bytes:
                raise SystemExit("DEB control query followed the replacement pathname")
        finally:
            archive.rename(replacement)
            saved.rename(archive)
        return (
            0,
            b"Package: example\nVersion: 1.0-1\nArchitecture: amd64\n",
            b"",
        )

    verifier._bounded_command = swap_restore_runner
    try:
        try:
            record = verifier.capture_deb_archive(
                archive, os.getuid(), os.getgid()
            )
        except verifier.AptTransactionError as exc:
            if str(exc) != "APT archive changed during its control query":
                raise SystemExit(
                    "DEB control swap rejected at the wrong boundary: "
                    f"{exc}"
                ) from exc
            record = None
    finally:
        verifier._bounded_command = original_runner
    if len(calls) != 1:
        raise SystemExit(f"DEB control query command count drifted: {len(calls)}")
    if (
        archive.stat().st_dev != original_stat.st_dev
        or archive.stat().st_ino != original_stat.st_ino
        or hashlib.sha256(archive.read_bytes()).hexdigest()
        != hashlib.sha256(original_bytes).hexdigest()
    ):
        raise SystemExit("DEB control swap fixture did not restore the original inode")
    if record is not None and (
        record.device != original_stat.st_dev
        or record.inode != original_stat.st_ino
        or record.sha256 != hashlib.sha256(original_bytes).hexdigest()
        or record.package != "example"
        or record.version != "1.0-1"
        or record.architecture != "amd64"
        or record.multiarch != "no"
    ):
        raise SystemExit("pinned DEB control query mixed archive identities")


def verify_control_query_exception_domain(
    verifier, archive: pathlib.Path
) -> None:
    original_runner = verifier._bounded_command
    for failure, expected in (
        (
            subprocess.TimeoutExpired(["injected dpkg-deb"], 1),
            "dpkg-deb control query timed out",
        ),
        (
            subprocess.SubprocessError("injected dpkg-deb failure"),
            "dpkg-deb control query failed",
        ),
        (OSError("injected dpkg-deb failure"), "dpkg-deb control query failed"),
    ):
        def fail_runner(*_args, injected=failure, **_kwargs):
            raise injected

        verifier._bounded_command = fail_runner
        caught = None
        try:
            verifier.capture_deb_archive(archive, os.getuid(), os.getgid())
        except verifier.AptTransactionError as exc:
            caught = exc
        finally:
            verifier._bounded_command = original_runner
        if (
            caught is None
            or str(caught) != expected
            or caught.__cause__ is not failure
        ):
            raise SystemExit(
                "DEB control query exception-domain drift: "
                f"failure={failure!r} caught={caught!r}"
            ) from caught


def verify_descriptor_close_custody(verifier) -> None:
    original_close = verifier.os.close
    original_fstat = verifier.os.fstat

    def require_closed(descriptor: int, label: str) -> None:
        try:
            original_fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return
            raise
        original_close(descriptor)
        raise SystemExit(f"APT descriptor cleanup leaked {label}")

    for applied in (False, True):
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        cancellation = KeyboardInterrupt(
            f"injected {'applied' if applied else 'pre-close'} cancellation"
        )
        calls = 0

        def cancel_close(target: int) -> None:
            nonlocal calls
            calls += 1
            if target == descriptor and calls == 1:
                if applied:
                    original_close(target)
                raise cancellation
            original_close(target)

        verifier.os.close = cancel_close
        caught: BaseException | None = None
        try:
            verifier.close_descriptors(
                (descriptor,),
                "APT archive cancellation oracle",
                None,
            )
        except BaseException as exc:
            caught = exc
        finally:
            verifier.os.close = original_close
        if caught is not cancellation:
            try:
                original_close(descriptor)
            except OSError:
                pass
            raise SystemExit(
                f"APT descriptor cleanup replaced {applied=} cancellation: {caught}"
            ) from caught
        require_closed(descriptor, f"{applied=} cancellation descriptor")

    descriptors = tuple(
        os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) for _ in range(2)
    )
    ordinary_primary = verifier.AptTransactionError("ordinary descriptor primary")
    cleanup_cancellation = KeyboardInterrupt("injected cleanup cancellation")

    def cancel_first_after_close(target: int) -> None:
        original_close(target)
        if target == descriptors[0]:
            raise cleanup_cancellation

    verifier.os.close = cancel_first_after_close
    caught = None
    try:
        verifier.close_descriptors(
            descriptors,
            "APT archive primary-priority oracle",
            ordinary_primary,
        )
    except BaseException as exc:
        caught = exc
    finally:
        verifier.os.close = original_close
    if caught is not cleanup_cancellation or caught.__cause__ is not ordinary_primary:
        for descriptor in descriptors:
            try:
                original_close(descriptor)
            except OSError:
                pass
        raise SystemExit(
            f"APT descriptor cleanup masked exact caller cancellation: {caught}"
        ) from caught
    for descriptor in descriptors:
        require_closed(descriptor, "primary-priority descriptor")

    descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)

    def no_progress_close(target: int) -> None:
        if target != descriptor:
            original_close(target)

    verifier.os.close = no_progress_close
    caught = None
    try:
        verifier.close_descriptors(
            (descriptor,),
            "APT archive bounded-close oracle",
            None,
        )
    except verifier.AptTransactionError as exc:
        caught = exc
    finally:
        verifier.os.close = original_close
        original_close(descriptor)
    if (
        caught is None
        or str(caught) != "cannot close APT archive bounded-close oracle descriptors"
        or not isinstance(caught.__cause__, verifier.AptTransactionError)
        or str(caught.__cause__)
        != "APT archive bounded-close oracle descriptor close did not converge"
    ):
        raise SystemExit(
            f"APT descriptor cleanup lost its bounded fixed-domain failure: {caught}"
        ) from caught


def main() -> None:
    verifier = load_module()
    prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier)
    verify_bounded_control_query(verifier)
    verify_descriptor_close_custody(verifier)
    if not hasattr(verifier, "capture_deb_archive"):
        raise SystemExit("APT DEB archive capture is missing")
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-apt-archive-test.") as raw:
        root = pathlib.Path(raw)
        verify_pinned_control_query(verifier, root)
        archive = make_deb(root)
        verify_control_query_exception_domain(verifier, archive)
        record = verifier.capture_deb_archive(archive, os.getuid(), os.getgid())
        if (
            record.path != str(archive)
            or record.package != "example"
            or record.version != "1.0-1"
            or record.architecture != "amd64"
            or record.multiarch != "no"
            or record.mode != 0o644
            or record.uid != os.getuid()
            or record.gid != os.getgid()
            or record.nlink != 1
            or record.size != archive.stat().st_size
        ):
            raise SystemExit("APT DEB archive capture changed the exact identity")
        if not hasattr(verifier, "verify_archive_actions"):
            raise SystemExit("APT archive/action closure verifier is missing")
        hook_command = (
            "/usr/bin/python3 -I -B /tmp/private/verify-haptics-apt-transaction.py "
            "--verify-hook /tmp/private/expected.tsv /tmp/private/hook.ok"
        )
        encoded_hook_command = hook_command.replace(" ", "%20")
        eipp = (
            "VERSION 3\n"
            "APT::Architecture=amd64\n"
            "APT::Architectures::=amd64\n"
            "Dir::Bin::dpkg=/usr/bin/dpkg\n"
            "DPkg::ConfigurePending=1\n"
            "DPkg::Path=/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"DPkg::Pre-Install-Pkgs::={encoded_hook_command}\n"
            "DPkg::Run-Directory=/\n"
            f"DPkg::Tools::options::{encoded_hook_command}::InfoFD=21\n"
            f"DPkg::Tools::options::{encoded_hook_command}::Version=3\n"
            "\n"
            f"example - - none < 1.0-1 amd64 none {archive}\n"
            "example - - none < 1.0-1 amd64 none **CONFIGURE**\n"
        ).encode("ascii")
        document = verifier.parse_eipp_v3_bytes(eipp)
        verifier.verify_archive_actions((record,), document.actions)
        require_rejected(
            verifier,
            lambda: verifier.verify_archive_actions((record, record), document.actions),
            "duplicate archive record",
            "APT archive/action closure is not canonical",
        )
        drifted_document = verifier.parse_eipp_v3_bytes(
            eipp.replace(b"1.0-1 amd64 none", b"1.0-1 arm64 none", 1)
        )
        require_rejected(
            verifier,
            lambda: verifier.verify_archive_actions(
                (record,), drifted_document.actions
            ),
            "archive/action architecture drift",
            "APT archive differs from its exact EIPP actions",
        )
        hardlink = root / "example-hardlink.deb"
        os.link(archive, hardlink)
        require_rejected(
            verifier,
            lambda: verifier.capture_deb_archive(
                archive, os.getuid(), os.getgid()
            ),
            "hardlinked archive",
            "APT archive metadata differs from policy",
        )
    print("HAPTICS_APT_ARCHIVE_FIXTURE=PASS")


if __name__ == "__main__":
    main()
