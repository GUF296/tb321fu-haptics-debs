#!/usr/bin/env python3
"""Exercise APT EIPP v3 with a real dpkg transaction in a disposable root."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import importlib.util
import os
import pathlib
import pwd
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VERIFIER_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"
HOOK_SOURCE = """#!/usr/bin/python3 -I
import os
import pathlib
import sys
fd_text = os.environ.get("APT_HOOK_INFO_FD", "")
if fd_text != "21":
    raise SystemExit("unexpected APT hook descriptor")
if len(sys.argv) != 3 or sys.argv[1] != "--capture":
    raise SystemExit("unexpected APT hook arguments")
remaining = 4 * 1024 * 1024 + 1
chunks = []
while remaining:
    chunk = os.read(21, min(remaining, 65536))
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
raw = b"".join(chunks)
if not raw or len(raw) > 4 * 1024 * 1024:
    raise SystemExit("invalid EIPP hook stream size")
path = pathlib.Path(sys.argv[2])
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
try:
    os.write(descriptor, raw)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
"""


def load_verifier():
    spec = importlib.util.spec_from_file_location("haptics_apt_transaction", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT transaction verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run(
    arguments: list[str],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"canary command timed out: {arguments[0]}") from exc


def require_success(result: subprocess.CompletedProcess[bytes], label: str) -> None:
    if result.returncode:
        raise SystemExit(
            f"{label} failed: " + result.stderr[:8192].decode("utf-8", errors="replace")
        )


def mkdir(path: pathlib.Path, mode: int = 0o755) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def run_with_unchanged_file_guard(
    path: pathlib.Path,
    label: str,
    callback: Callable[[], None],
) -> None:
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        callback()
    finally:
        try:
            after = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise SystemExit(f"{label} could not be rechecked") from exc
        if before != after:
            raise SystemExit(f"{label} changed during guarded execution")


def self_test_native_status_guard() -> None:
    with tempfile.TemporaryDirectory(
        prefix="tb321fu-haptics-eipp-native-guard-test."
    ) as raw:
        guarded = pathlib.Path(raw) / "status"
        guarded.write_bytes(b"before\n")

        def mutate_then_fail() -> None:
            guarded.write_bytes(b"after\n")
            raise RuntimeError("forced guard fixture failure")

        try:
            run_with_unchanged_file_guard(
                guarded,
                "native guard fixture",
                mutate_then_fail,
            )
        except SystemExit as exc:
            if "changed during guarded execution" not in str(exc) or not isinstance(
                exc.__context__, RuntimeError
            ):
                raise SystemExit(
                    "native-status guard lost its mutation or original failure evidence"
                ) from exc
        else:
            raise SystemExit("native-status guard accepted mutation on a failing path")
    print("HAPTICS_APT_EIPP_NATIVE_GUARD=PASS")


def run_disposable_canary(verifier, apt_account) -> None:

    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-eipp-canary.") as raw:
        work = pathlib.Path(raw)
        work.chmod(0o755)
        repo = work / "repo"
        package_root = work / "package"
        control = package_root / "DEBIAN"
        payload_dir = package_root / "usr/bin"
        rootfs = work / "rootfs"
        admin = rootfs / "var/lib/dpkg"
        info = admin / "info"
        updates = admin / "updates"
        triggers = admin / "triggers"
        parts = admin / "parts"
        logs = rootfs / "var/log"
        lists = work / "state/lists"
        archives = work / "cache/archives"
        source_parts = work / "source-parts"
        config_parts = work / "config-parts"
        trusted_parts = work / "trusted-parts"
        for directory in (
            repo,
            control,
            payload_dir,
            rootfs,
            admin,
            info,
            updates,
            triggers,
            parts,
            logs,
            lists / "partial",
            archives / "partial",
            source_parts,
            config_parts,
            trusted_parts,
        ):
            mkdir(directory)
        os.chown(lists / "partial", apt_account.pw_uid, 0)
        os.chown(archives / "partial", apt_account.pw_uid, 0)
        (lists / "partial").chmod(0o700)
        (archives / "partial").chmod(0o700)
        (admin / "status").write_bytes(b"")
        (admin / "status").chmod(0o644)
        (admin / "available").write_bytes(b"")
        (admin / "available").chmod(0o644)
        (control / "control").write_text(
            "Package: haptics-eipp-canary\n"
            "Version: 1.0-1\n"
            "Architecture: amd64\n"
            "Maintainer: Fixture <fixture@example.invalid>\n"
            "Description: Disposable EIPP canary\n",
            encoding="ascii",
        )
        payload = payload_dir / "haptics-eipp-canary"
        payload.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        payload.chmod(0o755)
        archive = repo / "haptics-eipp-canary_1.0-1_amd64.deb"
        base_environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(work),
            "TMPDIR": "/tmp",
            "SOURCE_DATE_EPOCH": "1",
            "DEBIAN_FRONTEND": "noninteractive",
        }
        require_success(
            run(
                [
                    "/usr/bin/dpkg-deb",
                    "--build",
                    "--root-owner-group",
                    str(package_root),
                    str(archive),
                ],
                cwd=work,
                environment=base_environment,
            ),
            "canary DEB build",
        )
        scan = run(
            ["/usr/bin/dpkg-scanpackages", ".", "/dev/null"],
            cwd=repo,
            environment=base_environment,
        )
        require_success(scan, "canary repository scan")
        archive_name = archive.name.encode("ascii")
        generated_filename = b"Filename: ./" + archive_name + b"\n"
        canonical_filename = b"Filename: " + archive_name + b"\n"
        if scan.stdout.count(generated_filename) != 1:
            raise SystemExit("canary repository scan produced an unexpected Filename field")
        packages = scan.stdout.replace(
            generated_filename,
            canonical_filename,
            1,
        )
        (repo / "Packages").write_bytes(packages)
        (repo / "Packages").chmod(0o644)

        sources = work / "sources.list"
        sources.write_text(f"deb [trusted=yes] file:{repo} ./\n", encoding="ascii")
        sources.chmod(0o644)
        empty = work / "empty.conf"
        empty.write_bytes(b"")
        empty.chmod(0o644)
        apt_config = work / "apt.conf"
        eipp_log = work / "eipp-v3.log"
        hook = work / "capture-eipp.py"
        hook.write_text(
            HOOK_SOURCE,
            encoding="ascii",
        )
        hook.chmod(0o755)
        hook_command = (
            f"/usr/bin/python3 -I -B {hook} --capture {eipp_log}"
        )
        apt_config.write_text(
            f'Dir::State::lists "{lists}";\n'
            f'Dir::State::status "{admin / "status"}";\n'
            f'Dir::Cache "{work / "cache"}";\n'
            f'Dir::Cache::archives "{archives}";\n'
            f'Dir::Etc::sourcelist "{sources}";\n'
            f'Dir::Etc::sourceparts "{source_parts}";\n'
            f'Dir::Etc::main "{empty}";\n'
            f'Dir::Etc::parts "{config_parts}";\n'
            'Dir::Etc::trusted "/dev/null";\n'
            f'Dir::Etc::trustedparts "{trusted_parts}";\n'
            'APT::Architecture "amd64";\n'
            'APT::Architectures { "amd64"; };\n'
            'APT::Get::AllowUnauthenticated "1";\n'
            'APT::Sandbox::User "_apt";\n'
            'Dir::Bin::dpkg "/usr/bin/dpkg";\n'
            'DPkg::ConfigurePending "1";\n'
            'DPkg::Path "/usr/sbin:/usr/bin:/sbin:/bin";\n'
            'DPkg::Run-Directory "/";\n'
            f'DPkg::Options:: "--root={rootfs}";\n'
            f'DPkg::Options:: "--admindir={admin}";\n'
            f'DPkg::Pre-Install-Pkgs:: "{hook_command}";\n'
            'DPkg::Tools::options::/usr/bin/python3::Version "3";\n'
            'DPkg::Tools::options::/usr/bin/python3::InfoFD "21";\n',
            encoding="ascii",
        )
        apt_config.chmod(0o600)
        apt_environment = dict(base_environment)
        apt_environment["APT_CONFIG"] = str(apt_config)
        apt_command = ["/usr/bin/apt-get", "-qq"]
        require_success(
            run(apt_command + ["update"], cwd=work, environment=apt_environment),
            "canary apt update",
        )
        require_success(
            run(
                apt_command
                + [
                    "-y",
                    "--download-only",
                    "install",
                    "--no-install-recommends",
                    "--no-remove",
                    str(archive),
                ],
                cwd=work,
                environment=apt_environment,
            ),
            "canary local-DEB download-only pass",
        )
        cached_debs = tuple(sorted(archives.glob("*.deb")))
        if cached_debs:
            raise SystemExit(
                "download-only duplicated a local DEB into the APT cache: "
                + repr(cached_debs)
            )
        require_success(
            run(
                apt_command
                + [
                    "-y",
                    "install",
                    "--no-install-recommends",
                    "--no-remove",
                    str(archive),
                ],
                cwd=work,
                environment=apt_environment,
            ),
            "canary apt install",
        )
        installed = rootfs / "usr/bin/haptics-eipp-canary"
        if not installed.is_file():
            raise SystemExit("disposable canary package was not installed")
        if not eipp_log.is_file():
            raise SystemExit("real disposable transaction did not execute the EIPP hook")
        eipp_raw = eipp_log.read_bytes()
        try:
            document = verifier.parse_eipp_v3_bytes(eipp_raw)
        except ValueError:
            after_separator = False
            for line in eipp_raw.splitlines():
                if line == b"":
                    after_separator = True
                    continue
                if b"%" in line:
                    print("EIPP_ESCAPED_LINE=" + repr(line[:2048]), file=sys.stderr)
                if after_separator:
                    print("EIPP_ACTION_LINE=" + repr(line[:2048]), file=sys.stderr)
            raise
        expected_actions = (
            verifier.PackageAction(
                "haptics-eipp-canary",
                None,
                None,
                None,
                "<",
                "1.0-1",
                "amd64",
                "no",
                str(archive),
            ),
            verifier.PackageAction(
                "haptics-eipp-canary",
                None,
                None,
                None,
                "<",
                "1.0-1",
                "amd64",
                "no",
                "**CONFIGURE**",
            ),
        )
        if document.actions != expected_actions:
            raise SystemExit(
                "real disposable transaction produced unexpected EIPP actions: "
                + repr(document.actions)
            )

def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("APT EIPP canary must run as root")
    verifier = load_verifier()
    apt_account = pwd.getpwnam("_apt")
    native_status = pathlib.Path("/var/lib/dpkg/status")
    run_with_unchanged_file_guard(
        native_status,
        "native dpkg status",
        lambda: run_disposable_canary(verifier, apt_account),
    )
    print("HAPTICS_APT_EIPP_CANARY=PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test-native-guard"]:
        self_test_native_status_guard()
    elif sys.argv[1:]:
        raise SystemExit("unknown APT EIPP canary mode")
    else:
        main()
