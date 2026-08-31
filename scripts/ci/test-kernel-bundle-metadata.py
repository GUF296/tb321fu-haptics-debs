#!/usr/bin/env python3
"""Hostile fixtures for the canonical TB321FU kernel bundle parser."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import pathlib
import select
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


SCRIPT = pathlib.Path(__file__).with_name("verify-kernel-bundle.py")
SPEC = importlib.util.spec_from_file_location("verify_kernel_bundle", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load kernel bundle verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

EXPECTED_TOOLCHAIN_TOOL_NAMES = (
    "gcc", "as", "ld", "ar", "nm", "objcopy", "objdump", "readelf",
    "strip", "rustc", "host-gcc", "host-gxx", "host-as", "host-ld",
    "host-ar", "flex", "bison", "m4", "awk", "perl", "python3",
    "pkg-config", "pahole", "git", "make", "depmod", "modinfo", "tar",
    "gzip", "xz", "dpkg-deb", "fdtget", "bash", "sh", "bc", "getconf",
    "sha1sum", "ln", "uname", "sha256sum", "find", "sort", "xargs",
    "rsync", "cp", "dpkg", "touch", "realpath", "nproc", "date",
    "install", "stat", "grep", "sed", "readlink", "wc", "tr", "cut",
    "findmnt", "curl", "flock", "mv", "chmod", "mkdir", "mktemp", "rm",
    "cat", "dirname", "basename", "env", "true", "cmp", "head", "expr",
    "uniq",
)
EXPECTED_TOOLCHAIN_FIELD_NAMES = (
    "schema", "cross-compile", "bison-data-directory", "bison-data-sha256",
) + tuple(
    field
    for tool in EXPECTED_TOOLCHAIN_TOOL_NAMES
    for field in (f"{tool}-sha256", f"{tool}-version")
)
EXPECTED_LIVE_TOOL_COMMANDS = {
    "gcc": "/usr/bin/aarch64-linux-gnu-gcc",
    "as": "/usr/bin/aarch64-linux-gnu-as",
    "ld": "/usr/bin/aarch64-linux-gnu-ld",
    "ar": "/usr/bin/aarch64-linux-gnu-ar",
    "nm": "/usr/bin/aarch64-linux-gnu-nm",
    "objcopy": "/usr/bin/aarch64-linux-gnu-objcopy",
    "objdump": "/usr/bin/aarch64-linux-gnu-objdump",
    "readelf": "/usr/bin/aarch64-linux-gnu-readelf",
    "strip": "/usr/bin/aarch64-linux-gnu-strip",
    "host-gcc": "/usr/bin/gcc",
    "host-as": "/usr/bin/as",
    "host-ld": "/usr/bin/ld",
    "host-ar": "/usr/bin/ar",
    "flex": "/usr/bin/flex",
    "bison": "/usr/bin/bison",
    "m4": "/usr/bin/m4",
    "awk": "/usr/bin/awk",
    "make": "/usr/bin/make",
    "bash": "/usr/bin/bash",
    "sh": "/usr/bin/sh",
    "tar": "/usr/bin/tar",
}
EXPECTED_NONZERO_VERSION_PROBE_STATUS = {"sh": 2}
REFERENCE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "HOME": "/nonexistent",
    "TMPDIR": "/tmp",
}
TEST_COMMAND_TIMEOUT_SECONDS = 60
REFERENCE_MAX_FILE_BYTES = 256 * 1024 * 1024
REFERENCE_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
REFERENCE_MAX_METADATA_BYTES = 64 * 1024
REFERENCE_MAX_LIVE_TOOL_BYTES = 256 * 1024 * 1024
REFERENCE_MAX_BISON_TAR_BYTES = 64 * 1024 * 1024
REFERENCE_MAX_BISON_ENTRIES = 4096
REFERENCE_MAX_BISON_LOGICAL_BYTES = 16 * 1024 * 1024
REFERENCE_MAX_BISON_DEPTH = 64


def run_bounded(
    arguments: list[str],
    *,
    timeout: float = TEST_COMMAND_TIMEOUT_SECONDS,
    maximum_output: int = REFERENCE_MAX_OUTPUT_BYTES,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    streams = {
        process.stdout.fileno(): (process.stdout, stdout),
        process.stderr.fileno(): (process.stderr, stderr),
    }
    all_streams = (process.stdout, process.stderr)
    deadline = time.monotonic() + timeout
    completed = False

    def terminate_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    try:
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, timeout)
            ready, _, _ = select.select(tuple(streams), (), (), remaining)
            if not ready:
                raise subprocess.TimeoutExpired(arguments, timeout)
            for descriptor in ready:
                stream, output = streams[descriptor]
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                output.extend(chunk)
                if len(output) > maximum_output:
                    raise SystemExit(
                        f"test command exceeded its output bound: {arguments[0]}"
                    )
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        completed = True
    except BaseException:
        terminate_group()
        raise
    finally:
        if completed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for stream in all_streams:
            if not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(
        arguments, returncode, bytes(stdout), bytes(stderr)
    )


def reference_file_digest(
    path: pathlib.Path,
    *,
    maximum: int = REFERENCE_MAX_FILE_BYTES,
    allow_symlink: bool = True,
) -> str:
    requested_before = path.lstat()
    if not (
        stat.S_ISREG(requested_before.st_mode)
        or (allow_symlink and stat.S_ISLNK(requested_before.st_mode))
    ):
        raise SystemExit(f"reference digest path has an unsafe type: {path}")
    resolved = path.resolve(strict=True)
    descriptor = os.open(
        resolved,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise SystemExit(f"reference digest target is not bounded: {path}")
        digest = hashlib.sha256()
        read_size = 0
        while read_size <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - read_size))
            if not chunk:
                break
            digest.update(chunk)
            read_size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    requested_after = path.lstat()
    resolved_after = path.resolve(strict=True)
    target_after = resolved_after.lstat()
    if (
        read_size != before.st_size
        or read_size > maximum
        or identity(before) != identity(after)
        or identity(requested_before) != identity(requested_after)
        or resolved_after != resolved
        or identity(target_after) != identity(after)
    ):
        raise SystemExit(f"reference digest path changed while reading: {path}")
    return digest.hexdigest()


def reference_command_identity(command: str, label: str) -> tuple[str, str]:
    digest = reference_file_digest(pathlib.Path(command))
    arguments = [command, "-W", "version"] if label == "awk" else [command, "--version"]
    result = run_bounded(
        arguments,
        timeout=10,
        maximum_output=64 * 1024,
        env=REFERENCE_ENV,
    )
    expected_status = EXPECTED_NONZERO_VERSION_PROBE_STATUS.get(label, 0)
    if result.returncode != expected_status:
        raise SystemExit(
            "reference live tool returned status "
            f"{result.returncode}, expected {expected_status}: {label}"
        )
    lines = (result.stdout + result.stderr).decode(
        "utf-8", errors="replace"
    ).splitlines()
    version = next((line for line in lines if line), "")
    if not version or len(version) > 255 or any(not 32 <= ord(char) <= 126 for char in version):
        raise SystemExit(f"reference live tool returned an invalid version: {label}")
    if reference_file_digest(pathlib.Path(command)) != digest:
        raise SystemExit(f"reference live tool changed during inspection: {label}")
    return digest, version


def reference_bison_data_sha256() -> str:
    result = run_bounded(
        [
            "/usr/bin/tar", "--sort=name", "--format=gnu", "--numeric-owner",
            "--owner=0", "--group=0", "--mtime=@0", "-C", "/usr/share/bison",
            "-cf", "-", ".",
        ],
        timeout=30,
        maximum_output=64 * 1024 * 1024,
        env=REFERENCE_ENV,
    )
    if result.returncode:
        raise SystemExit(f"reference Bison digest failed: {result.stderr!r}")
    return hashlib.sha256(result.stdout).hexdigest()


def make_bundle(**overrides: str) -> bytes:
    fields = [
        ("schema", "tb321fu.kernel-bundle/v2"),
        ("kernel-source-commit", "1" * 40),
        ("kernel-release", "7.1.1-g111111111111"),
        ("kernel-config-sha256", "2" * 64),
        ("kernel-image-sha256", "3" * 64),
        ("kernel-dtb-name", "sm8650-lenovo-tb321fu.dtb"),
        ("kernel-dtb-sha256", "4" * 64),
        ("kernel-modules-deb-sha256", "5" * 64),
        ("kernel-modules-manifest-sha256", "6" * 64),
        ("kernel-sdk-archive-sha256", "7" * 64),
        ("kernel-sdk-manifest-sha256", "8" * 64),
        ("kernel-toolchain-manifest-sha256", "9" * 64),
        ("kbuild-flags-sha256", "a" * 64),
        ("rustc-sha256", "b" * 64),
        ("rustc", "rustc 1.80.1 (3f5fd8dd4 2025-01-01)"),
        ("source-date-epoch", "1784073600"),
        ("kbuild-build-timestamp", "2026-07-15 00:00:00 UTC"),
        ("kbuild-build-user", "tb321fu-ci"),
        ("kbuild-build-host", "tb321fu-builder"),
        ("kbuild-build-version", "1"),
    ]
    fields = [(key, overrides.get(key, value)) for key, value in fields]
    identity = "".join(f"{key}\t{value}\n" for key, value in fields).encode("ascii")
    bundle_id = overrides.get("kernel-bundle-id", hashlib.sha256(identity).hexdigest())
    return identity + f"kernel-bundle-id\t{bundle_id}\n".encode("ascii")


def make_live_toolchain(**overrides: str) -> bytes:
    live = {
        label: reference_command_identity(command, label)
        for label, command in EXPECTED_LIVE_TOOL_COMMANDS.items()
    }
    fields: list[tuple[str, str]] = []
    bison_digest = reference_bison_data_sha256()
    false_digest = reference_file_digest(pathlib.Path("/usr/bin/false"), allow_symlink=False)
    for key in EXPECTED_TOOLCHAIN_FIELD_NAMES:
        if key == "schema":
            value = "tb321fu.kernel-toolchain/v2"
        elif key == "cross-compile":
            value = "/usr/bin/aarch64-linux-gnu-"
        elif key == "bison-data-directory":
            value = "/usr/share/bison"
        elif key == "bison-data-sha256":
            value = bison_digest
        else:
            label, kind = key.rsplit("-", 1)
            if label in live:
                value = live[label][0 if kind == "sha256" else 1]
            elif label == "rustc":
                value = false_digest if kind == "sha256" else "disabled"
            elif label == "pahole":
                value = "unused"
            else:
                value = "d" * 64 if kind == "sha256" else f"fixture {label} 1.0"
        fields.append((key, overrides.get(key, value)))
    return "".join(f"{key}\t{value}\n" for key, value in fields).encode("ascii")


def replace_toolchain_field(data: bytes, key: str, value: str) -> bytes:
    prefix = f"{key}\t".encode("ascii")
    replacement = f"{key}\t{value}\n".encode("ascii")
    lines = data.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError((key, matches))
    lines[matches[0]] = replacement
    return b"".join(lines)


def make_bundle_for_toolchain(data: bytes) -> bytes:
    values = dict(
        line.split("\t", 1)
        for line in data.decode("ascii").splitlines()
    )
    return make_bundle(
        **{
            "kernel-toolchain-manifest-sha256": hashlib.sha256(data).hexdigest(),
            "rustc-sha256": values["rustc-sha256"],
            "rustc": values["rustc-version"],
        }
    )


def run(bundle: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return run_bounded(
        [sys.executable, str(SCRIPT), str(bundle), *arguments],
        timeout=TEST_COMMAND_TIMEOUT_SECONDS,
        maximum_output=2 * 1024 * 1024,
    )


def require_failure(
    bundle: pathlib.Path, data: bytes, expected: bytes, *arguments: str
) -> None:
    bundle.write_bytes(data)
    result = run(bundle, *arguments)
    if result.returncode == 0 or expected not in result.stderr:
        raise SystemExit(
            f"fixture did not fail at {expected!r}: "
            f"status={result.returncode} stderr={result.stderr!r}"
        )


def require_toolchain_failure(
    bundle: pathlib.Path,
    toolchain: pathlib.Path,
    data: bytes,
    expected: bytes,
    *,
    verify_live: bool = False,
    bundle_data: bytes | None = None,
) -> None:
    toolchain.unlink(missing_ok=True)
    toolchain.write_bytes(data)
    bundle.write_bytes(bundle_data if bundle_data is not None else make_bundle())
    arguments = ["--toolchain", str(toolchain)]
    if verify_live:
        arguments.append("--verify-live-toolchain")
    result = run(bundle, *arguments)
    if result.returncode == 0 or expected not in result.stderr:
        raise SystemExit(
            f"toolchain fixture did not fail at {expected!r}: "
            f"status={result.returncode} stderr={result.stderr!r}"
        )


def wait_for_pid_file(path: pathlib.Path, label: str, timeout: float = 2.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            time.sleep(0.01)
            continue
        if text.isdecimal() and int(text) > 1:
            return int(text)
        raise SystemExit(f"{label} wrote an invalid descendant PID: {text!r}")
    raise SystemExit(f"{label} did not expose its descendant PID")


def require_pid_gone(pid: int, label: str, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    raise SystemExit(f"{label} left descendant PID {pid} running")


def main() -> None:
    actual_field_names = tuple(key for key, _ in VERIFIER.TOOLCHAIN_FIELDS)
    if len(actual_field_names) != 154:
        raise SystemExit("toolchain verifier does not expose the exact 154-field v2 schema")
    if len(set(actual_field_names)) != 154:
        raise SystemExit("toolchain verifier schema contains duplicate field names")
    if tuple(VERIFIER.TOOLCHAIN_TOOL_NAMES) != EXPECTED_TOOLCHAIN_TOOL_NAMES:
        raise SystemExit("toolchain verifier tool order differs from the producer contract")
    if actual_field_names != EXPECTED_TOOLCHAIN_FIELD_NAMES:
        raise SystemExit("toolchain verifier field order differs from the producer contract")
    if VERIFIER.LIVE_TOOL_COMMANDS != EXPECTED_LIVE_TOOL_COMMANDS:
        raise SystemExit("live-tool mapping differs from the external-module contract")
    if VERIFIER.NONZERO_VERSION_PROBE_STATUS != EXPECTED_NONZERO_VERSION_PROBE_STATUS:
        raise SystemExit("live-tool probe status contract differs from the independent oracle")
    if VERIFIER.CANONICAL_ENV != REFERENCE_ENV:
        raise SystemExit("live-tool environment differs from the independent oracle")
    expected_bounds = {
        "MAX_METADATA_BYTES": REFERENCE_MAX_METADATA_BYTES,
        "MAX_LIVE_TOOL_BYTES": REFERENCE_MAX_LIVE_TOOL_BYTES,
        "MAX_BISON_TAR_BYTES": REFERENCE_MAX_BISON_TAR_BYTES,
        "MAX_BISON_ENTRIES": REFERENCE_MAX_BISON_ENTRIES,
        "MAX_BISON_LOGICAL_BYTES": REFERENCE_MAX_BISON_LOGICAL_BYTES,
        "MAX_BISON_DEPTH": REFERENCE_MAX_BISON_DEPTH,
    }
    for name, expected in expected_bounds.items():
        if getattr(VERIFIER, name) != expected:
            raise SystemExit(f"{name} differs from the independent resource oracle")
    with tempfile.TemporaryDirectory(prefix="tb321fu-kernel-bundle-metadata.") as temp:
        root = pathlib.Path(temp)
        bundle = root / "KERNEL-BUNDLE.tsv"
        identical = root / "identical.tsv"
        toolchain = root / "KERNEL-TOOLCHAIN.tsv"
        valid = make_bundle()
        bundle.write_bytes(valid)
        identical.write_bytes(valid)

        boundary = root / "metadata-boundary.tsv"
        exact_boundary = b"x" * (REFERENCE_MAX_METADATA_BYTES - 1) + b"\n"
        boundary.write_bytes(exact_boundary)
        raw, _ = VERIFIER.read_ascii_regular(boundary, "boundary")
        if raw != exact_boundary:
            raise SystemExit("exact metadata byte boundary was not read completely")
        boundary.write_bytes(exact_boundary + b"x")
        try:
            VERIFIER.read_ascii_regular(boundary, "boundary")
        except VERIFIER.BundleError as exc:
            if "exceeds" not in str(exc):
                raise SystemExit(f"wrong oversized metadata rejection: {exc}") from exc
        else:
            raise SystemExit("metadata larger than the byte boundary was accepted")

        boundary.write_bytes(b"schema\tfixture\n")
        original_fstat = VERIFIER.os.fstat
        fstat_calls = 0

        class ChangedStat:
            def __init__(self, original: os.stat_result):
                self._original = original

            def __getattr__(self, name: str):
                if name == "st_ctime_ns":
                    return self._original.st_ctime_ns + 1
                return getattr(self._original, name)

        def changed_fstat(descriptor: int):
            nonlocal fstat_calls
            fstat_calls += 1
            result = original_fstat(descriptor)
            return ChangedStat(result) if fstat_calls == 2 else result

        VERIFIER.os.fstat = changed_fstat
        try:
            VERIFIER.read_ascii_regular(boundary, "boundary")
        except VERIFIER.BundleError as exc:
            if "changed while it was read" not in str(exc):
                raise SystemExit(f"wrong metadata race rejection: {exc}") from exc
        else:
            raise SystemExit("metadata identity drift while reading was accepted")
        finally:
            VERIFIER.os.fstat = original_fstat

        result = run(
            bundle,
            "--identical",
            str(identical),
            "--expect",
            "kernel-release=7.1.1-g111111111111",
            "--expect",
            "kernel-sdk-archive-sha256=" + "7" * 64,
            "--emit-tsv",
        )
        if result.returncode or result.stdout != valid:
            raise SystemExit(
                f"valid fixture failed: status={result.returncode} "
                f"stderr={result.stderr!r}"
            )

        live_toolchain = make_live_toolchain()
        toolchain.write_bytes(live_toolchain)
        live_bundle = make_bundle(
            **{
                "kernel-toolchain-manifest-sha256": hashlib.sha256(
                live_toolchain
                ).hexdigest(),
                "rustc-sha256": reference_file_digest(
                    pathlib.Path("/usr/bin/false"), allow_symlink=False
                ),
                "rustc": "disabled",
            }
        )
        bundle.write_bytes(live_bundle)
        result = run(
            bundle,
            "--toolchain",
            str(toolchain),
            "--verify-live-toolchain",
        )
        if result.returncode:
            raise SystemExit(f"live canonical toolchain failed: {result.stderr!r}")

        marker = root / "unexpected-tool-execution"
        hostile_tool = root / "hostile-tool"
        hostile_tool.write_text(f"#!/bin/sh\ntouch -- {marker}\n")
        hostile_tool.chmod(0o700)
        try:
            VERIFIER.command_identity(str(hostile_tool), "hostile", "0" * 64)
        except VERIFIER.BundleError as exc:
            if "SHA-256 differs" not in str(exc):
                raise SystemExit(f"wrong pre-execution tool rejection: {exc}") from exc
        else:
            raise SystemExit("wrong-digest live tool was accepted")
        if marker.exists():
            raise SystemExit("wrong-digest live tool executed before SHA-256 rejection")

        nonzero_tool = root / "nonzero-tool"
        nonzero_tool.write_text("#!/bin/sh\nprintf 'valid-looking version\\n'\nexit 7\n")
        nonzero_tool.chmod(0o700)
        nonzero_digest = hashlib.sha256(nonzero_tool.read_bytes()).hexdigest()
        try:
            VERIFIER.command_identity(str(nonzero_tool), "nonzero", nonzero_digest)
        except VERIFIER.BundleError as exc:
            if "returned status 7, expected 0" not in str(exc):
                raise SystemExit(f"wrong nonzero probe-status rejection: {exc}") from exc
        else:
            raise SystemExit("valid-looking nonzero live-tool probe was accepted")

        timeout_pid_file = root / "timeout-descendant.pid"
        timeout_tool = root / "timeout-tool"
        timeout_tool.write_text(
            "#!/bin/sh\n"
            "/usr/bin/sleep 30 &\n"
            f"printf '%s\\n' \"$!\" > {shlex.quote(str(timeout_pid_file))}\n"
            "printf 'ready\\n'\n"
            "exec /usr/bin/sleep 30\n"
        )
        timeout_tool.chmod(0o700)
        timeout_digest = hashlib.sha256(timeout_tool.read_bytes()).hexdigest()
        previous_timeout = VERIFIER.LIVE_TOOL_TIMEOUT_SECONDS
        VERIFIER.LIVE_TOOL_TIMEOUT_SECONDS = 0.05
        try:
            VERIFIER.command_identity(str(timeout_tool), "timeout", timeout_digest)
        except VERIFIER.BundleError as exc:
            if "version probe timed out" not in str(exc):
                raise SystemExit(f"wrong live-tool timeout rejection: {exc}") from exc
        else:
            raise SystemExit("hanging live-tool version probe was accepted")
        finally:
            VERIFIER.LIVE_TOOL_TIMEOUT_SECONDS = previous_timeout
        timeout_pid = wait_for_pid_file(timeout_pid_file, "live-tool timeout fixture")
        require_pid_gone(timeout_pid, "live-tool timeout")

        flood_tool = root / "flood-tool"
        flood_tool.write_text(
            "#!/bin/sh\n"
            "while :; do printf '0123456789abcdef0123456789abcdef\\n'; done\n"
        )
        flood_tool.chmod(0o700)
        flood_digest = hashlib.sha256(flood_tool.read_bytes()).hexdigest()
        try:
            VERIFIER.command_identity(str(flood_tool), "flood", flood_digest)
        except VERIFIER.BundleError as exc:
            if "stdout exceeds its size bound" not in str(exc):
                raise SystemExit(f"wrong live-tool output-bound rejection: {exc}") from exc
        else:
            raise SystemExit("unbounded live-tool version output was accepted")

        retarget_command = root / "retarget-command"
        retarget_first = root / "retarget-first"
        retarget_second = root / "retarget-second"
        first_marker = root / "retarget-first.executed"
        second_marker = root / "retarget-second.executed"
        retarget_second.write_text(
            "#!/bin/sh\n"
            f"/usr/bin/touch -- {shlex.quote(str(second_marker))}\n"
            "printf 'second version\\n'\n"
        )
        retarget_second.chmod(0o700)
        retarget_first.write_text(
            "#!/bin/sh\n"
            f"/usr/bin/touch -- {shlex.quote(str(first_marker))}\n"
            "printf 'first version\\n'\n"
        )
        retarget_first.chmod(0o700)
        retarget_command.symlink_to(retarget_first)
        retarget_digest = hashlib.sha256(retarget_first.read_bytes()).hexdigest()
        original_bounded_command = VERIFIER._bounded_command
        retargeted_before_popen = False

        def retarget_before_popen(*args, **kwargs):
            nonlocal retargeted_before_popen
            if not retargeted_before_popen:
                retarget_command.unlink()
                retarget_command.symlink_to(retarget_second)
                retargeted_before_popen = True
            return original_bounded_command(*args, **kwargs)

        VERIFIER._bounded_command = retarget_before_popen
        try:
            VERIFIER.command_identity(
                str(retarget_command), "retarget", retarget_digest
            )
        except VERIFIER.BundleError as exc:
            if "changed during inspection" not in str(exc):
                raise SystemExit(f"wrong command-retarget rejection: {exc}") from exc
        else:
            raise SystemExit("live-tool command retargeting was accepted")
        finally:
            VERIFIER._bounded_command = original_bounded_command
        if not retargeted_before_popen:
            raise SystemExit("retarget fixture did not reach its pre-Popen barrier")
        if not first_marker.exists() or second_marker.exists():
            raise SystemExit("live-tool probe did not execute the verified descriptor inode")

        cleanup_tool = root / "cleanup-tool"
        cleanup_pid_file = root / "select-failure-descendant.pid"
        cleanup_tool.write_text(
            "#!/bin/sh\n"
            "/usr/bin/sleep 30 &\n"
            f"printf '%s\\n' \"$!\" > {shlex.quote(str(cleanup_pid_file))}\n"
            "exec /usr/bin/sleep 30\n"
        )
        cleanup_tool.chmod(0o700)
        original_select = VERIFIER.select.select

        def broken_select(*_args, **_kwargs):
            wait_for_pid_file(cleanup_pid_file, "select-failure fixture")
            raise OSError("fixture select failure")

        VERIFIER.select.select = broken_select
        try:
            VERIFIER._bounded_command(
                ["/bin/sh", str(cleanup_tool)],
                "select-failure fixture",
                timeout=1,
                max_stdout=1024,
                max_stderr=1024,
            )
        except OSError as exc:
            if "fixture select failure" not in str(exc):
                raise SystemExit(f"wrong select failure propagated: {exc}") from exc
        else:
            raise SystemExit("select failure was accepted")
        finally:
            VERIFIER.select.select = original_select
        cleanup_pid = wait_for_pid_file(cleanup_pid_file, "select-failure fixture")
        require_pid_gone(cleanup_pid, "select failure")

        original_read = VERIFIER.os.read

        def broken_read(*_args, **_kwargs):
            raise OSError("fixture read failure")

        read_failure_tool = root / "read-failure-tool"
        read_failure_pid_file = root / "read-failure-descendant.pid"
        read_failure_tool.write_text(
            "#!/bin/sh\n"
            "/usr/bin/sleep 30 &\n"
            f"printf '%s\\n' \"$!\" > {shlex.quote(str(read_failure_pid_file))}\n"
            "printf 'ready\\n'\n"
            "exec /usr/bin/sleep 30\n"
        )
        read_failure_tool.chmod(0o700)

        def arm_broken_read(*args, **kwargs):
            ready = original_select(*args, **kwargs)
            wait_for_pid_file(read_failure_pid_file, "read-failure fixture")
            VERIFIER.os.read = broken_read
            return ready

        VERIFIER.select.select = arm_broken_read
        try:
            VERIFIER._bounded_command(
                ["/bin/sh", str(read_failure_tool)],
                "read-failure fixture",
                timeout=1,
                max_stdout=1024,
                max_stderr=1024,
            )
        except OSError as exc:
            if "fixture read failure" not in str(exc):
                raise SystemExit(f"wrong read failure propagated: {exc}") from exc
        else:
            raise SystemExit("read failure was accepted")
        finally:
            VERIFIER.os.read = original_read
            VERIFIER.select.select = original_select
        read_failure_pid = wait_for_pid_file(
            read_failure_pid_file, "read-failure fixture"
        )
        require_pid_gone(read_failure_pid, "read failure")

        pipe_closing_pid_file = root / "pipe-closing-descendant.pid"
        pipe_closing_tool = root / "pipe-closing-tool"
        pipe_closing_tool.write_text(
            "#!/bin/sh\n"
            "/usr/bin/sleep 30 </dev/null >/dev/null 2>&1 &\n"
            f"printf '%s\\n' \"$!\" > {shlex.quote(str(pipe_closing_pid_file))}\n"
            "exit 0\n"
        )
        pipe_closing_tool.chmod(0o700)
        result_code, _, _ = VERIFIER._bounded_command(
            ["/bin/sh", str(pipe_closing_tool)],
            "pipe-closing descendant fixture",
            timeout=1,
            max_stdout=1024,
            max_stderr=1024,
        )
        if result_code != 0:
            raise SystemExit("pipe-closing parent did not exit successfully")
        pipe_closing_pid = wait_for_pid_file(
            pipe_closing_pid_file, "pipe-closing fixture"
        )
        require_pid_gone(pipe_closing_pid, "successful parent")

        bison_fixture = root / "bison-data"
        bison_fixture.mkdir(mode=0o755)
        (bison_fixture / "data").write_bytes(b"fixture\n")
        (bison_fixture / "data").chmod(0o644)
        fixture_uid = os.getuid()
        fixture_gid = os.getgid()

        def fixture_bison_digest(
            directory: pathlib.Path,
            tar_expected_digest: str | None = None,
            tar_command: pathlib.Path = pathlib.Path("/usr/bin/tar"),
        ) -> str:
            return VERIFIER.canonical_bison_data_sha256(
                directory,
                tar_expected_digest,
                tar_command,
                expected_uid=fixture_uid,
                expected_gid=fixture_gid,
            )

        def require_bison_failure(
            directory: pathlib.Path, expected: str,
        ) -> None:
            try:
                fixture_bison_digest(directory)
            except VERIFIER.BundleError as exc:
                if expected not in str(exc):
                    raise SystemExit(
                        f"wrong Bison boundary rejection: {exc}"
                    ) from exc
            else:
                raise SystemExit(
                    f"unsafe Bison fixture was accepted: {directory}"
                )

        def bison_directory(
            name: str,
            *,
            mode: int = 0o755,
            uid: int = 0,
            gid: int = 0,
            mtime: int = 0,
        ) -> tuple[tarfile.TarInfo, None]:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = mode
            member.uid = uid
            member.gid = gid
            member.mtime = mtime
            member.size = 0
            return member, None

        def bison_regular(
            name: str,
            payload: bytes = b"fixture\n",
            *,
            mode: int = 0o644,
            uid: int = 0,
            gid: int = 0,
            mtime: int = 0,
        ) -> tuple[tarfile.TarInfo, bytes]:
            member = tarfile.TarInfo(name)
            member.type = tarfile.REGTYPE
            member.mode = mode
            member.uid = uid
            member.gid = gid
            member.mtime = mtime
            member.size = len(payload)
            return member, payload

        def render_bison_tar(
            members: list[tuple[tarfile.TarInfo, bytes | None]],
            *,
            archive_format: int = tarfile.GNU_FORMAT,
        ) -> bytes:
            stream = io.BytesIO()
            with tarfile.open(
                fileobj=stream, mode="w", format=archive_format
            ) as archive:
                for member, payload in members:
                    archive.addfile(
                        member,
                        io.BytesIO(payload) if payload is not None else None,
                    )
            return stream.getvalue()

        def require_bison_stream_failure(
            raw: bytes,
            expected: str,
            *,
            expected_count: int = 2,
            expected_size: int = len(b"fixture\n"),
        ) -> None:
            try:
                VERIFIER.validate_bison_tar_stream(
                    raw,
                    expected_entry_count=expected_count,
                    expected_logical_size=expected_size,
                )
            except VERIFIER.BundleError as exc:
                if expected not in str(exc):
                    raise SystemExit(
                        f"wrong Bison tar-stream rejection: {exc}"
                    ) from exc
            else:
                raise SystemExit("unsafe Bison tar stream was accepted")

        canonical_bison_tar = render_bison_tar(
            [bison_directory("."), bison_regular("./data")]
        )
        VERIFIER.validate_bison_tar_stream(
            canonical_bison_tar,
            expected_entry_count=2,
            expected_logical_size=len(b"fixture\n"),
        )
        nested_prefix_bison_tar = render_bison_tar(
            [
                bison_directory("."),
                bison_directory("./a"),
                bison_regular("./a/data"),
                bison_regular("./a-z"),
            ]
        )
        VERIFIER.validate_bison_tar_stream(
            nested_prefix_bison_tar,
            expected_entry_count=4,
            expected_logical_size=2 * len(b"fixture\n"),
        )
        require_bison_stream_failure(
            render_bison_tar(
                [
                    bison_directory("."),
                    bison_regular("./data"),
                    bison_regular("./data"),
                ]
            ),
            "duplicate member",
            expected_count=3,
            expected_size=2 * len(b"fixture\n"),
        )
        require_bison_stream_failure(
            render_bison_tar(
                [
                    bison_directory("."),
                    bison_directory("./nested"),
                    bison_regular("./nested/z-data"),
                    bison_regular("./nested/a-data"),
                ]
            ),
            "canonical order",
            expected_count=4,
            expected_size=2 * len(b"fixture\n"),
        )
        require_bison_stream_failure(
            render_bison_tar(
                [
                    bison_directory("."),
                    bison_directory("./a"),
                    bison_regular("./a/data"),
                    bison_regular("./a-z"),
                    bison_regular("./a/late"),
                ]
            ),
            "canonical depth-first order",
            expected_count=5,
            expected_size=3 * len(b"fixture\n"),
        )
        require_bison_stream_failure(
            render_bison_tar(
                [
                    bison_directory("."),
                    bison_regular("./z-data"),
                    bison_regular("./a-data"),
                ]
            ),
            "canonical order",
            expected_count=3,
            expected_size=2 * len(b"fixture\n"),
        )
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), bison_regular("./nested/data")]
            ),
            "missing its parent directory",
        )
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), bison_regular("./../escape")]
            ),
            "unsafe member path",
        )

        linked_member = tarfile.TarInfo("./linked")
        linked_member.type = tarfile.SYMTYPE
        linked_member.mode = 0o777
        linked_member.uid = linked_member.gid = linked_member.mtime = 0
        linked_member.linkname = "data"
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), (linked_member, None)]
            ),
            "unsupported member type",
            expected_size=0,
        )
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), bison_regular("./data", mode=0o600)]
            ),
            "unexpected file mode",
        )
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), bison_regular("./data", uid=1)]
            ),
            "unexpected owner",
        )
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), bison_regular("./data", mtime=1)]
            ),
            "unexpected timestamp",
        )

        sparse_member = tarfile.TarInfo("./sparse")
        sparse_member.type = tarfile.GNUTYPE_SPARSE
        sparse_member.mode = 0o644
        sparse_member.uid = sparse_member.gid = sparse_member.mtime = 0
        sparse_member.size = 0
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), (sparse_member, None)]
            ),
            "sparse member",
            expected_size=0,
        )

        pax_member, pax_payload = bison_regular("./pax-data")
        pax_member.pax_headers = {"comment": "fixture"}
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), (pax_member, pax_payload)],
                archive_format=tarfile.PAX_FORMAT,
            ),
            "extended PAX metadata",
        )
        require_bison_stream_failure(
            render_bison_tar(
                [bison_directory("."), bison_regular("./" + "x" * 101)]
            ),
            "noncanonical header layout",
        )
        require_bison_stream_failure(
            canonical_bison_tar + b"x" * tarfile.BLOCKSIZE,
            "invalid end marker or trailing data",
        )
        require_bison_stream_failure(
            canonical_bison_tar,
            "entry count differs from the scanned tree",
            expected_count=3,
        )
        require_bison_stream_failure(
            canonical_bison_tar,
            "logical size differs from the scanned tree",
            expected_size=len(b"fixture\n") + 1,
        )

        original_entry_limit = VERIFIER.MAX_BISON_ENTRIES
        VERIFIER.MAX_BISON_ENTRIES = 1
        try:
            require_bison_stream_failure(
                canonical_bison_tar, "unsafe entry count"
            )
        finally:
            VERIFIER.MAX_BISON_ENTRIES = original_entry_limit
        original_logical_limit = VERIFIER.MAX_BISON_LOGICAL_BYTES
        VERIFIER.MAX_BISON_LOGICAL_BYTES = len(b"fixture\n") - 1
        try:
            require_bison_stream_failure(
                canonical_bison_tar, "unsafe logical size"
            )
        finally:
            VERIFIER.MAX_BISON_LOGICAL_BYTES = original_logical_limit

        fixture_bison_digest(bison_fixture)
        nested_bison_fixture = root / "nested-bison-data"
        (nested_bison_fixture / "a").mkdir(parents=True, mode=0o755)
        (nested_bison_fixture / "a" / "data").write_bytes(b"fixture\n")
        (nested_bison_fixture / "a" / "data").chmod(0o644)
        (nested_bison_fixture / "a-z").write_bytes(b"fixture\n")
        (nested_bison_fixture / "a-z").chmod(0o644)
        fixture_bison_digest(nested_bison_fixture)
        forged_bison_tar = render_bison_tar(
            [
                bison_directory("."),
                bison_regular("./data"),
                bison_regular("./extra", b""),
            ]
        )
        original_stream_command = VERIFIER._bounded_command

        def return_forged_bison_stream(*_args, **_kwargs):
            return 0, forged_bison_tar, b""

        VERIFIER._bounded_command = return_forged_bison_stream
        try:
            require_bison_failure(
                bison_fixture,
                "entry count differs from the scanned tree",
            )
        finally:
            VERIFIER._bounded_command = original_stream_command

        bison_fixture.chmod(0o775)
        require_bison_failure(bison_fixture, "canonical root-owned mode-0755")
        bison_fixture.chmod(0o755)

        bison_hardlink = root / "bison-hardlink"
        bison_hardlink.mkdir(mode=0o755)
        bison_hardlink_target = root / "bison-hardlink-target"
        bison_hardlink_target.write_bytes(b"hard-linked Bison data\n")
        bison_hardlink_target.chmod(0o644)
        os.link(bison_hardlink_target, bison_hardlink / "alias")
        original_hardlink_command = VERIFIER._bounded_command
        hardlink_tar_started = False

        def reject_hardlink_tar(*_args, **_kwargs):
            nonlocal hardlink_tar_started
            hardlink_tar_started = True
            raise SystemExit("Bison hardlink rejection started tar")

        VERIFIER._bounded_command = reject_hardlink_tar
        try:
            require_bison_failure(bison_hardlink, "hard-linked file")
        finally:
            VERIFIER._bounded_command = original_hardlink_command
        if hardlink_tar_started:
            raise SystemExit("Bison hardlink was not rejected before tar")

        bison_descriptor = os.open(
            bison_fixture,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            VERIFIER.scan_bison_tree(
                bison_descriptor,
                expected_uid=fixture_uid + 1,
                expected_gid=fixture_gid,
            )
        except VERIFIER.BundleError as exc:
            if "unexpected owner" not in str(exc):
                raise SystemExit(
                    f"wrong non-root-capable Bison owner rejection: {exc}"
                ) from exc
        else:
            raise SystemExit("Bison nested owner mismatch was accepted")
        finally:
            os.close(bison_descriptor)

        bison_link = root / "bison-link"
        bison_link.symlink_to(bison_fixture, target_is_directory=True)
        require_bison_failure(bison_link, "cannot open Bison data directory")
        if fixture_uid == 0:
            os.chown(bison_fixture, 65534, 65534)
            require_bison_failure(bison_fixture, "canonical root-owned mode-0755")
            os.chown(bison_fixture, fixture_uid, fixture_gid)
            data_path = bison_fixture / "data"
            os.chown(data_path, 65534, 65534)
            try:
                fixture_bison_digest(bison_fixture)
            except VERIFIER.BundleError as exc:
                if "unexpected owner" not in str(exc):
                    raise SystemExit(
                        f"wrong Bison nested-owner rejection: {exc}"
                    ) from exc
            else:
                raise SystemExit("Bison nested non-root owner was accepted")
            os.chown(data_path, fixture_uid, fixture_gid)

        original_bounded_command = VERIFIER._bounded_command

        def timed_out_bison(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        VERIFIER._bounded_command = timed_out_bison
        try:
            fixture_bison_digest(bison_fixture)
        except VERIFIER.BundleError as exc:
            if "Bison data tree hash timed out" not in str(exc):
                raise SystemExit(f"wrong Bison hash timeout rejection: {exc}") from exc
        else:
            raise SystemExit("timed-out Bison data hash was accepted")
        finally:
            VERIFIER._bounded_command = original_bounded_command

        bison_overflow = root / "bison-overflow"
        bison_overflow.mkdir(mode=0o755)
        for index in range(REFERENCE_MAX_BISON_ENTRIES + 128):
            (bison_overflow / f"entry-{index:05d}").touch(mode=0o644)
        original_scandir = VERIFIER.os.scandir
        scandir_yields = 0

        class CountingScandir:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args):
                return self.wrapped.__exit__(*args)

            def __iter__(self):
                return self

            def __next__(self):
                nonlocal scandir_yields
                value = next(self.wrapped)
                scandir_yields += 1
                return value

        def counting_scandir(descriptor):
            return CountingScandir(original_scandir(descriptor))

        VERIFIER.os.scandir = counting_scandir
        try:
            fixture_bison_digest(bison_overflow)
        except VERIFIER.BundleError as exc:
            if "unsafe entry count" not in str(exc):
                raise SystemExit(f"wrong Bison entry-limit rejection: {exc}") from exc
        else:
            raise SystemExit("oversized Bison entry set was accepted")
        finally:
            VERIFIER.os.scandir = original_scandir
        if scandir_yields != REFERENCE_MAX_BISON_ENTRIES:
            raise SystemExit(
                "Bison entry limit was not enforced at the first excess entry: "
                f"yielded={scandir_yields}"
            )

        def failed_scandir(_descriptor):
            raise OSError("fixture traversal failure")

        VERIFIER.os.scandir = failed_scandir
        try:
            fixture_bison_digest(bison_fixture)
        except VERIFIER.BundleError as exc:
            if "cannot scan Bison data tree" not in str(exc):
                raise SystemExit(f"wrong Bison traversal failure: {exc}") from exc
        else:
            raise SystemExit("Bison traversal failure was ignored")
        finally:
            VERIFIER.os.scandir = original_scandir

        cross_device_metadata = (bison_fixture / "data").lstat()

        class CrossDeviceEntry:
            name = "data"

            @staticmethod
            def stat(*, follow_symlinks):
                if follow_symlinks:
                    raise SystemExit("cross-device fixture followed a directory entry")
                values = list(cross_device_metadata)
                values[2] = cross_device_metadata.st_dev + 1
                return os.stat_result(values)

        class CrossDeviceScandir:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def __iter__(self):
                return iter((CrossDeviceEntry(),))

        VERIFIER.os.scandir = lambda _descriptor: CrossDeviceScandir()
        try:
            fixture_bison_digest(bison_fixture)
        except VERIFIER.BundleError as exc:
            if "cross-device entry" not in str(exc):
                raise SystemExit(f"wrong cross-device Bison rejection: {exc}") from exc
        else:
            raise SystemExit("cross-device Bison entry was accepted")
        finally:
            VERIFIER.os.scandir = original_scandir

        tar_link = root / "fixture-tar"
        tar_first = root / "fixture-tar-first"
        tar_second = root / "fixture-tar-second"
        tar_second.write_text("#!/bin/sh\nprintf 'second tar output'\n")
        tar_second.chmod(0o700)
        tar_first.write_text(
            "#!/bin/sh\n"
            f"/usr/bin/ln -sfn -- {shlex.quote(str(tar_second))} "
            f"{shlex.quote(str(tar_link))}\n"
            "printf 'first tar output'\n"
        )
        tar_first.chmod(0o700)
        tar_link.symlink_to(tar_first)
        try:
            fixture_bison_digest(
                bison_fixture,
                reference_file_digest(tar_first, allow_symlink=False),
                tar_link,
            )
        except VERIFIER.BundleError as exc:
            if "changed during inspection" not in str(exc):
                raise SystemExit(f"wrong Bison tar retarget rejection: {exc}") from exc
        else:
            raise SystemExit("Bison hash accepted a retargeted tar command")

        rust_sentinel = root / "rust-disabled-sentinel"
        rust_sentinel.write_bytes(b"disabled sentinel\n")
        rust_digest = reference_file_digest(rust_sentinel, allow_symlink=False)
        VERIFIER.verify_disabled_rust_sentinel(rust_sentinel, rust_digest)
        rust_link = root / "rust-disabled-link"
        rust_link.symlink_to(rust_sentinel)
        try:
            VERIFIER.verify_disabled_rust_sentinel(rust_link, rust_digest)
        except VERIFIER.BundleError as exc:
            if "unsupported type" not in str(exc):
                raise SystemExit(f"wrong Rust symlink rejection: {exc}") from exc
        else:
            raise SystemExit("Rust-disabled sentinel symlink was accepted")
        rust_fifo = root / "rust-disabled-fifo"
        os.mkfifo(rust_fifo)
        try:
            VERIFIER.verify_disabled_rust_sentinel(rust_fifo, rust_digest)
        except VERIFIER.BundleError as exc:
            if "unsupported type" not in str(exc):
                raise SystemExit(f"wrong Rust FIFO rejection: {exc}") from exc
        else:
            raise SystemExit("Rust-disabled sentinel FIFO was accepted")
        rust_oversized = root / "rust-disabled-oversized"
        rust_oversized.write_bytes(b"12345")
        try:
            VERIFIER.verify_disabled_rust_sentinel(
                rust_oversized, hashlib.sha256(b"12345").hexdigest(), maximum=4
            )
        except VERIFIER.BundleError as exc:
            if "not a bounded regular file" not in str(exc):
                raise SystemExit(f"wrong Rust size rejection: {exc}") from exc
        else:
            raise SystemExit("oversized Rust-disabled sentinel was accepted")
        original_digest_descriptor = VERIFIER.digest_descriptor
        digest_calls = 0

        def mutate_after_digest(descriptor, label, maximum=REFERENCE_MAX_LIVE_TOOL_BYTES):
            nonlocal digest_calls
            result = original_digest_descriptor(descriptor, label, maximum)
            digest_calls += 1
            if digest_calls == 1:
                rust_sentinel.write_bytes(b"changed sentinel\n")
            return result

        VERIFIER.digest_descriptor = mutate_after_digest
        try:
            VERIFIER.verify_disabled_rust_sentinel(rust_sentinel, rust_digest)
        except VERIFIER.BundleError as exc:
            if "changed during inspection" not in str(exc):
                raise SystemExit(f"wrong Rust mutation rejection: {exc}") from exc
        else:
            raise SystemExit("changing Rust-disabled sentinel was accepted")
        finally:
            VERIFIER.digest_descriptor = original_digest_descriptor

        require_toolchain_failure(
            bundle,
            toolchain,
            live_toolchain,
            b"toolchain manifest SHA-256 mismatch",
            bundle_data=make_bundle(),
        )
        for label in EXPECTED_LIVE_TOOL_COMMANDS:
            candidate = replace_toolchain_field(
                live_toolchain, f"{label}-sha256", "0" * 64
            )
            require_toolchain_failure(
                bundle,
                toolchain,
                candidate,
                f"live tool SHA-256 differs from manifest: {label}".encode(),
                verify_live=True,
                bundle_data=make_bundle_for_toolchain(candidate),
            )
        wrong_gcc_version = replace_toolchain_field(
            live_toolchain, "gcc-version", "fixture compiler version"
        )
        require_toolchain_failure(
            bundle,
            toolchain,
            wrong_gcc_version,
            b"live tool version differs from manifest: gcc",
            verify_live=True,
            bundle_data=make_bundle_for_toolchain(wrong_gcc_version),
        )
        wrong_bison_tree = replace_toolchain_field(
            live_toolchain, "bison-data-sha256", "0" * 64
        )
        require_toolchain_failure(
            bundle,
            toolchain,
            wrong_bison_tree,
            b"live Bison data tree differs from manifest",
            verify_live=True,
            bundle_data=make_bundle_for_toolchain(wrong_bison_tree),
        )
        wrong_rust_sentinel = replace_toolchain_field(
            live_toolchain, "rustc-sha256", "0" * 64
        )
        require_toolchain_failure(
            bundle,
            toolchain,
            wrong_rust_sentinel,
            b"live Rust-disabled sentinel differs from manifest",
            verify_live=True,
            bundle_data=make_bundle_for_toolchain(wrong_rust_sentinel),
        )

        semantic_failures = (
            (
                replace_toolchain_field(
                    live_toolchain, "cross-compile", "/usr/bin/wrong-prefix-"
                ),
                b"cross-compile is not the canonical absolute prefix",
            ),
            (
                replace_toolchain_field(
                    live_toolchain, "bison-data-directory", "/usr/share/wrong-bison"
                ),
                b"Bison data directory is not canonical",
            ),
            (
                replace_toolchain_field(live_toolchain, "rustc-version", "enabled"),
                b"Rust-disabled sentinel",
            ),
            (
                replace_toolchain_field(live_toolchain, "pahole-version", "pahole 1.0"),
                b"pahole unused state is inconsistent",
            ),
        )
        for candidate, expected in semantic_failures:
            require_toolchain_failure(bundle, toolchain, candidate, expected)

        lines = live_toolchain.splitlines(keepends=True)
        reordered = lines.copy()
        reordered[4], reordered[5] = reordered[5], reordered[4]
        malformed_toolchains = (
            (b"".join(reordered), b"field 5 must be gcc-sha256"),
            (
                live_toolchain.replace(b"cross-compile\t", b"schema\t", 1),
                b"field 2 must be cross-compile",
            ),
            (b"".join(lines[:-1]), b"fields, expected"),
            (live_toolchain + b"extra\tfield\n", b"fields, expected"),
            (
                live_toolchain.replace(b"schema\t", b"schema\textra\t", 1),
                b"exactly one tab",
            ),
            (live_toolchain[:-1], b"must end with LF"),
            (live_toolchain.replace(b"\n", b"\r\n"), b"contains CR"),
            (live_toolchain.replace(b"gcc-version\t", b"gcc-version\tbad\x00", 1), b"contains NUL"),
            (live_toolchain.replace(b"gcc-version\t", b"gcc-version\t\xff", 1), b"ASCII only"),
            (live_toolchain + b"x" * 65536, b"exceeds 65536 bytes"),
        )
        for candidate, expected in malformed_toolchains:
            require_toolchain_failure(bundle, toolchain, candidate, expected)

        exact_tool_version = replace_toolchain_field(
            live_toolchain, "cat-version", "v" * 255
        )
        toolchain.write_bytes(exact_tool_version)
        bundle.write_bytes(make_bundle_for_toolchain(exact_tool_version))
        result = run(bundle, "--toolchain", str(toolchain))
        if result.returncode:
            raise SystemExit(
                f"exact 255-byte tool version failed: {result.stderr!r}"
            )
        require_toolchain_failure(
            bundle,
            toolchain,
            replace_toolchain_field(live_toolchain, "cat-version", "v" * 256),
            b"invalid toolchain manifest cat-version",
        )

        target = root / "toolchain-target.tsv"
        target.write_bytes(live_toolchain)
        toolchain.unlink(missing_ok=True)
        toolchain.symlink_to(target)
        result = run(bundle, "--toolchain", str(toolchain))
        if result.returncode == 0 or b"cannot open toolchain manifest" not in result.stderr:
            raise SystemExit("symlink toolchain manifest was accepted")
        toolchain.unlink()
        os.mkfifo(toolchain)
        result = run(bundle, "--toolchain", str(toolchain))
        if result.returncode == 0 or b"must be a regular file" not in result.stderr:
            raise SystemExit("FIFO toolchain manifest was accepted")
        toolchain.unlink()

        require_failure(bundle, valid[:-1], b"must end with LF")
        require_failure(bundle, valid.replace(b"\n", b"\r\n"), b"contains CR")
        require_failure(
            bundle,
            valid.replace(b"schema\t", b"kernel-release\t", 1),
            b"field 1 must be schema",
        )
        require_failure(
            bundle,
            valid.replace(b"schema\t", b"schema\textra\t", 1),
            b"exactly one tab",
        )
        require_failure(
            bundle,
            make_bundle(**{"kbuild-build-timestamp": "$(touch owned)"}),
            b"invalid bundle kbuild-build-timestamp",
        )
        require_failure(
            bundle,
            make_bundle(**{"kernel-sdk-archive-sha256": "not-a-digest"}),
            b"invalid bundle kernel-sdk-archive-sha256",
        )
        require_failure(
            bundle,
            make_bundle(**{"kernel-dtb-name": "sm8650-lenovo-tb321fu.bin"}),
            b"invalid bundle kernel-dtb-name",
        )
        exact_release = "1" + "r" * 63
        bundle.write_bytes(make_bundle(**{"kernel-release": exact_release}))
        result = run(bundle)
        if result.returncode:
            raise SystemExit(f"exact 64-byte kernel release failed: {result.stderr!r}")
        require_failure(
            bundle,
            make_bundle(**{"kernel-release": "1" + "r" * 64}),
            b"invalid bundle kernel-release",
        )
        require_failure(
            bundle,
            make_bundle(**{"kernel-release": "release-1"}),
            b"invalid bundle kernel-release",
        )
        require_failure(
            bundle,
            make_bundle(**{"kernel-release": "1_invalid"}),
            b"invalid bundle kernel-release",
        )
        exact_dtb = "d" * 128 + ".dtb"
        bundle.write_bytes(make_bundle(**{"kernel-dtb-name": exact_dtb}))
        result = run(bundle)
        if result.returncode:
            raise SystemExit(f"exact 128-byte DTB stem failed: {result.stderr!r}")
        require_failure(
            bundle,
            make_bundle(**{"kernel-dtb-name": "d" * 129 + ".dtb"}),
            b"invalid bundle kernel-dtb-name",
        )
        require_failure(
            bundle,
            make_bundle(**{"kernel-dtb-name": "tb321fu~test.dtb"}),
            b"invalid bundle kernel-dtb-name",
        )
        for epoch_length in (10, 11, 12):
            bundle.write_bytes(
                make_bundle(**{"source-date-epoch": "1" * epoch_length})
            )
            result = run(bundle)
            if result.returncode:
                raise SystemExit(
                    f"valid {epoch_length}-digit source epoch failed: {result.stderr!r}"
                )
        require_failure(
            bundle,
            make_bundle(**{"source-date-epoch": "1" * 13}),
            b"invalid bundle source-date-epoch",
        )
        require_failure(
            bundle,
            valid.replace(
                b"schema\ttb321fu.kernel-bundle/v2",
                b"schema\ttb321fu.kernel-bundle/v1",
                1,
            ),
            b"invalid bundle schema",
        )
        require_failure(
            bundle,
            valid.replace(b"kernel-sdk-archive-sha256\t", b"", 1),
            b"field 10 must contain exactly one tab",
        )
        require_failure(bundle, valid + b"x" * 65536, b"bundle exceeds")
        require_failure(
            bundle,
            make_bundle(**{"kernel-bundle-id": "0" * 64}),
            b"kernel-bundle-id mismatch",
        )

        bundle.write_bytes(valid)
        identical.write_bytes(make_bundle(**{"source-date-epoch": "1784073601"}))
        result = run(bundle, "--identical", str(identical))
        if result.returncode == 0 or b"not byte-identical" not in result.stderr:
            raise SystemExit("non-identical valid bundle was accepted")

        result = run(bundle, "--expect", "kernel-release=7.1.1-wrong")
        if result.returncode == 0 or b"expectation mismatch" not in result.stderr:
            raise SystemExit("mismatched expectation was accepted")
        result = run(bundle, "--expect", "kernel-sdk-archive-sha256=" + "0" * 64)
        if result.returncode == 0 or b"expectation mismatch" not in result.stderr:
            raise SystemExit("mismatched SDK archive expectation was accepted")

    print("KERNEL_BUNDLE_METADATA=PASS")


if __name__ == "__main__":
    main()
