#!/usr/bin/env python3
"""Validate canonical TB321FU kernel bundle and toolchain evidence."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
import pathlib
import re
import select
import signal
import stat
import subprocess
import sys
import time


MAX_METADATA_BYTES = 64 * 1024
LIVE_TOOL_TIMEOUT_SECONDS = 10
MAX_LIVE_TOOL_BYTES = 256 * 1024 * 1024
MAX_VERSION_OUTPUT_BYTES = 64 * 1024
BISON_HASH_TIMEOUT_SECONDS = 30
MAX_BISON_TAR_BYTES = 64 * 1024 * 1024
MAX_COMMAND_STDERR_BYTES = 64 * 1024
MAX_BISON_ENTRIES = 4096
MAX_BISON_LOGICAL_BYTES = 16 * 1024 * 1024
MAX_BISON_DEPTH = 64
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX64_OR_UNUSED = re.compile(r"(?:[0-9a-f]{64}|unused)")
PRINTABLE = re.compile(r"[ -~]{1,255}")

BUNDLE_FIELDS = (
    ("schema", re.compile(r"tb321fu\.kernel-bundle/v2")),
    ("kernel-source-commit", HEX40),
    ("kernel-release", re.compile(r"[0-9][0-9A-Za-z.+~-]{0,63}")),
    ("kernel-config-sha256", HEX64),
    ("kernel-image-sha256", HEX64),
    ("kernel-dtb-name", re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,127}\.dtb")),
    ("kernel-dtb-sha256", HEX64),
    ("kernel-modules-deb-sha256", HEX64),
    ("kernel-modules-manifest-sha256", HEX64),
    ("kernel-sdk-archive-sha256", HEX64),
    ("kernel-sdk-manifest-sha256", HEX64),
    ("kernel-toolchain-manifest-sha256", HEX64),
    ("kbuild-flags-sha256", HEX64),
    ("rustc-sha256", HEX64),
    ("rustc", PRINTABLE),
    ("source-date-epoch", re.compile(r"[0-9]{1,12}")),
    ("kbuild-build-timestamp", re.compile(r"[0-9A-Za-z][0-9A-Za-z,:+._ -]{0,95}")),
    ("kbuild-build-user", re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")),
    ("kbuild-build-host", re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")),
    ("kbuild-build-version", re.compile(r"[1-9][0-9]{0,8}")),
    ("kernel-bundle-id", HEX64),
)

TOOLCHAIN_TOOL_NAMES = (
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

TOOLCHAIN_FIELDS = (
    ("schema", re.compile(r"tb321fu\.kernel-toolchain/v2")),
    ("cross-compile", re.compile(r"/[A-Za-z0-9][A-Za-z0-9._+/-]{0,254}-")),
    ("bison-data-directory", re.compile(r"/[A-Za-z0-9._+/-]{1,511}")),
    ("bison-data-sha256", HEX64),
) + tuple(
    field
    for tool in TOOLCHAIN_TOOL_NAMES
    for field in (
        (f"{tool}-sha256", HEX64_OR_UNUSED if tool == "pahole" else HEX64),
        (f"{tool}-version", PRINTABLE),
    )
)

# Only tools that can affect the external-module Kbuild path are compared live.
# Every other v2 field is still parsed and bound by the bundle digest.
LIVE_TOOL_COMMANDS = {
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
NONZERO_VERSION_PROBE_STATUS = {"sh": 2}

CANONICAL_CROSS_COMPILE = "/usr/bin/aarch64-linux-gnu-"
CANONICAL_BISON_DATA = "/usr/share/bison"
CANONICAL_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "HOME": "/nonexistent",
    "TMPDIR": "/tmp",
}


class BundleError(ValueError):
    """Raised when kernel evidence violates the canonical contract."""


def read_ascii_regular(path: pathlib.Path, label: str) -> tuple[bytes, str]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError(f"cannot open {label} {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BundleError(f"{label} must be a regular file: {path}")
        if before.st_size > MAX_METADATA_BYTES:
            raise BundleError(f"{label} exceeds {MAX_METADATA_BYTES} bytes: {path}")
        chunks: list[bytes] = []
        remaining = MAX_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise BundleError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev, before.st_ino, before.st_mode, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev, after.st_ino, after.st_mode, after.st_size,
        after.st_mtime_ns, after.st_ctime_ns,
    )
    if identity_before != identity_after or len(raw) != before.st_size:
        raise BundleError(f"{label} changed while it was read: {path}")
    if len(raw) > MAX_METADATA_BYTES:
        raise BundleError(f"{label} exceeds {MAX_METADATA_BYTES} bytes: {path}")
    if not raw.endswith(b"\n"):
        raise BundleError(f"{label} must end with LF: {path}")
    if b"\x00" in raw:
        raise BundleError(f"{label} contains NUL: {path}")
    if b"\r" in raw:
        raise BundleError(f"{label} contains CR: {path}")
    try:
        return raw, raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BundleError(f"{label} must contain ASCII only: {path}") from exc


def parse_ordered_tsv(
    path: pathlib.Path,
    label: str,
    fields: tuple[tuple[str, re.Pattern[str]], ...],
) -> tuple[dict[str, str], bytes]:
    raw, text = read_ascii_regular(path, label)
    lines = text.splitlines()
    if len(lines) != len(fields):
        raise BundleError(
            f"{label} has {len(lines)} fields, expected {len(fields)}: {path}"
        )
    values: dict[str, str] = {}
    for index, ((expected_key, validator), line) in enumerate(
        zip(fields, lines, strict=True), start=1
    ):
        if line.count("\t") != 1:
            raise BundleError(
                f"{label} field {index} must contain exactly one tab: {path}"
            )
        key, value = line.split("\t", 1)
        if key != expected_key:
            raise BundleError(
                f"{label} field {index} must be {expected_key}, "
                f"found {key or '<empty>'}: {path}"
            )
        if validator.fullmatch(value) is None:
            raise BundleError(f"invalid {label} {key}: {path}")
        values[key] = value
    return values, raw


def parse_bundle(path: pathlib.Path) -> tuple[dict[str, str], bytes]:
    values, raw = parse_ordered_tsv(path, "bundle", BUNDLE_FIELDS)
    identity = b"".join(raw.splitlines(keepends=True)[:-1])
    actual_id = hashlib.sha256(identity).hexdigest()
    if values["kernel-bundle-id"] != actual_id:
        raise BundleError(
            "kernel-bundle-id mismatch: "
            f"expected {actual_id}, found {values['kernel-bundle-id']}: {path}"
        )
    return values, raw


def parse_toolchain(path: pathlib.Path) -> tuple[dict[str, str], bytes]:
    values, raw = parse_ordered_tsv(path, "toolchain manifest", TOOLCHAIN_FIELDS)
    if values["cross-compile"] != CANONICAL_CROSS_COMPILE:
        raise BundleError("toolchain cross-compile is not the canonical absolute prefix")
    if values["bison-data-directory"] != CANONICAL_BISON_DATA:
        raise BundleError("toolchain Bison data directory is not canonical")
    if (values["pahole-sha256"] == "unused") != (
        values["pahole-version"] == "unused"
    ):
        raise BundleError("toolchain pahole unused state is inconsistent")
    if values["rustc-version"] != "disabled":
        raise BundleError("toolchain must record the Rust-disabled sentinel")
    if values["pahole-sha256"] != "unused":
        raise BundleError("toolchain must record pahole as unused for this kernel config")
    return values, raw


def _bounded_command(
    args: list[str],
    label: str,
    *,
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    executable: str | None = None,
    pass_fds: tuple[int, ...] = (),
) -> tuple[int, bytes, bytes]:
    """Run one process group with bounded output and wall-clock time."""
    try:
        process = subprocess.Popen(
            args,
            executable=executable,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=CANONICAL_ENV,
            pass_fds=pass_fds,
            start_new_session=True,
        )
    except OSError as exc:
        raise BundleError(f"cannot start {label}: {exc}") from exc
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    streams = {
        process.stdout.fileno(): (process.stdout, stdout, max_stdout, "stdout"),
        process.stderr.fileno(): (process.stderr, stderr, max_stderr, "stderr"),
    }
    all_streams = (process.stdout, process.stderr)
    deadline = time.monotonic() + timeout

    def kill_group(*, reap_parent: bool) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        if reap_parent and process.poll() is None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired as exc:
                    raise BundleError(f"cannot terminate {label}") from exc

    completed = False
    try:
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            ready, _, _ = select.select(tuple(streams), (), (), remaining)
            if not ready:
                raise subprocess.TimeoutExpired(args, timeout)
            for descriptor in ready:
                stream, output, maximum, stream_name = streams[descriptor]
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                output.extend(chunk)
                if len(output) > maximum:
                    raise BundleError(f"{label} {stream_name} exceeds its size bound")
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        completed = True
    except BaseException:
        kill_group(reap_parent=True)
        raise
    finally:
        if completed:
            # A successful parent may leave a pipe-closing background descendant.
            kill_group(reap_parent=False)
        for stream in all_streams:
            if not stream.closed:
                stream.close()
    return returncode, bytes(stdout), bytes(stderr)


FileIdentity = tuple[int, int, int, int, int, int, int, int, int]


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def digest_descriptor(
    descriptor: int, label: str, maximum: int = MAX_LIVE_TOOL_BYTES
) -> str:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise BundleError(f"verification target is not a bounded regular file: {label}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            break
        digest.update(chunk)
        remaining -= len(chunk)
    if remaining == 0 or os.lseek(descriptor, 0, os.SEEK_CUR) != metadata.st_size:
        raise BundleError(f"verification target exceeds its size bound: {label}")
    return digest.hexdigest()


@dataclass(frozen=True)
class OpenedRegular:
    descriptor: int
    requested: pathlib.Path
    resolved: pathlib.Path
    requested_before: FileIdentity
    target_before: FileIdentity
    digest: str
    label: str
    maximum: int


def open_verified_regular(
    path: pathlib.Path,
    label: str,
    *,
    expected_digest: str | None = None,
    require_executable: bool = False,
    allow_symlink: bool = True,
    maximum: int = MAX_LIVE_TOOL_BYTES,
    digest_subject: str = "verification target",
) -> OpenedRegular:
    descriptor = -1
    try:
        requested_meta = path.lstat()
        requested_is_supported = stat.S_ISREG(requested_meta.st_mode) or (
            allow_symlink and stat.S_ISLNK(requested_meta.st_mode)
        )
        if not requested_is_supported:
            raise BundleError(f"verification path has an unsupported type: {label}")
        resolved = path.resolve(strict=True)
        target_meta = resolved.lstat()
        descriptor = os.open(
            resolved,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        descriptor_meta = os.fstat(descriptor)
        if (
            not stat.S_ISREG(target_meta.st_mode)
            or file_identity(target_meta) != file_identity(descriptor_meta)
            or (require_executable and not (descriptor_meta.st_mode & 0o111))
        ):
            raise BundleError(f"verification target is not a suitable regular file: {label}")
        requested_after = path.lstat()
        resolved_after = path.resolve(strict=True)
        target_after = resolved_after.lstat()
        if (
            file_identity(requested_after) != file_identity(requested_meta)
            or resolved_after != resolved
            or file_identity(target_after) != file_identity(descriptor_meta)
        ):
            raise BundleError(f"verification path changed while it was opened: {label}")
        digest = digest_descriptor(descriptor, label, maximum)
        if expected_digest is not None and digest != expected_digest:
            raise BundleError(f"{digest_subject} SHA-256 differs from manifest: {label}")
        return OpenedRegular(
            descriptor=descriptor,
            requested=path,
            resolved=resolved,
            requested_before=file_identity(requested_meta),
            target_before=file_identity(descriptor_meta),
            digest=digest,
            label=label,
            maximum=maximum,
        )
    except BundleError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise BundleError(f"cannot open verification target {label}: {path}: {exc}") from exc


def finish_verified_regular(opened: OpenedRegular) -> None:
    try:
        descriptor_after = os.fstat(opened.descriptor)
        digest_after = digest_descriptor(
            opened.descriptor, opened.label, opened.maximum
        )
        requested_after = opened.requested.lstat()
        resolved_after = opened.requested.resolve(strict=True)
        target_after = resolved_after.lstat()
    except (OSError, BundleError) as exc:
        raise BundleError(
            f"verification target changed during inspection: {opened.label}: {exc}"
        ) from exc
    finally:
        os.close(opened.descriptor)
    if (
        file_identity(descriptor_after) != opened.target_before
        or digest_after != opened.digest
        or file_identity(requested_after) != opened.requested_before
        or resolved_after != opened.resolved
        or file_identity(target_after) != opened.target_before
    ):
        raise BundleError(
            f"verification target changed during inspection: {opened.label}"
        )


def bounded_regular_digest(
    path: pathlib.Path,
    label: str,
    *,
    expected_digest: str | None = None,
    allow_symlink: bool = False,
    maximum: int = MAX_LIVE_TOOL_BYTES,
) -> str:
    opened = open_verified_regular(
        path,
        label,
        expected_digest=expected_digest,
        allow_symlink=allow_symlink,
        maximum=maximum,
    )
    try:
        return opened.digest
    finally:
        finish_verified_regular(opened)


def command_identity(
    command: str, label: str, expected_digest: str | None = None
) -> tuple[str, str]:
    path = pathlib.Path(command)
    opened = open_verified_regular(
        path,
        label,
        expected_digest=expected_digest,
        require_executable=True,
        allow_symlink=True,
        digest_subject="live tool",
    )
    try:
        args = [command, "-W", "version"] if label == "awk" else [command, "--version"]
        returncode, stdout, stderr = _bounded_command(
            args,
            f"live tool version probe: {label}",
            timeout=LIVE_TOOL_TIMEOUT_SECONDS,
            max_stdout=MAX_VERSION_OUTPUT_BYTES,
            max_stderr=MAX_VERSION_OUTPUT_BYTES,
            executable=f"/proc/self/fd/{opened.descriptor}",
            pass_fds=(opened.descriptor,),
        )
    except subprocess.TimeoutExpired as exc:
        raise BundleError(f"live tool version probe timed out: {label}") from exc
    except OSError as exc:
        raise BundleError(f"cannot inspect live tool {label}: {exc}") from exc
    finally:
        finish_verified_regular(opened)
    expected_status = NONZERO_VERSION_PROBE_STATUS.get(label, 0)
    if returncode != expected_status:
        raise BundleError(
            "live tool version probe returned status "
            f"{returncode}, expected {expected_status}: {label}"
        )
    lines = (stdout + stderr).decode("utf-8", errors="replace").splitlines()
    version = next((line for line in lines if line), "")
    if not version or len(version) > 255 or PRINTABLE.fullmatch(version) is None:
        raise BundleError(f"live tool returned an invalid version line: {label}")
    return opened.digest, version


def scan_bison_tree(
    root_descriptor: int, *, expected_uid: int = 0, expected_gid: int = 0
) -> tuple[int, int]:
    entry_count = 1
    total_size = 0
    root_device = os.fstat(root_descriptor).st_dev

    def visit(directory_descriptor: int, depth: int) -> None:
        nonlocal entry_count, total_size
        if depth > MAX_BISON_DEPTH:
            raise BundleError("Bison data tree exceeds its depth limit")
        try:
            iterator = os.scandir(directory_descriptor)
            with iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count > MAX_BISON_ENTRIES:
                        raise BundleError("Bison data tree has an unsafe entry count")
                    entry_meta = entry.stat(follow_symlinks=False)
                    if entry_meta.st_dev != root_device:
                        raise BundleError("Bison data tree contains a cross-device entry")
                    if (
                        entry_meta.st_uid != expected_uid
                        or entry_meta.st_gid != expected_gid
                    ):
                        raise BundleError(
                            "Bison data tree contains an unexpected owner"
                        )
                    if stat.S_ISDIR(entry_meta.st_mode):
                        if stat.S_IMODE(entry_meta.st_mode) != 0o755:
                            raise BundleError(
                                "Bison data tree contains an unexpected directory mode"
                            )
                        child_descriptor = os.open(
                            entry.name,
                            os.O_RDONLY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_DIRECTORY", 0),
                            dir_fd=directory_descriptor,
                        )
                        try:
                            child_before = os.fstat(child_descriptor)
                            if file_identity(child_before) != file_identity(entry_meta):
                                raise BundleError(
                                    "Bison data directory changed while it was opened"
                                )
                            visit(child_descriptor, depth + 1)
                            child_after = os.fstat(child_descriptor)
                            if file_identity(child_after) != file_identity(child_before):
                                raise BundleError(
                                    "Bison data directory changed while it was scanned"
                                )
                        finally:
                            os.close(child_descriptor)
                    elif stat.S_ISREG(entry_meta.st_mode):
                        if entry_meta.st_nlink != 1:
                            raise BundleError(
                                "Bison data tree contains a hard-linked file"
                            )
                        if stat.S_IMODE(entry_meta.st_mode) != 0o644:
                            raise BundleError(
                                "Bison data tree contains an unexpected file mode"
                            )
                        total_size += entry_meta.st_size
                        if total_size > MAX_BISON_LOGICAL_BYTES:
                            raise BundleError(
                                "Bison data tree has an unsafe logical size"
                            )
                    else:
                        raise BundleError(
                            "Bison data tree contains an unsupported entry"
                        )
        except BundleError:
            raise
        except OSError as exc:
            raise BundleError(f"cannot scan Bison data tree: {exc}") from exc

    visit(root_descriptor, 0)
    if entry_count < 2:
        raise BundleError("Bison data tree has an unsafe entry count")
    if total_size <= 0:
        raise BundleError("Bison data tree has an unsafe logical size")
    return entry_count, total_size


def canonical_bison_data_sha256(
    directory: pathlib.Path,
    tar_expected_digest: str | None = None,
    tar_command: pathlib.Path = pathlib.Path("/usr/bin/tar"),
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> str:
    root_descriptor = -1
    try:
        metadata = directory.lstat()
        root_descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        opened_metadata = os.fstat(root_descriptor)
    except OSError as exc:
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise BundleError(f"cannot open Bison data directory: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or file_identity(metadata) != file_identity(opened_metadata)
    ):
        os.close(root_descriptor)
        raise BundleError(
            "Bison data directory is not a canonical root-owned mode-0755 directory"
        )
    try:
        scan_bison_tree(
            root_descriptor, expected_uid=expected_uid, expected_gid=expected_gid
        )
        opened_tar = open_verified_regular(
            tar_command,
            "tar",
            expected_digest=tar_expected_digest,
            require_executable=True,
            allow_symlink=True,
            digest_subject="live tool",
        )
        try:
            command = [
                str(tar_command), "--sort=name", "--format=gnu", "--numeric-owner",
                "--owner=0", "--group=0", "--mtime=@0", "-C",
                f"/proc/self/fd/{root_descriptor}", "-cf", "-", ".",
            ]
            returncode, stdout, stderr = _bounded_command(
                command,
                "Bison data tree hash",
                timeout=BISON_HASH_TIMEOUT_SECONDS,
                max_stdout=MAX_BISON_TAR_BYTES,
                max_stderr=MAX_COMMAND_STDERR_BYTES,
                executable=f"/proc/self/fd/{opened_tar.descriptor}",
                pass_fds=(opened_tar.descriptor, root_descriptor),
            )
        finally:
            finish_verified_regular(opened_tar)
        path_after = directory.lstat()
        descriptor_after = os.fstat(root_descriptor)
        if (
            file_identity(path_after) != file_identity(metadata)
            or file_identity(descriptor_after) != file_identity(opened_metadata)
        ):
            raise BundleError("Bison data directory changed while it was hashed")
    except subprocess.TimeoutExpired as exc:
        raise BundleError("Bison data tree hash timed out") from exc
    except OSError as exc:
        raise BundleError(f"cannot hash Bison data tree: {exc}") from exc
    finally:
        os.close(root_descriptor)
    if returncode:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise BundleError(f"cannot hash Bison data tree: {detail}")
    return hashlib.sha256(stdout).hexdigest()


def verify_disabled_rust_sentinel(
    path: pathlib.Path,
    expected_digest: str,
    maximum: int = MAX_LIVE_TOOL_BYTES,
) -> None:
    try:
        bounded_regular_digest(
            path,
            "Rust-disabled sentinel",
            expected_digest=expected_digest,
            allow_symlink=False,
            maximum=maximum,
        )
    except BundleError as exc:
        if "SHA-256 differs from manifest" in str(exc):
            raise BundleError("live Rust-disabled sentinel differs from manifest") from exc
        raise


def verify_live_toolchain(values: dict[str, str]) -> None:
    for label, command in LIVE_TOOL_COMMANDS.items():
        _, version = command_identity(
            command, label, values[f"{label}-sha256"]
        )
        if version != values[f"{label}-version"]:
            raise BundleError(f"live tool version differs from manifest: {label}")

    verify_disabled_rust_sentinel(
        pathlib.Path("/usr/bin/false"),
        values["rustc-sha256"],
    )
    bison_digest = canonical_bison_data_sha256(
        pathlib.Path(CANONICAL_BISON_DATA), values["tar-sha256"]
    )
    if bison_digest != values["bison-data-sha256"]:
        raise BundleError("live Bison data tree differs from manifest")


def parse_expectation(argument: str) -> tuple[str, str]:
    if "=" not in argument:
        raise BundleError(f"expectation must be KEY=VALUE: {argument}")
    key, value = argument.split("=", 1)
    known = {name for name, _ in BUNDLE_FIELDS}
    if key not in known or not value:
        raise BundleError(f"invalid expectation: {argument}")
    return key, value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate canonical TB321FU KERNEL-BUNDLE.tsv metadata."
    )
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("--identical", action="append", default=[], type=pathlib.Path)
    parser.add_argument(
        "--toolchain", type=pathlib.Path,
        help="validate the KERNEL-TOOLCHAIN.tsv file bound by this bundle",
    )
    parser.add_argument(
        "--verify-live-toolchain", action="store_true",
        help="also compare the Kbuild-relevant host tools with the manifest",
    )
    parser.add_argument("--expect", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--emit-tsv", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        values, raw = parse_bundle(args.bundle)
        if args.verify_live_toolchain and args.toolchain is None:
            raise BundleError("--verify-live-toolchain requires --toolchain")
        if args.toolchain is not None:
            toolchain, toolchain_raw = parse_toolchain(args.toolchain)
            actual_digest = hashlib.sha256(toolchain_raw).hexdigest()
            if actual_digest != values["kernel-toolchain-manifest-sha256"]:
                raise BundleError("toolchain manifest SHA-256 mismatch")
            if toolchain["rustc-sha256"] != values["rustc-sha256"]:
                raise BundleError("toolchain rustc SHA-256 differs from bundle")
            if toolchain["rustc-version"] != values["rustc"]:
                raise BundleError("toolchain rustc version differs from bundle")
            if args.verify_live_toolchain:
                verify_live_toolchain(toolchain)
        for other_path in args.identical:
            _, other_raw = parse_bundle(other_path)
            if other_raw != raw:
                raise BundleError(
                    f"bundle metadata is not byte-identical: {args.bundle} != {other_path}"
                )
        seen: set[str] = set()
        for argument in args.expect:
            key, expected = parse_expectation(argument)
            if key in seen:
                raise BundleError(f"duplicate expectation for {key}")
            seen.add(key)
            if values[key] != expected:
                raise BundleError(
                    f"expectation mismatch for {key}: expected {expected}, "
                    f"found {values[key]}"
                )
    except (BundleError, OSError) as exc:
        print(f"kernel bundle metadata verification failed: {exc}", file=sys.stderr)
        return 1

    if args.emit_tsv:
        sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
