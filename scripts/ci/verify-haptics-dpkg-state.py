#!/usr/bin/env python3
"""Capture reviewed dpkg trigger handlers and mutable transaction state."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import os
import pathlib
import re
import stat
import sys


STATE_SCHEMA = "tb321fu.haptics-dpkg-state/v1"
HOST_REFERENCE_SCHEMA = "tb321fu.haptics-dpkg-host-reference/v1"
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
ARCHITECTURE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+:~\-]{0,254}")
STATUS_WANTS = {"unknown", "install", "hold", "deinstall", "purge"}
STATUS_EFLAGS = {"ok", "reinstreq"}
STATUS_STATES = {
    "not-installed",
    "config-files",
    "half-installed",
    "unpacked",
    "half-configured",
    "triggers-awaited",
    "triggers-pending",
    "installed",
}
DEBIAN_MULTIARCH = {"no", "same", "foreign", "allowed"}
ACCOUNT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
NUMERIC_ACCOUNT = re.compile(r"#(?:0|[1-9][0-9]{0,9})")
OVERRIDE_MODE = re.compile(r"[0-7]{3,4}")
HEX64 = re.compile(r"[0-9a-f]{64}")
UNSIGNED = re.compile(r"0|[1-9][0-9]{0,15}")
CONTROL_FIELD_NAME = re.compile(r"(?!#)[\x21-\x39\x3b-\x7e]+")
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_STATE_FILE_BYTES = 4 * 1024 * 1024
MAX_SCRIPT_BYTES = 4 * 1024 * 1024
MAX_SCRIPT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SERIALIZED_STATE_BYTES = 32 * 1024 * 1024
MAX_PATH_COMPONENTS = 128
MAX_DIRECTORY_ENTRIES = 4096
MAX_TRIGGER_RECORDS = 4096
MAX_EXPLICIT_TRIGGER_FILE_BYTES = 256 * 1024
MAX_EXPLICIT_TRIGGER_TOTAL_BYTES = 4 * 1024 * 1024
MAX_HANDLER_RECORDS = 1024
SCRIPT_SUFFIXES = ("preinst", "postinst", "prerm", "postrm", "triggers")
MAX_SCRIPT_RECORDS = MAX_HANDLER_RECORDS * len(SCRIPT_SUFFIXES)
STATE_FILE_LIMITS = {
    "status": MAX_STATUS_BYTES,
    "diversions": MAX_STATE_FILE_BYTES,
    "statoverride": MAX_STATE_FILE_BYTES,
    "triggers/File": MAX_STATE_FILE_BYTES,
    "triggers/Unincorp": MAX_STATE_FILE_BYTES,
}


class DpkgStateError(ValueError):
    pass


def has_non_lf_control(raw: bytes) -> bool:
    return any(byte < 0x20 and byte not in {0x09, 0x0A} for byte in raw) or b"\x7f" in raw


@dataclass(frozen=True)
class TriggerRecord:
    path: str
    package: str
    architecture: str
    mode: str


@dataclass(frozen=True)
class HandlerRecord:
    package: str
    architecture: str
    version: str
    status: str


@dataclass(frozen=True)
class ScriptRecord:
    package: str
    architecture: str
    filename: str
    mode: int
    size: int
    sha256: str


@dataclass(frozen=True)
class StateFileRecord:
    name: str
    mode: int
    size: int
    sha256: str


@dataclass(frozen=True)
class DiversionRecord:
    source: str
    destination: str
    package: str


@dataclass(frozen=True)
class StatoverrideRecord:
    user: str
    group: str
    mode: str
    path: str


@dataclass(frozen=True)
class DpkgState:
    state_files: tuple[StateFileRecord, ...]
    triggers: tuple[TriggerRecord, ...]
    handlers: tuple[HandlerRecord, ...]
    diversions: tuple[DiversionRecord, ...]
    statoverrides: tuple[StatoverrideRecord, ...]
    scripts: tuple[ScriptRecord, ...]


@dataclass(frozen=True)
class DpkgHostReference:
    state_files: tuple[StateFileRecord, ...]
    triggers: tuple[TriggerRecord, ...]
    handlers: tuple[HandlerRecord, ...]
    diversions: tuple[DiversionRecord, ...]
    statoverrides: tuple[StatoverrideRecord, ...]
    scripts: tuple[ScriptRecord, ...]


@dataclass(frozen=True)
class DirectoryChainEntry:
    descriptor: int
    parent_descriptor: int | None
    name: str | None
    metadata: os.stat_result


@dataclass(frozen=True)
class RegularFilePin:
    descriptor: int
    directory_descriptor: int
    name: str
    metadata: os.stat_result
    sha256: str
    label: str


def stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def directory_namespace_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def pin_directory_chain(path: pathlib.Path) -> tuple[DirectoryChainEntry, ...]:
    path_text = str(path)
    components = path.parts
    try:
        path_size = len(os.fsencode(path_text))
    except UnicodeEncodeError as exc:
        raise DpkgStateError("dpkg admin directory path is not canonical") from exc
    if (
        not path.is_absolute()
        or path_size > 4096
        or len(components) < 2
        or components[0] != "/"
        or len(components) - 1 > MAX_PATH_COMPONENTS
        or any(component in {"", ".", ".."} for component in components[1:])
        or path_text != "/" + "/".join(components[1:])
    ):
        raise DpkgStateError("dpkg admin directory path is not canonical")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    entries: list[DirectoryChainEntry] = []
    opened_descriptors: list[int] = []
    try:
        descriptor = os.open("/", flags)
        opened_descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        namespace = os.stat("/", follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or directory_namespace_identity(namespace)
            != directory_namespace_identity(metadata)
        ):
            raise DpkgStateError("dpkg admin root namespace is not a stable directory")
        entries.append(DirectoryChainEntry(descriptor, None, None, metadata))
        parent_descriptor = descriptor
        for component in components[1:]:
            descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            opened_descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            namespace = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or directory_namespace_identity(namespace)
                != directory_namespace_identity(metadata)
            ):
                raise DpkgStateError(
                    "dpkg admin directory component is not a stable real directory"
                )
            entries.append(
                DirectoryChainEntry(
                    descriptor,
                    parent_descriptor,
                    component,
                    metadata,
                )
            )
            parent_descriptor = descriptor
        return tuple(entries)
    except DpkgStateError:
        for descriptor in reversed(opened_descriptors):
            os.close(descriptor)
        raise
    except OSError as exc:
        for descriptor in reversed(opened_descriptors):
            os.close(descriptor)
        raise DpkgStateError(f"cannot pin dpkg admin directory path: {exc}") from exc


def verify_directory_chain(entries: tuple[DirectoryChainEntry, ...]) -> None:
    for entry in entries:
        try:
            after = os.fstat(entry.descriptor)
            if entry.parent_descriptor is None:
                namespace = os.stat("/", follow_symlinks=False)
            else:
                namespace = os.stat(
                    entry.name,
                    dir_fd=entry.parent_descriptor,
                    follow_symlinks=False,
                )
        except OSError as exc:
            raise DpkgStateError(
                f"dpkg admin directory ancestor namespace changed: {exc}"
            ) from exc
        if (
            directory_namespace_identity(entry.metadata)
            != directory_namespace_identity(after)
            or directory_namespace_identity(after)
            != directory_namespace_identity(namespace)
        ):
            raise DpkgStateError("dpkg admin directory ancestor namespace changed")


def require_directory(
    path: pathlib.Path,
    expected_uid: int,
    expected_gid: int,
    label: str,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DpkgStateError(f"cannot inspect {label}: {exc}") from exc
    if (
        not path.is_absolute()
        or path.resolve(strict=True) != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
    ):
        raise DpkgStateError(f"{label} is not a canonical owned mode-0755 directory")


def read_regular(
    path: pathlib.Path,
    expected_mode: int,
    expected_uid: int,
    expected_gid: int,
    size_bound: int,
    label: str,
) -> bytes:
    directory_chain = pin_directory_chain(path.parent)
    pinned_files: list[RegularFilePin] = []
    try:
        raw = read_regular_at(
            directory_chain[-1].descriptor,
            path.name,
            expected_mode,
            expected_uid,
            expected_gid,
            size_bound,
            label,
            pinned_files,
        )
        verify_directory_chain(directory_chain)
        verify_regular_file_pins(pinned_files)
        return raw
    finally:
        for pinned in reversed(pinned_files):
            os.close(pinned.descriptor)
        for entry in reversed(directory_chain):
            os.close(entry.descriptor)


def read_regular_at(
    directory_descriptor: int,
    name: str,
    expected_mode: int,
    expected_uid: int,
    expected_gid: int,
    size_bound: int,
    label: str,
    pinned_files: list[RegularFilePin] | None = None,
) -> bytes:
    if not name or "/" in name or name in {".", ".."}:
        raise DpkgStateError(f"{label} has an invalid directory entry name")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        raise DpkgStateError(f"cannot open {label}: {exc}") from exc
    retained = False

    def retain(metadata: os.stat_result, raw: bytes) -> None:
        nonlocal retained
        if pinned_files is not None:
            pinned_files.append(
                RegularFilePin(
                    descriptor,
                    directory_descriptor,
                    name,
                    metadata,
                    hashlib.sha256(raw).hexdigest(),
                    label,
                )
            )
            retained = True

    try:
        return read_open_regular(
            descriptor,
            lambda: os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            ),
            expected_mode,
            expected_uid,
            expected_gid,
            size_bound,
            label,
            retain if pinned_files is not None else None,
        )
    finally:
        if not retained:
            os.close(descriptor)


def read_open_regular(
    descriptor: int,
    namespace_stat,
    expected_mode: int,
    expected_uid: int,
    expected_gid: int,
    size_bound: int,
    label: str,
    on_verified=None,
) -> bytes:
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_nlink != 1
            or metadata.st_size > size_bound
        ):
            raise DpkgStateError(f"{label} metadata differs from policy")
        chunks: list[bytes] = []
        remaining = size_bound + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > size_bound:
            raise DpkgStateError(f"{label} exceeds its read bound")
        after = os.fstat(descriptor)
        if stable_identity(after) != stable_identity(metadata):
            raise DpkgStateError(f"{label} changed while it was read")
        try:
            namespace = namespace_stat()
        except OSError as exc:
            raise DpkgStateError(f"{label} namespace changed while it was read: {exc}") from exc
        if stable_identity(namespace) != stable_identity(after):
            raise DpkgStateError(f"{label} namespace changed while it was read")
        if on_verified is not None:
            on_verified(after, raw)
        return raw
    except DpkgStateError:
        raise
    except OSError as exc:
        raise DpkgStateError(f"cannot read {label}: {exc}") from exc


def parse_status_identities(
    raw: bytes,
) -> dict[tuple[str, str], tuple[str, str, str]]:
    if raw == b"":
        return {}
    if not raw.endswith(b"\n") or has_non_lf_control(raw):
        raise DpkgStateError("dpkg status has invalid framing")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DpkgStateError("dpkg status is not UTF-8") from exc
    packages: dict[tuple[str, str], tuple[str, str, str]] = {}
    for paragraph in text.strip("\n").split("\n\n"):
        fields: dict[str, str] = {}
        current: str | None = None
        for line in paragraph.split("\n"):
            if line.startswith((" ", "\t")):
                if current is None:
                    raise DpkgStateError("dpkg status has an orphan continuation")
                if current in {
                    "package",
                    "status",
                    "architecture",
                    "version",
                    "multi-arch",
                    "triggers-pending",
                    "triggers-awaited",
                }:
                    raise DpkgStateError("dpkg status simple field must not be folded")
                continue
            name, found, remainder = line.partition(":")
            canonical_name = name.lower()
            if (
                not found
                or CONTROL_FIELD_NAME.fullmatch(name) is None
                or canonical_name in fields
                or remainder
                and not remainder.startswith(" ")
            ):
                raise DpkgStateError("dpkg status contains a malformed field")
            value = remainder[1:] if remainder else ""
            fields[canonical_name] = value
            current = canonical_name
        try:
            package = fields["package"]
            architecture = fields["architecture"]
            version = fields["version"]
            status_value = fields["status"]
        except KeyError as exc:
            raise DpkgStateError("dpkg status paragraph lacks package identity") from exc
        status_fields = status_value.split(" ")
        multiarch = fields.get("multi-arch", "no")
        if (
            "triggers-pending" in fields
            or "triggers-awaited" in fields
            or len(status_fields) == 3
            and status_fields[2] in {"triggers-pending", "triggers-awaited"}
        ):
            raise DpkgStateError("dpkg status contains pending or awaited trigger state")
        identity = (package, architecture)
        if (
            not PACKAGE_NAME.fullmatch(package)
            or not ARCHITECTURE.fullmatch(architecture)
            or not VERSION.fullmatch(version)
            or len(status_fields) != 3
            or status_fields[0] not in STATUS_WANTS
            or status_fields[1] not in STATUS_EFLAGS
            or status_fields[2] not in STATUS_STATES
            or multiarch not in DEBIAN_MULTIARCH
            or identity in packages
        ):
            raise DpkgStateError("dpkg status contains an unsafe package identity")
        packages[identity] = (version, status_value, multiarch)
    return packages


def parse_status(raw: bytes) -> dict[tuple[str, str], tuple[str, str]]:
    return {
        identity: (version, status_value)
        for identity, (version, status_value, _) in parse_status_identities(raw).items()
    }


def validate_absolute_path(value: str, label: str) -> str:
    components = value.split("/")
    try:
        path_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise DpkgStateError(f"{label} is not canonical") from exc
    if len(components) - 1 > MAX_PATH_COMPONENTS:
        raise DpkgStateError(f"{label} exceeds its component depth bound")
    if (
        path_size > 4096
        or not value.startswith("/")
        or components[0] != ""
        or len(components) < 2
        or any(component in {"", ".", ".."} for component in components[1:])
        or any(character.isspace() for character in value)
    ):
        raise DpkgStateError(f"{label} is not canonical")
    return value


def validate_trigger_subject(value: str, label: str) -> str:
    if value.startswith("explicit:"):
        name = value.removeprefix("explicit:")
        if not PACKAGE_NAME.fullmatch(name):
            raise DpkgStateError(f"{label} explicit name is not canonical")
        return value
    return validate_absolute_path(value, label)


def parse_trigger_owner(
    owner: str,
    packages: dict[tuple[str, str], tuple[str, str]],
) -> tuple[str, str, str]:
    mode = "await"
    if owner.endswith("/noawait"):
        owner = owner[: -len("/noawait")]
        mode = "noawait"
    if "/" in owner:
        raise DpkgStateError("trigger owner contains an invalid mode")
    if ":" in owner:
        package, architecture = owner.rsplit(":", 1)
        identities = [(package, architecture)]
    else:
        package = owner
        identities = [
            identity
            for identity, (_, status_value) in packages.items()
            if identity[0] == package
            and status_value in {"install ok installed", "hold ok installed"}
        ]
        if not identities:
            raise DpkgStateError("trigger registry contains an unsafe owner")
        if len(identities) != 1:
            raise DpkgStateError("unqualified trigger owner is ambiguous")
        _, architecture = identities[0]
    identity = (package, architecture)
    if (
        not PACKAGE_NAME.fullmatch(package)
        or not ARCHITECTURE.fullmatch(architecture)
        or identity not in packages
        or packages[identity][1] not in {"install ok installed", "hold ok installed"}
    ):
        raise DpkgStateError("trigger registry contains an unsafe owner")
    return package, architecture, mode


def parse_triggers(
    raw: bytes,
    packages: dict[tuple[str, str], tuple[str, str]],
) -> tuple[TriggerRecord, ...]:
    if raw == b"":
        return ()
    if not raw.endswith(b"\n") or has_non_lf_control(raw):
        raise DpkgStateError("trigger registry has invalid framing")
    try:
        lines = raw.decode("ascii")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise DpkgStateError("trigger registry must contain ASCII only") from exc
    if len(lines) > MAX_TRIGGER_RECORDS:
        raise DpkgStateError("trigger registry exceeds its record-count bound")
    records: list[TriggerRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for line in lines:
        fields = line.split(" ")
        if len(fields) != 2 or any(not field for field in fields):
            raise DpkgStateError("trigger registry contains a malformed record")
        path, owner = fields
        package, architecture, mode = parse_trigger_owner(owner, packages)
        canonical_path = validate_absolute_path(path, "trigger path")
        logical_key = (canonical_path, package, architecture)
        if logical_key in seen:
            raise DpkgStateError("trigger registry contains an unsafe owner")
        seen.add(logical_key)
        records.append(TriggerRecord(canonical_path, package, architecture, mode))
    return tuple(sorted(records, key=lambda item: (item.path, item.package, item.architecture, item.mode)))


def parse_explicit_triggers(
    name: str,
    raw: bytes,
    packages: dict[tuple[str, str], tuple[str, str]],
) -> tuple[TriggerRecord, ...]:
    subject = validate_trigger_subject(f"explicit:{name}", "explicit trigger")
    if (
        not raw
        or len(raw) > MAX_EXPLICIT_TRIGGER_FILE_BYTES
        or not raw.endswith(b"\n")
        or has_non_lf_control(raw)
    ):
        raise DpkgStateError("explicit trigger registry has invalid framing or size")
    try:
        lines = raw.decode("ascii")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise DpkgStateError("explicit trigger registry must contain ASCII only") from exc
    if len(lines) > MAX_TRIGGER_RECORDS:
        raise DpkgStateError("explicit trigger registry exceeds its record-count bound")
    records: list[TriggerRecord] = []
    seen: set[tuple[str, str]] = set()
    for owner in lines:
        if not owner or " " in owner or "\t" in owner:
            raise DpkgStateError("explicit trigger registry contains a malformed owner")
        package, architecture, mode = parse_trigger_owner(owner, packages)
        logical_key = (package, architecture)
        if logical_key in seen:
            raise DpkgStateError("explicit trigger registry repeats an owner")
        seen.add(logical_key)
        records.append(TriggerRecord(subject, package, architecture, mode))
    return tuple(
        sorted(
            records,
            key=lambda item: (item.path, item.package, item.architecture, item.mode),
        )
    )


def decode_state_lines(raw: bytes, label: str) -> list[str]:
    if not raw:
        return []
    if not raw.endswith(b"\n") or has_non_lf_control(raw):
        raise DpkgStateError(f"{label} has invalid framing")
    try:
        return raw.decode("utf-8")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise DpkgStateError(f"{label} is not UTF-8") from exc


def valid_statoverride_account(value: str) -> bool:
    if ACCOUNT_NAME.fullmatch(value):
        return True
    return bool(NUMERIC_ACCOUNT.fullmatch(value)) and int(value[1:]) <= 2**32 - 1


def parse_diversions(raw: bytes) -> tuple[DiversionRecord, ...]:
    lines = decode_state_lines(raw, "dpkg diversions")
    if len(lines) % 3:
        raise DpkgStateError("dpkg diversions has an incomplete record")
    records: list[DiversionRecord] = []
    sources: set[str] = set()
    destinations: set[str] = set()
    for position in range(0, len(lines), 3):
        source = validate_absolute_path(lines[position], "diversion source")
        destination = validate_absolute_path(lines[position + 1], "diversion destination")
        package = lines[position + 2]
        if (
            source == destination
            or source in sources
            or destination in destinations
            or (package != "LOCAL" and not PACKAGE_NAME.fullmatch(package))
        ):
            raise DpkgStateError("dpkg diversions contains an unsafe record")
        sources.add(source)
        destinations.add(destination)
        records.append(DiversionRecord(source, destination, package))
    return tuple(sorted(records, key=lambda item: (item.source, item.destination, item.package)))


def parse_statoverrides(raw: bytes) -> tuple[StatoverrideRecord, ...]:
    records: list[StatoverrideRecord] = []
    paths: set[str] = set()
    for line in decode_state_lines(raw, "dpkg statoverride"):
        fields = line.split(" ", 3)
        if len(fields) != 4 or any(not field for field in fields):
            raise DpkgStateError("dpkg statoverride contains a malformed record")
        user, group, mode, path = fields
        path = validate_absolute_path(path, "statoverride path")
        if (
            not valid_statoverride_account(user)
            or not valid_statoverride_account(group)
            or not OVERRIDE_MODE.fullmatch(mode)
            or path in paths
        ):
            raise DpkgStateError("dpkg statoverride contains an unsafe record")
        paths.add(path)
        records.append(StatoverrideRecord(user, group, mode, path))
    return tuple(sorted(records, key=lambda item: item.path))


def open_directory_at(
    parent_descriptor: int,
    name: str,
    expected_uid: int,
    expected_gid: int,
    label: str,
) -> tuple[int, os.stat_result]:
    if not name or "/" in name or name in {".", ".."}:
        raise DpkgStateError(f"{label} has an invalid directory entry name")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise DpkgStateError(f"cannot pin {label}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        namespace = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_dev != os.fstat(parent_descriptor).st_dev
            or stable_identity(namespace) != stable_identity(metadata)
        ):
            raise DpkgStateError(f"{label} metadata differs from policy")
        return descriptor, metadata
    except DpkgStateError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise DpkgStateError(f"cannot verify pinned {label}: {exc}") from exc
    except BaseException:
        os.close(descriptor)
        raise


def verify_directory_at(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    before: os.stat_result,
    label: str,
) -> None:
    try:
        after = os.fstat(descriptor)
        namespace = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise DpkgStateError(f"{label} namespace changed during capture: {exc}") from exc
    if (
        stable_identity(before) != stable_identity(after)
        or stable_identity(after) != stable_identity(namespace)
    ):
        raise DpkgStateError(f"{label} namespace changed during capture")


def bounded_directory_names(descriptor: int, label: str) -> tuple[str, ...]:
    before = os.fstat(descriptor)
    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) >= MAX_DIRECTORY_ENTRIES:
                    raise DpkgStateError(f"{label} exceeds its entry-count bound")
                names.append(entry.name)
    except OSError as exc:
        raise DpkgStateError(f"cannot enumerate {label}: {exc}") from exc
    if any(not name or "/" in name or name in {".", ".."} for name in names):
        raise DpkgStateError(f"{label} contains an invalid entry name")
    if stable_identity(os.fstat(descriptor)) != stable_identity(before):
        raise DpkgStateError(f"{label} changed while it was enumerated")
    return tuple(sorted(names))


def entry_exists_at(directory_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise DpkgStateError(f"cannot inspect maintainer metadata {name}: {exc}") from exc
    return True


def verify_regular_file_pins(pinned_files: list[RegularFilePin]) -> None:
    for pinned in pinned_files:
        try:
            before_read = os.fstat(pinned.descriptor)
            os.lseek(pinned.descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            size = 0
            remaining = pinned.metadata.st_size + 1
            while remaining:
                chunk = os.read(pinned.descriptor, min(remaining, 65536))
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                remaining -= len(chunk)
            after_read = os.fstat(pinned.descriptor)
            namespace = os.stat(
                pinned.name,
                dir_fd=pinned.directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise DpkgStateError(
                f"{pinned.label} regular file changed before capture completed: {exc}"
            ) from exc
        if (
            stable_identity(pinned.metadata) != stable_identity(before_read)
            or stable_identity(before_read) != stable_identity(after_read)
            or stable_identity(after_read) != stable_identity(namespace)
            or size != pinned.metadata.st_size
            or digest.hexdigest() != pinned.sha256
        ):
            raise DpkgStateError(
                f"{pinned.label} regular file changed before capture completed"
            )


def capture_dpkg_state(
    admin: pathlib.Path,
    expected_uid: int,
    expected_gid: int,
) -> DpkgState:
    directory_chain = pin_directory_chain(admin)
    admin_descriptor = directory_chain[-1].descriptor
    try:
        require_directory(admin, expected_uid, expected_gid, "dpkg admin directory")
        before = directory_chain[-1].metadata
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o755
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
        ):
            raise DpkgStateError("pinned dpkg admin directory metadata differs from policy")

        def verify_admin_namespace() -> None:
            after = os.fstat(admin_descriptor)
            if stable_identity(before) != stable_identity(after):
                raise DpkgStateError(
                    "dpkg admin directory namespace changed during capture"
                )
            verify_directory_chain(directory_chain)

        state = _capture_dpkg_state_contents(
            admin_descriptor,
            expected_uid,
            expected_gid,
            verify_admin_namespace,
        )
        return state
    finally:
        for entry in reversed(directory_chain):
            os.close(entry.descriptor)


def _capture_dpkg_state_contents(
    admin_descriptor: int,
    expected_uid: int,
    expected_gid: int,
    final_namespace_verifier: Callable[[], None],
) -> DpkgState:
    directory_labels = {
        "triggers": "dpkg trigger directory",
        "info": "dpkg info directory",
        "updates": "dpkg updates directory",
        "parts": "dpkg parts directory",
    }
    directories: dict[str, tuple[int, os.stat_result]] = {}
    pinned_files: list[RegularFilePin] = []
    try:
        for name, label in directory_labels.items():
            directories[name] = open_directory_at(
                admin_descriptor,
                name,
                expected_uid,
                expected_gid,
                label,
            )
        triggers_descriptor = directories["triggers"][0]
        info_descriptor = directories["info"][0]
        if bounded_directory_names(directories["updates"][0], "dpkg updates directory"):
            raise DpkgStateError("dpkg journal directory is not empty")
        if bounded_directory_names(directories["parts"][0], "dpkg parts directory"):
            raise DpkgStateError("dpkg journal directory is not empty")

        state_raw: dict[str, bytes] = {}
        for relative, bound in STATE_FILE_LIMITS.items():
            if relative.startswith("triggers/"):
                descriptor = triggers_descriptor
                name = relative.removeprefix("triggers/")
            else:
                descriptor = admin_descriptor
                name = relative
            state_raw[relative] = read_regular_at(
                descriptor,
                name,
                0o644,
                expected_uid,
                expected_gid,
                bound,
                relative,
                pinned_files,
            )
        if state_raw["triggers/Unincorp"]:
            raise DpkgStateError("dpkg Unincorp is not empty")
        if entry_exists_at(triggers_descriptor, "Lock"):
            read_regular_at(
                triggers_descriptor,
                "Lock",
                0o600,
                expected_uid,
                expected_gid,
                0,
                "trigger Lock",
                pinned_files,
            )
        explicit_registry_names = set(
            bounded_directory_names(triggers_descriptor, "dpkg trigger directory")
        )
        explicit_registry_names.difference_update({"File", "Unincorp", "Lock"})
        explicit_registry_raw: dict[str, bytes] = {}
        explicit_registry_bytes = 0
        for name in sorted(explicit_registry_names):
            validate_trigger_subject(f"explicit:{name}", "explicit trigger filename")
            raw = read_regular_at(
                triggers_descriptor,
                name,
                0o644,
                expected_uid,
                expected_gid,
                MAX_EXPLICIT_TRIGGER_FILE_BYTES,
                f"explicit trigger registry {name}",
                pinned_files,
            )
            explicit_registry_bytes += len(raw)
            if explicit_registry_bytes > MAX_EXPLICIT_TRIGGER_TOTAL_BYTES:
                raise DpkgStateError(
                    "explicit trigger registries exceed their total byte bound"
                )
            explicit_registry_raw[name] = raw
            state_raw[f"triggers/{name}"] = raw

        packages = parse_status(state_raw["status"])
        trigger_records = list(parse_triggers(state_raw["triggers/File"], packages))
        for name, raw in sorted(explicit_registry_raw.items()):
            trigger_records.extend(parse_explicit_triggers(name, raw, packages))
            if len(trigger_records) > MAX_TRIGGER_RECORDS:
                raise DpkgStateError("trigger registries exceed their total record bound")
        triggers = tuple(
            sorted(
                trigger_records,
                key=lambda item: (
                    item.path,
                    item.package,
                    item.architecture,
                    item.mode,
                ),
            )
        )
        diversions = parse_diversions(state_raw["diversions"])
        statoverrides = parse_statoverrides(state_raw["statoverride"])
        handler_identities = sorted({(item.package, item.architecture) for item in triggers})
        if len(handler_identities) > MAX_HANDLER_RECORDS:
            raise DpkgStateError("dpkg trigger handler set exceeds its count bound")
        handlers = tuple(
            HandlerRecord(package, architecture, *packages[(package, architecture)])
            for package, architecture in handler_identities
        )
        handler_architectures: dict[str, set[str]] = {}
        for package, architecture in handler_identities:
            handler_architectures.setdefault(package, set()).add(architecture)
        scripts: list[ScriptRecord] = []
        script_bytes = 0
        for package, architecture in handler_identities:
            found_trigger_metadata = False
            for suffix in SCRIPT_SUFFIXES:
                unqualified = f"{package}.{suffix}"
                qualified = f"{package}:{architecture}.{suffix}"
                candidates = [
                    name
                    for name in (unqualified, qualified)
                    if entry_exists_at(info_descriptor, name)
                ]
                if len(candidates) > 1:
                    raise DpkgStateError("handler has ambiguous maintainer metadata names")
                if not candidates:
                    continue
                if (
                    candidates[0] == unqualified
                    and len(handler_architectures[package]) != 1
                ):
                    raise DpkgStateError(
                        "unqualified maintainer metadata is ambiguous across architectures"
                    )
                expected_mode = 0o644 if suffix == "triggers" else 0o755
                raw = read_regular_at(
                    info_descriptor,
                    candidates[0],
                    expected_mode,
                    expected_uid,
                    expected_gid,
                    MAX_SCRIPT_BYTES,
                    f"maintainer metadata {candidates[0]}",
                    pinned_files,
                )
                script_bytes += len(raw)
                if script_bytes > MAX_SCRIPT_TOTAL_BYTES:
                    raise DpkgStateError(
                        "dpkg maintainer scripts exceed their total byte bound"
                    )
                scripts.append(
                    ScriptRecord(
                        package,
                        architecture,
                        candidates[0],
                        expected_mode,
                        len(raw),
                        hashlib.sha256(raw).hexdigest(),
                    )
                )
                if suffix == "triggers":
                    found_trigger_metadata = True
            if not found_trigger_metadata:
                raise DpkgStateError("registered handler lacks its triggers metadata")
        state_files = tuple(
            StateFileRecord(name, 0o644, len(raw), hashlib.sha256(raw).hexdigest())
            for name, raw in sorted(state_raw.items())
        )
        state = DpkgState(
            state_files,
            triggers,
            handlers,
            diversions,
            statoverrides,
            tuple(
                sorted(
                    scripts,
                    key=lambda item: (item.package, item.architecture, item.filename),
                )
            ),
        )
        for name, label in directory_labels.items():
            descriptor, before = directories[name]
            verify_directory_at(
                admin_descriptor,
                name,
                descriptor,
                before,
                label,
            )
        final_namespace_verifier()
        verify_regular_file_pins(pinned_files)
        return state
    finally:
        for pinned in reversed(pinned_files):
            os.close(pinned.descriptor)
        for descriptor, _ in reversed(tuple(directories.values())):
            os.close(descriptor)


def serialize_dpkg_state(state: DpkgState) -> bytes:
    lines = [f"schema\t{STATE_SCHEMA}"]
    lines.extend(
        f"state-file\t{item.name}\t{item.mode:o}\t{item.size}\t{item.sha256}"
        for item in sorted(
            state.state_files,
            key=lambda item: (item.name, item.mode, item.size, item.sha256),
        )
    )
    lines.extend(
        f"trigger\t{item.path}\t{item.package}\t{item.architecture}\t{item.mode}"
        for item in sorted(
            state.triggers,
            key=lambda item: (item.path, item.package, item.architecture, item.mode),
        )
    )
    lines.extend(
        f"handler\t{item.package}\t{item.architecture}\t{item.version}\t{item.status}"
        for item in sorted(
            state.handlers,
            key=lambda item: (item.package, item.architecture, item.version, item.status),
        )
    )
    lines.extend(
        f"diversion\t{item.source}\t{item.destination}\t{item.package}"
        for item in sorted(
            state.diversions,
            key=lambda item: (item.source, item.destination, item.package),
        )
    )
    lines.extend(
        f"statoverride\t{item.user}\t{item.group}\t{item.mode}\t{item.path}"
        for item in sorted(
            state.statoverrides,
            key=lambda item: (item.path, item.user, item.group, item.mode),
        )
    )
    lines.extend(
        f"script\t{item.package}\t{item.architecture}\t{item.filename}\t"
        f"{item.mode:o}\t{item.size}\t{item.sha256}"
        for item in sorted(
            state.scripts,
            key=lambda item: (
                item.package,
                item.architecture,
                item.filename,
                item.mode,
                item.size,
                item.sha256,
            ),
        )
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def verify_dpkg_state(actual: DpkgState, expected: DpkgState) -> None:
    if type(actual) is not DpkgState or type(expected) is not DpkgState:
        raise DpkgStateError("dpkg state comparison received an invalid object")
    if actual != expected:
        raise DpkgStateError("dpkg mutable or trigger state differs from its reference")


def verify_post_dpkg_state(
    before: DpkgState,
    after: DpkgState,
    approved_handler_identities: tuple[tuple[str, str], ...],
) -> None:
    if type(before) is not DpkgState or type(after) is not DpkgState:
        raise DpkgStateError("post-state comparison received an invalid dpkg state")
    if (
        type(approved_handler_identities) is not tuple
        or any(
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(field) is not str for field in identity)
            or not PACKAGE_NAME.fullmatch(identity[0])
            or not ARCHITECTURE.fullmatch(identity[1])
            for identity in approved_handler_identities
        )
        or tuple(sorted(approved_handler_identities)) != approved_handler_identities
        or len(set(approved_handler_identities)) != len(approved_handler_identities)
    ):
        raise DpkgStateError("approved post-state package identities are not canonical")
    approved = set(approved_handler_identities)
    before_files = {item.name: item for item in before.state_files}
    after_files = {item.name: item for item in after.state_files}
    for name in ("diversions", "statoverride", "triggers/Unincorp"):
        if before_files.get(name) != after_files.get(name):
            raise DpkgStateError("dpkg static mutable state changed after transaction")
    if before.diversions != after.diversions or before.statoverrides != after.statoverrides:
        raise DpkgStateError("dpkg diversion or statoverride state changed after transaction")

    def changed_owners(before_records, after_records, key, owner) -> set[tuple[str, str]]:
        before_map = {key(item): item for item in before_records}
        after_map = {key(item): item for item in after_records}
        changed: set[tuple[str, str]] = set()
        for logical_key in before_map.keys() | after_map.keys():
            old = before_map.get(logical_key)
            new = after_map.get(logical_key)
            if old != new:
                if old is not None:
                    changed.add(owner(old))
                if new is not None:
                    changed.add(owner(new))
        return changed

    changed = changed_owners(
        before.triggers,
        after.triggers,
        lambda item: (item.path, item.package, item.architecture),
        lambda item: (item.package, item.architecture),
    )
    changed.update(
        changed_owners(
            before.handlers,
            after.handlers,
            lambda item: (item.package, item.architecture),
            lambda item: (item.package, item.architecture),
        )
    )
    changed.update(
        changed_owners(
            before.scripts,
            after.scripts,
            lambda item: (item.package, item.architecture, item.filename),
            lambda item: (item.package, item.architecture),
        )
    )
    if not changed.issubset(approved):
        raise DpkgStateError(
            "dpkg trigger or maintainer state changed outside the approved package set"
        )
    before_trigger_files = {
        name: record
        for name, record in before_files.items()
        if name.startswith("triggers/") and name != "triggers/Unincorp"
    }
    after_trigger_files = {
        name: record
        for name, record in after_files.items()
        if name.startswith("triggers/") and name != "triggers/Unincorp"
    }
    if before_trigger_files != after_trigger_files and before.triggers == after.triggers:
        raise DpkgStateError("dpkg trigger registry bytes changed without a semantic transition")


def logical_keys_are_unique(items: tuple, key) -> bool:
    keys = [key(item) for item in items]
    return len(keys) == len(set(keys))


def state_file_size_bound(name: str) -> int:
    if name in STATE_FILE_LIMITS:
        return STATE_FILE_LIMITS[name]
    if name.startswith("triggers/"):
        trigger_name = name.removeprefix("triggers/")
        if PACKAGE_NAME.fullmatch(trigger_name):
            return MAX_EXPLICIT_TRIGGER_FILE_BYTES
    return -1


def parse_dpkg_state_bytes(raw: bytes) -> DpkgState:
    if not raw or len(raw) > MAX_SERIALIZED_STATE_BYTES:
        raise DpkgStateError("dpkg state reference is empty or exceeds its size bound")
    if not raw.endswith(b"\n") or has_non_lf_control(raw):
        raise DpkgStateError("dpkg state reference has invalid framing")
    try:
        lines = raw.decode("utf-8")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise DpkgStateError("dpkg state reference must contain UTF-8 only") from exc
    if not lines or lines[0] != f"schema\t{STATE_SCHEMA}":
        raise DpkgStateError("dpkg state reference schema mismatch")
    order = {
        "state-file": 0,
        "trigger": 1,
        "handler": 2,
        "diversion": 3,
        "statoverride": 4,
        "script": 5,
    }
    section = 0
    state_files: list[StateFileRecord] = []
    triggers: list[TriggerRecord] = []
    handlers: list[HandlerRecord] = []
    diversions: list[DiversionRecord] = []
    statoverrides: list[StatoverrideRecord] = []
    scripts: list[ScriptRecord] = []
    script_bytes = 0
    for line in lines[1:]:
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind not in order or order[kind] < section:
            raise DpkgStateError("dpkg state reference section order is invalid")
        section = order[kind]
        if kind == "state-file" and len(fields) == 5:
            _, name, mode, size_text, digest = fields
            size_bound = state_file_size_bound(name)
            if (
                size_bound < 0
                or mode != "644"
                or not UNSIGNED.fullmatch(size_text)
                or int(size_text) > size_bound
                or not HEX64.fullmatch(digest)
            ):
                raise DpkgStateError("state-file reference exceeds its exact size bound or is invalid")
            if name not in STATE_FILE_LIMITS and int(size_text) == 0:
                raise DpkgStateError("explicit trigger registry file is empty")
            state_files.append(StateFileRecord(name, 0o644, int(size_text), digest))
        elif kind == "trigger" and len(fields) == 5:
            if len(triggers) >= MAX_TRIGGER_RECORDS:
                raise DpkgStateError(
                    "trigger reference exceeds its record-count bound"
                )
            _, path, package, architecture, trigger_mode = fields
            if (
                not PACKAGE_NAME.fullmatch(package)
                or not ARCHITECTURE.fullmatch(architecture)
                or trigger_mode not in {"await", "noawait"}
            ):
                raise DpkgStateError("invalid trigger reference record")
            triggers.append(
                TriggerRecord(
                    validate_trigger_subject(path, "trigger reference subject"),
                    package,
                    architecture,
                    trigger_mode,
                )
            )
        elif kind == "handler" and len(fields) == 5:
            if len(handlers) >= MAX_HANDLER_RECORDS:
                raise DpkgStateError(
                    "dpkg trigger handler set exceeds its count bound"
                )
            _, package, architecture, version, status_value = fields
            if (
                not PACKAGE_NAME.fullmatch(package)
                or not ARCHITECTURE.fullmatch(architecture)
                or not VERSION.fullmatch(version)
                or status_value not in {"install ok installed", "hold ok installed"}
            ):
                raise DpkgStateError("invalid handler reference record")
            handlers.append(HandlerRecord(package, architecture, version, status_value))
        elif kind == "diversion" and len(fields) == 4:
            _, source, destination, package = fields
            if package != "LOCAL" and not PACKAGE_NAME.fullmatch(package):
                raise DpkgStateError("invalid diversion reference owner")
            diversions.append(
                DiversionRecord(
                    validate_absolute_path(source, "diversion reference source"),
                    validate_absolute_path(destination, "diversion reference destination"),
                    package,
                )
            )
        elif kind == "statoverride" and len(fields) == 5:
            _, user, group, mode, path = fields
            if (
                not valid_statoverride_account(user)
                or not valid_statoverride_account(group)
                or not OVERRIDE_MODE.fullmatch(mode)
            ):
                raise DpkgStateError("invalid statoverride reference record")
            statoverrides.append(
                StatoverrideRecord(
                    user,
                    group,
                    mode,
                    validate_absolute_path(path, "statoverride reference path"),
                )
            )
        elif kind == "script" and len(fields) == 7:
            if len(scripts) >= MAX_SCRIPT_RECORDS:
                raise DpkgStateError(
                    "dpkg maintainer script set exceeds its count bound"
                )
            _, package, architecture, filename, mode_text, size_text, digest = fields
            suffix = filename.rsplit(".", 1)[-1] if "." in filename else ""
            expected_mode = "644" if suffix == "triggers" else "755"
            if (
                not PACKAGE_NAME.fullmatch(package)
                or not ARCHITECTURE.fullmatch(architecture)
                or suffix not in SCRIPT_SUFFIXES
                or filename not in {
                    f"{package}.{suffix}",
                    f"{package}:{architecture}.{suffix}",
                }
                or mode_text != expected_mode
                or not UNSIGNED.fullmatch(size_text)
                or int(size_text) > MAX_SCRIPT_BYTES
                or not HEX64.fullmatch(digest)
            ):
                raise DpkgStateError("invalid maintainer-script reference record")
            script_size = int(size_text)
            script_bytes += script_size
            if script_bytes > MAX_SCRIPT_TOTAL_BYTES:
                raise DpkgStateError(
                    "dpkg maintainer scripts exceed their total byte bound"
                )
            scripts.append(
                ScriptRecord(
                    package,
                    architecture,
                    filename,
                    int(mode_text, 8),
                    script_size,
                    digest,
                )
            )
        else:
            raise DpkgStateError("dpkg state reference contains an invalid record")
    state = DpkgState(
        tuple(state_files),
        tuple(triggers),
        tuple(handlers),
        tuple(diversions),
        tuple(statoverrides),
        tuple(scripts),
    )
    trigger_handler_identities = {
        (item.package, item.architecture) for item in triggers
    }
    handler_identities = {(item.package, item.architecture) for item in handlers}
    trigger_script_identities = {
        (item.package, item.architecture)
        for item in scripts
        if item.filename.endswith(".triggers")
    }
    handler_architectures: dict[str, set[str]] = {}
    for package, architecture in handler_identities:
        handler_architectures.setdefault(package, set()).add(architecture)
    if any(
        item.filename == f"{item.package}.{item.filename.rsplit('.', 1)[-1]}"
        and len(handler_architectures.get(item.package, ())) > 1
        for item in scripts
    ):
        raise DpkgStateError(
            "unqualified maintainer metadata is ambiguous across architectures"
        )
    required_state_files = {
        "status",
        "diversions",
        "statoverride",
        "triggers/File",
        "triggers/Unincorp",
    }
    state_file_names = {item.name for item in state_files}
    explicit_state_files = {
        item.name.removeprefix("triggers/"): item
        for item in state_files
        if item.name.startswith("triggers/")
        and item.name not in {"triggers/File", "triggers/Unincorp"}
    }
    explicit_trigger_names = {
        item.path.removeprefix("explicit:")
        for item in triggers
        if item.path.startswith("explicit:")
    }
    if (
        explicit_state_files.keys() != explicit_trigger_names
        or len(explicit_state_files) > MAX_DIRECTORY_ENTRIES
        or sum(item.size for item in explicit_state_files.values())
        > MAX_EXPLICIT_TRIGGER_TOTAL_BYTES
    ):
        raise DpkgStateError("explicit trigger registry files and records differ")
    if (
        not required_state_files.issubset(state_file_names)
        or len(state_files) != len(state_file_names)
        or not logical_keys_are_unique(
            tuple(triggers),
            lambda item: (item.path, item.package, item.architecture),
        )
        or not logical_keys_are_unique(
            tuple(handlers), lambda item: (item.package, item.architecture)
        )
        or not logical_keys_are_unique(tuple(diversions), lambda item: item.source)
        or not logical_keys_are_unique(tuple(diversions), lambda item: item.destination)
        or not logical_keys_are_unique(tuple(statoverrides), lambda item: item.path)
        or not logical_keys_are_unique(
            tuple(scripts),
            lambda item: (
                item.package,
                item.architecture,
                item.filename.rsplit(".", 1)[-1],
            ),
        )
        or not logical_keys_are_unique(tuple(scripts), lambda item: item.filename)
        or handler_identities != trigger_handler_identities
        or trigger_script_identities != handler_identities
        or serialize_dpkg_state(state) != raw
    ):
        raise DpkgStateError(
            "dpkg state reference has a duplicate logical key or is noncanonical"
        )
    if any((item.package, item.architecture) not in handler_identities for item in triggers):
        raise DpkgStateError("trigger reference lacks its handler package")
    if any((item.package, item.architecture) not in handler_identities for item in scripts):
        raise DpkgStateError("script reference lacks its handler package")
    return state


def host_reference_from_state(state: DpkgState) -> DpkgHostReference:
    if type(state) is not DpkgState:
        raise DpkgStateError("host reference requires a captured dpkg state")
    required_static_names = {"diversions", "statoverride", "triggers/File"}
    state_files = tuple(
        item
        for item in state.state_files
        if item.name in {"diversions", "statoverride"}
        or item.name.startswith("triggers/")
        and item.name != "triggers/Unincorp"
    )
    state_file_names = {item.name for item in state_files}
    if (
        not required_static_names.issubset(state_file_names)
        or len(state_files) != len(state_file_names)
    ):
        raise DpkgStateError("captured dpkg state lacks static host-reference files")
    return DpkgHostReference(
        state_files,
        state.triggers,
        state.handlers,
        state.diversions,
        state.statoverrides,
        state.scripts,
    )


def serialize_host_reference(reference: DpkgHostReference) -> bytes:
    if type(reference) is not DpkgHostReference:
        raise DpkgStateError("host reference serializer received an invalid object")
    lines = [f"schema\t{HOST_REFERENCE_SCHEMA}"]
    lines.extend(
        f"state-file\t{item.name}\t{item.mode:o}\t{item.size}\t{item.sha256}"
        for item in sorted(
            reference.state_files,
            key=lambda item: (item.name, item.mode, item.size, item.sha256),
        )
    )
    lines.extend(
        f"trigger\t{item.path}\t{item.package}\t{item.architecture}\t{item.mode}"
        for item in sorted(
            reference.triggers,
            key=lambda item: (item.path, item.package, item.architecture, item.mode),
        )
    )
    lines.extend(
        f"handler\t{item.package}\t{item.architecture}\t{item.version}\t{item.status}"
        for item in sorted(
            reference.handlers,
            key=lambda item: (item.package, item.architecture, item.version, item.status),
        )
    )
    lines.extend(
        f"diversion\t{item.source}\t{item.destination}\t{item.package}"
        for item in sorted(
            reference.diversions,
            key=lambda item: (item.source, item.destination, item.package),
        )
    )
    lines.extend(
        f"statoverride\t{item.user}\t{item.group}\t{item.mode}\t{item.path}"
        for item in sorted(
            reference.statoverrides,
            key=lambda item: (item.path, item.user, item.group, item.mode),
        )
    )
    lines.extend(
        f"script\t{item.package}\t{item.architecture}\t{item.filename}\t"
        f"{item.mode:o}\t{item.size}\t{item.sha256}"
        for item in sorted(
            reference.scripts,
            key=lambda item: (
                item.package,
                item.architecture,
                item.filename,
                item.mode,
                item.size,
                item.sha256,
            ),
        )
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_host_reference_bytes(raw: bytes) -> DpkgHostReference:
    if not raw or len(raw) > MAX_SERIALIZED_STATE_BYTES:
        raise DpkgStateError("host reference is empty or exceeds its size bound")
    if not raw.endswith(b"\n") or has_non_lf_control(raw):
        raise DpkgStateError("host reference has invalid framing")
    try:
        lines = raw.decode("utf-8")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise DpkgStateError("host reference must contain UTF-8 only") from exc
    if not lines or lines[0] != f"schema\t{HOST_REFERENCE_SCHEMA}":
        raise DpkgStateError("host reference schema mismatch")
    state_lines = [line for line in lines[1:] if line.startswith("state-file\t")]
    other_lines = [line for line in lines[1:] if not line.startswith("state-file\t")]
    empty_digest = hashlib.sha256(b"").hexdigest()
    state_lines.extend(
        (
            f"state-file\tstatus\t644\t0\t{empty_digest}",
            f"state-file\ttriggers/Unincorp\t644\t0\t{empty_digest}",
        )
    )
    full_raw = (
        "\n".join(
            [f"schema\t{STATE_SCHEMA}", *sorted(state_lines), *other_lines]
        )
        + "\n"
    ).encode("utf-8")
    state = parse_dpkg_state_bytes(full_raw)
    reference = host_reference_from_state(state)
    if serialize_host_reference(reference) != raw:
        raise DpkgStateError("host reference is duplicate or noncanonical")
    return reference


def verify_host_reference(actual: DpkgState, expected: DpkgHostReference) -> None:
    if type(actual) is not DpkgState or type(expected) is not DpkgHostReference:
        raise DpkgStateError("host reference comparison received an invalid object")
    if host_reference_from_state(actual) != expected:
        raise DpkgStateError("dpkg trigger host state differs from its reviewed reference")


def parse_numeric_id(value: str) -> int:
    if not UNSIGNED.fullmatch(value):
        raise argparse.ArgumentTypeError("owner/group id is not canonical")
    number = int(value)
    if number > 2**32 - 1:
        raise argparse.ArgumentTypeError("owner/group id exceeds its bound")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--capture-state", action="store_true")
    modes.add_argument("--capture-host-reference", action="store_true")
    modes.add_argument("--verify-state", action="store_true")
    modes.add_argument("--verify-host-reference", action="store_true")
    parser.add_argument("admin")
    parser.add_argument("expected_uid", type=parse_numeric_id)
    parser.add_argument("expected_gid", type=parse_numeric_id)
    parser.add_argument("reference", nargs="?")
    arguments = parser.parse_args()
    capture_mode = arguments.capture_state or arguments.capture_host_reference
    if capture_mode == (arguments.reference is not None):
        raise SystemExit("capture modes forbid a reference; verify modes require one")
    try:
        admin = pathlib.Path(arguments.admin)
        state = capture_dpkg_state(
            admin,
            arguments.expected_uid,
            arguments.expected_gid,
        )
        if arguments.capture_state:
            sys.stdout.buffer.write(serialize_dpkg_state(state))
            return
        if arguments.capture_host_reference:
            sys.stdout.buffer.write(
                serialize_host_reference(host_reference_from_state(state))
            )
            return
        reference_path = pathlib.Path(arguments.reference)
        if not reference_path.is_absolute():
            raise DpkgStateError("dpkg reference path must be absolute")
        reference_raw = read_regular(
            reference_path,
            0o600,
            arguments.expected_uid,
            arguments.expected_gid,
            MAX_SERIALIZED_STATE_BYTES,
            "dpkg reference",
        )
        if arguments.verify_state:
            verify_dpkg_state(state, parse_dpkg_state_bytes(reference_raw))
            print("HAPTICS_DPKG_STATE=PASS")
        else:
            verify_host_reference(state, parse_host_reference_bytes(reference_raw))
            print("HAPTICS_DPKG_HOST_REFERENCE=PASS")
    except (OSError, DpkgStateError) as exc:
        raise SystemExit(f"haptics dpkg state verification failed: {exc}") from exc


if __name__ == "__main__":
    main()
