#!/usr/bin/env python3
"""Verify that native dpkg cannot consume mutable host or user options."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
import errno
import hashlib
import os
import pathlib
import re
import stat
import sys


REVIEWED_CONFIG_SHA256 = "fead43b89af3ea5691c48f32d7fe1ba0f7ab229fb5d230f612d76fe8e6f5a015"
MAX_CONFIG_BYTES = 4096
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 128
MAX_DESCRIPTOR_SNAPSHOT_ENTRIES = 4096
DESCRIPTOR_SETTLEMENT_ATTEMPTS = 3
UNSIGNED_INTEGER = re.compile(r"0|[1-9][0-9]{0,9}")
_TRUSTED_SCANDIR = os.scandir
_TRUSTED_FSTAT = os.fstat


class DpkgConfigurationError(ValueError):
    pass


@dataclass
class DescriptorOwner:
    descriptor: int = -1


@dataclass(frozen=True)
class DirectoryPin:
    descriptor: int
    parent_descriptor: int | None
    name: str | None
    metadata: os.stat_result
    label: str


@dataclass(frozen=True)
class RegularFilePin:
    descriptor: int
    directory_descriptor: int
    name: str
    metadata: os.stat_result
    sha256: str
    label: str


def stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def stable_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    )


def choose_cleanup_failure(
    current: BaseException | None,
    new: BaseException,
    note: str,
) -> BaseException:
    if current is None:
        return new

    def priority(failure: BaseException) -> int:
        if isinstance(failure, KeyboardInterrupt):
            return 2
        if not isinstance(failure, Exception):
            return 1
        return 0

    if priority(new) > priority(current):
        new.add_note(note)
        if new.__cause__ is None and isinstance(current, Exception):
            new.__cause__ = current
        return new
    if new is not current:
        current.add_note(note)
    return current


def fixed_cleanup_candidate(exc: BaseException, message: str) -> BaseException:
    if not isinstance(exc, Exception):
        return exc
    failure = DpkgConfigurationError(message)
    failure.__cause__ = exc
    return failure


def snapshot_live_descriptors(label: str) -> frozenset[int]:
    descriptors: set[int] = set()
    try:
        with _TRUSTED_SCANDIR("/proc/self/fd") as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_DESCRIPTOR_SNAPSHOT_ENTRIES:
                    raise DpkgConfigurationError(
                        f"{label} descriptor snapshot exceeds its entry bound"
                    )
                if not entry.name.isascii() or not entry.name.isdecimal():
                    raise DpkgConfigurationError(
                        f"{label} descriptor snapshot is malformed"
                    )
                descriptor = int(entry.name, 10)
                if str(descriptor) != entry.name:
                    raise DpkgConfigurationError(
                        f"{label} descriptor snapshot is not canonical"
                    )
                descriptors.add(descriptor)
    except DpkgConfigurationError:
        raise
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise DpkgConfigurationError(
            f"cannot enumerate {label} descriptors"
        ) from exc
    live: set[int] = set()
    for descriptor in descriptors:
        try:
            _TRUSTED_FSTAT(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise DpkgConfigurationError(
                f"cannot inspect {label} descriptor snapshot"
            ) from exc
        live.add(descriptor)
    return frozenset(live)


def close_owned_descriptor(
    owner: DescriptorOwner,
    label: str,
) -> tuple[BaseException | None, bool]:
    descriptor = owner.descriptor
    if descriptor < 0:
        return None, True
    failure: BaseException | None = None
    for _ in range(DESCRIPTOR_SETTLEMENT_ATTEMPTS):
        try:
            os.close(descriptor)
        except BaseException as exc:
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(exc, f"cannot close {label} descriptor"),
                f"{label} descriptor close also failed",
            )
        try:
            _TRUSTED_FSTAT(descriptor)
        except OSError as probe:
            if probe.errno == errno.EBADF:
                owner.descriptor = -1
                return failure, True
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(
                    probe,
                    f"cannot determine {label} descriptor custody",
                ),
                f"{label} descriptor custody inspection also failed",
            )
        except BaseException as probe:
            failure = choose_cleanup_failure(
                failure,
                fixed_cleanup_candidate(
                    probe,
                    f"cannot determine {label} descriptor custody",
                ),
                f"{label} descriptor custody inspection also failed",
            )
    failure = choose_cleanup_failure(
        failure,
        DpkgConfigurationError(f"{label} descriptor close did not converge"),
        f"{label} descriptor cleanup also did not converge",
    )
    return failure, False


def settle_descriptor_owners(
    owners: list[DescriptorOwner],
    label: str,
) -> BaseException | None:
    failure: BaseException | None = None
    for index, owner in reversed(tuple(enumerate(owners))):
        if owner.descriptor < 0:
            continue
        close_failure, _ = close_owned_descriptor(
            owner,
            f"{label} #{index + 1}",
        )
        if close_failure is not None:
            failure = choose_cleanup_failure(
                failure,
                close_failure,
                f"{label} #{index + 1} cleanup also failed",
            )
    return failure


def acquire_owned_descriptor(
    owner: DescriptorOwner,
    opener: Callable[[], int],
    label: str,
) -> int:
    if owner.descriptor >= 0:
        raise DpkgConfigurationError(f"{label} descriptor owner is already populated")
    baseline = snapshot_live_descriptors(label)
    returned: object = None
    try:
        returned = opener()
        if (
            not isinstance(returned, int)
            or isinstance(returned, bool)
            or returned < 0
            or returned in baseline
        ):
            raise DpkgConfigurationError(f"{label} returned an invalid descriptor")
        owner.descriptor = returned
        _TRUSTED_FSTAT(returned)
        if os.get_inheritable(returned):
            raise DpkgConfigurationError(f"{label} returned an inheritable descriptor")
        return returned
    except BaseException as exc:
        primary: BaseException = exc
        candidates: set[int] = set()
        if owner.descriptor >= 0:
            if owner.descriptor in baseline:
                owner.descriptor = -1
            else:
                candidates.add(owner.descriptor)
        if (
            isinstance(returned, int)
            and not isinstance(returned, bool)
            and returned >= 0
            and returned not in baseline
        ):
            candidates.add(returned)
        try:
            candidates.update(snapshot_live_descriptors(label) - baseline)
        except BaseException as snapshot_exc:
            primary = choose_cleanup_failure(
                primary,
                fixed_cleanup_candidate(
                    snapshot_exc,
                    f"cannot recover applied {label} descriptor acquisition",
                ),
                f"{label} applied-acquisition recovery also failed",
            )
        if len(candidates) > 1:
            primary = choose_cleanup_failure(
                primary,
                DpkgConfigurationError(
                    f"{label} acquisition introduced unexpected descriptors"
                ),
                f"{label} acquisition containment also failed",
            )
        for descriptor in sorted(candidates, reverse=True):
            recovery_owner = owner if descriptor == owner.descriptor else DescriptorOwner(descriptor)
            close_failure, _ = close_owned_descriptor(
                recovery_owner,
                f"applied {label}",
            )
            if close_failure is not None:
                primary = choose_cleanup_failure(
                    primary,
                    close_failure,
                    f"applied {label} cleanup also failed",
                )
        raise primary


def verify_directory_pin(pin: DirectoryPin) -> None:
    try:
        after = os.fstat(pin.descriptor)
        if pin.parent_descriptor is None:
            namespace = os.stat("/", follow_symlinks=False)
        else:
            namespace = os.stat(
                pin.name,
                dir_fd=pin.parent_descriptor,
                follow_symlinks=False,
            )
    except OSError as exc:
        raise DpkgConfigurationError(
            f"{pin.label} namespace changed during verification: {exc}"
        ) from exc
    if (
        stable_directory_identity(after) != stable_directory_identity(pin.metadata)
        or stable_directory_identity(namespace) != stable_directory_identity(after)
    ):
        raise DpkgConfigurationError(f"{pin.label} namespace changed during verification")


def pin_directory_chain(
    path: pathlib.Path,
    owners: list[DescriptorOwner],
    mode: int,
    owner: int,
    group: int,
    label: str,
) -> tuple[DirectoryPin, ...]:
    path_text = str(path)
    components = path.parts
    try:
        path_size = len(os.fsencode(path_text))
    except UnicodeEncodeError as exc:
        raise DpkgConfigurationError(f"{label} path is not canonical") from exc
    if (
        not path.is_absolute()
        or path_size > MAX_PATH_BYTES
        or "\x00" in path_text
        or len(components) < 2
        or components[0] != "/"
        or len(components) - 1 > MAX_PATH_COMPONENTS
        or any(component in {"", ".", ".."} for component in components[1:])
        or path_text != "/" + "/".join(components[1:])
    ):
        raise DpkgConfigurationError(f"{label} path is not canonical")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise DpkgConfigurationError(f"{label} cannot enforce no-follow directory opens")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    pins: list[DirectoryPin] = []
    root_owner = DescriptorOwner()
    owners.append(root_owner)
    descriptor = acquire_owned_descriptor(
        root_owner,
        lambda: os.open("/", flags),
        f"{label} root",
    )
    metadata = os.fstat(descriptor)
    namespace = os.stat("/", follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stable_directory_identity(namespace) != stable_directory_identity(metadata)
    ):
        raise DpkgConfigurationError(f"{label} root namespace is not stable")
    pins.append(DirectoryPin(descriptor, None, None, metadata, f"{label} root"))
    parent_descriptor = descriptor
    for component in components[1:]:
        child_owner = DescriptorOwner()
        owners.append(child_owner)
        descriptor = acquire_owned_descriptor(
            child_owner,
            lambda component=component, parent_descriptor=parent_descriptor: os.open(
                component,
                flags,
                dir_fd=parent_descriptor,
            ),
            f"{label} ancestor",
        )
        metadata = os.fstat(descriptor)
        namespace = os.stat(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stable_directory_identity(namespace)
            != stable_directory_identity(metadata)
        ):
            raise DpkgConfigurationError(f"{label} ancestor namespace is not stable")
        pins.append(
            DirectoryPin(
                descriptor,
                parent_descriptor,
                component,
                metadata,
                f"{label} ancestor {component}",
            )
        )
        parent_descriptor = descriptor
    final = pins[-1].metadata
    if (
        stat.S_IMODE(final.st_mode) != mode
        or final.st_uid != owner
        or final.st_gid != group
    ):
        raise DpkgConfigurationError(f"{label} ownership or mode differs from policy")
    for pin in pins[:-1]:
        ancestor_mode = stat.S_IMODE(pin.metadata.st_mode)
        if pin.metadata.st_uid not in {0, owner} or (
            ancestor_mode & 0o022
            and not (pin.metadata.st_uid == 0 and ancestor_mode & stat.S_ISVTX)
        ):
            raise DpkgConfigurationError(f"{label} has an untrusted ancestor")
    return tuple(pins)


def parse_identity(value: str, label: str) -> int:
    if not UNSIGNED_INTEGER.fullmatch(value):
        raise DpkgConfigurationError(f"invalid expected {label}")
    number = int(value)
    if number > 2**32 - 2:
        raise DpkgConfigurationError(f"expected {label} exceeds the uid/gid bound")
    return number


def read_reviewed_config(
    directory_descriptor: int,
    descriptor_owners: list[DescriptorOwner],
    owner: int,
    group: int,
) -> RegularFilePin:
    if not hasattr(os, "O_NOFOLLOW"):
        raise DpkgConfigurationError("dpkg.cfg cannot enforce a no-follow open")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    descriptor_owner = DescriptorOwner()
    descriptor_owners.append(descriptor_owner)
    try:
        descriptor = acquire_owned_descriptor(
            descriptor_owner,
            lambda: os.open(
                "dpkg.cfg",
                flags,
                dir_fd=directory_descriptor,
            ),
            "dpkg.cfg",
        )
    except OSError as exc:
        raise DpkgConfigurationError(f"cannot open dpkg.cfg: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        namespace = os.stat(
            "dpkg.cfg",
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(metadata.st_mode):
            raise DpkgConfigurationError("dpkg.cfg is not a regular file")
        if (
            stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_uid != owner
            or metadata.st_gid != group
            or metadata.st_nlink != 1
            or stable_file_identity(namespace) != stable_file_identity(metadata)
        ):
            raise DpkgConfigurationError(
                "dpkg.cfg ownership, mode, links, or namespace differ from policy"
            )
        if metadata.st_size > MAX_CONFIG_BYTES:
            raise DpkgConfigurationError("dpkg.cfg exceeds its size bound")
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_CONFIG_BYTES:
            raise DpkgConfigurationError("dpkg.cfg exceeds its read bound")
        if hashlib.sha256(raw).hexdigest() != REVIEWED_CONFIG_SHA256:
            raise DpkgConfigurationError("dpkg.cfg differs from the reviewed Ubuntu default")
        after = os.fstat(descriptor)
        namespace = os.stat(
            "dpkg.cfg",
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            stable_file_identity(after) != stable_file_identity(metadata)
            or stable_file_identity(namespace) != stable_file_identity(after)
        ):
            raise DpkgConfigurationError(
                "dpkg.cfg namespace changed while it was read"
            )
        return RegularFilePin(
            descriptor,
            directory_descriptor,
            "dpkg.cfg",
            metadata,
            hashlib.sha256(raw).hexdigest(),
            "dpkg.cfg",
        )
    except DpkgConfigurationError:
        raise
    except OSError as exc:
        raise DpkgConfigurationError(f"cannot verify dpkg.cfg: {exc}") from exc


def verify_reviewed_config_pin(pin: RegularFilePin) -> None:
    try:
        before = os.fstat(pin.descriptor)
        os.lseek(pin.descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(pin.descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(pin.descriptor)
        namespace = os.stat(
            pin.name,
            dir_fd=pin.directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise DpkgConfigurationError(
            f"{pin.label} namespace changed before verification completed: {exc}"
        ) from exc
    if (
        len(raw) > MAX_CONFIG_BYTES
        or stable_file_identity(before) != stable_file_identity(pin.metadata)
        or stable_file_identity(after) != stable_file_identity(before)
        or stable_file_identity(namespace) != stable_file_identity(after)
        or hashlib.sha256(raw).hexdigest() != pin.sha256
        or pin.sha256 != REVIEWED_CONFIG_SHA256
    ):
        raise DpkgConfigurationError(
            f"{pin.label} namespace changed before verification completed"
        )


def require_empty_parts(
    directory_descriptor: int,
    descriptor_owners: list[DescriptorOwner],
    owner: int,
    group: int,
) -> DirectoryPin:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise DpkgConfigurationError("dpkg.cfg.d cannot enforce a no-follow open")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor_owner = DescriptorOwner()
    descriptor_owners.append(descriptor_owner)
    try:
        descriptor = acquire_owned_descriptor(
            descriptor_owner,
            lambda: os.open(
                "dpkg.cfg.d",
                flags,
                dir_fd=directory_descriptor,
            ),
            "dpkg.cfg.d",
        )
    except OSError as exc:
        raise DpkgConfigurationError(f"cannot open dpkg.cfg.d: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        namespace = os.stat(
            "dpkg.cfg.d",
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_uid != owner
            or metadata.st_gid != group
            or metadata.st_dev != os.fstat(directory_descriptor).st_dev
            or stable_file_identity(namespace) != stable_file_identity(metadata)
        ):
            raise DpkgConfigurationError(
                "dpkg.cfg.d ownership, mode, or namespace differs from policy"
            )
        require_empty_directory_descriptor(descriptor, "dpkg.cfg.d")
        after = os.fstat(descriptor)
        namespace = os.stat(
            "dpkg.cfg.d",
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            stable_file_identity(after) != stable_file_identity(metadata)
            or stable_file_identity(namespace) != stable_file_identity(after)
        ):
            raise DpkgConfigurationError(
                "dpkg.cfg.d namespace changed while it was enumerated"
            )
        return DirectoryPin(
            descriptor,
            directory_descriptor,
            "dpkg.cfg.d",
            metadata,
            "dpkg.cfg.d",
        )
    except DpkgConfigurationError:
        raise
    except OSError as exc:
        raise DpkgConfigurationError(f"cannot verify dpkg.cfg.d: {exc}") from exc


def verify_empty_parts_pin(pin: DirectoryPin) -> None:
    try:
        before = os.fstat(pin.descriptor)
        require_empty_directory_descriptor(pin.descriptor, "dpkg.cfg.d")
        after = os.fstat(pin.descriptor)
        namespace = os.stat(
            pin.name,
            dir_fd=pin.parent_descriptor,
            follow_symlinks=False,
        )
    except DpkgConfigurationError:
        raise
    except OSError as exc:
        raise DpkgConfigurationError(
            f"dpkg.cfg.d namespace changed before verification completed: {exc}"
        ) from exc
    if (
        stable_file_identity(before) != stable_file_identity(pin.metadata)
        or stable_file_identity(after) != stable_file_identity(before)
        or stable_file_identity(namespace) != stable_file_identity(after)
    ):
        raise DpkgConfigurationError(
            "dpkg.cfg.d namespace changed before verification completed"
        )


def require_absent_at(directory_descriptor: int, name: str, label: str) -> None:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DpkgConfigurationError(f"cannot inspect {label}: {exc}") from exc
    raise DpkgConfigurationError(f"{label} exists")


def require_empty_directory_descriptor(descriptor: int, label: str) -> None:
    try:
        with os.scandir(descriptor) as entries:
            try:
                next(entries)
            except StopIteration:
                return
    except OSError as exc:
        raise DpkgConfigurationError(f"cannot enumerate {label}: {exc}") from exc
    raise DpkgConfigurationError(f"{label} is not empty")


def verify(
    config_dir: pathlib.Path,
    home: pathlib.Path,
    config_owner: int,
    config_group: int,
    home_owner: int,
    home_group: int,
) -> None:
    descriptor_owners: list[DescriptorOwner] = []
    config_pins: tuple[DirectoryPin, ...] = ()
    home_pins: tuple[DirectoryPin, ...] = ()
    config_pin: RegularFilePin | None = None
    parts_pin: DirectoryPin | None = None
    primary: BaseException | None = None
    try:
        config_pins = pin_directory_chain(
            config_dir,
            descriptor_owners,
            0o755,
            config_owner,
            config_group,
            "dpkg configuration",
        )
        config_descriptor = config_pins[-1].descriptor
        config_pin = read_reviewed_config(
            config_descriptor,
            descriptor_owners,
            config_owner,
            config_group,
        )
        parts_pin = require_empty_parts(
            config_descriptor,
            descriptor_owners,
            config_owner,
            config_group,
        )
        home_pins = pin_directory_chain(
            home,
            descriptor_owners,
            0o700,
            home_owner,
            home_group,
            "private dpkg home",
        )
        home_descriptor = home_pins[-1].descriptor
        require_absent_at(
            home_descriptor,
            ".dpkg.cfg",
            "private dpkg home .dpkg.cfg",
        )
        for _ in range(2):
            verify_reviewed_config_pin(config_pin)
            verify_empty_parts_pin(parts_pin)
            require_absent_at(
                home_descriptor,
                ".dpkg.cfg",
                "private dpkg home .dpkg.cfg",
            )
            for pin in (*config_pins, *home_pins):
                verify_directory_pin(pin)
    except BaseException as exc:
        primary = exc
    cleanup_failure = settle_descriptor_owners(
        descriptor_owners,
        "dpkg configuration verification",
    )
    if cleanup_failure is not None:
        primary = choose_cleanup_failure(
            primary,
            cleanup_failure,
            "dpkg configuration descriptor cleanup also failed",
        )
    if primary is not None:
        raise primary


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--expected-owner", required=True)
    parser.add_argument("--expected-group", required=True)
    parser.add_argument("--expected-home-owner")
    parser.add_argument("--expected-home-group")
    parser.add_argument("config_dir")
    parser.add_argument("home")
    try:
        arguments = parser.parse_args()
        owner = parse_identity(arguments.expected_owner, "owner")
        group = parse_identity(arguments.expected_group, "group")
        home_owner = parse_identity(
            arguments.expected_home_owner or arguments.expected_owner, "home owner"
        )
        home_group = parse_identity(
            arguments.expected_home_group or arguments.expected_group, "home group"
        )
        verify(
            pathlib.Path(arguments.config_dir),
            pathlib.Path(arguments.home),
            owner,
            group,
            home_owner,
            home_group,
        )
    except (DpkgConfigurationError, OSError) as exc:
        raise SystemExit(f"haptics dpkg configuration verification failed: {exc}") from exc
    print("HAPTICS_DPKG_CONFIGURATION=PASS")


if __name__ == "__main__":
    main()
