#!/usr/bin/env python3
"""Parse and verify the exact Ubuntu package closure for haptics builds."""

from __future__ import annotations

import errno
import hashlib
import math
import os
import pathlib
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass


SCHEMA = "tb321fu.haptics-build-packages/v2"
SNAPSHOTS = (
    "https://snapshot.ubuntu.com/ubuntu/20260730T000000Z/",
)
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,79}")
PACKAGE_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+:~\-]{0,159}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_LOCK_BYTES = 32768
EXPECTED_LOCK_SHA256 = "a6acdcd26063bae02edd930e1d2ec46f23c9e072cfc842ea7ccfe5812352cc75"
EXPECTED_PACKAGE_COUNT = 209
EXPECTED_CLOSURE_COUNT = 100
EXPECTED_ALTERNATIVES = {"awk": ("manual", "/usr/bin/gawk")}
BOOTSTRAP_ARCHITECTURES = {
    "apt": "amd64",
    "ca-certificates": "all",
    "dpkg": "amd64",
    "ubuntu-keyring": "all",
}
MAX_PLAN_BYTES = 4 * 1024 * 1024
PLAN_IDENTITY_PATTERN = (
    r"[a-z0-9][a-z0-9+.-]{0,79}:[a-z0-9][a-z0-9-]{0,31}"
)
PLAN_LINE = re.compile(
    r"(Inst|Conf) "
    r"([a-z0-9][a-z0-9+.-]{0,79})(?::([a-z0-9][a-z0-9-]{0,31}))?"
    r"(?: \[([^\]\s]+)\])? "
    r"\(([^()\s]+) [^\r\n\t]* \[([a-z0-9][a-z0-9-]{0,31})\]\)"
    r"(.*)"
)
PLAN_DEPENDENCY_ANNOTATION = re.compile(
    rf"{PLAN_IDENTITY_PATTERN} on {PLAN_IDENTITY_PATTERN}"
)
PLAN_SHORT_BREAKS_ANNOTATION = re.compile(rf"(?:{PLAN_IDENTITY_PATTERN} )*")
MAX_PLAN_ANNOTATION_GROUPS = 512
EXPECTED_PACKAGES = tuple(sorted("""
apt bash bc binutils binutils-aarch64-linux-gnu binutils-common
binutils-x86-64-linux-gnu bison ca-certificates coreutils
cpp-13-aarch64-linux-gnu cpp-aarch64-linux-gnu curl dash diffutils dpkg
dpkg-dev findutils flex gawk gcc gcc-13 gcc-13-aarch64-linux-gnu
gcc-13-aarch64-linux-gnu-base gcc-13-cross-base gcc-13-x86-64-linux-gnu
gcc-aarch64-linux-gnu git grep gzip kmod libacl1 libattr1 libbinutils
libbrotli1 libbz2-1.0 libc-bin libc-dev-bin libc-devtools libc6 libc6-dev
libcom-err2 libctf-nobfd0 libctf0 libcurl3t64-gnutls libcurl4t64
libexpat1 libffi8 libgcc-13-dev-arm64-cross libgmp10 libgnutls30t64
libgprofng0 libgssapi-krb5-2 libhogweed6t64 libidn2-0 libisl23
libjansson4 libk5crypto3 libkeyutils1 libkrb5-3 libkrb5support0
libldap-common libldap2 liblz4-1 liblzma5 libmd0 libmpc3 libmpfr6
libnettle8t64 libnghttp2-14 libp11-kit0 libpcre2-8-0 libpopt0
libpsl5t64 libpython3-stdlib libpython3.12-minimal libpython3.12-stdlib
libreadline8t64 librtmp1 libsasl2-2 libselinux1 libsframe1 libsigsegv2
libssh-4 libssl-dev libssl3t64 libtasn1-6 libtinfo6 libunistring5
libxxhash0 libyaml-0-2 libzstd1 locales m4 make openssl python3
python3-minimal python3-yaml python3.12 python3.12-minimal rsync sed tar unzip
ubuntu-keyring xz-utils zlib1g zstd
""".split()))
COMPAT_PACKAGES = (
    (
        "libc-bin", "amd64", "2.39-0ubuntu8.7",
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/g/glibc/libc-bin_2.39-0ubuntu8.7_amd64.deb",
        "38e3e603aeca8cbbaefce34eec6b8190f53939425bf2eb2c8a3956d0a947a630",
    ),
    (
        "libc-dev-bin", "amd64", "2.39-0ubuntu8.7",
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/g/glibc/libc-dev-bin_2.39-0ubuntu8.7_amd64.deb",
        "83291a1d9b26262ac8f44a3bb188ce2cb796a0543134aae00e19db066c84dfdd",
    ),
    (
        "libc-devtools", "amd64", "2.39-0ubuntu8.7",
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/g/glibc/libc-devtools_2.39-0ubuntu8.7_amd64.deb",
        "24a808559d1505b99cb197cb16bc198a9afb595a9b412c772efaba5b1d061f2f",
    ),
    (
        "libc6", "amd64", "2.39-0ubuntu8.7",
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/g/glibc/libc6_2.39-0ubuntu8.7_amd64.deb",
        "955644e8bc2930a9bf8eea5e4c2237c8a118c1e2ac2845b993b6f7f35eefd293",
    ),
    (
        "libc6-dev", "amd64", "2.39-0ubuntu8.7",
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/g/glibc/libc6-dev_2.39-0ubuntu8.7_amd64.deb",
        "bbf5a155039042634961a61276650631ee47b9e721f91f8dbb731b0bbe046df3",
    ),
    (
        "libldap-common", "all", "2.6.7+dfsg-1~exp1ubuntu8.2",
        "https://snapshot.ubuntu.com/ubuntu/20260201T000000Z/pool/main/o/openldap/libldap-common_2.6.7+dfsg-1~exp1ubuntu8.2_all.deb",
        "f1da79d8033ba0fe5e6167f27361c4619eb8822143ca65c0ac983565f57520bd",
    ),
    (
        "libldap2", "amd64", "2.6.7+dfsg-1~exp1ubuntu8.2",
        "https://snapshot.ubuntu.com/ubuntu/20260201T000000Z/pool/main/o/openldap/libldap2_2.6.7+dfsg-1~exp1ubuntu8.2_amd64.deb",
        "17000967a1fae30c8dbb92b2183ec6e245c6d802aacf2c2945a20ee89298b8e9",
    ),
    (
        "locales", "all", "2.39-0ubuntu8.7",
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/pool/main/g/glibc/locales_2.39-0ubuntu8.7_all.deb",
        "27e74084e2b33a05754e10a4c304ed0a559b3325098fa65b2930fc46e914aaaf",
    ),
)
BOOTSTRAP_PACKAGES = ("apt", "ca-certificates", "dpkg", "ubuntu-keyring")


class PackageLockError(ValueError):
    pass


@dataclass(frozen=True)
class PlannedPackage:
    version: str
    architecture: str
    old_version: str | None = None


@dataclass(frozen=True)
class AptPlan:
    installs: dict[tuple[str, str], PlannedPackage]
    configures: dict[tuple[str, str], PlannedPackage]


@dataclass(frozen=True)
class AlternativeState:
    mode: str
    target: bytes | None
    query_sha256: str


EXPECTED_AWK_ALTERNATIVE_STATE = AlternativeState(
    "manual",
    b"/usr/bin/gawk",
    "de2080a49a1b964d0421e4f7a9786afe78187717c9a3f70651ae9cde3d04e68b",
)


@dataclass(frozen=True)
class SystemState:
    packages: dict[tuple[str, str], tuple[str, str]]
    selections: dict[str, str]
    foreign_architectures: tuple[str, ...]
    alternatives: dict[bytes, AlternativeState]


@dataclass(frozen=True)
class PackageRecord:
    version: str
    role: str
    source: str
    url: str | None = None
    digest: str | None = None


@dataclass(frozen=True)
class LockPolicy:
    snapshots: tuple[str, ...]
    packages: dict[tuple[str, str], PackageRecord]
    alternatives: dict[str, tuple[str, str]]

    def expected_versions(self) -> dict[tuple[str, str], str]:
        return {identity: record.version for identity, record in self.packages.items()}


def parse_lock_bytes(raw: bytes) -> LockPolicy:
    if not raw or len(raw) > MAX_LOCK_BYTES:
        raise PackageLockError("package lock is empty or exceeds its size bound")
    if (
        not raw.endswith(b"\n")
        or any(
            separator in raw
            for separator in (b"\r", b"\v", b"\f", b"\x1c", b"\x1d", b"\x1e")
        )
        or b"\0" in raw
    ):
        raise PackageLockError("package lock has invalid line framing")
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as exc:
        raise PackageLockError("package lock must contain ASCII only") from exc
    if lines[0] != f"schema\t{SCHEMA}":
        raise PackageLockError("package lock schema mismatch")
    snapshots: list[str] = []
    packages: dict[tuple[str, str], PackageRecord] = {}
    alternatives: dict[str, tuple[str, str]] = {}
    package_order: list[tuple[str, str]] = []
    compat_order: list[tuple[str, str]] = []
    section = "snapshot"
    for line in lines[1:]:
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind == "snapshot" and len(fields) == 2:
            if section != "snapshot":
                raise PackageLockError("snapshot record appears after package policy")
            snapshots.append(fields[1])
            continue
        if kind == "package" and len(fields) == 5:
            if section not in {"snapshot", "package"}:
                raise PackageLockError("repository package record is out of section order")
            section = "package"
            _, name, architecture, version, role = fields
            source = "repo"
            url = digest = None
            package_order.append((name, architecture))
        elif kind == "compat-package" and len(fields) == 7:
            if section not in {"package", "compat"}:
                raise PackageLockError("compatibility package record is out of section order")
            section = "compat"
            _, name, architecture, version, role, url, digest = fields
            source = "compat"
            compat_order.append((name, architecture))
            if not url.startswith("https://snapshot.ubuntu.com/ubuntu/") or "/pool/" not in url:
                raise PackageLockError(f"invalid compatibility package URL: {name}")
            if not HEX64.fullmatch(digest):
                raise PackageLockError(f"invalid compatibility package digest: {name}")
        elif kind == "alternative" and len(fields) == 4:
            if section not in {"package", "compat", "alternative"}:
                raise PackageLockError("alternative record is out of section order")
            section = "alternative"
            _, name, mode, target = fields
            if (
                not PACKAGE_NAME.fullmatch(name)
                or mode not in {"auto", "manual"}
                or not target.startswith("/usr/bin/")
                or not PACKAGE_NAME.fullmatch(target.removeprefix("/usr/bin/"))
            ):
                raise PackageLockError(f"invalid alternative record: {name}")
            if name in alternatives:
                raise PackageLockError(f"duplicate alternative record: {name}")
            alternatives[name] = (mode, target)
            continue
        else:
            raise PackageLockError("package lock contains an invalid record")
        if (
            not PACKAGE_NAME.fullmatch(name)
            or architecture not in {"amd64", "all"}
            or not PACKAGE_VERSION.fullmatch(version)
            or role not in {"bootstrap", "requested", "closure"}
        ):
            raise PackageLockError(f"invalid package identity or policy: {name}")
        if source == "compat" and role == "bootstrap":
            raise PackageLockError(f"compatibility package cannot bootstrap acquisition: {name}")
        identity = (name, architecture)
        if identity in packages:
            raise PackageLockError(f"duplicate package identity: {name}:{architecture}")
        packages[identity] = PackageRecord(version, role, source, url, digest)
    if tuple(snapshots) != SNAPSHOTS:
        raise PackageLockError("package snapshot set differs from the reviewed contract")
    if package_order != sorted(package_order) or compat_order != sorted(compat_order):
        raise PackageLockError("package records are not lexically ordered")
    if not packages:
        raise PackageLockError("package lock contains no packages")
    if not any(record.role == "bootstrap" for record in packages.values()):
        raise PackageLockError("package lock contains no bootstrap package")
    return LockPolicy(tuple(snapshots), packages, alternatives)


def verify_apt_plan_annotations(
    suffix: str,
    *,
    allow_dependency_annotations: bool = True,
) -> None:
    position = 0
    group_count = 0
    saw_short_breaks = False
    dependency_annotations: set[str] = set()
    while position < len(suffix):
        if not suffix.startswith(" [", position):
            raise PackageLockError("apt plan contains malformed annotation framing")
        close = suffix.find("]", position + 2)
        if close < 0:
            raise PackageLockError("apt plan contains an unclosed annotation")
        content = suffix[position + 2 : close]
        if PLAN_DEPENDENCY_ANNOTATION.fullmatch(content):
            if not allow_dependency_annotations:
                raise PackageLockError(
                    "apt configure record contains a dependency annotation"
                )
            if saw_short_breaks:
                raise PackageLockError(
                    "apt plan dependency annotation follows its short-break list"
                )
            if content in dependency_annotations:
                raise PackageLockError("apt plan contains a duplicate dependency annotation")
            dependency_annotations.add(content)
        elif PLAN_SHORT_BREAKS_ANNOTATION.fullmatch(content):
            if saw_short_breaks:
                raise PackageLockError("apt plan contains multiple short-break lists")
            identities = content.split()
            if len(identities) != len(set(identities)):
                raise PackageLockError("apt plan contains a duplicate short-break identity")
            saw_short_breaks = True
        else:
            raise PackageLockError("apt plan contains a malformed annotation")
        group_count += 1
        if group_count > MAX_PLAN_ANNOTATION_GROUPS:
            raise PackageLockError("apt plan contains too many annotations")
        position = close + 1


def parse_apt_plan_bytes(raw: bytes, *, allow_empty: bool = False) -> AptPlan:
    if not raw:
        if allow_empty:
            return AptPlan({}, {})
        raise PackageLockError("apt plan is empty")
    if len(raw) > MAX_PLAN_BYTES:
        raise PackageLockError("apt plan exceeds its size bound")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise PackageLockError("apt plan has invalid line framing")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PackageLockError("apt plan must contain ASCII only") from exc
    lines = text.splitlines()
    if "\n".join(lines) + "\n" != text:
        raise PackageLockError("apt plan has invalid line framing")
    records: dict[str, dict[tuple[str, str], PlannedPackage]] = {
        "Inst": {},
        "Conf": {},
    }
    for line in lines:
        match = PLAN_LINE.fullmatch(line)
        if match is None:
            raise PackageLockError(f"apt plan contains an unparsed line: {line!r}")
        action, name, qualifier, old_version, version, architecture, annotations = (
            match.groups()
        )
        verify_apt_plan_annotations(
            annotations,
            allow_dependency_annotations=action == "Inst",
        )
        if action == "Conf" and old_version is not None:
            raise PackageLockError("apt configure record contains an old version")
        if qualifier is not None and qualifier != architecture:
            raise PackageLockError(f"apt plan architecture qualifier mismatch: {name}")
        identity = (name, architecture)
        if identity in records[action]:
            raise PackageLockError(f"apt plan contains a duplicate {action} record: {name}")
        records[action][identity] = PlannedPackage(version, architecture, old_version)
    for identity, configured in records["Conf"].items():
        installed = records["Inst"].get(identity)
        if installed is None or configured.version != installed.version:
            raise PackageLockError(
                f"apt plan configures a package outside its install set: {identity[0]}"
            )
    return AptPlan(records["Inst"], records["Conf"])


def verify_closure_plan(
    expected: dict[tuple[str, str], str],
    plan: AptPlan,
) -> None:
    if any(record.old_version is not None for record in plan.installs.values()):
        raise PackageLockError("empty-status apt closure contains an old version")
    selected = {identity: record.version for identity, record in plan.installs.items()}
    configured = {identity: record.version for identity, record in plan.configures.items()}
    if selected != expected:
        missing = sorted(set(expected) - set(selected))
        extra = sorted(set(selected) - set(expected))
        wrong = sorted(
            identity
            for identity in set(expected) & set(selected)
            if expected[identity] != selected[identity]
        )
        raise PackageLockError(
            f"apt closure plan differs from lock: missing={missing}, extra={extra}, wrong={wrong}"
        )
    if configured != expected:
        raise PackageLockError("apt closure plan does not configure the exact locked set")


def verify_host_plan(
    expected: dict[tuple[str, str], str],
    before: SystemState,
    plan: AptPlan,
) -> None:
    if before.foreign_architectures:
        raise PackageLockError("foreign dpkg architectures are not allowed before transaction")
    required: dict[tuple[str, str], str] = {}
    for identity, version in expected.items():
        if before.packages.get(identity) != (version, "install ok installed"):
            required[identity] = version
    selected = {identity: record.version for identity, record in plan.installs.items()}
    configured = {identity: record.version for identity, record in plan.configures.items()}
    if selected != required or configured != required:
        raise PackageLockError("host apt plan differs from the exact required lock delta")
    for identity, record in plan.installs.items():
        previous = before.packages.get(identity)
        expected_old = (
            previous[0]
            if previous is not None
            and previous[1] in {"install ok installed", "hold ok installed"}
            else None
        )
        if record.old_version != expected_old:
            raise PackageLockError(
                f"host apt plan has wrong prior version: {identity[0]}:{identity[1]}"
            )


STATE_SCHEMA = "tb321fu.haptics-system-state/v3"
SELECTION_TOKEN = re.compile(
    r"[a-z0-9][a-z0-9+.-]{0,79}(?::[a-z0-9][a-z0-9-]{0,31})?"
)
STATE_WORDS = re.compile(r"[a-z-]+ [a-z-]+ [a-z-]+")
SIGNED_PRIORITY = re.compile(rb"-?(?:0|[1-9][0-9]{0,9})")
MAX_ALTERNATIVE_QUERY_BYTES = 512 * 1024
MAX_ALTERNATIVE_CANONICAL_BYTES = 4 * 1024 * 1024
MAX_SYSTEM_STATE_BYTES = 16 * 1024 * 1024
MAX_ALTERNATIVE_DIAGNOSTIC_BYTES = 64
MAX_COMMAND_DIAGNOSTIC_BYTES = 8192
COMMAND_TIMEOUT_SECONDS = 30.0
COMMAND_TERM_GRACE_SECONDS = 0.25
COMMAND_KILL_REAP_SECONDS = 1.0
CAPTURE_TIMEOUT_SECONDS = 120.0
VERIFY_INSTALLED_TIMEOUT_SECONDS = 120.0
VERIFY_BOOTSTRAP_TIMEOUT_SECONDS = 60.0
MAX_COMMAND_STDOUT_BYTES = 4 * 1024 * 1024
MAX_COMMAND_STDERR_BYTES = 8192
MAX_ALTERNATIVE_GROUPS = 4096


def validate_alternative_name(
    value: bytes,
    label: str,
    *,
    domain: str = "alternative query",
    allow_dot_entries: bool = False,
) -> bytes:
    if (
        not value
        or (not allow_dot_entries and value in {b".", b".."})
        or any(byte in value for byte in (0, 10, 32, 47, 9))
    ):
        raise PackageLockError(f"{domain} contains an invalid {label}")
    return value


def validate_alternative_path(
    value: bytes,
    label: str,
    *,
    domain: str = "alternative query",
) -> bytes:
    if not value.startswith(b"/") or b"\0" in value or b"\n" in value:
        raise PackageLockError(f"{domain} contains an invalid {label}")
    return value


def render_alternative_name(value: bytes) -> str:
    if len(value) <= MAX_ALTERNATIVE_DIAGNOSTIC_BYTES and all(
        0x21 <= byte <= 0x7E for byte in value
    ):
        return value.decode("ascii")
    prefix = value[:MAX_ALTERNATIVE_DIAGNOSTIC_BYTES].hex()
    return f"hex:{prefix}:bytes={len(value)}"


def render_command_diagnostic(value: bytes) -> str:
    prefix = value[:MAX_COMMAND_DIAGNOSTIC_BYTES]
    rendered = "".join(
        chr(byte)
        if 0x20 <= byte <= 0x7E and byte != 0x5C
        else f"\\x{byte:02x}"
        for byte in prefix
    )
    if len(value) > len(prefix):
        rendered += f"...:bytes={len(value)}"
    return rendered


def digest_alternative_records(
    records: Iterable[bytes],
    *,
    allow_fallback: bool,
) -> str | None:
    digest = hashlib.sha256()
    total = 0
    for record in records:
        framed = record + b"\n"
        total += len(framed)
        if total > MAX_ALTERNATIVE_CANONICAL_BYTES:
            if allow_fallback:
                return None
            raise PackageLockError("alternative canonical state exceeds its work bound")
        digest.update(framed)
    return digest.hexdigest()


@dataclass
class _BoundedPopenOwner:
    """Publish Popen custody before its initializer can acquire resources."""

    process: object | None = None
    child_baseline: dict[int, int] | None = None
    descriptor_baseline: dict[int, tuple[int, int, int, str]] | None = None
    recovered_pid: int | None = None
    recovered_returncode: int | None = None
    recovered_descriptors: tuple[int, ...] = ()


def _process_start_time(pid: int) -> int:
    raw = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
    if not raw or len(raw) > 4096:
        raise PackageLockError("bounded command child stat record is invalid")
    closing = raw.rfind(b")")
    if closing <= 0:
        raise PackageLockError("bounded command child stat record is malformed")
    fields = raw[closing + 1 :].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        raise PackageLockError("bounded command child start time is malformed")
    return int(fields[19], 10)


def _direct_child_snapshot() -> dict[int, int]:
    tasks = os.listdir("/proc/self/task")
    if len(tasks) != 1 or tasks[0] != str(os.getpid()):
        raise PackageLockError(
            "bounded command handoff requires a single-threaded caller"
        )
    raw = pathlib.Path(
        f"/proc/self/task/{os.getpid()}/children"
    ).read_bytes()
    fields = raw.split()
    if len(fields) > 64:
        raise PackageLockError("bounded command direct-child baseline is too large")
    children: dict[int, int] = {}
    for field in fields:
        if not field.isdigit() or field.startswith(b"0"):
            raise PackageLockError("bounded command direct-child baseline is malformed")
        pid = int(field, 10)
        if pid in children:
            raise PackageLockError("bounded command direct-child baseline has duplicates")
        children[pid] = _process_start_time(pid)
    return children


def _descriptor_snapshot() -> dict[int, tuple[int, int, int, str]]:
    try:
        names = os.listdir("/proc/self/fd")
    except BaseException as exc:
        raise PackageLockError("cannot inspect bounded command descriptors") from exc
    if len(names) > 4096:
        raise PackageLockError("bounded command descriptor baseline is too large")
    descriptors: dict[int, tuple[int, int, int, str]] = {}
    for name in names:
        if not name.isdigit():
            raise PackageLockError("bounded command descriptor baseline is malformed")
        descriptor = int(name, 10)
        try:
            metadata = os.fstat(descriptor)
            target = os.readlink(f"/proc/self/fd/{descriptor}")
        except (FileNotFoundError, OSError) as exc:
            if isinstance(exc, OSError) and exc.errno not in {errno.EBADF, errno.ENOENT}:
                raise
            continue
        descriptors[descriptor] = (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            target,
        )
    return descriptors


def _initialize_owned_popen(
    owner: _BoundedPopenOwner,
    args: list[str | bytes],
    *,
    env: dict[str, str],
) -> subprocess.Popen[bytes]:
    if owner.process is not None:
        raise PackageLockError("bounded command process owner is already populated")
    popen_type = subprocess.Popen
    if not isinstance(popen_type, type):
        process = popen_type(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        owner.process = process
        return process
    process = popen_type.__new__(popen_type)
    owner.process = process
    # Popen.__del__ may observe an initializer interrupted before Popen assigns
    # its own fields.  These values describe the pre-acquisition state and are
    # overwritten by the real initializer.
    for attribute, value in (
        ("_child_created", False),
        ("pid", None),
        ("returncode", None),
        ("stdin", None),
        ("stdout", None),
        ("stderr", None),
    ):
        if not hasattr(process, attribute):
            setattr(process, attribute, value)
    result = popen_type.__init__(
        process,
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    if result is not None:
        raise TypeError("Popen.__init__() returned a non-None result")
    return process


def _recover_unassigned_popen(
    owner: _BoundedPopenOwner,
    primary: BaseException | None,
) -> BaseException | None:
    if owner.child_baseline is None or owner.descriptor_baseline is None:
        return _retain_primary_failure(
            primary,
            PackageLockError("bounded command recovery baseline is unavailable"),
            "bounded command unassigned handoff also failed",
        )
    try:
        children_after = _direct_child_snapshot()
    except BaseException as exc:
        primary = _retain_primary_failure(
            primary, exc, "bounded command child recovery scan also failed"
        )
        children_after = {}
    introduced_children = [
        (pid, start_time)
        for pid, start_time in sorted(children_after.items())
        if owner.child_baseline.get(pid) != start_time
    ]
    if len(introduced_children) > 1:
        primary = _retain_primary_failure(
            primary,
            PackageLockError("bounded command child recovery identity is ambiguous"),
            "bounded command child recovery also failed",
        )
    elif introduced_children:
        pid, start_time = introduced_children[0]
        owner.recovered_pid = pid
        leader_reaped = False

        def leader_exited_without_reaping() -> bool:
            nonlocal leader_reaped, primary
            try:
                result = os.waitid(
                    os.P_PID,
                    pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError as exc:
                leader_reaped = True
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered child lost custody"
                )
                return True
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered child probe also failed"
                )
                return False
            return result is not None and result.si_pid == pid

        try:
            if _process_start_time(pid) != start_time:
                raise PackageLockError("bounded command recovered child identity changed")
            if os.getpgid(pid) != pid:
                raise PackageLockError("bounded command recovered child has wrong session")
        except BaseException as exc:
            primary = _retain_primary_failure(
                primary, exc, "bounded command recovered child identity also failed"
            )
        else:
            try:
                os.killpg(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered TERM also failed"
                )
            term_deadline = time.monotonic() + COMMAND_TERM_GRACE_SECONDS
            while time.monotonic() < term_deadline:
                if leader_exited_without_reaping():
                    break
                try:
                    time.sleep(min(0.01, term_deadline - time.monotonic()))
                except BaseException as exc:
                    primary = _retain_primary_failure(
                        primary, exc, "bounded command recovered TERM delay also failed"
                    )
            if not leader_reaped:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                except BaseException as exc:
                    primary = _retain_primary_failure(
                        primary, exc, "bounded command recovered KILL also failed"
                    )
        reap_deadline = time.monotonic() + COMMAND_KILL_REAP_SECONDS
        while not leader_reaped and time.monotonic() < reap_deadline:
            try:
                waited, status_value = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError as exc:
                leader_reaped = True
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered reap lost status"
                )
                break
            except InterruptedError:
                continue
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered reap also failed"
                )
                continue
            if waited == pid:
                leader_reaped = True
                owner.recovered_returncode = os.waitstatus_to_exitcode(status_value)
                break
            if waited != 0:
                primary = _retain_primary_failure(
                    primary,
                    PackageLockError("bounded command recovered reap returned another pid"),
                    "bounded command recovered reap also failed",
                )
                break
            try:
                time.sleep(0.01)
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered reap delay also failed"
                )
        if not leader_reaped:
            primary = _retain_primary_failure(
                primary,
                PackageLockError("bounded command recovered reap did not converge"),
                "bounded command recovered child custody also failed",
            )
        else:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, "bounded command terminal reap probe also failed"
                )
            else:
                primary = _retain_primary_failure(
                    primary,
                    PackageLockError("bounded command recovered child was not exactly reaped"),
                    "bounded command terminal reap proof also failed",
                )

    try:
        descriptors_after = _descriptor_snapshot()
    except BaseException as exc:
        primary = _retain_primary_failure(
            primary, exc, "bounded command descriptor recovery scan also failed"
        )
        descriptors_after = {}
    introduced_descriptors = tuple(
        descriptor
        for descriptor, identity in sorted(descriptors_after.items())
        if owner.descriptor_baseline.get(descriptor) != identity
    )
    owner.recovered_descriptors = introduced_descriptors
    if len(introduced_descriptors) not in {0, 2}:
        primary = _retain_primary_failure(
            primary,
            PackageLockError("bounded command recovered an incomplete pipe pair"),
            "bounded command descriptor recovery cardinality also failed",
        )
    for descriptor in introduced_descriptors:
        identity = descriptors_after[descriptor]
        if not (
            identity[2] == stat.S_IFIFO
            and identity[3].startswith("pipe:[")
            and identity[3].endswith("]")
        ):
            primary = _retain_primary_failure(
                primary,
                PackageLockError("bounded command recovered a non-pipe descriptor"),
                "bounded command descriptor recovery identity also failed",
            )
        closed = False
        for _ in range(3):
            try:
                current = os.fstat(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    closed = True
                    break
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered descriptor probe also failed"
                )
            else:
                if (
                    current.st_dev,
                    current.st_ino,
                    stat.S_IFMT(current.st_mode),
                ) != identity[:3]:
                    primary = _retain_primary_failure(
                        primary,
                        PackageLockError(
                            "bounded command recovered descriptor identity changed"
                        ),
                        "bounded command descriptor recovery also failed",
                    )
                    break
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    closed = True
                    break
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered descriptor close also failed"
                )
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, "bounded command recovered descriptor close also failed"
                )
        if not closed:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                closed = exc.errno == errno.EBADF
            if not closed:
                primary = _retain_primary_failure(
                    primary,
                    PackageLockError(
                        "bounded command recovered descriptor close did not converge"
                    ),
                    "bounded command descriptor custody also failed",
                )
    return primary


def _retain_primary_failure(
    primary: BaseException | None,
    secondary: BaseException,
    label: str,
) -> BaseException:
    if primary is None:
        return secondary
    if secondary is not primary:
        try:
            primary.add_note(
                f"{label}: {type(secondary).__name__}: {secondary}"
            )
        except BaseException:
            pass
    return primary


def _close_owned_popen_streams(
    process: object,
    primary: BaseException | None,
) -> tuple[BaseException | None, bool]:
    converged = True
    for attribute, label in (("stderr", "stderr"), ("stdout", "stdout")):
        try:
            stream = getattr(process, attribute, None)
        except BaseException as exc:
            primary = _retain_primary_failure(
                primary, exc, f"bounded command {label} lookup also failed"
            )
            converged = False
            continue
        if stream is None:
            continue
        closed = False
        for _ in range(3):
            try:
                if stream.closed:
                    closed = True
                    break
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, f"bounded command {label} state probe also failed"
                )
            try:
                stream.close()
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary, exc, f"bounded command {label} close also failed"
                )
                continue
            closed = True
            break
        if not closed:
            try:
                closed = bool(stream.closed)
            except BaseException as exc:
                primary = _retain_primary_failure(
                    primary,
                    exc,
                    f"bounded command terminal {label} state probe also failed",
                )
        if not closed:
            primary = _retain_primary_failure(
                primary,
                PackageLockError(f"bounded command {label} close did not converge"),
                f"bounded command {label} custody also failed",
            )
            converged = False
    return primary, converged


def _settle_owned_popen(
    owner: _BoundedPopenOwner,
    label: str,
    *,
    normal_completion: bool,
    primary: BaseException | None,
) -> BaseException | None:
    process = owner.process
    if process is None:
        return _recover_unassigned_popen(owner, primary)
    try:
        child_created = bool(getattr(process, "_child_created", False))
    except BaseException as exc:
        primary = _retain_primary_failure(
            primary, exc, "bounded command child-state probe also failed"
        )
        child_created = True
    try:
        pid = getattr(process, "pid", None)
    except BaseException as exc:
        primary = _retain_primary_failure(
            primary, exc, "bounded command pid lookup also failed"
        )
        pid = None
    if child_created and (type(pid) is not int or pid <= 0):
        primary = _retain_primary_failure(
            primary,
            PackageLockError(f"cannot retain {label} process identity"),
            "bounded command process identity also failed",
        )
        child_created = False

    leader_reaped = False

    def returncode() -> int | None:
        nonlocal primary
        try:
            value = getattr(process, "returncode", None)
        except BaseException as exc:
            primary = _retain_primary_failure(
                primary, exc, "bounded command returncode probe also failed"
            )
            return None
        return value if type(value) is int else None

    def leader_exited_without_reaping() -> bool:
        nonlocal leader_reaped, primary
        if leader_reaped or not child_created:
            return True
        try:
            result = os.waitid(
                os.P_PID,
                pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            leader_reaped = True
            return True
        except BaseException as exc:
            primary = _retain_primary_failure(
                primary, exc, "bounded command leader probe also failed"
            )
            return False
        return result is not None and result.si_pid == pid

    def signal_group(signum: int) -> None:
        nonlocal primary
        if leader_reaped or not child_created:
            return
        try:
            os.killpg(pid, signum)
        except (ProcessLookupError, PermissionError):
            pass
        except BaseException as exc:
            primary = _retain_primary_failure(
                primary, exc, "bounded command group signal also failed"
            )

    if child_created and returncode() is None:
        cleanup_deadline = time.monotonic() + COMMAND_KILL_REAP_SECONDS
        leader_exited_without_reaping()
        if leader_reaped:
            primary = _retain_primary_failure(
                primary,
                PackageLockError(f"cannot retain {label} process ownership"),
                "bounded command leader custody also failed",
            )
        else:
            if not normal_completion:
                signal_group(signal.SIGTERM)
                term_deadline = min(
                    cleanup_deadline,
                    time.monotonic() + COMMAND_TERM_GRACE_SECONDS,
                )
                while time.monotonic() < term_deadline:
                    if leader_exited_without_reaping():
                        break
                    try:
                        time.sleep(min(0.01, term_deadline - time.monotonic()))
                    except BaseException as exc:
                        primary = _retain_primary_failure(
                            primary,
                            exc,
                            "bounded command TERM delay also failed",
                        )
            # Keep the leader unreaped until the complete session has received
            # KILL; this preserves the numeric process-group identity.
            signal_group(signal.SIGKILL)
            while returncode() is None and time.monotonic() < cleanup_deadline:
                remaining = max(0.0, cleanup_deadline - time.monotonic())
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired as exc:
                    primary = _retain_primary_failure(
                        primary,
                        PackageLockError(f"cannot terminate {label}"),
                        "bounded command reap also timed out",
                    )
                    try:
                        exc.add_note(f"bounded command cleanup timeout: {label}")
                    except BaseException:
                        pass
                    break
                except ChildProcessError as exc:
                    primary = _retain_primary_failure(
                        primary,
                        PackageLockError(f"cannot retain {label} process ownership"),
                        "bounded command reap also lost custody",
                    )
                    try:
                        primary.add_note(
                            f"wait failure: {type(exc).__name__}: {exc}"
                        )
                    except BaseException:
                        pass
                    break
                except BaseException as exc:
                    primary = _retain_primary_failure(
                        primary, exc, "bounded command wait also failed"
                    )
                    continue
                if returncode() is not None:
                    break
        if returncode() is None:
            primary = _retain_primary_failure(
                primary,
                PackageLockError(f"cannot terminate {label}"),
                "bounded command reap did not converge",
            )

    primary, streams_closed = _close_owned_popen_streams(process, primary)
    if (not child_created or returncode() is not None) and streams_closed:
        owner.process = None
    return primary


def _bounded_command(
    args: list[str | bytes],
    label: str,
    *,
    env: dict[str, str],
    timeout: float,
    max_stdout: int,
    max_stderr: int,
) -> tuple[int, bytes, bytes]:
    """Run one process group with bounded output, time and cleanup."""
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or type(max_stdout) is not int
        or max_stdout < 0
        or type(max_stderr) is not int
        or max_stderr < 0
    ):
        raise ValueError("bounded command received an invalid resource limit")
    owner = _BoundedPopenOwner(
        child_baseline=_direct_child_snapshot(),
        descriptor_baseline=_descriptor_snapshot(),
    )
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    completed = False
    primary: BaseException | None = None
    try:
        process = _initialize_owned_popen(owner, args, env=env)
        assert process.stdout is not None and process.stderr is not None
        streams = {
            process.stdout.fileno(): (
                process.stdout,
                stdout,
                max_stdout,
                "stdout",
            ),
            process.stderr.fileno(): (
                process.stderr,
                stderr,
                max_stderr,
                "stderr",
            ),
        }
        deadline = time.monotonic() + timeout
        leader_reaped_early = False

        def leader_exited_without_reaping() -> bool:
            nonlocal leader_reaped_early
            try:
                result = os.waitid(
                    os.P_PID,
                    process.pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError:
                leader_reaped_early = True
                return True
            return result is not None and result.si_pid == process.pid

        def wait_for_leader_exit(limit: float) -> bool:
            while not leader_exited_without_reaping():
                remaining = limit - time.monotonic()
                if remaining <= 0:
                    return False
                time.sleep(min(0.01, remaining))
            return True

        while streams:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            ready, _, _ = select.select(
                tuple(streams),
                (),
                (),
                remaining_time,
            )
            if not ready:
                raise subprocess.TimeoutExpired(args, timeout)
            for descriptor in ready:
                stream, output, maximum, stream_name = streams[descriptor]
                remaining_output = maximum - len(output)
                chunk = os.read(descriptor, min(64 * 1024, remaining_output + 1))
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                output.extend(chunk)
                if len(output) > maximum:
                    raise PackageLockError(
                        f"{label} {stream_name} exceeds its size bound"
                    )
        if not wait_for_leader_exit(deadline):
            raise subprocess.TimeoutExpired(args, timeout)
        completed = True
    except BaseException as exc:
        primary = exc
    finally:
        primary = _settle_owned_popen(
            owner,
            label,
            normal_completion=completed,
            primary=primary,
        )
    if primary is not None:
        raise primary
    assert process is not None and process.returncode is not None
    return process.returncode, bytes(stdout), bytes(stderr)


def parse_alternative_slave_lines(
    lines: list[bytes],
    position: int,
) -> tuple[tuple[tuple[bytes, bytes], ...], int, bool]:
    if position >= len(lines) or lines[position] != b"Slaves:":
        return (), position, False
    position += 1
    slaves: dict[bytes, bytes] = {}
    while position < len(lines) and lines[position].startswith(b" "):
        line = lines[position]
        if line.startswith(b"  "):
            raise PackageLockError("alternative query contains a malformed slave")
        name, separator, path = line[1:].partition(b" ")
        if not separator:
            raise PackageLockError("alternative query contains a malformed slave")
        validate_alternative_name(name, "slave name", allow_dot_entries=True)
        if name in slaves:
            raise PackageLockError("alternative query contains an invalid slave name")
        slaves[name] = validate_alternative_path(path, "slave path")
        position += 1
    return tuple(sorted(slaves.items())), position, True


def parse_alternative_field(
    lines: list[bytes],
    position: int,
    name: str,
) -> tuple[bytes, int]:
    prefix = f"{name}: ".encode("ascii")
    if position >= len(lines) or not lines[position].startswith(prefix):
        raise PackageLockError(f"alternative query is missing {name}")
    value = lines[position][len(prefix) :]
    if not value:
        raise PackageLockError(f"alternative query contains an empty {name}")
    return value, position + 1


def parse_alternative_query_bytes(raw: bytes, expected_name: bytes) -> AlternativeState:
    if not raw or len(raw) > MAX_ALTERNATIVE_QUERY_BYTES:
        raise PackageLockError("alternative query is empty or exceeds its size bound")
    if not raw.endswith(b"\n") or b"\0" in raw:
        raise PackageLockError("alternative query has invalid line framing")
    lines = raw[:-1].split(b"\n")
    validate_alternative_name(expected_name, "expected name")

    position = 0
    name, position = parse_alternative_field(lines, position, "Name")
    validate_alternative_name(name, "name")
    if name != expected_name:
        raise PackageLockError("alternative query name differs from its selection")
    link, position = parse_alternative_field(lines, position, "Link")
    link = validate_alternative_path(link, "master link")
    master_slaves, position, master_slaves_header = parse_alternative_slave_lines(
        lines, position
    )
    if master_slaves_header != bool(master_slaves):
        raise PackageLockError("alternative query has invalid master Slaves framing")
    if name in {slave_name for slave_name, _ in master_slaves}:
        raise PackageLockError(
            "alternative query master name conflicts with a slave name"
        )
    master_links = (link, *(slave_path for _, slave_path in master_slaves))
    if len(master_links) != len(set(master_links)):
        raise PackageLockError("alternative query contains a duplicate master link")
    mode, position = parse_alternative_field(lines, position, "Status")
    if mode not in {b"auto", b"manual"}:
        raise PackageLockError("alternative query contains an invalid status")
    best: bytes | None = None
    if position < len(lines) and lines[position].startswith(b"Best: "):
        best, position = parse_alternative_field(lines, position, "Best")
        best = validate_alternative_path(best, "best path")
    target, position = parse_alternative_field(lines, position, "Value")
    if target == b"none":
        target = None
    else:
        target = validate_alternative_path(target, "selected path")

    candidates: dict[bytes, tuple[int, tuple[tuple[bytes, bytes], ...]]] = {}
    if position < len(lines):
        if lines[position] != b"":
            raise PackageLockError("alternative query has malformed stanza framing")
        position += 1
        if position == len(lines):
            raise PackageLockError("alternative query contains a trailing blank stanza")
    while position < len(lines):
        path, position = parse_alternative_field(lines, position, "Alternative")
        path = validate_alternative_path(path, "candidate path")
        if path in candidates:
            raise PackageLockError("alternative query contains a duplicate candidate")
        priority_text, position = parse_alternative_field(lines, position, "Priority")
        if not SIGNED_PRIORITY.fullmatch(priority_text):
            raise PackageLockError("alternative query contains an invalid priority")
        priority = int(priority_text)
        if priority_text != str(priority).encode("ascii"):
            raise PackageLockError("alternative query contains an invalid priority")
        if not -(2**31) <= priority <= 2**31 - 1:
            raise PackageLockError("alternative query priority exceeds its bound")
        slaves, position, candidate_slaves_header = parse_alternative_slave_lines(
            lines, position
        )
        if candidate_slaves_header != bool(master_slaves):
            raise PackageLockError("alternative query has invalid candidate Slaves framing")
        candidates[path] = (priority, slaves)
        if position < len(lines):
            if lines[position] != b"":
                raise PackageLockError("alternative query has malformed candidate framing")
            position += 1
            if position == len(lines):
                raise PackageLockError("alternative query contains a trailing blank stanza")

    candidate_paths = set(candidates)
    if link in candidate_paths:
        raise PackageLockError(
            "alternative query master link conflicts with a candidate path"
        )
    if bool(candidates) != (best is not None):
        raise PackageLockError("alternative query Best does not match its candidate set")
    if best is not None and best not in candidate_paths:
        raise PackageLockError("alternative query Best is not a candidate")
    if target is not None and target not in candidate_paths:
        raise PackageLockError("alternative query Value is not a candidate")
    if candidates:
        selected_best = target if target is not None else next(iter(candidates))
        selected_priority = candidates[selected_best][0]
        for path, (priority, _) in candidates.items():
            if priority > selected_priority:
                selected_best = path
                selected_priority = priority
        if best != selected_best:
            raise PackageLockError(
                "alternative query Best differs from dpkg selection semantics"
            )
    master_slave_links = dict(master_slaves)
    for _, candidate_slaves in candidates.values():
        for slave_name, slave_path in candidate_slaves:
            if slave_name not in master_slave_links:
                raise PackageLockError("alternative candidate declares an unknown slave")
            if slave_path == master_slave_links[slave_name]:
                raise PackageLockError(
                    "alternative query slave link conflicts with a candidate slave path"
                )

    semantic_values = [name, link]
    if best is not None:
        semantic_values.append(best)
    if target is not None:
        semantic_values.append(target)
    for slave_name, slave_path in master_slaves:
        semantic_values.extend((slave_name, slave_path))
    for path, (_, slaves) in candidates.items():
        semantic_values.append(path)
        for slave_name, slave_path in slaves:
            semantic_values.extend((slave_name, slave_path))

    def v1_records() -> Iterable[bytes]:
        yield b"schema\ttb321fu.alternative-query/v1"
        yield b"name\t" + name
        yield b"link\t" + link
        yield b"status\t" + mode
        yield b"best\t" + (best if best is not None else b"-")
        yield b"value\t" + (target if target is not None else b"none")
        for slave_name, slave_path in master_slaves:
            yield b"master-slave\t" + slave_name + b"\t" + slave_path
        for path, (priority, slaves) in sorted(candidates.items()):
            yield b"candidate\t" + path + b"\t" + str(priority).encode("ascii")
            for slave_name, slave_path in slaves:
                yield (
                    b"candidate-slave\t"
                    + path
                    + b"\t"
                    + slave_name
                    + b"\t"
                    + slave_path
                )

    def v2_records() -> Iterable[bytes]:
        yield b"schema\ttb321fu.alternative-query/v2"
        yield b"name-hex\t" + name.hex().encode("ascii")
        yield b"link-hex\t" + link.hex().encode("ascii")
        yield b"status\t" + mode
        yield b"best-hex\t" + (
            best.hex().encode("ascii") if best is not None else b"-"
        )
        yield b"value-hex\t" + (
            target.hex().encode("ascii") if target is not None else b"-"
        )
        for slave_name, slave_path in master_slaves:
            yield (
                b"master-slave-hex\t"
                + slave_name.hex().encode("ascii")
                + b"\t"
                + slave_path.hex().encode("ascii")
            )
        for path, (priority, slaves) in sorted(candidates.items()):
            yield (
                b"candidate-hex\t"
                + path.hex().encode("ascii")
                + b"\t"
                + str(priority).encode("ascii")
            )
            for slave_name, slave_path in slaves:
                yield (
                    b"candidate-slave-hex\t"
                    + slave_name.hex().encode("ascii")
                    + b"\t"
                    + slave_path.hex().encode("ascii")
                )

    v1_safe = all(
        all(0x20 <= byte <= 0x7E for byte in value)
        for value in semantic_values
    )
    query_sha256 = (
        digest_alternative_records(v1_records(), allow_fallback=True)
        if v1_safe
        else None
    )
    if query_sha256 is None:
        query_sha256 = digest_alternative_records(
            v2_records(), allow_fallback=False
        )
    assert query_sha256 is not None
    return AlternativeState(mode.decode("ascii"), target, query_sha256)


def serialize_system_state(state: SystemState) -> bytes:
    output = bytearray()

    def append_fields(*fields: bytes) -> None:
        framed_size = sum(len(field) for field in fields) + len(fields)
        if len(output) + framed_size > MAX_SYSTEM_STATE_BYTES:
            raise PackageLockError("system state exceeds its size bound")
        for index, field in enumerate(fields):
            if index:
                output.extend(b"\t")
            output.extend(field)
        output.extend(b"\n")

    append_fields(b"schema", STATE_SCHEMA.encode("ascii"))
    for (name, architecture), (version, status_value) in sorted(state.packages.items()):
        append_fields(
            b"package",
            name.encode("ascii"),
            architecture.encode("ascii"),
            version.encode("ascii"),
            status_value.encode("ascii"),
        )
    for name, selection in sorted(state.selections.items()):
        append_fields(b"selection", name.encode("ascii"), selection.encode("ascii"))
    for architecture in sorted(state.foreign_architectures):
        append_fields(b"foreign-architecture", architecture.encode("ascii"))
    for name, alternative in sorted(state.alternatives.items()):
        target_hex_size = (
            1 if alternative.target is None else 2 * len(alternative.target)
        )
        projected_size = (
            len(b"alternative")
            + 2 * len(name)
            + len(alternative.mode)
            + target_hex_size
            + len(alternative.query_sha256)
            + 5
        )
        if len(output) + projected_size > MAX_SYSTEM_STATE_BYTES:
            raise PackageLockError("system state exceeds its size bound")
        append_fields(
            b"alternative",
            name.hex().encode("ascii"),
            alternative.mode.encode("ascii"),
            (
                b"-"
                if alternative.target is None
                else alternative.target.hex().encode("ascii")
            ),
            alternative.query_sha256.encode("ascii"),
        )
    return bytes(output)


def parse_system_state_bytes(raw: bytes) -> SystemState:
    if not raw or len(raw) > MAX_SYSTEM_STATE_BYTES:
        raise PackageLockError("system state is empty or exceeds its size bound")
    if (
        not raw.endswith(b"\n")
        or any(separator in raw for separator in (b"\r", b"\v", b"\f", b"\x1c", b"\x1d", b"\x1e"))
        or b"\0" in raw
    ):
        raise PackageLockError("system state has invalid line framing")
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as exc:
        raise PackageLockError("system state must contain ASCII only") from exc
    if lines[0] != f"schema\t{STATE_SCHEMA}":
        raise PackageLockError("system state schema mismatch")
    packages: dict[tuple[str, str], tuple[str, str]] = {}
    selections: dict[str, str] = {}
    foreign: list[str] = []
    alternatives: dict[bytes, AlternativeState] = {}
    order = {"package": 0, "selection": 1, "foreign-architecture": 2, "alternative": 3}
    current_section = 0
    previous: dict[str, tuple[str, ...] | None] = {name: None for name in order}
    for line in lines[1:]:
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind not in order or order[kind] < current_section:
            raise PackageLockError("system state record is out of section order")
        current_section = order[kind]
        key = tuple(fields[1:-1] if kind == "package" else fields[1:2])
        if previous[kind] is not None and key <= previous[kind]:
            raise PackageLockError(f"system state {kind} records are duplicate or unsorted")
        previous[kind] = key
        if kind == "package" and len(fields) == 5:
            _, name, architecture, version, status_value = fields
            if (
                not PACKAGE_NAME.fullmatch(name)
                or architecture not in {"amd64", "all", "arm64"}
                or not PACKAGE_VERSION.fullmatch(version)
                or not STATE_WORDS.fullmatch(status_value)
                or (name, architecture) in packages
            ):
                raise PackageLockError("invalid package state record")
            packages[(name, architecture)] = (version, status_value)
        elif kind == "selection" and len(fields) == 3:
            _, name, selection = fields
            if not SELECTION_TOKEN.fullmatch(name) or selection not in {
                "install", "hold", "deinstall", "purge"
            } or name in selections:
                raise PackageLockError("invalid package selection record")
            selections[name] = selection
        elif kind == "foreign-architecture" and len(fields) == 2:
            architecture = fields[1]
            if architecture not in {"amd64", "arm64"} or architecture in foreign:
                raise PackageLockError("invalid foreign architecture record")
            foreign.append(architecture)
        elif kind == "alternative" and len(fields) == 5:
            _, name_hex, mode, target_hex, query_sha256 = fields
            if (
                not name_hex
                or len(name_hex) % 2
                or re.fullmatch(r"[0-9a-f]+", name_hex) is None
                or (
                    target_hex != "-"
                    and (
                        not target_hex
                        or len(target_hex) % 2
                        or re.fullmatch(r"[0-9a-f]+", target_hex) is None
                    )
                )
            ):
                raise PackageLockError("invalid alternative state record")
            name = bytes.fromhex(name_hex)
            target = None if target_hex == "-" else bytes.fromhex(target_hex)
            validate_alternative_name(
                name,
                "state name",
                domain="system state",
            )
            if (
                mode not in {"auto", "manual"}
                or not HEX64.fullmatch(query_sha256)
                or name in alternatives
            ):
                raise PackageLockError("invalid alternative state record")
            if target is not None:
                validate_alternative_path(
                    target,
                    "state target",
                    domain="system state",
                )
            alternatives[name] = AlternativeState(mode, target, query_sha256)
        else:
            raise PackageLockError("system state contains an invalid record")
    state = SystemState(packages, selections, tuple(foreign), alternatives)
    if serialize_system_state(state) != raw:
        raise PackageLockError("system state is not canonically encoded")
    return state


def verify_state_transition(
    expected: dict[tuple[str, str], str],
    allowed_alternatives: dict[str, tuple[str, str]],
    before: SystemState,
    after: SystemState,
) -> None:
    allowed_alternative_bytes = {
        name.encode("ascii"): (mode, target.encode("ascii"))
        for name, (mode, target) in allowed_alternatives.items()
    }
    if before.foreign_architectures or after.foreign_architectures:
        raise PackageLockError("foreign dpkg architectures are not allowed")
    for identity in set(before.packages) | set(after.packages):
        if (
            identity not in expected
            and before.packages.get(identity) != after.packages.get(identity)
        ):
            raise PackageLockError(
                f"package outside the lock changed: {identity[0]}:{identity[1]}"
            )
    for identity, version in expected.items():
        if after.packages.get(identity) != (version, "install ok installed"):
            raise PackageLockError(
                f"locked package has wrong final state: {identity[0]}:{identity[1]}"
            )
    allowed_selection_tokens = {
        token
        for name, architecture in expected
        for token in (name, f"{name}:{architecture}")
    }
    for name, architecture in expected:
        matches = [
            token
            for token in (name, f"{name}:{architecture}")
            if token in after.selections
        ]
        if len(matches) != 1 or after.selections[matches[0]] != "install":
            raise PackageLockError(
                f"locked package has wrong final selection: {name}:{architecture}"
            )
    for token in set(before.selections) | set(after.selections):
        if (
            token not in allowed_selection_tokens
            and before.selections.get(token) != after.selections.get(token)
        ):
            raise PackageLockError(f"selection outside the lock changed: {token}")
    for name in set(before.alternatives) | set(after.alternatives):
        if name in allowed_alternative_bytes:
            actual = after.alternatives.get(name)
            expected_mode, expected_target = allowed_alternative_bytes[name]
            if (
                actual is None
                or (actual.mode, actual.target) != (expected_mode, expected_target)
            ):
                raise PackageLockError(
                    "locked alternative has wrong final state: "
                    f"{render_alternative_name(name)}"
                )
            if name != b"awk" or actual != EXPECTED_AWK_ALTERNATIVE_STATE:
                raise PackageLockError(
                    "locked alternative has wrong complete group state: "
                    f"{render_alternative_name(name)}"
                )
        elif before.alternatives.get(name) != after.alternatives.get(name):
            raise PackageLockError(
                "alternative outside the lock changed: "
                f"{render_alternative_name(name)}"
            )
    for name, (expected_mode, expected_target) in allowed_alternatives.items():
        name_bytes = name.encode("ascii")
        actual = after.alternatives.get(name_bytes)
        if actual is None or (actual.mode, actual.target) != (
            expected_mode,
            expected_target.encode("ascii"),
        ):
            raise PackageLockError(f"locked alternative is absent after transaction: {name}")


def verify_baseline_state(state: SystemState) -> None:
    if state.foreign_architectures:
        raise PackageLockError(
            f"foreign dpkg architectures are not allowed: {state.foreign_architectures}"
        )


def read_regular(path: pathlib.Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PackageLockError(f"cannot open package lock: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise PackageLockError("package lock is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            raise PackageLockError("package lock mode must be 0644")
        if metadata.st_size > MAX_LOCK_BYTES:
            raise PackageLockError("package lock exceeds its size bound")
        chunks: list[bytes] = []
        remaining = MAX_LOCK_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_LOCK_BYTES:
            raise PackageLockError("package lock exceeds its read bound")
        return raw
    finally:
        os.close(fd)


def read_private_evidence(path: pathlib.Path, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackageLockError(f"cannot open {label}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PackageLockError(f"{label} is not a regular file")
        if (
            stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getgid()
            or metadata.st_nlink != 1
        ):
            raise PackageLockError(f"{label} ownership, mode, or links differ from policy")
        if metadata.st_size > maximum:
            raise PackageLockError(f"{label} exceeds its size bound")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise PackageLockError(f"{label} exceeds its read bound")
        final = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_uid,
            item.st_gid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(final) != identity(metadata):
            raise PackageLockError(f"{label} changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def command_output(
    arguments: list[str | bytes],
    label: str,
    *,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> bytes:
    returncode, stdout, stderr = _bounded_command(
        arguments,
        label,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": os.environ.get("HOME", "/nonexistent"),
        },
        timeout=timeout,
        max_stdout=MAX_COMMAND_STDOUT_BYTES,
        max_stderr=MAX_COMMAND_STDERR_BYTES,
    )
    if returncode:
        error = render_command_diagnostic(stderr)
        raise PackageLockError(f"{label} failed: {error}")
    return stdout


def split_command_lines(raw: bytes, label: str) -> list[bytes]:
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise PackageLockError(f"{label} output has invalid line framing")
    return raw[:-1].split(b"\n")


def decode_command_line(raw: bytes, label: str) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PackageLockError(f"{label} output is not ASCII") from exc


def parse_alternative_selection_line(
    line: bytes,
) -> tuple[bytes, str, bytes | None]:
    name, separator, _ = line.partition(b" ")
    if not separator or not name:
        raise PackageLockError("alternative-state capture emitted an invalid record")
    validate_alternative_name(
        name,
        "selection name",
        domain="alternative-state capture",
    )
    name_padding = max(30 - len(name), 0) + 1
    remainder = line[len(name) :]
    if not remainder.startswith(b" " * name_padding):
        raise PackageLockError("alternative-state capture emitted invalid name padding")
    remainder = remainder[name_padding:]
    for mode_bytes in (b"auto", b"manual"):
        mode_padding = max(8 - len(mode_bytes), 0) + 1
        prefix = mode_bytes + b" " * mode_padding
        if not remainder.startswith(prefix):
            continue
        target = remainder[len(prefix) :]
        if not target:
            return name, mode_bytes.decode("ascii"), None
        if target == b"none":
            raise PackageLockError(
                "alternative-state capture emitted an invalid target"
            )
        return (
            name,
            mode_bytes.decode("ascii"),
            validate_alternative_path(
                target,
                "selection target",
                domain="alternative-state capture",
            ),
        )
    raise PackageLockError("alternative-state capture emitted an invalid status")


def capture_system_state(*, deadline: float | None = None) -> SystemState:
    started = time.monotonic()
    local_deadline = started + CAPTURE_TIMEOUT_SECONDS
    if deadline is None:
        deadline = local_deadline
    elif (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise PackageLockError("system-state capture deadline is invalid")
    else:
        deadline = min(float(deadline), local_deadline)

    def remaining_capture_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PackageLockError("system-state capture exceeds its deadline")
        return remaining

    def capture_output(arguments: list[str | bytes], label: str) -> bytes:
        return command_output(
            arguments,
            label,
            timeout=min(COMMAND_TIMEOUT_SECONDS, remaining_capture_time()),
        )

    package_output = capture_output(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${Package}\t${Architecture}\t${Version}\t${Status}\n",
        ],
        "dpkg package-state capture",
    )
    packages: dict[tuple[str, str], tuple[str, str]] = {}
    for raw_line in split_command_lines(package_output, "dpkg package-state capture"):
        line = decode_command_line(raw_line, "dpkg package-state capture")
        fields = line.split("\t")
        if len(fields) != 4:
            raise PackageLockError("dpkg package-state capture emitted an invalid record")
        name, architecture, version, status_value = fields
        identity = (name, architecture)
        if (
            not PACKAGE_NAME.fullmatch(name)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", architecture)
            or not PACKAGE_VERSION.fullmatch(version)
            or not STATE_WORDS.fullmatch(status_value)
            or identity in packages
        ):
            raise PackageLockError("dpkg package-state capture emitted unsafe metadata")
        packages[identity] = (version, status_value)
    selection_output = capture_output(
        ["/usr/bin/dpkg", "--get-selections", "*"],
        "dpkg selection capture",
    )
    selections: dict[str, str] = {}
    for raw_line in split_command_lines(selection_output, "dpkg selection capture"):
        name_length = raw_line.find(b"\t")
        tab_count = max(1, 6 - (name_length >> 3))
        selection_offset = name_length + tab_count
        if (
            name_length <= 0
            or raw_line[name_length:selection_offset] != b"\t" * tab_count
            or selection_offset >= len(raw_line)
            or b"\t" in raw_line[selection_offset:]
        ):
            raise PackageLockError("dpkg selection capture emitted an invalid record")
        line = decode_command_line(raw_line, "dpkg selection capture")
        name = line[:name_length]
        selection = line[selection_offset:]
        if (
            not SELECTION_TOKEN.fullmatch(name)
            or selection not in {"install", "hold", "deinstall", "purge"}
            or name in selections
        ):
            raise PackageLockError("dpkg selection capture emitted unsafe metadata")
        selections[name] = selection
    foreign_output = capture_output(
        ["/usr/bin/dpkg", "--print-foreign-architectures"],
        "foreign-architecture capture",
    )
    foreign = tuple(
        decode_command_line(raw_line, "foreign-architecture capture")
        for raw_line in split_command_lines(
            foreign_output, "foreign-architecture capture"
        )
    )
    if len(set(foreign)) != len(foreign) or any(
        re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", item) is None for item in foreign
    ):
        raise PackageLockError("foreign-architecture capture emitted unsafe metadata")
    alternative_output = capture_output(
        ["/usr/bin/update-alternatives", "--get-selections"],
        "alternative-state capture",
    )
    selected_alternatives: dict[bytes, tuple[str, bytes | None]] = {}
    for raw_line in split_command_lines(alternative_output, "alternative-state capture"):
        name, mode, target = parse_alternative_selection_line(raw_line)
        validate_alternative_name(
            name,
            "selection name",
            domain="alternative-state capture",
        )
        if (
            mode not in {"auto", "manual"}
            or name in selected_alternatives
        ):
            raise PackageLockError("alternative-state capture emitted unsafe metadata")
        selected_alternatives[name] = (mode, target)
    if len(selected_alternatives) > MAX_ALTERNATIVE_GROUPS:
        raise PackageLockError("alternative-state capture exceeds its group bound")
    alternatives: dict[bytes, AlternativeState] = {}
    for name, selection in sorted(selected_alternatives.items()):
        rendered_name = render_alternative_name(name)
        query = capture_output(
            [b"/usr/bin/update-alternatives", b"--query", name],
            f"alternative query capture: {rendered_name}",
        )
        state = parse_alternative_query_bytes(query, name)
        if (state.mode, state.target) != selection:
            raise PackageLockError(
                "alternative query differs from its selection record: "
                f"{rendered_name}"
            )
        alternatives[name] = state
    if capture_output(
        ["/usr/bin/update-alternatives", "--get-selections"],
        "alternative-state recapture",
    ) != alternative_output:
        raise PackageLockError("alternative selections changed while they were captured")
    for name, expected_state in alternatives.items():
        rendered_name = render_alternative_name(name)
        query = capture_output(
            [b"/usr/bin/update-alternatives", b"--query", name],
            f"alternative query recapture: {rendered_name}",
        )
        if parse_alternative_query_bytes(query, name) != expected_state:
            raise PackageLockError(
                "alternative group changed while it was captured: "
                f"{rendered_name}"
            )
    state = SystemState(packages, selections, tuple(sorted(foreign)), alternatives)
    serialize_system_state(state)
    remaining_capture_time()
    return state


def parse_lock(
    path: pathlib.Path,
) -> LockPolicy:
    raw = read_regular(path)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_LOCK_SHA256:
        raise PackageLockError("package lock differs from the reviewed closure bytes")
    policy = parse_lock_bytes(raw)
    if len(policy.packages) != EXPECTED_PACKAGE_COUNT:
        raise PackageLockError("package lock has an unexpected closure size")
    by_name: dict[str, tuple[str, PackageRecord]] = {}
    for (name, architecture), record in policy.packages.items():
        if name in by_name:
            raise PackageLockError(f"package lock contains a multiarch ambiguity: {name}")
        by_name[name] = (architecture, record)
    roots = tuple(
        sorted(name for name, (_, record) in by_name.items() if record.role != "closure")
    )
    if roots != EXPECTED_PACKAGES:
        raise PackageLockError("requested package roots differ from the reviewed tool closure")
    closure_count = sum(record.role == "closure" for record in policy.packages.values())
    if closure_count != EXPECTED_CLOSURE_COUNT:
        raise PackageLockError("dependency closure has an unexpected size")
    for name, architecture in BOOTSTRAP_ARCHITECTURES.items():
        actual_architecture, record = by_name[name]
        if actual_architecture != architecture or record.role != "bootstrap":
            raise PackageLockError(f"bootstrap package policy mismatch: {name}")
    if {
        name for name, (_, record) in by_name.items() if record.role == "bootstrap"
    } != set(BOOTSTRAP_PACKAGES):
        raise PackageLockError("bootstrap package set differs from policy")
    expected_compat = {
        (name, architecture): (version, url, digest)
        for name, architecture, version, url, digest in COMPAT_PACKAGES
    }
    actual_compat = {
        identity: (record.version, record.url, record.digest)
        for identity, record in policy.packages.items()
        if record.source == "compat" and record.role == "requested"
    }
    if actual_compat != expected_compat:
        raise PackageLockError("compatibility package set differs from policy")
    if policy.alternatives != EXPECTED_ALTERNATIVES:
        raise PackageLockError("alternative policy differs from the reviewed contract")
    return policy


def emit_nul(values: list[str]) -> None:
    sys.stdout.buffer.write(b"\0".join(value.encode("ascii") for value in values) + b"\0")


def _installed_command(
    arguments: list[str],
    label: str,
    *,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    return _bounded_command(
        arguments,
        label,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "HOME": os.environ.get("HOME", "/nonexistent"),
        },
        timeout=timeout,
        max_stdout=MAX_COMMAND_STDOUT_BYTES,
        max_stderr=MAX_COMMAND_STDERR_BYTES,
    )


def installed_record(
    name: str,
    architecture: str,
    *,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> tuple[str, str]:
    arguments = [
        "/usr/bin/dpkg-query",
        "-W",
        "-f=${binary:Package}\t${Architecture}\t${Version}\t${Status}\n",
        name,
    ]
    returncode, stdout, _stderr = _installed_command(
        arguments,
        f"installed package query: {name}",
        timeout=timeout,
    )
    if returncode:
        raise PackageLockError(f"required package is not installed: {name}")
    matches: list[tuple[str, str]] = []
    label = f"installed package query: {name}"
    for raw_line in split_command_lines(stdout, label):
        line = decode_command_line(raw_line, label)
        fields = line.split("\t")
        if len(fields) != 4:
            raise PackageLockError(f"{label} emitted an invalid record")
        binary_name, actual_architecture, version, status_value = fields
        binary_parts = binary_name.split(":", 1)
        if (
            not PACKAGE_NAME.fullmatch(binary_parts[0])
            or (
                len(binary_parts) == 2
                and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", binary_parts[1])
                is None
            )
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", actual_architecture)
            is None
            or not PACKAGE_VERSION.fullmatch(version)
            or not STATE_WORDS.fullmatch(status_value)
        ):
            raise PackageLockError(f"{label} emitted unsafe metadata")
        if (
            binary_name in {name, f"{name}:{architecture}"}
            and actual_architecture == architecture
        ):
            matches.append((version, status_value))
    if len(matches) != 1:
        raise PackageLockError(f"installed package identity is ambiguous: {name}")
    return matches[0]


def verify_installed(policy: LockPolicy) -> None:
    deadline = time.monotonic() + VERIFY_INSTALLED_TIMEOUT_SECONDS

    def remaining_verification_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PackageLockError("installed package verification exceeds its deadline")
        return remaining

    def checked_output(arguments: list[str], label: str) -> bytes:
        returncode, stdout, stderr = _installed_command(
            arguments,
            label,
            timeout=min(COMMAND_TIMEOUT_SECONDS, remaining_verification_time()),
        )
        if returncode:
            raise subprocess.CalledProcessError(
                returncode,
                arguments,
                output=stdout,
                stderr=stderr,
            )
        return stdout

    architecture_arguments = ["/usr/bin/dpkg", "--print-architecture"]
    architecture_output = checked_output(
        architecture_arguments, "native package architecture"
    )
    architecture_lines = split_command_lines(
        architecture_output, "native package architecture"
    )
    if len(architecture_lines) != 1:
        raise PackageLockError("native package architecture emitted an invalid record")
    architecture = decode_command_line(
        architecture_lines[0], "native package architecture"
    )
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", architecture) is None:
        raise PackageLockError("native package architecture emitted unsafe metadata")
    if architecture != "amd64":
        raise PackageLockError(f"unsupported package architecture: {architecture}")
    foreign_arguments = ["/usr/bin/dpkg", "--print-foreign-architectures"]
    foreign_output = checked_output(
        foreign_arguments, "foreign package architectures"
    )
    foreign = [
        decode_command_line(raw_line, "foreign package architectures")
        for raw_line in split_command_lines(
            foreign_output, "foreign package architectures"
        )
    ]
    if len(set(foreign)) != len(foreign) or any(
        re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", item) is None
        for item in foreign
    ):
        raise PackageLockError("foreign package architectures emitted unsafe metadata")
    if foreign:
        raise PackageLockError(f"foreign package architectures are not allowed: {foreign}")
    for (name, package_architecture), record in policy.packages.items():
        actual = installed_record(
            name,
            package_architecture,
            timeout=min(COMMAND_TIMEOUT_SECONDS, remaining_verification_time()),
        )
        expected = (record.version, "install ok installed")
        if actual != expected:
            raise PackageLockError(
                f"installed package state mismatch: {name}:{package_architecture}: "
                f"expected {expected}, got {actual}"
            )
    remaining_verification_time()


def verify_bootstrap(policy: LockPolicy) -> None:
    deadline = time.monotonic() + VERIFY_BOOTSTRAP_TIMEOUT_SECONDS

    def remaining_verification_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PackageLockError("bootstrap package verification exceeds its deadline")
        return remaining

    for (name, architecture), record in policy.packages.items():
        if record.role != "bootstrap":
            continue
        actual = installed_record(
            name,
            architecture,
            timeout=min(COMMAND_TIMEOUT_SECONDS, remaining_verification_time()),
        )
        expected = (record.version, "install ok installed")
        if actual != expected:
            raise PackageLockError(
                f"bootstrap package state mismatch: {name}:{architecture}: "
                f"expected {expected}, got {actual}"
            )
    remaining_verification_time()


def fixture_text() -> str:
    return (
        f"schema\t{SCHEMA}\n"
        f"snapshot\t{SNAPSHOTS[0]}\n"
        "package\tapt\tamd64\t2.8.3\tbootstrap\n"
        "package\troot-tool\tamd64\t1\trequested\n"
        "package\ttransitive\tall\t2\tclosure\n"
        "compat-package\tcompat-lib\tamd64\t3\trequested\t"
        "https://snapshot.ubuntu.com/ubuntu/20260727T000000Z/"
        "pool/main/c/compat/compat-lib_3_amd64.deb\t"
        + "a" * 64
        + "\nalternative\tawk\tmanual\t/usr/bin/gawk\n"
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-package-lock-test.") as directory:
        root = pathlib.Path(directory)

        def write(name: str, text: str) -> pathlib.Path:
            path = root / name
            path.write_text(text, encoding="ascii")
            path.chmod(0o644)
            return path

        valid = write("valid.tsv", fixture_text())
        parse_lock_bytes(read_regular(valid))
        cases = {
            "duplicate.tsv": (
                fixture_text().replace(
                    "package\troot-tool\tamd64\t1\trequested\n",
                    "package\troot-tool\tamd64\t1\trequested\n"
                    "package\troot-tool\tamd64\t1\tclosure\n",
                ),
                "duplicate package identity",
            ),
            "unsorted.tsv": (
                fixture_text().replace(
                    "package\troot-tool\tamd64\t1\trequested\n"
                    "package\ttransitive\tall\t2\tclosure\n",
                    "package\ttransitive\tall\t2\tclosure\n"
                    "package\troot-tool\tamd64\t1\trequested\n",
                ),
                "package records are not lexically ordered",
            ),
            "hostile-version.tsv": (
                fixture_text().replace(
                    "package\troot-tool\tamd64\t1\trequested",
                    "package\troot-tool\tamd64\t--option\trequested",
                ),
                "invalid package identity or policy",
            ),
            "wrong-snapshot.tsv": (
                fixture_text().replace("20260730T000000Z", "latest"),
                "package snapshot set differs from the reviewed contract",
            ),
            "wrong-compat-url.tsv": (
                fixture_text().replace(
                    "https://snapshot.ubuntu.com", "http://snapshot.ubuntu.com"
                ),
                "invalid compatibility package URL",
            ),
            "wrong-compat-digest.tsv": (
                fixture_text().replace("a" * 64, "g" * 64),
                "invalid compatibility package digest",
            ),
            "crlf.tsv": (
                fixture_text().replace("\n", "\r\n"),
                "package lock has invalid line framing",
            ),
        }
        for name, (text, expected_error) in cases.items():
            try:
                parse_lock_bytes(read_regular(write(name, text)))
            except PackageLockError as exc:
                exact = name == "crlf.tsv"
                diagnostic = str(exc)
                wrong_boundary = (
                    diagnostic != expected_error
                    if exact
                    else expected_error not in diagnostic
                )
                if wrong_boundary:
                    raise PackageLockError(
                        f"self-test rejected {name} at wrong boundary: {exc}"
                    ) from exc
            else:
                raise PackageLockError(f"self-test accepted hostile fixture: {name}")
        symlink = root / "symlink.tsv"
        symlink.symlink_to(valid)
        try:
            read_regular(symlink)
        except PackageLockError as exc:
            if "cannot open package lock" not in str(exc):
                raise PackageLockError(
                    f"self-test rejected symlink.tsv at wrong boundary: {exc}"
                ) from exc
        else:
            raise PackageLockError("self-test accepted a symlink package lock")
    print("haptics build-package lock self-test: PASS")


def main() -> None:
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test()
            return
        if len(sys.argv) == 2:
            parse_lock(pathlib.Path(sys.argv[1]))
            print("HAPTICS_BUILD_PACKAGES=PASS")
            return
        if len(sys.argv) == 4 and sys.argv[1] == "--verify-closure-plan":
            _, lock_path, plan_path = sys.argv[1:]
            policy = parse_lock(pathlib.Path(lock_path))
            plan = parse_apt_plan_bytes(
                read_private_evidence(pathlib.Path(plan_path), "apt closure plan", MAX_PLAN_BYTES)
            )
            verify_closure_plan(policy.expected_versions(), plan)
            print("HAPTICS_APT_CLOSURE_PLAN=PASS")
            return
        if len(sys.argv) == 4 and sys.argv[1] == "--verify-baseline-state":
            _, lock_path, state_path = sys.argv[1:]
            parse_lock(pathlib.Path(lock_path))
            state = parse_system_state_bytes(
                read_private_evidence(
                    pathlib.Path(state_path),
                    "pre-transaction package state",
                    MAX_SYSTEM_STATE_BYTES,
                )
            )
            verify_baseline_state(state)
            print("HAPTICS_PACKAGE_BASELINE_STATE=PASS")
            return
        if len(sys.argv) == 5 and sys.argv[1] == "--verify-host-plan":
            _, lock_path, state_path, plan_path = sys.argv[1:]
            policy = parse_lock(pathlib.Path(lock_path))
            before = parse_system_state_bytes(
                read_private_evidence(
                    pathlib.Path(state_path),
                    "pre-transaction package state",
                    MAX_SYSTEM_STATE_BYTES,
                )
            )
            plan = parse_apt_plan_bytes(
                read_private_evidence(pathlib.Path(plan_path), "host apt plan", MAX_PLAN_BYTES),
                allow_empty=True,
            )
            verify_host_plan(policy.expected_versions(), before, plan)
            print("HAPTICS_APT_HOST_PLAN=PASS")
            return
        if len(sys.argv) == 5 and sys.argv[1] == "--verify-state-transition":
            _, lock_path, before_path, after_path = sys.argv[1:]
            policy = parse_lock(pathlib.Path(lock_path))
            before = parse_system_state_bytes(
                read_private_evidence(
                    pathlib.Path(before_path),
                    "pre-transaction package state",
                    MAX_SYSTEM_STATE_BYTES,
                )
            )
            after = parse_system_state_bytes(
                read_private_evidence(
                    pathlib.Path(after_path),
                    "post-transaction package state",
                    MAX_SYSTEM_STATE_BYTES,
                )
            )
            verify_state_transition(
                policy.expected_versions(), policy.alternatives, before, after
            )
            print("HAPTICS_PACKAGE_STATE_TRANSITION=PASS")
            return
        if len(sys.argv) != 3:
            raise PackageLockError(
                "usage: verify-haptics-build-packages.py LOCK | "
                "--self-test | --emit-apt-arguments LOCK | "
                "--emit-snapshot-urls LOCK | --emit-compat-records LOCK | "
                "--capture-system-state LOCK | --verify-bootstrap LOCK | "
                "--verify-installed LOCK | --verify-closure-plan LOCK PLAN | "
                "--verify-baseline-state LOCK STATE | "
                "--verify-host-plan LOCK BEFORE PLAN | "
                "--verify-state-transition LOCK BEFORE AFTER"
            )
        mode, path = sys.argv[1:]
        policy = parse_lock(pathlib.Path(path))
        if mode == "--emit-apt-arguments":
            emit_nul(
                [
                    f"{name}={record.version}"
                    for (name, _), record in policy.packages.items()
                    if record.source == "repo"
                ]
            )
        elif mode == "--emit-snapshot-urls":
            emit_nul(list(policy.snapshots))
        elif mode == "--emit-compat-records":
            emit_nul(
                [
                    "\t".join(
                        (
                            name,
                            architecture,
                            record.version,
                            record.url or "",
                            record.digest or "",
                        )
                    )
                    for (name, architecture), record in policy.packages.items()
                    if record.source == "compat"
                ]
            )
        elif mode == "--verify-bootstrap":
            verify_bootstrap(policy)
            print("HAPTICS_BUILD_PACKAGES_BOOTSTRAP=PASS")
        elif mode == "--verify-installed":
            verify_installed(policy)
            print("HAPTICS_BUILD_PACKAGES_INSTALLED=PASS")
        elif mode == "--capture-system-state":
            sys.stdout.buffer.write(serialize_system_state(capture_system_state()))
        else:
            raise PackageLockError(f"unknown mode: {mode}")
    except (OSError, PackageLockError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"haptics build-package verification failed: {exc}") from exc


if __name__ == "__main__":
    main()
