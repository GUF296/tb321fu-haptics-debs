#!/usr/bin/env python3
"""Focused fixture for preparing the root-private APT transaction manifest."""

from __future__ import annotations

from dataclasses import dataclass
import contextlib
import errno
import hashlib
import importlib.util
import io
import os
import pathlib
import stat
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "haptics_apt_preparation", MODULE_PATH
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT transaction verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_rejected(
    verifier, callback, label: str, expected: str, *, exact: bool = False
) -> None:
    try:
        callback()
    except verifier.AptTransactionError as exc:
        if (str(exc) != expected) if exact else (expected not in str(exc)):
            raise SystemExit(
                f"APT preparation rejected {label} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"APT preparation raised an unexpected exception for {label}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"APT preparation accepted hostile fixture: {label}")


@dataclass(frozen=True)
class FakePlannedPackage:
    version: str
    architecture: str
    old_version: str | None


@dataclass(frozen=True)
class FakePlan:
    installs: dict[tuple[str, str], FakePlannedPackage]
    configures: dict[tuple[str, str], FakePlannedPackage]


class FakePolicy:
    def expected_versions(self):
        return {("example", "amd64"): "1.0-1"}


class FakePackageVerifier:
    def __init__(self) -> None:
        self.state = object()
        self.capture_count = 0
        self.capture_deadlines: list[float] = []
        self.verified_plan = False

    def parse_lock_bytes(self, raw: bytes):
        if raw != b"lock\n":
            raise ValueError("wrong package lock")
        return FakePolicy()

    def parse_system_state_bytes(self, raw: bytes):
        if raw != b"package-state\n":
            raise ValueError("wrong package state")
        return self.state

    def serialize_system_state(self, state) -> bytes:
        if state is not self.state:
            raise ValueError("wrong package state object")
        return b"package-state\n"

    def parse_apt_plan_bytes(self, raw: bytes):
        if raw != b"plan\n":
            raise ValueError("wrong APT plan")
        planned = FakePlannedPackage("1.0-1", "amd64", None)
        return FakePlan({("example", "amd64"): planned}, {("example", "amd64"): planned})

    def verify_host_plan(self, expected, before, plan) -> None:
        if expected != {("example", "amd64"): "1.0-1"} or before is not self.state:
            raise ValueError("host plan inputs differ")
        if set(plan.installs) != {("example", "amd64")}:
            raise ValueError("host plan identity differs")
        self.verified_plan = True

    def capture_system_state(self, *, deadline=None):
        if not isinstance(deadline, float):
            raise AssertionError("APT preparation omitted the package capture deadline")
        self.capture_deadlines.append(deadline)
        self.capture_count += 1
        return self.state


class FakeDpkgVerifier:
    MAX_STATUS_BYTES = 16 * 1024 * 1024
    MAX_SERIALIZED_STATE_BYTES = 32 * 1024 * 1024

    def __init__(self) -> None:
        self.state = object()
        self.host = object()
        self.capture_count = 0
        self.parsed_host_reference_count = 0
        self.serialized_host_reference_count = 0
        self.verified_host_count = 0
        self.verified_host = False
        self.verified_post = False

    def parse_dpkg_state_bytes(self, raw: bytes):
        if raw != b"dpkg-state\n":
            raise ValueError("wrong dpkg state")
        return self.state

    def serialize_dpkg_state(self, state) -> bytes:
        if state is not self.state:
            raise ValueError("wrong dpkg state object")
        return b"dpkg-state\n"

    def parse_host_reference_bytes(self, raw: bytes):
        self.parsed_host_reference_count += 1
        if raw != b"host-reference\n":
            raise ValueError("wrong host reference")
        return self.host

    def verify_host_reference(self, state, reference) -> None:
        self.verified_host_count += 1
        if state is not self.state or reference is not self.host:
            raise ValueError("host reference inputs differ")
        self.verified_host = True

    def host_reference_from_state(self, state):
        if state is not self.state:
            raise ValueError("wrong host state")
        return self.host

    def serialize_host_reference(self, reference) -> bytes:
        self.serialized_host_reference_count += 1
        if reference is not self.host:
            raise ValueError("wrong host reference object")
        return b"host-reference\n"

    def parse_status_identities(self, raw: bytes):
        if raw != b"status\n":
            raise ValueError("wrong status bytes")
        return {}

    def capture_dpkg_state(self, admin, uid: int, gid: int):
        if admin not in {
            pathlib.Path("/tmp/dpkg-admin"),
            pathlib.Path("/var/lib/dpkg"),
        } or (uid, gid) not in {
            (0, 0),
            (os.getuid(), os.getgid()),
        }:
            raise ValueError("wrong dpkg capture inputs")
        self.capture_count += 1
        return self.state

    def verify_dpkg_state(self, actual, expected) -> None:
        if actual is not self.state or expected is not self.state:
            raise ValueError("dpkg state drift")

    def verify_post_dpkg_state(self, before, after, approved) -> None:
        if before is not self.state or after is not self.state:
            raise ValueError("wrong post-state objects")
        if approved != (("example", "amd64"),):
            raise ValueError("wrong post-state allowlist")
        self.verified_post = True

    def read_regular(
        self,
        path: pathlib.Path,
        mode: int,
        uid: int,
        gid: int,
        maximum: int,
        label: str,
    ) -> bytes:
        if path == pathlib.Path("/tmp/dpkg-admin/status"):
            return b"status\n"
        metadata = path.stat()
        raw = path.read_bytes()
        if (
            stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or len(raw) > maximum
            or not label
        ):
            raise ValueError("unsafe private evidence")
        return raw


def verify_whole_preparation_deadline(
    verifier,
    package,
    dpkg,
    transaction,
    cli_archive,
    archive_path: pathlib.Path,
    archives: pathlib.Path,
    compat: pathlib.Path,
    private: pathlib.Path,
    hook_command: str,
) -> None:
    original_argv = sys.argv
    original_package_loader = verifier.load_package_verifier
    original_dpkg_loader = verifier.load_dpkg_state_verifier
    original_archive_capture = verifier.capture_deb_archive
    original_monotonic = verifier.time.monotonic
    original_enumerate = verifier.enumerate_archive_paths
    original_prepare = verifier.prepare_expected_transaction
    original_write_manifest = verifier.write_private_manifest
    original_read_regular = dpkg.read_regular
    original_open = verifier.os.open
    original_fsync = verifier.os.fsync
    original_fstat = verifier.os.fstat
    original_dup = verifier.os.dup
    original_close = verifier.os.close
    original_stat = verifier.os.stat
    original_unlink = verifier.os.unlink

    def preparation_argv(manifest_path: pathlib.Path) -> list[str]:
        return [
            str(MODULE_PATH),
            "--prepare-manifest-disposable",
            "/tmp/dpkg-admin",
            str(os.getuid()),
            str(os.getgid()),
            hook_command,
            str(private / "lock.tsv"),
            str(private / "package-state.tsv"),
            str(private / "host.plan"),
            str(private / "dpkg-state.tsv"),
            str(private / "host-reference.tsv"),
            str(archives),
            str(compat),
            str(manifest_path),
        ]

    def expect_deadline_rejection(
        label: str, expected_notes: tuple[str, ...] = ()
    ) -> SystemExit:
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                verifier.main()
        except SystemExit as exc:
            expected = (
                "haptics APT manifest preparation failed: "
                "APT transaction preparation exceeded its deadline"
            )
            expected += "".join(
                "\nhaptics APT manifest preparation failed cleanup: " + note
                for note in expected_notes
            )
            if str(exc) != expected:
                raise SystemExit(
                    f"APT preparation rejected {label} at the wrong boundary: {exc}"
                ) from exc
            if output.getvalue():
                raise SystemExit(f"APT preparation printed PASS before rejecting {label}")
            return exc
        raise SystemExit(f"APT preparation accepted expired whole deadline: {label}")

    verifier.load_package_verifier = lambda: package
    verifier.load_dpkg_state_verifier = lambda: dpkg
    verifier.capture_deb_archive = lambda path, uid, gid, **kwargs: (
        cli_archive
        if path == archive_path and (uid, gid) == (os.getuid(), os.getgid())
        else (_ for _ in ()).throw(ValueError("wrong deadline archive capture inputs"))
    )
    try:
        pre_read_manifest = private / "deadline-pre-read.tsv"
        pre_read_clock = [0.0]
        pre_read_calls = 0

        def timed_read_regular(*args, **kwargs):
            nonlocal pre_read_calls
            raw = original_read_regular(*args, **kwargs)
            pre_read_calls += 1
            if pre_read_calls == 1:
                pre_read_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS
            return raw

        verifier.time.monotonic = lambda: pre_read_clock[0]
        dpkg.read_regular = timed_read_regular
        sys.argv = preparation_argv(pre_read_manifest)
        try:
            expect_deadline_rejection("evidence pre-read")
        finally:
            dpkg.read_regular = original_read_regular
            pre_read_manifest.unlink(missing_ok=True)
        if pre_read_calls != 1:
            raise SystemExit(
                "APT whole deadline crossed an extra evidence read: "
                f"{pre_read_calls}"
            )

        second_enumeration_manifest = private / "deadline-second-enumeration.tsv"
        second_clock = [0.0]
        enumeration_deadlines: list[float | None] = []
        preparation_deadlines: list[float | None] = []
        writer_calls = 0

        def timed_enumerate(*args, **kwargs):
            supplied_deadline = kwargs.pop("deadline", None)
            enumeration_deadlines.append(supplied_deadline)
            result = original_enumerate(*args, **kwargs)
            if len(enumeration_deadlines) == 2:
                second_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS
            return result

        def timed_prepare(*args, **kwargs):
            preparation_deadlines.append(kwargs.pop("deadline", None))
            if kwargs:
                raise SystemExit(
                    f"APT preparation received unexpected keywords: {kwargs!r}"
                )
            second_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS - 0.1
            return transaction

        def counting_writer(*args, **kwargs):
            nonlocal writer_calls
            del args, kwargs
            writer_calls += 1

        verifier.time.monotonic = lambda: second_clock[0]
        verifier.enumerate_archive_paths = timed_enumerate
        verifier.prepare_expected_transaction = timed_prepare
        verifier.write_private_manifest = counting_writer
        sys.argv = preparation_argv(second_enumeration_manifest)
        try:
            expect_deadline_rejection("second archive enumeration")
        finally:
            verifier.enumerate_archive_paths = original_enumerate
            verifier.prepare_expected_transaction = original_prepare
            verifier.write_private_manifest = original_write_manifest
            second_enumeration_manifest.unlink(missing_ok=True)
        expected_deadline = verifier.PREPARATION_TIMEOUT_SECONDS
        if enumeration_deadlines != [expected_deadline, expected_deadline]:
            raise SystemExit(
                "APT preparation did not reuse its entry deadline for both enumerations: "
                f"{enumeration_deadlines!r}"
            )
        if preparation_deadlines != [expected_deadline]:
            raise SystemExit(
                "APT preparation reset the deadline inside transaction preparation: "
                f"{preparation_deadlines!r}"
            )
        if writer_calls:
            raise SystemExit("APT preparation entered manifest publication after expiry")

        post_fsync_manifest = private / "deadline-post-fsync.tsv"
        post_fsync_clock = [0.0]
        post_fsync_deadlines: list[float | None] = []
        fsync_calls = 0

        def post_fsync_prepare(*args, **kwargs):
            post_fsync_deadlines.append(kwargs.pop("deadline", None))
            if kwargs:
                raise SystemExit(
                    f"APT preparation received unexpected keywords: {kwargs!r}"
                )
            post_fsync_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS - 0.1
            return transaction

        def expiring_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            original_fsync(descriptor)
            fsync_calls += 1
            if fsync_calls == 2:
                post_fsync_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS

        verifier.time.monotonic = lambda: post_fsync_clock[0]
        verifier.prepare_expected_transaction = post_fsync_prepare
        verifier.os.fsync = expiring_fsync
        sys.argv = preparation_argv(post_fsync_manifest)
        try:
            expect_deadline_rejection("manifest directory fsync")
        finally:
            verifier.prepare_expected_transaction = original_prepare
            verifier.os.fsync = original_fsync
            post_fsync_manifest.unlink(missing_ok=True)
        if post_fsync_deadlines != [verifier.PREPARATION_TIMEOUT_SECONDS]:
            raise SystemExit(
                "APT manifest writer did not inherit the preparation deadline: "
                f"{post_fsync_deadlines!r}"
            )
        if fsync_calls < 2:
            raise SystemExit("APT post-fsync deadline fixture did not reach publication")
        if post_fsync_manifest.exists():
            raise SystemExit("APT preparation retained an expired manifest inode")

        prepin_issues: list[str] = []
        for case in ("deadline", "first-fstat", "first-fstat-replacement"):
            prepin_manifest = private / f"prepin-{case}.tsv"
            prepin_clock = [0.0]
            created_descriptors: list[int] = []
            target_fstat_calls = 0
            replacement_raw = b"unrelated manifest namespace\n"

            def prepin_prepare(*args, **kwargs):
                del args
                kwargs.pop("deadline", None)
                if kwargs:
                    raise SystemExit(
                        f"APT pre-pin preparation received unexpected keywords: {kwargs!r}"
                    )
                return transaction

            def prepin_open(path, flags, *args, **kwargs):
                descriptor = original_open(path, flags, *args, **kwargs)
                if (
                    os.fspath(path) == prepin_manifest.name
                    and flags & os.O_EXCL
                    and kwargs.get("dir_fd") is not None
                ):
                    created_descriptors.append(descriptor)
                    if case == "deadline":
                        prepin_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS
                return descriptor

            def prepin_fstat(descriptor: int):
                nonlocal target_fstat_calls
                if created_descriptors and descriptor == created_descriptors[0]:
                    target_fstat_calls += 1
                    if case.startswith("first-fstat") and target_fstat_calls == 1:
                        if case.endswith("replacement"):
                            original_unlink(prepin_manifest)
                            prepin_manifest.write_bytes(replacement_raw)
                            prepin_manifest.chmod(0o600)
                        raise OSError(
                            "injected first post-open manifest fstat failure"
                        )
                return original_fstat(descriptor)

            verifier.time.monotonic = lambda: prepin_clock[0]
            verifier.prepare_expected_transaction = prepin_prepare
            verifier.os.open = prepin_open
            verifier.os.fstat = prepin_fstat
            sys.argv = preparation_argv(prepin_manifest)
            output = io.StringIO()
            caught: SystemExit | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except SystemExit as exc:
                caught = exc
            finally:
                sys.argv = original_argv
                verifier.os.open = original_open
                verifier.os.fstat = original_fstat
                verifier.prepare_expected_transaction = original_prepare
                verifier.time.monotonic = original_monotonic
            expected_primary = (
                "APT transaction preparation exceeded its deadline"
                if case == "deadline"
                else "cannot create private APT transaction manifest: "
                "injected first post-open manifest fstat failure"
            )
            expected_notes = (
                (
                    "APT transaction manifest cleanup found the published "
                    "manifest namespace changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected_rendered = (
                "haptics APT manifest preparation failed: " + expected_primary
                + "".join(
                    "\nhaptics APT manifest preparation failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None:
                prepin_issues.append(f"{case} was accepted")
            else:
                primary = caught.__cause__
                if (
                    not isinstance(primary, verifier.AptTransactionError)
                    or str(primary) != expected_primary
                ):
                    prepin_issues.append(
                        f"{case} replaced its primary with {primary!r}"
                    )
                elif tuple(getattr(primary, "__notes__", ())) != expected_notes:
                    prepin_issues.append(
                        f"{case} cleanup notes were "
                        f"{tuple(getattr(primary, '__notes__', ()))!r}"
                    )
                if str(caught) != expected_rendered:
                    prepin_issues.append(
                        f"{case} CLI evidence was {str(caught)!r}"
                    )
            if output.getvalue():
                prepin_issues.append(f"{case} printed PASS output")
            minimum_fstats = 1 if case == "deadline" else 2
            if target_fstat_calls < minimum_fstats:
                prepin_issues.append(
                    f"{case} used only {target_fstat_calls} owned-descriptor fstats"
                )
            for descriptor in created_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    prepin_issues.append(f"{case} leaked its publication descriptor")
            if case.endswith("replacement"):
                if (
                    not prepin_manifest.exists()
                    or prepin_manifest.read_bytes() != replacement_raw
                ):
                    prepin_issues.append(f"{case} removed the replacement namespace")
            elif prepin_manifest.exists():
                prepin_issues.append(f"{case} left the owned manifest pathname")
            try:
                original_unlink(prepin_manifest)
            except FileNotFoundError:
                pass
        if prepin_issues:
            raise SystemExit(
                "APT manifest pre-pin fixture failures: " + "; ".join(prepin_issues)
            )

        transfer_manifest = private / "ownership-transfer-cancel.tsv"
        transfer_cancel = KeyboardInterrupt(
            "injected manifest ownership-transfer cancellation"
        )
        transfer_descriptors: list[int] = []
        original_accept = verifier.PublicationOwnershipSlot.accept

        def accept_then_cancel(self, ownership) -> None:
            original_accept(self, ownership)
            if ownership.parent_descriptor is None:
                raise SystemExit(
                    "APT manifest transfer fixture lost parent ownership"
                )
            transfer_descriptors.extend(
                (ownership.descriptor, ownership.parent_descriptor)
            )
            raise transfer_cancel

        verifier.PublicationOwnershipSlot.accept = accept_then_cancel
        sys.argv = preparation_argv(transfer_manifest)
        transfer_output = io.StringIO()
        transfer_caught: BaseException | None = None
        try:
            with contextlib.redirect_stdout(transfer_output):
                verifier.main()
        except BaseException as exc:
            transfer_caught = exc
        finally:
            sys.argv = original_argv
            verifier.PublicationOwnershipSlot.accept = original_accept
        if transfer_caught is not transfer_cancel:
            raise SystemExit(
                "APT manifest transfer cleanup replaced cancellation: "
                f"{transfer_caught!r}"
            ) from transfer_caught
        if transfer_output.getvalue():
            raise SystemExit("APT manifest transfer cancellation printed PASS")
        if len(transfer_descriptors) != 2:
            raise SystemExit("APT manifest transfer fixture missed owned descriptors")
        for descriptor in transfer_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise SystemExit(
                    "APT manifest transfer cancellation leaked an owned descriptor"
                )
        if transfer_manifest.exists():
            raise SystemExit(
                "APT manifest transfer cancellation left its published inode"
            )

        return_cancel_manifest = private / "ownership-return-cancel.tsv"
        return_cancel = KeyboardInterrupt(
            "injected manifest post-return cancellation"
        )
        return_descriptors: list[int] = []

        def return_then_cancel(*args, **kwargs):
            result = original_write_manifest(*args, **kwargs)
            slot = kwargs.get("ownership_slot")
            if (
                result is None
                or type(slot) is not verifier.PublicationOwnershipSlot
                or slot.ownership is not result
                or result.parent_descriptor is None
            ):
                raise SystemExit(
                    "APT manifest return fixture lost transferred ownership"
                )
            return_descriptors.extend((result.descriptor, result.parent_descriptor))
            raise return_cancel

        verifier.write_private_manifest = return_then_cancel
        sys.argv = preparation_argv(return_cancel_manifest)
        return_output = io.StringIO()
        return_caught: BaseException | None = None
        try:
            with contextlib.redirect_stdout(return_output):
                verifier.main()
        except BaseException as exc:
            return_caught = exc
        finally:
            sys.argv = original_argv
            verifier.write_private_manifest = original_write_manifest
        if return_caught is not return_cancel:
            raise SystemExit(
                "APT manifest post-return cleanup replaced cancellation: "
                f"{return_caught!r}"
            ) from return_caught
        if return_output.getvalue():
            raise SystemExit("APT manifest post-return cancellation printed PASS")
        if len(return_descriptors) != 2:
            raise SystemExit("APT manifest return fixture missed owned descriptors")
        for descriptor in return_descriptors:
            try:
                original_fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise SystemExit(
                    "APT manifest post-return cancellation leaked a descriptor"
                )
        if return_cancel_manifest.exists():
            raise SystemExit(
                "APT manifest post-return cancellation left its published inode"
            )

        outer_cases = (
            ("clean", ()),
            (
                "unlink-failure",
                (
                    "APT transaction manifest cleanup could not remove published manifest",
                    "APT transaction manifest cleanup left the published manifest inode present",
                ),
            ),
            (
                "namespace-replacement",
                (
                    "APT transaction manifest cleanup found the published manifest namespace changed",
                ),
            ),
            (
                "directory-fsync",
                (
                    "APT transaction manifest cleanup could not synchronize manifest directory",
                ),
            ),
            (
                "published-recheck",
                (
                    "APT transaction manifest cleanup could not confirm published manifest removal",
                ),
            ),
            (
                "ownership-fstat",
                (
                    "APT transaction manifest cleanup could not inspect owned publication inode",
                    "APT transaction manifest cleanup left the published manifest inode present",
                    "APT transaction manifest cleanup could not close publication descriptor",
                ),
            ),
            (
                "publication-close",
                (
                    "APT transaction manifest cleanup could not close publication descriptor",
                ),
            ),
            (
                "parent-close",
                (
                    "APT transaction manifest cleanup could not close parent directory descriptor",
                ),
            ),
        )
        for case, expected_notes in outer_cases:
            outer_return_manifest = private / f"deadline-after-return-{case}.tsv"
            outer_return_clock = [0.0]
            stat_calls = 0
            owned_descriptors: list[int] = []
            replacement_raw = b"unrelated manifest namespace\n"

            def hostile_stat(path, *args, **kwargs):
                nonlocal stat_calls
                if (
                    case == "published-recheck"
                    and os.fspath(path) == outer_return_manifest.name
                    and kwargs.get("dir_fd") is not None
                ):
                    stat_calls += 1
                    if stat_calls == 2:
                        raise OSError("injected outer manifest recheck failure")
                return original_stat(path, *args, **kwargs)

            def hostile_unlink(path, *args, **kwargs):
                if (
                    case == "unlink-failure"
                    and os.fspath(path) == outer_return_manifest.name
                    and kwargs.get("dir_fd") is not None
                ):
                    raise OSError("injected outer manifest unlink failure")
                return original_unlink(path, *args, **kwargs)

            def hostile_fsync(descriptor: int) -> None:
                del descriptor
                raise OSError("injected outer manifest fsync failure")

            def hostile_fstat(descriptor: int):
                if (
                    case == "ownership-fstat"
                    and owned_descriptors
                    and descriptor == owned_descriptors[0]
                ):
                    raise OSError("injected outer manifest ownership failure")
                return original_fstat(descriptor)

            def hostile_close(descriptor: int) -> None:
                target = (
                    owned_descriptors[0]
                    if case == "publication-close"
                    else owned_descriptors[1]
                )
                original_close(descriptor)
                if descriptor == target:
                    raise OSError("injected outer manifest close failure")

            def returning_then_expiring_writer(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest main did not retain publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                if case == "namespace-replacement":
                    original_unlink(outer_return_manifest)
                    outer_return_manifest.write_bytes(replacement_raw)
                    outer_return_manifest.chmod(0o600)
                elif case == "unlink-failure":
                    verifier.os.unlink = hostile_unlink
                elif case == "directory-fsync":
                    verifier.os.fsync = hostile_fsync
                elif case == "published-recheck":
                    verifier.os.stat = hostile_stat
                elif case == "ownership-fstat":
                    verifier.os.fstat = hostile_fstat
                elif case in {"publication-close", "parent-close"}:
                    verifier.os.close = hostile_close
                outer_return_clock[0] = verifier.PREPARATION_TIMEOUT_SECONDS
                return result

            verifier.time.monotonic = lambda: outer_return_clock[0]
            verifier.write_private_manifest = returning_then_expiring_writer
            sys.argv = preparation_argv(outer_return_manifest)
            try:
                caught = expect_deadline_rejection(
                    f"manifest writer return: {case}", expected_notes
                )
                primary = caught.__cause__
                if (
                    not isinstance(primary, verifier.AptTransactionError)
                    or str(primary)
                    != "APT transaction preparation exceeded its deadline"
                ):
                    raise SystemExit(
                        "APT manifest outer cleanup replaced the deadline primary: "
                        f"{case}: {primary}"
                    ) from caught
                notes = tuple(getattr(primary, "__notes__", ()))
                if notes != expected_notes or any(
                    "injected" in note for note in notes
                ):
                    raise SystemExit(
                        "APT manifest outer cleanup evidence drifted: "
                        f"{case}: expected={expected_notes!r} actual={notes!r}"
                    ) from caught
                for descriptor in owned_descriptors:
                    try:
                        original_fstat(descriptor)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise
                    else:
                        raise SystemExit(
                            "APT manifest main leaked publication ownership"
                        )
                if case == "namespace-replacement":
                    if (
                        not outer_return_manifest.exists()
                        or outer_return_manifest.read_bytes() != replacement_raw
                    ):
                        raise SystemExit(
                            "APT manifest outer cleanup removed a replacement namespace"
                        )
                elif case in {"unlink-failure", "ownership-fstat"}:
                    if not outer_return_manifest.exists():
                        raise SystemExit(
                            "APT manifest unlink-failure fixture lost its owned inode"
                        )
                elif outer_return_manifest.exists():
                    raise SystemExit(
                        "APT preparation retained the manifest after its writer returned: "
                        f"{case}"
                    )
            finally:
                verifier.os.stat = original_stat
                verifier.os.unlink = original_unlink
                verifier.os.fsync = original_fsync
                verifier.os.fstat = original_fstat
                verifier.os.close = original_close
                verifier.write_private_manifest = original_write_manifest
                try:
                    original_unlink(outer_return_manifest)
                except FileNotFoundError:
                    pass

        replacement_raw = b"unrelated release-close manifest namespace\n"
        for case in (
            "publication-close",
            "publication-close-replacement",
            "parent-close",
            "parent-close-replacement",
        ):
            release_manifest = private / f"{case}.tsv"
            owned_descriptors: list[int] = []

            def close_owned_publication_then_fail(descriptor: int) -> None:
                original_close(descriptor)
                target_index = 1 if case.startswith("parent") else 0
                if (
                    len(owned_descriptors) > target_index
                    and descriptor == owned_descriptors[target_index]
                ):
                    raise OSError("injected manifest release close failure")

            def returning_release_manifest(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest release-close fixture lost publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                if case.endswith("replacement"):
                    original_unlink(release_manifest)
                    release_manifest.write_bytes(replacement_raw)
                    release_manifest.chmod(0o600)
                verifier.os.close = close_owned_publication_then_fail
                return result

            verifier.write_private_manifest = returning_release_manifest
            sys.argv = preparation_argv(release_manifest)
            output = io.StringIO()
            caught: SystemExit | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except SystemExit as exc:
                caught = exc
            finally:
                verifier.os.close = original_close
                verifier.write_private_manifest = original_write_manifest
            close_role = "parent directory" if case.startswith("parent") else "publication"
            expected_notes = (
                f"APT transaction manifest cleanup could not close {close_role} descriptor",
            ) + (
                (
                    "APT transaction manifest cleanup found the published manifest "
                    "namespace changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected = (
                "haptics APT manifest preparation failed: cannot release "
                "APT transaction manifest ownership"
                + "".join(
                    "\nhaptics APT manifest preparation failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None or str(caught) != expected or output.getvalue():
                raise SystemExit(
                    f"APT manifest release-close rollback drifted: {case}: {caught}"
                ) from caught
            primary = caught.__cause__
            if (
                not isinstance(primary, verifier.AptTransactionError)
                or str(primary)
                != "cannot release APT transaction manifest ownership"
                or tuple(getattr(primary, "__notes__", ())) != expected_notes
            ):
                raise SystemExit(
                    f"APT manifest release-close primary drifted: {case}: {primary}"
                ) from caught
            for descriptor in owned_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT manifest release-close fixture leaked original ownership"
                    )
            if case.endswith("replacement"):
                if (
                    not release_manifest.exists()
                    or release_manifest.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT manifest release-close rollback removed replacement namespace"
                    )
                original_unlink(release_manifest)
            elif release_manifest.exists():
                raise SystemExit(
                    "APT manifest release-close rollback left its published inode"
                )

        for case in (
            "publication-guard-close",
            "publication-guard-close-replacement",
            "parent-guard-close",
            "parent-guard-close-replacement",
        ):
            release_manifest = private / f"{case}.tsv"
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []

            def track_rollback_dup(descriptor: int) -> int:
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def close_rollback_guard_then_fail(descriptor: int) -> None:
                original_close(descriptor)
                target_index = 1 if case.startswith("parent") else 0
                if (
                    len(duplicated_descriptors) > target_index
                    and descriptor == duplicated_descriptors[target_index]
                ):
                    raise OSError("injected manifest rollback guard close failure")

            def returning_guard_close_manifest(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest guard-close fixture lost publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                if case.endswith("replacement"):
                    original_unlink(release_manifest)
                    release_manifest.write_bytes(replacement_raw)
                    release_manifest.chmod(0o600)
                verifier.os.dup = track_rollback_dup
                verifier.os.close = close_rollback_guard_then_fail
                return result

            verifier.write_private_manifest = returning_guard_close_manifest
            sys.argv = preparation_argv(release_manifest)
            output = io.StringIO()
            caught: SystemExit | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except SystemExit as exc:
                caught = exc
            finally:
                verifier.os.dup = original_dup
                verifier.os.close = original_close
                verifier.write_private_manifest = original_write_manifest
            close_role = "parent directory" if case.startswith("parent") else "publication"
            expected_notes = (
                f"APT transaction manifest cleanup could not close {close_role} descriptor",
            ) + (
                (
                    "APT transaction manifest cleanup found the published manifest "
                    "namespace changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected = (
                "haptics APT manifest preparation failed: cannot release "
                "APT transaction manifest ownership"
                + "".join(
                    "\nhaptics APT manifest preparation failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None or str(caught) != expected or output.getvalue():
                raise SystemExit(
                    f"APT manifest rollback-guard close drifted: {case}: {caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT manifest rollback-guard fixture leaked a descriptor"
                    )
            if case.endswith("replacement"):
                if (
                    not release_manifest.exists()
                    or release_manifest.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT manifest rollback-guard cleanup removed replacement namespace"
                    )
                original_unlink(release_manifest)
            elif release_manifest.exists():
                raise SystemExit(
                    "APT manifest rollback-guard cleanup left its published inode"
                )

        for case in (
            "cleanup-publication-close",
            "cleanup-parent-close",
            "terminal-parent-close",
        ):
            release_manifest = private / f"{case}.tsv"
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []

            def track_cleanup_dup(descriptor: int) -> int:
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def close_final_cleanup_then_fail(descriptor: int) -> None:
                original_close(descriptor)
                target_index = (
                    4
                    if case.startswith("terminal-parent")
                    else 3
                    if case.startswith("cleanup-parent")
                    else 2
                )
                if (
                    len(duplicated_descriptors) > target_index
                    and descriptor == duplicated_descriptors[target_index]
                ):
                    raise OSError("injected final manifest cleanup close failure")

            def returning_cleanup_close_manifest(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest cleanup-close fixture lost publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                verifier.os.dup = track_cleanup_dup
                verifier.os.close = close_final_cleanup_then_fail
                return result

            verifier.write_private_manifest = returning_cleanup_close_manifest
            sys.argv = preparation_argv(release_manifest)
            output = io.StringIO()
            caught: SystemExit | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except SystemExit as exc:
                caught = exc
            finally:
                verifier.os.dup = original_dup
                verifier.os.close = original_close
                verifier.write_private_manifest = original_write_manifest
            close_role = "parent directory" if "parent" in case else "publication"
            expected_note = (
                f"APT transaction manifest cleanup could not close {close_role} descriptor"
            )
            expected = (
                "haptics APT manifest preparation failed: cannot release "
                "APT transaction manifest ownership\n"
                "haptics APT manifest preparation failed cleanup: "
                + expected_note
            )
            if caught is None or str(caught) != expected or output.getvalue():
                raise SystemExit(
                    f"APT final manifest cleanup-close semantics drifted: {case}: {caught}"
                ) from caught
            primary = caught.__cause__
            if (
                not isinstance(primary, verifier.AptTransactionError)
                or str(primary)
                != "cannot release APT transaction manifest ownership"
                or expected_note not in tuple(getattr(primary, "__notes__", ()))
            ):
                raise SystemExit(
                    f"APT final manifest cleanup-close primary drifted: {case}: {primary}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT final manifest cleanup-close fixture leaked a descriptor"
                    )
            if release_manifest.exists():
                raise SystemExit(
                    "APT final manifest cleanup-close rollback left its published inode"
                )

        for case in (
            "cleanup-publication-cancel",
            "cleanup-parent-cancel",
            "terminal-parent-cancel",
        ):
            release_manifest = private / f"{case}.tsv"
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []
            cancellation = KeyboardInterrupt(
                f"injected final manifest {case} cancellation"
            )

            def track_cleanup_dup(descriptor: int) -> int:
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def cancel_final_cleanup_close(descriptor: int) -> None:
                original_close(descriptor)
                target_index = (
                    4
                    if case.startswith("terminal-parent")
                    else 3
                    if case.startswith("cleanup-parent")
                    else 2
                )
                if (
                    len(duplicated_descriptors) > target_index
                    and descriptor == duplicated_descriptors[target_index]
                ):
                    raise cancellation

            def returning_cleanup_cancel_manifest(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest cleanup-cancellation fixture lost publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                verifier.os.dup = track_cleanup_dup
                verifier.os.close = cancel_final_cleanup_close
                return result

            verifier.write_private_manifest = returning_cleanup_cancel_manifest
            sys.argv = preparation_argv(release_manifest)
            output = io.StringIO()
            caught: BaseException | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except BaseException as exc:
                caught = exc
            finally:
                verifier.os.dup = original_dup
                verifier.os.close = original_close
                verifier.write_private_manifest = original_write_manifest
            close_role = "parent directory" if "parent" in case else "publication"
            expected_note = (
                f"APT transaction manifest cleanup could not close {close_role} descriptor"
            )
            if (
                caught is not cancellation
                or output.getvalue()
                or expected_note not in tuple(getattr(caught, "__notes__", ()))
            ):
                raise SystemExit(
                    f"APT final manifest cleanup cancellation drifted: {case}: {caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT final manifest cleanup cancellation leaked a descriptor"
                    )
            if release_manifest.exists():
                raise SystemExit(
                    "APT final manifest cleanup cancellation left its published inode"
                )

        for case in (
            "publication-dup",
            "publication-dup-replacement",
            "parent-dup",
            "parent-dup-replacement",
            "cleanup-publication-dup",
            "cleanup-publication-dup-replacement",
            "cleanup-parent-dup",
            "cleanup-parent-dup-replacement",
        ):
            release_manifest = private / f"{case}.tsv"
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []
            dup_calls = 0

            def fail_selected_rollback_dup(descriptor: int) -> int:
                nonlocal dup_calls
                dup_calls += 1
                base_case = case.removesuffix("-replacement")
                target_call = {
                    "publication-dup": 1,
                    "parent-dup": 2,
                    "cleanup-publication-dup": 3,
                    "cleanup-parent-dup": 4,
                }[base_case]
                if dup_calls == target_call:
                    raise OSError("injected manifest rollback dup failure")
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                return duplicated

            def returning_dup_failure_manifest(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest dup-failure fixture lost publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                if case.endswith("replacement"):
                    original_unlink(release_manifest)
                    release_manifest.write_bytes(replacement_raw)
                    release_manifest.chmod(0o600)
                verifier.os.dup = fail_selected_rollback_dup
                return result

            verifier.write_private_manifest = returning_dup_failure_manifest
            sys.argv = preparation_argv(release_manifest)
            output = io.StringIO()
            caught: SystemExit | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except SystemExit as exc:
                caught = exc
            finally:
                verifier.os.dup = original_dup
                verifier.write_private_manifest = original_write_manifest
            expected_notes = (
                (
                    "APT transaction manifest cleanup found the published manifest "
                    "namespace changed",
                )
                if case.endswith("replacement")
                else ()
            )
            expected = (
                "haptics APT manifest preparation failed: cannot preserve "
                "APT transaction manifest release rollback ownership"
                + "".join(
                    "\nhaptics APT manifest preparation failed cleanup: " + note
                    for note in expected_notes
                )
            )
            if caught is None or str(caught) != expected or output.getvalue():
                raise SystemExit(
                    f"APT manifest rollback-dup cleanup drifted: {case}: {caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT manifest rollback-dup fixture leaked a descriptor"
                    )
            if case.endswith("replacement"):
                if (
                    not release_manifest.exists()
                    or release_manifest.read_bytes() != replacement_raw
                ):
                    raise SystemExit(
                        "APT manifest rollback-dup cleanup removed replacement namespace"
                    )
                original_unlink(release_manifest)
            elif release_manifest.exists():
                raise SystemExit(
                    "APT manifest rollback-dup cleanup left its published inode"
                )

        for target_call in range(1, 6):
            release_manifest = private / f"applied-dup-{target_call}.tsv"
            owned_descriptors: list[int] = []
            duplicated_descriptors: list[int] = []
            dup_calls = 0
            cancellation = KeyboardInterrupt(
                f"injected applied manifest dup {target_call} cancellation"
            )

            def duplicate_then_cancel(descriptor: int) -> int:
                nonlocal dup_calls
                dup_calls += 1
                duplicated = original_dup(descriptor)
                duplicated_descriptors.append(duplicated)
                if dup_calls == target_call:
                    raise cancellation
                return duplicated

            def returning_applied_dup_manifest(*args, **kwargs):
                result = original_write_manifest(*args, **kwargs)
                if result is None or result.parent_descriptor is None:
                    raise SystemExit(
                        "APT manifest applied-dup fixture lost publication ownership"
                    )
                owned_descriptors.extend(
                    (result.descriptor, result.parent_descriptor)
                )
                verifier.os.dup = duplicate_then_cancel
                return result

            verifier.write_private_manifest = returning_applied_dup_manifest
            sys.argv = preparation_argv(release_manifest)
            output = io.StringIO()
            caught: BaseException | None = None
            try:
                with contextlib.redirect_stdout(output):
                    verifier.main()
            except BaseException as exc:
                caught = exc
            finally:
                verifier.os.dup = original_dup
                verifier.write_private_manifest = original_write_manifest
            if (
                caught is not cancellation
                or output.getvalue()
                or dup_calls != target_call
            ):
                raise SystemExit(
                    "APT manifest applied-dup cancellation drifted: "
                    f"call={target_call} caught={caught}"
                ) from caught
            for descriptor in owned_descriptors + duplicated_descriptors:
                try:
                    original_fstat(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise SystemExit(
                        "APT manifest applied-dup fixture leaked a descriptor"
                    )
            if release_manifest.exists():
                raise SystemExit(
                    "APT manifest applied-dup rollback left its published inode"
                )
    finally:
        sys.argv = original_argv
        verifier.os.fsync = original_fsync
        verifier.os.fstat = original_fstat
        verifier.os.dup = original_dup
        verifier.os.open = original_open
        verifier.os.close = original_close
        verifier.os.stat = original_stat
        verifier.os.unlink = original_unlink
        dpkg.read_regular = original_read_regular
        verifier.write_private_manifest = original_write_manifest
        verifier.prepare_expected_transaction = original_prepare
        verifier.enumerate_archive_paths = original_enumerate
        verifier.time.monotonic = original_monotonic
        verifier.capture_deb_archive = original_archive_capture
        verifier.load_dpkg_state_verifier = original_dpkg_loader
        verifier.load_package_verifier = original_package_loader


def verify_runtime_reference_mode(
    verifier,
    archive_path: pathlib.Path,
    archives: pathlib.Path,
    compat: pathlib.Path,
    private: pathlib.Path,
    hook_command: str,
    cli_archive,
) -> None:
    host_reference_path = private / "runtime-host-reference.tsv"
    manifest_path = private / "runtime-manifest.tsv"
    publication_sentinel = "runtime reference fixture reached manifest publication"

    def run_case(mode: str, host_reference_raw: bytes, configure=None):
        package = FakePackageVerifier()
        dpkg = FakeDpkgVerifier()
        if configure is not None:
            configure(dpkg)
        evidence = {
            private / "lock.tsv": b"lock\n",
            private / "package-state.tsv": b"package-state\n",
            private / "host.plan": b"plan\n",
            private / "dpkg-state.tsv": b"dpkg-state\n",
            host_reference_path: host_reference_raw,
            pathlib.Path("/var/lib/dpkg/status"): b"status\n",
        }
        archive_capture_count = 0
        enumeration_count = 0
        original_argv = sys.argv
        original_package_loader = verifier.load_package_verifier
        original_dpkg_loader = verifier.load_dpkg_state_verifier
        original_enumerate = verifier.enumerate_archive_paths
        original_archive_capture = verifier.capture_deb_archive
        original_manifest_writer = verifier.write_private_manifest
        original_read_regular = dpkg.read_regular

        def read_regular(path, mode_bits, uid, gid, maximum, label):
            raw = evidence.get(path)
            expected_mode = (
                0o644
                if path == pathlib.Path("/var/lib/dpkg/status")
                else 0o600
            )
            if (
                raw is None
                or mode_bits != expected_mode
                or (uid, gid) != (0, 0)
                or len(raw) > maximum
                or not label
            ):
                raise ValueError("wrong runtime-reference evidence read")
            return raw

        def enumerate_archives(directories, uid, gid, **kwargs):
            nonlocal enumeration_count
            if (
                directories != (archives, compat)
                or (uid, gid) != (0, 0)
                or not isinstance(kwargs.get("deadline"), float)
            ):
                raise ValueError("wrong runtime-reference archive enumeration")
            enumeration_count += 1
            return (archive_path,)

        def capture_archive(path, uid, gid, **kwargs):
            nonlocal archive_capture_count
            if (
                path != archive_path
                or (uid, gid) != (0, 0)
                or not isinstance(kwargs.get("deadline"), float)
            ):
                raise ValueError("wrong runtime-reference archive capture")
            archive_capture_count += 1
            return cli_archive

        def refuse_manifest_publication(path, raw, uid, gid, **kwargs):
            if (
                path != manifest_path
                or not raw
                or (uid, gid) != (0, 0)
                or not kwargs.get("retain_ownership")
                or kwargs.get("ownership_slot") is None
                or not isinstance(kwargs.get("deadline"), float)
            ):
                raise verifier.AptTransactionError(
                    "runtime reference fixture received invalid publication inputs"
                )
            raise verifier.AptTransactionError(publication_sentinel)

        dpkg.read_regular = read_regular
        verifier.load_package_verifier = lambda: package
        verifier.load_dpkg_state_verifier = lambda: dpkg
        verifier.enumerate_archive_paths = enumerate_archives
        verifier.capture_deb_archive = capture_archive
        verifier.write_private_manifest = refuse_manifest_publication
        sys.argv = [
            str(MODULE_PATH),
            mode,
            hook_command,
            str(private / "lock.tsv"),
            str(private / "package-state.tsv"),
            str(private / "host.plan"),
            str(private / "dpkg-state.tsv"),
            str(host_reference_path),
            str(archives),
            str(compat),
            str(manifest_path),
        ]
        output = io.StringIO()
        caught = None
        try:
            with contextlib.redirect_stdout(output):
                verifier.main()
        except SystemExit as exc:
            caught = exc
        finally:
            sys.argv = original_argv
            dpkg.read_regular = original_read_regular
            verifier.write_private_manifest = original_manifest_writer
            verifier.capture_deb_archive = original_archive_capture
            verifier.enumerate_archive_paths = original_enumerate
            verifier.load_dpkg_state_verifier = original_dpkg_loader
            verifier.load_package_verifier = original_package_loader
        if caught is None or output.getvalue():
            raise SystemExit(
                f"APT runtime-reference fixture did not fail closed: mode={mode}"
            )
        return (
            str(caught),
            package,
            dpkg,
            archive_capture_count,
            enumeration_count,
        )

    runtime_reference = b"host-reference\n"
    if (
        hashlib.sha256(runtime_reference).hexdigest()
        == verifier.EXPECTED_HOST_REFERENCE_SHA256
    ):
        raise SystemExit("APT runtime-reference fixture accidentally uses the trust anchor")
    message, package, dpkg, archive_count, enumeration_count = run_case(
        "--prepare-manifest", runtime_reference
    )
    if (
        "dpkg host reference differs from the committed trust anchor" not in message
        or package.capture_count
        or dpkg.parsed_host_reference_count
        or dpkg.capture_count
        or archive_count
        or enumeration_count
    ):
        raise SystemExit("APT committed-reference mode no longer enforces its trust anchor")

    message, package, dpkg, archive_count, enumeration_count = run_case(
        "--prepare-manifest-runtime-reference", runtime_reference
    )
    if (
        publication_sentinel not in message
        or not package.verified_plan
        or package.capture_count != 2
        or dpkg.parsed_host_reference_count != 1
        or dpkg.verified_host_count != 2
        or dpkg.serialized_host_reference_count != 2
        or dpkg.capture_count != 2
        or archive_count != 1
        or enumeration_count != 2
    ):
        raise SystemExit(
            "APT runtime-reference mode skipped parsing, live comparison, or race checks"
        )

    message, package, dpkg, archive_count, _ = run_case(
        "--prepare-manifest-runtime-reference", b"host-reference \n"
    )
    if (
        "cannot parse APT transaction preparation evidence: wrong host reference"
        not in message
        or dpkg.parsed_host_reference_count != 1
        or dpkg.capture_count
        or package.capture_count
        or archive_count
    ):
        raise SystemExit("APT runtime-reference mode accepted noncanonical reference bytes")

    def reject_live_reference(dpkg) -> None:
        def reject(state, reference):
            dpkg.verified_host_count += 1
            if state is not dpkg.state or reference is not dpkg.host:
                raise ValueError("runtime host comparison received different objects")
            raise ValueError("injected live host-reference mismatch")

        dpkg.verify_host_reference = reject

    message, _, dpkg, archive_count, _ = run_case(
        "--prepare-manifest-runtime-reference",
        runtime_reference,
        reject_live_reference,
    )
    if (
        "cannot verify dpkg preparation state: injected live host-reference mismatch"
        not in message
        or dpkg.verified_host_count != 1
        or dpkg.capture_count != 1
        or archive_count
    ):
        raise SystemExit("APT runtime-reference mode accepted live host-state drift")

    def drift_live_reference_bytes(dpkg) -> None:
        def serialize(reference):
            dpkg.serialized_host_reference_count += 1
            if reference is not dpkg.host:
                raise ValueError("wrong runtime host-reference object")
            return b"host-reference-drift\n"

        dpkg.serialize_host_reference = serialize

    message, _, dpkg, archive_count, _ = run_case(
        "--prepare-manifest-runtime-reference",
        runtime_reference,
        drift_live_reference_bytes,
    )
    if (
        "dpkg host reference bytes differ from the reviewed reference" not in message
        or dpkg.verified_host_count != 1
        or dpkg.serialized_host_reference_count != 1
        or dpkg.capture_count != 1
        or archive_count
    ):
        raise SystemExit("APT runtime-reference mode accepted non-exact live bytes")

    def drift_second_live_capture(dpkg) -> None:
        original_capture = dpkg.capture_dpkg_state

        def capture(admin, uid, gid):
            state = original_capture(admin, uid, gid)
            return state if dpkg.capture_count == 1 else object()

        dpkg.capture_dpkg_state = capture

    message, package, dpkg, archive_count, enumeration_count = run_case(
        "--prepare-manifest-runtime-reference",
        runtime_reference,
        drift_second_live_capture,
    )
    if (
        "cannot verify dpkg preparation state: dpkg state drift" not in message
        or package.capture_count != 2
        or dpkg.capture_count != 2
        or dpkg.verified_host_count != 1
        or archive_count != 1
        or enumeration_count != 1
    ):
        raise SystemExit("APT runtime-reference mode accepted a preparation race")


def main() -> None:
    verifier = load_module()
    committed_host_reference = SCRIPT_DIR / "HAPTICS-DPKG-HOST-REFERENCE.tsv"
    if not hasattr(verifier, "EXPECTED_HOST_REFERENCE_SHA256"):
        raise SystemExit("APT preparation host-reference trust anchor is missing")
    if (
        not committed_host_reference.is_file()
        or hashlib.sha256(committed_host_reference.read_bytes()).hexdigest()
        != verifier.EXPECTED_HOST_REFERENCE_SHA256
    ):
        raise SystemExit("committed dpkg host reference differs from its trust anchor")
    if not hasattr(verifier, "verify_host_reference_trust_anchor"):
        raise SystemExit("APT host-reference trust-anchor verifier is missing")
    committed_reference_raw = committed_host_reference.read_bytes()
    verifier.verify_host_reference_trust_anchor(committed_reference_raw)
    drifted_reference = bytearray(committed_reference_raw)
    drifted_reference[-2] = ord("0") if drifted_reference[-2] != ord("0") else ord("1")
    require_rejected(
        verifier,
        lambda: verifier.verify_host_reference_trust_anchor(bytes(drifted_reference)),
        "committed host-reference digest drift",
        "dpkg host reference differs from the committed trust anchor",
    )
    if not hasattr(verifier, "prepare_expected_transaction"):
        raise SystemExit("APT transaction preparation interface is missing")
    package = FakePackageVerifier()
    dpkg = FakeDpkgVerifier()
    archive = verifier.ArchiveRecord(
        "/tmp/cache/example_1.0-1_amd64.deb",
        1,
        2,
        0o644,
        0,
        0,
        1,
        123,
        "4" * 64,
        "example",
        "1.0-1",
        "amd64",
        "no",
    )
    original_package_loader = verifier.load_package_verifier
    original_dpkg_loader = verifier.load_dpkg_state_verifier
    original_archive_capture = verifier.capture_deb_archive
    verifier.load_package_verifier = lambda: package
    verifier.load_dpkg_state_verifier = lambda: dpkg
    verifier.capture_deb_archive = lambda path, uid, gid, **kwargs: (
        archive
        if path == pathlib.Path(archive.path) and (uid, gid) == (0, 0)
        else (_ for _ in ()).throw(ValueError("wrong archive capture inputs"))
    )
    try:
        transaction = verifier.prepare_expected_transaction(
            "/usr/bin/python3 -I -B /tmp/private/verify-haptics-apt-transaction.py "
            "--verify-hook /tmp/private/expected.tsv /tmp/private/hook.ok",
            b"lock\n",
            b"package-state\n",
            b"plan\n",
            b"dpkg-state\n",
            b"host-reference\n",
            b"status\n",
            (pathlib.Path(archive.path),),
            pathlib.Path("/tmp/dpkg-admin"),
            0,
            0,
        )
    finally:
        verifier.capture_deb_archive = original_archive_capture
        verifier.load_dpkg_state_verifier = original_dpkg_loader
        verifier.load_package_verifier = original_package_loader
    if not package.verified_plan or not dpkg.verified_host:
        raise SystemExit("APT preparation skipped plan or host-reference verification")
    if package.capture_count != 2 or dpkg.capture_count != 2:
        raise SystemExit("APT preparation did not bracket archives with both state captures")
    if (
        len(package.capture_deadlines) != 2
        or package.capture_deadlines[0] != package.capture_deadlines[1]
    ):
        raise SystemExit("APT preparation did not reuse one package capture deadline")
    if transaction.package_state_sha256 != hashlib.sha256(b"package-state\n").hexdigest():
        raise SystemExit("APT preparation changed the package-state digest")
    if transaction.dpkg_state_sha256 != hashlib.sha256(b"dpkg-state\n").hexdigest():
        raise SystemExit("APT preparation changed the dpkg-state digest")
    if transaction.host_reference_sha256 != hashlib.sha256(b"host-reference\n").hexdigest():
        raise SystemExit("APT preparation changed the host-reference digest")
    if len(transaction.actions) != 2 or transaction.archives != (archive,):
        raise SystemExit("APT preparation changed action/archive closure")
    deadline_clock = [0.0]
    original_monotonic = verifier.time.monotonic
    verifier.load_package_verifier = lambda: package
    verifier.load_dpkg_state_verifier = lambda: dpkg

    def deadline_archive_capture(path, uid, gid, **kwargs):
        if path != pathlib.Path(archive.path) or (uid, gid) != (0, 0):
            raise ValueError("wrong deadline archive capture inputs")
        deadline_clock[0] = 301.0
        return archive

    verifier.capture_deb_archive = deadline_archive_capture
    verifier.time.monotonic = lambda: deadline_clock[0]
    try:
        require_rejected(
            verifier,
            lambda: verifier.prepare_expected_transaction(
                "/usr/bin/python3 -I -B /tmp/private/verify-haptics-apt-transaction.py "
                "--verify-hook /tmp/private/expected.tsv /tmp/private/hook.ok",
                b"lock\n",
                b"package-state\n",
                b"plan\n",
                b"dpkg-state\n",
                b"host-reference\n",
                b"status\n",
                (pathlib.Path(archive.path),),
                pathlib.Path("/tmp/dpkg-admin"),
                0,
                0,
            ),
            "aggregate preparation deadline",
            "APT transaction preparation exceeded its deadline",
        )
    finally:
        verifier.time.monotonic = original_monotonic
        verifier.capture_deb_archive = original_archive_capture
        verifier.load_dpkg_state_verifier = original_dpkg_loader
        verifier.load_package_verifier = original_package_loader
    original_capture_system_state = package.capture_system_state
    verifier.load_package_verifier = lambda: package
    verifier.load_dpkg_state_verifier = lambda: dpkg
    try:
        for label, injected in (
            (
                "package-state capture timeout",
                subprocess.TimeoutExpired(["injected package capture"], 1),
            ),
            (
                "package-state subprocess failure",
                subprocess.SubprocessError("injected package capture failure"),
            ),
            ("package-state operating-system failure", OSError("injected package capture")),
        ):
            package.capture_system_state = lambda failure=injected, **kwargs: (
                (_ for _ in ()).throw(failure)
            )
            require_rejected(
                verifier,
                lambda: verifier.prepare_expected_transaction(
                    "/usr/bin/python3 -I -B /tmp/private/verify-haptics-apt-transaction.py "
                    "--verify-hook /tmp/private/expected.tsv /tmp/private/hook.ok",
                    b"lock\n",
                    b"package-state\n",
                    b"plan\n",
                    b"dpkg-state\n",
                    b"host-reference\n",
                    b"status\n",
                    (pathlib.Path(archive.path),),
                    pathlib.Path("/tmp/dpkg-admin"),
                    0,
                    0,
                ),
                label,
                "cannot capture package preparation state",
                exact=True,
            )
    finally:
        package.capture_system_state = original_capture_system_state
        verifier.load_dpkg_state_verifier = original_dpkg_loader
        verifier.load_package_verifier = original_package_loader
    if not hasattr(verifier, "verify_post_transaction"):
        raise SystemExit("APT post-transaction verification interface is missing")
    original_dpkg_loader = verifier.load_dpkg_state_verifier
    verifier.load_dpkg_state_verifier = lambda: dpkg
    try:
        verifier.verify_post_transaction(
            verifier.serialize_expected_transaction(transaction),
            b"dpkg-state\n",
            pathlib.Path("/tmp/dpkg-admin"),
            0,
            0,
        )
    finally:
        verifier.load_dpkg_state_verifier = original_dpkg_loader
    if not dpkg.verified_post:
        raise SystemExit("APT post-transaction verification skipped dpkg policy")
    for interface in ("enumerate_archive_paths", "write_private_manifest"):
        if not hasattr(verifier, interface):
            raise SystemExit(f"APT preparation filesystem interface is missing: {interface}")
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-apt-preparation.") as raw:
        root = pathlib.Path(raw)
        archives = root / "cache/archives"
        compat = root / "compat"
        private = root / "private"
        for directory, mode in ((archives, 0o755), (compat, 0o755), (private, 0o700)):
            directory.mkdir(parents=True)
            directory.chmod(mode)
        first = archives / "first_1.0-1_amd64.deb"
        second = compat / "second_1.0-1_amd64.deb"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        first.chmod(0o644)
        second.chmod(0o644)
        expected_paths = tuple(sorted((first, second), key=str))
        actual_paths = verifier.enumerate_archive_paths(
            (archives, compat), os.getuid(), os.getgid()
        )
        if actual_paths != expected_paths:
            raise SystemExit("APT preparation changed the closed archive path set")
        hostile = archives / "hostile_1.0-1_amd64.deb"
        hostile.symlink_to(first.name)
        require_rejected(
            verifier,
            lambda: verifier.enumerate_archive_paths(
                (archives, compat), os.getuid(), os.getgid()
            ),
            "archive symlink",
            "APT archive directory contains an unsafe DEB entry",
        )
        hostile.unlink()
        first.chmod(0o600)
        try:
            require_rejected(
                verifier,
                lambda: verifier.enumerate_archive_paths(
                    (archives, compat), os.getuid(), os.getgid()
                ),
                "archive mode drift",
                "APT archive directory contains an unsafe DEB entry",
            )
        finally:
            first.chmod(0o644)
        hardlink = archives / "hardlink_1.0-1_amd64.deb"
        os.link(first, hardlink)
        try:
            require_rejected(
                verifier,
                lambda: verifier.enumerate_archive_paths(
                    (archives, compat), os.getuid(), os.getgid()
                ),
                "hard-linked archive",
                "APT archive directory contains an unsafe DEB entry",
            )
        finally:
            hardlink.unlink()
        archives.chmod(0o700)
        try:
            require_rejected(
                verifier,
                lambda: verifier.enumerate_archive_paths(
                    (archives, compat), os.getuid(), os.getgid()
                ),
                "archive directory mode drift",
                "APT archive directory metadata differs from policy",
            )
        finally:
            archives.chmod(0o755)
        manifest_path = private / "expected.tsv"
        manifest_raw = verifier.serialize_expected_transaction(transaction)
        direct_publication = verifier.write_private_manifest(
            manifest_path, manifest_raw, os.getuid(), os.getgid()
        )
        if direct_publication is not None:
            raise SystemExit("APT manifest direct writer retained hidden ownership")
        metadata = manifest_path.stat()
        if (
            manifest_path.read_bytes() != manifest_raw
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getgid()
            or metadata.st_nlink != 1
        ):
            raise SystemExit("APT preparation wrote an unsafe private manifest")
        require_rejected(
            verifier,
            lambda: verifier.write_private_manifest(
                manifest_path, manifest_raw, os.getuid(), os.getgid()
            ),
            "pre-existing manifest",
            "cannot create private APT transaction manifest",
        )
        private.chmod(0o755)
        unsafe_parent_manifest = private / "unsafe-parent.tsv"
        try:
            require_rejected(
                verifier,
                lambda: verifier.write_private_manifest(
                    unsafe_parent_manifest,
                    manifest_raw,
                    os.getuid(),
                    os.getgid(),
                ),
                "non-private manifest parent",
                "private APT transaction directory metadata differs from policy",
            )
        finally:
            private.chmod(0o700)
        if unsafe_parent_manifest.exists():
            raise SystemExit("APT preparation leaked a manifest under an unsafe parent")
        short_manifest = private / "short-write.tsv"
        original_write = verifier.os.write
        verifier.os.write = lambda descriptor, content: 0
        try:
            require_rejected(
                verifier,
                lambda: verifier.write_private_manifest(
                    short_manifest,
                    manifest_raw,
                    os.getuid(),
                    os.getgid(),
                ),
                "zero-progress manifest write",
                "private APT transaction manifest write made no progress",
            )
        finally:
            verifier.os.write = original_write
        if short_manifest.exists():
            raise SystemExit("APT preparation leaked a short manifest inode")
        close_failure_manifest = private / "close-failure.tsv"
        original_close = verifier.os.close
        original_write = verifier.os.write
        close_calls = 0

        def close_then_fail(descriptor: int) -> None:
            nonlocal close_calls
            original_close(descriptor)
            close_calls += 1
            if close_calls == 1:
                raise OSError("injected manifest close failure")

        verifier.os.write = lambda descriptor, content: 0
        verifier.os.close = close_then_fail
        try:
            require_rejected(
                verifier,
                lambda: verifier.write_private_manifest(
                    close_failure_manifest,
                    manifest_raw,
                    os.getuid(),
                    os.getgid(),
                ),
                "manifest close failure after a failed write",
                "private APT transaction manifest write made no progress",
            )
        finally:
            verifier.os.close = original_close
            verifier.os.write = original_write
        if close_failure_manifest.exists():
            raise SystemExit("APT preparation leaked a close-failed manifest inode")
        second.unlink()
        cli_archive = verifier.ArchiveRecord(
            str(first),
            archive.device,
            archive.inode,
            archive.mode,
            archive.uid,
            archive.gid,
            archive.nlink,
            archive.size,
            archive.sha256,
            archive.package,
            archive.version,
            archive.architecture,
            archive.multiarch,
        )
        evidence = {
            "lock.tsv": b"lock\n",
            "package-state.tsv": b"package-state\n",
            "host.plan": b"plan\n",
            "dpkg-state.tsv": b"dpkg-state\n",
            "host-reference.tsv": b"host-reference\n",
        }
        for name, content in evidence.items():
            path = private / name
            path.write_bytes(content)
            path.chmod(0o600)
        prepared_path = private / "prepared.tsv"
        marker_path = private / "prepared.ok"
        hook_command = (
            f"/usr/bin/python3 -I -B {MODULE_PATH} --verify-hook "
            f"{prepared_path} {marker_path}"
        )
        verify_runtime_reference_mode(
            verifier,
            first,
            archives,
            compat,
            private,
            hook_command,
            cli_archive,
        )
        verify_whole_preparation_deadline(
            verifier,
            package,
            dpkg,
            transaction,
            cli_archive,
            first,
            archives,
            compat,
            private,
            hook_command,
        )
        original_argv = sys.argv
        original_package_loader = verifier.load_package_verifier
        original_dpkg_loader = verifier.load_dpkg_state_verifier
        original_archive_capture = verifier.capture_deb_archive
        original_write_manifest = verifier.write_private_manifest
        successful_ownership: list[int] = []

        def recording_manifest_writer(*args, **kwargs):
            result = original_write_manifest(*args, **kwargs)
            if result is None or result.parent_descriptor is None:
                raise SystemExit(
                    "APT preparation main did not retain successful publication ownership"
                )
            successful_ownership.extend(
                (result.descriptor, result.parent_descriptor)
            )
            return result

        verifier.load_package_verifier = lambda: package
        verifier.load_dpkg_state_verifier = lambda: dpkg
        verifier.write_private_manifest = recording_manifest_writer
        verifier.capture_deb_archive = lambda path, uid, gid, **kwargs: (
            cli_archive
            if path == first and (uid, gid) == (os.getuid(), os.getgid())
            else (_ for _ in ()).throw(ValueError("wrong CLI archive capture inputs"))
        )
        sys.argv = [
            str(MODULE_PATH),
            "--prepare-manifest-disposable",
            "/tmp/dpkg-admin",
            str(os.getuid()),
            str(os.getgid()),
            hook_command,
            str(private / "lock.tsv"),
            str(private / "package-state.tsv"),
            str(private / "host.plan"),
            str(private / "dpkg-state.tsv"),
            str(private / "host-reference.tsv"),
            str(archives),
            str(compat),
            str(prepared_path),
        ]
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                verifier.main()
        finally:
            sys.argv = original_argv
            verifier.capture_deb_archive = original_archive_capture
            verifier.load_dpkg_state_verifier = original_dpkg_loader
            verifier.load_package_verifier = original_package_loader
            verifier.write_private_manifest = original_write_manifest
        if output.getvalue() != "HAPTICS_APT_MANIFEST=PASS\n":
            raise SystemExit("APT preparation CLI changed its success marker")
        for descriptor in successful_ownership:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise SystemExit(
                    "APT preparation main leaked successful publication ownership"
                )
        if verifier.parse_expected_transaction_bytes(prepared_path.read_bytes()).archives != (
            cli_archive,
        ):
            raise SystemExit("APT preparation CLI changed the archive closure")
        dpkg.verified_post = False
        original_argv = sys.argv
        original_dpkg_loader = verifier.load_dpkg_state_verifier
        verifier.load_dpkg_state_verifier = lambda: dpkg
        sys.argv = [
            str(MODULE_PATH),
            "--verify-post-disposable",
            "/tmp/dpkg-admin",
            str(os.getuid()),
            str(os.getgid()),
            str(prepared_path),
            str(private / "dpkg-state.tsv"),
        ]
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                verifier.main()
        finally:
            sys.argv = original_argv
            verifier.load_dpkg_state_verifier = original_dpkg_loader
        if output.getvalue() != "HAPTICS_APT_POST_STATE=PASS\n" or not dpkg.verified_post:
            raise SystemExit("APT post-state CLI skipped the exact dpkg policy")
    print("HAPTICS_APT_PREPARATION_FIXTURE=PASS")


if __name__ == "__main__":
    main()
