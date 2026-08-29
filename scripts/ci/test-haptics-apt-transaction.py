#!/usr/bin/env python3
"""Hostile fixtures for the APT EIPP v3 transaction boundary."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"
HOOK_COMMAND = (
    "/usr/bin/python3 -I -B /tmp/private/verify-haptics-apt-transaction.py "
    "--verify-hook /tmp/private/expected.tsv /tmp/private/hook.ok"
)
ENCODED_HOOK_COMMAND = HOOK_COMMAND.replace(" ", "%20")
HOOK_TOOL = "/usr/bin/python3"
VALID_EIPP_V3 = (
    "VERSION 3\n"
    "APT::Architecture=amd64\n"
    "APT::Architectures::=amd64\n"
    "Dir::Bin::dpkg=/usr/bin/dpkg\n"
    "DPkg::ConfigurePending=1\n"
    "DPkg::Path=/usr/sbin:/usr/bin:/sbin:/bin\n"
    f"DPkg::Pre-Install-Pkgs::={ENCODED_HOOK_COMMAND}\n"
    "DPkg::Run-Directory=/\n"
    f"DPkg::Tools::options::{HOOK_TOOL}::InfoFD=21\n"
    f"DPkg::Tools::options::{HOOK_TOOL}::Version=3\n"
    "\n"
    "example - - none < 1.0-1 amd64 none /tmp/private/example_1.0-1_amd64.deb\n"
    "example - - none < 1.0-1 amd64 none **CONFIGURE**\n"
).encode("ascii")
EXPECTED_CONFIGURATION = (
    ("APT::Architecture", "amd64"),
    ("APT::Architectures::", "amd64"),
    ("DPkg::ConfigurePending", "1"),
    ("DPkg::Path", "/usr/sbin:/usr/bin:/sbin:/bin"),
    ("DPkg::Pre-Install-Pkgs::", HOOK_COMMAND),
    ("DPkg::Run-Directory", "/"),
    (f"DPkg::Tools::options::{HOOK_TOOL}::InfoFD", "21"),
    (f"DPkg::Tools::options::{HOOK_TOOL}::Version", "3"),
    ("Dir::Bin::dpkg", "/usr/bin/dpkg"),
)


def load_module():
    if not MODULE_PATH.is_file():
        raise SystemExit("APT transaction verifier is missing")
    spec = importlib.util.spec_from_file_location("haptics_apt_transaction", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT transaction verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_rejected(
    verifier,
    callback,
    label: str,
    expected: str,
    *,
    exact: bool = False,
) -> None:
    if not expected:
        raise SystemExit(f"empty rejection boundary for hostile fixture: {label}")
    try:
        callback()
    except verifier.AptTransactionError as exc:
        diagnostic = str(exc)
        wrong_boundary = diagnostic != expected if exact else expected not in diagnostic
        if wrong_boundary:
            raise SystemExit(
                f"APT transaction verifier rejected {label} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"APT transaction verifier raised an unexpected exception for {label}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"APT transaction verifier accepted hostile fixture: {label}")


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
                    f"APT transaction rejection oracle failed unclearly: {exc}"
                ) from exc
            continue
        raise SystemExit(
            "APT transaction rejection oracle swallowed "
            f"{type(sentinel).__name__}"
        )


def verify_eipp_read_deadline(verifier) -> None:
    try:
        saved = os.dup(21)
    except OSError:
        saved = -1
    read_descriptor, write_descriptor = os.pipe()
    try:
        os.write(write_descriptor, b"VERSION 3\n")
        os.dup2(read_descriptor, 21)
        started = time.monotonic()
        require_rejected(
            verifier,
            lambda: verifier.read_eipp_hook_fd(
                timeout=verifier.EIPP_READ_TIMEOUT_SECONDS,
                deadline=started + 0.05,
            ),
            "EIPP writer retaining its pipe",
            "APT EIPP hook stream read timed out",
            exact=True,
        )
        if time.monotonic() - started > 1:
            raise SystemExit("APT EIPP hook read exceeded its outer watchdog")
    finally:
        os.close(read_descriptor)
        os.close(write_descriptor)
        if saved >= 0:
            os.dup2(saved, 21)
            os.close(saved)
        else:
            try:
                os.close(21)
            except OSError:
                pass


def verify_version_comparison_deadline(verifier) -> None:
    original_bounded_command = verifier._bounded_command
    original_monotonic = verifier.time.monotonic
    calls: list[float] = []

    def bounded_command(arguments, label, **kwargs):
        if arguments[0:2] != ["/usr/bin/dpkg", "--compare-versions"]:
            raise SystemExit("version deadline fixture received the wrong command")
        if label != "dpkg version comparison":
            raise SystemExit("version deadline fixture received the wrong label")
        calls.append(kwargs["timeout"])
        return 0, b"", b""

    verifier._bounded_command = bounded_command
    verifier.time.monotonic = lambda: 99.0
    try:
        direction = verifier.debian_version_direction("1.0-1", "2.0-1", deadline=100.0)
    finally:
        verifier.time.monotonic = original_monotonic
        verifier._bounded_command = original_bounded_command
    if direction != "<" or calls != [1.0]:
        raise SystemExit(
            f"version comparison did not consume the outer deadline: {calls!r}"
        )
    for label, invalid_deadline in (
        ("boolean", True),
        ("NaN", float("nan")),
        ("infinite", float("inf")),
    ):
        require_rejected(
            verifier,
            lambda invalid_deadline=invalid_deadline: verifier.debian_version_direction(
                "1.0-1", "2.0-1", deadline=invalid_deadline
            ),
            f"version comparison {label} deadline",
            "APT transaction preparation deadline is invalid",
            exact=True,
        )
    verifier.time.monotonic = lambda: 99.0
    try:
        for label, invalid_deadline, expected in (
            (
                "equal-version boolean",
                True,
                "APT transaction preparation deadline is invalid",
            ),
            (
                "equal-version NaN",
                float("nan"),
                "APT transaction preparation deadline is invalid",
            ),
            (
                "equal-version infinite",
                float("inf"),
                "APT transaction preparation deadline is invalid",
            ),
            (
                "equal-version expired",
                98.0,
                "APT transaction preparation exceeded its deadline",
            ),
        ):
            require_rejected(
                verifier,
                lambda invalid_deadline=invalid_deadline: (
                    verifier.debian_version_direction(
                        "1.0-1", "1.0-1", deadline=invalid_deadline
                    )
                ),
                f"version comparison {label} deadline",
                expected,
                exact=True,
            )
    finally:
        verifier.time.monotonic = original_monotonic


def verify_descriptor_cleanup(verifier) -> None:
    if not hasattr(verifier, "close_descriptors"):
        raise SystemExit("APT transaction verifier has no shared descriptor cleanup")
    original_close = verifier.os.close
    calls: list[int] = []

    def failing_close(descriptor: int) -> None:
        calls.append(descriptor)
        raise OSError(f"close failure {descriptor}")

    verifier.os.close = failing_close
    primary = verifier.AptTransactionError("primary policy failure")
    try:
        verifier.close_descriptors((101, 102), "fixture", primary)
        if calls != [101, 102]:
            raise SystemExit(f"descriptor cleanup skipped a close: {calls!r}")
        if getattr(primary, "__notes__", []) != [
            "fixture cleanup failed for descriptor 101: OSError: close failure 101",
            "fixture cleanup failed for descriptor 102: OSError: close failure 102",
        ]:
            raise SystemExit("descriptor cleanup did not annotate the primary failure")
        calls.clear()
        require_rejected(
            verifier,
            lambda: verifier.close_descriptors((201, 202), "fixture", None),
            "descriptor cleanup without a primary failure",
            "cannot close fixture descriptors",
            exact=True,
        )
        if calls != [201, 202]:
            raise SystemExit("descriptor cleanup stopped after its first close failure")
    finally:
        verifier.os.close = original_close


def verify_disposable_hook_path_binding(verifier) -> None:
    """Ensure disposable hook argv cannot name a different manifest/marker."""
    script = pathlib.Path(verifier.__file__).resolve()
    admin = pathlib.Path("/tmp/dpkg")
    manifest = pathlib.Path("/tmp/caller/expected.tsv")
    marker = pathlib.Path("/tmp/caller/hook.ok")
    command = (
        f"/usr/bin/python3 -I -B {script} --verify-hook-disposable "
        f"{admin} 0 0 /tmp/other/expected.tsv /tmp/other/hook.ok"
    )
    require_rejected(
        verifier,
        lambda: verifier.validate_runtime_hook_binding(
            command,
            manifest_path=manifest,
            marker_path=marker,
            dpkg_admin=admin,
            expected_uid=0,
            expected_gid=0,
            disposable=True,
        ),
        "disposable hook manifest/marker substitution",
        "APT runtime hook command is not bound to its disposable paths",
        exact=True,
    )
    good_command = (
        f"/usr/bin/python3 -I -B {script} --verify-hook-disposable "
        f"{admin} 0 0 {manifest} {marker}"
    )
    verifier.validate_runtime_hook_binding(
        good_command,
        manifest_path=manifest,
        marker_path=marker,
        dpkg_admin=admin,
        expected_uid=0,
        expected_gid=0,
        disposable=True,
    )


def verify_disposable_dpkg_option_policy(verifier) -> None:
    """Bind disposable dpkg options to the private status/admin layout."""
    root = pathlib.PurePosixPath("/tmp/eipp-disposable")
    admin = root / "var/lib/dpkg"
    status = admin / "status"
    private_paths = (("Dir::State::status", str(status)),)
    required_runtime = dict(verifier.RUNTIME_REQUIRED_CONFIGURATION)
    base_configuration = tuple(
        record
        for record in EXPECTED_CONFIGURATION
        if record[0] != "DPkg::Pre-Install-Pkgs::"
    )
    capture_command = (
        "/usr/bin/python3 -I -B /tmp/private/capture-eipp.py "
        "--capture /tmp/private/eipp.log"
    )
    capture_configuration = tuple(
        sorted(
            (
                *base_configuration,
                ("DPkg::Pre-Install-Pkgs::", capture_command),
                ("DPkg::Options::", f"--admindir={admin}"),
                ("DPkg::Options::", f"--root={root}"),
            )
        )
    )
    verifier.validate_expected_configuration_policy(
        capture_configuration,
        required_runtime=required_runtime,
        private_paths=dict(private_paths),
    )
    capture_actual = tuple(
        sorted(
            (
                *capture_configuration,
                *tuple(required_runtime.items()),
                *private_paths,
            )
        )
    )
    verifier.verify_eipp_configuration(
        capture_actual,
        capture_configuration,
        enforce_runtime_projection=True,
        required_paths=private_paths,
    )

    script = pathlib.Path(verifier.__file__).resolve()
    disposable_command = (
        f"/usr/bin/python3 -I -B {script} --verify-hook-disposable "
        f"{admin} 0 0 {root}/transaction/expected.tsv "
        f"{root}/transaction/hook.ok"
    )
    disposable_configuration = tuple(
        sorted(
            (
                *base_configuration,
                ("DPkg::Pre-Install-Pkgs::", disposable_command),
                ("DPkg::Options::", f"--admindir={admin}"),
                ("DPkg::Options::", f"--root={root}"),
            )
        )
    )
    verifier.validate_expected_configuration_policy(
        disposable_configuration,
        required_runtime=required_runtime,
        private_paths=dict(private_paths),
    )

    def reject_policy(
        label: str,
        configuration: tuple[tuple[str, str], ...],
        paths: tuple[tuple[str, str], ...] = private_paths,
        expected: str = "expected EIPP dpkg root and admindir options are not bound to private paths",
    ) -> None:
        require_rejected(
            verifier,
            lambda: verifier.validate_expected_configuration_policy(
                configuration,
                required_runtime=required_runtime,
                private_paths=dict(paths),
            ),
            label,
            expected,
            exact=True,
        )

    reject_policy(
        "capture missing disposable status path",
        capture_configuration,
        (),
        "expected EIPP configuration has no private dpkg status path",
    )
    reject_policy(
        "capture root option mismatch",
        tuple(
            sorted(
                record
                if record != ("DPkg::Options::", f"--root={root}")
                else ("DPkg::Options::", "--root=/tmp/eipp-disposable-wrong-root")
                for record in capture_configuration
            )
        ),
    )
    reject_policy(
        "capture admindir option mismatch",
        tuple(
            sorted(
                record
                if record != ("DPkg::Options::", f"--admindir={admin}")
                else ("DPkg::Options::", "--admindir=/tmp/eipp-other/var/lib/dpkg")
                for record in capture_configuration
            )
        ),
    )
    reject_policy(
        "capture status outside dpkg layout",
        capture_configuration,
        (("Dir::State::status", "/tmp/eipp-disposable/state/status"),),
    )
    reject_policy(
        "capture noncanonical status path",
        capture_configuration,
        (("Dir::State::status", "/tmp/eipp-disposable/var/lib/dpkg/../status"),),
        "expected EIPP configuration has no private dpkg status path",
    )
    reject_policy(
        "capture duplicate disposable option",
        tuple(
            sorted(
                (*capture_configuration, ("DPkg::Options::", f"--root={root}"))
            )
        ),
    )
    reject_policy(
        "production hook disposable options",
        tuple(
            sorted(
                (
                    *base_configuration,
                    ("DPkg::Pre-Install-Pkgs::", HOOK_COMMAND),
                    ("DPkg::Options::", f"--admindir={admin}"),
                    ("DPkg::Options::", f"--root={root}"),
                )
            )
        ),
        expected="expected EIPP configuration contains disposable dpkg options",
    )
    reject_policy(
        "disposable hook admindir mismatch",
        tuple(
            sorted(
                (
                    (
                        record[0],
                        disposable_command.replace(
                            str(admin), "/tmp/eipp-other/var/lib/dpkg"
                        ),
                    )
                    if record == ("DPkg::Pre-Install-Pkgs::", disposable_command)
                    else record
                )
                for record in disposable_configuration
            )
        ),
        expected="expected EIPP dpkg admindir option differs from the disposable hook",
    )


def verify_bounded_command_high_fd(verifier) -> None:
    """Exercise the production command path with descriptors above FD_SETSIZE."""
    descriptors: list[int] = []
    try:
        while max(descriptors, default=-1) < 1100:
            descriptors.append(os.open("/dev/null", os.O_RDONLY))
        returncode, stdout, stderr = verifier._bounded_command(
            ["/bin/sh", "-c", "printf ok"],
            "high-fd fixture",
            env={"PATH": "/usr/bin:/bin"},
            timeout=2.0,
            max_stdout=64,
            max_stderr=64,
        )
    except BaseException as exc:
        raise SystemExit(
            f"bounded command failed with a legal high descriptor: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (returncode, stdout, stderr) != (0, b"ok", b""):
        raise SystemExit(
            f"bounded command high-fd result changed: {returncode!r}, "
            f"{stdout!r}, {stderr!r}"
        )


def run_cli(*arguments: str, environment: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(MODULE_PATH), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        env=environment
        or {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": "/nonexistent",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )


def main() -> None:
    missing_hook_fd = run_cli(
        "--verify-hook",
        "/tmp/private/expected.tsv",
        "/tmp/private/hook.ok",
    )
    if (
        missing_hook_fd.returncode == 0
        or b"APT_HOOK_INFO_FD must be exactly 21" not in missing_hook_fd.stderr
    ):
        raise SystemExit("APT hook CLI did not reject a missing exact InfoFD")
    verifier = load_module()
    prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier)
    verify_eipp_read_deadline(verifier)
    verify_version_comparison_deadline(verifier)
    verify_descriptor_cleanup(verifier)
    verify_disposable_hook_path_binding(verifier)
    verify_disposable_dpkg_option_policy(verifier)
    verify_bounded_command_high_fd(verifier)
    original_bounded_command = verifier._bounded_command
    verifier._bounded_command = lambda *args, **kwargs: (_ for _ in ()).throw(
        subprocess.TimeoutExpired(["injected dpkg comparison"], 1)
    )
    try:
        require_rejected(
            verifier,
            lambda: verifier.debian_version_direction("1.0-1", "2.0-1"),
            "dpkg version comparison timeout",
            "dpkg version comparison timed out",
            exact=True,
        )
    finally:
        verifier._bounded_command = original_bounded_command
    if not hasattr(verifier, "expected_hook_configuration"):
        raise SystemExit("expected APT hook configuration builder is missing")
    if verifier.expected_hook_configuration(HOOK_COMMAND) != EXPECTED_CONFIGURATION:
        raise SystemExit("expected APT hook configuration builder changed exact keys")
    require_rejected(
        verifier,
        lambda: verifier.expected_hook_configuration(HOOK_COMMAND + "\n/bin/true"),
        "hook command newline injection",
        "APT hook command is not canonical",
        exact=True,
    )
    require_rejected(
        verifier,
        lambda: verifier.expected_hook_configuration(
            HOOK_COMMAND.replace("/tmp/private", "//tmp/private")
        ),
        "hook command double-slash root alias",
        "APT hook command is not canonical",
        exact=True,
    )
    document = verifier.parse_eipp_v3_bytes(VALID_EIPP_V3)
    if document.configuration != EXPECTED_CONFIGURATION:
        raise SystemExit("EIPP v3 parser changed the canonical configuration")
    if not hasattr(verifier, "verify_eipp_configuration"):
        raise SystemExit("EIPP v3 configuration verifier is missing")
    verifier.verify_eipp_configuration(document.configuration, EXPECTED_CONFIGURATION)
    benign_defaults = verifier.parse_eipp_v3_bytes(
        VALID_EIPP_V3.replace(
            b"\n\n",
            b"\nAPT::Color=0\nDir::Bin::methods=/usr/lib/apt/methods\n\n",
            1,
        )
    )
    verifier.verify_eipp_configuration(
        benign_defaults.configuration,
        EXPECTED_CONFIGURATION,
    )
    verifier.validate_runtime_command_line(
        "/usr/bin/apt-get -qq -y install --no-install-recommends "
        "--allow-downgrades --no-remove -- example=1.0-1 "
        "/tmp/private/example_1.0-1_amd64.deb"
    )
    for label, command in (
        (
            "executable prefix alias",
            "/usr/bin/apt-get-evil -y install --no-install-recommends "
            "--no-remove -- example=1.0-1",
        ),
        (
            "option assignment bypass",
            "/usr/bin/apt-get -y install --no-install-recommends "
            "--no-remove --remove=example -- example=1.0-1",
        ),
        (
            "short config override",
            "/usr/bin/apt-get -c APT::Get::AllowUnauthenticated=1 -y install "
            "--no-install-recommends --allow-downgrades --no-remove -- "
            "example=1.0-1",
        ),
        (
            "config-file override",
            "/usr/bin/apt-get --config-file=/tmp/evil.conf -y install "
            "--no-install-recommends --allow-downgrades --no-remove -- "
            "example=1.0-1",
        ),
        (
            "long option override",
            "/usr/bin/apt-get --option APT::Get::AllowUnauthenticated=1 -y install "
            "--no-install-recommends --allow-downgrades --no-remove -- "
            "example=1.0-1",
        ),
        (
            "unknown install option",
            "/usr/bin/apt-get -y install --allow-unauthenticated "
            "--no-install-recommends --no-remove -- example=1.0-1",
        ),
        (
            "missing downgrade policy",
            "/usr/bin/apt-get -y install --no-install-recommends "
            "--no-remove -- example=1.0-1",
        ),
        (
            "unpinned package",
            "/usr/bin/apt-get -y install --no-install-recommends "
            "--no-remove -- example",
        ),
        (
            "noncanonical local archive",
            "/usr/bin/apt-get -y install --no-install-recommends "
            "--no-remove -- /tmp/private/../example.deb",
        ),
    ):
        require_rejected(
            verifier,
            lambda command=command: verifier.validate_runtime_command_line(command),
            label,
            "effective APT configuration differs from the exact contract",
        )
    for label, record in (
        ("manifest-side force option", ("DPkg::Options::", "--force-all")),
        (
            "manifest-side insecure policy",
            ("APT::Get::AllowUnauthenticated", "1"),
        ),
        (
            "manifest-side source redirection",
            ("Dir::Etc::sourcelist", "/etc/apt/sources.list"),
        ),
        (
            "manifest-side extra hook tool",
            ("DPkg::Tools::options::/bin/evil::InfoFD", "21"),
        ),
    ):
        hostile_expected = tuple(sorted((*EXPECTED_CONFIGURATION, record)))
        require_rejected(
            verifier,
            lambda hostile_expected=hostile_expected: verifier.verify_eipp_configuration(
                hostile_expected,
                hostile_expected,
            ),
            label,
            "expected EIPP configuration",
        )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_configuration(
            EXPECTED_CONFIGURATION,
            EXPECTED_CONFIGURATION,
            enforce_runtime_projection=True,
        ),
        "production hook without transaction layout",
        "production hook does not identify its private transaction layout",
        exact=False,
    )
    runtime_hook_command = (
        f"/usr/bin/python3 -I -B {MODULE_PATH} --verify-hook "
        "/tmp/runtime/transaction/expected.tsv "
        "/tmp/runtime/transaction/hook.ok"
    )
    runtime_expected = verifier.expected_hook_configuration(runtime_hook_command)
    runtime_paths = verifier.runtime_private_path_projection(runtime_expected)
    if not runtime_paths:
        raise SystemExit("runtime APT path projection is empty")
    verifier.validate_runtime_hook_binding(
        runtime_hook_command,
        manifest_path=pathlib.Path("/tmp/runtime/transaction/expected.tsv"),
        marker_path=pathlib.Path("/tmp/runtime/transaction/hook.ok"),
        dpkg_admin=pathlib.Path("/var/lib/dpkg"),
        expected_uid=0,
        expected_gid=0,
        disposable=False,
    )
    require_rejected(
        verifier,
        lambda: verifier.validate_runtime_hook_binding(
            runtime_hook_command.replace(
                str(MODULE_PATH),
                "/tmp/runtime/other/verify-haptics-apt-transaction.py",
            ),
            manifest_path=pathlib.Path("/tmp/runtime/transaction/expected.tsv"),
            marker_path=pathlib.Path("/tmp/runtime/transaction/hook.ok"),
            dpkg_admin=pathlib.Path("/var/lib/dpkg"),
            expected_uid=0,
            expected_gid=0,
            disposable=False,
        ),
        "same-basename replacement verifier",
        "APT runtime hook command does not identify the executing verifier",
        exact=True,
    )
    require_rejected(
        verifier,
        lambda: verifier.validate_runtime_hook_binding(
            runtime_hook_command.replace("expected.tsv", "other.tsv"),
            manifest_path=pathlib.Path("/tmp/runtime/transaction/other.tsv"),
            marker_path=pathlib.Path("/tmp/runtime/transaction/hook.ok"),
            dpkg_admin=pathlib.Path("/var/lib/dpkg"),
            expected_uid=0,
            expected_gid=0,
            disposable=False,
        ),
        "arbitrary production manifest name",
        "APT runtime hook paths are not canonical",
        exact=True,
    )
    safe_command_line = (
        "/usr/bin/apt-get -y install --no-install-recommends "
        "--allow-downgrades --no-remove -- example=1.0-1 "
        "/tmp/runtime/compat/example_1.0-1_amd64.deb"
    )
    runtime_actual = tuple(
        sorted(
            (
                *runtime_expected,
                *tuple(verifier.RUNTIME_REQUIRED_CONFIGURATION.items()),
                *runtime_paths,
                ("APT::Color", "0"),
                ("Binary", "apt-get"),
                ("CommandLine::AsString", safe_command_line),
                ("Dir", "/"),
                ("quiet", "1"),
            )
        )
    )
    verifier.verify_eipp_configuration(
        runtime_actual,
        runtime_expected,
        enforce_runtime_projection=True,
    )

    def add_runtime_record(key: str, value: str):
        return tuple(sorted((*runtime_actual, (key, value))))

    def replace_runtime_record(
        key: str,
        old_value: str,
        new_value: str,
    ):
        old_record = (key, old_value)
        if runtime_actual.count(old_record) != 1:
            raise SystemExit(f"runtime fixture cannot replace {key}")
        return tuple(
            sorted(
                (key, new_value) if record == old_record else record
                for record in runtime_actual
            )
        )

    def remove_runtime_record(key: str, value: str):
        record = (key, value)
        if runtime_actual.count(record) != 1:
            raise SystemExit(f"runtime fixture cannot remove {key}")
        return tuple(item for item in runtime_actual if item != record)

    runtime_hostile_configurations = (
        (
            "extra APT architecture",
            add_runtime_record("APT::Architectures::", "arm64"),
        ),
        (
            "APT architecture namespace drift",
            add_runtime_record("APT::Architecture::Native", "arm64"),
        ),
        (
            "substituted APT helper binary",
            add_runtime_record("Dir::Bin::evil", "/bin/true"),
        ),
        (
            "substituted dpkg helper child",
            add_runtime_record("Dir::Bin::dpkg::evil", "/bin/true"),
        ),
        (
            "custom TLS CA",
            add_runtime_record("Acquire::https::CaInfo", "/tmp/evil-ca.pem"),
        ),
        (
            "forced TLS version",
            add_runtime_record("Acquire::https::SslForceVersion", "TLSv1.0"),
        ),
        (
            "proxy auto detection",
            add_runtime_record("Acquire::http::Proxy-Auto-Detect", "/bin/true"),
        ),
        (
            "remove-essential policy",
            add_runtime_record("APT::Get::Allow-Remove-Essential", "1"),
        ),
        (
            "APT command-line override",
            replace_runtime_record(
                "CommandLine::AsString",
                safe_command_line,
                safe_command_line.replace(
                    "-y install",
                    "-o APT::Get::AllowUnauthenticated=1 -y install",
                ),
            ),
        ),
        (
            "missing TLS verification policy",
            remove_runtime_record("Acquire::https::Verify-Peer", "1"),
        ),
        (
            "private archive path drift",
            replace_runtime_record(
                "Dir::Cache::archives",
                "/tmp/runtime/cache/archives",
                "/var/cache/apt/archives",
            ),
        ),
        (
            "duplicate allowed default",
            add_runtime_record("APT::Color", "0"),
        ),
        (
            "production quiet-level drift",
            replace_runtime_record("quiet", "1", "2"),
        ),
    )
    for label, hostile_configuration in runtime_hostile_configurations:
        require_rejected(
            verifier,
            lambda hostile_configuration=hostile_configuration: (
                verifier.verify_eipp_configuration(
                    hostile_configuration,
                    runtime_expected,
                    enforce_runtime_projection=True,
                )
            ),
            label,
            "effective APT configuration differs from the exact contract",
        )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_configuration((), ()),
        "missing manifest hook",
        "expected EIPP configuration has no unique hook",
        exact=True,
    )
    if not all(
        hasattr(verifier, name)
        for name in (
            "ExpectedTransaction",
            "ArchiveRecord",
            "serialize_expected_transaction",
            "parse_expected_transaction_bytes",
        )
    ):
        raise SystemExit("expected APT transaction manifest interface is missing")
    archive_record = verifier.ArchiveRecord(
        "/tmp/private/example_1.0-1_amd64.deb",
        1,
        2,
        0o644,
        0,
        0,
        1,
        123,
        "1" * 64,
        "example",
        "1.0-1",
        "amd64",
        "no",
    )
    if not all(
        hasattr(verifier, name)
        for name in ("PlannedChange", "build_expected_actions")
    ):
        raise SystemExit("expected APT action builder interface is missing")
    initial_actions = verifier.build_expected_actions(
        (
            verifier.PlannedChange(
                "example",
                "amd64",
                None,
                "1.0-1",
            ),
        ),
        {},
        (archive_record,),
    )
    if initial_actions != document.actions:
        raise SystemExit("expected action builder changed initial-install semantics")
    upgrade_archive = verifier.ArchiveRecord(
        "/tmp/private/upgrade_1.0-1_amd64.deb",
        1,
        3,
        0o644,
        0,
        0,
        1,
        124,
        "4" * 64,
        "upgrade",
        "1.0-1",
        "amd64",
        "no",
    )
    downgrade_archive = verifier.ArchiveRecord(
        "/tmp/private/downgrade_1.0-1_amd64.deb",
        1,
        4,
        0o644,
        0,
        0,
        1,
        125,
        "5" * 64,
        "downgrade",
        "1.0-1",
        "amd64",
        "no",
    )
    changed_actions = verifier.build_expected_actions(
        (
            verifier.PlannedChange("downgrade", "amd64", "2.0-1", "1.0-1"),
            verifier.PlannedChange("upgrade", "amd64", "0.9-1", "1.0-1"),
        ),
        {
            ("downgrade", "amd64"): (
                "2.0-1",
                "install ok installed",
                "same",
            ),
            ("upgrade", "amd64"): (
                "0.9-1",
                "hold ok installed",
                "no",
            ),
        },
        (downgrade_archive, upgrade_archive),
    )
    unpack_changes = {
        action.package: (
            action.direction,
            action.old_multiarch,
            action.new_multiarch,
        )
        for action in changed_actions
        if action.action != "**CONFIGURE**"
    }
    if unpack_changes != {
        "downgrade": (">", "same", "no"),
        "upgrade": ("<", "no", "no"),
    }:
        raise SystemExit(
            f"expected action builder changed version directions: {unpack_changes!r}"
        )
    noop_archive = verifier.ArchiveRecord(
        "/tmp/private/compat-noop_1.0-1_amd64.deb",
        1,
        5,
        0o644,
        0,
        0,
        1,
        126,
        "6" * 64,
        "compat-noop",
        "1.0-1",
        "amd64",
        "no",
    )
    noop_actions = verifier.build_expected_actions(
        (verifier.PlannedChange("example", "amd64", None, "1.0-1"),),
        {
            ("compat-noop", "amd64"): (
                "1.0-1",
                "install ok installed",
                "no",
            )
        },
        (archive_record, noop_archive),
        allowed_noop_archives=frozenset({("compat-noop", "amd64")}),
    )
    if noop_actions != document.actions:
        raise SystemExit(
            "action builder failed to exclude an already-installed compat archive"
        )
    require_rejected(
        verifier,
        lambda: verifier.build_expected_actions(
            (verifier.PlannedChange("example", "amd64", None, "1.0-1"),),
            {},
            (archive_record, noop_archive),
            allowed_noop_archives=frozenset({("compat-noop", "amd64")}),
        ),
        "compat archive without matching installed package",
        "no-op compatibility archive differs from installed status",
        exact=True,
    )
    expected_transaction = verifier.ExpectedTransaction(
        "1" * 64,
        "2" * 64,
        "3" * 64,
        document.configuration,
        document.actions,
        (archive_record,),
    )
    manifest = verifier.serialize_expected_transaction(expected_transaction)
    if b"package-state-sha256\t" + b"1" * 64 + b"\n" not in manifest:
        raise SystemExit("expected APT transaction manifest lacks package-state binding")
    expected_action_prefix = b"action\texample\t-\t-\tnone\t<\t1.0-1\tamd64\tno\t"
    if manifest.count(expected_action_prefix) != 2:
        raise SystemExit("expected APT transaction manifest changed absent identity encoding")
    if verifier.parse_expected_transaction_bytes(manifest) != expected_transaction:
        raise SystemExit("expected APT transaction manifest did not round-trip exactly")
    bulk_archives = tuple(
        verifier.ArchiveRecord(
            f"/tmp/private/bulk{index:02d}_1.0-1_amd64.deb",
            1,
            100 + index,
            0o644,
            0,
            0,
            1,
            64 * 1024 * 1024,
            f"{index + 1:064x}",
            f"bulk{index:02d}",
            "1.0-1",
            "amd64",
            "no",
        )
        for index in range(33)
    )
    bulk_actions = tuple(
        action
        for archive in bulk_archives
        for action in (
            verifier.PackageAction(
                archive.package,
                None,
                None,
                None,
                "<",
                archive.version,
                archive.architecture,
                archive.multiarch,
                archive.path,
            ),
            verifier.PackageAction(
                archive.package,
                None,
                None,
                None,
                "<",
                archive.version,
                archive.architecture,
                archive.multiarch,
                "**CONFIGURE**",
            ),
        )
    )
    require_rejected(
        verifier,
        lambda: verifier.serialize_expected_transaction(
            verifier.ExpectedTransaction(
                "1" * 64,
                "2" * 64,
                "3" * 64,
                document.configuration,
                bulk_actions,
                bulk_archives,
            )
        ),
        "aggregate archive bytes above 2 GiB",
        "expected transaction archive set exceeds its aggregate size bound",
        exact=True,
    )
    bounded_bulk_transaction = verifier.ExpectedTransaction(
        "1" * 64,
        "2" * 64,
        "3" * 64,
        document.configuration,
        bulk_actions[:64],
        bulk_archives[:32],
    )
    bounded_bulk_manifest = verifier.serialize_expected_transaction(
        bounded_bulk_transaction
    )
    if (
        verifier.parse_expected_transaction_bytes(bounded_bulk_manifest)
        != bounded_bulk_transaction
    ):
        raise SystemExit("2 GiB aggregate archive boundary did not round-trip")
    for label, separator in (
        ("VT", b"\v"),
        ("FF", b"\f"),
        ("FS", b"\x1c"),
        ("GS", b"\x1d"),
        ("RS", b"\x1e"),
    ):
        require_rejected(
            verifier,
            lambda separator=separator: verifier.parse_expected_transaction_bytes(
                manifest.replace(b"\n", separator, 1)
            ),
            f"expected transaction {label} line separator",
            "expected transaction manifest has invalid framing",
            exact=True,
        )
    nonsemantic_actions = tuple(
        verifier.PackageAction(
            action.package,
            action.old_version,
            action.old_architecture,
            action.old_multiarch,
            action.direction,
            action.new_version,
            action.new_architecture,
            "none",
            action.action,
        )
        for action in document.actions
    )
    require_rejected(
        verifier,
        lambda: verifier.serialize_expected_transaction(
            verifier.ExpectedTransaction(
                expected_transaction.package_state_sha256,
                expected_transaction.dpkg_state_sha256,
                expected_transaction.host_reference_sha256,
                expected_transaction.configuration,
                nonsemantic_actions,
                expected_transaction.archives,
            )
        ),
        "semantic manifest present Multi-Arch none alias",
        "EIPP semantic action identity is invalid",
    )
    invalid_package_action = verifier.PackageAction(
        1,
        None,
        None,
        None,
        "<",
        "1.0-1",
        "amd64",
        "no",
        "/tmp/private/example_1.0-1_amd64.deb",
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_actions(
            (invalid_package_action,), (invalid_package_action,)
        ),
        "non-string semantic action package",
        "EIPP action closure contains an invalid package",
    )
    unhashable_package_action = verifier.PackageAction(
        [],
        None,
        None,
        None,
        "<",
        "1.0-1",
        "amd64",
        "no",
        "/tmp/private/example_1.0-1_amd64.deb",
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_actions(
            (unhashable_package_action,), (unhashable_package_action,)
        ),
        "unhashable semantic action package",
        "EIPP action closure contains an invalid package",
    )
    invalid_direction_action = verifier.PackageAction(
        "example",
        "0.9-1",
        "amd64",
        "no",
        7,
        "1.0-1",
        "amd64",
        "no",
        "/tmp/private/example_1.0-1_amd64.deb",
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_actions(
            (invalid_direction_action,), (invalid_direction_action,)
        ),
        "non-string semantic action direction",
        "EIPP semantic action direction is invalid",
    )
    class ConfigureAlias(str):
        pass

    configure_alias_action = verifier.PackageAction(
        "example",
        None,
        None,
        None,
        "<",
        "1.0-1",
        "amd64",
        "no",
        ConfigureAlias("**CONFIGURE**"),
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_actions(
            (configure_alias_action,), (configure_alias_action,)
        ),
        "semantic configure action string subclass",
        "EIPP semantic action target is invalid",
    )
    if len(document.actions) != 2:
        raise SystemExit("EIPP v3 parser lost an action")
    install, configure = document.actions
    if (
        install.package,
        install.old_version,
        install.old_architecture,
        install.old_multiarch,
        install.direction,
        install.new_version,
        install.new_architecture,
        install.new_multiarch,
        install.action,
    ) != (
        "example",
        None,
        None,
        None,
        "<",
        "1.0-1",
        "amd64",
        "no",
        "/tmp/private/example_1.0-1_amd64.deb",
    ):
        raise SystemExit("EIPP v3 parser changed the unpack action")
    if configure.action != "**CONFIGURE**":
        raise SystemExit("EIPP v3 parser lost the configure action")
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(
                b"1.0-1 amd64 none",
                b"1.0-1 amd64 no",
                1,
            )
        ),
        "present raw EIPP Multi-Arch no alias",
        "invalid new package identity",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_control_fields(
            b"Package: example\n"
            b"Version: 1.0-1\n"
            b"Architecture: amd64\n"
            b"Multi-Arch: none\n"
        ),
        "DEB control Multi-Arch none alias",
        "DEB control package identity is unsafe",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_control_fields(
            b"Package: example\v"
            b"Version: 1.0-1\n"
            b"Architecture: amd64\n"
        ),
        "DEB control vertical-tab field separator",
        "DEB control output has invalid framing",
    )
    lowercase_control = (
        b"package: example\n"
        b"version: 1.0-1\n"
        b"architecture: amd64\n"
        b"multi-arch: no\n"
    )
    if verifier.parse_control_fields(lowercase_control) != (
        "example",
        "1.0-1",
        "amd64",
        "no",
    ):
        raise SystemExit("DEB control lowercase identity changed")
    require_rejected(
        verifier,
        lambda: verifier.parse_control_fields(
            lowercase_control + b"description: ignored\n continued value\n"
        ),
        "DEB control unexpected field with legal SP continuation",
        "DEB control contains an unexpected field set",
        exact=True,
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_control_fields(
            lowercase_control.replace(
                b"package: example\n",
                b"Package: example\npackage: other\n",
                1,
            )
        ),
        "DEB control case-alias duplicate identity",
        "DEB control contains a malformed field",
        exact=True,
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_control_fields(
            lowercase_control + b"Bad\tName: ignored\n"
        ),
        "DEB control field name with embedded TAB",
        "DEB control contains a malformed field",
        exact=True,
    )
    for field in (b"package", b"version", b"architecture", b"multi-arch"):
        require_rejected(
            verifier,
            lambda field=field: verifier.parse_control_fields(
                lowercase_control.replace(field + b": ", field + b": \n folded", 1)
            ),
            f"DEB control folded {field.decode('ascii')}",
            "DEB control simple identity field must not be folded",
            exact=True,
        )
    if not hasattr(verifier, "verify_eipp_actions"):
        raise SystemExit("EIPP v3 action-set verifier is missing")
    verifier.verify_eipp_actions(document.actions, tuple(reversed(document.actions)))
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_actions(document.actions, document.actions[:-1]),
        "missing expected action",
        "EIPP actions differ from the exact transaction closure",
    )
    drifted_action_document = verifier.parse_eipp_v3_bytes(
        VALID_EIPP_V3.replace(b"1.0-1 amd64 none", b"1.0-1 arm64 none", 1)
    )
    require_rejected(
        verifier,
        lambda: verifier.verify_eipp_actions(
            drifted_action_document.actions, document.actions
        ),
        "action architecture drift",
        "EIPP actions differ from the exact transaction closure",
    )
    escaped = verifier.parse_eipp_v3_bytes(
        VALID_EIPP_V3.replace(
            b"\n\n",
            b"\nFixture::Key%3DName=value%0Aline%25\n\n",
            1,
        )
    )
    if ("Fixture::Key=Name", "value\nline%") not in escaped.configuration:
        raise SystemExit("EIPP v3 parser did not decode configuration escapes")
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(b"\n", b"\v", 1)
        ),
        "vertical-tab line separator",
        "EIPP stream contains a noncanonical raw byte",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nAPT::Architecture=amd64\n\n", 1
            )
        ),
        "duplicate scalar configuration key",
        "EIPP configuration repeats a scalar key",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(
                b"example - - none < 1.0-1",
                b"example - - none = 1.0-1",
                1,
            )
        ),
        "initial install with equality direction",
        "initial-install action has an invalid direction",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(
                b"example - - none < 1.0-1 amd64 none "
                b"/tmp/private/example_1.0-1_amd64.deb",
                b"example 1.0-1 amd64 none > - - none **REMOVE**",
                1,
            )
        ),
        "package removal action",
        "package removal is forbidden by the transaction policy",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(
                b"/tmp/private/example_1.0-1_amd64.deb",
                b"/tmp/private/../escape.deb",
                1,
            )
        ),
        "noncanonical archive path",
        "EIPP archive path is not canonical",
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(
                b"example - - none < 1.0-1",
                b"example - - - < 1.0-1",
                1,
            )
        ),
        "missing-version identity with legacy Multi-Arch hyphen",
        "missing old version has metadata",
    )
    unpack_line = (
        b"example - - none < 1.0-1 amd64 none "
        b"/tmp/private/example_1.0-1_amd64.deb\n"
    )
    require_rejected(
        verifier,
        lambda: verifier.parse_eipp_v3_bytes(
            VALID_EIPP_V3.replace(unpack_line, unpack_line + unpack_line, 1)
        ),
        "duplicate package action",
        "EIPP stream repeats a package action",
    )
    for label, hostile_configuration in (
        ("wrong InfoFD", VALID_EIPP_V3.replace(b"InfoFD=21", b"InfoFD=22", 1)),
        (
            "additional hook",
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nDPkg::Pre-Install-Pkgs::=/bin/true\n\n", 1
            ),
        ),
        (
            "dpkg option",
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nDPkg::Options::=--force-all\n\n", 1
            ),
        ),
        (
            "download proxy",
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nAcquire::http::Proxy=http://evil.invalid\n\n", 1
            ),
        ),
        (
            "private source redirection",
            VALID_EIPP_V3.replace(
                b"\n\n",
                b"\nDir::Etc::sourcelist=/etc/apt/sources.list\n\n",
                1,
            ),
        ),
        (
            "insecure package policy",
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nAPT::Get::AllowUnauthenticated=1\n\n", 1
            ),
        ),
        (
            "build-essential resolver drift",
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nAPT::Build-Essential::=evil-package\n\n", 1
            ),
        ),
        (
            "compression helper drift",
            VALID_EIPP_V3.replace(
                b"\n\n", b"\nAcquire::CompressionTypes::gz=evil\n\n", 1
            ),
        ),
        (
            "index target drift",
            VALID_EIPP_V3.replace(
                b"\n\n",
                b"\nAcquire::IndexTargets::deb::Packages::MetaKey=../../escape\n\n",
                1,
            ),
        ),
    ):
        hostile_document = verifier.parse_eipp_v3_bytes(hostile_configuration)
        require_rejected(
            verifier,
            lambda hostile_document=hostile_document: verifier.verify_eipp_configuration(
                hostile_document.configuration, EXPECTED_CONFIGURATION
            ),
            label,
            "effective APT configuration differs from the exact contract",
        )
    print("HAPTICS_APT_TRANSACTION_FIXTURE=PASS")


if __name__ == "__main__":
    main()
