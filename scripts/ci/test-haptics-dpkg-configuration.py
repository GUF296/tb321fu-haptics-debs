#!/usr/bin/env python3
"""Hostile fixtures for the native dpkg configuration boundary."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VERIFIER = SCRIPT_DIR / "verify-haptics-dpkg-configuration.py"
REVIEWED_CONFIG = b"""# dpkg configuration file
#
# This file can contain default options for dpkg.  All command-line
# options are allowed.  Values can be specified by putting them after
# the option, separated by whitespace and/or an `=' sign.
#

# Do not enable debsig-verify by default; since the distribution is not using
# embedded signatures, debsig-verify would reject all packages.
no-debsig

# Log status changes and actions to a file.
log /var/log/dpkg.log
"""


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "haptics_dpkg_configuration",
        VERIFIER,
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load dpkg configuration verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_valid_tree(parent: pathlib.Path, config: bytes = REVIEWED_CONFIG):
    config_dir = parent / "dpkg"
    parts = config_dir / "dpkg.cfg.d"
    home = parent / "home"
    parts.mkdir(parents=True)
    home.mkdir()
    parent.chmod(0o700)
    config_dir.chmod(0o755)
    parts.chmod(0o755)
    home.chmod(0o700)
    main_config = config_dir / "dpkg.cfg"
    main_config.write_bytes(config)
    main_config.chmod(0o644)
    return config_dir, parts, home, main_config


def require_module_rejected(verifier, callback, name: str, expected: str) -> None:
    try:
        callback()
    except (verifier.DpkgConfigurationError, OSError) as exc:
        if expected not in str(exc):
            raise SystemExit(
                f"dpkg configuration verifier rejected {name} at the wrong boundary: {exc}"
            ) from exc
    else:
        raise SystemExit(f"dpkg configuration verifier accepted hostile fixture: {name}")


def require_namespace_binding_oracles(verifier, root: pathlib.Path) -> None:
    direct_parent = root / "direct-replacement"
    config_dir, _, home, main_config = make_valid_tree(direct_parent)
    displaced_config = config_dir / "dpkg.cfg.displaced"
    original_read = verifier.os.read
    replaced = False

    def replace_config_after_bounded_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        raw = original_read(descriptor, size)
        if raw and not replaced:
            replaced = True
            main_config.rename(displaced_config)
            main_config.write_bytes(b"post-invoke=/bin/false\n")
            main_config.chmod(0o644)
        return raw

    verifier.os.read = replace_config_after_bounded_read
    try:
        require_module_rejected(
            verifier,
            lambda: verifier.verify(
                config_dir,
                home,
                os.getuid(),
                os.getgid(),
                os.getuid(),
                os.getgid(),
            ),
            "dpkg.cfg replacement after bounded read",
            "dpkg.cfg namespace changed while it was read",
        )
    finally:
        verifier.os.read = original_read
        if displaced_config.exists():
            main_config.unlink(missing_ok=True)
            displaced_config.rename(main_config)
    if not replaced:
        raise SystemExit("dpkg.cfg replacement oracle did not reach the bounded read")

    trusted_parent = root / "namespace-parent"
    alternate_parent = root / "namespace-parent-alternate"
    displaced_parent = root / "namespace-parent-displaced"
    config_dir, _, home, _ = make_valid_tree(trusted_parent)
    make_valid_tree(alternate_parent, b"post-invoke=/bin/false\n")
    original_pin_verifier = verifier.verify_reviewed_config_pin
    parent_replaced = False

    def replace_parent_before_final_namespace_check(pin) -> None:
        nonlocal parent_replaced
        original_pin_verifier(pin)
        if not parent_replaced:
            parent_replaced = True
            trusted_parent.rename(displaced_parent)
            alternate_parent.rename(trusted_parent)

    verifier.verify_reviewed_config_pin = replace_parent_before_final_namespace_check
    try:
        require_module_rejected(
            verifier,
            lambda: verifier.verify(
                config_dir,
                home,
                os.getuid(),
                os.getgid(),
                os.getuid(),
                os.getgid(),
            ),
            "dpkg configuration ancestor replacement",
            "namespace changed during verification",
        )
    finally:
        verifier.verify_reviewed_config_pin = original_pin_verifier
        if displaced_parent.exists():
            trusted_parent.rename(alternate_parent)
            displaced_parent.rename(trusted_parent)
    if not parent_replaced:
        raise SystemExit("dpkg configuration ancestor replacement oracle did not fire")

    real_parent = root / "real-ancestor"
    real_config, _, real_home, _ = make_valid_tree(real_parent)
    alias_parent = root / "alias-ancestor"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    require_module_rejected(
        verifier,
        lambda: verifier.verify(
            alias_parent / real_config.name,
            real_home,
            os.getuid(),
            os.getgid(),
            os.getuid(),
            os.getgid(),
        ),
        "dpkg configuration ancestor symlink",
        "Not a directory",
    )

    require_module_rejected(
        verifier,
        lambda: verifier.verify(
            root / "nul\x00ancestor" / "dpkg",
            real_home,
            os.getuid(),
            os.getgid(),
            os.getuid(),
            os.getgid(),
        ),
        "dpkg configuration NUL pathname",
        "path is not canonical",
    )


def run_verifier(config_dir: pathlib.Path, home: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(VERIFIER),
            "--expected-owner",
            str(os.getuid()),
            "--expected-group",
            str(os.getgid()),
            str(config_dir),
            str(home),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": str(home),
        },
    )


def require_rejected(result: subprocess.CompletedProcess[str], name: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"dpkg configuration verifier accepted hostile fixture: {name}")


def main() -> None:
    verifier = load_verifier()
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-dpkg-config-test.") as raw:
        root = pathlib.Path(raw)
        require_namespace_binding_oracles(verifier, root)
        config_dir = root / "dpkg"
        parts = config_dir / "dpkg.cfg.d"
        home = root / "home"
        parts.mkdir(parents=True)
        home.mkdir()
        config_dir.chmod(0o755)
        parts.chmod(0o755)
        home.chmod(0o700)
        main_config = config_dir / "dpkg.cfg"
        main_config.write_bytes(REVIEWED_CONFIG)
        main_config.chmod(0o644)
        metadata = main_config.stat()
        os.utime(main_config, ns=(0, metadata.st_mtime_ns))

        valid = run_verifier(config_dir, home)
        if valid.returncode:
            raise SystemExit(
                "valid dpkg configuration fixture was rejected: " + valid.stderr.strip()
            )

        original = main_config.read_bytes()
        main_config.write_bytes(original + b"pre-invoke=/bin/false\n")
        require_rejected(run_verifier(config_dir, home), "main hook")
        main_config.write_bytes(original)
        main_config.chmod(0o644)

        hostile_part = parts / "zz-hostile"
        hostile_part.write_text("path-exclude=/usr/bin/getconf\n", encoding="ascii")
        hostile_part.chmod(0o644)
        require_rejected(run_verifier(config_dir, home), "configuration part")
        hostile_part.unlink()

        user_config = home / ".dpkg.cfg"
        user_config.write_text("post-invoke=/bin/false\n", encoding="ascii")
        user_config.chmod(0o600)
        require_rejected(run_verifier(config_dir, home), "user configuration")
        user_config.unlink()

        main_config.chmod(0o600)
        require_rejected(run_verifier(config_dir, home), "main mode")
        main_config.chmod(0o644)

        replacement = root / "replacement.cfg"
        replacement.write_bytes(REVIEWED_CONFIG)
        replacement.chmod(0o644)
        main_config.unlink()
        main_config.symlink_to(replacement)
        require_rejected(run_verifier(config_dir, home), "main symlink")
        main_config.unlink()
        shutil.copyfile(replacement, main_config)
        main_config.chmod(0o644)

        parts.rmdir()
        parts.symlink_to(root)
        require_rejected(run_verifier(config_dir, home), "parts symlink")

    print("HAPTICS_DPKG_CONFIGURATION_FIXTURE=PASS")


if __name__ == "__main__":
    main()
