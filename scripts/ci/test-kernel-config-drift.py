#!/usr/bin/env python3
"""Hostile fixtures for bounded kernel config drift diagnostics."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile


REPORTER = pathlib.Path(__file__).with_name("report-kernel-config-drift.py")
SPEC = importlib.util.spec_from_file_location("report_kernel_config_drift", REPORTER)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load kernel config drift reporter")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def run(before: pathlib.Path, after: pathlib.Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", "-B", str(REPORTER), str(before), str(after)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )


def require_failure(
    before: pathlib.Path, after: pathlib.Path, expected: bytes
) -> None:
    result = run(before, after)
    if result.returncode == 0 or expected not in result.stderr:
        raise SystemExit(
            f"config diagnostic fixture did not fail at {expected!r}: "
            f"status={result.returncode} stderr={result.stderr!r}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-kconfig-drift-") as temporary:
        root = pathlib.Path(temporary)
        before = root / "before.config"
        after = root / "after.config"
        before.write_bytes(b"CONFIG_A=y\n# CONFIG_B is not set\n")
        after.write_bytes(b"CONFIG_A=y\nCONFIG_B=y\nCONFIG_C=m\n")
        result = run(before, after)
        if result.returncode or result.stderr:
            raise SystemExit(f"canonical config diagnostic failed: {result.stderr!r}")
        for expected in (
            b"KERNEL_CONFIG_DRIFT_DIAGNOSTIC=v1\n",
            b"--- verified-sdk/.config\n",
            b"+++ live-build/.config\n",
            b"-# CONFIG_B is not set\n",
            b"+CONFIG_B=y\n",
            b"+CONFIG_C=m\n",
            b"KERNEL_CONFIG_DRIFT_DIAGNOSTIC_END\n",
        ):
            if expected not in result.stdout:
                raise SystemExit(f"config diagnostic omitted {expected!r}")

        after.write_bytes(before.read_bytes())
        result = run(before, after)
        if (
            result.returncode
            or b"changed-baseline-lines=0\n" not in result.stdout
            or b"changed-live-lines=0\n" not in result.stdout
            or b"@@" in result.stdout
        ):
            raise SystemExit("identical config diagnostic is not empty")

        after.write_bytes(b"CONFIG_A=\x1b[31m\n")
        result = run(before, after)
        if result.returncode or b"\x1b" in result.stdout or b"\\x1b" not in result.stdout:
            raise SystemExit("config diagnostic emitted an unsafe terminal control byte")

        after.write_bytes(b"CONFIG_LONG=\"" + b"x" * 1024 + b"\"\n")
        result = run(before, after)
        if result.returncode or b"bytes omitted]" not in result.stdout:
            raise SystemExit("config diagnostic did not bound an individual line")

        before.write_bytes(
            b"".join(
                f"CONFIG_FIXTURE_{index:04d}=n\n".encode("ascii")
                for index in range(MODULE.MAX_DIFF_LINES + 64)
            )
        )
        after.write_bytes(before.read_bytes().replace(b"=n\n", b"=y\n"))
        result = run(before, after)
        if (
            result.returncode
            or b"diff-lines-emitted=160\n" not in result.stdout
            or b"diff-lines-omitted=0\n" in result.stdout
            or len(result.stdout) > 256 * 1024
        ):
            raise SystemExit("config diagnostic output bound was not enforced")

        oversized = root / "oversized.config"
        with oversized.open("wb") as stream:
            stream.truncate(MODULE.MAX_CONFIG_BYTES + 1)
        require_failure(before, oversized, b"not a bounded regular file")

        too_many_lines = root / "too-many-lines.config"
        too_many_lines.write_bytes(b"x\n" * (MODULE.MAX_CONFIG_LINES + 1))
        require_failure(before, too_many_lines, b"diagnostic line limit")

        target = root / "target.config"
        target.write_bytes(b"CONFIG_TARGET=y\n")
        link = root / "link.config"
        link.symlink_to(target)
        require_failure(before, link, b"not a bounded regular file")

        fifo = root / "fifo.config"
        os.mkfifo(fifo)
        require_failure(before, fifo, b"not a bounded regular file")

    print("KERNEL_CONFIG_DRIFT_DIAGNOSTIC=PASS")


if __name__ == "__main__":
    main()
