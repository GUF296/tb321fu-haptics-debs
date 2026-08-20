#!/usr/bin/env python3
"""Hostile fixtures for the haptics payload reference profile."""

from __future__ import annotations

import importlib.util
import pathlib
import os
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VERIFIER = SCRIPT_DIR / "verify-haptics-release-reference.py"
REFERENCE = SCRIPT_DIR / "HAPTICS-RELEASE-REFERENCE.tsv"
SPEC = importlib.util.spec_from_file_location("verify_haptics_release_reference", VERIFIER)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load haptics release reference verifier")
REFERENCE_VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE_VERIFIER)


def run(path: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require_failure(path: pathlib.Path, data: bytes, expected: bytes) -> None:
    path.write_bytes(data)
    result = run(path)
    if result.returncode == 0 or expected not in result.stderr:
        raise SystemExit(
            f"reference fixture did not fail at {expected!r}: {result.stderr!r}"
        )


def main() -> None:
    canonical = REFERENCE.read_bytes()
    result = run(REFERENCE, "--emit-tsv")
    if result.returncode or result.stdout != canonical:
        raise SystemExit(f"canonical release reference failed: {result.stderr!r}")
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-reference.") as temp:
        root = pathlib.Path(temp)
        candidate = root / "reference.tsv"
        result = run(candidate)
        if result.returncode == 0 or b"cannot open reference" not in result.stderr:
            raise SystemExit("missing release reference was accepted")
        require_failure(candidate, canonical[:-1], b"end with LF")
        require_failure(candidate, canonical.replace(b"\n", b"\r\n"), b"NUL/CR-free")
        require_failure(
            candidate,
            canonical.replace(b"package-version\t", b"package-version\tbad\x00", 1),
            b"NUL/CR-free",
        )
        require_failure(
            candidate,
            canonical.replace(b"package-version\t", b"package-version\t\xff", 1),
            b"ASCII only",
        )
        require_failure(candidate, canonical + b"extra\tfield\n", b"fields, expected")
        require_failure(
            candidate,
            b"".join(canonical.splitlines(keepends=True)[:-1]),
            b"fields, expected",
        )
        lines = canonical.splitlines(keepends=True)
        reordered = lines.copy()
        reordered[1], reordered[2] = reordered[2], reordered[1]
        require_failure(candidate, b"".join(reordered), b"invalid reference field 2")
        require_failure(
            candidate,
            canonical.replace(b"reference-producer-commit\t", b"schema\t", 1),
            b"invalid reference field 2",
        )
        require_failure(
            candidate,
            canonical.replace(b"schema\t", b"schema\textra\t", 1),
            b"must contain one tab",
        )
        require_failure(
            candidate,
            canonical.replace(b"haptics-deb-sha256\t", b"haptics-deb-sha256\tnot-a-digest", 1),
            b"invalid reference field",
        )
        require_failure(
            candidate,
            canonical + b"x" * REFERENCE_VERIFIER.MAX_BYTES,
            b"bounded regular file",
        )
        exact_boundary = b"x" * (REFERENCE_VERIFIER.MAX_BYTES - 1) + b"\n"
        candidate.write_bytes(exact_boundary)
        result = run(candidate)
        if result.returncode == 0 or b"bounded regular file" in result.stderr:
            raise SystemExit("exact release-reference byte boundary was rejected as oversized")
        require_failure(
            candidate,
            exact_boundary + b"x",
            b"bounded regular file",
        )

        candidate.write_bytes(canonical)
        original_fstat = REFERENCE_VERIFIER.os.fstat
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

        REFERENCE_VERIFIER.os.fstat = changed_fstat
        try:
            REFERENCE_VERIFIER.parse_reference(candidate)
        except REFERENCE_VERIFIER.ReferenceError as exc:
            if "changed while it was read" not in str(exc):
                raise SystemExit(f"wrong reference race rejection: {exc}") from exc
        else:
            raise SystemExit("release reference identity drift while reading was accepted")
        finally:
            REFERENCE_VERIFIER.os.fstat = original_fstat
        target = root / "target.tsv"
        target.write_bytes(canonical)
        link = root / "link.tsv"
        link.symlink_to(target)
        result = run(link)
        if result.returncode == 0 or b"cannot open reference" not in result.stderr:
            raise SystemExit("symlink release reference was accepted")
        fifo = root / "fifo.tsv"
        os.mkfifo(fifo)
        result = run(fifo)
        if result.returncode == 0 or b"bounded regular file" not in result.stderr:
            raise SystemExit("FIFO release reference was accepted")
    print("HAPTICS_RELEASE_REFERENCE=PASS")


if __name__ == "__main__":
    main()
