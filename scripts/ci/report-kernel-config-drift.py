#!/usr/bin/env python3
"""Emit a bounded, terminal-safe diff for a verified kernel config drift."""

from __future__ import annotations

import difflib
import hashlib
import os
import pathlib
import signal
import stat
import sys


MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_CONFIG_LINES = 65536
MAX_DIFF_LINES = 160
MAX_DISPLAY_LINE_BYTES = 256
DIAGNOSTIC_TIMEOUT_SECONDS = 5


class ConfigDiagnosticError(RuntimeError):
    """Raised when a config cannot be inspected safely."""


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _read_bounded_regular(path: pathlib.Path, label: str) -> bytes:
    descriptor = -1
    try:
        requested_before = path.lstat()
        if (
            not stat.S_ISREG(requested_before.st_mode)
            or requested_before.st_size > MAX_CONFIG_BYTES
        ):
            raise ConfigDiagnosticError(
                f"{label} is not a bounded regular file: {path}"
            )
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if (
            _identity(requested_before) != _identity(before)
            or before.st_size > MAX_CONFIG_BYTES
        ):
            raise ConfigDiagnosticError(
                f"{label} is not a bounded regular file: {path}"
            )
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        requested_after = path.lstat()
    except ConfigDiagnosticError:
        raise
    except OSError as exc:
        raise ConfigDiagnosticError(f"cannot inspect {label} {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        remaining == 0
        or len(raw) != before.st_size
        or _identity(before) != _identity(after)
        or _identity(requested_before) != _identity(requested_after)
    ):
        raise ConfigDiagnosticError(f"{label} changed while it was read: {path}")
    return raw


def _display_line(line: bytes) -> str:
    newline = line.endswith(b"\n")
    payload = line[:-1] if newline else line
    omitted = max(0, len(payload) - MAX_DISPLAY_LINE_BYTES)
    payload = payload[:MAX_DISPLAY_LINE_BYTES]
    rendered = "".join(
        chr(byte) if byte == 0x09 or 0x20 <= byte <= 0x7E else f"\\x{byte:02x}"
        for byte in payload
    )
    if omitted:
        rendered += f"...[{omitted} bytes omitted]"
    if not newline:
        rendered += " [no LF]"
    return rendered


def report(before_path: pathlib.Path, after_path: pathlib.Path) -> None:
    def timed_out(_signum: int, _frame: object) -> None:
        raise ConfigDiagnosticError("kernel config diagnostic exceeded its time limit")

    previous_handler = signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, DIAGNOSTIC_TIMEOUT_SECONDS)
    try:
        before = _read_bounded_regular(before_path, "verified config baseline")
        after = _read_bounded_regular(after_path, "live kernel config")
        before_lines = before.splitlines(keepends=True)
        after_lines = after.splitlines(keepends=True)
        if len(before_lines) > MAX_CONFIG_LINES or len(after_lines) > MAX_CONFIG_LINES:
            raise ConfigDiagnosticError("kernel config exceeds the diagnostic line limit")

        matcher = difflib.SequenceMatcher(
            None, before_lines, after_lines, autojunk=False
        )
        changed_before = 0
        changed_after = 0
        for operation, before_start, before_end, after_start, after_end in matcher.get_opcodes():
            if operation != "equal":
                changed_before += before_end - before_start
                changed_after += after_end - after_start

        emitted: list[str] = []
        omitted_lines = 0
        diff = difflib.diff_bytes(
            difflib.unified_diff,
            before_lines,
            after_lines,
            fromfile=b"verified-sdk/.config",
            tofile=b"live-build/.config",
            n=3,
            lineterm=b"\n",
        )
        for line in diff:
            if len(emitted) < MAX_DIFF_LINES:
                emitted.append(_display_line(line))
            else:
                omitted_lines += 1

        print("KERNEL_CONFIG_DRIFT_DIAGNOSTIC=v1")
        print(f"baseline-sha256={hashlib.sha256(before).hexdigest()}")
        print(f"live-sha256={hashlib.sha256(after).hexdigest()}")
        print(f"changed-baseline-lines={changed_before}")
        print(f"changed-live-lines={changed_after}")
        for line in emitted:
            print(line)
        print(f"diff-lines-emitted={len(emitted)}")
        print(f"diff-lines-omitted={omitted_lines}")
        print("KERNEL_CONFIG_DRIFT_DIAGNOSTIC_END")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: report-kernel-config-drift.py BASELINE_CONFIG LIVE_CONFIG"
        )
    try:
        report(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
    except ConfigDiagnosticError as exc:
        print(f"kernel config drift diagnostic unavailable: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
