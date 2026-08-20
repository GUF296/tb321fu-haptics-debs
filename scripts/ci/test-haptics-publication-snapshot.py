#!/usr/bin/env python3
"""Hostile fixtures for immutable haptics publication snapshots."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile
import time


SCRIPT = pathlib.Path(__file__).with_name("snapshot-haptics-publication-stage.py")
SPEC = importlib.util.spec_from_file_location("snapshot_haptics_publication_stage", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load haptics publication snapshotter")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SNAPSHOT
SPEC.loader.exec_module(SNAPSHOT)

VERSION = "20260730.2"
ARCHIVE = f"tb321fu-haptics-debs_{VERSION}_arm64.tar.gz"
ASSETS = (
    "BUILD-PARAMETERS.md",
    "HAPTICS-SOURCE-LOCK.tsv",
    "SHA256SUMS-tb321fu-haptics-debs.txt",
    "SHA256SUMS.txt",
    ARCHIVE,
)


def make_source(path: pathlib.Path, marker: str = "trusted") -> None:
    path.mkdir(mode=0o755)
    for name in ASSETS:
        asset = path / name
        asset.write_text(f"{marker} {name}\n", encoding="ascii")
        asset.chmod(0o644)


def require_failure(function, expected: str) -> None:
    try:
        function()
    except SNAPSHOT.SnapshotError as exc:
        if expected not in str(exc):
            raise SystemExit(f"snapshot fixture failed at the wrong boundary: {exc}") from exc
    else:
        raise SystemExit(f"snapshot fixture unexpectedly succeeded: expected {expected}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-publication-snapshot.") as temp:
        root = pathlib.Path(temp)
        canonical = root / "canonical"
        make_source(canonical)
        destination = root / "snapshot"
        SNAPSHOT.snapshot(canonical, canonical / "BUILD-PARAMETERS.md", VERSION, destination)
        if tuple(sorted(path.name for path in destination.iterdir())) != tuple(sorted(ASSETS)):
            raise SystemExit("canonical snapshot has the wrong asset set")
        for name in ASSETS:
            if (destination / name).read_bytes() != (canonical / name).read_bytes():
                raise SystemExit(f"canonical snapshot differs: {name}")
            if (destination / name).stat().st_mode & 0o777 != 0o644:
                raise SystemExit(f"canonical snapshot mode differs: {name}")

        extra = root / "extra"
        make_source(extra)
        for index in range(100):
            (extra / f"extra-{index:03d}").write_text("extra\n", encoding="ascii")
        original_scandir = SNAPSHOT.os.scandir
        yielded = 0

        class CountingScandir:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *arguments):
                return self.wrapped.__exit__(*arguments)

            def __iter__(self):
                return self

            def __next__(self):
                nonlocal yielded
                entry = next(self.wrapped)
                yielded += 1
                return entry

        SNAPSHOT.os.scandir = lambda descriptor: CountingScandir(
            original_scandir(descriptor)
        )
        try:
            require_failure(
                lambda: SNAPSHOT.snapshot(
                    extra, extra / "BUILD-PARAMETERS.md", VERSION, root / "extra-output"
                ),
                "more than five entries",
            )
        finally:
            SNAPSHOT.os.scandir = original_scandir
        if yielded != 6:
            raise SystemExit(f"publication directory enumeration was not early-bounded: {yielded}")

        symlink_source = root / "symlink-source"
        make_source(symlink_source)
        (symlink_source / ARCHIVE).unlink()
        (symlink_source / ARCHIVE).symlink_to("HAPTICS-SOURCE-LOCK.tsv")
        require_failure(
            lambda: SNAPSHOT.snapshot(
                symlink_source,
                symlink_source / "BUILD-PARAMETERS.md",
                VERSION,
                root / "symlink-output",
            ),
            "cannot open publication asset",
        )

        fifo_source = root / "fifo-source"
        make_source(fifo_source)
        (fifo_source / ARCHIVE).unlink()
        os.mkfifo(fifo_source / ARCHIVE)
        require_failure(
            lambda: SNAPSHOT.snapshot(
                fifo_source,
                fifo_source / "BUILD-PARAMETERS.md",
                VERSION,
                root / "fifo-output",
            ),
            "not regular",
        )

        mode_source = root / "mode-source"
        make_source(mode_source)
        (mode_source / ARCHIVE).chmod(0o600)
        require_failure(
            lambda: SNAPSHOT.snapshot(
                mode_source,
                mode_source / "BUILD-PARAMETERS.md",
                VERSION,
                root / "mode-output",
            ),
            "mode is not 0644",
        )

        size_source = root / "size-source"
        make_source(size_source)
        previous_maximum = SNAPSHOT.MAX_ARCHIVE_BYTES
        SNAPSHOT.MAX_ARCHIVE_BYTES = 4
        try:
            require_failure(
                lambda: SNAPSHOT.snapshot(
                    size_source,
                    size_source / "BUILD-PARAMETERS.md",
                    VERSION,
                    root / "size-output",
                ),
                "exceeds its size limit",
            )
        finally:
            SNAPSHOT.MAX_ARCHIVE_BYTES = previous_maximum

        wrong_notes = root / "wrong-notes.md"
        wrong_notes.write_text("untrusted notes\n", encoding="ascii")
        wrong_notes.chmod(0o644)
        require_failure(
            lambda: SNAPSHOT.snapshot(
                canonical, wrong_notes, VERSION, root / "notes-output"
            ),
            "notes are not the stage",
        )

        exchange = root / "exchange"
        replacement = root / "replacement"
        displaced = root / "displaced"
        make_source(exchange, "trusted")
        make_source(replacement, "malicious")
        original_copy = SNAPSHOT.copy_regular
        exchanged = False

        def exchange_after_first(*arguments, **keywords):
            nonlocal exchanged
            result = original_copy(*arguments, **keywords)
            if not exchanged:
                exchange.rename(displaced)
                replacement.rename(exchange)
                exchanged = True
            return result

        SNAPSHOT.copy_regular = exchange_after_first
        try:
            require_failure(
                lambda: SNAPSHOT.snapshot(
                    exchange,
                    exchange / "BUILD-PARAMETERS.md",
                    VERSION,
                    root / "exchange-output",
                ),
                "changed while it was copied",
            )
        finally:
            SNAPSHOT.copy_regular = original_copy
        if not exchanged:
            raise SystemExit("directory-exchange fixture did not run")

        replace_source = root / "replace-source"
        make_source(replace_source)
        original_copy = SNAPSHOT.copy_regular
        replaced = False

        def replace_future_asset(*arguments, **keywords):
            nonlocal replaced
            result = original_copy(*arguments, **keywords)
            if not replaced:
                time.sleep(0.01)
                target = replace_source / ARCHIVE
                replacement_file = replace_source / f"{ARCHIVE}.new"
                replacement_file.write_text("replacement archive\n", encoding="ascii")
                replacement_file.chmod(0o644)
                replacement_file.replace(target)
                replaced = True
            return result

        SNAPSHOT.copy_regular = replace_future_asset
        try:
            require_failure(
                lambda: SNAPSHOT.snapshot(
                    replace_source,
                    replace_source / "BUILD-PARAMETERS.md",
                    VERSION,
                    root / "replace-output",
                ),
                "changed while it was copied",
            )
        finally:
            SNAPSHOT.copy_regular = original_copy

    print("HAPTICS_PUBLICATION_SNAPSHOT=PASS")


if __name__ == "__main__":
    main()
