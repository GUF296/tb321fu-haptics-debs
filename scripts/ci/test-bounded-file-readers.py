#!/usr/bin/env python3
"""Regression fixtures for descriptor-relative bounded file readers."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).parent


def load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SNAPSHOT = load(
    "bounded_snapshot_test_module",
    SCRIPT_DIR / "snapshot-bounded-regular-file.py",
)
PROVENANCE = load(
    "bounded_provenance_test_module",
    SCRIPT_DIR / "verify-haptics-release-provenance.py",
)


def require_failure(function, exception_type, label: str) -> None:
    try:
        function()
    except exception_type:
        return
    except Exception as exc:  # pragma: no cover - diagnostic path
        raise SystemExit(f"{label} failed at the wrong boundary: {exc}") from exc
    raise SystemExit(f"{label} unexpectedly succeeded")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tb321fu-bounded-readers.") as raw:
        root = pathlib.Path(raw)
        outside = root / "outside"
        outside.mkdir()
        source = outside / "source.tsv"
        source.write_text("trusted\n", encoding="ascii")
        source.chmod(0o644)

        snapshot_destination = root / "snapshot.tsv"
        SNAPSHOT.snapshot(source, snapshot_destination, 4096, 0o644)
        if snapshot_destination.read_text(encoding="ascii") != "trusted\n":
            raise SystemExit("canonical bounded snapshot changed the source bytes")

        source_alias = root / "source-alias"
        source_alias.symlink_to(outside, target_is_directory=True)
        require_failure(
            lambda: SNAPSHOT.snapshot(
                source_alias / "source.tsv", root / "source-alias-output", 4096, 0o644
            ),
            SNAPSHOT.SnapshotError,
            "source parent symlink",
        )

        destination_target = root / "destination-target"
        destination_target.mkdir()
        destination_alias = root / "destination-alias"
        destination_alias.symlink_to(destination_target, target_is_directory=True)
        require_failure(
            lambda: SNAPSHOT.snapshot(
                source, destination_alias / "copied.tsv", 4096, 0o644
            ),
            SNAPSHOT.SnapshotError,
            "destination parent symlink",
        )
        if (destination_target / "copied.tsv").exists():
            raise SystemExit("destination parent symlink fixture wrote outside its tree")

        provenance_root = root / "provenance"
        (provenance_root / "nested").mkdir(parents=True)
        member = provenance_root / "nested" / "member.tsv"
        member.write_text("member\n", encoding="ascii")
        member.chmod(0o644)
        if PROVENANCE.read_regular(provenance_root, "nested/member.tsv", 4096) != b"member\n":
            raise SystemExit("canonical provenance read changed the source bytes")

        provenance_alias = provenance_root / "alias"
        provenance_alias.symlink_to(outside, target_is_directory=True)
        require_failure(
            lambda: PROVENANCE.read_regular(provenance_root, "alias/source.tsv", 4096),
            PROVENANCE.ProvenanceError,
            "provenance parent symlink",
        )

        reference_alias = root / "reference-alias"
        reference_alias.symlink_to(outside, target_is_directory=True)
        require_failure(
            lambda: PROVENANCE.read_reference(reference_alias / "source.tsv"),
            PROVENANCE.ProvenanceError,
            "reference parent symlink",
        )

    print("BOUNDED_FILE_READERS=PASS")


if __name__ == "__main__":
    main()
