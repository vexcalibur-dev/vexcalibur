"""Prepare checked-in seeds for the coverage-guided fuzzing runner."""

from __future__ import annotations

import argparse
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from tests.fuzz.boundaries import FUZZ_TARGETS


@dataclass(frozen=True, slots=True)
class _TargetPlan:
    """Validated files to stage for one fuzz target."""

    destination: Path
    seeds: dict[str, bytes]
    obsolete_hex_files: tuple[Path, ...]


def _require_safe_destination(path: Path) -> None:
    """Reject paths that could redirect or obstruct corpus writes."""
    if path.is_symlink():
        raise ValueError(f"fuzz corpus destination must not be a symlink: {path}")
    if path.exists() and not path.is_file() and not path.is_dir():
        raise ValueError(f"fuzz corpus destination has an unsupported type: {path}")


def _build_staging_plan(source_root: Path, destination_root: Path) -> tuple[_TargetPlan, ...]:
    """Validate all source and destination paths before staging any files."""
    plans: list[_TargetPlan] = []
    for target in FUZZ_TARGETS:
        source = source_root / target
        destination = destination_root / target
        if source.is_symlink():
            raise ValueError(f"fuzz corpus target must not be a symlink: {source}")
        if source.exists() and not source.is_dir():
            raise ValueError(f"fuzz corpus target must be a directory: {source}")
        _require_safe_destination(destination)
        if destination.exists() and not destination.is_dir():
            raise ValueError(f"fuzz corpus target destination must be a directory: {destination}")

        staged_seeds: dict[str, bytes] = {}
        staged_sources: dict[str, Path] = {}
        obsolete_hex_files: list[Path] = []
        if source.is_dir():
            for seed in sorted(source.iterdir(), key=lambda path: path.name):
                if seed.is_symlink() or not seed.is_file():
                    raise ValueError(f"fuzz corpus entry must be a regular file: {seed}")
                staged_name = f"{seed.stem}.bin" if seed.suffix == ".hex" else seed.name
                if staged_name in staged_sources:
                    raise ValueError(
                        f"fuzz corpus entries map to the same staged name: "
                        f"{staged_sources[staged_name]} and {seed}"
                    )
                staged_sources[staged_name] = seed
                if seed.suffix == ".hex":
                    staged_seeds[staged_name] = bytes.fromhex(seed.read_text(encoding="ascii"))
                else:
                    staged_seeds[staged_name] = seed.read_bytes()

                staged_destination = destination / staged_name
                _require_safe_destination(staged_destination)
                if staged_destination.exists() and not staged_destination.is_file():
                    raise ValueError(
                        f"fuzz corpus seed destination must be a regular file: {staged_destination}"
                    )
                if seed.suffix == ".hex":
                    encoded_destination = destination / seed.name
                    _require_safe_destination(encoded_destination)
                    if encoded_destination.exists() and not encoded_destination.is_file():
                        raise ValueError(
                            "obsolete encoded fuzz seed must be a regular file: "
                            f"{encoded_destination}"
                        )
                    obsolete_hex_files.append(encoded_destination)

        plans.append(
            _TargetPlan(
                destination=destination,
                seeds=staged_seeds,
                obsolete_hex_files=tuple(obsolete_hex_files),
            )
        )
    return tuple(plans)


def _write_seed_atomic(destination: Path, seed_data: bytes) -> None:
    """Replace one seed without following links or modifying shared inodes."""
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as temporary_file:
            temporary_file.write(seed_data)
            temporary_path = Path(temporary_file.name)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def stage_corpus(source_root: Path, destination_root: Path) -> None:
    """Copy every target corpus and materialize hexadecimal binary seeds."""
    if destination_root.is_symlink():
        raise ValueError(f"fuzz corpus destination root must not be a symlink: {destination_root}")
    source_root = source_root.resolve()
    destination_root = destination_root.resolve()
    if (
        source_root == destination_root
        or source_root in destination_root.parents
        or destination_root in source_root.parents
    ):
        raise ValueError("fuzz corpus source and destination must not overlap")
    plans = _build_staging_plan(source_root, destination_root)
    for plan in plans:
        plan.destination.mkdir(parents=True, exist_ok=True)
        for obsolete_hex_file in plan.obsolete_hex_files:
            obsolete_hex_file.unlink(missing_ok=True)
        for staged_name, seed_data in plan.seeds.items():
            _write_seed_atomic(plan.destination / staged_name, seed_data)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list-targets", help="Print one configured target per line")
    stage = subparsers.add_parser("stage", help="Prepare all checked-in target corpora")
    stage.add_argument("source_root", type=Path)
    stage.add_argument("destination_root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """List targets or prepare their checked-in corpus."""
    arguments = _parser().parse_args(argv)
    if arguments.command == "list-targets":
        print(*FUZZ_TARGETS, sep="\n")
    else:
        stage_corpus(arguments.source_root, arguments.destination_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
