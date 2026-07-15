#!/usr/bin/env python3
"""Rewrite a safe source distribution with deterministic archive metadata."""

from __future__ import annotations

import argparse
import gzip
import sys
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024


class NormalizationError(ValueError):
    """Raised when an sdist cannot be normalized safely."""


@dataclass(frozen=True)
class Member:
    """One validated archive member and its optional contents."""

    name: str
    is_directory: bool
    executable: bool
    contents: bytes | None


def _safe_member_name(name: str) -> str:
    canonical = name.rstrip("/")
    if (
        not canonical
        or canonical.startswith(("/", "\\"))
        or (
            len(canonical) >= 2
            and canonical[0].isascii()
            and canonical[0].isalpha()
            and canonical[1] == ":"
        )
        or "\\" in canonical
        or any(ord(character) < 32 or ord(character) == 127 for character in canonical)
        or any(part in {"", ".", ".."} for part in canonical.split("/"))
    ):
        raise NormalizationError(f"sdist contains an unsafe member path: {name!r}")
    return canonical


def _read_members(path: Path) -> list[Member]:
    if not path.is_file() or path.is_symlink():
        raise NormalizationError(f"input must be a regular, non-symlink file: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise NormalizationError(f"input exceeds the {MAX_INPUT_BYTES}-byte limit: {path}")

    result: list[Member] = []
    names: set[str] = set()
    uncompressed_bytes = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_MEMBERS:
                    raise NormalizationError("sdist contains too many members")
                name = _safe_member_name(member.name)
                if name in names:
                    raise NormalizationError(f"sdist contains duplicate member {name!r}")
                names.add(name)
                if not (member.isfile() or member.isdir()):
                    raise NormalizationError("sdist contains a link or special member")

                contents: bytes | None = None
                if member.isfile():
                    uncompressed_bytes += member.size
                    if uncompressed_bytes > MAX_UNCOMPRESSED_BYTES:
                        raise NormalizationError(
                            "sdist exceeds the cumulative uncompressed byte limit"
                        )
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise NormalizationError(f"could not read sdist member {name!r}")
                    contents = stream.read(member.size + 1)
                    if len(contents) != member.size:
                        raise NormalizationError(f"sdist member size changed: {name!r}")
                result.append(
                    Member(
                        name=name,
                        is_directory=member.isdir(),
                        executable=bool(member.mode & 0o111),
                        contents=contents,
                    )
                )
    except (OSError, tarfile.TarError) as exc:
        raise NormalizationError(f"could not read sdist: {exc}") from exc
    return sorted(result, key=lambda item: item.name)


def normalize_sdist(input_path: Path, *, output_path: Path, source_date_epoch: int) -> None:
    """Write one deterministic gzip/PAX archive without replacing an existing path."""
    if source_date_epoch < 0 or source_date_epoch > 253_402_300_799:
        raise NormalizationError("SOURCE_DATE_EPOCH is outside the supported range")
    if output_path.exists() or output_path.is_symlink():
        raise NormalizationError(f"output already exists: {output_path}")
    members = _read_members(input_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        # The created flag must be set immediately after the exclusive open so a
        # later context-manager failure cannot leave a partial output behind.
        with output_path.open("xb") as raw_output:
            created = True
            with (
                gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=9,
                    fileobj=raw_output,
                    mtime=source_date_epoch,
                ) as compressed_output,
                tarfile.open(
                    fileobj=compressed_output,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as output_archive,
            ):
                for member in members:
                    normalized = tarfile.TarInfo(member.name)
                    normalized.mtime = source_date_epoch
                    normalized.uid = 0
                    normalized.gid = 0
                    normalized.uname = ""
                    normalized.gname = ""
                    normalized.pax_headers = {}
                    if member.is_directory:
                        normalized.type = tarfile.DIRTYPE
                        normalized.mode = 0o755
                        normalized.size = 0
                        output_archive.addfile(normalized)
                        continue
                    normalized.type = tarfile.REGTYPE
                    normalized.mode = 0o755 if member.executable else 0o644
                    assert member.contents is not None
                    normalized.size = len(member.contents)
                    output_archive.addfile(
                        normalized,
                        BytesIO(member.contents),
                    )
        if output_path.stat().st_size > MAX_INPUT_BYTES:
            raise NormalizationError("normalized sdist exceeds the compressed byte limit")
    except Exception:
        if created:
            output_path.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser


def main() -> int:
    """Normalize one command-line-selected sdist."""
    args = _parser().parse_args()
    try:
        normalize_sdist(
            args.input,
            output_path=args.output,
            source_date_epoch=args.source_date_epoch,
        )
    except (OSError, NormalizationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
