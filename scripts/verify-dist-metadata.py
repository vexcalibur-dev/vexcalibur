#!/usr/bin/env python3
"""Verify Vexcalibur distribution artifact metadata."""

from __future__ import annotations

import argparse
import email
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_REQUIRED_SDIST_FILE_BYTES = 1024 * 1024


def main() -> None:
    """Verify wheel and source distribution metadata."""
    args = _parse_args()
    dist_dir = args.dist_dir
    expected_name = args.expected_name
    expected_version = args.expected_version

    wheel, sdist = _find_artifacts(dist_dir)
    metadata = {
        "wheel": _read_wheel_metadata(wheel),
        "sdist": _read_sdist_metadata(sdist),
    }

    for artifact_type, artifact_metadata in metadata.items():
        actual_name = artifact_metadata["Name"]
        actual_version = artifact_metadata["Version"]
        if actual_name != expected_name:
            raise SystemExit(
                f"Built {artifact_type} name {actual_name!r} "
                f"does not match expected name {expected_name!r}."
            )
        if actual_version != expected_version:
            raise SystemExit(
                f"Built {artifact_type} version {actual_version!r} "
                f"does not match expected version {expected_version!r}."
            )

    _verify_required_sdist_files(
        sdist,
        archive_root=f"{expected_name}-{expected_version}",
        source_root=args.source_root,
        required_files=args.required_sdist_file,
    )

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"version={metadata['wheel']['Version']}\n")
            output.write(f"wheel={wheel}\n")
            output.write(f"sdist={sdist}\n")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--expected-name", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument(
        "--required-sdist-file",
        action="append",
        default=[],
        type=PurePosixPath,
    )
    return parser.parse_args()


def _find_artifacts(dist_dir: Path) -> tuple[Path, Path]:
    if not dist_dir.is_dir():
        raise SystemExit(f"Distribution directory does not exist: {dist_dir}")

    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1:
        raise SystemExit(f"Expected exactly one wheel artifact, found {len(wheels)}.")
    if len(sdists) != 1:
        raise SystemExit(f"Expected exactly one sdist artifact, found {len(sdists)}.")

    expected_artifacts = {wheels[0], sdists[0]}
    unexpected_artifacts = sorted(
        path for path in dist_dir.iterdir() if path.is_file() and path not in expected_artifacts
    )
    if unexpected_artifacts:
        raise SystemExit(
            "Unexpected files in distribution directory: "
            + ", ".join(str(path) for path in unexpected_artifacts)
        )

    return wheels[0], sdists[0]


def _read_wheel_metadata(path: Path) -> email.message.Message:
    with zipfile.ZipFile(path) as wheel:
        metadata_path = next(
            (name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")),
            None,
        )
        if metadata_path is None:
            raise SystemExit(f"Could not find wheel metadata in {path}.")
        return email.message_from_bytes(wheel.read(metadata_path))


def _read_sdist_metadata(path: Path) -> email.message.Message:
    with tarfile.open(path, "r:gz") as sdist:
        metadata_path = next(
            (member for member in sdist.getmembers() if member.name.endswith("/PKG-INFO")),
            None,
        )
        if metadata_path is None:
            raise SystemExit(f"Could not find sdist metadata in {path}.")
        metadata_file = sdist.extractfile(metadata_path)
        if metadata_file is None:
            raise SystemExit(f"Could not read {metadata_path.name} from {path}.")
        return email.message_from_bytes(metadata_file.read())


def _verify_required_sdist_files(
    sdist_path: Path,
    *,
    archive_root: str,
    source_root: Path | None,
    required_files: list[PurePosixPath],
) -> None:
    if not required_files:
        return
    if source_root is None:
        raise SystemExit("--source-root is required with --required-sdist-file.")
    if not source_root.is_dir():
        raise SystemExit(f"Source root does not exist: {source_root}")

    seen: set[PurePosixPath] = set()
    expected: dict[str, bytes] = {}
    for relative_path in required_files:
        if (
            relative_path in seen
            or relative_path.is_absolute()
            or not relative_path.parts
            or any(part in {"", ".", ".."} for part in relative_path.parts)
        ):
            raise SystemExit(f"Required sdist path is unsafe or repeated: {relative_path}")
        seen.add(relative_path)
        source_path = source_root.joinpath(*relative_path.parts)
        if not source_path.is_file() or source_path.is_symlink():
            raise SystemExit(f"Required sdist source is not a regular file: {source_path}")
        if source_path.stat().st_size > MAX_REQUIRED_SDIST_FILE_BYTES:
            raise SystemExit(f"Required sdist source exceeds the byte limit: {source_path}")
        expected[f"{archive_root}/{relative_path.as_posix()}"] = source_path.read_bytes()

    with tarfile.open(sdist_path, "r:gz") as sdist:
        members = {member.name: member for member in sdist.getmembers()}
        for member_name, expected_bytes in expected.items():
            member = members.get(member_name)
            if member is None or not member.isfile() or member.size > MAX_REQUIRED_SDIST_FILE_BYTES:
                raise SystemExit(f"Required file is missing or invalid in the sdist: {member_name}")
            stream = sdist.extractfile(member)
            if stream is None or stream.read(MAX_REQUIRED_SDIST_FILE_BYTES + 1) != expected_bytes:
                raise SystemExit(f"Required sdist file differs from source: {member_name}")


if __name__ == "__main__":
    main()
