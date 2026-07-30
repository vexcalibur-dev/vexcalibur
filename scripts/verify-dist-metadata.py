#!/usr/bin/env python3
"""Verify Vexcalibur distribution artifact metadata."""

from __future__ import annotations

import argparse
import email
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
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

    for artifact in expected_artifacts:
        metadata = artifact.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or artifact.is_symlink()
            or metadata.st_size > MAX_ARCHIVE_BYTES
        ):
            raise SystemExit(f"Distribution is not a bounded regular file: {artifact}")

    return wheels[0], sdists[0]


def _read_wheel_metadata(path: Path) -> email.message.Message:
    with zipfile.ZipFile(path) as wheel:
        members = wheel.infolist()
        _validate_zip_members(members)
        metadata_members = [
            member for member in members if member.filename.endswith(".dist-info/METADATA")
        ]
        if len(metadata_members) != 1:
            raise SystemExit(f"Expected exactly one wheel metadata member in {path}.")
        metadata_member = metadata_members[0]
        if metadata_member.is_dir() or metadata_member.file_size > MAX_METADATA_BYTES:
            raise SystemExit(f"Wheel metadata is not a bounded regular member in {path}.")
        with wheel.open(metadata_member) as metadata_stream:
            metadata = metadata_stream.read(MAX_METADATA_BYTES + 1)
        if len(metadata) > MAX_METADATA_BYTES:
            raise SystemExit(f"Wheel metadata exceeds the byte limit in {path}.")
        return email.message_from_bytes(metadata)


def _read_sdist_metadata(path: Path) -> email.message.Message:
    with tarfile.open(path, "r:gz") as sdist:
        metadata: bytes | None = None
        for member in _validated_sdist_members(sdist):
            member_path = PurePosixPath(member.name)
            if len(member_path.parts) != 2 or member_path.name != "PKG-INFO":
                continue
            if metadata is not None:
                raise SystemExit(f"Expected exactly one sdist metadata member in {path}.")
            if not member.isfile() or member.size > MAX_METADATA_BYTES:
                raise SystemExit(f"Sdist metadata is not a bounded regular member in {path}.")
            metadata_file = sdist.extractfile(member)
            if metadata_file is None:
                raise SystemExit(f"Could not read {member.name} from {path}.")
            metadata = metadata_file.read(MAX_METADATA_BYTES + 1)
        if metadata is None:
            raise SystemExit(f"Could not find sdist metadata in {path}.")
        if len(metadata) > MAX_METADATA_BYTES:
            raise SystemExit(f"Sdist metadata exceeds the byte limit in {path}.")
        return email.message_from_bytes(metadata)


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
        found: set[str] = set()
        for member in _validated_sdist_members(sdist):
            expected_bytes = expected.get(member.name)
            if expected_bytes is None:
                continue
            if member.name in found:
                raise SystemExit(f"Required sdist file is repeated: {member.name}")
            found.add(member.name)
            if not member.isfile() or member.size > MAX_REQUIRED_SDIST_FILE_BYTES:
                raise SystemExit(f"Required file is missing or invalid in the sdist: {member.name}")
            stream = sdist.extractfile(member)
            if stream is None or stream.read(MAX_REQUIRED_SDIST_FILE_BYTES + 1) != expected_bytes:
                raise SystemExit(f"Required sdist file differs from source: {member.name}")
        missing = sorted(set(expected) - found)
        if missing:
            raise SystemExit(f"Required file is missing or invalid in the sdist: {missing[0]}")


def _validate_zip_members(members: list[zipfile.ZipInfo]) -> None:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise SystemExit("Wheel contains too many archive members.")
    names: set[str] = set()
    uncompressed_bytes = 0
    for member in members:
        _validate_member_name(member.filename, artifact="wheel")
        if member.filename in names:
            raise SystemExit(f"Wheel contains duplicate member: {member.filename}")
        names.add(member.filename)
        if member.flag_bits & 0x1:
            raise SystemExit("Wheel contains an encrypted archive member.")
        if not member.is_dir():
            uncompressed_bytes += member.file_size
            if uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise SystemExit("Wheel exceeds the cumulative uncompressed byte limit.")
        if member.create_system == 3:
            file_type = stat.S_IFMT(member.external_attr >> 16)
            expected_types = {0, stat.S_IFDIR} if member.is_dir() else {0, stat.S_IFREG}
            if file_type not in expected_types:
                raise SystemExit("Wheel contains a link or special archive member.")


def _validated_sdist_members(
    sdist: tarfile.TarFile,
) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    names: set[str] = set()
    uncompressed_bytes = 0
    for index, member in enumerate(sdist):
        if index >= MAX_ARCHIVE_MEMBERS:
            raise SystemExit("Sdist contains too many archive members.")
        _validate_member_name(member.name, artifact="sdist")
        if member.name in names:
            raise SystemExit(f"Sdist contains duplicate member: {member.name}")
        names.add(member.name)
        if not (member.isfile() or member.isdir()):
            raise SystemExit("Sdist contains a link or special archive member.")
        if member.isfile():
            uncompressed_bytes += member.size
            if uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise SystemExit("Sdist exceeds the cumulative uncompressed byte limit.")
        members.append(member)
    return members


def _validate_member_name(name: str, *, artifact: str) -> None:
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
        raise SystemExit(f"{artifact} contains an unsafe archive member path.")


if __name__ == "__main__":
    main()
