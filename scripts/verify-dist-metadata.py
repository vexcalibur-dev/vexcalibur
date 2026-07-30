#!/usr/bin/env python3
"""Verify Vexcalibur distribution artifact metadata."""

from __future__ import annotations

import argparse
import configparser
import email
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_REQUIRED_SDIST_FILE_BYTES = 1024 * 1024
_METADATA_CONTRACT_HEADERS = (
    "Metadata-Version",
    "Requires-Python",
    "Requires-Dist",
    "Provides-Extra",
)


@dataclass(frozen=True)
class DistributionMetadata:
    """Validated package metadata and console entry points from one artifact."""

    message: email.message.Message
    console_scripts: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ProjectMetadata:
    """Normalized package metadata declared by ``pyproject.toml``."""

    requires_python: str | None
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]
    console_scripts: tuple[tuple[str, str], ...]


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
        actual_name = artifact_metadata.message["Name"]
        actual_version = artifact_metadata.message["Version"]
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

    _verify_matching_artifact_contracts(metadata)
    if args.source_root is not None:
        _verify_project_metadata(
            _read_project_metadata(args.source_root),
            metadata,
        )

    _verify_required_sdist_files(
        sdist,
        archive_root=f"{expected_name}-{expected_version}",
        source_root=args.source_root,
        required_files=args.required_sdist_file,
    )

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"version={metadata['wheel'].message['Version']}\n")
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


def _read_wheel_metadata(path: Path) -> DistributionMetadata:
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
        entry_points = _read_bounded_zip_member(
            wheel,
            members,
            suffix=".dist-info/entry_points.txt",
            role="wheel entry points",
        )
        return DistributionMetadata(
            message=email.message_from_bytes(metadata),
            console_scripts=_parse_console_scripts(entry_points, role="wheel entry points"),
        )


def _read_sdist_metadata(path: Path) -> DistributionMetadata:
    with tarfile.open(path, "r:gz") as sdist:
        metadata: bytes | None = None
        entry_points: bytes | None = None
        for member in _validated_sdist_members(sdist):
            member_path = PurePosixPath(member.name)
            if len(member_path.parts) == 2 and member_path.name == "PKG-INFO":
                if metadata is not None:
                    raise SystemExit(f"Expected exactly one sdist metadata member in {path}.")
                metadata = _read_bounded_tar_member(
                    sdist,
                    member,
                    role="sdist metadata",
                )
            elif member_path.name == "entry_points.txt" and member_path.parent.name.endswith(
                ".egg-info"
            ):
                if entry_points is not None:
                    raise SystemExit(f"Expected at most one sdist entry-points member in {path}.")
                entry_points = _read_bounded_tar_member(
                    sdist,
                    member,
                    role="sdist entry points",
                )
        if metadata is None:
            raise SystemExit(f"Could not find sdist metadata in {path}.")
        if len(metadata) > MAX_METADATA_BYTES:
            raise SystemExit(f"Sdist metadata exceeds the byte limit in {path}.")
        return DistributionMetadata(
            message=email.message_from_bytes(metadata),
            console_scripts=_parse_console_scripts(entry_points, role="sdist entry points"),
        )


def _read_bounded_zip_member(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    *,
    suffix: str,
    role: str,
) -> bytes | None:
    matching = [member for member in members if member.filename.endswith(suffix)]
    if not matching:
        return None
    if len(matching) != 1:
        raise SystemExit(f"Expected at most one {role} member.")
    member = matching[0]
    if member.is_dir() or member.file_size > MAX_METADATA_BYTES:
        raise SystemExit(f"{role.capitalize()} is not a bounded regular member.")
    with archive.open(member) as stream:
        value = stream.read(MAX_METADATA_BYTES + 1)
    if len(value) > MAX_METADATA_BYTES:
        raise SystemExit(f"{role.capitalize()} exceeds the byte limit.")
    return value


def _read_bounded_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    role: str,
) -> bytes:
    if not member.isfile() or member.size > MAX_METADATA_BYTES:
        raise SystemExit(f"{role.capitalize()} is not a bounded regular member.")
    stream = archive.extractfile(member)
    if stream is None:
        raise SystemExit(f"Could not read {role}.")
    value = stream.read(MAX_METADATA_BYTES + 1)
    if len(value) > MAX_METADATA_BYTES:
        raise SystemExit(f"{role.capitalize()} exceeds the byte limit.")
    return value


def _parse_console_scripts(value: bytes | None, *, role: str) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    try:
        decoded = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{role.capitalize()} is not valid UTF-8.") from exc
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        parser.read_string(decoded)
    except configparser.Error as exc:
        raise SystemExit(f"{role.capitalize()} is invalid.") from exc
    if not parser.has_section("console_scripts"):
        return ()
    scripts = tuple(
        sorted((name.strip(), target.strip()) for name, target in parser.items("console_scripts"))
    )
    if any(not name or not target for name, target in scripts):
        raise SystemExit(f"{role.capitalize()} contains an empty console script.")
    return scripts


def _verify_matching_artifact_contracts(
    metadata: dict[str, DistributionMetadata],
) -> None:
    wheel = metadata["wheel"]
    sdist = metadata["sdist"]
    for header in _METADATA_CONTRACT_HEADERS:
        wheel_values = _normalized_metadata_header(wheel.message, header)
        sdist_values = _normalized_metadata_header(sdist.message, header)
        if wheel_values != sdist_values:
            raise SystemExit(f"Built wheel and sdist {header} metadata do not match.")
    if wheel.console_scripts != sdist.console_scripts:
        raise SystemExit("Built wheel and sdist console scripts do not match.")


def _normalized_metadata_header(
    metadata: email.message.Message,
    header: str,
) -> tuple[str, ...]:
    values = metadata.get_all(header, [])
    try:
        if header == "Requires-Python":
            if len(values) > 1:
                raise SystemExit("Artifact contains repeated Requires-Python metadata.")
            return tuple(str(SpecifierSet(value)) for value in values)
        if header == "Requires-Dist":
            return tuple(sorted(str(Requirement(value)) for value in values))
        if header == "Provides-Extra":
            return tuple(sorted(canonicalize_name(value) for value in values))
    except (InvalidRequirement, InvalidSpecifier) as exc:
        raise SystemExit(f"Artifact contains invalid {header} metadata.") from exc
    return tuple(values)


def _read_project_metadata(source_root: Path) -> ProjectMetadata:
    pyproject_path = source_root / "pyproject.toml"
    if not pyproject_path.is_file() or pyproject_path.is_symlink():
        raise SystemExit(f"Project metadata source is not a regular file: {pyproject_path}")
    if pyproject_path.stat().st_size > MAX_METADATA_BYTES:
        raise SystemExit("Project metadata source exceeds the byte limit.")
    try:
        project_document = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        project = project_document["project"]
        if not isinstance(project, dict):
            raise TypeError
        dependencies = project.get("dependencies", [])
        optional_dependencies = project.get("optional-dependencies", {})
        scripts = project.get("scripts", {})
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise SystemExit("Project metadata source is invalid.") from exc
    if not isinstance(dependencies, list) or not isinstance(optional_dependencies, dict):
        raise SystemExit("Project metadata source is invalid.")

    normalized_requirements = [_normalize_requirement(value) for value in dependencies]
    extras: list[str] = []
    for extra, values in optional_dependencies.items():
        if not isinstance(extra, str) or not isinstance(values, list):
            raise SystemExit("Project optional-dependency metadata is invalid.")
        extras.append(canonicalize_name(extra))
        normalized_requirements.extend(
            _normalize_extra_requirement(value, extra=extra) for value in values
        )
    if not isinstance(scripts, dict) or any(
        not isinstance(name, str) or not isinstance(target, str) for name, target in scripts.items()
    ):
        raise SystemExit("Project console-script metadata is invalid.")

    requires_python = project.get("requires-python")
    if requires_python is not None and not isinstance(requires_python, str):
        raise SystemExit("Project Requires-Python metadata is invalid.")
    try:
        normalized_requires_python = (
            None if requires_python is None else str(SpecifierSet(requires_python))
        )
    except InvalidSpecifier as exc:
        raise SystemExit("Project Requires-Python metadata is invalid.") from exc
    return ProjectMetadata(
        requires_python=normalized_requires_python,
        requires_dist=tuple(sorted(normalized_requirements)),
        provides_extra=tuple(sorted(extras)),
        console_scripts=tuple(sorted(scripts.items())),
    )


def _normalize_requirement(value: object) -> str:
    if not isinstance(value, str):
        raise SystemExit("Project dependency metadata is invalid.")
    try:
        return str(Requirement(value))
    except InvalidRequirement as exc:
        raise SystemExit("Project dependency metadata is invalid.") from exc


def _normalize_extra_requirement(value: object, *, extra: str) -> str:
    requirement = Requirement(_normalize_requirement(value))
    extra_marker = f'extra == "{canonicalize_name(extra)}"'
    try:
        requirement.marker = Marker(
            extra_marker
            if requirement.marker is None
            else f"({requirement.marker}) and {extra_marker}"
        )
    except InvalidMarker as exc:
        raise SystemExit("Project optional-dependency metadata is invalid.") from exc
    return str(requirement)


def _verify_project_metadata(
    expected: ProjectMetadata,
    metadata: dict[str, DistributionMetadata],
) -> None:
    for artifact_type, artifact in metadata.items():
        actual_requires_python = _normalized_metadata_header(
            artifact.message,
            "Requires-Python",
        )
        expected_requires_python = (
            () if expected.requires_python is None else (expected.requires_python,)
        )
        if actual_requires_python != expected_requires_python:
            raise SystemExit(
                f"Built {artifact_type} Requires-Python metadata does not match pyproject.toml."
            )
        if _normalized_metadata_header(artifact.message, "Requires-Dist") != expected.requires_dist:
            raise SystemExit(
                f"Built {artifact_type} Requires-Dist metadata does not match pyproject.toml."
            )
        if (
            _normalized_metadata_header(artifact.message, "Provides-Extra")
            != expected.provides_extra
        ):
            raise SystemExit(
                f"Built {artifact_type} Provides-Extra metadata does not match pyproject.toml."
            )
        if artifact.console_scripts != expected.console_scripts:
            raise SystemExit(f"Built {artifact_type} console scripts do not match pyproject.toml.")


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
