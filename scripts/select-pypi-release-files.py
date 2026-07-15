#!/usr/bin/env python3
"""Select only missing Vexcalibur distributions for a safe PyPI retry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_PYPI_RESPONSE_BYTES = 4 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
VERSION_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]{0,5})\."
    r"(?:0|[1-9][0-9]{0,5})\."
    r"(?:0|[1-9][0-9]{0,5})$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_PYPI_FILENAME_CHARACTERS = 512
MAX_PACKAGE_TYPE_CHARACTERS = 64


class SelectionError(ValueError):
    """Raised when a PyPI retry cannot be proven safe."""


@dataclass(frozen=True)
class Distribution:
    """One already-open local distribution and its checked digest."""

    filename: str
    package_type: str
    file_descriptor: int
    sha256: str


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SelectionError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _require_version(version: str) -> str:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise SelectionError(
            "version must be MAJOR.MINOR.PATCH with components from 0 through 999999 "
            "and no leading zeroes"
        )
    return version


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_directory(path: Path, *, label: str) -> int:
    try:
        descriptor = os.open(path, _directory_flags())
    except OSError as exc:
        raise SelectionError(f"could not open {label} {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise SelectionError(f"could not inspect opened {label} {path}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise SelectionError(f"{label} is not a directory: {path}")
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        os.close(descriptor)
        raise SelectionError(f"could not inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(path_metadata.st_mode):
        os.close(descriptor)
        raise SelectionError(f"{label} must not be a symlink: {path}")
    if (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino):
        os.close(descriptor)
        raise SelectionError(f"{label} changed while it was being opened: {path}")
    return descriptor


def _sha256_descriptor(descriptor: int) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, READ_CHUNK_BYTES):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise SelectionError(f"could not hash an input distribution: {exc}") from exc
    return digest.hexdigest()


def _open_distributions(directory: Path, *, version: str) -> tuple[int, list[Distribution]]:
    directory_descriptor = _open_directory(directory, label="distribution directory")
    expected = {
        f"vexcalibur-{version}-py3-none-any.whl": "bdist_wheel",
        f"vexcalibur-{version}.tar.gz": "sdist",
    }
    try:
        names = set(os.listdir(directory_descriptor))
        if names != set(expected):
            missing = sorted(set(expected) - names)
            unexpected = sorted(names - set(expected))
            details: list[str] = []
            if missing:
                details.append(f"missing {missing!r}")
            if unexpected:
                details.append(f"unexpected {unexpected!r}")
            raise SelectionError(
                "distribution directory must contain exactly the expected wheel and sdist: "
                + "; ".join(details)
            )

        distributions: list[Distribution] = []
        try:
            for filename in sorted(expected):
                try:
                    descriptor = os.open(
                        filename,
                        _file_read_flags(),
                        dir_fd=directory_descriptor,
                    )
                except OSError as exc:
                    raise SelectionError(
                        f"could not open input distribution {filename}: {exc}"
                    ) from exc
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise SelectionError(
                            f"input distribution must be a regular, non-symlink file: {filename}"
                        )
                    digest = _sha256_descriptor(descriptor)
                except Exception:
                    os.close(descriptor)
                    raise
                distributions.append(
                    Distribution(
                        filename=filename,
                        package_type=expected[filename],
                        file_descriptor=descriptor,
                        sha256=digest,
                    )
                )
        except Exception:
            for distribution in distributions:
                os.close(distribution.file_descriptor)
            raise
    except Exception:
        os.close(directory_descriptor)
        raise
    return directory_descriptor, distributions


def _read_bounded_json(path: Path) -> Any:
    try:
        descriptor = os.open(path, _file_read_flags())
    except OSError as exc:
        raise SelectionError(f"could not open PyPI response {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SelectionError(f"PyPI response must be a regular, non-symlink file: {path}")
        if metadata.st_size > MAX_PYPI_RESPONSE_BYTES:
            raise SelectionError(
                f"PyPI response exceeds the {MAX_PYPI_RESPONSE_BYTES}-byte limit: {path}"
            )
        chunks: list[bytes] = []
        remaining = MAX_PYPI_RESPONSE_BYTES + 1
        while remaining > 0 and (chunk := os.read(descriptor, min(READ_CHUNK_BYTES, remaining))):
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise SelectionError(f"could not read PyPI response {path}: {exc}") from exc
    finally:
        os.close(descriptor)

    if len(raw) > MAX_PYPI_RESPONSE_BYTES:
        raise SelectionError(
            f"PyPI response exceeds the {MAX_PYPI_RESPONSE_BYTES}-byte limit: {path}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise SelectionError(f"PyPI response is not UTF-8: {path}") from exc
    try:
        return json.loads(text, object_pairs_hook=_object_without_duplicates)
    except SelectionError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SelectionError(f"PyPI response is not valid JSON: {exc}") from exc


def _require_object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SelectionError(f"{field} must be a JSON object")
    return value


def _published_files(response: Any, *, version: str) -> dict[str, str]:
    document = _require_object(response, field="PyPI response")
    info = _require_object(document.get("info"), field="PyPI response.info")
    if info.get("name") != "vexcalibur":
        raise SelectionError("PyPI response.info.name must be 'vexcalibur'")
    if info.get("version") != version:
        raise SelectionError(f"PyPI response.info.version must be {version!r}")

    urls = document.get("urls")
    if not isinstance(urls, list):
        raise SelectionError("PyPI response.urls must be a JSON array")
    published: dict[str, str] = {}
    for index, value in enumerate(urls):
        entry = _require_object(value, field=f"PyPI response.urls[{index}]")
        filename = entry.get("filename")
        if (
            not isinstance(filename, str)
            or not filename
            or len(filename) > MAX_PYPI_FILENAME_CHARACTERS
        ):
            raise SelectionError(f"PyPI response.urls[{index}].filename must be a string")
        if filename in published:
            raise SelectionError(f"PyPI response contains duplicate file record: {filename!r}")
        package_type = entry.get("packagetype")
        if (
            not isinstance(package_type, str)
            or not package_type
            or len(package_type) > MAX_PACKAGE_TYPE_CHARACTERS
        ):
            raise SelectionError(f"PyPI response.urls[{index}].packagetype must be a string")
        digests = _require_object(
            entry.get("digests"), field=f"PyPI response.urls[{index}].digests"
        )
        digest = digests.get("sha256")
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise SelectionError(
                f"PyPI response.urls[{index}].digests.sha256 must be a lowercase SHA-256"
            )
        published[filename] = f"{package_type}:{digest}"
    return published


def _missing_distributions(
    distributions: Sequence[Distribution],
    *,
    response: Any | None,
    version: str,
) -> tuple[list[Distribution], list[Distribution]]:
    expected = {distribution.filename: distribution for distribution in distributions}
    published = {} if response is None else _published_files(response, version=version)
    unexpected = sorted(set(published) - set(expected))
    if unexpected:
        raise SelectionError(f"PyPI response contains unexpected release files: {unexpected!r}")

    missing: list[Distribution] = []
    satisfied: list[Distribution] = []
    for filename in sorted(expected):
        distribution = expected[filename]
        published_record = published.get(filename)
        if published_record is None:
            missing.append(distribution)
            continue
        expected_record = f"{distribution.package_type}:{distribution.sha256}"
        if published_record != expected_record:
            raise SelectionError(
                f"PyPI already has {filename!r} with a different digest or package type"
            )
        satisfied.append(distribution)
    return missing, satisfied


def _write_all(descriptor: int, contents: bytes) -> None:
    offset = 0
    while offset < len(contents):
        written = os.write(descriptor, contents[offset:])
        if written <= 0:
            raise OSError("write returned no progress")
        offset += written


def _copy_distributions_exclusively(
    distributions: Sequence[Distribution], *, output_directory: Path
) -> None:
    try:
        os.mkdir(output_directory, 0o755)
    except OSError as exc:
        raise SelectionError(
            f"output directory must be fresh and creatable: {output_directory}: {exc}"
        ) from exc

    output_descriptor = _open_directory(output_directory, label="output directory")
    try:
        for distribution in distributions:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                target_descriptor = os.open(
                    distribution.filename,
                    flags,
                    0o644,
                    dir_fd=output_descriptor,
                )
            except OSError as exc:
                raise SelectionError(
                    f"refusing to overwrite output file {distribution.filename}: {exc}"
                ) from exc
            copied_digest = hashlib.sha256()
            try:
                os.lseek(distribution.file_descriptor, 0, os.SEEK_SET)
                while chunk := os.read(distribution.file_descriptor, READ_CHUNK_BYTES):
                    copied_digest.update(chunk)
                    _write_all(target_descriptor, chunk)
                os.fsync(target_descriptor)
            except OSError as exc:
                raise SelectionError(
                    f"could not copy output file {distribution.filename}: {exc}"
                ) from exc
            finally:
                os.close(target_descriptor)
            if copied_digest.hexdigest() != distribution.sha256:
                raise SelectionError(
                    f"input distribution changed while copying: {distribution.filename}"
                )
    finally:
        os.close(output_descriptor)


def _write_github_output(path: Path, result: dict[str, Any]) -> None:
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise SelectionError(f"GitHub output must be a regular, non-symlink file: {path}")
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SelectionError(f"could not open GitHub output {path}: {exc}") from exc
    contents = (
        f"publish_needed={str(result['publish_needed']).lower()}\n"
        f"missing_count={result['missing_count']}\n"
        f"missing_files={json.dumps(result['missing_files'], separators=(',', ':'))}\n"
    ).encode()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SelectionError(f"GitHub output must be a regular file: {path}")
        _write_all(descriptor, contents)
    except OSError as exc:
        raise SelectionError(f"could not write GitHub output {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def select_release_files(
    distribution_directory: Path,
    *,
    version: str,
    pypi_response: Path | None,
    output_directory: Path,
) -> dict[str, Any]:
    """Copy exactly the distributions absent from one version-specific PyPI response."""
    version = _require_version(version)
    directory_descriptor, distributions = _open_distributions(
        distribution_directory, version=version
    )
    try:
        response = None if pypi_response is None else _read_bounded_json(pypi_response)
        missing, satisfied = _missing_distributions(
            distributions,
            response=response,
            version=version,
        )
        _copy_distributions_exclusively(missing, output_directory=output_directory)
        return {
            "publish_needed": bool(missing),
            "missing_count": len(missing),
            "missing_files": [distribution.filename for distribution in missing],
            "satisfied_files": [distribution.filename for distribution in satisfied],
        }
    finally:
        for distribution in distributions:
            os.close(distribution.file_descriptor)
        os.close(directory_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distribution_directory", type=Path)
    parser.add_argument("--version", required=True)
    response = parser.add_mutually_exclusive_group(required=True)
    response.add_argument("--pypi-response", type=Path)
    response.add_argument(
        "--pypi-missing",
        action="store_true",
        help="treat an explicitly observed HTTP 404 as an absent project version",
    )
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument(
        "--github-output",
        type=Path,
        help="append step outputs here (defaults to GITHUB_OUTPUT when set)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    github_output = args.github_output
    if github_output is None and (environment_output := os.environ.get("GITHUB_OUTPUT")):
        github_output = Path(environment_output)
    try:
        result = select_release_files(
            args.distribution_directory,
            version=args.version,
            pypi_response=None if args.pypi_missing else args.pypi_response,
            output_directory=args.output_directory,
        )
        if github_output is not None:
            _write_github_output(github_output, result)
    except (OSError, SelectionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
