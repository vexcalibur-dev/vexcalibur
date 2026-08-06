#!/usr/bin/env python3
"""Validate one execution report against its exact generated document."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, NoReturn

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource

MAX_EXECUTION_REPORT_BYTES = 16 * 1024
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
MAX_SCHEMA_BYTES = 256 * 1024
EXECUTION_REPORT_SCHEMA_SHA256 = (
    "8e49a8d5652a94bcbd46eb012e643d8300f1e7c376803def509d37e37e54ed65"  # pragma: allowlist secret
)


def _reject_external_schema_reference(uri: str) -> NoReturn:
    raise NoSuchResource(ref=uri)


SCHEMA_REGISTRY: Registry[Any] = Registry(retrieve=_reject_external_schema_reference)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@contextmanager
def _open_regular_file(path: Path, *, role: str) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    before_open = os.lstat(path)
    if stat.S_ISLNK(before_open.st_mode):
        raise ValueError(f"{role} must not be a symbolic link")
    if not stat.S_ISREG(before_open.st_mode):
        raise ValueError(f"{role} must be a regular file")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{role} must be a regular file")
        after_open = os.lstat(path)
        if stat.S_ISLNK(after_open.st_mode):
            raise ValueError(f"{role} must not be a symbolic link")
        if not os.path.samestat(before_open, metadata) or not os.path.samestat(
            metadata,
            after_open,
        ):
            raise ValueError(f"{role} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            yield stream, metadata
            after_read = os.fstat(stream.fileno())
            current_path = os.lstat(path)
            snapshots = (after_read, current_path)
            if any(not stat.S_ISREG(snapshot.st_mode) for snapshot in snapshots):
                raise ValueError(f"{role} changed while it was read")
            if any(not os.path.samestat(metadata, snapshot) for snapshot in snapshots):
                raise ValueError(f"{role} changed while it was read")
            expected_state = (
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            if any(
                (
                    snapshot.st_size,
                    snapshot.st_mtime_ns,
                    snapshot.st_ctime_ns,
                )
                != expected_state
                for snapshot in snapshots
            ):
                raise ValueError(f"{role} changed while it was read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_bounded_file(
    path: Path,
    *,
    role: str,
    maximum: int,
    too_large: str,
) -> bytes:
    with _open_regular_file(path, role=role) as (stream, metadata):
        if metadata.st_size > maximum:
            raise ValueError(too_large)
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError(too_large)
    if len(value) != metadata.st_size:
        raise ValueError(f"{role} changed while it was read")
    return value


def _read_json_object(
    path: Path,
    *,
    role: str,
    maximum: int,
    too_large: str,
) -> dict[str, Any]:
    return _decode_json_object(
        _read_bounded_file(
            path,
            role=role,
            maximum=maximum,
            too_large=too_large,
        ),
        role=role,
    )


def _decode_json_object(value: bytes, *, role: str) -> dict[str, Any]:
    """Decode one bounded JSON object."""
    try:
        value = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RecursionError as exc:
        raise ValueError(f"{role} is too deeply nested") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{role} must be a JSON object")
    return value


def _read_report(path: Path) -> dict[str, Any]:
    return _read_json_object(
        path,
        role="execution report",
        maximum=MAX_EXECUTION_REPORT_BYTES,
        too_large="execution report exceeds 16 KiB",
    )


def _read_schema(path: Path) -> dict[str, Any]:
    schema_bytes = _read_bounded_file(
        path,
        role="execution report schema",
        maximum=MAX_SCHEMA_BYTES,
        too_large=f"execution report schema exceeds {MAX_SCHEMA_BYTES} bytes",
    )
    if hashlib.sha256(schema_bytes).hexdigest() != EXECUTION_REPORT_SCHEMA_SHA256:
        raise ValueError("execution report schema does not match the reviewed schema")
    return _decode_json_object(schema_bytes, role="execution report schema")


def _require_exact_integer(value: Any, *, field: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{field} must be an integer")
    return value


def validate_execution_report(
    report_path: Path,
    document_path: Path,
    schema_path: Path,
) -> dict[str, Any]:
    """Validate the closed report schema, cross-fields, and document binding."""
    report = _read_report(report_path)
    for field in ("schema_version", "component_count", "finding_count"):
        _require_exact_integer(report.get(field), field=field)

    analysis_state_counts = report.get("analysis_state_counts")
    if isinstance(analysis_state_counts, dict):
        for state, count in analysis_state_counts.items():
            _require_exact_integer(count, field=f"analysis_state_counts.{state}")

    document_metadata = report.get("document")
    if isinstance(document_metadata, dict):
        untrusted_bytes = _require_exact_integer(
            document_metadata.get("bytes"),
            field="document.bytes",
        )
        if untrusted_bytes > MAX_DOCUMENT_BYTES:
            raise ValueError("document exceeds the 25 MiB Vexcalibur output limit")

    schema = _read_schema(schema_path)
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=SCHEMA_REGISTRY).validate(report)
    except RecursionError as exc:
        raise ValueError("execution report schema is too deeply nested") from exc
    if sum(report["analysis_state_counts"].values()) != report["finding_count"]:
        raise ValueError("analysis state counts do not sum to finding_count")

    expected_bytes = report["document"]["bytes"]
    actual_bytes = 0
    document_digest = hashlib.sha256()
    with _open_regular_file(document_path, role="generated document") as (stream, metadata):
        if metadata.st_size != expected_bytes:
            raise ValueError("document byte count does not match")
        while chunk := stream.read(1024 * 1024):
            actual_bytes += len(chunk)
            if actual_bytes > expected_bytes:
                raise ValueError("document byte count does not match")
            document_digest.update(chunk)

    if actual_bytes != expected_bytes:
        raise ValueError("document byte count does not match")
    if report["document"]["sha256"] != document_digest.hexdigest():
        raise ValueError("document digest does not match")
    return report


def _nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return parsed


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("document", type=Path)
    parser.add_argument("schema", type=Path)
    parser.add_argument(
        "--max-exploitable",
        type=_nonnegative_integer,
        help="Reject reports whose exploitable count exceeds this value.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = validate_execution_report(args.report, args.document, args.schema)
    except (OSError, UnicodeError, ValueError, SchemaError, ValidationError) as exc:
        print(
            f"execution report validation failed: {_validation_error_message(exc)}",
            file=sys.stderr,
        )
        return 2
    exploitable = report["analysis_state_counts"].get("exploitable", 0)
    if args.max_exploitable is not None and exploitable > args.max_exploitable:
        print(
            f"execution report rejected: exploitable count {exploitable} "
            f"exceeds maximum {args.max_exploitable}",
            file=sys.stderr,
        )
        return 1
    print("execution report verified")
    return 0


def _validation_error_message(
    error: OSError | UnicodeError | ValueError | SchemaError | ValidationError,
) -> str:
    if isinstance(error, ValidationError):
        return "execution report does not match the reviewed schema"
    if isinstance(error, SchemaError):
        return "reviewed execution report schema is invalid"
    if isinstance(error, OSError):
        return "could not read an input file"
    if isinstance(error, UnicodeError):
        return "an input file is not valid UTF-8"
    if isinstance(error, json.JSONDecodeError):
        return "an input file is not valid JSON"
    return str(error)


if __name__ == "__main__":
    raise SystemExit(main())
