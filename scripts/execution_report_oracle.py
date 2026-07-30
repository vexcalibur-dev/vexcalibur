"""Independent execution-report validation for release publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

MAX_EXECUTION_REPORT_BYTES = 16 * 1024
MAX_GENERATED_DOCUMENT_BYTES = 25 * 1024 * 1024
MAX_FINDINGS_BYTES = 5 * 1024 * 1024
MAX_PUBLICATION_MANIFEST_BYTES = 64 * 1024
MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COMPONENTS = 10_000
MAX_COMPONENT_DEPTH = 50
MAX_REPORT_COUNT = 10_000_000
REPORT_KEYS = {
    "analysis_state_counts",
    "command",
    "component_count",
    "document",
    "finding_count",
    "finding_source",
    "inventory_source",
    "output_format",
    "schema_version",
    "vexcalibur_version",
}
DOCUMENT_KEYS = {"bytes", "sha256"}
MANIFEST_KEYS = {
    "artifacts",
    "inventory",
    "inventory_kind",
    "release",
    "review",
    "schema_version",
    "source_tree_clean",
    "uv_version",
}
RELEASE_KEYS = {
    "commit",
    "purl",
    "source_date_epoch",
    "timestamp",
    "version",
}
ANALYSIS_STATES = {
    "resolved",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)


class ExecutionReportOracleError(ValueError):
    """Raised when release evidence contains an invalid execution report."""


class _ValidationError(Protocol):
    absolute_path: Iterable[object]
    message: str


class ReportSchemaValidator(Protocol):
    """Structural validator used by the independent publication oracle."""

    def iter_errors(self, instance: object) -> Iterable[_ValidationError]:
        """Return schema errors for one report candidate."""


def canonical_execution_report_json(document: object) -> str:
    """Serialize one report according to the public canonical byte contract."""
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def execution_report_schema_validator(schema_path: Path) -> ReportSchemaValidator:
    """Load and validate the checked-in report schema."""
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
    except ImportError as exc:
        raise ExecutionReportOracleError(
            "execution report publication validation requires the locked jsonschema dependency"
        ) from exc

    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionReportOracleError(f"could not load execution report schema: {exc}") from exc
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ExecutionReportOracleError(
            f"execution report schema is invalid: {exc.message}"
        ) from exc
    return Draft202012Validator(schema)


def validate_execution_report_document(
    document: object,
    *,
    validator: ReportSchemaValidator,
) -> dict[str, object]:
    """Validate schema and cross-field integer invariants."""
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "report"
        raise ExecutionReportOracleError(
            f"execution report schema violation at {location}: {first.message}"
        )
    report = _require_dict(document, field="execution report")
    state_counts = _require_dict(
        report.get("analysis_state_counts"),
        field="execution report analysis_state_counts",
    )
    for field in ("schema_version", "component_count", "finding_count"):
        if type(report.get(field)) is not int:
            raise ExecutionReportOracleError(f"execution report {field} must be an integer")
    document_metadata = _require_dict(
        report.get("document"),
        field="execution report document",
    )
    if type(document_metadata.get("bytes")) is not int:
        raise ExecutionReportOracleError("execution report document bytes must be an integer")
    counts: list[int] = []
    for count in state_counts.values():
        if type(count) is not int:
            raise ExecutionReportOracleError(
                "execution report analysis-state counts must be integers"
            )
        counts.append(count)
    if sum(counts) != report.get("finding_count"):
        raise ExecutionReportOracleError(
            "execution report analysis-state counts do not sum to finding count"
        )
    return report


def load_execution_report(
    path: Path,
    *,
    validator: ReportSchemaValidator,
    max_bytes: int,
) -> dict[str, object]:
    """Read one bounded canonical report and validate it independently."""
    raw = read_bounded_regular_file(
        path,
        max_bytes=max_bytes,
        field="execution report",
    )
    document = _decode_json(raw, field=f"execution report {path}")
    if raw != canonical_execution_report_json(document).encode("ascii"):
        raise ExecutionReportOracleError(f"execution report is not canonical JSON: {path}")
    return validate_execution_report_document(document, validator=validator)


def read_bounded_regular_file(
    path: Path,
    *,
    max_bytes: int,
    field: str,
) -> bytes:
    """Read a bounded regular file without following a final symlink."""
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExecutionReportOracleError(f"could not open {field} {path}: {exc}") from exc
    try:
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise ExecutionReportOracleError(f"expected a regular, non-symlink {field}: {path}")
        if file_status.st_size > max_bytes:
            raise ExecutionReportOracleError(f"{field} exceeds the {max_bytes} byte limit: {path}")
        raw = _read_bounded(descriptor, max_bytes=max_bytes)
    except OSError as exc:
        raise ExecutionReportOracleError(f"could not read {field} {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if len(raw) > max_bytes:
        raise ExecutionReportOracleError(f"{field} exceeds the {max_bytes} byte limit: {path}")
    return raw


class _NoSchemaValidator:
    def iter_errors(self, instance: object) -> Iterable[_ValidationError]:
        del instance
        return ()


def verify_action_generation(
    *,
    report_path: Path,
    document_path: Path,
    findings_path: Path,
    sbom_path: Path,
    expected_version: str,
) -> None:
    """Verify one candidate Action result against fresh trusted inputs."""
    document_bytes = read_bounded_regular_file(
        document_path,
        max_bytes=MAX_GENERATED_DOCUMENT_BYTES,
        field="generated document",
    )
    report = load_execution_report(
        report_path,
        validator=_NoSchemaValidator(),
        max_bytes=MAX_EXECUTION_REPORT_BYTES,
    )
    _require_exact_fields(report, REPORT_KEYS, field="execution report")
    _require_exact_int(
        report.get("schema_version"),
        field="schema_version",
        minimum=1,
        maximum=1,
    )
    _require_equal(report.get("command"), "generate", field="command")
    _require_equal(
        report.get("vexcalibur_version"),
        expected_version,
        field="vexcalibur_version",
    )
    _require_equal(report.get("inventory_source"), "sbom_file", field="inventory_source")
    _require_equal(report.get("finding_source"), "local_file", field="finding_source")
    _require_equal(report.get("output_format"), "cyclonedx", field="output_format")

    component_count = _require_exact_int(
        report.get("component_count"),
        field="component_count",
        minimum=0,
        maximum=MAX_REPORT_COUNT,
    )
    finding_count = _require_exact_int(
        report.get("finding_count"),
        field="finding_count",
        minimum=0,
        maximum=MAX_REPORT_COUNT,
    )
    state_counts = _require_dict(
        report.get("analysis_state_counts"),
        field="analysis_state_counts",
    )
    if not set(state_counts).issubset(ANALYSIS_STATES):
        raise ExecutionReportOracleError("analysis_state_counts has an unknown state")
    validated_state_counts = {
        state: _require_exact_int(
            count,
            field=f"analysis_state_counts.{state}",
            minimum=1,
            maximum=MAX_REPORT_COUNT,
        )
        for state, count in state_counts.items()
    }
    if sum(validated_state_counts.values()) != finding_count:
        raise ExecutionReportOracleError("analysis_state_counts does not sum to finding_count")

    document_metadata = _require_dict(report.get("document"), field="document")
    _require_exact_fields(document_metadata, DOCUMENT_KEYS, field="document")
    digest = document_metadata.get("sha256")
    if type(digest) is not str or SHA256_PATTERN.fullmatch(digest) is None:
        raise ExecutionReportOracleError("document.sha256 is not a lowercase SHA-256")
    document_size = _require_exact_int(
        document_metadata.get("bytes"),
        field="document.bytes",
        minimum=0,
        maximum=MAX_GENERATED_DOCUMENT_BYTES,
    )
    if document_size != len(document_bytes):
        raise ExecutionReportOracleError("document.bytes does not match the generated file")
    if digest != hashlib.sha256(document_bytes).hexdigest():
        raise ExecutionReportOracleError("document.sha256 does not match the generated file")

    findings_document = _load_bounded_json(
        findings_path,
        max_bytes=MAX_FINDINGS_BYTES,
        field="findings input",
    )
    findings_object = _require_dict(findings_document, field="findings input")
    _require_exact_fields(findings_object, {"findings"}, field="findings input")
    findings = findings_object.get("findings")
    if type(findings) is not list:
        raise ExecutionReportOracleError("findings input must contain a list")
    expected_states: Counter[str] = Counter()
    for item in findings:
        finding = _require_dict(item, field="finding")
        state = finding.get("analysis_state")
        if type(state) is not str or state not in ANALYSIS_STATES:
            raise ExecutionReportOracleError("finding has an invalid analysis_state")
        expected_states[state] += 1
    if finding_count != len(findings):
        raise ExecutionReportOracleError("finding_count does not match the findings input")
    expected_state_counts = {
        state: expected_states[state]
        for state in (
            "resolved",
            "exploitable",
            "in_triage",
            "false_positive",
            "not_affected",
        )
        if expected_states[state]
    }
    if validated_state_counts != expected_state_counts:
        raise ExecutionReportOracleError("analysis_state_counts does not match the findings input")

    sbom_document = _load_bounded_json(
        sbom_path,
        max_bytes=MAX_SBOM_BYTES,
        field="SBOM input",
    )
    expected_components = _component_identity_count(sbom_document)
    if component_count != expected_components:
        raise ExecutionReportOracleError("component_count does not match the SBOM input")

    output = _require_dict(
        _decode_json(document_bytes, field="generated document"),
        field="generated document",
    )
    _require_equal(output.get("bomFormat"), "CycloneDX", field="generated bomFormat")


def verify_publication_manifest(
    *,
    manifest_path: Path,
    expected_sha: str,
    expected_version: str,
    expected_timestamp: str,
) -> None:
    """Bind a fresh publication inventory to the requested release inputs."""
    manifest = _require_dict(
        _load_bounded_json(
            manifest_path,
            max_bytes=MAX_PUBLICATION_MANIFEST_BYTES,
            field="publication manifest",
        ),
        field="publication manifest",
    )
    _require_exact_fields(manifest, MANIFEST_KEYS, field="publication manifest")
    _require_exact_int(
        manifest.get("schema_version"),
        field="publication manifest schema_version",
        minimum=1,
        maximum=1,
    )
    _require_equal(
        manifest.get("inventory_kind"),
        "publication_oracle",
        field="publication manifest inventory_kind",
    )
    if manifest.get("source_tree_clean") is not True:
        raise ExecutionReportOracleError("publication manifest source_tree_clean must be true")

    if re.fullmatch(r"[0-9a-f]{40}", expected_sha, re.ASCII) is None:
        raise ExecutionReportOracleError(
            "expected release SHA must be a lowercase 40-character commit"
        )
    release = _require_dict(
        manifest.get("release"),
        field="publication manifest release",
    )
    _require_exact_fields(release, RELEASE_KEYS, field="publication manifest release")
    _require_equal(release.get("commit"), expected_sha, field="release commit")
    _require_equal(release.get("version"), expected_version, field="release version")
    _require_equal(
        release.get("timestamp"),
        expected_timestamp,
        field="release timestamp",
    )
    _require_equal(
        release.get("purl"),
        f"pkg:pypi/vexcalibur@{expected_version}",
        field="release purl",
    )
    _require_exact_int(
        release.get("source_date_epoch"),
        field="release source_date_epoch",
        minimum=0,
        maximum=2**63 - 1,
    )


def _load_bounded_json(path: Path, *, max_bytes: int, field: str) -> object:
    raw = read_bounded_regular_file(path, max_bytes=max_bytes, field=field)
    return _decode_json(raw, field=field)


def _decode_json(raw: bytes, *, field: str) -> object:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionReportOracleError(f"{field} is not valid UTF-8 JSON: {exc}") from exc


def _component_identity_count(document: object) -> int:
    sbom = _require_dict(document, field="SBOM input")
    roots = _require_list(sbom.get("components", []), field="SBOM components")
    metadata = _require_dict(sbom.get("metadata", {}), field="SBOM metadata")
    metadata_component = metadata.get("component")
    stack = [(component, 1) for component in roots]
    if metadata_component is not None:
        stack.append((metadata_component, 1))
    identities: set[tuple[str, str]] = set()
    processed = 0
    while stack:
        raw_component, depth = stack.pop()
        if depth > MAX_COMPONENT_DEPTH:
            raise ExecutionReportOracleError("SBOM components exceed the nesting limit")
        component = _require_dict(raw_component, field="SBOM component")
        processed += 1
        if processed > MAX_COMPONENTS:
            raise ExecutionReportOracleError("SBOM exceeds the component limit")
        children = _require_list(
            component.get("components", []),
            field="nested SBOM components",
        )
        stack.extend((child, depth + 1) for child in children)
        purl = component.get("purl")
        if purl is None:
            continue
        if type(purl) is not str or not purl:
            raise ExecutionReportOracleError("SBOM component purl must be a string")
        reference = component.get("bom-ref", purl)
        if type(reference) is not str or not reference:
            raise ExecutionReportOracleError("SBOM component bom-ref must be a string")
        identities.add((reference, purl))
    if not identities:
        raise ExecutionReportOracleError("SBOM contains no reportable component identities")
    return len(identities)


def _read_bounded(descriptor: int, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _object_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionReportOracleError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _require_dict(value: object, *, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ExecutionReportOracleError(f"{field} must be an object")
    return value


def _require_list(value: object, *, field: str) -> list[object]:
    if type(value) is not list:
        raise ExecutionReportOracleError(f"{field} must be an array")
    return value


def _require_exact_fields(
    value: dict[str, object],
    expected: set[str],
    *,
    field: str,
) -> None:
    if set(value) != expected:
        raise ExecutionReportOracleError(f"{field} has invalid fields")


def _require_exact_int(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ExecutionReportOracleError(
            f"{field} must be an integer from {minimum} through {maximum}"
        )
    return value


def _require_equal(value: object, expected: str, *, field: str) -> None:
    if type(value) is not str or value != expected:
        raise ExecutionReportOracleError(f"{field} has an unexpected value")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--document", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-timestamp", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        verify_publication_manifest(
            manifest_path=args.manifest,
            expected_sha=args.expected_sha,
            expected_version=args.expected_version,
            expected_timestamp=args.expected_timestamp,
        )
        verify_action_generation(
            report_path=args.report,
            document_path=args.document,
            findings_path=args.findings,
            sbom_path=args.sbom,
            expected_version=args.expected_version,
        )
    except ExecutionReportOracleError as error:
        print(f"execution report oracle error: {error}", file=sys.stderr)
        return 2
    print("candidate Action execution report verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
