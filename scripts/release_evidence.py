#!/usr/bin/env python3
"""Build and verify deterministic Vexcalibur self-release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from packageurl import PackageURL

MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_WHEEL_SCM_METADATA_BYTES = 64 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GROUPED_SHA256_PATTERN = re.compile(r"^(?:[0-9a-f]{16}:){3}[0-9a-f]{16}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SCM_NODE_PATTERN = re.compile(r"^g?([0-9a-f]{40})$")
SCM_METADATA_MEMBER_PATTERN = re.compile(r"^vexcalibur-[^/]+\.dist-info/scm_version\.json$")
WHEEL_METADATA_MEMBER_PATTERN = re.compile(r"^vexcalibur-[^/]+\.dist-info/METADATA$")
RFC3339_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
CHECKSUM_LINE_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)$")
ORIGINAL_STATE_PATTERN = re.compile(
    r"(?:^|\n)Original Vexcalibur analysis state: "
    r"(resolved|exploitable|in_triage|false_positive|not_affected)(?:\n|$)"
)
ALLOWED_PRODUCTION_STATES = ("in_triage",)
REVIEW_KEYS = {
    "schema_version",
    "review_kind",
    "analysis_revision",
    "reviewed_at",
    "reviewed_by",
    "inventory",
    "findings",
    "policy",
    "conclusion",
}
OPENVEX_STATUS_BY_STATE = {
    "resolved": "fixed",
    "exploitable": "affected",
    "in_triage": "under_investigation",
    "false_positive": "not_affected",
    "not_affected": "not_affected",
}
CSAF_STATUS_BY_STATE = {
    "resolved": "fixed",
    "exploitable": "known_affected",
    "in_triage": "under_investigation",
    "false_positive": "known_not_affected",
    "not_affected": "known_not_affected",
}


class EvidenceError(ValueError):
    """Raised when release evidence violates its checked contract."""


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one regular file."""
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"expected a regular, non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    """Read bounded UTF-8 JSON while rejecting duplicate object keys."""
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"expected a regular, non-symlink JSON file: {path}")
    size = path.stat().st_size
    if size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceError(f"evidence JSON exceeds {MAX_EVIDENCE_FILE_BYTES} bytes: {path}")
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(f"could not read UTF-8 JSON {path}: {exc}") from exc
    try:
        return json.loads(contents, object_pairs_hook=_object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid JSON {path}: {exc}") from exc


def validate_wheel_source(wheel_path: Path, *, release_sha: str) -> str:
    """Require wheel SCM metadata for the exact clean release commit."""
    if COMMIT_PATTERN.fullmatch(release_sha) is None:
        raise EvidenceError("release SHA must be a lowercase 40-character Git commit")
    if not wheel_path.is_file() or wheel_path.is_symlink():
        raise EvidenceError(f"expected a regular, non-symlink wheel: {wheel_path}")

    try:
        with zipfile.ZipFile(wheel_path) as wheel:
            distribution_metadata = [
                member
                for member in wheel.infolist()
                if WHEEL_METADATA_MEMBER_PATTERN.fullmatch(member.filename) is not None
            ]
            if len(distribution_metadata) != 1:
                raise EvidenceError(
                    "wheel must contain exactly one vexcalibur-*.dist-info/METADATA member"
                )
            scm_members = [
                member
                for member in wheel.infolist()
                if SCM_METADATA_MEMBER_PATTERN.fullmatch(member.filename) is not None
            ]
            expected_scm_member = (
                distribution_metadata[0].filename.rsplit("/", maxsplit=1)[0] + "/scm_version.json"
            )
            if len(scm_members) != 1 or scm_members[0].filename != expected_scm_member:
                raise EvidenceError(
                    "wheel must contain exactly one scm_version.json beside its "
                    "Vexcalibur METADATA member"
                )
            member = scm_members[0]
            if member.is_dir() or member.file_size > MAX_WHEEL_SCM_METADATA_BYTES:
                raise EvidenceError("wheel SCM metadata is not a bounded regular member")
            if member.create_system == 3:
                file_type = stat.S_IFMT(member.external_attr >> 16)
                if file_type not in {0, stat.S_IFREG}:
                    raise EvidenceError("wheel SCM metadata is not a bounded regular member")
            with wheel.open(member) as stream:
                raw_metadata = stream.read(MAX_WHEEL_SCM_METADATA_BYTES + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise EvidenceError(f"could not read wheel SCM metadata: {exc}") from exc

    if len(raw_metadata) > MAX_WHEEL_SCM_METADATA_BYTES:
        raise EvidenceError("wheel SCM metadata exceeds the byte limit")
    try:
        metadata = json.loads(
            raw_metadata.decode("utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"wheel SCM metadata is not valid UTF-8 JSON: {exc}") from exc
    metadata_object = _require_dict(metadata, field="wheel SCM metadata")
    node = metadata_object.get("node")
    if not isinstance(node, str) or (match := SCM_NODE_PATTERN.fullmatch(node)) is None:
        raise EvidenceError("wheel SCM node must be a full Git commit with an optional g prefix")
    wheel_commit = match.group(1)
    if wheel_commit != release_sha:
        raise EvidenceError(
            f"wheel SCM commit {wheel_commit} does not match release SHA {release_sha}"
        )
    if metadata_object.get("dirty") is not False:
        raise EvidenceError("wheel SCM metadata must record dirty=false")
    return wheel_commit


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def canonical_json(document: object) -> str:
    """Serialize one canonical, reviewable JSON document."""
    return f"{json.dumps(document, indent=2, sort_keys=True)}\n"


def release_timestamp(source_date_epoch: int) -> str:
    """Return an RFC 3339 UTC timestamp for a release commit epoch."""
    if source_date_epoch < 0:
        raise EvidenceError("SOURCE_DATE_EPOCH must not be negative")
    try:
        value = datetime.fromtimestamp(source_date_epoch, tz=timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise EvidenceError(f"invalid SOURCE_DATE_EPOCH: {source_date_epoch}") from exc
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _release_purl(version: str) -> str:
    stripped = version.strip()
    if not stripped or any(character.isspace() for character in stripped):
        raise EvidenceError("release version must be nonempty and contain no whitespace")
    return f"pkg:pypi/vexcalibur@{quote(stripped, safe='.-_~')}"


def normalize_sbom(
    document: dict[str, Any],
    *,
    release_version: str,
    timestamp: str,
    lock_sha256: str,
) -> dict[str, Any]:
    """Normalize uv's CycloneDX 1.5 export for one exact release."""
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise EvidenceError("uv export must be a CycloneDX 1.5 document")
    if document.get("version") != 1:
        raise EvidenceError("uv export must use CycloneDX document version 1")
    _require_sha256(lock_sha256, name="lock SHA-256")
    _parse_timestamp(timestamp, field="release timestamp")

    metadata = _require_dict(document.get("metadata"), field="metadata")
    root = _require_dict(metadata.get("component"), field="metadata.component")
    if root.get("name") != "vexcalibur":
        raise EvidenceError("uv export metadata component is not vexcalibur")
    old_root_ref = _require_nonempty_string(root.get("bom-ref"), field="metadata.component.bom-ref")
    purl = _release_purl(release_version)

    normalized = json.loads(json.dumps(document))
    normalized.pop("serialNumber", None)
    normalized_metadata = _require_dict(normalized["metadata"], field="metadata")
    normalized_metadata["timestamp"] = timestamp
    normalized_root = _require_dict(normalized_metadata["component"], field="metadata.component")
    normalized_root["bom-ref"] = purl
    normalized_root["version"] = release_version
    normalized_root["purl"] = purl

    properties = normalized_root.setdefault("properties", [])
    if not isinstance(properties, list):
        raise EvidenceError("metadata.component.properties must be an array")
    properties.append(
        {
            "name": "vexcalibur:source:uv-lock-sha256",
            "value": lock_sha256,
        }
    )
    normalized_root["properties"] = _sorted_dict_list(
        properties,
        field="metadata.component.properties",
        keys=("name", "value"),
    )

    tools = normalized_metadata.get("tools", [])
    normalized_metadata["tools"] = _sorted_dict_list(
        tools,
        field="metadata.tools",
        keys=("vendor", "name", "version"),
    )

    components = normalized.get("components", [])
    if not isinstance(components, list):
        raise EvidenceError("components must be an array")
    for index, component in enumerate(components):
        component_object = _require_dict(component, field=f"components[{index}]")
        if "properties" in component_object:
            component_object["properties"] = _sorted_dict_list(
                component_object["properties"],
                field=f"components[{index}].properties",
                keys=("name", "value"),
            )
    normalized["components"] = sorted(
        components,
        key=lambda component: (
            str(component.get("purl", "")),
            str(component.get("name", "")),
            str(component.get("version", "")),
            str(component.get("bom-ref", "")),
        ),
    )

    dependencies = normalized.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise EvidenceError("dependencies must be an array")
    root_dependency_seen = False
    for index, dependency in enumerate(dependencies):
        item = _require_dict(dependency, field=f"dependencies[{index}]")
        if item.get("ref") == old_root_ref:
            item["ref"] = purl
            root_dependency_seen = True
        if "dependsOn" in item:
            depends_on = item["dependsOn"]
            if not isinstance(depends_on, list) or not all(
                isinstance(value, str) for value in depends_on
            ):
                raise EvidenceError(f"dependencies[{index}].dependsOn must contain strings")
            item["dependsOn"] = sorted(set(depends_on))
    if not root_dependency_seen:
        raise EvidenceError("uv export has no dependency entry for the root project")
    normalized["dependencies"] = sorted(dependencies, key=lambda item: str(item.get("ref", "")))
    return normalized


def _sorted_dict_list(value: Any, *, field: str, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise EvidenceError(f"{field} must be an array")
    objects = [_require_dict(item, field=f"{field}[{index}]") for index, item in enumerate(value)]
    return sorted(objects, key=lambda item: tuple(str(item.get(key, "")) for key in keys))


def validate_review(
    review: dict[str, Any],
    findings_document: dict[str, Any],
    *,
    lock_path: Path,
    findings_path: Path,
    allow_synthetic: bool = False,
) -> tuple[str, tuple[dict[str, Any], ...]]:
    """Validate review binding and the intentionally narrow assertion policy."""
    if set(review) != REVIEW_KEYS:
        raise EvidenceError(
            f"review keys must be exactly {sorted(REVIEW_KEYS)!r}; got {sorted(review)!r}"
        )
    if review.get("schema_version") != 1:
        raise EvidenceError("review schema_version must be 1")
    review_kind = review.get("review_kind")
    if review_kind not in {"production", "synthetic_fixture"}:
        raise EvidenceError("review_kind must be production or synthetic_fixture")
    if review_kind == "synthetic_fixture" and not allow_synthetic:
        raise EvidenceError("synthetic review requires explicit --allow-synthetic")
    revision = review.get("analysis_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise EvidenceError("analysis_revision must be a positive integer")
    _parse_timestamp(review.get("reviewed_at"), field="reviewed_at")
    _require_nonempty_string(review.get("reviewed_by"), field="reviewed_by")
    _require_nonempty_string(review.get("conclusion"), field="conclusion")

    inventory = _require_dict(review.get("inventory"), field="inventory")
    if set(inventory) != {"path", "sha256", "coverage"}:
        raise EvidenceError("inventory must contain only path, sha256, and coverage")
    if inventory.get("path") != "uv.lock":
        raise EvidenceError("review inventory path must be uv.lock")
    if inventory.get("coverage") != "cross-platform-reference-runtime":
        raise EvidenceError("review inventory coverage must be cross-platform-reference-runtime")
    expected_lock_digest = _require_grouped_sha256(inventory.get("sha256"), name="inventory.sha256")
    if sha256_file(lock_path) != expected_lock_digest:
        raise EvidenceError("review inventory SHA-256 does not match uv.lock")

    findings_binding = _require_dict(review.get("findings"), field="findings")
    if set(findings_binding) != {"path", "sha256"}:
        raise EvidenceError("findings binding must contain only path and sha256")
    expected_findings_path = (
        "release-evidence/findings.json"
        if review_kind == "production"
        else "tests/fixtures/release-evidence/findings.json"
    )
    if findings_binding.get("path") != expected_findings_path:
        raise EvidenceError(f"{review_kind} findings path must be {expected_findings_path}")
    expected_findings_digest = _require_grouped_sha256(
        findings_binding.get("sha256"), name="findings.sha256"
    )
    if sha256_file(findings_path) != expected_findings_digest:
        raise EvidenceError("review findings SHA-256 does not match the findings file")

    policy = _require_dict(review.get("policy"), field="policy")
    if set(policy) != {"allowed_analysis_states"}:
        raise EvidenceError("policy must contain only allowed_analysis_states")
    if policy.get("allowed_analysis_states") != list(ALLOWED_PRODUCTION_STATES):
        raise EvidenceError("release evidence policy must allow only in_triage")

    if set(findings_document) != {"findings"}:
        raise EvidenceError("findings document must contain only the findings array")
    raw_findings = findings_document.get("findings")
    if not isinstance(raw_findings, list):
        raise EvidenceError("findings must be an array")
    findings: list[dict[str, Any]] = []
    assertion_keys: set[tuple[str, str, str]] = set()
    for index, raw_finding in enumerate(raw_findings):
        finding = _require_dict(raw_finding, field=f"findings[{index}]")
        if finding.get("analysis_state") != "in_triage":
            raise EvidenceError(
                f"findings[{index}].analysis_state must be explicitly set to in_triage"
            )
        vulnerability_id = _require_nonempty_string(
            finding.get("id"), field=f"findings[{index}].id"
        )
        component_ref = finding.get("component_ref")
        purl = finding.get("purl")
        if component_ref is not None and (
            not isinstance(component_ref, str) or not component_ref.strip()
        ):
            raise EvidenceError(f"findings[{index}].component_ref must be a nonempty string")
        if purl is not None and (not isinstance(purl, str) or not purl.strip()):
            raise EvidenceError(f"findings[{index}].purl must be a nonempty string")
        if (component_ref is None) == (purl is None):
            raise EvidenceError(
                f"findings[{index}] must identify exactly one component_ref or purl"
            )
        if purl is not None:
            try:
                selector = ("purl", PackageURL.from_string(purl).to_string())
            except ValueError as exc:
                raise EvidenceError(f"findings[{index}].purl is invalid: {exc}") from exc
        else:
            assert isinstance(component_ref, str)
            selector = ("component_ref", component_ref)
        assertion_key = (vulnerability_id, *selector)
        if assertion_key in assertion_keys:
            raise EvidenceError(f"duplicate reviewed assertion: {assertion_key!r}")
        assertion_keys.add(assertion_key)
        findings.append(finding)
    return str(review_kind), tuple(findings)


def compare_vex_formats(
    cyclonedx: dict[str, Any], openvex: dict[str, Any], csaf: dict[str, Any]
) -> set[tuple[str, str, str]]:
    """Require equivalent vulnerability, product, and state assertions in all formats."""
    assertions = {
        "CycloneDX": _cyclonedx_assertions(cyclonedx),
        "OpenVEX": _openvex_assertions(openvex),
        "CSAF": _csaf_assertions(csaf),
    }
    if not assertions["CycloneDX"]:
        raise EvidenceError("cross-format fixture must contain at least one assertion")
    baseline = assertions["CycloneDX"]
    for format_name, candidate in assertions.items():
        if candidate != baseline:
            raise EvidenceError(
                f"{format_name} assertions differ from CycloneDX: "
                f"expected {sorted(baseline)!r}, got {sorted(candidate)!r}"
            )
    return baseline


def _cyclonedx_assertions(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    component_by_ref = {
        _require_nonempty_string(
            component.get("bom-ref"), field="CycloneDX component bom-ref"
        ): _require_nonempty_string(component.get("purl"), field="CycloneDX component purl")
        for component in _dict_items(document.get("components", []), field="CycloneDX components")
    }
    records: list[tuple[str, str, str]] = []
    for vulnerability in _dict_items(
        document.get("vulnerabilities", []), field="CycloneDX vulnerabilities"
    ):
        vulnerability_id = _require_nonempty_string(
            vulnerability.get("id"), field="CycloneDX vulnerability id"
        )
        analysis = _require_dict(
            vulnerability.get("analysis"), field="CycloneDX vulnerability analysis"
        )
        state = _require_nonempty_string(
            analysis.get("state"), field="CycloneDX vulnerability analysis state"
        )
        for affect in _dict_items(
            vulnerability.get("affects", []), field="CycloneDX vulnerability affects"
        ):
            ref = _require_nonempty_string(affect.get("ref"), field="CycloneDX affect ref")
            try:
                purl = component_by_ref[ref]
            except KeyError as exc:
                raise EvidenceError(
                    f"CycloneDX affect references unknown component {ref!r}"
                ) from exc
            records.append((vulnerability_id, purl, state))
    return _unique_assertions(records, format_name="CycloneDX")


def _openvex_assertions(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    for statement in _dict_items(document.get("statements", []), field="OpenVEX statements"):
        vulnerability = _require_dict(
            statement.get("vulnerability"), field="OpenVEX statement vulnerability"
        )
        vulnerability_id = _require_nonempty_string(
            vulnerability.get("name"), field="OpenVEX vulnerability name"
        )
        notes = _require_nonempty_string(
            statement.get("status_notes"), field="OpenVEX status_notes"
        )
        state = _state_from_notes(notes, field="OpenVEX status_notes")
        status = _require_nonempty_string(statement.get("status"), field="OpenVEX status")
        if status != OPENVEX_STATUS_BY_STATE[state]:
            raise EvidenceError(f"OpenVEX status {status!r} does not match state {state!r}")
        for product in _dict_items(statement.get("products", []), field="OpenVEX products"):
            identifiers = _require_dict(
                product.get("identifiers"), field="OpenVEX product identifiers"
            )
            purl = _require_nonempty_string(identifiers.get("purl"), field="OpenVEX product purl")
            records.append((vulnerability_id, purl, state))
    return _unique_assertions(records, format_name="OpenVEX")


def _csaf_assertions(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    product_tree = _require_dict(document.get("product_tree"), field="CSAF product_tree")
    product_by_id: dict[str, str] = {}
    for product in _dict_items(
        product_tree.get("full_product_names", []), field="CSAF full_product_names"
    ):
        product_id = _require_nonempty_string(product.get("product_id"), field="CSAF product_id")
        helper = _require_dict(
            product.get("product_identification_helper"), field="CSAF product helper"
        )
        product_by_id[product_id] = _require_nonempty_string(
            helper.get("purl"), field="CSAF product purl"
        )

    records: list[tuple[str, str, str]] = []
    for vulnerability in _dict_items(
        document.get("vulnerabilities", []), field="CSAF vulnerabilities"
    ):
        vulnerability_id = _require_nonempty_string(vulnerability.get("cve"), field="CSAF cve")
        notes = "\n".join(
            _require_nonempty_string(note.get("text"), field="CSAF note text")
            for note in _dict_items(vulnerability.get("notes", []), field="CSAF notes")
        )
        state = _state_from_notes(notes, field="CSAF notes")
        product_status = _require_dict(
            vulnerability.get("product_status"), field="CSAF product_status"
        )
        expected_status = CSAF_STATUS_BY_STATE[state]
        if set(product_status) != {expected_status}:
            raise EvidenceError(
                f"CSAF product status {sorted(product_status)!r} does not match state {state!r}"
            )
        product_ids = product_status[expected_status]
        if not isinstance(product_ids, list) or not product_ids:
            raise EvidenceError("CSAF product status must contain product IDs")
        for product_id in product_ids:
            if not isinstance(product_id, str) or product_id not in product_by_id:
                raise EvidenceError(f"CSAF references unknown product ID {product_id!r}")
            records.append((vulnerability_id, product_by_id[product_id], state))
    return _unique_assertions(records, format_name="CSAF")


def _state_from_notes(notes: str, *, field: str) -> str:
    match = ORIGINAL_STATE_PATTERN.search(notes)
    if match is None:
        raise EvidenceError(f"{field} does not preserve the original Vexcalibur state")
    return match.group(1)


def _unique_assertions(
    records: list[tuple[str, str, str]], *, format_name: str
) -> set[tuple[str, str, str]]:
    unique = set(records)
    if len(unique) != len(records):
        raise EvidenceError(f"{format_name} contains duplicate assertions")
    return unique


def build_manifest(
    *,
    bundle_dir: Path,
    release_sha: str,
    release_version: str,
    source_date_epoch: int,
    lock_path: Path,
    wheel_path: Path,
    review_path: Path,
    findings_path: Path,
    uv_version: str,
    source_tree_clean: bool,
) -> dict[str, Any]:
    """Build the bundle manifest after all applicable validators pass."""
    if COMMIT_PATTERN.fullmatch(release_sha) is None:
        raise EvidenceError("release SHA must be a lowercase 40-character Git commit")
    timestamp = release_timestamp(source_date_epoch)
    review = _require_dict(load_json(review_path), field="review")
    findings_document = _require_dict(load_json(findings_path), field="findings document")
    review_kind, findings = validate_review(
        review,
        findings_document,
        lock_path=lock_path,
        findings_path=findings_path,
        allow_synthetic=True,
    )
    state_counts = dict(sorted(Counter(str(item["analysis_state"]) for item in findings).items()))
    assertion_count = len(findings)
    wheel_source_commit = validate_wheel_source(wheel_path, release_sha=release_sha)

    files = _bundle_files(bundle_dir, excluded={"manifest.json", "SHA256SUMS"})
    expected_names = {
        "findings.json",
        "review.json",
        "runtime-constraints.txt",
        "sbom.cdx.json",
        "vex.cdx.json",
    }
    if assertion_count > 0:
        expected_names.update({"vex.openvex.json", "vexcalibur-vex.json"})
    actual_names = {path.name for path in files}
    if actual_names != expected_names:
        raise EvidenceError(
            f"bundle files differ from the evidence contract: "
            f"{sorted(actual_names)!r} != {sorted(expected_names)!r}"
        )
    cyclonedx_assertions = _cyclonedx_assertions(
        _require_dict(load_json(bundle_dir / "vex.cdx.json"), field="CycloneDX VEX")
    )
    if len(cyclonedx_assertions) != assertion_count:
        raise EvidenceError(
            "reviewed assertion count does not match canonical CycloneDX output: "
            f"{assertion_count} != {len(cyclonedx_assertions)}"
        )
    artifact_records = [
        {"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}
        for path in files
    ]

    formats: dict[str, dict[str, Any]] = {
        "cyclonedx": {
            "artifact": "vex.cdx.json",
            "assertion_count": assertion_count,
            "conformance": "CycloneDX 1.6 schema passed",
            "status": "generated",
        }
    }
    omitted_formats: list[dict[str, str]] = []
    if assertion_count == 0:
        for format_name, specification in (
            ("openvex", "OpenVEX 0.2.0"),
            ("csaf", "CSAF 2.0 VEX profile"),
        ):
            reason = (
                f"{specification} requires at least one vulnerability finding; "
                "this reviewed snapshot contains zero findings and makes zero VEX assertions."
            )
            formats[format_name] = {"reason": reason, "status": "omitted"}
            omitted_formats.append({"format": format_name, "reason": reason})
        cross_format_validation = "not_applicable_without_assertions"
    else:
        formats["openvex"] = {
            "artifact": "vex.openvex.json",
            "assertion_count": assertion_count,
            "conformance": "official OpenVEX Go parser passed",
            "status": "generated",
        }
        formats["csaf"] = {
            "artifact": "vexcalibur-vex.json",
            "assertion_count": assertion_count,
            "conformance": "CSAF 2.0 strict schema and mandatory tests passed",
            "status": "generated",
        }
        cross_format_validation = "passed"

    return {
        "schema_version": 1,
        "evidence_kind": review_kind,
        "intended_use": (
            "release_evidence_candidate" if review_kind == "production" else "ci_conformance_only"
        ),
        "source_tree_clean": source_tree_clean,
        "release": {
            "commit": release_sha,
            "purl": _release_purl(release_version),
            "source_date_epoch": source_date_epoch,
            "timestamp": timestamp,
            "version": release_version,
        },
        "inventory": {
            "coverage": "cross-platform-reference-runtime",
            "limitation": (
                "uv.lock records the project's cross-platform reference runtime; it is not a "
                "claim about every environment-specific consumer resolution."
            ),
            "lock_sha256": sha256_file(lock_path),
            "sbom": "sbom.cdx.json",
            "sbom_specification": "CycloneDX 1.5",
        },
        "generator": {
            "distribution": "vexcalibur",
            "version": release_version,
            "wheel_filename": wheel_path.name,
            "wheel_sha256": sha256_file(wheel_path),
            "wheel_source_commit": wheel_source_commit,
            "wheel_source_dirty": False,
            "uv_version": uv_version,
        },
        "review": {
            "analysis_revision": review["analysis_revision"],
            "assertion_count": assertion_count,
            "conclusion": review["conclusion"],
            "findings_sha256": sha256_file(findings_path),
            "review_sha256": sha256_file(review_path),
            "state_counts": state_counts,
        },
        "formats": formats,
        "omitted_formats": omitted_formats,
        "validation": {
            "cross_format_assertion_equivalence": cross_format_validation,
            "installed_local_wheel": "passed",
            "network_during_generation": "disabled_by_offline_local_findings_mode",
            "production_state_policy": "only_in_triage",
            "sbom_cyclonedx_1_5_schema": "passed",
            "vex_cyclonedx_1_6_schema": "passed",
        },
        "artifacts": artifact_records,
    }


def write_checksums(bundle_dir: Path) -> None:
    """Write sorted SHA256SUMS for every bundle file except SHA256SUMS itself."""
    files = _bundle_files(bundle_dir, excluded={"SHA256SUMS"})
    lines = [f"{sha256_file(path)}  {path.name}" for path in files]
    (bundle_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_bundle(bundle_dir: Path) -> None:
    """Verify sorted checksums and manifest artifact records."""
    checksum_path = bundle_dir / "SHA256SUMS"
    if not checksum_path.is_file() or checksum_path.is_symlink():
        raise EvidenceError("bundle has no regular SHA256SUMS file")
    if checksum_path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceError("SHA256SUMS exceeds the evidence byte limit")
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(f"could not read SHA256SUMS: {exc}") from exc
    expected_names = {path.name for path in _bundle_files(bundle_dir, excluded={"SHA256SUMS"})}
    checksums: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            raise EvidenceError(f"invalid SHA256SUMS line: {line!r}")
        digest, filename = match.groups()
        if filename in checksums:
            raise EvidenceError(f"duplicate SHA256SUMS entry: {filename}")
        checksums[filename] = digest
    if list(checksums) != sorted(checksums):
        raise EvidenceError("SHA256SUMS entries are not sorted by filename")
    if set(checksums) != expected_names:
        raise EvidenceError(
            f"SHA256SUMS file set differs from bundle: {sorted(checksums)!r} "
            f"!= {sorted(expected_names)!r}"
        )
    for filename, digest in checksums.items():
        if sha256_file(bundle_dir / filename) != digest:
            raise EvidenceError(f"SHA256SUMS digest mismatch for {filename}")

    manifest = _require_dict(load_json(bundle_dir / "manifest.json"), field="manifest")
    artifact_records = manifest.get("artifacts")
    if not isinstance(artifact_records, list):
        raise EvidenceError("manifest artifacts must be an array")
    manifest_artifacts: dict[str, tuple[str, int]] = {}
    for index, record in enumerate(artifact_records):
        item = _require_dict(record, field=f"manifest artifacts[{index}]")
        if set(item) != {"name", "sha256", "size"}:
            raise EvidenceError(
                f"manifest artifacts[{index}] must contain only name, sha256, and size"
            )
        filename = _require_nonempty_string(item.get("name"), field="artifact name")
        if filename in manifest_artifacts:
            raise EvidenceError(f"duplicate manifest artifact record: {filename}")
        digest = _require_sha256(item.get("sha256"), name="artifact sha256")
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceError("manifest artifact size must be a nonnegative integer")
        manifest_artifacts[filename] = (digest, size)
    expected_artifacts = expected_names - {"manifest.json"}
    if set(manifest_artifacts) != expected_artifacts:
        raise EvidenceError("manifest artifact file set differs from bundle")
    for filename, (digest, size) in manifest_artifacts.items():
        if checksums.get(filename) != digest:
            raise EvidenceError(f"manifest artifact digest mismatch for {filename}")
        if (bundle_dir / filename).stat().st_size != size:
            raise EvidenceError(f"manifest artifact size mismatch for {filename}")


def _bundle_files(bundle_dir: Path, *, excluded: set[str]) -> list[Path]:
    if not bundle_dir.is_dir() or bundle_dir.is_symlink():
        raise EvidenceError(f"bundle directory is not a regular directory: {bundle_dir}")
    files: list[Path] = []
    for path in bundle_dir.iterdir():
        if path.name in excluded:
            continue
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"bundle contains a non-regular entry: {path.name}")
        files.append(path)
    return sorted(files, key=lambda path: path.name)


def validate_cyclonedx(path: Path, *, spec_version: str) -> None:
    """Validate a CycloneDX JSON document with the installed schema library."""
    from cyclonedx.output import OutputFormat, SchemaVersion
    from cyclonedx.validation import make_schemabased_validator

    versions = {"1.5": SchemaVersion.V1_5, "1.6": SchemaVersion.V1_6}
    try:
        version = versions[spec_version]
    except KeyError as exc:
        raise EvidenceError(f"unsupported CycloneDX validation version: {spec_version}") from exc
    contents = path.read_text(encoding="utf-8")
    error = make_schemabased_validator(OutputFormat.JSON, version).validate_str(contents)
    if error is not None:
        raise EvidenceError(f"{path} fails the CycloneDX {spec_version} schema: {error}")


def _require_dict(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{field} must be an object")
    return value


def _dict_items(value: Any, *, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise EvidenceError(f"{field} must be an array")
    return [_require_dict(item, field=f"{field}[{index}]") for index, item in enumerate(value)]


def _require_nonempty_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a nonempty string")
    return value


def _require_sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{name} must be a lowercase hexadecimal SHA-256 digest")
    if SHA256_PATTERN.fullmatch(value) is not None:
        return value
    if GROUPED_SHA256_PATTERN.fullmatch(value) is not None:
        return value.replace(":", "")
    raise EvidenceError(
        f"{name} must be 64 lowercase hexadecimal characters, optionally grouped "
        "into four colon-delimited fields"
    )


def _require_grouped_sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or GROUPED_SHA256_PATTERN.fullmatch(value) is None:
        raise EvidenceError(
            f"{name} must be four colon-delimited groups of 16 lowercase hexadecimal characters"
        )
    return value.replace(":", "")


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or RFC3339_UTC_PATTERN.fullmatch(value) is None:
        raise EvidenceError(
            f"{field} must be an RFC 3339 UTC timestamp using T separators and ending in Z"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{field} is not a valid timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise EvidenceError(f"{field} must be in UTC")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    timestamp_parser = subparsers.add_parser("timestamp")
    timestamp_parser.add_argument("--epoch", required=True, type=int)

    normalize_parser = subparsers.add_parser("normalize-sbom")
    normalize_parser.add_argument("--input", required=True, type=Path)
    normalize_parser.add_argument("--output", required=True, type=Path)
    normalize_parser.add_argument("--release-version", required=True)
    normalize_parser.add_argument("--timestamp", required=True)
    normalize_parser.add_argument("--lock-sha256", required=True)

    review_parser = subparsers.add_parser("validate-review")
    review_parser.add_argument("--review", required=True, type=Path)
    review_parser.add_argument("--findings", required=True, type=Path)
    review_parser.add_argument("--lock", required=True, type=Path)
    review_parser.add_argument("--allow-synthetic", action="store_true")

    wheel_parser = subparsers.add_parser("validate-wheel")
    wheel_parser.add_argument("--wheel", required=True, type=Path)
    wheel_parser.add_argument("--release-sha", required=True)

    cyclonedx_parser = subparsers.add_parser("validate-cyclonedx")
    cyclonedx_parser.add_argument("--document", required=True, type=Path)
    cyclonedx_parser.add_argument("--spec-version", required=True, choices=("1.5", "1.6"))

    compare_parser = subparsers.add_parser("compare-formats")
    compare_parser.add_argument("--cyclonedx", required=True, type=Path)
    compare_parser.add_argument("--openvex", required=True, type=Path)
    compare_parser.add_argument("--csaf", required=True, type=Path)

    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--bundle-dir", required=True, type=Path)
    finalize_parser.add_argument("--release-sha", required=True)
    finalize_parser.add_argument("--release-version", required=True)
    finalize_parser.add_argument("--source-date-epoch", required=True, type=int)
    finalize_parser.add_argument("--lock", required=True, type=Path)
    finalize_parser.add_argument("--wheel", required=True, type=Path)
    finalize_parser.add_argument("--review", required=True, type=Path)
    finalize_parser.add_argument("--findings", required=True, type=Path)
    finalize_parser.add_argument("--uv-version", required=True)
    finalize_parser.add_argument("--source-tree-clean", required=True, choices=("true", "false"))

    verify_parser = subparsers.add_parser("verify-bundle")
    verify_parser.add_argument("--bundle-dir", required=True, type=Path)
    return parser


def main() -> None:
    """Run the selected release-evidence operation."""
    args = _parser().parse_args()
    try:
        if args.command == "timestamp":
            print(release_timestamp(args.epoch))
        elif args.command == "normalize-sbom":
            document = _require_dict(load_json(args.input), field="SBOM")
            normalized = normalize_sbom(
                document,
                release_version=args.release_version,
                timestamp=args.timestamp,
                lock_sha256=args.lock_sha256,
            )
            args.output.write_text(canonical_json(normalized), encoding="utf-8")
        elif args.command == "validate-review":
            review = _require_dict(load_json(args.review), field="review")
            findings_document = _require_dict(load_json(args.findings), field="findings document")
            review_kind, findings = validate_review(
                review,
                findings_document,
                lock_path=args.lock,
                findings_path=args.findings,
                allow_synthetic=args.allow_synthetic,
            )
            print(f"{review_kind}\t{len(findings)}")
        elif args.command == "validate-wheel":
            print(validate_wheel_source(args.wheel, release_sha=args.release_sha))
        elif args.command == "validate-cyclonedx":
            validate_cyclonedx(args.document, spec_version=args.spec_version)
        elif args.command == "compare-formats":
            assertions = compare_vex_formats(
                _require_dict(load_json(args.cyclonedx), field="CycloneDX VEX"),
                _require_dict(load_json(args.openvex), field="OpenVEX"),
                _require_dict(load_json(args.csaf), field="CSAF"),
            )
            print(f"validated {len(assertions)} equivalent assertions")
        elif args.command == "finalize":
            manifest = build_manifest(
                bundle_dir=args.bundle_dir,
                release_sha=args.release_sha,
                release_version=args.release_version,
                source_date_epoch=args.source_date_epoch,
                lock_path=args.lock,
                wheel_path=args.wheel,
                review_path=args.review,
                findings_path=args.findings,
                uv_version=args.uv_version,
                source_tree_clean=args.source_tree_clean == "true",
            )
            (args.bundle_dir / "manifest.json").write_text(
                canonical_json(manifest), encoding="utf-8"
            )
            write_checksums(args.bundle_dir)
            verify_bundle(args.bundle_dir)
        elif args.command == "verify-bundle":
            verify_bundle(args.bundle_dir)
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except (EvidenceError, OSError) as exc:
        print(f"release evidence failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
