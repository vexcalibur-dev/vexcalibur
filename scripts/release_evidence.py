#!/usr/bin/env python3
"""Build and verify deterministic Vexcalibur self-release evidence."""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import re
import shutil
import stat
import sys
import tarfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from packageurl import PackageURL

MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_METADATA_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_WHEEL_SCM_METADATA_BYTES = 64 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GROUPED_SHA256_PATTERN = re.compile(r"^(?:[0-9a-f]{16}:){3}[0-9a-f]{16}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
RELEASE_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$")
SCM_NODE_PATTERN = re.compile(r"^g?([0-9a-f]{40})$")
SCM_METADATA_MEMBER_PATTERN = re.compile(r"^vexcalibur-[^/]+\.dist-info/scm_version\.json$")
WHEEL_METADATA_MEMBER_PATTERN = re.compile(r"^vexcalibur-[^/]+\.dist-info/METADATA$")
RFC3339_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
CHECKSUM_LINE_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)$")
CONSTRAINT_REQUIREMENT_PATTERN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.!+_-]+)(?: ; [^\\\r\n]+)?$"
)
CONSTRAINT_HASH_PATTERN = re.compile(r"^    --hash=sha256:([0-9a-f]{64})$")
ORIGINAL_STATE_PATTERN = re.compile(
    r"(?:^|\n)Original Vexcalibur analysis state: "
    r"(resolved|exploitable|in_triage|false_positive|not_affected)(?:\n|$)"
)
ALLOWED_PRODUCTION_STATES = ("in_triage",)
ACTION_REPOSITORY = "vexcalibur-dev/vexcalibur-action"
PUBLICATION_ACTION_COMMIT = "cc570fb0ab80df3f4b1e31c0608b95c0707d5b66"  # pragma: allowlist secret
PUBLICATION_ACTION_COMMITS_BY_SCHEMA = {2: frozenset({PUBLICATION_ACTION_COMMIT})}
PUBLICATION_INVENTORY_FILES = {
    "findings.json",
    "review.json",
    "runtime-constraints.txt",
    "sbom.cdx.json",
    "uv.lock",
}
INVENTORY_COVERAGE = "cross-platform-reference-runtime"
INVENTORY_LIMITATION = (
    "uv.lock records the project's cross-platform reference runtime; it is not a "
    "claim about every environment-specific consumer resolution."
)
VULNERABILITY_PROVIDER_POLICY = "offline_local_findings_only"
PRODUCTION_STATE_POLICY = "only_in_triage"
PAYLOAD_DIGEST_ALGORITHM = "sha256_canonical_artifact_records_v1"
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


def hashed_file_uri(path: Path) -> str:
    """Return an absolute file URI carrying the file's SHA-256 fragment."""
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"expected a regular, non-symlink file: {path}")
    resolved = path.resolve(strict=True)
    return f"{resolved.as_uri()}#sha256={sha256_file(resolved)}"


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
            _validate_zip_members(wheel.infolist())
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
    component_by_ref: dict[str, str] = {}
    for component in _dict_items(document.get("components", []), field="CycloneDX components"):
        component_ref = _require_nonempty_string(
            component.get("bom-ref"), field="CycloneDX component bom-ref"
        )
        if component_ref in component_by_ref:
            raise EvidenceError(f"CycloneDX contains duplicate bom-ref {component_ref!r}")
        component_by_ref[component_ref] = _canonical_purl(
            component.get("purl"), field="CycloneDX component purl"
        )
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
        if set(vulnerability) != {"name"}:
            raise EvidenceError("OpenVEX vulnerability identity has unexpected fields")
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
            if set(product) != {"@id", "identifiers"}:
                raise EvidenceError("OpenVEX product identity has unexpected fields")
            identifiers = _require_dict(
                product.get("identifiers"), field="OpenVEX product identifiers"
            )
            if set(identifiers) != {"purl"}:
                raise EvidenceError("OpenVEX product identifiers have unexpected fields")
            purl = _canonical_purl(identifiers.get("purl"), field="OpenVEX product purl")
            product_id = _canonical_purl(product.get("@id"), field="OpenVEX product @id")
            if product_id != purl:
                raise EvidenceError("OpenVEX product @id differs from its canonical PURL")
            records.append((vulnerability_id, purl, state))
    return _unique_assertions(records, format_name="OpenVEX")


def _csaf_assertions(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    product_tree = _require_dict(document.get("product_tree"), field="CSAF product_tree")
    product_by_id: dict[str, str] = {}
    for product in _dict_items(
        product_tree.get("full_product_names", []), field="CSAF full_product_names"
    ):
        product_id = _require_nonempty_string(product.get("product_id"), field="CSAF product_id")
        if product_id in product_by_id:
            raise EvidenceError(f"CSAF contains duplicate product_id {product_id!r}")
        helper = _require_dict(
            product.get("product_identification_helper"), field="CSAF product helper"
        )
        product_by_id[product_id] = _canonical_purl(helper.get("purl"), field="CSAF product purl")

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
    expected_names = _expected_evidence_payload_names(assertion_count)
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

    formats, omitted_formats = _expected_format_manifest(assertion_count)
    cross_format_validation = (
        "passed" if assertion_count > 0 else "not_applicable_without_assertions"
    )

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
            "coverage": INVENTORY_COVERAGE,
            "limitation": INVENTORY_LIMITATION,
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
            "production_state_policy": PRODUCTION_STATE_POLICY,
            "sbom_cyclonedx_1_5_schema": "passed",
            "vex_cyclonedx_1_6_schema": "passed",
            "vulnerability_provider_selection": VULNERABILITY_PROVIDER_POLICY,
        },
        "artifacts": artifact_records,
    }


def _expected_evidence_payload_names(assertion_count: int) -> set[str]:
    if assertion_count < 0:
        raise EvidenceError("assertion count must not be negative")
    names = {
        "findings.json",
        "review.json",
        "runtime-constraints.txt",
        "sbom.cdx.json",
        "vex.cdx.json",
    }
    if assertion_count > 0:
        names.update({"vex.openvex.json", "vexcalibur-vex.json"})
    return names


def _expected_format_manifest(
    assertion_count: int,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    if assertion_count < 0:
        raise EvidenceError("assertion count must not be negative")
    formats: dict[str, dict[str, Any]] = {
        "cyclonedx": {
            "artifact": "vex.cdx.json",
            "assertion_count": assertion_count,
            "conformance": "CycloneDX 1.6 schema passed",
            "status": "generated",
        }
    }
    omitted_formats: list[dict[str, str]] = []
    for format_name, specification, artifact, conformance in (
        (
            "openvex",
            "OpenVEX 0.2.0",
            "vex.openvex.json",
            "official OpenVEX Go parser passed",
        ),
        (
            "csaf",
            "CSAF 2.0 VEX profile",
            "vexcalibur-vex.json",
            "CSAF 2.0 strict schema and mandatory tests passed",
        ),
    ):
        if assertion_count == 0:
            reason = (
                f"{specification} requires at least one vulnerability finding; "
                "this reviewed snapshot contains zero findings and makes zero VEX assertions."
            )
            formats[format_name] = {"reason": reason, "status": "omitted"}
            omitted_formats.append({"format": format_name, "reason": reason})
        else:
            formats[format_name] = {
                "artifact": artifact,
                "assertion_count": assertion_count,
                "conformance": conformance,
                "status": "generated",
            }
    return formats, omitted_formats


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
    artifact_names: list[str] = []
    for index, record in enumerate(artifact_records):
        item = _require_dict(record, field=f"manifest artifacts[{index}]")
        if set(item) != {"name", "sha256", "size"}:
            raise EvidenceError(
                f"manifest artifacts[{index}] must contain only name, sha256, and size"
            )
        filename = _require_nonempty_string(item.get("name"), field="artifact name")
        if filename in manifest_artifacts:
            raise EvidenceError(f"duplicate manifest artifact record: {filename}")
        artifact_names.append(filename)
        digest = _require_sha256(item.get("sha256"), name="artifact sha256")
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceError("manifest artifact size must be a nonnegative integer")
        manifest_artifacts[filename] = (digest, size)
    if artifact_names != sorted(artifact_names):
        raise EvidenceError("manifest artifact records are not sorted by filename")
    expected_artifacts = expected_names - {"manifest.json"}
    if set(manifest_artifacts) != expected_artifacts:
        raise EvidenceError("manifest artifact file set differs from bundle")
    for filename, (digest, size) in manifest_artifacts.items():
        if checksums.get(filename) != digest:
            raise EvidenceError(f"manifest artifact digest mismatch for {filename}")
        if (bundle_dir / filename).stat().st_size != size:
            raise EvidenceError(f"manifest artifact size mismatch for {filename}")


def prepare_publication_inventory(
    *,
    output_dir: Path,
    release_sha: str,
    release_version: str,
    source_date_epoch: int,
    lock_path: Path,
    review_path: Path,
    findings_path: Path,
    constraints_path: Path,
    sbom_path: Path,
    uv_version: str,
    source_tree_clean: bool,
) -> None:
    """Build the candidate-free oracle artifact used by publication jobs."""
    if output_dir.exists() or output_dir.is_symlink():
        raise EvidenceError(f"publication inventory output already exists: {output_dir}")
    if COMMIT_PATTERN.fullmatch(release_sha) is None:
        raise EvidenceError("release SHA must be a lowercase 40-character Git commit")
    release_version = _require_release_version(release_version)
    timestamp = release_timestamp(source_date_epoch)
    uv_version = _require_nonempty_string(uv_version, field="uv version")
    for path in (lock_path, review_path, findings_path, constraints_path, sbom_path):
        _require_bounded_publication_file(path)

    review_document = _require_dict(load_json(review_path), field="review")
    findings_document = _require_dict(load_json(findings_path), field="findings document")
    review_kind, findings = validate_review(
        review_document,
        findings_document,
        lock_path=lock_path,
        findings_path=findings_path,
    )
    if review_kind != "production":
        raise EvidenceError("publication inventory requires a production review")
    _validate_runtime_constraints(constraints_path)
    sbom_document = _require_dict(load_json(sbom_path), field="SBOM")
    validate_cyclonedx(sbom_path, spec_version="1.5")
    _validate_normalized_sbom(
        sbom_document,
        release_version=release_version,
        release_timestamp_value=timestamp,
        lock_sha256=sha256_file(lock_path),
    )
    _reviewed_assertions(findings, sbom_document)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_dir.mkdir(mode=0o700)
    except OSError as exc:
        raise EvidenceError(f"could not create fresh publication inventory: {exc}") from exc
    try:
        for source, name in (
            (findings_path, "findings.json"),
            (review_path, "review.json"),
            (constraints_path, "runtime-constraints.txt"),
            (sbom_path, "sbom.cdx.json"),
            (lock_path, "uv.lock"),
        ):
            _copy_regular_file_exclusive(source, output_dir / name)
        manifest = {
            "artifacts": [
                _artifact_record(output_dir / name) for name in sorted(PUBLICATION_INVENTORY_FILES)
            ],
            "inventory": {
                "coverage": INVENTORY_COVERAGE,
                "limitation": INVENTORY_LIMITATION,
                "lock": "uv.lock",
                "lock_sha256": sha256_file(output_dir / "uv.lock"),
                "sbom": "sbom.cdx.json",
                "sbom_specification": "CycloneDX 1.5",
            },
            "inventory_kind": "publication_oracle",
            "release": {
                "commit": release_sha,
                "purl": _release_purl(release_version),
                "source_date_epoch": source_date_epoch,
                "timestamp": timestamp,
                "version": release_version,
            },
            "review": _review_manifest_record(
                review_document,
                findings,
                review_path=output_dir / "review.json",
                findings_path=output_dir / "findings.json",
            ),
            "schema_version": 1,
            "source_tree_clean": source_tree_clean,
            "uv_version": uv_version,
        }
        (output_dir / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
        write_checksums(output_dir)
        verify_publication_inventory(
            inventory_dir=output_dir,
            expected_release_sha=release_sha,
            expected_release_version=release_version,
        )
    except Exception:
        if output_dir.exists():
            shutil.rmtree(output_dir)
        raise


def verify_publication_inventory(
    *, inventory_dir: Path, expected_release_sha: str, expected_release_version: str
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Verify the immutable oracle artifact without executing the release package."""
    verify_bundle(inventory_dir)
    if COMMIT_PATTERN.fullmatch(expected_release_sha) is None:
        raise EvidenceError("expected release SHA must be a lowercase 40-character commit")
    expected_release_version = _require_release_version(expected_release_version)
    manifest = _require_dict(load_json(inventory_dir / "manifest.json"), field="manifest")
    if set(manifest) != {
        "artifacts",
        "inventory",
        "inventory_kind",
        "release",
        "review",
        "schema_version",
        "source_tree_clean",
        "uv_version",
    }:
        raise EvidenceError("publication inventory manifest contains unexpected fields")
    if manifest.get("schema_version") != 1:
        raise EvidenceError("publication inventory schema version must be 1")
    if manifest.get("inventory_kind") != "publication_oracle":
        raise EvidenceError("publication inventory has the wrong kind")
    if manifest.get("source_tree_clean") is not True:
        raise EvidenceError("publication inventory requires a clean source tree")
    _require_nonempty_string(manifest.get("uv_version"), field="publication inventory uv version")

    release = _validate_release_record(
        manifest.get("release"),
        expected_release_sha=expected_release_sha,
        expected_release_version=expected_release_version,
    )
    lock_path = inventory_dir / "uv.lock"
    expected_inventory = {
        "coverage": INVENTORY_COVERAGE,
        "limitation": INVENTORY_LIMITATION,
        "lock": "uv.lock",
        "lock_sha256": sha256_file(lock_path),
        "sbom": "sbom.cdx.json",
        "sbom_specification": "CycloneDX 1.5",
    }
    if manifest.get("inventory") != expected_inventory:
        raise EvidenceError("publication inventory does not bind its bundled uv.lock")
    actual_names = {
        path.name for path in _bundle_files(inventory_dir, excluded={"manifest.json", "SHA256SUMS"})
    }
    if actual_names != PUBLICATION_INVENTORY_FILES:
        raise EvidenceError("publication inventory file set differs from the contract")

    review_document = _require_dict(load_json(inventory_dir / "review.json"), field="review")
    findings_document = _require_dict(
        load_json(inventory_dir / "findings.json"), field="findings document"
    )
    review_kind, findings = validate_review(
        review_document,
        findings_document,
        lock_path=lock_path,
        findings_path=inventory_dir / "findings.json",
    )
    if review_kind != "production":
        raise EvidenceError("publication inventory review is not production evidence")
    expected_review = _review_manifest_record(
        review_document,
        findings,
        review_path=inventory_dir / "review.json",
        findings_path=inventory_dir / "findings.json",
    )
    if manifest.get("review") != expected_review:
        raise EvidenceError("publication inventory review record differs from its inputs")

    _validate_runtime_constraints(inventory_dir / "runtime-constraints.txt")
    sbom = _require_dict(load_json(inventory_dir / "sbom.cdx.json"), field="SBOM")
    validate_cyclonedx(inventory_dir / "sbom.cdx.json", spec_version="1.5")
    _validate_normalized_sbom(
        sbom,
        release_version=expected_release_version,
        release_timestamp_value=str(release["timestamp"]),
        lock_sha256=sha256_file(lock_path),
    )
    _reviewed_assertions(findings, sbom)
    return manifest, findings


def _review_manifest_record(
    review: dict[str, Any],
    findings: tuple[dict[str, Any], ...],
    *,
    review_path: Path,
    findings_path: Path,
) -> dict[str, Any]:
    return {
        "analysis_revision": review["analysis_revision"],
        "assertion_count": len(findings),
        "conclusion": review["conclusion"],
        "findings_sha256": sha256_file(findings_path),
        "review_sha256": sha256_file(review_path),
        "state_counts": dict(
            sorted(Counter(str(item["analysis_state"]) for item in findings).items())
        ),
    }


def _validate_release_record(
    value: Any, *, expected_release_sha: str, expected_release_version: str
) -> dict[str, Any]:
    release = _require_dict(value, field="release record")
    if set(release) != {"commit", "purl", "source_date_epoch", "timestamp", "version"}:
        raise EvidenceError("release record contains unexpected fields")
    if release.get("commit") != expected_release_sha:
        raise EvidenceError("release record commit differs from the expected SHA")
    if release.get("version") != expected_release_version:
        raise EvidenceError("release record version differs from the expected version")
    if release.get("purl") != _release_purl(expected_release_version):
        raise EvidenceError("release record purl differs from the expected version")
    source_date_epoch = release.get("source_date_epoch")
    if (
        not isinstance(source_date_epoch, int)
        or isinstance(source_date_epoch, bool)
        or source_date_epoch < 0
    ):
        raise EvidenceError("release source_date_epoch must be a nonnegative integer")
    if release.get("timestamp") != release_timestamp(source_date_epoch):
        raise EvidenceError("release timestamp differs from source_date_epoch")
    return release


def _verify_generated_vex(
    *,
    output_dir: Path,
    findings: tuple[dict[str, Any], ...],
    sbom: dict[str, Any],
) -> None:
    vex_document = _require_dict(load_json(output_dir / "vex.cdx.json"), field="CycloneDX VEX")
    validate_cyclonedx(output_dir / "vex.cdx.json", spec_version="1.6")
    if _cyclonedx_assertions(vex_document) != _reviewed_assertions(findings, sbom):
        raise EvidenceError("generated CycloneDX assertions differ from reviewed findings")
    if findings:
        compare_vex_formats(
            vex_document,
            _require_dict(load_json(output_dir / "vex.openvex.json"), field="OpenVEX"),
            _require_dict(load_json(output_dir / "vexcalibur-vex.json"), field="CSAF"),
        )


def _expected_publication_validation(assertion_count: int) -> dict[str, str]:
    return {
        "action_local_wheel_equivalence": "passed",
        "cross_format_assertion_equivalence": (
            "passed" if assertion_count > 0 else "not_applicable_without_assertions"
        ),
        "installed_local_wheel": "passed",
        "production_state_policy": PRODUCTION_STATE_POLICY,
        "sbom_cyclonedx_1_5_schema": "passed",
        "vex_cyclonedx_1_6_schema": "passed",
        "vulnerability_provider_selection": VULNERABILITY_PROVIDER_POLICY,
    }


def finalize_publication_bundle(
    *,
    output_dir: Path,
    inventory_dir: Path,
    wheel_path: Path,
    sdist_path: Path,
    direct_output_dir: Path,
    action_output_dir: Path,
    release_tag: str,
    action_commit: str,
    expected_wheel_sha256: str,
    expected_sdist_sha256: str,
) -> None:
    """Assemble release assets atomically from isolated, verified job outputs."""
    if output_dir.exists() or output_dir.is_symlink():
        raise EvidenceError(f"publication output already exists: {output_dir}")
    if action_commit != PUBLICATION_ACTION_COMMIT:
        raise EvidenceError("Action commit differs from the schema-version 2 publication pin")
    expected_wheel_sha256 = _require_sha256(expected_wheel_sha256, name="build-job wheel SHA-256")
    expected_sdist_sha256 = _require_sha256(expected_sdist_sha256, name="build-job sdist SHA-256")

    untrusted_inventory = _require_dict(
        load_json(inventory_dir / "manifest.json"), field="inventory manifest"
    )
    untrusted_release = _require_dict(untrusted_inventory.get("release"), field="inventory release")
    release_sha = _require_nonempty_string(untrusted_release.get("commit"), field="release commit")
    release_version = _require_release_version(untrusted_release.get("version"))
    inventory_manifest, findings = verify_publication_inventory(
        inventory_dir=inventory_dir,
        expected_release_sha=release_sha,
        expected_release_version=release_version,
    )
    release = _require_dict(inventory_manifest.get("release"), field="inventory release")
    if release_tag != f"v{release_version}":
        raise EvidenceError("release tag differs from the publication inventory version")

    _require_bounded_publication_file(wheel_path)
    _require_bounded_publication_file(sdist_path)
    expected_wheel_name = f"vexcalibur-{release_version}-py3-none-any.whl"
    expected_sdist_name = f"vexcalibur-{release_version}.tar.gz"
    if wheel_path.name != expected_wheel_name or sdist_path.name != expected_sdist_name:
        raise EvidenceError("publication distribution filenames differ from the release version")
    if sha256_file(wheel_path) != expected_wheel_sha256:
        raise EvidenceError("publication wheel differs from the build-job digest")
    if sha256_file(sdist_path) != expected_sdist_sha256:
        raise EvidenceError("publication sdist differs from the build-job digest")
    _validate_distribution_metadata(
        wheel_path=wheel_path,
        sdist_path=sdist_path,
        expected_version=release_version,
        expected_release_sha=release_sha,
    )
    wheel_commit = validate_wheel_source(wheel_path, release_sha=release_sha)

    formats, omitted_formats = _expected_format_manifest(len(findings))
    generated_artifacts = _generated_format_artifacts(
        {"formats": formats}, assertion_count=len(findings)
    )
    direct_files = _bundle_files(direct_output_dir, excluded=set())
    action_files = _bundle_files(action_output_dir, excluded=set())
    if {path.name for path in direct_files} != generated_artifacts:
        raise EvidenceError("direct-wheel output file set differs from the format contract")
    if {path.name for path in action_files} != generated_artifacts:
        raise EvidenceError("Action output file set differs from the format contract")
    action_by_name = {path.name: path for path in action_files}
    for direct_file in direct_files:
        action_file = action_by_name[direct_file.name]
        _require_bounded_publication_file(direct_file)
        _require_bounded_publication_file(action_file)
        if direct_file.stat().st_size != action_file.stat().st_size or sha256_file(
            direct_file
        ) != sha256_file(action_file):
            raise EvidenceError(f"Action output differs from direct output: {action_file.name}")
    _verify_generated_vex(
        output_dir=direct_output_dir,
        findings=findings,
        sbom=_require_dict(load_json(inventory_dir / "sbom.cdx.json"), field="SBOM"),
    )
    build_payload_sha256 = _payload_sha256([wheel_path, sdist_path])
    inventory_payload_sha256 = _payload_sha256(
        [inventory_dir / name for name in sorted(PUBLICATION_INVENTORY_FILES)]
    )
    direct_payload_sha256 = _payload_sha256(direct_files)
    action_payload_sha256 = _payload_sha256(action_files)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_dir.mkdir(mode=0o700)
    except OSError as exc:
        raise EvidenceError(f"could not create fresh publication output: {exc}") from exc
    try:
        for name in sorted(PUBLICATION_INVENTORY_FILES):
            _copy_regular_file_exclusive(inventory_dir / name, output_dir / name)
        for direct_file in direct_files:
            _copy_regular_file_exclusive(direct_file, output_dir / direct_file.name)
        _copy_regular_file_exclusive(wheel_path, output_dir / wheel_path.name)
        _copy_regular_file_exclusive(sdist_path, output_dir / sdist_path.name)

        distribution_records = [
            _distribution_record(output_dir / expected_sdist_name, kind="sdist"),
            _distribution_record(output_dir / expected_wheel_name, kind="wheel"),
        ]
        manifest = {
            "artifacts": [],
            "evidence_kind": "production",
            "formats": formats,
            "generator": {
                "distribution": "vexcalibur",
                "sdist_filename": sdist_path.name,
                "sdist_sha256": sha256_file(sdist_path),
                "uv_version": inventory_manifest["uv_version"],
                "version": release_version,
                "wheel_filename": wheel_path.name,
                "wheel_sha256": sha256_file(wheel_path),
                "wheel_source_commit": wheel_commit,
                "wheel_source_dirty": False,
            },
            "intended_use": "immutable_release_candidate",
            "inventory": inventory_manifest["inventory"],
            "omitted_formats": omitted_formats,
            "publication": {
                "action": {
                    "actions_artifact_name": f"action-vex-{release_sha}",
                    "commit": action_commit,
                    "constraints": "runtime-constraints.txt",
                    "job": "action-vex",
                    "output_equivalence": "byte_for_byte",
                    "package_spec": "file_uri_with_sha256_fragment",
                    "payload_sha256": action_payload_sha256,
                    "repository": ACTION_REPOSITORY,
                },
                "asset_contract": "flat_immutable_github_release",
                "build": {
                    "actions_artifact_name": f"dist-{release_sha}",
                    "job": "build",
                    "payload_sha256": build_payload_sha256,
                    "workflow": ".github/workflows/release-validation.yml",
                },
                "direct_generation": {
                    "actions_artifact_name": f"direct-vex-{release_sha}",
                    "job": "direct-vex",
                    "payload_sha256": direct_payload_sha256,
                },
                "distributions": distribution_records,
                "inventory": {
                    "actions_artifact_name": f"release-inventory-{release_sha}",
                    "job": "publication-inventory",
                    "payload_sha256": inventory_payload_sha256,
                },
                "payload_digest_algorithm": PAYLOAD_DIGEST_ALGORITHM,
                "release_tag": release_tag,
            },
            "release": release,
            "review": inventory_manifest["review"],
            "schema_version": 2,
            "source_tree_clean": True,
            "validation": _expected_publication_validation(len(findings)),
        }
        files = _bundle_files(output_dir, excluded={"manifest.json", "SHA256SUMS"})
        manifest["artifacts"] = [_artifact_record(path) for path in files]
        (output_dir / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
        write_checksums(output_dir)
        verify_publication_bundle(
            bundle_dir=output_dir,
            expected_release_tag=release_tag,
            expected_release_sha=release_sha,
            expected_action_commit=action_commit,
        )
    except Exception:
        if output_dir.exists():
            shutil.rmtree(output_dir)
        raise


def verify_publication_bundle(
    *,
    bundle_dir: Path,
    expected_release_tag: str,
    expected_release_sha: str,
    expected_action_commit: str | None,
) -> None:
    """Verify the complete immutable-release asset contract."""
    verify_bundle(bundle_dir)
    if COMMIT_PATTERN.fullmatch(expected_release_sha) is None:
        raise EvidenceError("expected release SHA must be a lowercase 40-character commit")
    if (
        expected_action_commit is not None
        and COMMIT_PATTERN.fullmatch(expected_action_commit) is None
    ):
        raise EvidenceError("expected Action commit must be a lowercase 40-character commit")

    manifest = _require_dict(load_json(bundle_dir / "manifest.json"), field="manifest")
    expected_top_level_keys = {
        "artifacts",
        "evidence_kind",
        "formats",
        "generator",
        "intended_use",
        "inventory",
        "omitted_formats",
        "publication",
        "release",
        "review",
        "schema_version",
        "source_tree_clean",
        "validation",
    }
    if set(manifest) != expected_top_level_keys:
        raise EvidenceError("publication manifest contains unexpected top-level fields")
    if manifest.get("schema_version") != 2:
        raise EvidenceError("publication manifest must use schema version 2")
    if manifest.get("evidence_kind") != "production":
        raise EvidenceError("publication manifest must contain production evidence")
    if manifest.get("intended_use") != "immutable_release_candidate":
        raise EvidenceError("publication manifest has the wrong intended use")
    if manifest.get("source_tree_clean") is not True:
        raise EvidenceError("publication manifest must record a clean source tree")

    release = _require_dict(manifest.get("release"), field="manifest release")
    if set(release) != {"commit", "purl", "source_date_epoch", "timestamp", "version"}:
        raise EvidenceError("publication release record contains unexpected fields")
    release_version = _require_release_version(release.get("version"))
    if expected_release_tag != f"v{release_version}":
        raise EvidenceError("expected release tag differs from the manifest version")
    if release.get("commit") != expected_release_sha:
        raise EvidenceError("manifest release commit differs from the expected release SHA")
    if release.get("purl") != _release_purl(release_version):
        raise EvidenceError("manifest release purl differs from the release version")
    source_date_epoch = release.get("source_date_epoch")
    if (
        not isinstance(source_date_epoch, int)
        or isinstance(source_date_epoch, bool)
        or source_date_epoch < 0
    ):
        raise EvidenceError("manifest release source_date_epoch must be nonnegative")
    if release.get("timestamp") != release_timestamp(source_date_epoch):
        raise EvidenceError("manifest release timestamp differs from source_date_epoch")

    lock_path = bundle_dir / "uv.lock"
    _require_bounded_publication_file(lock_path)
    inventory = _require_dict(manifest.get("inventory"), field="manifest inventory")
    expected_inventory = {
        "coverage": INVENTORY_COVERAGE,
        "limitation": INVENTORY_LIMITATION,
        "lock": "uv.lock",
        "lock_sha256": sha256_file(lock_path),
        "sbom": "sbom.cdx.json",
        "sbom_specification": "CycloneDX 1.5",
    }
    if inventory != expected_inventory:
        raise EvidenceError("publication inventory differs from the bundled lock contract")
    _validate_runtime_constraints(bundle_dir / "runtime-constraints.txt")

    review_kind, findings = validate_review(
        _require_dict(load_json(bundle_dir / "review.json"), field="review"),
        _require_dict(load_json(bundle_dir / "findings.json"), field="findings document"),
        lock_path=lock_path,
        findings_path=bundle_dir / "findings.json",
    )
    if review_kind != "production":
        raise EvidenceError("publication bundle review is not production evidence")
    review = _require_dict(manifest.get("review"), field="manifest review")
    review_document = _require_dict(load_json(bundle_dir / "review.json"), field="review")
    expected_review = {
        "analysis_revision": review_document["analysis_revision"],
        "assertion_count": len(findings),
        "conclusion": review_document["conclusion"],
        "findings_sha256": sha256_file(bundle_dir / "findings.json"),
        "review_sha256": sha256_file(bundle_dir / "review.json"),
        "state_counts": dict(
            sorted(Counter(str(item["analysis_state"]) for item in findings).items())
        ),
    }
    if review != expected_review:
        raise EvidenceError("publication review record differs from the reviewed inputs")

    publication = _require_dict(manifest.get("publication"), field="manifest publication")
    if set(publication) != {
        "action",
        "asset_contract",
        "build",
        "direct_generation",
        "distributions",
        "inventory",
        "payload_digest_algorithm",
        "release_tag",
    }:
        raise EvidenceError("publication manifest contains unexpected publication fields")
    if publication.get("asset_contract") != "flat_immutable_github_release":
        raise EvidenceError("publication manifest has an unsupported asset contract")
    if publication.get("release_tag") != expected_release_tag:
        raise EvidenceError("publication release tag differs from the expected tag")
    if publication.get("payload_digest_algorithm") != PAYLOAD_DIGEST_ALGORITHM:
        raise EvidenceError("publication payload digest algorithm is unsupported")
    generated_names = _generated_format_artifacts(
        {"formats": _expected_format_manifest(len(findings))[0]},
        assertion_count=len(findings),
    )
    generated_paths = [bundle_dir / name for name in sorted(generated_names)]
    generated_payload_sha256 = _payload_sha256(generated_paths)
    build_payload_sha256 = _payload_sha256(
        [
            bundle_dir / f"vexcalibur-{release_version}-py3-none-any.whl",
            bundle_dir / f"vexcalibur-{release_version}.tar.gz",
        ]
    )
    inventory_payload_sha256 = _payload_sha256(
        [bundle_dir / name for name in sorted(PUBLICATION_INVENTORY_FILES)]
    )
    action = _require_dict(publication.get("action"), field="publication action")
    recorded_action_commit = _require_nonempty_string(
        action.get("commit"), field="publication Action commit"
    )
    if expected_action_commit is None:
        allowed_commits = PUBLICATION_ACTION_COMMITS_BY_SCHEMA.get(2, frozenset())
        if recorded_action_commit not in allowed_commits:
            raise EvidenceError("publication Action commit is not in the schema pin history")
        expected_action_commit = recorded_action_commit
    expected_action = {
        "actions_artifact_name": f"action-vex-{expected_release_sha}",
        "commit": expected_action_commit,
        "constraints": "runtime-constraints.txt",
        "job": "action-vex",
        "output_equivalence": "byte_for_byte",
        "package_spec": "file_uri_with_sha256_fragment",
        "payload_sha256": generated_payload_sha256,
        "repository": ACTION_REPOSITORY,
    }
    if action != expected_action:
        raise EvidenceError("publication Action provenance differs from the pinned contract")
    build = _require_dict(publication.get("build"), field="publication build")
    expected_build = {
        "actions_artifact_name": f"dist-{expected_release_sha}",
        "job": "build",
        "payload_sha256": build_payload_sha256,
        "workflow": ".github/workflows/release-validation.yml",
    }
    if build != expected_build:
        raise EvidenceError("publication build provenance differs from the workflow contract")
    direct_generation = _require_dict(
        publication.get("direct_generation"), field="publication direct generation"
    )
    expected_direct_generation = {
        "actions_artifact_name": f"direct-vex-{expected_release_sha}",
        "job": "direct-vex",
        "payload_sha256": generated_payload_sha256,
    }
    if direct_generation != expected_direct_generation:
        raise EvidenceError("publication direct-generation provenance is invalid")
    inventory_provenance = _require_dict(
        publication.get("inventory"), field="publication inventory provenance"
    )
    expected_inventory_provenance = {
        "actions_artifact_name": f"release-inventory-{expected_release_sha}",
        "job": "publication-inventory",
        "payload_sha256": inventory_payload_sha256,
    }
    if inventory_provenance != expected_inventory_provenance:
        raise EvidenceError("publication inventory provenance is invalid")

    expected_wheel_name = f"vexcalibur-{release_version}-py3-none-any.whl"
    expected_sdist_name = f"vexcalibur-{release_version}.tar.gz"
    distribution_records = _dict_items(
        publication.get("distributions"), field="publication distributions"
    )
    if len(distribution_records) != 2:
        raise EvidenceError("publication must contain exactly one wheel and one sdist record")
    expected_distributions = {
        "sdist": expected_sdist_name,
        "wheel": expected_wheel_name,
    }
    actual_distributions: dict[str, str] = {}
    for record in distribution_records:
        if set(record) != {"kind", "name", "sha256", "size"}:
            raise EvidenceError("publication distribution record has unexpected fields")
        kind = _require_nonempty_string(record.get("kind"), field="distribution kind")
        name = _require_nonempty_string(record.get("name"), field="distribution name")
        if kind in actual_distributions:
            raise EvidenceError(f"duplicate publication distribution kind: {kind}")
        if expected_distributions.get(kind) != name:
            raise EvidenceError(f"publication {kind!r} filename is invalid")
        path = bundle_dir / name
        _require_bounded_publication_file(path)
        if record.get("sha256") != sha256_file(path):
            raise EvidenceError(f"publication {kind} digest mismatch")
        if record.get("size") != path.stat().st_size:
            raise EvidenceError(f"publication {kind} size mismatch")
        actual_distributions[kind] = name
    if actual_distributions != expected_distributions:
        raise EvidenceError("publication distribution set is incomplete")

    expected_names = _expected_evidence_payload_names(len(findings)) | {
        expected_wheel_name,
        expected_sdist_name,
        "uv.lock",
        "manifest.json",
        "SHA256SUMS",
    }
    actual_names = {path.name for path in _bundle_files(bundle_dir, excluded=set())}
    if actual_names != expected_names:
        raise EvidenceError(
            "publication asset file set differs from the contract: "
            f"{sorted(actual_names)!r} != {sorted(expected_names)!r}"
        )
    for name in actual_names:
        _require_bounded_publication_file(bundle_dir / name)

    generator = _require_dict(manifest.get("generator"), field="manifest generator")
    expected_generator_keys = {
        "distribution",
        "sdist_filename",
        "sdist_sha256",
        "uv_version",
        "version",
        "wheel_filename",
        "wheel_sha256",
        "wheel_source_commit",
        "wheel_source_dirty",
    }
    if set(generator) != expected_generator_keys:
        raise EvidenceError("publication generator contains unexpected fields")
    wheel_path = bundle_dir / expected_wheel_name
    sdist_path = bundle_dir / expected_sdist_name
    if generator.get("distribution") != "vexcalibur":
        raise EvidenceError("generator distribution is not vexcalibur")
    if generator.get("version") != release_version:
        raise EvidenceError("generator version differs from the release version")
    _require_nonempty_string(generator.get("uv_version"), field="generator uv_version")
    if generator.get("wheel_filename") != expected_wheel_name:
        raise EvidenceError("generator wheel filename differs from the release asset")
    if generator.get("wheel_sha256") != sha256_file(wheel_path):
        raise EvidenceError("generator wheel digest differs from the release asset")
    if generator.get("sdist_filename") != expected_sdist_name:
        raise EvidenceError("generator sdist filename differs from the release asset")
    if generator.get("sdist_sha256") != sha256_file(sdist_path):
        raise EvidenceError("generator sdist digest differs from the release asset")
    if generator.get("wheel_source_dirty") is not False:
        raise EvidenceError("generator wheel source must be clean")
    _validate_distribution_metadata(
        wheel_path=wheel_path,
        sdist_path=sdist_path,
        expected_version=release_version,
        expected_release_sha=expected_release_sha,
    )
    if generator.get("wheel_source_commit") != validate_wheel_source(
        wheel_path, release_sha=expected_release_sha
    ):
        raise EvidenceError("generator wheel source commit is invalid")

    expected_formats, expected_omissions = _expected_format_manifest(len(findings))
    if manifest.get("formats") != expected_formats:
        raise EvidenceError("publication format records differ from the reviewed assertion count")
    if manifest.get("omitted_formats") != expected_omissions:
        raise EvidenceError("publication omitted-format records differ from the format contract")
    generated_artifacts = _generated_format_artifacts(manifest, assertion_count=len(findings))
    if generated_artifacts != {"vex.cdx.json"} and len(findings) == 0:
        raise EvidenceError("zero-assertion publication generated unexpected VEX formats")
    sbom_document = _require_dict(load_json(bundle_dir / "sbom.cdx.json"), field="SBOM")
    vex_document = _require_dict(load_json(bundle_dir / "vex.cdx.json"), field="CycloneDX VEX")
    validate_cyclonedx(bundle_dir / "sbom.cdx.json", spec_version="1.5")
    validate_cyclonedx(bundle_dir / "vex.cdx.json", spec_version="1.6")
    _validate_normalized_sbom(
        sbom_document,
        release_version=release_version,
        release_timestamp_value=str(release["timestamp"]),
        lock_sha256=sha256_file(lock_path),
    )
    expected_assertions = _reviewed_assertions(findings, sbom_document)
    if _cyclonedx_assertions(vex_document) != expected_assertions:
        raise EvidenceError("CycloneDX assertions differ from the reviewed findings")
    if len(findings) > 0:
        compare_vex_formats(
            vex_document,
            _require_dict(load_json(bundle_dir / "vex.openvex.json"), field="OpenVEX"),
            _require_dict(load_json(bundle_dir / "vexcalibur-vex.json"), field="CSAF"),
        )
    expected_validation = _expected_publication_validation(len(findings))
    if manifest.get("validation") != expected_validation:
        raise EvidenceError("publication validation record differs from the checked contract")


def _validate_runtime_constraints(path: Path) -> None:
    _require_bounded_publication_file(path)
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(f"could not read runtime constraints: {exc}") from exc
    if any(ord(character) < 32 and character != "\n" for character in contents):
        raise EvidenceError("runtime constraints must be newline-delimited UTF-8 text")
    lines = contents.splitlines()
    if lines[:3] != ["--require-hashes", "--only-binary :all:", ""]:
        raise EvidenceError(
            "runtime constraints must require hashes and binary distributions before entries"
        )
    if len(lines) < 5:
        raise EvidenceError("runtime constraints contain no SHA-256-pinned requirements")

    index = 3
    package_names: set[str] = set()
    while index < len(lines):
        requirement_line = lines[index]
        if not requirement_line.endswith(" \\"):
            raise EvidenceError("each runtime requirement must continue to SHA-256 hashes")
        match = CONSTRAINT_REQUIREMENT_PATTERN.fullmatch(requirement_line[:-2])
        if match is None:
            raise EvidenceError("runtime constraints contain a non-exact requirement or directive")
        package_name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if package_name in package_names:
            raise EvidenceError(f"runtime constraints repeat package {package_name!r}")
        package_names.add(package_name)
        index += 1

        hashes: set[str] = set()
        while index < len(lines) and lines[index].startswith("    --hash="):
            hash_line = lines[index]
            continued = hash_line.endswith(" \\")
            candidate = hash_line[:-2] if continued else hash_line
            hash_match = CONSTRAINT_HASH_PATTERN.fullmatch(candidate)
            if hash_match is None:
                raise EvidenceError("runtime constraints contain a malformed package hash")
            digest = hash_match.group(1)
            if digest in hashes:
                raise EvidenceError("runtime constraints repeat a package hash")
            hashes.add(digest)
            index += 1
            if not continued:
                break
        if not hashes:
            raise EvidenceError("every runtime requirement must have a SHA-256 hash")
        if continued:
            raise EvidenceError("runtime constraint hash continuation is incomplete")
        if index < len(lines) and lines[index].startswith((" ", "-")):
            raise EvidenceError("runtime constraints contain an unsupported directive")


def _validate_distribution_metadata(
    *,
    wheel_path: Path,
    sdist_path: Path,
    expected_version: str,
    expected_release_sha: str,
) -> None:
    expected = {"Name": "vexcalibur", "Version": expected_version}
    wheel_metadata = _read_wheel_distribution_metadata(wheel_path)
    sdist_metadata, sdist_commit = _read_sdist_distribution_metadata(sdist_path, expected_version)
    if wheel_metadata != expected:
        raise EvidenceError("wheel Name or Version metadata differs from the release")
    if sdist_metadata != expected:
        raise EvidenceError("sdist Name or Version metadata differs from the release")
    if not expected_release_sha.startswith(sdist_commit):
        raise EvidenceError("sdist SCM commit differs from the release commit")


def _validate_zip_members(members: list[zipfile.ZipInfo]) -> None:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise EvidenceError("wheel contains too many archive members")
    names: set[str] = set()
    uncompressed_bytes = 0
    for member in members:
        _validate_archive_member_name(member.filename, artifact="wheel")
        if member.filename in names:
            raise EvidenceError(f"wheel contains duplicate member {member.filename!r}")
        names.add(member.filename)
        if member.flag_bits & 0x1:
            raise EvidenceError("wheel contains an encrypted archive member")
        if not member.is_dir():
            uncompressed_bytes += member.file_size
            if uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise EvidenceError("wheel exceeds the cumulative uncompressed byte limit")
        if member.create_system == 3:
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if member.is_dir():
                if file_type not in {0, stat.S_IFDIR}:
                    raise EvidenceError("wheel directory member has an invalid file type")
            elif file_type not in {0, stat.S_IFREG}:
                raise EvidenceError("wheel contains a link or special nonregular member")


def _validate_archive_member_name(name: str, *, artifact: str) -> None:
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
        raise EvidenceError(f"{artifact} contains an unsafe archive member path")


def _read_wheel_distribution_metadata(path: Path) -> dict[str, str]:
    _require_bounded_publication_file(path)
    try:
        with zipfile.ZipFile(path) as wheel:
            _validate_zip_members(wheel.infolist())
            members = [
                member
                for member in wheel.infolist()
                if WHEEL_METADATA_MEMBER_PATTERN.fullmatch(member.filename) is not None
            ]
            if len(members) != 1:
                raise EvidenceError("wheel must contain exactly one Vexcalibur METADATA member")
            member = members[0]
            if member.is_dir() or member.file_size > MAX_ARCHIVE_METADATA_BYTES:
                raise EvidenceError("wheel METADATA is not a bounded regular member")
            if member.create_system == 3:
                file_type = stat.S_IFMT(member.external_attr >> 16)
                if file_type not in {0, stat.S_IFREG}:
                    raise EvidenceError("wheel METADATA is not a bounded regular member")
            with wheel.open(member) as stream:
                metadata = stream.read(MAX_ARCHIVE_METADATA_BYTES + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise EvidenceError(f"could not read wheel metadata: {exc}") from exc
    return _parse_distribution_metadata(metadata, artifact="wheel")


def _read_sdist_distribution_metadata(path: Path, version: str) -> tuple[dict[str, str], str]:
    _require_bounded_publication_file(path)
    expected_member = f"vexcalibur-{version}/PKG-INFO"
    expected_version_member = f"vexcalibur-{version}/src/vexcalibur/_version.py"
    metadata: bytes | None = None
    version_source: bytes | None = None
    member_names: set[str] = set()
    uncompressed_bytes = 0
    try:
        with tarfile.open(path, "r:gz") as sdist:
            for index, member in enumerate(sdist):
                if index >= MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError("sdist contains too many archive members")
                _validate_archive_member_name(member.name, artifact="sdist")
                if member.name in member_names:
                    raise EvidenceError(f"sdist contains duplicate member {member.name!r}")
                member_names.add(member.name)
                if not (member.isfile() or member.isdir()):
                    raise EvidenceError("sdist contains a link or special archive member")
                if member.isfile():
                    uncompressed_bytes += member.size
                    if uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        raise EvidenceError("sdist exceeds the cumulative uncompressed byte limit")
                if member.name != expected_member:
                    if member.name != expected_version_member:
                        continue
                    if version_source is not None:
                        raise EvidenceError("sdist contains duplicate generated version files")
                    if not member.isfile() or member.size > MAX_ARCHIVE_METADATA_BYTES:
                        raise EvidenceError("sdist generated version is not a bounded member")
                    version_stream = sdist.extractfile(member)
                    if version_stream is None:
                        raise EvidenceError("could not read sdist generated version")
                    version_source = version_stream.read(MAX_ARCHIVE_METADATA_BYTES + 1)
                    continue
                if metadata is not None:
                    raise EvidenceError("sdist contains duplicate PKG-INFO members")
                if not member.isfile() or member.size > MAX_ARCHIVE_METADATA_BYTES:
                    raise EvidenceError("sdist PKG-INFO is not a bounded regular member")
                stream = sdist.extractfile(member)
                if stream is None:
                    raise EvidenceError("could not read sdist PKG-INFO")
                metadata = stream.read(MAX_ARCHIVE_METADATA_BYTES + 1)
    except (OSError, tarfile.TarError) as exc:
        raise EvidenceError(f"could not read sdist metadata: {exc}") from exc
    if metadata is None:
        raise EvidenceError(f"sdist does not contain exactly {expected_member}")
    if version_source is None or len(version_source) > MAX_ARCHIVE_METADATA_BYTES:
        raise EvidenceError("sdist does not contain a bounded generated version file")
    try:
        version_text = version_source.decode("utf-8")
    except UnicodeError as exc:
        raise EvidenceError("sdist generated version is not UTF-8") from exc
    version_match = re.search(r"(?m)^__version__ = version = '([^'\r\n]+)'$", version_text)
    commit_match = re.search(
        r"(?m)^__commit_id__ = commit_id = 'g?([0-9a-f]{7,40})'$", version_text
    )
    if version_match is None or version_match.group(1) != version or commit_match is None:
        raise EvidenceError("sdist generated version does not bind its version and SCM commit")
    return _parse_distribution_metadata(metadata, artifact="sdist"), commit_match.group(1)


def _parse_distribution_metadata(raw_metadata: bytes, *, artifact: str) -> dict[str, str]:
    if len(raw_metadata) > MAX_ARCHIVE_METADATA_BYTES:
        raise EvidenceError(f"{artifact} metadata exceeds the byte limit")
    try:
        metadata = email.message_from_bytes(raw_metadata)
    except (TypeError, UnicodeError) as exc:
        raise EvidenceError(f"{artifact} metadata is malformed: {exc}") from exc
    values: dict[str, str] = {}
    for key in ("Name", "Version"):
        headers = metadata.get_all(key, [])
        if len(headers) != 1 or not isinstance(headers[0], str) or not headers[0].strip():
            raise EvidenceError(f"{artifact} metadata must contain exactly one {key} header")
        values[key] = headers[0]
    return values


def _validate_normalized_sbom(
    document: dict[str, Any],
    *,
    release_version: str,
    release_timestamp_value: str,
    lock_sha256: str,
) -> None:
    metadata = _require_dict(document.get("metadata"), field="SBOM metadata")
    if metadata.get("timestamp") != release_timestamp_value:
        raise EvidenceError("SBOM timestamp differs from the release timestamp")
    component = _require_dict(metadata.get("component"), field="SBOM root component")
    release_purl = _release_purl(release_version)
    for field, expected in (
        ("name", "vexcalibur"),
        ("version", release_version),
        ("purl", release_purl),
        ("bom-ref", release_purl),
    ):
        if component.get(field) != expected:
            raise EvidenceError(f"SBOM root component {field} differs from the release")
    properties = _dict_items(component.get("properties", []), field="SBOM root properties")
    lock_properties = [
        item for item in properties if item.get("name") == "vexcalibur:source:uv-lock-sha256"
    ]
    if lock_properties != [{"name": "vexcalibur:source:uv-lock-sha256", "value": lock_sha256}]:
        raise EvidenceError("SBOM root component does not bind the bundled uv.lock")
    if "serialNumber" in document:
        raise EvidenceError("normalized SBOM must not contain a random serial number")


def _reviewed_assertions(
    findings: tuple[dict[str, Any], ...], sbom: dict[str, Any]
) -> set[tuple[str, str, str]]:
    components = list(_dict_items(sbom.get("components", []), field="SBOM components"))
    metadata = _require_dict(sbom.get("metadata"), field="SBOM metadata")
    root = metadata.get("component")
    if root is not None:
        components.append(_require_dict(root, field="SBOM root component"))
    component_by_ref: dict[str, str] = {}
    known_purls: set[str] = set()
    for component in components:
        component_ref = _require_nonempty_string(component.get("bom-ref"), field="SBOM bom-ref")
        purl = _canonical_purl(component.get("purl"), field="SBOM component purl")
        if component_ref in component_by_ref:
            raise EvidenceError(f"SBOM contains duplicate component reference {component_ref!r}")
        component_by_ref[component_ref] = purl
        known_purls.add(purl)

    assertions: set[tuple[str, str, str]] = set()
    for index, finding in enumerate(findings):
        vulnerability_id = _require_nonempty_string(
            finding.get("id"), field=f"findings[{index}].id"
        )
        if finding.get("purl") is not None:
            purl = _canonical_purl(finding.get("purl"), field=f"findings[{index}].purl")
            if purl not in known_purls:
                raise EvidenceError(f"findings[{index}] purl is absent from the SBOM")
        else:
            component_ref = _require_nonempty_string(
                finding.get("component_ref"), field=f"findings[{index}].component_ref"
            )
            try:
                purl = component_by_ref[component_ref]
            except KeyError as exc:
                raise EvidenceError(
                    f"findings[{index}] references an unknown SBOM component"
                ) from exc
        assertion = (vulnerability_id, purl, "in_triage")
        if assertion in assertions:
            raise EvidenceError(f"reviewed findings resolve to duplicate assertion {assertion!r}")
        assertions.add(assertion)
    return assertions


def _canonical_purl(value: Any, *, field: str) -> str:
    raw = _require_nonempty_string(value, field=field)
    try:
        return PackageURL.from_string(raw).to_string()
    except ValueError as exc:
        raise EvidenceError(f"{field} is invalid: {exc}") from exc


def _generated_format_artifacts(manifest: dict[str, Any], *, assertion_count: int) -> set[str]:
    formats = _require_dict(manifest.get("formats"), field="manifest formats")
    if set(formats) != {"cyclonedx", "openvex", "csaf"}:
        raise EvidenceError("manifest formats must contain CycloneDX, OpenVEX, and CSAF")
    artifacts: set[str] = set()
    for format_name in ("cyclonedx", "openvex", "csaf"):
        record = _require_dict(formats.get(format_name), field=f"manifest format {format_name}")
        status = record.get("status")
        if status == "generated":
            artifact = _require_nonempty_string(
                record.get("artifact"), field=f"{format_name} artifact"
            )
            if artifact in artifacts:
                raise EvidenceError(f"duplicate generated format artifact: {artifact}")
            artifacts.add(artifact)
        elif status != "omitted":
            raise EvidenceError(f"manifest format {format_name} has an invalid status")
    expected = {"vex.cdx.json"}
    if assertion_count > 0:
        expected.update({"vex.openvex.json", "vexcalibur-vex.json"})
    if artifacts != expected:
        raise EvidenceError(
            f"generated format artifacts differ from reviewed assertions: "
            f"{sorted(artifacts)!r} != {sorted(expected)!r}"
        )
    return artifacts


def _require_release_version(value: Any) -> str:
    version = _require_nonempty_string(value, field="release version")
    match = RELEASE_VERSION_PATTERN.fullmatch(version)
    if match is None or any(int(component) > 999_999 for component in match.groups()):
        raise EvidenceError(
            "release version must be bounded MAJOR.MINOR.PATCH without leading zeros"
        )
    return version


def _require_bounded_publication_file(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"expected a regular, non-symlink publication file: {path}")
    if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceError(f"publication file exceeds {MAX_EVIDENCE_FILE_BYTES} bytes: {path}")


def _copy_regular_file_exclusive(source: Path, target: Path) -> None:
    _require_bounded_publication_file(source)
    created = False
    try:
        with source.open("rb") as input_stream, target.open("xb") as output_stream:
            created = True
            shutil.copyfileobj(input_stream, output_stream, length=64 * 1024)
    except Exception:
        if created:
            target.unlink(missing_ok=True)
        raise
    if source.stat().st_size != target.stat().st_size or sha256_file(source) != sha256_file(target):
        target.unlink(missing_ok=True)
        raise EvidenceError(f"copied publication asset differs from its source: {source.name}")


def _artifact_record(path: Path) -> dict[str, Any]:
    _require_bounded_publication_file(path)
    return {"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}


def _payload_sha256(paths: list[Path]) -> str:
    """Digest a stable, filename-sorted set of publication payload records."""
    records = [_artifact_record(path) for path in sorted(paths, key=lambda item: item.name)]
    names = [str(record["name"]) for record in records]
    if len(names) != len(set(names)):
        raise EvidenceError("publication payload contains duplicate filenames")
    return hashlib.sha256(canonical_json(records).encode()).hexdigest()


def _distribution_record(path: Path, *, kind: str) -> dict[str, Any]:
    return {"kind": kind, **_artifact_record(path)}


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

    file_uri_parser = subparsers.add_parser("hashed-file-uri")
    file_uri_parser.add_argument("--file", required=True, type=Path)

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

    inventory_parser = subparsers.add_parser("prepare-publication-inventory")
    inventory_parser.add_argument("--output-dir", required=True, type=Path)
    inventory_parser.add_argument("--release-sha", required=True)
    inventory_parser.add_argument("--release-version", required=True)
    inventory_parser.add_argument("--source-date-epoch", required=True, type=int)
    inventory_parser.add_argument("--lock", required=True, type=Path)
    inventory_parser.add_argument("--review", required=True, type=Path)
    inventory_parser.add_argument("--findings", required=True, type=Path)
    inventory_parser.add_argument("--constraints", required=True, type=Path)
    inventory_parser.add_argument("--sbom", required=True, type=Path)
    inventory_parser.add_argument("--uv-version", required=True)
    inventory_parser.add_argument("--source-tree-clean", required=True, choices=("true", "false"))

    verify_inventory_parser = subparsers.add_parser("verify-publication-inventory")
    verify_inventory_parser.add_argument("--inventory-dir", required=True, type=Path)
    verify_inventory_parser.add_argument("--release-sha", required=True)
    verify_inventory_parser.add_argument("--release-version", required=True)

    publication_parser = subparsers.add_parser("finalize-publication")
    publication_parser.add_argument("--output-dir", required=True, type=Path)
    publication_parser.add_argument("--inventory-dir", required=True, type=Path)
    publication_parser.add_argument("--wheel", required=True, type=Path)
    publication_parser.add_argument("--sdist", required=True, type=Path)
    publication_parser.add_argument("--direct-output-dir", required=True, type=Path)
    publication_parser.add_argument("--action-output-dir", required=True, type=Path)
    publication_parser.add_argument("--release-tag", required=True)
    publication_parser.add_argument("--action-commit", required=True)
    publication_parser.add_argument("--expected-wheel-sha256", required=True)
    publication_parser.add_argument("--expected-sdist-sha256", required=True)

    verify_publication_parser = subparsers.add_parser("verify-publication")
    verify_publication_parser.add_argument("--bundle-dir", required=True, type=Path)
    verify_publication_parser.add_argument("--release-tag", required=True)
    verify_publication_parser.add_argument("--release-sha", required=True)
    verify_publication_parser.add_argument("--action-commit")
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
        elif args.command == "hashed-file-uri":
            print(hashed_file_uri(args.file))
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
        elif args.command == "prepare-publication-inventory":
            prepare_publication_inventory(
                output_dir=args.output_dir,
                release_sha=args.release_sha,
                release_version=args.release_version,
                source_date_epoch=args.source_date_epoch,
                lock_path=args.lock,
                review_path=args.review,
                findings_path=args.findings,
                constraints_path=args.constraints,
                sbom_path=args.sbom,
                uv_version=args.uv_version,
                source_tree_clean=args.source_tree_clean == "true",
            )
        elif args.command == "verify-publication-inventory":
            verify_publication_inventory(
                inventory_dir=args.inventory_dir,
                expected_release_sha=args.release_sha,
                expected_release_version=args.release_version,
            )
        elif args.command == "finalize-publication":
            finalize_publication_bundle(
                output_dir=args.output_dir,
                inventory_dir=args.inventory_dir,
                wheel_path=args.wheel,
                sdist_path=args.sdist,
                direct_output_dir=args.direct_output_dir,
                action_output_dir=args.action_output_dir,
                release_tag=args.release_tag,
                action_commit=args.action_commit,
                expected_wheel_sha256=args.expected_wheel_sha256,
                expected_sdist_sha256=args.expected_sdist_sha256,
            )
        elif args.command == "verify-publication":
            verify_publication_bundle(
                bundle_dir=args.bundle_dir,
                expected_release_tag=args.release_tag,
                expected_release_sha=args.release_sha,
                expected_action_commit=args.action_commit,
            )
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except (EvidenceError, OSError) as exc:
        print(f"release evidence failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
