"""Native OpenVEX 0.2.0 document generation."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from packageurl import PackageURL

from vexcalibur.document import (
    VexAssertion,
    VexDocument,
    analysis_state,
    product_purl,
    validate_vex_document,
    versioned_product_purl,
    vex_document_from_findings,
)
from vexcalibur.domain import ComponentIdentity, VexAnalysisState, VulnerabilityFinding
from vexcalibur.render import VexRenderError

OPENVEX_SPEC_VERSION = "0.2.0"
OPENVEX_CONTEXT = f"https://openvex.dev/ns/v{OPENVEX_SPEC_VERSION}"
OPENVEX_TOOLING = "Vexcalibur"

_STATUS_BY_STATE = {
    VexAnalysisState.RESOLVED: "fixed",
    VexAnalysisState.EXPLOITABLE: "affected",
    VexAnalysisState.IN_TRIAGE: "under_investigation",
    VexAnalysisState.FALSE_POSITIVE: "not_affected",
    VexAnalysisState.NOT_AFFECTED: "not_affected",
}


@dataclass(frozen=True, order=True)
class _OpenVexGroupKey:
    vulnerability_id: str
    source_name: str
    source_url: str
    analysis_state: str
    analysis_detail: str
    action_statement: str
    impact_statement: str
    fixed_version: str
    modified: str


_OpenVexAssertionKey = tuple[_OpenVexGroupKey, str, str]


class OpenVexRenderError(VexRenderError):
    """Raised when findings cannot form a valid standalone OpenVEX document."""


@dataclass(frozen=True)
class OpenVexJsonRenderer:
    """Render OpenVEX 0.2.0 JSON for one document author."""

    author: str
    role: str | None = None

    def __post_init__(self) -> None:
        author, role = _validate_document_metadata(author=self.author, role=self.role)
        object.__setattr__(self, "author", author)
        object.__setattr__(self, "role", role)

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Adapt provider findings and return OpenVEX 0.2.0 JSON."""
        try:
            document = vex_document_from_findings(components=components, findings=findings)
        except VexRenderError as exc:
            raise OpenVexRenderError(str(exc)) from exc
        return self.render_document(
            document=document,
            timestamp=timestamp,
        )

    def render_document(
        self,
        *,
        document: VexDocument,
        timestamp: datetime | None = None,
    ) -> str:
        """Return deterministic OpenVEX 0.2.0 JSON for a VEX document."""
        return _render_openvex_document(
            document=document,
            author=self.author,
            role=self.role,
            timestamp=_normalize_timestamp(timestamp or datetime.now(tz=timezone.utc)),
        )


def render_openvex_json(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    author: str,
    role: str | None = None,
    timestamp: datetime | None = None,
) -> str:
    """Render deterministic OpenVEX 0.2.0 JSON."""
    return OpenVexJsonRenderer(author=author, role=role).render(
        components=components,
        findings=findings,
        timestamp=timestamp,
    )


def _render_openvex_document(
    *,
    document: VexDocument,
    author: str,
    role: str | None,
    timestamp: datetime,
) -> str:
    try:
        validate_vex_document(document)
    except VexRenderError as exc:
        raise OpenVexRenderError(str(exc)) from exc
    canonical_assertions = _canonical_assertions(document.assertions)
    if not canonical_assertions:
        msg = "OpenVEX output requires at least one vulnerability finding"
        raise OpenVexRenderError(msg)

    _validate_assertions(canonical_assertions)
    _validate_no_overlapping_assertions(canonical_assertions)

    openvex_document: dict[str, object] = {
        "@context": OPENVEX_CONTEXT,
        "author": author,
        "statements": [
            _statement(group_key=group_key, assertions=group_assertions)
            for group_key, group_assertions in _group_assertions(canonical_assertions)
        ],
        "timestamp": _format_timestamp(timestamp),
        "tooling": OPENVEX_TOOLING,
        "version": 1,
    }
    if role is not None:
        openvex_document["role"] = role

    canonical = json.dumps(openvex_document, sort_keys=True, separators=(",", ":"))
    openvex_document["@id"] = (
        f"urn:uuid:{uuid5(NAMESPACE_URL, f'https://vexcalibur.dev/openvex/{canonical}')}"
    )
    return f"{json.dumps(openvex_document, indent=2, sort_keys=True)}\n"


def _statement(
    *,
    group_key: _OpenVexGroupKey,
    assertions: tuple[VexAssertion, ...],
) -> dict[str, object]:
    state = VexAnalysisState(group_key.analysis_state)
    detail = group_key.analysis_detail
    action_statement = group_key.action_statement or None
    impact_statement = group_key.impact_statement or None
    fixed_version = group_key.fixed_version or None
    modified = group_key.modified or None
    product_purls = sorted({versioned_product_purl(assertion.product) for assertion in assertions})
    statement: dict[str, object] = {
        "products": [{"@id": purl, "identifiers": {"purl": purl}} for purl in product_purls],
        "status": _STATUS_BY_STATE[state],
        "status_notes": _status_notes(
            detail=detail,
            source_name=group_key.source_name,
            source_url=group_key.source_url,
            state=state,
            fixed_version=fixed_version,
            modified=modified,
        ),
        "vulnerability": {"name": group_key.vulnerability_id},
    }
    if state in {VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED}:
        if impact_statement is None:
            msg = (
                f"OpenVEX not_affected statement {group_key.vulnerability_id!r} requires "
                "an impact_statement that explains why the product is not affected"
            )
            raise OpenVexRenderError(msg)
        statement["impact_statement"] = impact_statement
    elif state is VexAnalysisState.EXPLOITABLE:
        if action_statement is None:
            msg = (
                f"OpenVEX affected statement {group_key.vulnerability_id!r} requires "
                "an action_statement that describes remediation or mitigation"
            )
            raise OpenVexRenderError(msg)
        statement["action_statement"] = action_statement
    return statement


def _group_assertions(
    assertions: tuple[VexAssertion, ...],
) -> tuple[tuple[_OpenVexGroupKey, tuple[VexAssertion, ...]], ...]:
    grouped: dict[_OpenVexGroupKey, list[VexAssertion]] = defaultdict(list)
    for assertion in assertions:
        key = _assertion_group_key(assertion)
        grouped[key].append(assertion)
    return tuple((key, tuple(grouped[key])) for key in sorted(grouped))


def _assertion_group_key(assertion: VexAssertion) -> _OpenVexGroupKey:
    vulnerability = assertion.vulnerability
    return _OpenVexGroupKey(
        vulnerability_id=vulnerability.id,
        source_name=vulnerability.source_name,
        source_url=vulnerability.source_url,
        analysis_state=analysis_state(assertion).value,
        analysis_detail=assertion.analysis_detail,
        action_statement=assertion.action_statement or "",
        impact_statement=assertion.impact_statement or "",
        fixed_version=assertion.fixed_version or "",
        modified=(
            _format_timestamp(assertion.source_record_modified_at)
            if assertion.source_record_modified_at is not None
            else ""
        ),
    )


def _canonical_assertions(
    assertions: tuple[VexAssertion, ...],
) -> tuple[VexAssertion, ...]:
    canonical: dict[_OpenVexAssertionKey, VexAssertion] = {}
    try:
        for assertion in sorted(assertions, key=_openvex_assertion_key):
            canonical.setdefault(_openvex_assertion_key(assertion), assertion)
    except (AttributeError, ValueError, VexRenderError) as exc:
        msg = "OpenVEX findings contain an unsupported analysis state or timestamp"
        raise OpenVexRenderError(msg) from exc
    return tuple(canonical.values())


def _openvex_assertion_key(assertion: VexAssertion) -> _OpenVexAssertionKey:
    return (
        _assertion_group_key(assertion),
        assertion.product.key,
        product_purl(assertion.product).to_string(),
    )


def _validate_assertions(assertions: tuple[VexAssertion, ...]) -> None:
    for assertion in assertions:
        vulnerability = assertion.vulnerability
        for field_name, value in (
            ("id", vulnerability.id),
            ("source_name", vulnerability.source_name),
            ("source_url", vulnerability.source_url),
            ("analysis_detail", assertion.analysis_detail),
        ):
            if not value.strip():
                msg = f"OpenVEX finding {field_name} must not be empty"
                raise OpenVexRenderError(msg)

        emitted_purl = versioned_product_purl(assertion.product)
        product_version = PackageURL.from_string(emitted_purl).version
        if product_version is None or not product_version.strip():
            msg = (
                f"OpenVEX product PURL {emitted_purl!r} must include a version to avoid "
                "applying an assertion to every package version"
            )
            raise OpenVexRenderError(msg)
        state = analysis_state(assertion)
        if assertion.action_statement is not None and not assertion.action_statement.strip():
            msg = "OpenVEX action_statement must not be empty"
            raise OpenVexRenderError(msg)
        if assertion.action_statement is not None and state is not VexAnalysisState.EXPLOITABLE:
            msg = "OpenVEX action_statement is only valid for an exploitable finding"
            raise OpenVexRenderError(msg)
        if assertion.impact_statement is not None and not assertion.impact_statement.strip():
            msg = "OpenVEX impact_statement must not be empty"
            raise OpenVexRenderError(msg)
        if state in {
            VexAnalysisState.FALSE_POSITIVE,
            VexAnalysisState.NOT_AFFECTED,
        }:
            if assertion.impact_statement is None:
                msg = "OpenVEX false_positive and not_affected findings require an impact_statement"
                raise OpenVexRenderError(msg)
        elif assertion.impact_statement is not None:
            msg = (
                "OpenVEX impact_statement is only valid for a false_positive or "
                "not_affected finding"
            )
            raise OpenVexRenderError(msg)

        if assertion.fixed_version is not None and not assertion.fixed_version.strip():
            msg = "OpenVEX fixed_version must not be empty"
            raise OpenVexRenderError(msg)
        if state is VexAnalysisState.RESOLVED:
            _validate_fixed_version(assertion)
        elif assertion.fixed_version is not None:
            msg = "OpenVEX fixed_version is only valid for a resolved finding"
            raise OpenVexRenderError(msg)


def _validate_fixed_version(assertion: VexAssertion) -> None:
    if assertion.fixed_version is None:
        msg = (
            "OpenVEX resolved findings require fixed_version to confirm that the "
            "identified product contains a fix"
        )
        raise OpenVexRenderError(msg)
    emitted_purl = versioned_product_purl(assertion.product)
    product_version = PackageURL.from_string(emitted_purl).version
    if product_version != assertion.fixed_version:
        msg = (
            f"OpenVEX fixed_version {assertion.fixed_version!r} does not match product "
            f"{emitted_purl!r} version {product_version!r}"
        )
        raise OpenVexRenderError(msg)


def _validate_no_overlapping_assertions(assertions: tuple[VexAssertion, ...]) -> None:
    effective_assertions: dict[tuple[str, str], _OpenVexGroupKey] = {}
    for assertion in assertions:
        product = versioned_product_purl(assertion.product)
        assertion_key = (assertion.vulnerability.id, product)
        group_key = _assertion_group_key(assertion)
        previous = effective_assertions.setdefault(assertion_key, group_key)
        if previous != group_key:
            msg = (
                "OpenVEX findings contain overlapping assertions for vulnerability "
                f"{assertion.vulnerability.id!r} and product {product!r}"
            )
            raise OpenVexRenderError(msg)


def _validate_document_metadata(*, author: str, role: str | None) -> tuple[str, str | None]:
    normalized_author = author.strip()
    if not normalized_author:
        msg = "OpenVEX output requires a nonempty author"
        raise OpenVexRenderError(msg)
    if role is None:
        return normalized_author, None
    normalized_role = role.strip()
    if not normalized_role:
        msg = "OpenVEX author role must not be empty"
        raise OpenVexRenderError(msg)
    return normalized_author, normalized_role


def _status_notes(
    *,
    detail: str,
    source_name: str,
    source_url: str,
    state: VexAnalysisState,
    fixed_version: str | None,
    modified: str | None,
) -> str:
    notes = [
        f"Analysis detail: {detail}",
        f"Source: {source_name} ({source_url})",
        f"Original Vexcalibur analysis state: {state.value}",
    ]
    if fixed_version is not None:
        notes.append(f"Confirmed fixed product version: {fixed_version}")
    if modified is not None:
        notes.append(f"Source record modified: {modified}")
    return "\n".join(notes)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return _normalize_timestamp(value).isoformat().replace("+00:00", "Z")
