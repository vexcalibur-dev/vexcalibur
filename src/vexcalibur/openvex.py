"""Native OpenVEX 0.2.0 document generation."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from packageurl import PackageURL

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


class OpenVexRenderError(VexRenderError):
    """Raised when findings cannot form a valid standalone OpenVEX document."""


@dataclass(frozen=True)
class OpenVexJsonRenderer:
    """Render OpenVEX 0.2.0 JSON for one document author."""

    author: str
    role: str | None = None

    def __post_init__(self) -> None:
        author = self.author.strip()
        if not author:
            msg = "OpenVEX output requires a nonempty author"
            raise OpenVexRenderError(msg)
        object.__setattr__(self, "author", author)

        if self.role is not None:
            role = self.role.strip()
            if not role:
                msg = "OpenVEX author role must not be empty"
                raise OpenVexRenderError(msg)
            object.__setattr__(self, "role", role)

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Return deterministic OpenVEX 0.2.0 JSON."""
        return render_openvex_json(
            components=components,
            findings=findings,
            author=self.author,
            role=self.role,
            timestamp=timestamp,
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
    normalized_author, normalized_role = _validate_document_metadata(author=author, role=role)
    normalized_timestamp = _normalize_timestamp(timestamp or datetime.now(tz=timezone.utc))
    canonical_findings = _canonical_findings(findings)
    if not canonical_findings:
        msg = "OpenVEX output requires at least one vulnerability finding"
        raise OpenVexRenderError(msg)

    components_by_ref = _components_by_ref(components)
    _validate_findings(findings=canonical_findings, components_by_ref=components_by_ref)
    _validate_no_overlapping_assertions(
        findings=canonical_findings,
        components_by_ref=components_by_ref,
    )

    document: dict[str, object] = {
        "@context": OPENVEX_CONTEXT,
        "author": normalized_author,
        "statements": [
            _statement(
                group_key=group_key,
                findings=group_findings,
                components_by_ref=components_by_ref,
            )
            for group_key, group_findings in _group_findings(canonical_findings)
        ],
        "timestamp": _format_timestamp(normalized_timestamp),
        "tooling": OPENVEX_TOOLING,
        "version": 1,
    }
    if normalized_role is not None:
        document["role"] = normalized_role

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    document["@id"] = (
        f"urn:uuid:{uuid5(NAMESPACE_URL, f'https://vexcalibur.dev/openvex/{canonical}')}"
    )
    return f"{json.dumps(document, indent=2, sort_keys=True)}\n"


def _statement(
    *,
    group_key: _OpenVexGroupKey,
    findings: tuple[VulnerabilityFinding, ...],
    components_by_ref: dict[str, ComponentIdentity],
) -> dict[str, object]:
    state = VexAnalysisState(group_key.analysis_state)
    detail = group_key.analysis_detail
    action_statement = group_key.action_statement or None
    impact_statement = group_key.impact_statement or None
    fixed_version = group_key.fixed_version or None
    modified = group_key.modified or None
    product_purls = sorted(
        {_product_purl(components_by_ref[finding.component_ref]) for finding in findings}
    )
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
                "an action_statement "
                "that describes remediation or mitigation"
            )
            raise OpenVexRenderError(msg)
        statement["action_statement"] = action_statement
    return statement


def _group_findings(
    findings: tuple[VulnerabilityFinding, ...],
) -> tuple[tuple[_OpenVexGroupKey, tuple[VulnerabilityFinding, ...]], ...]:
    grouped: dict[_OpenVexGroupKey, list[VulnerabilityFinding]] = defaultdict(list)
    for finding in findings:
        key = _finding_group_key(finding)
        grouped[key].append(finding)
    return tuple((key, tuple(grouped[key])) for key in sorted(grouped))


def _finding_group_key(finding: VulnerabilityFinding) -> _OpenVexGroupKey:
    return _OpenVexGroupKey(
        vulnerability_id=finding.id,
        source_name=finding.source_name,
        source_url=finding.source_url,
        analysis_state=finding.analysis_state.value,
        analysis_detail=finding.analysis_detail,
        action_statement=finding.action_statement or "",
        impact_statement=finding.impact_statement or "",
        fixed_version=finding.fixed_version or "",
        modified=_format_timestamp(finding.modified) if finding.modified is not None else "",
    )


def _canonical_findings(
    findings: tuple[VulnerabilityFinding, ...],
) -> tuple[VulnerabilityFinding, ...]:
    try:
        return tuple(
            dict.fromkeys(
                sorted(
                    findings,
                    key=lambda finding: (
                        _finding_group_key(finding),
                        finding.component_ref,
                        finding.purl,
                    ),
                )
            )
        )
    except (AttributeError, ValueError) as exc:
        msg = "OpenVEX findings contain an unsupported analysis state or timestamp"
        raise OpenVexRenderError(msg) from exc


def _components_by_ref(
    components: tuple[ComponentIdentity, ...],
) -> dict[str, ComponentIdentity]:
    components_by_ref: dict[str, ComponentIdentity] = {}
    duplicate_refs: set[str] = set()
    for component in components:
        if component.ref in components_by_ref:
            duplicate_refs.add(component.ref)
        components_by_ref[component.ref] = component
    if duplicate_refs:
        msg = f"OpenVEX components contain duplicate refs: {', '.join(sorted(duplicate_refs))}"
        raise OpenVexRenderError(msg)
    return components_by_ref


def _validate_findings(
    *,
    findings: tuple[VulnerabilityFinding, ...],
    components_by_ref: dict[str, ComponentIdentity],
) -> None:
    for finding in findings:
        for field_name, value in (
            ("id", finding.id),
            ("source_name", finding.source_name),
            ("source_url", finding.source_url),
            ("analysis_detail", finding.analysis_detail),
        ):
            if not value.strip():
                msg = f"OpenVEX finding {field_name} must not be empty"
                raise OpenVexRenderError(msg)

        component = components_by_ref.get(finding.component_ref)
        if component is None:
            msg = f"OpenVEX finding references unknown component {finding.component_ref!r}"
            raise OpenVexRenderError(msg)
        component_purl = component.purl.to_string()
        if finding.purl != component_purl:
            msg = (
                f"OpenVEX finding PURL {finding.purl!r} does not match component "
                f"{finding.component_ref!r} PURL {component_purl!r}"
            )
            raise OpenVexRenderError(msg)
        product_purl = _product_purl(component)
        product_version = PackageURL.from_string(product_purl).version
        if product_version is None or not product_version.strip():
            msg = (
                f"OpenVEX product PURL {product_purl!r} must include a version to avoid "
                "applying an assertion to every package version"
            )
            raise OpenVexRenderError(msg)
        if finding.action_statement is not None and not finding.action_statement.strip():
            msg = "OpenVEX action_statement must not be empty"
            raise OpenVexRenderError(msg)
        if (
            finding.action_statement is not None
            and finding.analysis_state is not VexAnalysisState.EXPLOITABLE
        ):
            msg = "OpenVEX action_statement is only valid for an exploitable finding"
            raise OpenVexRenderError(msg)
        if finding.impact_statement is not None and not finding.impact_statement.strip():
            msg = "OpenVEX impact_statement must not be empty"
            raise OpenVexRenderError(msg)
        if finding.analysis_state in {
            VexAnalysisState.FALSE_POSITIVE,
            VexAnalysisState.NOT_AFFECTED,
        }:
            if finding.impact_statement is None:
                msg = "OpenVEX false_positive and not_affected findings require an impact_statement"
                raise OpenVexRenderError(msg)
        elif finding.impact_statement is not None:
            msg = (
                "OpenVEX impact_statement is only valid for a false_positive or "
                "not_affected finding"
            )
            raise OpenVexRenderError(msg)

        if finding.fixed_version is not None and not finding.fixed_version.strip():
            msg = "OpenVEX fixed_version must not be empty"
            raise OpenVexRenderError(msg)
        if finding.analysis_state is VexAnalysisState.RESOLVED:
            _validate_fixed_version(finding=finding, component=component)
        elif finding.fixed_version is not None:
            msg = "OpenVEX fixed_version is only valid for a resolved finding"
            raise OpenVexRenderError(msg)


def _validate_fixed_version(
    *,
    finding: VulnerabilityFinding,
    component: ComponentIdentity,
) -> None:
    if finding.fixed_version is None:
        msg = (
            "OpenVEX resolved findings require fixed_version to confirm that the "
            "identified product contains a fix"
        )
        raise OpenVexRenderError(msg)
    product_version = PackageURL.from_string(_product_purl(component)).version
    if product_version != finding.fixed_version:
        msg = (
            f"OpenVEX fixed_version {finding.fixed_version!r} does not match product "
            f"{_product_purl(component)!r} version {product_version!r}"
        )
        raise OpenVexRenderError(msg)


def _validate_no_overlapping_assertions(
    *,
    findings: tuple[VulnerabilityFinding, ...],
    components_by_ref: dict[str, ComponentIdentity],
) -> None:
    assertions: dict[tuple[str, str], _OpenVexGroupKey] = {}
    for finding in findings:
        product_purl = _product_purl(components_by_ref[finding.component_ref])
        assertion_key = (finding.id, product_purl)
        group_key = _finding_group_key(finding)
        previous = assertions.setdefault(assertion_key, group_key)
        if previous != group_key:
            msg = (
                f"OpenVEX findings contain overlapping assertions for vulnerability "
                f"{finding.id!r} and product {product_purl!r}"
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


def _product_purl(component: ComponentIdentity) -> str:
    purl = component.purl
    if purl.version is not None or not component.version:
        return purl.to_string()
    return PackageURL(
        type=purl.type,
        namespace=purl.namespace,
        name=purl.name,
        version=component.version,
        qualifiers=purl.qualifiers,
        subpath=purl.subpath,
    ).to_string()


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
