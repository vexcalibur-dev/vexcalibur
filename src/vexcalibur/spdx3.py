"""Native SPDX 3.0.1 security-profile JSON-LD generation."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from packageurl import PackageURL

from vexcalibur import __version__
from vexcalibur.document import (
    VexAssertion,
    VexDocument,
    VexProduct,
    analysis_state,
    product_purl,
    validate_vex_document,
    versioned_product_purl,
    vex_document_from_findings,
)
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.errors import VexRenderError
from vexcalibur.render_budget import enforce_builtin_render_input_budget

SPDX3_SPEC_VERSION = "3.0.1"
SPDX3_CONTEXT = f"https://spdx.org/rdf/{SPDX3_SPEC_VERSION}/spdx-context.jsonld"
SPDX3_TOOL_NAME = "Vexcalibur"

_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_NAMESPACE_PLACEHOLDER = "urn:vexcalibur:spdx3:unassigned-document-namespace"
_CREATION_INFO_ID = "_:creationinfo"
_RELATIONSHIP_BY_STATE = {
    VexAnalysisState.RESOLVED: (
        "security_VexFixedVulnAssessmentRelationship",
        "fixedIn",
    ),
    VexAnalysisState.EXPLOITABLE: (
        "security_VexAffectedVulnAssessmentRelationship",
        "affects",
    ),
    VexAnalysisState.IN_TRIAGE: (
        "security_VexUnderInvestigationVulnAssessmentRelationship",
        "underInvestigationFor",
    ),
    VexAnalysisState.FALSE_POSITIVE: (
        "security_VexNotAffectedVulnAssessmentRelationship",
        "doesNotAffect",
    ),
    VexAnalysisState.NOT_AFFECTED: (
        "security_VexNotAffectedVulnAssessmentRelationship",
        "doesNotAffect",
    ),
}


class Spdx3RenderError(VexRenderError):
    """Raised when findings cannot form a valid SPDX 3.0.1 VEX document."""


@dataclass(frozen=True, order=True)
class _Spdx3GroupKey:
    vulnerability_id: str
    source_name: str
    source_url: str
    analysis_state: str
    analysis_detail: str
    action_statement: str
    impact_statement: str
    fixed_version: str
    remediation_category: str
    modified: str


_Spdx3AssertionKey = tuple[_Spdx3GroupKey, str, str]


@dataclass(frozen=True)
class Spdx3JsonRenderer:
    """Render SPDX 3.0.1 JSON-LD using the security profile's VEX relationships.

    Attributes:
        creator: Name recorded as the document's creating Agent.
        tool_version: Vexcalibur version recorded on the creating Tool.

    Raises:
        Spdx3RenderError: ``creator`` or ``tool_version`` is empty.
    """

    creator: str
    tool_version: str = field(default_factory=lambda: __version__)

    def __post_init__(self) -> None:
        normalized_creator = self.creator.strip()
        if not normalized_creator:
            msg = "SPDX output requires a nonempty creator"
            raise Spdx3RenderError(msg)
        normalized_tool_version = self.tool_version.strip()
        if not normalized_tool_version:
            msg = "SPDX generator tool version must not be empty"
            raise Spdx3RenderError(msg)
        object.__setattr__(self, "creator", normalized_creator)
        object.__setattr__(self, "tool_version", normalized_tool_version)

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Adapt provider findings and return SPDX 3.0.1 JSON-LD.

        Args:
            components: Components available to the document.
            findings: Findings associated with those components.
            timestamp: Document timestamp, or ``None`` to use current UTC.

        Returns:
            Serialized SPDX 3.0.1 JSON-LD.

        Raises:
            Spdx3RenderError: The values cannot form a valid document.
        """
        if type(self)._render_document is Spdx3JsonRenderer._render_document:
            enforce_builtin_render_input_budget(
                components=components,
                findings=findings,
                component_purl_copies=2,
                additional_text=(self.creator, self.tool_version),
            )
        try:
            document = vex_document_from_findings(components=components, findings=findings)
        except VexRenderError as exc:
            raise Spdx3RenderError(str(exc)) from exc
        return self._render_document(document=document, timestamp=timestamp)

    def _render_document(
        self,
        *,
        document: VexDocument,
        timestamp: datetime | None = None,
    ) -> str:
        """Return deterministic SPDX 3.0.1 JSON-LD for a VEX document."""
        return _render_spdx3_document(
            document=document,
            creator=self.creator,
            tool_version=self.tool_version,
            timestamp=_normalize_timestamp(timestamp or datetime.now(tz=timezone.utc)),
        )


def render_spdx3_json(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    creator: str,
    timestamp: datetime | None = None,
    tool_version: str | None = None,
) -> str:
    """Render deterministic SPDX 3.0.1 JSON-LD."""
    renderer = (
        Spdx3JsonRenderer(creator=creator)
        if tool_version is None
        else Spdx3JsonRenderer(creator=creator, tool_version=tool_version)
    )
    return renderer.render(components=components, findings=findings, timestamp=timestamp)


@dataclass(frozen=True, order=True)
class _CanonicalPackage:
    purl: str
    name: str
    version: str


def _render_spdx3_document(
    *,
    document: VexDocument,
    creator: str,
    tool_version: str,
    timestamp: datetime,
) -> str:
    try:
        validate_vex_document(document)
    except VexRenderError as exc:
        raise Spdx3RenderError(str(exc)) from exc
    assertions = _canonical_assertions(document.assertions)
    if not assertions:
        msg = "SPDX output requires at least one vulnerability finding"
        raise Spdx3RenderError(msg)
    _validate_assertions(assertions)
    _validate_no_overlapping_assertions(assertions)

    packages = _canonical_packages(assertions)
    package_locals = {package.purl: f"package-{index}" for index, package in enumerate(packages)}
    grouped_by_vulnerability: dict[str, list[VexAssertion]] = defaultdict(list)
    for assertion in assertions:
        grouped_by_vulnerability[assertion.vulnerability.id].append(assertion)
    assertions_by_vulnerability = {
        vulnerability_id: tuple(grouped_by_vulnerability[vulnerability_id])
        for vulnerability_id in sorted(grouped_by_vulnerability)
    }
    vulnerability_locals = {
        vulnerability_id: f"vulnerability-{index}"
        for index, vulnerability_id in enumerate(assertions_by_vulnerability)
    }
    groups = _group_assertions(assertions)

    def build_graph(namespace: str) -> list[dict[str, object]]:
        return _graph(
            namespace=namespace,
            assertions_by_vulnerability=assertions_by_vulnerability,
            packages=packages,
            package_locals=package_locals,
            vulnerability_locals=vulnerability_locals,
            groups=groups,
            creator=creator,
            tool_version=tool_version,
            timestamp=timestamp,
        )

    canonical = json.dumps(
        {"@context": SPDX3_CONTEXT, "@graph": build_graph(_NAMESPACE_PLACEHOLDER)},
        sort_keys=True,
        separators=(",", ":"),
    )
    document_uuid = uuid5(NAMESPACE_URL, f"https://vexcalibur.dev/spdx3/{canonical}")
    namespace = f"https://vexcalibur.dev/spdx3/{document_uuid}"
    spdx_document = {"@context": SPDX3_CONTEXT, "@graph": build_graph(namespace)}
    return f"{json.dumps(spdx_document, indent=2, sort_keys=True)}\n"


def _graph(
    *,
    namespace: str,
    assertions_by_vulnerability: dict[str, tuple[VexAssertion, ...]],
    packages: tuple[_CanonicalPackage, ...],
    package_locals: dict[str, str],
    vulnerability_locals: dict[str, str],
    groups: tuple[tuple[_Spdx3GroupKey, tuple[VexAssertion, ...]], ...],
    creator: str,
    tool_version: str,
    timestamp: datetime,
) -> list[dict[str, object]]:
    def iri(local: str) -> str:
        return f"{namespace}#{local}"

    agent_iri = iri("agent")
    tool_iri = iri("tool")
    creation_info: dict[str, object] = {
        "@id": _CREATION_INFO_ID,
        "type": "CreationInfo",
        "specVersion": SPDX3_SPEC_VERSION,
        "created": _format_spdx_timestamp(timestamp),
        "createdBy": [agent_iri],
        "createdUsing": [tool_iri],
    }
    agent: dict[str, object] = {
        "type": "Agent",
        "spdxId": agent_iri,
        "creationInfo": _CREATION_INFO_ID,
        "name": creator,
    }
    tool: dict[str, object] = {
        "type": "Tool",
        "spdxId": tool_iri,
        "creationInfo": _CREATION_INFO_ID,
        "name": SPDX3_TOOL_NAME,
        "description": f"{SPDX3_TOOL_NAME} {tool_version}",
    }

    package_elements = [
        _package_element(
            package=package,
            spdx_id=iri(package_locals[package.purl]),
        )
        for package in packages
    ]
    vulnerability_elements = [
        _vulnerability_element(
            vulnerability_id=vulnerability_id,
            spdx_id=iri(vulnerability_locals[vulnerability_id]),
            related=assertions_by_vulnerability[vulnerability_id],
        )
        for vulnerability_id in sorted(vulnerability_locals)
    ]
    relationship_elements = [
        _relationship_element(
            group_key=group_key,
            group_assertions=group_assertions,
            spdx_id=iri(f"assessment-{index}"),
            vulnerability_iri=iri(vulnerability_locals[group_key.vulnerability_id]),
            package_locals=package_locals,
            namespace=namespace,
        )
        for index, (group_key, group_assertions) in enumerate(groups)
    ]

    contained = sorted(
        str(element["spdxId"])
        for element in (*package_elements, *vulnerability_elements, *relationship_elements)
    )
    spdx_document: dict[str, object] = {
        "type": "SpdxDocument",
        "spdxId": iri("document"),
        "creationInfo": _CREATION_INFO_ID,
        "profileConformance": ["core", "security", "software"],
        "element": sorted((agent_iri, tool_iri, *contained)),
        "rootElement": sorted(str(element["spdxId"]) for element in relationship_elements),
    }
    return [
        creation_info,
        spdx_document,
        agent,
        tool,
        *package_elements,
        *vulnerability_elements,
        *relationship_elements,
    ]


def _package_element(*, package: _CanonicalPackage, spdx_id: str) -> dict[str, object]:
    return {
        "type": "software_Package",
        "spdxId": spdx_id,
        "creationInfo": _CREATION_INFO_ID,
        "name": package.name,
        "software_packageVersion": package.version,
        "software_packageUrl": package.purl,
    }


def _vulnerability_element(
    *,
    vulnerability_id: str,
    spdx_id: str,
    related: tuple[VexAssertion, ...],
) -> dict[str, object]:
    locators = sorted({assertion.vulnerability.source_url for assertion in related})
    identifier_type = "cve" if _CVE_PATTERN.fullmatch(vulnerability_id) else "securityOther"
    element: dict[str, object] = {
        "type": "security_Vulnerability",
        "spdxId": spdx_id,
        "creationInfo": _CREATION_INFO_ID,
        "name": vulnerability_id,
        "externalIdentifier": [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": identifier_type,
                "identifier": vulnerability_id,
                "identifierLocator": locators,
            }
        ],
    }
    modified_values = {
        assertion.source_record_modified_at
        for assertion in related
        if assertion.source_record_modified_at is not None
    }
    if len(modified_values) == 1:
        element["security_modifiedTime"] = _format_spdx_timestamp(
            _normalize_timestamp(next(iter(modified_values)))
        )
    return element


def _relationship_element(
    *,
    group_key: _Spdx3GroupKey,
    group_assertions: tuple[VexAssertion, ...],
    spdx_id: str,
    vulnerability_iri: str,
    package_locals: dict[str, str],
    namespace: str,
) -> dict[str, object]:
    state = VexAnalysisState(group_key.analysis_state)
    element_type, relationship_type = _RELATIONSHIP_BY_STATE[state]
    product_iris = sorted(
        {
            f"{namespace}#{package_locals[_canonical_versioned_purl(assertion.product)]}"
            for assertion in group_assertions
        }
    )
    element: dict[str, object] = {
        "type": element_type,
        "spdxId": spdx_id,
        "creationInfo": _CREATION_INFO_ID,
        "relationshipType": relationship_type,
        "from": vulnerability_iri,
        "to": product_iris,
        "security_statusNotes": _status_notes(group_key=group_key, state=state),
    }
    if state is VexAnalysisState.EXPLOITABLE:
        if not group_key.action_statement:
            msg = (
                f"SPDX affected relationship for {group_key.vulnerability_id!r} requires "
                "an action_statement that describes remediation or mitigation"
            )
            raise Spdx3RenderError(msg)
        element["security_actionStatement"] = group_key.action_statement
    elif state in {VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED}:
        if not group_key.impact_statement:
            msg = (
                f"SPDX not-affected relationship for {group_key.vulnerability_id!r} requires "
                "an impact_statement that explains why the product is not affected"
            )
            raise Spdx3RenderError(msg)
        element["security_impactStatement"] = group_key.impact_statement
    return element


def _status_notes(*, group_key: _Spdx3GroupKey, state: VexAnalysisState) -> str:
    notes = [
        f"Analysis detail: {group_key.analysis_detail}",
        f"Source: {group_key.source_name} ({group_key.source_url})",
        f"Original Vexcalibur analysis state: {state.value}",
    ]
    if group_key.remediation_category:
        notes.append(f"Remediation category: {group_key.remediation_category}")
    if group_key.fixed_version:
        notes.append(f"Confirmed fixed product version: {group_key.fixed_version}")
    if group_key.modified:
        notes.append(f"Source record modified: {group_key.modified}")
    return "\n".join(notes)


def _canonical_packages(assertions: tuple[VexAssertion, ...]) -> tuple[_CanonicalPackage, ...]:
    names_by_purl: dict[str, set[str]] = defaultdict(set)
    for assertion in assertions:
        purl = _canonical_versioned_purl(assertion.product)
        product_name = assertion.product.name.strip()
        if not product_name:
            msg = f"SPDX product {assertion.product.key!r} name must not be empty"
            raise Spdx3RenderError(msg)
        names_by_purl[purl].add(product_name)

    packages = []
    for purl in sorted(names_by_purl):
        version = PackageURL.from_string(purl).version
        if version is None:
            raise AssertionError("canonical SPDX PURL validation did not require a version")
        packages.append(
            _CanonicalPackage(purl=purl, name=min(names_by_purl[purl]), version=version)
        )
    return tuple(packages)


def _group_assertions(
    assertions: tuple[VexAssertion, ...],
) -> tuple[tuple[_Spdx3GroupKey, tuple[VexAssertion, ...]], ...]:
    grouped: dict[_Spdx3GroupKey, list[VexAssertion]] = defaultdict(list)
    for assertion in assertions:
        grouped[_assertion_group_key(assertion)].append(assertion)
    return tuple((key, tuple(grouped[key])) for key in sorted(grouped))


def _assertion_group_key(assertion: VexAssertion) -> _Spdx3GroupKey:
    vulnerability = assertion.vulnerability
    return _Spdx3GroupKey(
        vulnerability_id=vulnerability.id,
        source_name=vulnerability.source_name,
        source_url=vulnerability.source_url,
        analysis_state=analysis_state(assertion).value,
        analysis_detail=assertion.analysis_detail,
        action_statement=assertion.action_statement or "",
        impact_statement=assertion.impact_statement or "",
        fixed_version=assertion.fixed_version or "",
        remediation_category=(
            assertion.remediation_category.value
            if isinstance(assertion.remediation_category, VexRemediationCategory)
            else ""
        ),
        modified=(
            _format_timestamp(assertion.source_record_modified_at)
            if assertion.source_record_modified_at is not None
            else ""
        ),
    )


def _canonical_assertions(
    assertions: tuple[VexAssertion, ...],
) -> tuple[VexAssertion, ...]:
    canonical: dict[_Spdx3AssertionKey, VexAssertion] = {}
    try:
        for assertion in sorted(assertions, key=_spdx3_assertion_key):
            canonical.setdefault(_spdx3_assertion_key(assertion), assertion)
    except (AttributeError, ValueError, VexRenderError) as exc:
        msg = "SPDX findings contain an unsupported analysis state or timestamp"
        raise Spdx3RenderError(msg) from exc
    return tuple(canonical.values())


def _spdx3_assertion_key(assertion: VexAssertion) -> _Spdx3AssertionKey:
    return (
        _assertion_group_key(assertion),
        assertion.product.key,
        product_purl(assertion.product).to_string(),
    )


def _canonical_versioned_purl(product: VexProduct) -> str:
    try:
        purl = versioned_product_purl(product)
        parsed = PackageURL.from_string(purl)
    except (TypeError, ValueError, VexRenderError) as exc:
        msg = f"SPDX product {product.key!r} contains an invalid package URL: {exc}"
        raise Spdx3RenderError(msg) from exc
    if parsed.version is None or not parsed.version.strip():
        msg = (
            f"SPDX product PURL {purl!r} must include a version to avoid applying "
            "an assertion to every package version"
        )
        raise Spdx3RenderError(msg)
    return parsed.to_string()


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
                msg = f"SPDX finding {field_name} must not be empty"
                raise Spdx3RenderError(msg)

        _canonical_versioned_purl(assertion.product)
        state = analysis_state(assertion)
        _validate_action_and_remediation(assertion, state=state)
        _validate_impact(assertion, state=state)
        _validate_fixed_version(assertion, state=state)


def _validate_action_and_remediation(
    assertion: VexAssertion,
    *,
    state: VexAnalysisState,
) -> None:
    action = assertion.action_statement
    category = assertion.remediation_category
    if action is not None and not action.strip():
        msg = "SPDX action_statement must not be empty"
        raise Spdx3RenderError(msg)

    if state is VexAnalysisState.EXPLOITABLE:
        if action is None:
            msg = (
                f"SPDX affected relationship for {assertion.vulnerability.id!r} requires "
                "an action_statement that describes remediation or mitigation"
            )
            raise Spdx3RenderError(msg)
        if category is not None and not isinstance(category, VexRemediationCategory):
            msg = "SPDX remediation_category is not supported"
            raise Spdx3RenderError(msg)
        return

    if action is not None:
        msg = "SPDX action_statement is only valid for an exploitable finding"
        raise Spdx3RenderError(msg)
    if category is not None:
        msg = "SPDX remediation_category is only valid for an exploitable finding"
        raise Spdx3RenderError(msg)


def _validate_impact(assertion: VexAssertion, *, state: VexAnalysisState) -> None:
    impact = assertion.impact_statement
    if impact is not None and not impact.strip():
        msg = "SPDX impact_statement must not be empty"
        raise Spdx3RenderError(msg)
    if state in {VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED}:
        if impact is None:
            msg = "SPDX false_positive and not_affected findings require an impact_statement"
            raise Spdx3RenderError(msg)
        return
    if impact is not None:
        msg = "SPDX impact_statement is only valid for a false_positive or not_affected finding"
        raise Spdx3RenderError(msg)


def _validate_fixed_version(assertion: VexAssertion, *, state: VexAnalysisState) -> None:
    fixed_version = assertion.fixed_version
    if fixed_version is not None and not fixed_version.strip():
        msg = "SPDX fixed_version must not be empty"
        raise Spdx3RenderError(msg)
    if state is not VexAnalysisState.RESOLVED:
        if fixed_version is not None:
            msg = "SPDX fixed_version is only valid for a resolved finding"
            raise Spdx3RenderError(msg)
        return
    if fixed_version is None:
        msg = (
            "SPDX resolved findings require fixed_version to confirm that the "
            "identified product contains a fix"
        )
        raise Spdx3RenderError(msg)
    purl = _canonical_versioned_purl(assertion.product)
    product_version = PackageURL.from_string(purl).version
    if product_version != fixed_version:
        msg = (
            f"SPDX fixed_version {fixed_version!r} does not match product "
            f"{purl!r} version {product_version!r}"
        )
        raise Spdx3RenderError(msg)


def _validate_no_overlapping_assertions(assertions: tuple[VexAssertion, ...]) -> None:
    effective_assertions: dict[tuple[str, str], _Spdx3GroupKey] = {}
    for assertion in assertions:
        product = _canonical_versioned_purl(assertion.product)
        assertion_key = (assertion.vulnerability.id, product)
        group_key = _assertion_group_key(assertion)
        previous = effective_assertions.setdefault(assertion_key, group_key)
        if previous != group_key:
            msg = (
                "SPDX findings contain overlapping assertions for vulnerability "
                f"{assertion.vulnerability.id!r} and product {product!r}"
            )
            raise Spdx3RenderError(msg)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return _normalize_timestamp(value).isoformat().replace("+00:00", "Z")


def _format_spdx_timestamp(value: datetime) -> str:
    truncated = _normalize_timestamp(value).replace(microsecond=0)
    return truncated.isoformat().replace("+00:00", "Z")
