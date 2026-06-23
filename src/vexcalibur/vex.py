"""CycloneDX VEX document generation."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, UUID, uuid5

from cyclonedx.model import XsUri
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.impact_analysis import ImpactAnalysisState
from cyclonedx.model.vulnerability import (
    BomTarget,
    Vulnerability,
    VulnerabilityAnalysis,
    VulnerabilityReference,
    VulnerabilitySource,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

from vexcalibur.domain import ComponentIdentity, VexAnalysisState, VulnerabilityFinding

_FindingGroupKey = tuple[str, str, str, VexAnalysisState, str]


class VexRenderError(ValueError):
    """Raised when domain findings cannot be rendered as a valid VEX document."""


def render_cyclonedx_vex_json(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    timestamp: datetime | None = None,
) -> str:
    """Render deterministic CycloneDX VEX JSON for vulnerability findings."""
    timestamp = _normalize_timestamp(timestamp or datetime.now(tz=timezone.utc))
    findings = _canonical_findings(findings)
    _validate_finding_refs(components=components, findings=findings)
    bom = Bom(
        serial_number=_serial_number(
            components=components,
            findings=findings,
            timestamp=timestamp,
        ),
        metadata=BomMetaData(timestamp=timestamp),
        components=[
            _cyclonedx_component(component)
            for component in _affected_components(components=components, findings=findings)
        ],
        vulnerabilities=[
            _cyclonedx_vulnerability(
                group_key=group_key,
                vulnerability_id=group_key[0],
                source=VulnerabilitySource(name=group_key[1], url=XsUri(group_key[2])),
                findings=vulnerability_findings,
            )
            for group_key, vulnerability_findings in _group_findings(findings)
        ],
    )

    outputter = make_outputter(
        bom=bom,
        output_format=OutputFormat.JSON,
        schema_version=SchemaVersion.V1_6,
    )
    return _canonical_json(outputter.output_as_string())


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp for deterministic VEX output."""
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return _normalize_timestamp(parsed)


def _cyclonedx_vulnerability(
    *,
    group_key: _FindingGroupKey,
    vulnerability_id: str,
    source: VulnerabilitySource,
    findings: tuple[VulnerabilityFinding, ...],
) -> Vulnerability:
    affected_refs = tuple(sorted({finding.component_ref for finding in findings}))
    updated = _latest_modified_timestamp(findings)
    representative = findings[0]
    return Vulnerability(
        bom_ref=_vulnerability_bom_ref(
            group_key=group_key,
        ),
        id=vulnerability_id,
        source=source,
        references=[VulnerabilityReference(id=vulnerability_id, source=source)],
        updated=updated,
        analysis=VulnerabilityAnalysis(
            state=ImpactAnalysisState(representative.analysis_state.value),
            detail=representative.analysis_detail,
        ),
        affects=[BomTarget(ref=component_ref) for component_ref in affected_refs],
    )


def _cyclonedx_component(component: ComponentIdentity) -> Component:
    try:
        component_type = ComponentType(component.type)
    except ValueError:
        component_type = ComponentType.LIBRARY
    return Component(
        bom_ref=component.ref,
        name=component.name,
        type=component_type,
        version=component.version,
        purl=component.purl,
    )


def _affected_components(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
) -> tuple[ComponentIdentity, ...]:
    affected_refs = {finding.component_ref for finding in findings}
    return tuple(
        sorted(
            (component for component in components if component.ref in affected_refs),
            key=lambda component: component.ref,
        )
    )


def _group_findings(
    findings: tuple[VulnerabilityFinding, ...],
) -> tuple[tuple[_FindingGroupKey, tuple[VulnerabilityFinding, ...]], ...]:
    grouped: dict[_FindingGroupKey, list[VulnerabilityFinding]] = defaultdict(list)
    for finding in findings:
        grouped[
            (
                finding.id,
                finding.source_name,
                finding.source_url,
                finding.analysis_state,
                finding.analysis_detail,
            )
        ].append(finding)
    return tuple((group_key, tuple(grouped[group_key])) for group_key in sorted(grouped))


def _validate_finding_refs(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
) -> None:
    component_refs = {component.ref for component in components}
    missing_refs = sorted(
        finding.component_ref for finding in findings if finding.component_ref not in component_refs
    )
    if missing_refs:
        msg = (
            "findings reference components that are not present in the VEX: "
            f"{', '.join(missing_refs)}"
        )
        raise VexRenderError(msg)


def _latest_modified_timestamp(findings: tuple[VulnerabilityFinding, ...]) -> datetime | None:
    parsed = [finding.modified for finding in findings if finding.modified is not None]
    if not parsed:
        return None
    return max(parsed)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _serial_number(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    timestamp: datetime,
) -> UUID:
    canonical = json.dumps(
        {
            "components": [
                {
                    "name": component.name,
                    "purl": component.purl.to_string(),
                    "ref": component.ref,
                    "type": component.type,
                    "version": component.version,
                }
                for component in _affected_components(components=components, findings=findings)
            ],
            "findings": [
                {
                    "analysis_detail": finding.analysis_detail,
                    "analysis_state": finding.analysis_state.value,
                    "component_ref": finding.component_ref,
                    "id": finding.id,
                    "modified": finding.modified.isoformat() if finding.modified else None,
                    "purl": finding.purl,
                    "source_name": finding.source_name,
                    "source_url": finding.source_url,
                }
                for finding in findings
            ],
            "timestamp": timestamp.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return uuid5(NAMESPACE_URL, f"https://vexcalibur.dev/vex/{canonical}")


def _canonical_findings(
    findings: tuple[VulnerabilityFinding, ...],
) -> tuple[VulnerabilityFinding, ...]:
    return tuple(
        dict.fromkeys(
            sorted(
                findings,
                key=lambda finding: (
                    finding.id,
                    finding.source_name,
                    finding.source_url,
                    finding.analysis_state.value,
                    finding.analysis_detail,
                    finding.component_ref,
                    finding.purl,
                    finding.modified.isoformat() if finding.modified else "",
                ),
            )
        )
    )


def _vulnerability_bom_ref(
    *,
    group_key: _FindingGroupKey,
) -> str:
    canonical = json.dumps(
        {
            "analysis_detail": group_key[4],
            "analysis_state": group_key[3].value,
            "id": group_key[0],
            "source_name": group_key[1],
            "source_url": group_key[2],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    source_uuid = uuid5(NAMESPACE_URL, canonical)
    return f"vulnerability:{source_uuid}"


def _canonical_json(value: str) -> str:
    return f"{json.dumps(json.loads(value), indent=2, sort_keys=True)}\n"
