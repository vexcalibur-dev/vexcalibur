"""CycloneDX VEX document generation."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from uuid import NAMESPACE_URL, UUID, uuid5

from cyclonedx.model import XsUri
from cyclonedx.model.bom import Bom, BomMetaData
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

from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.sources.osv import OsvQueryResult

OSV_SOURCE_NAME = "OSV"
OSV_SOURCE_URL = "https://osv.dev/"
DEFAULT_ANALYSIS_DETAIL = "Detected by OSV; manual exploitability analysis required."


class VexAnalysisState(str, Enum):
    """CycloneDX VEX analysis states supported by the CLI."""

    RESOLVED = "resolved"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"


def findings_from_osv_results(
    *,
    components: tuple[ComponentIdentity, ...],
    results: list[OsvQueryResult],
) -> tuple[VulnerabilityFinding, ...]:
    """Map OSV query results onto affected SBOM component references."""
    components_by_purl: dict[str, list[ComponentIdentity]] = defaultdict(list)
    for component in components:
        components_by_purl[component.purl.to_string()].append(component)

    findings: list[VulnerabilityFinding] = []
    for result in results:
        for vulnerability in result.vulnerabilities:
            for component in components_by_purl[result.purl]:
                findings.append(
                    VulnerabilityFinding(
                        id=vulnerability.id,
                        source_name=OSV_SOURCE_NAME,
                        source_url=OSV_SOURCE_URL,
                        component_ref=component.ref,
                        purl=result.purl,
                        modified=vulnerability.modified,
                    )
                )

    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.id,
                finding.source_name,
                finding.component_ref,
                finding.purl,
            ),
        )
    )


def render_cyclonedx_vex_json(
    *,
    findings: tuple[VulnerabilityFinding, ...],
    analysis_state: VexAnalysisState = VexAnalysisState.IN_TRIAGE,
    timestamp: datetime | None = None,
) -> str:
    """Render deterministic CycloneDX VEX JSON for vulnerability findings."""
    timestamp = _normalize_timestamp(timestamp or datetime.now(tz=timezone.utc))
    bom = Bom(
        serial_number=_serial_number(
            findings=findings, analysis_state=analysis_state, timestamp=timestamp
        ),
        metadata=BomMetaData(timestamp=timestamp),
        vulnerabilities=[
            _cyclonedx_vulnerability(
                vulnerability_id=vulnerability_id,
                source=VulnerabilitySource(name=source_name, url=XsUri(source_url)),
                findings=vulnerability_findings,
                analysis_state=analysis_state,
            )
            for (
                vulnerability_id,
                source_name,
                source_url,
            ), vulnerability_findings in _group_findings(findings)
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
    vulnerability_id: str,
    source: VulnerabilitySource,
    findings: tuple[VulnerabilityFinding, ...],
    analysis_state: VexAnalysisState,
) -> Vulnerability:
    affected_refs = tuple(sorted({finding.component_ref for finding in findings}))
    updated = _latest_modified_timestamp(findings)
    return Vulnerability(
        bom_ref=f"vulnerability:{vulnerability_id}",
        id=vulnerability_id,
        source=source,
        references=[VulnerabilityReference(id=vulnerability_id, source=source)],
        updated=updated,
        analysis=VulnerabilityAnalysis(
            state=ImpactAnalysisState(analysis_state.value),
            detail=DEFAULT_ANALYSIS_DETAIL,
        ),
        affects=[BomTarget(ref=component_ref) for component_ref in affected_refs],
    )


def _group_findings(
    findings: tuple[VulnerabilityFinding, ...],
) -> tuple[tuple[tuple[str, str, str], tuple[VulnerabilityFinding, ...]], ...]:
    grouped: dict[tuple[str, str, str], list[VulnerabilityFinding]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.id, finding.source_name, finding.source_url)].append(finding)
    return tuple((group_key, tuple(grouped[group_key])) for group_key in sorted(grouped))


def _latest_modified_timestamp(findings: tuple[VulnerabilityFinding, ...]) -> datetime | None:
    parsed = [
        parsed_timestamp
        for finding in findings
        if (parsed_timestamp := _parse_optional_timestamp(finding.modified)) is not None
    ]
    if not parsed:
        return None
    return max(parsed)


def _parse_optional_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_timestamp(value)
    except ValueError:
        return None


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _serial_number(
    *,
    findings: tuple[VulnerabilityFinding, ...],
    analysis_state: VexAnalysisState,
    timestamp: datetime,
) -> UUID:
    canonical = json.dumps(
        {
            "analysis_state": analysis_state.value,
            "findings": [
                {
                    "component_ref": finding.component_ref,
                    "id": finding.id,
                    "modified": finding.modified,
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


def _canonical_json(value: str) -> str:
    return f"{json.dumps(json.loads(value), indent=2, sort_keys=True)}\n"
