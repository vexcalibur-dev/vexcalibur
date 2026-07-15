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

from vexcalibur.document import (
    VexAssertion,
    VexDocument,
    VexProduct,
    analysis_state,
    product_purl,
    vex_document_from_findings,
)
from vexcalibur.domain import ComponentIdentity, VexAnalysisState, VulnerabilityFinding
from vexcalibur.render import VexRenderError as VexRenderError

_AssertionGroupKey = tuple[str, str, str, VexAnalysisState, str]
_CycloneDxAssertionKey = tuple[str, str, str, str, str, str, str, str]


def render_cyclonedx_vex_json(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    timestamp: datetime | None = None,
) -> str:
    """Render deterministic CycloneDX VEX JSON for vulnerability findings."""
    return CycloneDxJsonRenderer().render(
        components=components,
        findings=findings,
        timestamp=timestamp,
    )


class CycloneDxJsonRenderer:
    """Render CycloneDX 1.6 VEX JSON."""

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Adapt provider findings and return CycloneDX 1.6 VEX JSON."""
        return self.render_document(
            document=vex_document_from_findings(components=components, findings=findings),
            timestamp=timestamp,
        )

    def render_document(
        self,
        *,
        document: VexDocument,
        timestamp: datetime | None = None,
    ) -> str:
        """Return deterministic CycloneDX 1.6 JSON for a VEX document."""
        normalized_timestamp = _normalize_timestamp(timestamp or datetime.now(tz=timezone.utc))
        assertions = _canonical_assertions(document.assertions)
        bom = Bom(
            serial_number=_serial_number(
                products=document.products,
                assertions=assertions,
                timestamp=normalized_timestamp,
            ),
            metadata=BomMetaData(timestamp=normalized_timestamp),
            components=[
                _cyclonedx_component(product)
                for product in _affected_products(
                    products=document.products,
                    assertions=assertions,
                )
            ],
            vulnerabilities=[
                _cyclonedx_vulnerability(
                    group_key=group_key,
                    vulnerability_id=group_key[0],
                    source=VulnerabilitySource(name=group_key[1], url=XsUri(group_key[2])),
                    assertions=vulnerability_assertions,
                )
                for group_key, vulnerability_assertions in _group_assertions(assertions)
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
    group_key: _AssertionGroupKey,
    vulnerability_id: str,
    source: VulnerabilitySource,
    assertions: tuple[VexAssertion, ...],
) -> Vulnerability:
    affected_refs = tuple(sorted({assertion.product.key for assertion in assertions}))
    updated = _latest_modified_timestamp(assertions)
    representative = assertions[0]
    return Vulnerability(
        bom_ref=_vulnerability_bom_ref(
            group_key=group_key,
        ),
        id=vulnerability_id,
        source=source,
        references=[VulnerabilityReference(id=vulnerability_id, source=source)],
        updated=updated,
        analysis=VulnerabilityAnalysis(
            state=ImpactAnalysisState(analysis_state(representative).value),
            detail=representative.analysis_detail,
        ),
        affects=[BomTarget(ref=product_ref) for product_ref in affected_refs],
    )


def _cyclonedx_component(product: VexProduct) -> Component:
    try:
        component_type = ComponentType(product.component_type)
    except ValueError:
        component_type = ComponentType.LIBRARY
    return Component(
        bom_ref=product.key,
        name=product.name,
        type=component_type,
        version=product.version,
        purl=product_purl(product),
    )


def _affected_products(
    *,
    products: tuple[VexProduct, ...],
    assertions: tuple[VexAssertion, ...],
) -> tuple[VexProduct, ...]:
    affected_refs = {assertion.product.key for assertion in assertions}
    return tuple(
        sorted(
            (product for product in products if product.key in affected_refs),
            key=lambda product: product.key,
        )
    )


def _group_assertions(
    assertions: tuple[VexAssertion, ...],
) -> tuple[tuple[_AssertionGroupKey, tuple[VexAssertion, ...]], ...]:
    grouped: dict[_AssertionGroupKey, list[VexAssertion]] = defaultdict(list)
    for assertion in assertions:
        vulnerability = assertion.vulnerability
        grouped[
            (
                vulnerability.id,
                vulnerability.source_name,
                vulnerability.source_url,
                analysis_state(assertion),
                assertion.analysis_detail,
            )
        ].append(assertion)
    return tuple((group_key, tuple(grouped[group_key])) for group_key in sorted(grouped))


def _latest_modified_timestamp(assertions: tuple[VexAssertion, ...]) -> datetime | None:
    parsed = [
        assertion.source_record_modified_at
        for assertion in assertions
        if assertion.source_record_modified_at is not None
    ]
    if not parsed:
        return None
    return max(parsed)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _serial_number(
    *,
    products: tuple[VexProduct, ...],
    assertions: tuple[VexAssertion, ...],
    timestamp: datetime,
) -> UUID:
    canonical = json.dumps(
        {
            "components": [
                {
                    "name": product.name,
                    "purl": product_purl(product).to_string(),
                    "ref": product.key,
                    "type": product.component_type,
                    "version": product.version,
                }
                for product in _affected_products(products=products, assertions=assertions)
            ],
            "findings": [
                {
                    "analysis_detail": assertion.analysis_detail,
                    "analysis_state": analysis_state(assertion).value,
                    "component_ref": assertion.product.key,
                    "id": assertion.vulnerability.id,
                    "modified": (
                        assertion.source_record_modified_at.isoformat()
                        if assertion.source_record_modified_at
                        else None
                    ),
                    "purl": product_purl(assertion.product).to_string(),
                    "source_name": assertion.vulnerability.source_name,
                    "source_url": assertion.vulnerability.source_url,
                }
                for assertion in assertions
            ],
            "timestamp": timestamp.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return uuid5(NAMESPACE_URL, f"https://vexcalibur.dev/vex/{canonical}")


def _canonical_assertions(
    assertions: tuple[VexAssertion, ...],
) -> tuple[VexAssertion, ...]:
    canonical: dict[_CycloneDxAssertionKey, VexAssertion] = {}
    for assertion in sorted(assertions, key=_cyclonedx_assertion_key):
        canonical.setdefault(_cyclonedx_assertion_key(assertion), assertion)
    return tuple(canonical.values())


def _cyclonedx_assertion_key(assertion: VexAssertion) -> _CycloneDxAssertionKey:
    vulnerability = assertion.vulnerability
    return (
        vulnerability.id,
        vulnerability.source_name,
        vulnerability.source_url,
        analysis_state(assertion).value,
        assertion.analysis_detail,
        assertion.product.key,
        product_purl(assertion.product).to_string(),
        (
            assertion.source_record_modified_at.isoformat()
            if assertion.source_record_modified_at
            else ""
        ),
    )


def _vulnerability_bom_ref(
    *,
    group_key: _AssertionGroupKey,
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
