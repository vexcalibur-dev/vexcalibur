import json
from dataclasses import replace
from pathlib import Path

import pytest
from cyclonedx.output import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

from vexcalibur.domain import ComponentIdentity, VexAnalysisState, VulnerabilityFinding
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.sources.osv import (
    OsvQueryResult,
    OsvVulnerabilitySummary,
    findings_from_osv_results,
)
from vexcalibur.vex import VexRenderError, parse_timestamp, render_cyclonedx_vex_json

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
GOLDEN_ROOT = Path(__file__).parent / "golden"
VALIDATOR = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_6)


def test_render_cyclonedx_vex_json_matches_golden_and_schema() -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")
    results = [
        OsvQueryResult(
            purl="pkg:npm/minimist@0.0.8",
            vulnerabilities=(
                OsvVulnerabilitySummary(
                    id="GHSA-minimist-0001",
                    modified=parse_timestamp("2026-01-02T00:00:00Z"),
                ),
            ),
        ),
        OsvQueryResult(
            purl="pkg:pypi/django@1.2",
            vulnerabilities=(
                OsvVulnerabilitySummary(
                    id="GHSA-django-0001",
                    modified=parse_timestamp("2026-01-01T00:00:00Z"),
                ),
            ),
        ),
    ]

    generated = render_cyclonedx_vex_json(
        components=components,
        findings=findings_from_osv_results(components=components, results=results),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert generated == (GOLDEN_ROOT / "cyclonedx-vex-simple.json").read_text(encoding="utf-8")
    assert VALIDATOR.validate_str(generated) is None


def test_render_cyclonedx_vex_json_supports_all_analysis_states() -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")

    states = (
        VexAnalysisState.RESOLVED,
        VexAnalysisState.EXPLOITABLE,
        VexAnalysisState.IN_TRIAGE,
        VexAnalysisState.FALSE_POSITIVE,
        VexAnalysisState.NOT_AFFECTED,
    )
    for state in states:
        finding = VulnerabilityFinding(
            id="GHSA-test-0001",
            source_name="OSV",
            source_url="https://osv.dev/",
            component_ref="component:django",
            purl="pkg:pypi/django@1.2",
            analysis_state=state,
            analysis_detail="Reviewed by test.",
        )

        generated = render_cyclonedx_vex_json(
            components=components,
            findings=(finding,),
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        )

        assert f'"state": "{state.value}"' in generated
        assert VALIDATOR.validate_str(generated) is None


def test_render_cyclonedx_vex_json_ignores_openvex_only_fields_when_deduplicating() -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")
    finding = VulnerabilityFinding(
        id="GHSA-test-0001",
        source_name="OSV",
        source_url="https://osv.dev/",
        component_ref="component:django",
        purl="pkg:pypi/django@1.2",
        analysis_state=VexAnalysisState.IN_TRIAGE,
        analysis_detail="Reviewed by test.",
    )
    timestamp = parse_timestamp("2026-06-23T00:00:00Z")

    generated = render_cyclonedx_vex_json(
        components=components,
        findings=(finding,),
        timestamp=timestamp,
    )
    generated_with_openvex_fields = render_cyclonedx_vex_json(
        components=components,
        findings=(
            finding,
            replace(finding, action_statement="Upgrade the component."),
            replace(finding, impact_statement="The vulnerable code is unreachable."),
            replace(finding, fixed_version="1.2"),
        ),
        timestamp=timestamp,
    )

    assert generated_with_openvex_fields == generated


def test_render_cyclonedx_vex_json_uses_source_qualified_vulnerability_bom_refs() -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")[0].purl,
    )
    findings = (
        VulnerabilityFinding(
            id="CVE-2026-0001",
            source_name="OSV",
            source_url="https://osv.dev/",
            component_ref=component.ref,
            purl=component.purl.to_string(),
        ),
        VulnerabilityFinding(
            id="CVE-2026-0001",
            source_name="Example Source",
            source_url="https://example.com/vulns",
            component_ref=component.ref,
            purl=component.purl.to_string(),
        ),
    )

    generated = render_cyclonedx_vex_json(
        components=(component,),
        findings=findings,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    vulnerabilities = json.loads(generated)["vulnerabilities"]
    assert len({vulnerability["bom-ref"] for vulnerability in vulnerabilities}) == 2


def test_render_cyclonedx_vex_json_uses_analysis_qualified_vulnerability_bom_refs() -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")[0].purl,
    )
    findings = (
        VulnerabilityFinding(
            id="CVE-2026-0001",
            source_name="OSV",
            source_url="https://osv.dev/",
            component_ref=component.ref,
            purl=component.purl.to_string(),
            analysis_state=VexAnalysisState.IN_TRIAGE,
            analysis_detail="Needs review.",
        ),
        VulnerabilityFinding(
            id="CVE-2026-0001",
            source_name="OSV",
            source_url="https://osv.dev/",
            component_ref=component.ref,
            purl=component.purl.to_string(),
            analysis_state=VexAnalysisState.NOT_AFFECTED,
            analysis_detail="Reviewed and not affected.",
        ),
    )

    generated = render_cyclonedx_vex_json(
        components=(component,),
        findings=findings,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    vulnerabilities = json.loads(generated)["vulnerabilities"]
    assert len({vulnerability["bom-ref"] for vulnerability in vulnerabilities}) == 2
    assert VALIDATOR.validate_str(generated) is None


def test_render_cyclonedx_vex_json_rejects_unknown_component_refs() -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")[0].purl,
    )
    finding = VulnerabilityFinding(
        id="CVE-2026-0001",
        source_name="OSV",
        source_url="https://osv.dev/",
        component_ref="component:missing",
        purl=component.purl.to_string(),
    )

    with pytest.raises(VexRenderError, match="component:missing"):
        render_cyclonedx_vex_json(
            components=(component,),
            findings=(finding,),
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        )


def test_render_cyclonedx_vex_json_without_findings_is_schema_valid() -> None:
    generated = render_cyclonedx_vex_json(
        components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        findings=(),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert VALIDATOR.validate_str(generated) is None
