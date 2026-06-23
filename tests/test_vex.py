from pathlib import Path

from cyclonedx.output import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

from vexcalibur.domain import VulnerabilityFinding
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.sources.osv import OsvQueryResult, OsvVulnerabilitySummary
from vexcalibur.vex import (
    VexAnalysisState,
    findings_from_osv_results,
    parse_timestamp,
    render_cyclonedx_vex_json,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
GOLDEN_ROOT = Path(__file__).parent / "golden"


def test_render_cyclonedx_vex_json_matches_golden_and_schema() -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")
    results = [
        OsvQueryResult(
            purl="pkg:npm/minimist@0.0.8",
            vulnerabilities=(
                OsvVulnerabilitySummary(
                    id="GHSA-minimist-0001",
                    modified="2026-01-02T00:00:00Z",
                ),
            ),
        ),
        OsvQueryResult(
            purl="pkg:pypi/django@1.2",
            vulnerabilities=(
                OsvVulnerabilitySummary(
                    id="GHSA-django-0001",
                    modified="2026-01-01T00:00:00Z",
                ),
            ),
        ),
    ]

    generated = render_cyclonedx_vex_json(
        findings=findings_from_osv_results(components=components, results=results),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert generated == (GOLDEN_ROOT / "cyclonedx-vex-simple.json").read_text(encoding="utf-8")
    validator = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_6)
    assert validator.validate_str(generated) is None


def test_render_cyclonedx_vex_json_supports_all_cli_analysis_states() -> None:
    finding = VulnerabilityFinding(
        id="GHSA-test-0001",
        source_name="OSV",
        source_url="https://osv.dev/",
        component_ref="component:test",
        purl="pkg:pypi/test@1.0.0",
    )

    states = (
        VexAnalysisState.RESOLVED,
        VexAnalysisState.EXPLOITABLE,
        VexAnalysisState.IN_TRIAGE,
        VexAnalysisState.FALSE_POSITIVE,
        VexAnalysisState.NOT_AFFECTED,
    )
    for state in states:
        generated = render_cyclonedx_vex_json(
            findings=(finding,),
            analysis_state=state,
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        )

        assert f'"state": "{state.value}"' in generated
