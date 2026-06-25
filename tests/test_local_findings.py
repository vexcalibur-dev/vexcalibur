from pathlib import Path

import pytest

from vexcalibur.domain import VexAnalysisState
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.sources.local import LocalFindingsError, load_local_findings
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"


def test_load_local_findings_maps_component_ref_to_vex_finding(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "source_name": "Internal Review",
              "source_url": "https://security.example.test/vulns/CVE-2026-0001",
              "modified": "2026-01-01T00:00:00-05:00",
              "analysis_state": "not_affected",
              "analysis_detail": "Django is not reachable in this deployment."
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    findings = load_local_findings(
        findings_path,
        components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "CVE-2026-0001"
    assert finding.component_ref == "component:django"
    assert finding.purl == "pkg:pypi/django@1.2"
    assert finding.source_name == "Internal Review"
    assert finding.source_url == "https://security.example.test/vulns/CVE-2026-0001"
    assert finding.modified == parse_timestamp("2026-01-01T05:00:00Z")
    assert finding.analysis_state is VexAnalysisState.NOT_AFFECTED
    assert finding.analysis_detail == "Django is not reachable in this deployment."


def test_load_local_findings_maps_unique_purl_to_vex_finding(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0002",
              "purl": "pkg:npm/minimist@0.0.8"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    findings = load_local_findings(
        findings_path,
        components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
    )

    assert [(finding.id, finding.component_ref, finding.purl) for finding in findings] == [
        ("CVE-2026-0002", "pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8")
    ]
    assert findings[0].analysis_state is VexAnalysisState.IN_TRIAGE


def test_load_local_findings_accepts_empty_findings(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text('{"findings": []}', encoding="utf-8")

    findings = load_local_findings(
        findings_path,
        components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
    )

    assert findings == ()


def test_load_local_findings_rejects_unknown_component_ref(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:missing"}]}',
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="unknown component_ref"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_mismatched_ref_and_purl(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "purl": "pkg:npm/minimist@0.0.8"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="does not match component_ref"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_unknown_purl(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        '{"findings": [{"id": "CVE-2026-0001", "purl": "pkg:pypi/missing@1.0.0"}]}',
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="unknown purl"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_ambiguous_purl(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "components": [
            {
              "type": "library",
              "bom-ref": "component:first",
              "name": "demo",
              "version": "1.0.0",
              "purl": "pkg:pypi/demo@1.0.0"
            },
            {
              "type": "library",
              "bom-ref": "component:second",
              "name": "demo-copy",
              "version": "1.0.0",
              "purl": "pkg:pypi/demo@1.0.0"
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        '{"findings": [{"id": "CVE-2026-0001", "purl": "pkg:pypi/demo@1.0.0"}]}',
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="matches multiple components"):
        load_local_findings(findings_path, components=load_cyclonedx_json(sbom_path))


def test_load_local_findings_requires_component_selector(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text('{"findings": [{"id": "CVE-2026-0001"}]}', encoding="utf-8")

    with pytest.raises(LocalFindingsError, match="component_ref or purl"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_invalid_purl(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        '{"findings": [{"id": "CVE-2026-0001", "purl": "not a purl"}]}',
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="not a valid package URL"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_relative_source_url(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "source_url": "internal/vulns/CVE-2026-0001"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="absolute URI"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_malformed_json(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(LocalFindingsError, match="not valid JSON"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )
