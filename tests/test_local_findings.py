import json
from pathlib import Path

import pytest

from vexcalibur.domain import VexAnalysisState, VexRemediationCategory
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.sources.local import (
    MAX_LOCAL_FINDINGS,
    MAX_LOCAL_FINDINGS_BYTES,
    LocalFindingsError,
    load_local_findings,
)
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
              "analysis_detail": "Django is not reachable in this deployment.",
              "impact_statement": "The vulnerable code is not reachable.",
              "remediation_category": "workaround"
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
    assert finding.impact_statement == "The vulnerable code is not reachable."
    assert finding.remediation_category is VexRemediationCategory.WORKAROUND


def test_load_local_findings_rejects_invalid_remediation_category(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "remediation_category": "patch"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match="remediation_category"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


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


@pytest.mark.parametrize(
    "source_url",
    (
        "internal/vulns/CVE-2026-0001",
        "javascript:alert(1)",
        "https://@",
        "https://:443",
        "https://example.com:bad/vuln",
        "https://example.com:99999/vuln",
        "https://exa mple.test/vuln",
    ),
)
def test_load_local_findings_rejects_unsafe_source_url(
    tmp_path: Path,
    source_url: str,
) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "CVE-2026-0001",
                        "component_ref": "component:django",
                        "source_url": source_url,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(LocalFindingsError, match=r"HTTP\(S\) URL"):
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


@pytest.mark.parametrize(
    ("document", "message"),
    (
        ("[]", "must be a JSON object"),
        ("{}", r"invalid at findings"),
        (
            '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:django", "x": 1}]}',
            r"invalid at findings\.0\.x",
        ),
        (
            '{"findings": [{"id": "", "component_ref": "component:django"}]}',
            r"invalid at findings\.0\.id",
        ),
        (
            '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:django", '
            '"analysis_state": "needs_review"}]}',
            r"invalid at findings\.0\.analysis_state",
        ),
        (
            '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:django", '
            '"modified": "not-a-date"}]}',
            r"invalid at findings\.0\.modified",
        ),
        (
            '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:django", '
            '"modified": 1700000000}]}',
            r"invalid at findings\.0\.modified",
        ),
        (
            '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:django", '
            '"modified": "1700000000"}]}',
            r"invalid at findings\.0\.modified",
        ),
    ),
)
def test_load_local_findings_rejects_invalid_document_shapes(
    tmp_path: Path,
    document: str,
    message: str,
) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(document, encoding="utf-8")

    with pytest.raises(LocalFindingsError, match=message):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_too_many_findings(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings = ",".join(
        '{"id":"CVE-2026-0001","component_ref":"component:django"}'
        for _ in range(MAX_LOCAL_FINDINGS + 1)
    )
    findings_path.write_text(f'{{"findings":[{findings}]}}', encoding="utf-8")

    with pytest.raises(LocalFindingsError, match="invalid at findings"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_oversized_files(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_bytes(b" " * (MAX_LOCAL_FINDINGS_BYTES + 1))

    with pytest.raises(LocalFindingsError, match="exceeds"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_non_utf8_json(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_bytes(b"\xff")

    with pytest.raises(LocalFindingsError, match="not valid UTF-8"):
        load_local_findings(
            findings_path,
            components=load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        )


def test_load_local_findings_rejects_deeply_nested_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text("{}", encoding="utf-8")
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")

    def raise_recursion_error(*args: object, **kwargs: object) -> object:
        raise RecursionError

    monkeypatch.setattr("vexcalibur.sources.local.json.load", raise_recursion_error)

    with pytest.raises(LocalFindingsError, match="too deeply nested"):
        load_local_findings(
            findings_path,
            components=components,
        )
