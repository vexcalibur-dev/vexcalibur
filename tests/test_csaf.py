import json
from dataclasses import replace
from datetime import datetime
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from packageurl import PackageURL

from vexcalibur.csaf import (
    CSAF_DOCUMENT_CATEGORY,
    CSAF_VERSION,
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafDocumentStatus,
    CsafPublisherCategory,
    CsafRenderError,
    csaf_filename,
    render_csaf20_vex_json,
)
from vexcalibur.document import VexDocument, vex_document_from_findings
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.generate import generate_vex_from_local_findings
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
SCHEMA_PATH = FIXTURE_ROOT / "schemas" / "csaf-2.0.schema.json"
GOLDEN_ROOT = Path(__file__).parent / "golden"
CSAF_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(CSAF_SCHEMA, format_checker=FormatChecker())
TIMESTAMP = parse_timestamp("2026-07-15T00:00:00Z")
TOOL_VERSION = "0.3.0"


def _components() -> tuple[ComponentIdentity, ...]:
    return load_cyclonedx_json(FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json")


def _component(name: str) -> ComponentIdentity:
    return next(component for component in _components() if component.name == name)


def _metadata(
    *,
    document_id: str = "ACME-VEX-2026-001",
    status: CsafDocumentStatus = CsafDocumentStatus.FINAL,
) -> Csaf20DocumentMetadata:
    return Csaf20DocumentMetadata(
        document_id=document_id,
        title="ACME component exploitability assessment",
        publisher_name="ACME Product Security",
        publisher_namespace="https://security.example.com",
        publisher_category=CsafPublisherCategory.VENDOR,
        status=status,
    )


def _finding(
    *,
    component: ComponentIdentity | None = None,
    vulnerability_id: str = "CVE-2026-0001",
    state: VexAnalysisState = VexAnalysisState.IN_TRIAGE,
    detail: str = "Review is underway.",
    action_statement: str | None = None,
    impact_statement: str | None = None,
    fixed_version: str | None = None,
    remediation_category: VexRemediationCategory | None = None,
    modified: datetime | None = None,
    source_name: str = "Internal Review",
    source_url: str = "https://security.example.test/vulnerabilities/CVE-2026-0001",
) -> VulnerabilityFinding:
    selected_component = _components()[0] if component is None else component
    return VulnerabilityFinding(
        id=vulnerability_id,
        source_name=source_name,
        source_url=source_url,
        component_ref=selected_component.ref,
        purl=selected_component.purl.to_string(),
        modified=modified,
        analysis_state=state,
        analysis_detail=detail,
        action_statement=action_statement,
        impact_statement=impact_statement,
        fixed_version=fixed_version,
        remediation_category=remediation_category,
    )


def _render(*findings: VulnerabilityFinding) -> str:
    return render_csaf20_vex_json(
        components=_components(),
        findings=findings,
        metadata=_metadata(),
        timestamp=TIMESTAMP,
        tool_version=TOOL_VERSION,
    )


def _validate(document_json: str) -> dict[str, object]:
    document = json.loads(document_json)
    VALIDATOR.validate(document)
    assert document["document"]["category"] == CSAF_DOCUMENT_CATEGORY
    assert document["document"]["csaf_version"] == CSAF_VERSION
    assert document["product_tree"]["full_product_names"]
    assert document["vulnerabilities"]
    return document


def test_render_csaf_matches_all_states_golden_and_official_schema() -> None:
    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json",
        findings_file=FIXTURE_ROOT / "findings" / "all-analysis-states.json",
        timestamp=TIMESTAMP,
        renderer=Csaf20VexJsonRenderer(metadata=_metadata(), tool_version=TOOL_VERSION),
    )

    assert generated == (GOLDEN_ROOT / "csaf-vex-all-analysis-states.json").read_text(
        encoding="utf-8"
    )
    document = _validate(generated)
    assert "$schema" not in document
    assert "distribution" not in document["document"]
    tracking = document["document"]["tracking"]
    assert tracking["current_release_date"] == "2026-07-15T00:00:00Z"
    assert tracking["initial_release_date"] == "2026-07-15T00:00:00Z"
    assert tracking["generator"] == {
        "date": "2026-07-15T00:00:00Z",
        "engine": {"name": "Vexcalibur", "version": TOOL_VERSION},
    }
    assert tracking["revision_history"] == [
        {
            "date": "2026-07-15T00:00:00Z",
            "number": "1",
            "summary": "Initial version.",
        }
    ]

    vulnerabilities = document["vulnerabilities"]
    assert [vulnerability["cve"] for vulnerability in vulnerabilities] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
        "CVE-2026-0004",
        "CVE-2026-0005",
    ]
    assert [next(iter(vulnerability["product_status"])) for vulnerability in vulnerabilities] == [
        "fixed",
        "known_affected",
        "under_investigation",
        "known_not_affected",
        "known_not_affected",
    ]
    assert vulnerabilities[1]["remediations"][0]["category"] == "vendor_fix"
    assert vulnerabilities[3]["threats"][0]["category"] == "impact"
    assert (
        "Original Vexcalibur analysis state: false_positive"
        in vulnerabilities[3]["notes"][0]["text"]
    )
    assert "Confirmed fixed product version: 1.2" in vulnerabilities[0]["notes"][0]["text"]


def test_vendored_csaf_schema_has_the_pinned_oasis_hash() -> None:
    assert (
        sha256(SCHEMA_PATH.read_bytes()).hexdigest()
        == "29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262"
    )


def test_csaf_compatibility_renderer_adapts_then_delegates() -> None:
    components = _components()
    finding = _finding(component=components[0])
    received: dict[str, object] = {}

    class RecordingRenderer(Csaf20VexJsonRenderer):
        def render_document(
            self,
            *,
            document: VexDocument,
            timestamp: datetime | None = None,
        ) -> str:
            received.update(document=document, timestamp=timestamp)
            return "rendered-document"

    rendered = RecordingRenderer(metadata=_metadata()).render(
        components=components,
        findings=(finding,),
        timestamp=TIMESTAMP,
    )

    assert rendered == "rendered-document"
    assert received["timestamp"] == TIMESTAMP
    document = received["document"]
    assert isinstance(document, VexDocument)
    assert document.assertions[0].product.key == components[0].ref


def test_csaf_renders_a_format_neutral_document_directly() -> None:
    components = _components()
    document = vex_document_from_findings(
        components=components,
        findings=(_finding(component=components[0]),),
    )

    rendered = Csaf20VexJsonRenderer(
        metadata=_metadata(),
        tool_version=TOOL_VERSION,
    ).render_document(document=document, timestamp=TIMESTAMP)

    parsed = _validate(rendered)
    assert parsed["vulnerabilities"][0]["product_status"] == {
        "under_investigation": ["CSAFPID-5067e6fe-3ac3-5070-b0e6-6b3e90adb071"]
    }


def test_csaf_deduplicates_canonical_products_and_is_input_order_independent() -> None:
    component = _component("django")
    alias = replace(component, ref="component:django-alias")
    first = _finding(component=component)
    second = replace(first, component_ref=alias.ref)

    forward = render_csaf20_vex_json(
        components=(component, alias),
        findings=(first, second, first),
        metadata=_metadata(),
        timestamp=TIMESTAMP,
        tool_version=TOOL_VERSION,
    )
    reverse = render_csaf20_vex_json(
        components=(alias, component),
        findings=(second, first),
        metadata=_metadata(),
        timestamp=TIMESTAMP,
        tool_version=TOOL_VERSION,
    )

    assert forward == reverse
    document = _validate(forward)
    assert document["product_tree"]["full_product_names"] == [
        {
            "name": "django 1.2",
            "product_id": "CSAFPID-03e0b21f-2224-5ca7-b492-de00c9efa74e",
            "product_identification_helper": {"purl": "pkg:pypi/django@1.2"},
        }
    ]
    assert document["vulnerabilities"][0]["product_status"] == {
        "under_investigation": ["CSAFPID-03e0b21f-2224-5ca7-b492-de00c9efa74e"]
    }


def test_csaf_groups_identical_remediation_and_impact_evidence_across_products() -> None:
    first_component, second_component = _components()[:2]
    affected = (
        _finding(
            component=first_component,
            vulnerability_id="CVE-2026-1001",
            state=VexAnalysisState.EXPLOITABLE,
            action_statement="Disable the affected feature.",
            remediation_category=VexRemediationCategory.MITIGATION,
        ),
        _finding(
            component=second_component,
            vulnerability_id="CVE-2026-1001",
            state=VexAnalysisState.EXPLOITABLE,
            action_statement="Disable the affected feature.",
            remediation_category=VexRemediationCategory.MITIGATION,
        ),
    )
    not_affected = (
        _finding(
            component=first_component,
            vulnerability_id="CVE-2026-1002",
            state=VexAnalysisState.NOT_AFFECTED,
            impact_statement="The vulnerable code is not present.",
        ),
        _finding(
            component=second_component,
            vulnerability_id="CVE-2026-1002",
            state=VexAnalysisState.FALSE_POSITIVE,
            impact_statement="The vulnerable code is not present.",
        ),
    )

    document = _validate(_render(*(affected + not_affected)))
    affected_document, not_affected_document = document["vulnerabilities"]
    assert len(affected_document["remediations"]) == 1
    assert len(affected_document["remediations"][0]["product_ids"]) == 2
    assert len(not_affected_document["threats"]) == 1
    assert len(not_affected_document["threats"][0]["product_ids"]) == 2


def test_csaf_maps_non_cve_ids_and_distinct_provenance() -> None:
    first = _finding(
        vulnerability_id="GHSA-abcd-1234-5678",
        source_name="GitHub Advisory Database",
        source_url="https://github.com/advisories/GHSA-abcd-1234-5678",
        modified=parse_timestamp("2026-01-02T03:04:05+02:00"),
    )
    second = replace(
        first,
        source_name="OSV",
        source_url="https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
    )

    vulnerability = _validate(_render(second, first))["vulnerabilities"][0]
    assert "cve" not in vulnerability
    assert vulnerability["ids"] == [
        {"system_name": "GitHub Advisory Database", "text": "GHSA-abcd-1234-5678"},
        {"system_name": "OSV", "text": "GHSA-abcd-1234-5678"},
    ]
    assert [reference["url"] for reference in vulnerability["references"]] == [
        "https://github.com/advisories/GHSA-abcd-1234-5678",
        "https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
    ]
    assert all(
        "Applicable product IDs: CSAFPID-" in note["text"] for note in vulnerability["notes"]
    )
    assert all(
        "Source record modified: 2026-01-02T01:04:05Z" in note["text"]
        for note in vulnerability["notes"]
    )


def test_csaf_allows_same_effective_status_with_distinct_provenance() -> None:
    false_positive = _finding(
        state=VexAnalysisState.FALSE_POSITIVE,
        detail="The source matched a package outside the deployed artifact.",
        impact_statement="The vulnerable code is not present.",
        source_name="Scanner Review",
        source_url="https://scanner.example.test/CVE-2026-0001",
    )
    not_affected = replace(
        false_positive,
        analysis_state=VexAnalysisState.NOT_AFFECTED,
        analysis_detail="The deployed artifact does not contain the vulnerable code.",
        source_name="Product Security Review",
        source_url="https://security.example.test/CVE-2026-0001",
    )

    vulnerability = _validate(_render(false_positive, not_affected))["vulnerabilities"][0]
    assert vulnerability["product_status"] == {
        "known_not_affected": ["CSAFPID-5067e6fe-3ac3-5070-b0e6-6b3e90adb071"]
    }
    assert len(vulnerability["notes"]) == 2
    assert len(vulnerability["threats"]) == 1
    assert {reference["url"] for reference in vulnerability["references"]} == {
        "https://scanner.example.test/CVE-2026-0001",
        "https://security.example.test/CVE-2026-0001",
    }


def test_csaf_uses_component_version_to_make_an_unversioned_product_purl_precise() -> None:
    component = replace(
        _component("django"),
        purl=PackageURL.from_string("pkg:pypi/django"),
    )
    finding = _finding(component=component)

    document = _validate(
        render_csaf20_vex_json(
            components=(component,),
            findings=(finding,),
            metadata=_metadata(),
            timestamp=TIMESTAMP,
            tool_version=TOOL_VERSION,
        )
    )

    assert document["product_tree"]["full_product_names"][0]["product_identification_helper"] == {
        "purl": "pkg:pypi/django@1.2"
    }


def test_csaf_normalizes_metadata_and_naive_document_timestamp() -> None:
    metadata = Csaf20DocumentMetadata(
        document_id="  ACME VEX:2026/001  ",
        title="  Assessment  ",
        publisher_name="  ACME Product Security  ",
        publisher_namespace="  https://security.example.com/team/  ",
        publisher_category=CsafPublisherCategory.USER,
    )
    renderer = Csaf20VexJsonRenderer(metadata=metadata, tool_version="  0.3.0  ")

    document = _validate(
        renderer.render(
            components=_components(),
            findings=(_finding(),),
            timestamp=datetime(2026, 7, 15),
        )
    )

    assert metadata.document_id == "ACME VEX:2026/001"
    assert metadata.title == "Assessment"
    assert metadata.publisher_name == "ACME Product Security"
    assert metadata.publisher_namespace == "https://security.example.com/team"
    assert metadata.status is CsafDocumentStatus.DRAFT
    assert document["document"]["tracking"]["status"] == "draft"
    assert document["document"]["tracking"]["current_release_date"] == "2026-07-15T00:00:00Z"
    assert document["document"]["tracking"]["generator"]["engine"]["version"] == "0.3.0"


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("document_id", " "),
        ("title", "\t"),
        ("publisher_name", ""),
    ),
)
def test_csaf_rejects_empty_document_metadata(field_name: str, value: str) -> None:
    values = {
        "document_id": "ACME-VEX-2026-001",
        "title": "Assessment",
        "publisher_name": "ACME Product Security",
    }
    values[field_name] = value

    with pytest.raises(CsafRenderError, match=field_name):
        Csaf20DocumentMetadata(
            **values,
            publisher_namespace="https://security.example.com",
            publisher_category=CsafPublisherCategory.VENDOR,
        )


@pytest.mark.parametrize("line_terminator", ("\n", "\r", "\u2028", "\u2029"))
def test_csaf_rejects_line_terminators_inside_document_ids(line_terminator: str) -> None:
    with pytest.raises(CsafRenderError, match="document_id must not contain line terminators"):
        replace(_metadata(), document_id=f"ACME{line_terminator}VEX")


def test_csaf_allows_schema_valid_internal_space_and_tab_in_document_ids() -> None:
    assert replace(_metadata(), document_id="ACME VEX\t2026").document_id == "ACME VEX\t2026"


@pytest.mark.parametrize(
    "namespace",
    (
        "security.example.com",
        "ftp://security.example.com",
        "https://user@security.example.com",
        "https://security.example.com?publisher=acme",
        "https://security.example.com:bad",
        "https://exa mple.com",
        "https://security.example.com/%zz",
        "https://sécurity.example.com",
        "https://security.example.com/\x7f",
    ),
)
def test_csaf_rejects_invalid_publisher_namespaces(namespace: str) -> None:
    with pytest.raises(CsafRenderError, match="publisher_namespace"):
        Csaf20DocumentMetadata(
            document_id="ACME-VEX-2026-001",
            title="Assessment",
            publisher_name="ACME Product Security",
            publisher_namespace=namespace,
            publisher_category=CsafPublisherCategory.VENDOR,
        )


@pytest.mark.parametrize("character", tuple('"<>[\\]^`{|}'))
def test_csaf_rejects_every_schema_invalid_printable_path_character(character: str) -> None:
    with pytest.raises(CsafRenderError, match="publisher_namespace"):
        replace(
            _metadata(),
            publisher_namespace=f"https://security.example.com/path{character}value",
        )


@pytest.mark.parametrize(
    "namespace",
    (
        "https://xn--tst-bma.example/security%20team",
        "https://[2001:db8::1]/security",
        "https://[2001:db8::1]:8443/security",
    ),
)
def test_csaf_accepts_schema_valid_encoded_idna_and_ipv6_namespaces(namespace: str) -> None:
    metadata = replace(_metadata(), publisher_namespace=namespace)

    rendered = Csaf20VexJsonRenderer(
        metadata=metadata,
        tool_version=TOOL_VERSION,
    ).render(
        components=_components(),
        findings=(_finding(),),
        timestamp=TIMESTAMP,
    )

    _validate(rendered)


def test_csaf_rejects_unsupported_metadata_enums_and_empty_tool_version() -> None:
    with pytest.raises(CsafRenderError, match="publisher_category"):
        Csaf20DocumentMetadata(
            document_id="ACME-VEX-2026-001",
            title="Assessment",
            publisher_name="ACME Product Security",
            publisher_namespace="https://security.example.com",
            publisher_category="translator",  # type: ignore[arg-type]
        )
    with pytest.raises(CsafRenderError, match="status"):
        replace(_metadata(), status="withdrawn")  # type: ignore[arg-type]
    with pytest.raises(CsafRenderError, match="tool version"):
        Csaf20VexJsonRenderer(metadata=_metadata(), tool_version=" ")


@pytest.mark.parametrize(
    ("document_id", "expected"),
    (
        ("ACME VEX:2026/001", "acme_vex_2026_001.json"),
        ("ACME_VEX___2026", "acme_vex_2026.json"),
        ("ACME+VEX-2026", "acme+vex-2026.json"),
    ),
)
def test_csaf_filename_follows_the_csaf_algorithm(document_id: str, expected: str) -> None:
    assert csaf_filename(document_id) == expected


def test_csaf_rejects_empty_findings() -> None:
    with pytest.raises(CsafRenderError, match="at least one"):
        _render()


def test_csaf_rejects_a_product_without_any_version() -> None:
    component = replace(
        _components()[0],
        version=None,
        purl=PackageURL.from_string("pkg:pypi/django"),
    )
    finding = _finding(component=component)

    with pytest.raises(CsafRenderError, match="must include a version"):
        render_csaf20_vex_json(
            components=(component,),
            findings=(finding,),
            metadata=_metadata(),
            timestamp=TIMESTAMP,
            tool_version=TOOL_VERSION,
        )


def test_csaf_rejects_unknown_duplicate_and_mismatched_components() -> None:
    finding = _finding()
    with pytest.raises(CsafRenderError, match="unknown component"):
        _render(replace(finding, component_ref="component:missing"))
    with pytest.raises(CsafRenderError, match="duplicate refs"):
        render_csaf20_vex_json(
            components=(_components()[0], _components()[0]),
            findings=(finding,),
            metadata=_metadata(),
            timestamp=TIMESTAMP,
            tool_version=TOOL_VERSION,
        )
    with pytest.raises(CsafRenderError, match="does not match"):
        _render(replace(finding, purl="pkg:pypi/not-django@1.2"))


@pytest.mark.parametrize(
    ("finding", "message"),
    (
        (
            _finding(state=VexAnalysisState.EXPLOITABLE),
            "require an action_statement",
        ),
        (
            _finding(
                state=VexAnalysisState.EXPLOITABLE,
                action_statement="Upgrade now.",
            ),
            "require a remediation_category",
        ),
        (
            _finding(state=VexAnalysisState.NOT_AFFECTED),
            "require an impact_statement",
        ),
        (
            _finding(state=VexAnalysisState.RESOLVED),
            "require fixed_version",
        ),
        (
            _finding(state=VexAnalysisState.RESOLVED, fixed_version="9.9"),
            "does not match product",
        ),
    ),
)
def test_csaf_requires_explicit_state_evidence(
    finding: VulnerabilityFinding,
    message: str,
) -> None:
    with pytest.raises(CsafRenderError, match=message):
        _render(finding)


@pytest.mark.parametrize(
    ("finding", "message"),
    (
        (_finding(action_statement="Upgrade now."), "action_statement is only valid"),
        (
            _finding(remediation_category=VexRemediationCategory.VENDOR_FIX),
            "remediation_category is only valid",
        ),
        (_finding(impact_statement="Not reachable."), "impact_statement is only valid"),
        (_finding(fixed_version="1.2"), "fixed_version is only valid"),
    ),
)
def test_csaf_rejects_evidence_on_the_wrong_state(
    finding: VulnerabilityFinding,
    message: str,
) -> None:
    with pytest.raises(CsafRenderError, match=message):
        _render(finding)


@pytest.mark.parametrize(
    ("field_name", "finding"),
    (
        ("id", replace(_finding(), id=" ")),
        ("source_name", replace(_finding(), source_name=" ")),
        ("source_url", replace(_finding(), source_url=" ")),
        ("source_url", replace(_finding(), source_url="javascript:alert(1)")),
        ("source_url", replace(_finding(), source_url="https://example.test/%zz")),
        ("source_url", replace(_finding(), source_url="https://tést.example/vuln")),
        ("source_url", replace(_finding(), source_url="https://example.test/\x7f")),
        ("source_url", replace(_finding(), source_url="https://example.test/path|value")),
        (
            "source_url",
            replace(_finding(), source_url="https://user@x@example.test/path"),
        ),
        (
            "source_url",
            replace(_finding(), source_url="https://example.test/path#first#second"),
        ),
        ("analysis_detail", replace(_finding(), analysis_detail=" ")),
        (
            "action_statement",
            replace(
                _finding(),
                analysis_state=VexAnalysisState.EXPLOITABLE,
                action_statement=" ",
                remediation_category=VexRemediationCategory.VENDOR_FIX,
            ),
        ),
        (
            "impact_statement",
            replace(
                _finding(),
                analysis_state=VexAnalysisState.NOT_AFFECTED,
                impact_statement=" ",
            ),
        ),
        (
            "fixed_version",
            replace(
                _finding(),
                analysis_state=VexAnalysisState.RESOLVED,
                fixed_version=" ",
            ),
        ),
    ),
)
def test_csaf_rejects_invalid_finding_text(
    field_name: str,
    finding: VulnerabilityFinding,
) -> None:
    with pytest.raises(CsafRenderError, match=field_name):
        _render(finding)


def test_csaf_rejects_conflicting_statuses_for_one_vulnerability_and_product() -> None:
    triage = _finding()
    fixed = replace(
        triage,
        analysis_state=VexAnalysisState.RESOLVED,
        fixed_version=_components()[0].version,
    )

    with pytest.raises(CsafRenderError, match="conflicting assertions"):
        _render(triage, fixed)
