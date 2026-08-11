import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from packageurl import PackageURL

from vexcalibur.document import VexDocument, vex_document_from_findings
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.generate import generate_vex_from_local_findings
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.spdx3 import (
    SPDX3_CONTEXT,
    SPDX3_SPEC_VERSION,
    Spdx3JsonRenderer,
    Spdx3RenderError,
    render_spdx3_json,
)
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
SCHEMA_PATH = FIXTURE_ROOT / "schemas" / "spdx-3.0.1.schema.json"
GOLDEN_ROOT = Path(__file__).parent / "golden"
SPDX3_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SPDX3_SCHEMA, format_checker=FormatChecker())
TIMESTAMP = parse_timestamp("2026-06-23T00:00:00Z")
TOOL_VERSION = "0.3.0"


def _components() -> tuple[ComponentIdentity, ...]:
    return load_cyclonedx_json(FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json")


def _finding(
    *,
    component: ComponentIdentity | None = None,
    vulnerability_id: str = "CVE-2026-0001",
    state: VexAnalysisState = VexAnalysisState.IN_TRIAGE,
    detail: str = "Review is underway.",
    action_statement: str | None = None,
    impact_statement: str | None = None,
    fixed_version: str | None = None,
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
    )


def _render(
    findings: tuple[VulnerabilityFinding, ...],
    *,
    components: tuple[ComponentIdentity, ...] | None = None,
    creator: str = "Example Security Team",
    timestamp: datetime | None = None,
) -> str:
    return render_spdx3_json(
        components=_components() if components is None else components,
        findings=findings,
        creator=creator,
        timestamp=TIMESTAMP if timestamp is None else timestamp,
        tool_version=TOOL_VERSION,
    )


def _validate(document_json: str) -> dict[str, object]:
    document = json.loads(document_json)
    VALIDATOR.validate(document)
    assert document["@context"] == SPDX3_CONTEXT
    graph = document["@graph"]
    spdx_ids = {element["spdxId"] for element in graph if "spdxId" in element}
    for element in graph:
        if element.get("type") == "SpdxDocument":
            assert set(element["element"]) <= spdx_ids
            assert set(element["rootElement"]) <= spdx_ids
        if "from" in element:
            assert element["from"] in spdx_ids
            assert set(element["to"]) <= spdx_ids
    return document


def _elements_of_type(document: dict[str, object], type_name: str) -> list[dict[str, object]]:
    graph = document["@graph"]
    assert isinstance(graph, list)
    return [element for element in graph if element.get("type") == type_name]


def _relationships(document: dict[str, object]) -> list[dict[str, object]]:
    graph = document["@graph"]
    assert isinstance(graph, list)
    return [
        element
        for element in graph
        if str(element.get("type", "")).endswith("VulnAssessmentRelationship")
    ]


def test_render_spdx3_matches_all_states_golden_and_official_schema() -> None:
    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json",
        findings_file=FIXTURE_ROOT / "findings" / "all-analysis-states.json",
        timestamp=TIMESTAMP,
        renderer=Spdx3JsonRenderer(
            creator="Vexcalibur Test Maintainers",
            tool_version=TOOL_VERSION,
        ),
    )

    assert generated == (GOLDEN_ROOT / "spdx3-vex-all-analysis-states.json").read_text(
        encoding="utf-8"
    )
    document = _validate(generated)
    relationships = _relationships(document)
    assert [relationship["type"] for relationship in relationships] == [
        "security_VexFixedVulnAssessmentRelationship",
        "security_VexAffectedVulnAssessmentRelationship",
        "security_VexUnderInvestigationVulnAssessmentRelationship",
        "security_VexNotAffectedVulnAssessmentRelationship",
        "security_VexNotAffectedVulnAssessmentRelationship",
    ]
    assert [relationship["relationshipType"] for relationship in relationships] == [
        "fixedIn",
        "affects",
        "underInvestigationFor",
        "doesNotAffect",
        "doesNotAffect",
    ]
    assert relationships[1]["security_actionStatement"] == (
        "Upgrade minimist to version 1.2.8 or later."
    )
    assert "security_impactStatement" not in relationships[1]
    assert str(relationships[3]["security_impactStatement"]).startswith("The source matched")
    assert str(relationships[4]["security_impactStatement"]).startswith(
        "The deployment does not enable"
    )
    notes = str(relationships[0]["security_statusNotes"])
    assert "Confirmed fixed product version: 1.2" in notes
    assert "Original Vexcalibur analysis state: resolved" in notes
    assert "Remediation category: vendor_fix" in str(relationships[1]["security_statusNotes"])

    creation_infos = _elements_of_type(document, "CreationInfo")
    assert len(creation_infos) == 1
    assert creation_infos[0]["specVersion"] == SPDX3_SPEC_VERSION
    assert creation_infos[0]["created"] == "2026-06-23T00:00:00Z"

    vulnerabilities = _elements_of_type(document, "security_Vulnerability")
    assert [vulnerability["name"] for vulnerability in vulnerabilities] == [
        f"CVE-2026-000{index}" for index in range(1, 6)
    ]
    assert all(
        vulnerability["externalIdentifier"][0]["externalIdentifierType"] == "cve"
        for vulnerability in vulnerabilities
    )
    assert vulnerabilities[0]["security_modifiedTime"] == "2026-01-01T00:00:00Z"

    packages = _elements_of_type(document, "software_Package")
    assert [(package["name"], package["software_packageVersion"]) for package in packages] == [
        ("minimist", "0.0.8"),
        ("django", "1.2"),
    ]


@pytest.mark.parametrize(
    "source_url",
    (
        "https://audit-user@example.test/advisory",
        "https://audit-user:super-secret@example.test/advisory",  # pragma: allowlist secret
        "https://audit%2Duser:super%2Dsecret@example.test/advisory",  # pragma: allowlist secret
    ),
)
def test_spdx3_renderer_rejects_source_url_userinfo_without_echoing_it(
    source_url: str,
) -> None:
    finding = _finding(source_url=source_url)

    with pytest.raises(Spdx3RenderError, match="must not include userinfo") as captured:
        _render((finding,))

    assert "audit" not in str(captured.value)


def test_spdx3_document_renderer_rejects_conflicting_product_version() -> None:
    finding = _finding()
    document = vex_document_from_findings(components=_components(), findings=(finding,))
    product = replace(document.products[0], version="9.9")
    document = replace(
        document,
        products=(product,),
        assertions=(replace(document.assertions[0], product=product),),
    )

    with pytest.raises(Spdx3RenderError, match="conflicting version identity"):
        Spdx3JsonRenderer(creator="Vexcalibur Test Maintainers")._render_document(document=document)


def test_spdx3_compatibility_renderer_adapts_then_delegates() -> None:
    components = _components()
    finding = _finding(component=components[0])
    received: dict[str, object] = {}

    class RecordingRenderer(Spdx3JsonRenderer):
        def _render_document(
            self,
            *,
            document: VexDocument,
            timestamp: datetime | None = None,
        ) -> str:
            received.update(document=document, timestamp=timestamp)
            return "rendered-document"

    rendered = RecordingRenderer(creator="Example Security Team").render(
        components=components,
        findings=(finding,),
        timestamp=TIMESTAMP,
    )

    assert rendered == "rendered-document"
    assert received["timestamp"] == TIMESTAMP
    document = received["document"]
    assert isinstance(document, VexDocument)
    assert document.assertions[0].product.key == components[0].ref


def test_spdx3_groups_products_and_is_input_order_independent() -> None:
    components = _components()
    first = _finding(component=components[0])
    second = replace(
        first,
        component_ref=components[1].ref,
        purl=components[1].purl.to_string(),
    )

    forward = _render((first, second, first))
    reverse = _render(
        (second, first),
        components=tuple(reversed(components)),
    )

    assert forward == reverse
    document = _validate(forward)
    relationships = _relationships(document)
    assert len(relationships) == 1
    packages = _elements_of_type(document, "software_Package")
    assert [package["software_packageUrl"] for package in packages] == [
        "pkg:npm/minimist@0.0.8",
        "pkg:pypi/django@1.2",
    ]
    assert relationships[0]["to"] == sorted(package["spdxId"] for package in packages)


def test_spdx3_merges_sources_into_one_vulnerability_element() -> None:
    components = _components()
    first = _finding(
        component=components[0],
        source_name="First Source",
        source_url="https://security.example.test/first/CVE-2026-0001",
        modified=parse_timestamp("2026-01-01T00:00:00Z"),
    )
    second = replace(
        first,
        component_ref=components[1].ref,
        purl=components[1].purl.to_string(),
        source_name="Second Source",
        source_url="https://security.example.test/second/CVE-2026-0001",
        modified=parse_timestamp("2026-02-02T00:00:00Z"),
    )

    document = _validate(_render((first, second)))

    vulnerabilities = _elements_of_type(document, "security_Vulnerability")
    assert len(vulnerabilities) == 1
    identifier = vulnerabilities[0]["externalIdentifier"][0]
    assert identifier["identifierLocator"] == [
        "https://security.example.test/first/CVE-2026-0001",
        "https://security.example.test/second/CVE-2026-0001",
    ]
    assert "security_modifiedTime" not in vulnerabilities[0]
    relationships = _relationships(document)
    assert len(relationships) == 2
    assert "Source record modified: 2026-01-01T00:00:00Z" in str(
        relationships[0]["security_statusNotes"]
    )


def test_spdx3_identifies_non_cve_ids_as_security_other() -> None:
    finding = _finding(vulnerability_id="GHSA-xxxx-yyyy-zzzz")

    document = _validate(_render((finding,)))

    vulnerability = _elements_of_type(document, "security_Vulnerability")[0]
    identifier = vulnerability["externalIdentifier"][0]
    assert identifier["externalIdentifierType"] == "securityOther"
    assert identifier["identifier"] == "GHSA-xxxx-yyyy-zzzz"


def test_spdx3_keeps_remediation_category_in_status_notes_only() -> None:
    finding = _finding(
        state=VexAnalysisState.EXPLOITABLE,
        action_statement="Upgrade to the next release.",
    )

    without_category = _render((finding,))
    with_category = _render(
        (replace(finding, remediation_category=VexRemediationCategory.WORKAROUND),),
    )

    assert without_category != with_category
    document = _validate(with_category)
    relationship = _relationships(document)[0]
    assert "Remediation category: workaround" in str(relationship["security_statusNotes"])
    assert not any("remediation" in key.lower() for key in relationship)


def test_spdx3_rejects_remediation_category_for_nonexploitable_findings() -> None:
    finding = _finding()

    with pytest.raises(Spdx3RenderError, match="only valid for an exploitable finding"):
        _render((replace(finding, remediation_category=VexRemediationCategory.WORKAROUND),))


@pytest.mark.parametrize(
    "conflict_kind",
    (
        "source",
        "detail",
        "modified",
        "state",
        "remediation",
    ),
)
def test_spdx3_rejects_overlapping_assertions_for_one_product(
    conflict_kind: str,
) -> None:
    base = _finding(
        state=VexAnalysisState.EXPLOITABLE,
        action_statement="Upgrade to the next release.",
        modified=TIMESTAMP,
    )
    if conflict_kind == "source":
        second = replace(base, source_name="Second Source")
    elif conflict_kind == "detail":
        second = replace(base, analysis_detail="A different analysis.")
    elif conflict_kind == "modified":
        second = replace(base, modified=parse_timestamp("2026-06-24T00:00:00Z"))
    elif conflict_kind == "remediation":
        second = replace(base, remediation_category=VexRemediationCategory.WORKAROUND)
    else:
        second = replace(
            base,
            analysis_state=VexAnalysisState.RESOLVED,
            action_statement=None,
            fixed_version="0.0.8",
        )

    with pytest.raises(Spdx3RenderError, match="overlapping assertions"):
        _render((base, second))


def test_spdx3_normalizes_naive_timestamps_and_content_derives_namespace() -> None:
    finding = _finding(modified=datetime(2026, 1, 2, 3, 4, 5))

    first = _validate(
        _render(
            (finding,),
            creator="  Example Security Team  ",
            timestamp=datetime(2026, 6, 23),
        )
    )
    repeated = _validate(_render((finding,), creator="Example Security Team"))
    changed = _validate(_render((finding,), creator="Another Security Team"))

    assert first == repeated
    creation_info = _elements_of_type(first, "CreationInfo")[0]
    assert creation_info["created"] == "2026-06-23T00:00:00Z"
    agent = _elements_of_type(first, "Agent")[0]
    assert agent["name"] == "Example Security Team"
    document_element = _elements_of_type(first, "SpdxDocument")[0]
    changed_document_element = _elements_of_type(changed, "SpdxDocument")[0]
    assert str(document_element["spdxId"]).startswith("https://vexcalibur.dev/spdx3/")
    assert changed_document_element["spdxId"] != document_element["spdxId"]


def test_spdx3_truncates_subsecond_timestamps_to_the_spdx_datetime_format() -> None:
    finding = _finding()

    document = _validate(_render((finding,), timestamp=datetime(2026, 6, 23, 1, 2, 3, 999_999)))

    creation_info = _elements_of_type(document, "CreationInfo")[0]
    assert creation_info["created"] == "2026-06-23T01:02:03Z"


def test_spdx3_zero_pads_years_below_1000_in_spdx_timestamps() -> None:
    finding = _finding(modified=datetime(2, 3, 4, 5, 6, 7))

    document = _validate(_render((finding,), timestamp=datetime(1, 1, 1)))

    creation_info = _elements_of_type(document, "CreationInfo")[0]
    assert creation_info["created"] == "0001-01-01T00:00:00Z"
    vulnerability = _elements_of_type(document, "security_Vulnerability")[0]
    assert vulnerability["security_modifiedTime"] == "0002-03-04T05:06:07Z"


def test_spdx3_uses_component_version_to_make_an_unversioned_product_purl_precise() -> None:
    component = replace(
        _components()[1],
        purl=PackageURL.from_string("pkg:pypi/django"),
    )
    finding = _finding(component=component)

    document = _validate(_render((finding,), components=(component,)))

    package = _elements_of_type(document, "software_Package")[0]
    assert package["software_packageUrl"] == "pkg:pypi/django@1.2"
    assert package["software_packageVersion"] == "1.2"


def test_spdx3_rejects_a_product_without_any_version() -> None:
    component = replace(
        _components()[1],
        version=None,
        purl=PackageURL.from_string("pkg:pypi/django"),
    )
    finding = _finding(component=component)

    with pytest.raises(Spdx3RenderError, match="must include a version"):
        _render((finding,), components=(component,))


@pytest.mark.parametrize("creator", ("", " ", "\t"))
def test_spdx3_rejects_empty_creators(creator: str) -> None:
    with pytest.raises(Spdx3RenderError, match="nonempty creator"):
        _render((_finding(),), creator=creator)


def test_spdx3_rejects_empty_tool_version() -> None:
    with pytest.raises(Spdx3RenderError, match="tool version must not be empty"):
        Spdx3JsonRenderer(creator="Example Security Team", tool_version=" ")


def test_spdx3_rejects_empty_findings() -> None:
    with pytest.raises(Spdx3RenderError, match="at least one"):
        _render(())


def test_spdx3_rejects_unknown_component_refs() -> None:
    finding = replace(_finding(), component_ref="component:missing")

    with pytest.raises(Spdx3RenderError, match="unknown component"):
        _render((finding,))


def test_spdx3_rejects_finding_purl_mismatch() -> None:
    finding = replace(_finding(), purl="pkg:pypi/not-django@1.2")

    with pytest.raises(Spdx3RenderError, match="does not match"):
        _render((finding,))


def test_spdx3_rejects_affected_finding_without_explicit_action() -> None:
    finding = _finding(
        state=VexAnalysisState.EXPLOITABLE,
        detail="The vulnerable feature is reachable.",
    )

    with pytest.raises(Spdx3RenderError, match="requires an action_statement"):
        _render((finding,))


def test_spdx3_rejects_action_for_a_nonaffected_status() -> None:
    finding = _finding(action_statement="Upgrade to the next release.")

    with pytest.raises(Spdx3RenderError, match="only valid for an exploitable finding"):
        _render((finding,))


@pytest.mark.parametrize(
    "state",
    (VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED),
)
def test_spdx3_requires_explicit_impact_for_not_affected_statuses(
    state: VexAnalysisState,
) -> None:
    finding = _finding(state=state, detail="This prose is not an impact statement.")

    with pytest.raises(Spdx3RenderError, match="require an impact_statement"):
        _render((finding,))


def test_spdx3_rejects_impact_for_an_affected_status() -> None:
    finding = _finding(
        state=VexAnalysisState.EXPLOITABLE,
        action_statement="Upgrade to the next release.",
        impact_statement="The vulnerable code is not reachable.",
    )

    with pytest.raises(Spdx3RenderError, match="only valid for a false_positive"):
        _render((finding,))


def test_spdx3_requires_fixed_version_for_resolved_findings() -> None:
    finding = _finding(state=VexAnalysisState.RESOLVED)

    with pytest.raises(Spdx3RenderError, match="require fixed_version"):
        _render((finding,))


def test_spdx3_rejects_fixed_version_that_does_not_match_product() -> None:
    finding = _finding(state=VexAnalysisState.RESOLVED, fixed_version="9.9")

    with pytest.raises(Spdx3RenderError, match="does not match product"):
        _render((finding,))


def test_spdx3_rejects_fixed_version_for_unresolved_finding() -> None:
    finding = _finding(fixed_version="1.2")

    with pytest.raises(Spdx3RenderError, match="only valid for a resolved finding"):
        _render((finding,))


@pytest.mark.parametrize(
    ("field_name", "finding"),
    (
        ("id", replace(_finding(), id=" ")),
        ("source_name", replace(_finding(), source_name=" ")),
        ("source_url", replace(_finding(), source_url=" ")),
        ("analysis_detail", replace(_finding(), analysis_detail=" ")),
        ("action_statement", replace(_finding(), action_statement=" ")),
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
def test_spdx3_rejects_empty_finding_text(
    field_name: str,
    finding: VulnerabilityFinding,
) -> None:
    with pytest.raises(Spdx3RenderError, match=field_name):
        _render((finding,))
