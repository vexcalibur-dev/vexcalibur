import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from packageurl import PackageURL

from vexcalibur.document import VexDocument
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.generate import generate_vex_from_local_findings
from vexcalibur.openvex import (
    OPENVEX_CONTEXT,
    OpenVexJsonRenderer,
    OpenVexRenderError,
    render_openvex_json,
)
from vexcalibur.sbom import load_cyclonedx_json
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
SCHEMA_PATH = FIXTURE_ROOT / "schemas" / "openvex-0.2.0.schema.json"
GOLDEN_ROOT = Path(__file__).parent / "golden"
OPENVEX_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(OPENVEX_SCHEMA, format_checker=FormatChecker())
TIMESTAMP = parse_timestamp("2026-06-23T00:00:00Z")


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


def _validate(document_json: str) -> dict[str, object]:
    document = json.loads(document_json)
    VALIDATOR.validate(document)
    assert document["@context"] == OPENVEX_CONTEXT
    assert document["statements"]
    for statement in document["statements"]:
        assert statement["products"]
    return document


def test_render_openvex_matches_all_states_golden_and_official_schema() -> None:
    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json",
        findings_file=FIXTURE_ROOT / "findings" / "all-analysis-states.json",
        timestamp=TIMESTAMP,
        renderer=OpenVexJsonRenderer(
            author="Vexcalibur Test Maintainers",
            role="Document producer",
        ),
    )

    assert generated == (GOLDEN_ROOT / "openvex-vex-all-analysis-states.json").read_text(
        encoding="utf-8"
    )
    document = _validate(generated)
    statements = document["statements"]
    assert [statement["status"] for statement in statements] == [
        "fixed",
        "affected",
        "under_investigation",
        "not_affected",
        "not_affected",
    ]
    assert statements[1]["action_statement"] == "Upgrade minimist to version 1.2.8 or later."
    assert "impact_statement" not in statements[1]
    assert statements[3]["impact_statement"].startswith("The source matched")
    assert statements[4]["impact_statement"].startswith("The deployment does not enable")
    assert "Confirmed fixed product version: 1.2" in statements[0]["status_notes"]
    assert all("last_updated" not in statement for statement in statements)
    assert "last_updated" not in document


def test_openvex_compatibility_renderer_adapts_then_delegates() -> None:
    components = _components()
    finding = _finding(component=components[0])
    received: dict[str, object] = {}

    class RecordingRenderer(OpenVexJsonRenderer):
        def render_document(
            self,
            *,
            document: VexDocument,
            timestamp: datetime | None = None,
        ) -> str:
            received.update(document=document, timestamp=timestamp)
            return "rendered-document"

    rendered = RecordingRenderer(author="Example Security Team").render(
        components=components,
        findings=(finding,),
        timestamp=TIMESTAMP,
    )

    assert rendered == "rendered-document"
    assert received["timestamp"] == TIMESTAMP
    document = received["document"]
    assert isinstance(document, VexDocument)
    assert document.assertions[0].product.key == components[0].ref


def test_openvex_groups_products_and_is_input_order_independent() -> None:
    components = _components()
    first = _finding(component=components[0])
    second = replace(
        first,
        component_ref=components[1].ref,
        purl=components[1].purl.to_string(),
    )

    forward = render_openvex_json(
        components=components,
        findings=(first, second, first),
        author="Example Security Team",
        timestamp=TIMESTAMP,
    )
    reverse = render_openvex_json(
        components=tuple(reversed(components)),
        findings=(second, first),
        author="Example Security Team",
        timestamp=TIMESTAMP,
    )

    assert forward == reverse
    document = _validate(forward)
    assert document["statements"] == [
        {
            "products": [
                {
                    "@id": "pkg:npm/minimist@0.0.8",
                    "identifiers": {"purl": "pkg:npm/minimist@0.0.8"},
                },
                {
                    "@id": "pkg:pypi/django@1.2",
                    "identifiers": {"purl": "pkg:pypi/django@1.2"},
                },
            ],
            "status": "under_investigation",
            "status_notes": (
                "Analysis detail: Review is underway.\n"
                "Source: Internal Review "
                "(https://security.example.test/vulnerabilities/CVE-2026-0001)\n"
                "Original Vexcalibur analysis state: in_triage"
            ),
            "vulnerability": {"name": "CVE-2026-0001"},
        }
    ]


def test_openvex_ignores_remediation_category() -> None:
    finding = _finding()

    without_category = render_openvex_json(
        components=_components(),
        findings=(finding,),
        author="Example Security Team",
        timestamp=TIMESTAMP,
    )
    with_category = render_openvex_json(
        components=_components(),
        findings=(
            finding,
            replace(finding, remediation_category=VexRemediationCategory.WORKAROUND),
        ),
        author="Example Security Team",
        timestamp=TIMESTAMP,
    )

    assert with_category == without_category


@pytest.mark.parametrize(
    "conflict_kind",
    (
        "source",
        "detail",
        "modified",
        "state",
    ),
)
def test_openvex_rejects_overlapping_assertions_for_one_product(
    conflict_kind: str,
) -> None:
    base = _finding(modified=TIMESTAMP)
    if conflict_kind == "source":
        second = replace(base, source_name="Second Source")
    elif conflict_kind == "detail":
        second = replace(base, analysis_detail="A different analysis.")
    elif conflict_kind == "modified":
        second = replace(base, modified=parse_timestamp("2026-06-24T00:00:00Z"))
    else:
        second = replace(
            base,
            analysis_state=VexAnalysisState.RESOLVED,
            fixed_version="0.0.8",
        )

    with pytest.raises(OpenVexRenderError, match="overlapping assertions"):
        render_openvex_json(
            components=_components(),
            findings=(base, second),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_normalizes_naive_timestamps_and_content_derives_document_id() -> None:
    finding = _finding(modified=datetime(2026, 1, 2, 3, 4, 5))

    first = _validate(
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="  Example Security Team  ",
            role="  Product security  ",
            timestamp=datetime(2026, 6, 23),
        )
    )
    repeated = _validate(
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            role="Product security",
            timestamp=TIMESTAMP,
        )
    )
    changed = _validate(
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Another Security Team",
            role="Product security",
            timestamp=TIMESTAMP,
        )
    )

    assert first == repeated
    assert first["timestamp"] == "2026-06-23T00:00:00Z"
    assert first["author"] == "Example Security Team"
    assert first["role"] == "Product security"
    assert first["@id"].startswith("urn:uuid:")
    assert changed["@id"] != first["@id"]


def test_openvex_uses_component_version_to_make_an_unversioned_product_purl_precise() -> None:
    component = replace(
        _components()[1],
        purl=PackageURL.from_string("pkg:pypi/django"),
    )
    finding = _finding(component=component)

    document = _validate(
        render_openvex_json(
            components=(component,),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )
    )

    assert document["statements"][0]["products"] == [
        {
            "@id": "pkg:pypi/django@1.2",
            "identifiers": {"purl": "pkg:pypi/django@1.2"},
        }
    ]


def test_openvex_rejects_a_product_without_any_version() -> None:
    component = replace(
        _components()[1],
        version=None,
        purl=PackageURL.from_string("pkg:pypi/django"),
    )
    finding = _finding(component=component)

    with pytest.raises(OpenVexRenderError, match="must include a version"):
        render_openvex_json(
            components=(component,),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


@pytest.mark.parametrize("author", ("", " ", "\t"))
def test_openvex_rejects_empty_authors(author: str) -> None:
    with pytest.raises(OpenVexRenderError, match="nonempty author"):
        render_openvex_json(
            components=_components(),
            findings=(_finding(),),
            author=author,
            timestamp=TIMESTAMP,
        )


def test_openvex_renderer_rejects_empty_role() -> None:
    with pytest.raises(OpenVexRenderError, match="role must not be empty"):
        OpenVexJsonRenderer(author="Example Security Team", role=" ")


def test_openvex_rejects_empty_findings() -> None:
    with pytest.raises(OpenVexRenderError, match="at least one"):
        render_openvex_json(
            components=_components(),
            findings=(),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_unknown_component_refs() -> None:
    finding = replace(_finding(), component_ref="component:missing")

    with pytest.raises(OpenVexRenderError, match="unknown component"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_finding_purl_mismatch() -> None:
    finding = replace(_finding(), purl="pkg:pypi/not-django@1.2")

    with pytest.raises(OpenVexRenderError, match="does not match"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_affected_finding_without_explicit_action() -> None:
    finding = _finding(
        state=VexAnalysisState.EXPLOITABLE,
        detail="The vulnerable feature is reachable.",
    )

    with pytest.raises(OpenVexRenderError, match="requires an action_statement"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_action_for_a_nonaffected_status() -> None:
    finding = _finding(action_statement="Upgrade to the next release.")

    with pytest.raises(OpenVexRenderError, match="only valid for an exploitable finding"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


@pytest.mark.parametrize(
    "state",
    (VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED),
)
def test_openvex_requires_explicit_impact_for_not_affected_statuses(
    state: VexAnalysisState,
) -> None:
    finding = _finding(state=state, detail="This prose is not an impact statement.")

    with pytest.raises(OpenVexRenderError, match="require an impact_statement"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_impact_for_an_affected_status() -> None:
    finding = _finding(
        state=VexAnalysisState.EXPLOITABLE,
        action_statement="Upgrade to the next release.",
        impact_statement="The vulnerable code is not reachable.",
    )

    with pytest.raises(OpenVexRenderError, match="only valid for a false_positive"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_requires_fixed_version_for_resolved_findings() -> None:
    finding = _finding(state=VexAnalysisState.RESOLVED)

    with pytest.raises(OpenVexRenderError, match="require fixed_version"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_fixed_version_that_does_not_match_product() -> None:
    finding = _finding(state=VexAnalysisState.RESOLVED, fixed_version="9.9")

    with pytest.raises(OpenVexRenderError, match="does not match product"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


def test_openvex_rejects_fixed_version_for_unresolved_finding() -> None:
    finding = _finding(fixed_version="1.2")

    with pytest.raises(OpenVexRenderError, match="only valid for a resolved finding"):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )


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
def test_openvex_rejects_empty_finding_text(
    field_name: str,
    finding: VulnerabilityFinding,
) -> None:
    with pytest.raises(OpenVexRenderError, match=field_name):
        render_openvex_json(
            components=_components(),
            findings=(finding,),
            author="Example Security Team",
            timestamp=TIMESTAMP,
        )
