from dataclasses import FrozenInstanceError, replace

import pytest
from packageurl import PackageURL

from vexcalibur.document import (
    VexAnalysisQualifier,
    VexDisposition,
    VexProductIdentifierType,
    analysis_state,
    vex_document_from_findings,
)
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.render import VexRenderError
from vexcalibur.vex import parse_timestamp


def _component(
    *,
    ref: str = "component:demo",
    purl: str = "pkg:pypi/demo@1.0.0",
) -> ComponentIdentity:
    return ComponentIdentity(
        ref=ref,
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string(purl),
        type="application",
    )


def _finding(
    component: ComponentIdentity,
    *,
    state: VexAnalysisState = VexAnalysisState.IN_TRIAGE,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id="CVE-2026-0001",
        source_name="Internal Review",
        source_url="https://security.example.test/CVE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
        analysis_state=state,
        analysis_detail="Reviewed by the product security team.",
    )


@pytest.mark.parametrize(
    ("state", "disposition", "qualifier"),
    (
        (VexAnalysisState.RESOLVED, VexDisposition.FIXED, None),
        (
            VexAnalysisState.EXPLOITABLE,
            VexDisposition.AFFECTED,
            VexAnalysisQualifier.EXPLOITABLE,
        ),
        (
            VexAnalysisState.IN_TRIAGE,
            VexDisposition.UNDER_INVESTIGATION,
            None,
        ),
        (
            VexAnalysisState.FALSE_POSITIVE,
            VexDisposition.NOT_AFFECTED,
            VexAnalysisQualifier.FALSE_POSITIVE,
        ),
        (VexAnalysisState.NOT_AFFECTED, VexDisposition.NOT_AFFECTED, None),
    ),
)
def test_adapter_preserves_analysis_semantics(
    state: VexAnalysisState,
    disposition: VexDisposition,
    qualifier: VexAnalysisQualifier | None,
) -> None:
    component = _component()

    document = vex_document_from_findings(
        components=(component,),
        findings=(_finding(component, state=state),),
    )

    assertion = document.assertions[0]
    assert assertion.disposition is disposition
    assert assertion.qualifier is qualifier
    assert analysis_state(assertion) is state


def test_adapter_retains_product_source_timestamp_and_all_evidence() -> None:
    component = _component()
    modified = parse_timestamp("2026-07-15T12:00:00Z")
    finding = replace(
        _finding(component, state=VexAnalysisState.EXPLOITABLE),
        modified=modified,
        action_statement="Upgrade the component.",
        impact_statement="The feature is reachable.",
        fixed_version="1.0.0",
        remediation_category=VexRemediationCategory.VENDOR_FIX,
    )

    document = vex_document_from_findings(
        components=(component,),
        findings=(finding,),
    )

    product = document.products[0]
    vulnerability = document.vulnerabilities[0]
    assertion = document.assertions[0]
    assert product.key == "component:demo"
    assert product.component_type == "application"
    assert product.identifiers[0].type is VexProductIdentifierType.PURL
    assert product.identifiers[0].value == "pkg:pypi/demo@1.0.0"
    assert vulnerability.source_name == "Internal Review"
    assert vulnerability.source_url == "https://security.example.test/CVE-2026-0001"
    assert assertion.source_record_modified_at == modified
    assert assertion.action_statement == "Upgrade the component."
    assert assertion.impact_statement == "The feature is reachable."
    assert assertion.fixed_version == "1.0.0"
    assert assertion.remediation_category is VexRemediationCategory.VENDOR_FIX


def test_adapter_is_input_order_independent_and_deduplicates_exact_findings() -> None:
    first_component = _component(ref="component:first", purl="pkg:pypi/first@1.0.0")
    second_component = _component(ref="component:second", purl="pkg:pypi/second@1.0.0")
    first_finding = _finding(first_component)
    second_finding = replace(
        _finding(second_component),
        id="CVE-2026-0002",
        source_url="https://security.example.test/CVE-2026-0002",
    )

    forward = vex_document_from_findings(
        components=(first_component, second_component),
        findings=(first_finding, second_finding, first_finding),
    )
    reverse = vex_document_from_findings(
        components=(second_component, first_component),
        findings=(second_finding, first_finding),
    )

    assert forward == reverse
    assert len(forward.assertions) == 2


def test_adapter_retains_renderer_specific_evidence_variants() -> None:
    component = _component()
    finding = _finding(component)

    document = vex_document_from_findings(
        components=(component,),
        findings=(
            finding,
            replace(finding, action_statement="Upgrade the component."),
            replace(finding, remediation_category=VexRemediationCategory.WORKAROUND),
        ),
    )

    assert len(document.products) == 1
    assert len(document.vulnerabilities) == 1
    assert len(document.assertions) == 3


def test_adapter_keeps_distinct_component_refs_that_share_a_purl() -> None:
    first_component = _component(ref="component:first")
    second_component = _component(ref="component:second")

    document = vex_document_from_findings(
        components=(first_component, second_component),
        findings=(_finding(first_component), _finding(second_component)),
    )

    assert [product.key for product in document.products] == [
        "component:first",
        "component:second",
    ]
    assert [assertion.product.key for assertion in document.assertions] == [
        "component:first",
        "component:second",
    ]


def test_adapter_rejects_duplicate_component_refs() -> None:
    component = _component()

    with pytest.raises(VexRenderError, match="duplicate refs: component:demo"):
        vex_document_from_findings(
            components=(component, component),
            findings=(_finding(component),),
        )


def test_adapter_rejects_unknown_component_refs() -> None:
    component = _component()
    finding = replace(_finding(component), component_ref="component:missing")

    with pytest.raises(VexRenderError, match="unknown component 'component:missing'"):
        vex_document_from_findings(components=(component,), findings=(finding,))


def test_adapter_rejects_finding_purl_mismatch() -> None:
    component = _component()
    finding = replace(_finding(component), purl="pkg:pypi/other@1.0.0")

    with pytest.raises(VexRenderError, match="does not match component"):
        vex_document_from_findings(components=(component,), findings=(finding,))


def test_adapter_preserves_empty_snapshot_behavior() -> None:
    document = vex_document_from_findings(components=(_component(),), findings=())

    assert document.products == ()
    assert document.vulnerabilities == ()
    assert document.assertions == ()


def test_document_values_are_immutable() -> None:
    component = _component()
    document = vex_document_from_findings(
        components=(component,),
        findings=(_finding(component),),
    )

    with pytest.raises(FrozenInstanceError):
        document.products = ()  # type: ignore[misc]
