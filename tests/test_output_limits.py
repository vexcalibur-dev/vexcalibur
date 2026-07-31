from datetime import datetime
from typing import Literal

import pytest
from packageurl import PackageURL

from vexcalibur import generate as generate_module
from vexcalibur.csaf import (
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafPublisherCategory,
)
from vexcalibur.document import VexDocument
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.generate import (
    ExecutionReportOutputFormat,
    generate_vex_from_components,
    generate_vex_from_components_result,
)
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import VexRenderer, VexRenderError
from vexcalibur.vex import CycloneDxJsonRenderer


def test_production_vex_output_limit_is_25_mib() -> None:
    assert generate_module.MAX_VEX_OUTPUT_BYTES == 25 * 1024 * 1024


class _StaticSource:
    def __init__(self, findings: tuple[VulnerabilityFinding, ...]) -> None:
        self._findings = findings

    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        return self._findings


def _renderers() -> tuple[VexRenderer | None, ...]:
    return (
        None,
        OpenVexJsonRenderer(author="https://security.example.test"),
        Csaf20VexJsonRenderer(
            metadata=Csaf20DocumentMetadata(
                document_id="VEX-2026-0001",
                title="Security advisory",
                publisher_name="Example Security",
                publisher_namespace="https://security.example.test",
                publisher_category=CsafPublisherCategory.VENDOR,
            )
        ),
    )


@pytest.mark.parametrize("renderer", _renderers(), ids=("cyclonedx", "openvex", "csaf"))
def test_builtin_renderers_reject_oversized_fields_before_rendering(
    monkeypatch: pytest.MonkeyPatch,
    renderer: VexRenderer | None,
) -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    repeated_detail = "A" * 4_096
    findings = tuple(
        VulnerabilityFinding(
            id=f"CVE-2026-{index:04d}",
            source_name="Unit Test",
            source_url="https://security.example.test/vulnerabilities",
            component_ref=component.ref,
            purl=component.purl.to_string(),
            analysis_detail=repeated_detail,
        )
        for index in range(32)
    )
    document_was_built = False

    def unexpected_document_build(**kwargs: object) -> object:
        nonlocal document_was_built
        document_was_built = True
        raise AssertionError("renderer built a document before input preflight")

    monkeypatch.setattr(
        "vexcalibur.render_budget.MAX_GENERATED_DOCUMENT_BYTES",
        64 * 1024,
    )
    module = "vexcalibur.vex" if renderer is None else f"{type(renderer).__module__}"
    monkeypatch.setattr(f"{module}.vex_document_from_findings", unexpected_document_build)

    with pytest.raises(VexRenderError, match="65536 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource(findings),
            timestamp=None,
            renderer=renderer,
        )

    assert document_was_built is False


def test_openvex_preflight_accounts_for_percent_encoded_derived_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="?" * 12_000,
        purl=PackageURL.from_string("pkg:pypi/demo"),
    )
    findings = (
        VulnerabilityFinding(
            id="CVE-2026-0001",
            source_name="Unit Test",
            source_url="https://security.example.test/vulnerabilities",
            component_ref=component.ref,
            purl=component.purl.to_string(),
        ),
    )
    renderer = OpenVexJsonRenderer(author="https://security.example.test")
    document_was_built = False

    def unexpected_document_build(**kwargs: object) -> object:
        nonlocal document_was_built
        document_was_built = True
        raise AssertionError("renderer built a document before input preflight")

    monkeypatch.setattr(
        "vexcalibur.render_budget.MAX_GENERATED_DOCUMENT_BYTES",
        64 * 1024,
    )
    monkeypatch.setattr(
        "vexcalibur.openvex.vex_document_from_findings",
        unexpected_document_build,
    )

    with pytest.raises(VexRenderError, match="65536 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource(findings),
            timestamp=None,
            renderer=renderer,
        )

    assert document_was_built is False


def test_openvex_preflight_scales_derived_purl_budget_per_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="?" * 3_000,
        purl=PackageURL.from_string("pkg:pypi/demo"),
    )
    findings = tuple(
        VulnerabilityFinding(
            id=f"CVE-2026-{index:04d}",
            source_name="Unit Test",
            source_url="https://security.example.test/vulnerabilities",
            component_ref=component.ref,
            purl=component.purl.to_string(),
        )
        for index in range(5)
    )
    renderer = OpenVexJsonRenderer(author="https://security.example.test")
    document_was_built = False

    def unexpected_document_build(**kwargs: object) -> object:
        nonlocal document_was_built
        document_was_built = True
        raise AssertionError("renderer built a document before input preflight")

    monkeypatch.setattr(
        "vexcalibur.render_budget.MAX_GENERATED_DOCUMENT_BYTES",
        64 * 1024,
    )
    monkeypatch.setattr(
        "vexcalibur.openvex.vex_document_from_findings",
        unexpected_document_build,
    )

    with pytest.raises(VexRenderError, match="65536 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource(findings),
            timestamp=None,
            renderer=renderer,
        )

    assert document_was_built is False


def test_preflight_ignores_unreferenced_component_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = ComponentIdentity(
        ref="component:clean",
        name="A" * 15_500,
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/clean@1.0.0"),
    )
    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64 * 1024)
    monkeypatch.setattr(
        "vexcalibur.render_budget.MAX_GENERATED_DOCUMENT_BYTES",
        64 * 1024,
    )

    rendered = generate_vex_from_components(
        components=(component,),
        source=_StaticSource(()),
        timestamp=None,
    )

    assert len(rendered.encode("utf-8")) < 64 * 1024


def test_builtin_renderer_subclass_uses_exact_post_render_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    render_was_called = False

    class CustomCycloneDxRenderer(CycloneDxJsonRenderer):
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            nonlocal render_was_called
            render_was_called = True
            return "x" * 65

    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    finding = VulnerabilityFinding(
        id="CVE-2026-0001",
        source_name="Unit Test",
        source_url="https://security.example.test/vulnerabilities",
        component_ref=component.ref,
        purl=component.purl.to_string(),
    )
    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64)

    with pytest.raises(VexRenderError, match="64 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource((finding,)),
            timestamp=None,
            renderer=CustomCycloneDxRenderer(),
        )

    assert render_was_called is True


def _inherited_render_subclasses() -> tuple[VexRenderer, ...]:
    class CustomCycloneDxRenderer(CycloneDxJsonRenderer):
        def render_document(
            self,
            *,
            document: VexDocument,
            timestamp: datetime | None = None,
        ) -> str:
            del document, timestamp
            return "{}\n"

    class CustomOpenVexRenderer(OpenVexJsonRenderer):
        def render_document(
            self,
            *,
            document: VexDocument,
            timestamp: datetime | None = None,
        ) -> str:
            del document, timestamp
            return "{}\n"

    class CustomCsafRenderer(Csaf20VexJsonRenderer):
        def render_document(
            self,
            *,
            document: VexDocument,
            timestamp: datetime | None = None,
        ) -> str:
            del document, timestamp
            return "{}\n"

    return (
        CustomCycloneDxRenderer(),
        CustomOpenVexRenderer(author="https://security.example.test"),
        CustomCsafRenderer(
            metadata=Csaf20DocumentMetadata(
                document_id="VEX-2026-0001",
                title="Security advisory",
                publisher_name="Example Security",
                publisher_namespace="https://security.example.test",
                publisher_category=CsafPublisherCategory.VENDOR,
            )
        ),
    )


@pytest.mark.parametrize(
    "renderer",
    _inherited_render_subclasses(),
    ids=("cyclonedx", "openvex", "csaf"),
)
def test_inherited_builtin_render_skips_builtin_preflight_budget(
    renderer: VexRenderer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    repeated_detail = "A" * 4_096
    findings = tuple(
        VulnerabilityFinding(
            id=f"CVE-2026-{index:04d}",
            source_name="Unit Test",
            source_url="https://security.example.test/vulnerabilities",
            component_ref=component.ref,
            purl=component.purl.to_string(),
            analysis_detail=repeated_detail,
        )
        for index in range(32)
    )
    monkeypatch.setattr(
        "vexcalibur.render_budget.MAX_GENERATED_DOCUMENT_BYTES",
        64 * 1024,
    )
    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64)

    rendered = generate_vex_from_components(
        components=(component,),
        source=_StaticSource(findings),
        timestamp=None,
        renderer=renderer,
    )

    assert rendered == "{}\n"


def test_report_format_capability_does_not_enable_preflight_budgeting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    render_was_called = False

    class RegisteredRenderer(CycloneDxJsonRenderer):
        def execution_report_output_format(
            self,
        ) -> Literal[ExecutionReportOutputFormat.CUSTOM]:
            return ExecutionReportOutputFormat.CUSTOM

        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            nonlocal render_was_called
            render_was_called = True
            return "{}\n"

    component = ComponentIdentity(
        ref="component:demo",
        name="A" * 1_024,
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    finding = VulnerabilityFinding(
        id="CVE-2026-0001",
        source_name="Unit Test",
        source_url="https://security.example.test/vulnerabilities",
        component_ref=component.ref,
        purl=component.purl.to_string(),
    )
    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64)

    result = generate_vex_from_components_result(
        components=(component,),
        source=_StaticSource((finding,)),
        timestamp=None,
        renderer=RegisteredRenderer(),
    )

    assert result.rendered_document == "{}\n"
    assert render_was_called is True


@pytest.mark.parametrize(
    ("rendered", "should_succeed"),
    (
        ("a" * 62 + "\N{LATIN SMALL LETTER E WITH ACUTE}", True),
        ("a" * 63 + "\N{LATIN SMALL LETTER E WITH ACUTE}", False),
    ),
)
def test_custom_renderer_limit_counts_exact_utf8_bytes(
    monkeypatch: pytest.MonkeyPatch,
    rendered: str,
    should_succeed: bool,
) -> None:
    class CustomRenderer:
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            return rendered

    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64)

    if should_succeed:
        assert (
            generate_vex_from_components(
                components=(component,),
                source=_StaticSource(()),
                timestamp=None,
                renderer=CustomRenderer(),
            )
            == rendered
        )
    else:
        with pytest.raises(VexRenderError, match="64 byte output limit"):
            generate_vex_from_components(
                components=(component,),
                source=_StaticSource(()),
                timestamp=None,
                renderer=CustomRenderer(),
            )
