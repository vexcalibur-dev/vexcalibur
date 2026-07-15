from datetime import datetime

import pytest
from packageurl import PackageURL

from vexcalibur.csaf import (
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafPublisherCategory,
)
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.generate import generate_vex_from_components
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import VexRenderer, VexRenderError
from vexcalibur.vex import CycloneDxJsonRenderer


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
    selected_renderer = CycloneDxJsonRenderer() if renderer is None else renderer
    render_was_called = False

    def unexpected_render(
        self: object,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        nonlocal render_was_called
        render_was_called = True
        return "{}"

    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64 * 1024)
    monkeypatch.setattr(type(selected_renderer), "render", unexpected_render)

    with pytest.raises(VexRenderError, match="65536 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource(findings),
            timestamp=None,
            renderer=renderer,
        )

    assert render_was_called is False


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
    render_was_called = False

    def unexpected_render(
        self: object,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        nonlocal render_was_called
        render_was_called = True
        return "{}"

    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64 * 1024)
    monkeypatch.setattr(type(renderer), "render", unexpected_render)

    with pytest.raises(VexRenderError, match="65536 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource(findings),
            timestamp=None,
            renderer=renderer,
        )

    assert render_was_called is False


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
    render_was_called = False

    def unexpected_render(
        self: object,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        nonlocal render_was_called
        render_was_called = True
        return "{}"

    monkeypatch.setattr("vexcalibur.generate.MAX_VEX_OUTPUT_BYTES", 64 * 1024)
    monkeypatch.setattr(type(renderer), "render", unexpected_render)

    with pytest.raises(VexRenderError, match="65536 byte output limit"):
        generate_vex_from_components(
            components=(component,),
            source=_StaticSource(findings),
            timestamp=None,
            renderer=renderer,
        )

    assert render_was_called is False


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
