from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

import pytest
from packageurl import PackageURL

from vexcalibur.csaf import (
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafPublisherCategory,
)
from vexcalibur.domain import (
    ComponentIdentity,
    VulnerabilityFinding,
    VulnerabilitySourceInputError,
)
from vexcalibur.errors import VexRenderError
from vexcalibur.generate import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    InventorySourceCategory,
    generate_vex_from_components,
    generate_vex_from_components_result,
    generate_vex_from_github_source_result,
    generate_vex_from_source_result,
)
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    OsvPackageQuery,
    OsvQueryResult,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
FINDINGS_ROOT = Path(__file__).parent / "fixtures" / "findings"


class SentinelExtensionError(RuntimeError):
    """Distinct exception used to verify extension error identity."""


class FakeOsvClient:
    def __init__(
        self,
        results: list[OsvQueryResult] | None = None,
        *,
        base_url: str | None = None,
    ) -> None:
        self._results = results or []
        if base_url is not None:
            self.base_url = base_url

    def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
        return self._results


class FakeVulnerabilitySource:
    def __init__(self, findings: tuple[VulnerabilityFinding, ...]) -> None:
        self._findings = findings

    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        return self._findings


class FakeGithubSbomClient:
    def component_identities(self, repository: str) -> tuple[ComponentIdentity, ...]:
        assert repository == "vexcalibur-dev/vexcalibur"
        return (
            ComponentIdentity(
                ref="SPDXRef-pypi-django-1.2",
                name="django",
                version="1.2",
                purl=PackageURL.from_string("pkg:pypi/django@1.2"),
            ),
        )


class CustomRenderer:
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
        return '{"custom":true}\n'


def _csaf_renderer() -> Csaf20VexJsonRenderer:
    return Csaf20VexJsonRenderer(
        Csaf20DocumentMetadata(
            document_id="ACME-VEX-2026-001",
            title="ACME component exploitability assessment",
            publisher_name="ACME Product Security",
            publisher_namespace="https://security.example.test",
            publisher_category=CsafPublisherCategory.VENDOR,
        )
    )


def _component() -> ComponentIdentity:
    return ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )


def test_generation_snapshot_contract_covers_every_domain_field() -> None:
    assert tuple(ComponentIdentity.__dataclass_fields__) == (
        "ref",
        "name",
        "version",
        "purl",
        "type",
    )
    assert tuple(VulnerabilityFinding.__dataclass_fields__) == (
        "id",
        "source_name",
        "source_url",
        "component_ref",
        "purl",
        "modified",
        "analysis_state",
        "analysis_detail",
        "action_statement",
        "impact_statement",
        "fixed_version",
        "remediation_category",
    )


def test_legacy_generation_preserves_extension_objects() -> None:
    class ExtendedComponent(ComponentIdentity):
        pass

    class ExtendedFinding(VulnerabilityFinding):
        pass

    class ExtendedTuple(tuple):
        pass

    class RenderedDocument(str):
        pass

    component = ExtendedComponent(
        ref="component:extended",
        name="extended",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/extended@1.0.0"),
    )
    finding = ExtendedFinding(
        id="PRIVATE-2026-0001",
        source_name="Private source",
        source_url="https://security.example.test/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
    )
    object.__setattr__(component, "extension_state", "component-state")
    object.__setattr__(finding, "extension_state", "finding-state")
    components = ExtendedTuple((component,))
    findings = ExtendedTuple((finding,))
    rendered = RenderedDocument('{"extended":true}\n')

    class PreservingSource:
        execution_report_finding_source = "legacy metadata"

        def findings_for_components(
            self,
            supplied_components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            assert supplied_components is components
            assert supplied_components[0] is component
            assert supplied_components[0].extension_state == "component-state"
            return findings

    class PreservingRenderer:
        execution_report_output_format = "legacy metadata"

        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            assert components is components_from_caller
            assert findings is findings_from_source
            assert findings[0] is finding
            assert findings[0].extension_state == "finding-state"
            return rendered

    components_from_caller = components
    findings_from_source = findings
    result = generate_vex_from_components(
        components=components,
        source=PreservingSource(),
        timestamp=None,
        renderer=PreservingRenderer(),
    )

    assert result is rendered


def test_legacy_generation_does_not_read_extensions_after_rendering() -> None:
    rendered = '{"extended":true}\n'

    class StatefulFinding(VulnerabilityFinding):
        def __getattribute__(self, name: str) -> object:
            if name in VulnerabilityFinding.__dataclass_fields__ and object.__getattribute__(
                self, "_render_complete"
            ):
                raise AssertionError("finding was read after rendering")
            return super().__getattribute__(name)

    component = _component()
    finding = StatefulFinding(
        id="PRIVATE-2026-0001",
        source_name="Private source",
        source_url="https://security.example.test/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
    )
    object.__setattr__(finding, "_render_complete", False)

    class Source:
        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            return (finding,)

    class Renderer:
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            object.__setattr__(findings[0], "_render_complete", True)
            return rendered

    assert (
        generate_vex_from_components(
            components=(component,),
            source=Source(),
            timestamp=None,
            renderer=Renderer(),
        )
        is rendered
    )


def test_result_generation_preserves_source_exception_identity() -> None:
    failure = SentinelExtensionError("source failed")

    class FailingSource(FakeVulnerabilitySource):
        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            raise failure

    with pytest.raises(SentinelExtensionError) as captured:
        generate_vex_from_components_result(
            components=(_component(),),
            source=FailingSource(()),
            timestamp=None,
        )

    assert captured.value is failure


def test_result_generation_preserves_renderer_exception_identity() -> None:
    failure = VexRenderError("renderer failed")

    class FailingRenderer(CustomRenderer):
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            raise failure

    with pytest.raises(VexRenderError) as captured:
        generate_vex_from_components_result(
            components=(_component(),),
            source=FakeVulnerabilitySource(()),
            timestamp=None,
            renderer=FailingRenderer(),
        )

    assert captured.value is failure


@pytest.mark.parametrize("declaration", ["source", "renderer"])
def test_result_generation_preserves_declaration_exception_identity(
    declaration: str,
) -> None:
    failure = SentinelExtensionError(f"{declaration} declaration failed")

    class FailingSource(FakeVulnerabilitySource):
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            raise failure

    class FailingRenderer(CustomRenderer):
        def execution_report_output_format(
            self,
        ) -> Literal[ExecutionReportOutputFormat.CUSTOM]:
            raise failure

    source = FailingSource(()) if declaration == "source" else FakeVulnerabilitySource(())
    renderer = FailingRenderer() if declaration == "renderer" else CustomRenderer()

    with pytest.raises(SentinelExtensionError) as captured:
        generate_vex_from_components_result(
            components=(_component(),),
            source=source,
            timestamp=None,
            renderer=renderer,
        )

    assert captured.value is failure


def test_github_result_generation_preserves_loader_exception_identity() -> None:
    failure = SentinelExtensionError("GitHub loader failed")

    class FailingGithubSbomClient:
        def component_identities(
            self,
            repository: str,
        ) -> tuple[ComponentIdentity, ...]:
            raise failure

    with pytest.raises(SentinelExtensionError) as captured:
        generate_vex_from_github_source_result(
            repository="vexcalibur-dev/vexcalibur",
            source=FakeVulnerabilitySource(()),
            github_client=FailingGithubSbomClient(),
        )

    assert captured.value is failure


def test_source_input_error_translation_retains_original_cause() -> None:
    failure = VulnerabilitySourceInputError("invalid source input")

    class InvalidInputSource(FakeVulnerabilitySource):
        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            raise failure

    with pytest.raises(SbomError, match="invalid source input") as captured:
        generate_vex_from_components_result(
            components=(_component(),),
            source=InvalidInputSource(()),
            timestamp=None,
        )

    assert captured.value.__cause__ is failure


def test_custom_generation_requires_explicit_execution_report_context() -> None:
    component = _component()
    source = FakeVulnerabilitySource(())

    result_without_context = generate_vex_from_components_result(
        components=(component,),
        source=source,
        timestamp=None,
    )

    assert result_without_context.execution_context is None
    with pytest.raises(ValueError, match="context is unavailable"):
        result_without_context.execution_report()

    context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )
    result_with_context = generate_vex_from_components_result(
        components=(component,),
        source=source,
        timestamp=None,
        execution_context=context,
    )

    assert result_with_context.execution_context is context


def test_direct_components_cannot_claim_builtin_inventory_provenance() -> None:
    components = load_cyclonedx_sbom(FIXTURE_ROOT / "cyclonedx-json-simple.json")
    source = LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json")
    result = generate_vex_from_components_result(
        components=components,
        source=source,
        timestamp=None,
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )

    reserved_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )
    with pytest.raises(ValueError, match="inventory_source contradicts"):
        generate_vex_from_components_result(
            components=components,
            source=source,
            timestamp=None,
            execution_context=reserved_context,
        )


def test_custom_source_can_declare_its_report_category() -> None:
    class CategorizedSource(FakeVulnerabilitySource):
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

    result = generate_vex_from_source_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        source=CategorizedSource(()),
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )


@pytest.mark.parametrize("declaration", ("custom", None))
def test_custom_source_rejects_mistyped_report_category(declaration: object) -> None:
    class MistypedSource(FakeVulnerabilitySource):
        def execution_report_finding_source(self) -> object:
            return declaration

    with pytest.raises(TypeError, match="must be a FindingSourceCategory"):
        generate_vex_from_source_result(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            source=MistypedSource(()),
        )


@pytest.mark.parametrize("declaration", ("custom", None))
def test_custom_renderer_rejects_mistyped_report_category(declaration: object) -> None:
    class MistypedRenderer(CustomRenderer):
        def execution_report_output_format(self) -> object:
            return declaration

    with pytest.raises(TypeError, match="must be an ExecutionReportOutputFormat"):
        generate_vex_from_components_result(
            components=(_component(),),
            source=LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json"),
            timestamp=None,
            renderer=MistypedRenderer(),
        )


@pytest.mark.parametrize(
    "declaration",
    tuple(
        category
        for category in FindingSourceCategory
        if category is not FindingSourceCategory.CUSTOM
    ),
)
def test_custom_source_cannot_declare_a_builtin_report_category(
    declaration: FindingSourceCategory,
) -> None:
    class ImpersonatingSource(FakeVulnerabilitySource):
        def execution_report_finding_source(self) -> FindingSourceCategory:
            return declaration

    with pytest.raises(ValueError, match=r"FindingSourceCategory\.CUSTOM"):
        generate_vex_from_source_result(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            source=ImpersonatingSource(()),
        )


@pytest.mark.parametrize(
    "declaration",
    tuple(
        category
        for category in ExecutionReportOutputFormat
        if category is not ExecutionReportOutputFormat.CUSTOM
    ),
)
def test_custom_renderer_cannot_declare_a_builtin_report_category(
    declaration: ExecutionReportOutputFormat,
) -> None:
    class ImpersonatingRenderer(CustomRenderer):
        def execution_report_output_format(self) -> ExecutionReportOutputFormat:
            return declaration

    with pytest.raises(ValueError, match=r"ExecutionReportOutputFormat\.CUSTOM"):
        generate_vex_from_components_result(
            components=(_component(),),
            source=LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json"),
            timestamp=None,
            renderer=ImpersonatingRenderer(),
        )


def test_custom_source_cannot_use_private_capability_to_claim_builtin_category() -> None:
    class ForgedBuiltinSource(FakeVulnerabilitySource):
        def _vexcalibur_execution_report_finding_source(
            self,
        ) -> FindingSourceCategory:
            return FindingSourceCategory.PUBLIC_OSV

        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

    result = generate_vex_from_source_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        source=ForgedBuiltinSource(()),
    )

    assert result.execution_context is not None
    assert result.execution_context.finding_source is FindingSourceCategory.CUSTOM


def test_custom_renderer_cannot_use_private_capability_to_claim_builtin_format() -> None:
    class ForgedBuiltinRenderer(CustomRenderer):
        def _vexcalibur_execution_report_output_format(
            self,
        ) -> ExecutionReportOutputFormat:
            return ExecutionReportOutputFormat.CSAF

    result = generate_vex_from_components_result(
        components=load_cyclonedx_sbom(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        source=LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json"),
        timestamp=None,
        renderer=ForgedBuiltinRenderer(),
    )

    assert result.execution_context is not None
    assert result.execution_context.output_format is ExecutionReportOutputFormat.CUSTOM


@pytest.mark.parametrize(
    ("context", "message"),
    (
        (
            GenerationExecutionContext(
                inventory_source=InventorySourceCategory.SBOM_FILE,
                finding_source=FindingSourceCategory.CUSTOM,
                output_format=ExecutionReportOutputFormat.CYCLONEDX,
            ),
            "inventory_source contradicts",
        ),
        (
            GenerationExecutionContext(
                inventory_source=InventorySourceCategory.CUSTOM,
                finding_source=FindingSourceCategory.LOCAL_FILE,
                output_format=ExecutionReportOutputFormat.CYCLONEDX,
            ),
            "custom finding_source",
        ),
    ),
)
def test_unclassified_custom_inputs_reject_builtin_explicit_categories(
    context: GenerationExecutionContext,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        generate_vex_from_components_result(
            components=(_component(),),
            source=FakeVulnerabilitySource(()),
            timestamp=None,
            execution_context=context,
        )


def test_unclassified_custom_renderer_rejects_builtin_explicit_category() -> None:
    class UnclassifiedRenderer:
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            return "{}\n"

    context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CSAF,
    )

    with pytest.raises(ValueError, match="custom output_format"):
        generate_vex_from_components_result(
            components=(_component(),),
            source=FakeVulnerabilitySource(()),
            timestamp=None,
            renderer=UnclassifiedRenderer(),
            execution_context=context,
        )
