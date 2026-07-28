from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal, get_args, get_origin, get_type_hints

import pytest
from packageurl import PackageURL

from vexcalibur.csaf import (
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafPublisherCategory,
)
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VulnerabilityFinding,
    VulnerabilitySourceInputError,
)
from vexcalibur.errors import VexRenderError
from vexcalibur.generate import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
    generate_vex_from_components,
    generate_vex_from_components_result,
    generate_vex_from_github_sbom_result,
    generate_vex_from_github_source_result,
    generate_vex_from_local_findings_result,
    generate_vex_from_sbom_result,
    generate_vex_from_source_result,
)
from vexcalibur.generation_result import (
    ExecutionReportFindingSourceDeclaration,
    ExecutionReportOutputFormatDeclaration,
)
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    OsvPackageQuery,
    OsvQueryResult,
    OsvSource,
)
from vexcalibur.vex import CycloneDxJsonRenderer, parse_timestamp

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
        def findings_for_components(
            self,
            supplied_components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            assert supplied_components is components
            assert supplied_components[0] is component
            assert supplied_components[0].extension_state == "component-state"
            return findings

    class PreservingRenderer:
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


def test_generation_snapshots_extension_inputs_as_exact_tuples() -> None:
    class ComponentSubclass(ComponentIdentity):
        pass

    component = ComponentSubclass(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    finding = VulnerabilityFinding(
        id="PRIVATE-2026-0001",
        source_name="Private source",
        source_url="https://security.example.test/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
    )

    class HostileTuple(tuple):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            yield from super().__iter__()
            if self.iterations > 1:
                yield self[0]

    raw_components = HostileTuple((component,))
    raw_findings = HostileTuple((finding,))

    class HostileSource:
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            assert type(components) is tuple
            assert type(components[0]) is ComponentIdentity
            return raw_findings

    class SnapshotRenderer:
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
            assert type(components) is tuple
            assert type(findings) is tuple
            return "{}\n"

    result = generate_vex_from_components_result(
        components=raw_components,
        source=HostileSource(),
        timestamp=None,
        renderer=SnapshotRenderer(),
    )

    assert type(result.components) is tuple
    assert type(result.components[0]) is ComponentIdentity
    assert type(result.findings) is tuple
    assert result.components == (_component(),)
    assert result.findings == (finding,)


def test_generation_snapshots_package_url_qualifiers() -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL(
            type="pypi",
            namespace=None,
            name="demo",
            version="1.0.0",
            qualifiers={"repository_url": "https://packages.example.test/simple"},
            subpath=None,
        ),
    )

    result = generate_vex_from_components_result(
        components=(component,),
        source=FakeVulnerabilitySource(()),
        timestamp=None,
    )
    component.purl.qualifiers["repository_url"] = "https://changed.example.test"

    retained_purl = result.components[0].purl
    assert retained_purl is not component.purl
    assert retained_purl.qualifiers is not component.purl.qualifiers
    assert retained_purl.qualifiers == {"repository_url": "https://packages.example.test/simple"}
    with pytest.raises(TypeError):
        retained_purl.qualifiers["repository_url"] = "https://changed-again.example.test"
    for method, arguments in (
        ("__delitem__", ("repository_url",)),
        ("clear", ()),
        ("pop", ("repository_url",)),
        ("popitem", ()),
        ("setdefault", ("arch", "x86_64")),
        ("update", ({"arch": "x86_64"},)),
        ("__ior__", ({"arch": "x86_64"},)),
    ):
        with pytest.raises((AttributeError, TypeError)):
            getattr(retained_purl.qualifiers, method)(*arguments)
    with pytest.raises(TypeError):
        dict.__setitem__(
            retained_purl.qualifiers,
            "repository_url",
            "https://changed-through-descriptor.example.test",
        )
    assert retained_purl.qualifiers == {"repository_url": "https://packages.example.test/simple"}
    assert retained_purl.to_string() == (
        "pkg:pypi/demo@1.0.0?repository_url=https://packages.example.test/simple"
    )
    assert retained_purl.to_dict()["qualifiers"] == {
        "repository_url": "https://packages.example.test/simple"
    }


def test_generation_snapshots_stateful_findings_before_rendering() -> None:
    class StatefulFinding(VulnerabilityFinding):
        def __getattribute__(self, name: str) -> object:
            if name == "analysis_state":
                reads = object.__getattribute__(self, "_analysis_state_reads")
                object.__setattr__(self, "_analysis_state_reads", reads + 1)
                if reads == 0:
                    return VexAnalysisState.EXPLOITABLE
                return VexAnalysisState.RESOLVED
            return super().__getattribute__(name)

    class StatefulSource:
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            component = components[0]
            finding = StatefulFinding(
                id="PRIVATE-2026-0001",
                source_name="Private source",
                source_url="https://security.example.test/PRIVATE-2026-0001",
                component_ref=component.ref,
                purl=component.purl.to_string(),
            )
            object.__setattr__(finding, "_analysis_state_reads", 0)
            return (finding,)

    rendered_states: list[VexAnalysisState] = []

    class RecordingRenderer:
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
            assert type(findings[0]) is VulnerabilityFinding
            rendered_states.append(findings[0].analysis_state)
            return "{}\n"

    result = generate_vex_from_components_result(
        components=(_component(),),
        source=StatefulSource(),
        timestamp=None,
        renderer=RecordingRenderer(),
    )
    object.__setattr__(result, "_vexcalibur_version", "0.5.0")

    assert rendered_states == [VexAnalysisState.EXPLOITABLE]
    assert result.execution_report().analysis_state_counts == ((VexAnalysisState.EXPLOITABLE, 1),)


def test_convenience_result_helpers_accept_custom_execution_context() -> None:
    sbom_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.CUSTOM_OSV,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )
    local_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )
    github_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
        finding_source=FindingSourceCategory.CUSTOM_OSV,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )

    sbom_result = generate_vex_from_sbom_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        osv_client=FakeOsvClient(),
        osv_base_url="https://osv.internal.example",
        renderer=CustomRenderer(),
        execution_context=sbom_context,
    )
    local_result = generate_vex_from_local_findings_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        findings_file=FINDINGS_ROOT / "all-analysis-states.json",
        renderer=CustomRenderer(),
        execution_context=local_context,
    )
    github_result = generate_vex_from_github_sbom_result(
        repository="vexcalibur-dev/vexcalibur",
        github_client=FakeGithubSbomClient(),
        osv_client=FakeOsvClient(),
        osv_base_url="https://osv.internal.example",
        renderer=CustomRenderer(),
        execution_context=github_context,
    )

    assert sbom_result.execution_context is sbom_context
    assert local_result.execution_context is local_context
    assert github_result.execution_context is github_context


def test_known_generation_facts_reject_false_execution_context() -> None:
    false_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
        finding_source=FindingSourceCategory.PUBLIC_OSV,
        output_format=ExecutionReportOutputFormat.CSAF,
    )

    with pytest.raises(ValueError, match="inventory_source contradicts"):
        generate_vex_from_source_result(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            source=LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json"),
            execution_context=false_context,
        )


def test_known_source_and_renderer_reject_false_execution_context() -> None:
    false_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.PUBLIC_OSV,
        output_format=ExecutionReportOutputFormat.OPENVEX,
    )

    with pytest.raises(ValueError, match="finding_source contradicts"):
        generate_vex_from_components_result(
            components=(_component(),),
            source=LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json"),
            timestamp=None,
            execution_context=false_context,
        )


def test_known_renderer_rejects_false_output_format_context() -> None:
    false_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.OPENVEX,
    )

    with pytest.raises(ValueError, match="output_format contradicts"):
        generate_vex_from_components_result(
            components=(_component(),),
            source=LocalFindingsSource(path=FINDINGS_ROOT / "all-analysis-states.json"),
            timestamp=None,
            execution_context=false_context,
        )


def test_builtin_source_subclass_does_not_inherit_report_category() -> None:
    class CustomOsvSource(OsvSource):
        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            return ()

    result = generate_vex_from_components_result(
        components=(_component(),),
        source=CustomOsvSource(
            osv_base_url="https://osv.internal.example",
            allow_public_osv=False,
        ),
        timestamp=None,
    )

    assert result.execution_context is None
    with pytest.raises(ValueError, match="context is unavailable"):
        result.execution_report()


def test_builtin_renderer_subclass_does_not_inherit_report_category() -> None:
    class CustomCycloneDxRenderer(CycloneDxJsonRenderer):
        pass

    result = generate_vex_from_components_result(
        components=(_component(),),
        source=OsvSource(
            client=FakeOsvClient(),
            osv_base_url="https://osv.internal.example",
            allow_public_osv=False,
        ),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        renderer=CustomCycloneDxRenderer(),
    )

    assert result.execution_context is None
    with pytest.raises(ValueError, match="context is unavailable"):
        result.execution_report()


def test_builtin_renderer_subclass_can_declare_custom_report_category() -> None:
    class CustomCycloneDxRenderer(CycloneDxJsonRenderer):
        def execution_report_output_format(
            self,
        ) -> Literal[ExecutionReportOutputFormat.CUSTOM]:
            return ExecutionReportOutputFormat.CUSTOM

    result = generate_vex_from_components_result(
        components=(_component(),),
        source=OsvSource(
            client=FakeOsvClient(),
            osv_base_url="https://osv.internal.example",
            allow_public_osv=False,
        ),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        renderer=CustomCycloneDxRenderer(),
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM_OSV,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )


def test_execution_report_annotation_resolves_at_runtime() -> None:
    hints = get_type_hints(GenerationResult.execution_report)

    assert hints["return"].__name__ == "GenerationExecutionReport"


@pytest.mark.parametrize(
    ("protocol", "field", "custom_value"),
    (
        (
            ExecutionReportFindingSourceDeclaration,
            "execution_report_finding_source",
            FindingSourceCategory.CUSTOM,
        ),
        (
            ExecutionReportOutputFormatDeclaration,
            "execution_report_output_format",
            ExecutionReportOutputFormat.CUSTOM,
        ),
    ),
)
def test_extension_protocols_only_accept_custom_categories(
    protocol: type[object],
    field: str,
    custom_value: object,
) -> None:
    annotation = get_type_hints(getattr(protocol, field))["return"]

    assert get_origin(annotation) is Literal
    assert get_args(annotation) == (custom_value,)


@pytest.mark.parametrize(
    ("renderer", "expected_format"),
    (
        (None, ExecutionReportOutputFormat.CYCLONEDX),
        (
            OpenVexJsonRenderer(
                author="Vexcalibur Test Maintainers",
                role="Document producer",
            ),
            ExecutionReportOutputFormat.OPENVEX,
        ),
        (_csaf_renderer(), ExecutionReportOutputFormat.CSAF),
    ),
)
def test_local_generation_result_retains_actual_execution_context(
    renderer,
    expected_format: ExecutionReportOutputFormat,
) -> None:
    result = generate_vex_from_local_findings_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        findings_file=FINDINGS_ROOT / "all-analysis-states.json",
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        renderer=renderer,
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=expected_format,
    )
    assert len(result.components) == 2
    assert len(result.findings) == 5
    assert result.rendered_bytes == result.rendered_document.encode("utf-8")
    assert result.rendered_bytes is result.rendered_bytes


@pytest.mark.parametrize(
    ("osv_base_url", "allow_public_osv", "expected_finding_source"),
    (
        ("https://api.osv.dev", True, FindingSourceCategory.PUBLIC_OSV),
        (
            "https://osv.internal.example",
            False,
            FindingSourceCategory.CUSTOM_OSV,
        ),
        (
            "https://api.osv.dev/path",
            True,
            FindingSourceCategory.CUSTOM_OSV,
        ),
        (
            "https://api.osv.dev:8443",
            True,
            FindingSourceCategory.CUSTOM_OSV,
        ),
    ),
)
def test_sbom_generation_result_retains_actual_source_categories(
    osv_base_url: str,
    allow_public_osv: bool,
    expected_finding_source: FindingSourceCategory,
) -> None:
    result = generate_vex_from_sbom_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        osv_client=FakeOsvClient(),
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=expected_finding_source,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )


@pytest.mark.parametrize(
    ("client_url", "configured_url", "allow_public_osv", "expected_finding_source"),
    (
        (
            "https://api.osv.dev",
            "https://osv.internal.example",
            True,
            FindingSourceCategory.PUBLIC_OSV,
        ),
        (
            "https://osv.internal.example",
            "https://api.osv.dev",
            False,
            FindingSourceCategory.CUSTOM_OSV,
        ),
    ),
)
def test_generation_result_uses_injected_client_url_for_source_category(
    client_url: str,
    configured_url: str,
    allow_public_osv: bool,
    expected_finding_source: FindingSourceCategory,
) -> None:
    result = generate_vex_from_sbom_result(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        osv_client=FakeOsvClient(base_url=client_url),
        osv_base_url=configured_url,
        allow_public_osv=allow_public_osv,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert result.execution_context is not None
    assert result.execution_context.finding_source is expected_finding_source


@pytest.mark.parametrize(
    ("osv_base_url", "allow_public_osv", "expected_finding_source"),
    (
        ("https://api.osv.dev", True, FindingSourceCategory.PUBLIC_OSV),
        (
            "https://osv.internal.example",
            False,
            FindingSourceCategory.CUSTOM_OSV,
        ),
    ),
)
def test_github_generation_result_retains_actual_source_categories(
    osv_base_url: str,
    allow_public_osv: bool,
    expected_finding_source: FindingSourceCategory,
) -> None:
    result = generate_vex_from_github_sbom_result(
        repository="vexcalibur-dev/vexcalibur",
        github_client=FakeGithubSbomClient(),
        osv_client=FakeOsvClient(),
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
        finding_source=expected_finding_source,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )


def test_github_source_validates_osv_configuration_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations: list[OsvSource] = []
    real_validate = OsvSource.validate_configuration

    def observe_validation(source: OsvSource) -> None:
        validations.append(source)
        real_validate(source)

    monkeypatch.setattr(OsvSource, "validate_configuration", observe_validation)
    source = OsvSource(
        client=FakeOsvClient(),
        osv_base_url="https://osv.internal.example",
    )

    generate_vex_from_github_source_result(
        repository="vexcalibur-dev/vexcalibur",
        github_client=FakeGithubSbomClient(),
        source=source,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert validations == [source]


def test_github_source_does_not_apply_builtin_osv_policy_to_subclass() -> None:
    class CustomOsvSource(OsvSource):
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

        def validate_configuration(self) -> None:
            raise AssertionError("custom OSV subclass must own its preflight policy")

    source = CustomOsvSource(
        client=FakeOsvClient(),
        osv_base_url="https://osv.internal.example",
    )
    result = generate_vex_from_github_source_result(
        repository="vexcalibur-dev/vexcalibur",
        github_client=FakeGithubSbomClient(),
        source=source,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )


def test_github_source_validates_extension_declaration_before_loading_inventory() -> None:
    loads: list[str] = []

    class InvalidDeclaredSource(FakeVulnerabilitySource):
        def execution_report_finding_source(self) -> FindingSourceCategory:
            return FindingSourceCategory.LOCAL_FILE

    class RecordingGithubSbomClient:
        def component_identities(self, repository: str) -> tuple[ComponentIdentity, ...]:
            loads.append(repository)
            return ()

    with pytest.raises(ValueError, match=r"FindingSourceCategory\.CUSTOM"):
        generate_vex_from_github_source_result(
            repository="vexcalibur-dev/vexcalibur",
            github_client=RecordingGithubSbomClient(),
            source=InvalidDeclaredSource(()),
        )

    assert loads == []


def test_github_source_validates_context_before_loading_inventory() -> None:
    loads: list[str] = []

    class RecordingGithubSbomClient:
        def component_identities(self, repository: str) -> tuple[ComponentIdentity, ...]:
            loads.append(repository)
            return ()

    context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )
    with pytest.raises(ValueError, match="inventory_source contradicts"):
        generate_vex_from_github_source_result(
            repository="vexcalibur-dev/vexcalibur",
            github_client=RecordingGithubSbomClient(),
            source=FakeVulnerabilitySource(()),
            execution_context=context,
        )

    assert loads == []


def test_github_source_result_retains_github_and_local_source_categories(
    tmp_path: Path,
) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "purl": "pkg:pypi/django@1.2"
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    result = generate_vex_from_github_source_result(
        repository="vexcalibur-dev/vexcalibur",
        github_client=FakeGithubSbomClient(),
        source=LocalFindingsSource(findings_path),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert result.execution_context == GenerationExecutionContext(
        inventory_source=InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )
