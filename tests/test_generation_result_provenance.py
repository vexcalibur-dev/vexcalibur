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
    VulnerabilityFinding,
)
from vexcalibur.generate import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
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
from vexcalibur.generation_selection import select_finding_source
from vexcalibur.github_sbom import GithubSbomClient
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    OsvClient,
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


def test_convenience_result_helpers_accept_custom_execution_context() -> None:
    sbom_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )
    local_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )
    github_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM,
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
        finding_source=FindingSourceCategory.CUSTOM,
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
        ("https://api.osv.dev", True, FindingSourceCategory.CUSTOM),
        (
            "https://osv.internal.example",
            False,
            FindingSourceCategory.CUSTOM,
        ),
        (
            "https://api.osv.dev/path",
            True,
            FindingSourceCategory.CUSTOM,
        ),
        (
            "https://api.osv.dev:8443",
            True,
            FindingSourceCategory.CUSTOM,
        ),
    ),
)
def test_sbom_generation_result_reserves_builtin_categories_from_custom_clients(
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
    ("osv_base_url", "expected_finding_source"),
    (
        ("https://api.osv.dev", FindingSourceCategory.PUBLIC_OSV),
        ("https://osv.internal.example", FindingSourceCategory.CUSTOM_OSV),
    ),
)
def test_exact_builtin_osv_source_retains_endpoint_category(
    osv_base_url: str,
    expected_finding_source: FindingSourceCategory,
) -> None:
    selection = select_finding_source(OsvSource(osv_base_url=osv_base_url))

    assert selection.report_category is expected_finding_source


@pytest.mark.parametrize(
    "client_url",
    (
        "https://api.osv.dev",
        "https://osv.internal.example",
    ),
)
def test_injected_exact_osv_client_is_always_custom(client_url: str) -> None:
    selection = select_finding_source(
        OsvSource(
            client=OsvClient(base_url=client_url),
            osv_base_url=client_url,
            allow_public_osv=client_url == "https://api.osv.dev",
        )
    )

    assert selection.report_category is FindingSourceCategory.CUSTOM


@pytest.mark.parametrize(
    ("client_url", "configured_url", "allow_public_osv", "expected_finding_source"),
    (
        (
            "https://api.osv.dev",
            "https://osv.internal.example",
            True,
            FindingSourceCategory.CUSTOM,
        ),
        (
            "https://osv.internal.example",
            "https://api.osv.dev",
            False,
            FindingSourceCategory.CUSTOM,
        ),
    ),
)
def test_injected_client_url_cannot_claim_a_builtin_source_category(
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
        ("https://api.osv.dev", True, FindingSourceCategory.CUSTOM),
        (
            "https://osv.internal.example",
            False,
            FindingSourceCategory.CUSTOM,
        ),
    ),
)
def test_github_generation_reserves_builtin_categories_from_custom_clients(
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
        inventory_source=InventorySourceCategory.CUSTOM,
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
        inventory_source=InventorySourceCategory.CUSTOM,
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
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )


def test_builtin_github_client_retains_github_inventory_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptySource:
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            return ()

    expected_components = FakeGithubSbomClient().component_identities("vexcalibur-dev/vexcalibur")
    monkeypatch.setattr(
        GithubSbomClient,
        "component_identities",
        lambda self, repository: expected_components,
    )

    result = generate_vex_from_github_source_result(
        repository="vexcalibur-dev/vexcalibur",
        source=EmptySource(),
    )

    assert result.execution_context is not None
    assert (
        result.execution_context.inventory_source is InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH
    )
