from __future__ import annotations

import json
from datetime import datetime, timedelta, tzinfo
from pathlib import Path
from typing import Literal

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
)
from vexcalibur.generate import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
    generate_vex_from_components_result,
)
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

    first_purl = result.components[0].purl
    assert type(first_purl) is PackageURL
    assert type(first_purl.qualifiers) is dict
    assert first_purl is not component.purl
    assert first_purl.qualifiers is not component.purl.qualifiers
    assert first_purl.qualifiers == {"repository_url": "https://packages.example.test/simple"}
    first_purl.qualifiers["repository_url"] = "https://changed-again.example.test"

    retained_purl = result.components[0].purl
    assert retained_purl is not first_purl
    assert retained_purl.qualifiers == {"repository_url": "https://packages.example.test/simple"}
    assert retained_purl.to_string() == (
        "pkg:pypi/demo@1.0.0?repository_url=https://packages.example.test/simple"
    )
    assert retained_purl.to_dict()["qualifiers"] == {
        "repository_url": "https://packages.example.test/simple"
    }


def test_direct_generation_result_snapshots_package_url_qualifiers() -> None:
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
    result = GenerationResult("{}\n", (component,), ())
    original_hash = hash(result)

    component.purl.qualifiers["repository_url"] = "https://changed.example.test"
    returned = result.components[0]
    returned.purl.qualifiers["repository_url"] = "https://changed-again.example.test"

    expected_component = ComponentIdentity(
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
    assert result.components == (expected_component,)
    assert hash(result) == original_hash
    assert result == GenerationResult("{}\n", (expected_component,), ())


def test_result_extensions_receive_independent_ordinary_package_urls() -> None:
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
    source_component: ComponentIdentity | None = None
    renderer_component: ComponentIdentity | None = None

    class MutatingSource:
        def execution_report_finding_source(
            self,
        ) -> Literal[FindingSourceCategory.CUSTOM]:
            return FindingSourceCategory.CUSTOM

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            nonlocal source_component
            source_component = components[0]
            assert type(source_component.purl) is PackageURL
            assert type(source_component.purl.qualifiers) is dict
            json.dumps(source_component.purl.qualifiers)
            source_component.purl.qualifiers["source_mutation"] = "discarded"
            return ()

    class MutatingRenderer:
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
            del findings, timestamp
            nonlocal renderer_component
            renderer_component = components[0]
            assert type(renderer_component.purl) is PackageURL
            assert type(renderer_component.purl.qualifiers) is dict
            assert "source_mutation" not in renderer_component.purl.qualifiers
            json.dumps(renderer_component.purl.qualifiers)
            renderer_component.purl.qualifiers["renderer_mutation"] = "discarded"
            return "{}\n"

    result = generate_vex_from_components_result(
        components=(component,),
        source=MutatingSource(),
        timestamp=None,
        renderer=MutatingRenderer(),
    )

    assert source_component is not None
    assert renderer_component is not None
    assert source_component is not renderer_component
    assert component.purl.qualifiers == {"repository_url": "https://packages.example.test/simple"}
    assert result.components[0].purl.qualifiers == {
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

    assert rendered_states == [VexAnalysisState.EXPLOITABLE]
    assert result.execution_report().analysis_state_counts == ((VexAnalysisState.EXPLOITABLE, 1),)


def test_renderer_mutation_cannot_change_retained_findings() -> None:
    component = _component()
    finding = VulnerabilityFinding(
        id="PRIVATE-2026-0001",
        source_name="Private source",
        source_url="https://security.example.test/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
        analysis_state=VexAnalysisState.EXPLOITABLE,
    )

    class MutatingRenderer(CustomRenderer):
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            object.__setattr__(findings[0], "analysis_state", VexAnalysisState.RESOLVED)
            return super().render(
                components=components,
                findings=findings,
                timestamp=timestamp,
            )

    result = generate_vex_from_components_result(
        components=(component,),
        source=FakeVulnerabilitySource((finding,)),
        timestamp=None,
        renderer=MutatingRenderer(),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.CUSTOM,
            finding_source=FindingSourceCategory.CUSTOM,
            output_format=ExecutionReportOutputFormat.CUSTOM,
        ),
    )

    assert result.findings[0].analysis_state is VexAnalysisState.EXPLOITABLE
    assert result.execution_report().analysis_state_counts == ((VexAnalysisState.EXPLOITABLE, 1),)


def test_generation_result_materializes_independent_finding_snapshots() -> None:
    component = _component()
    original = VulnerabilityFinding(
        id="PRIVATE-2026-0001",
        source_name="Private source",
        source_url="https://security.example.test/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
        analysis_state=VexAnalysisState.EXPLOITABLE,
    )
    result = GenerationResult("{}\n", (component,), (original,))

    object.__setattr__(original, "analysis_state", VexAnalysisState.RESOLVED)
    first = result.findings
    object.__setattr__(first[0], "analysis_state", VexAnalysisState.FALSE_POSITIVE)
    second = result.findings

    assert first is not second
    assert first[0] is not second[0]
    assert second[0].analysis_state is VexAnalysisState.EXPLOITABLE


def test_generation_result_snapshots_mutable_timezone_state() -> None:
    class MutableTimezone(tzinfo):
        offset = timedelta(0)

        def utcoffset(self, value: datetime | None) -> timedelta:
            return self.offset

        def dst(self, value: datetime | None) -> timedelta:
            return timedelta(0)

    mutable_timezone = MutableTimezone()
    modified = datetime(2026, 7, 30, 1, 2, 3, tzinfo=mutable_timezone)
    component = _component()
    finding = VulnerabilityFinding(
        id="PRIVATE-2026-0001",
        source_name="Private source",
        source_url="https://security.example.test/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
        modified=modified,
    )

    result = GenerationResult("{}\n", (component,), (finding,))
    mutable_timezone.offset = timedelta(hours=9)

    retained = result.findings[0].modified
    assert retained is not None
    assert retained.tzinfo is not mutable_timezone
    assert retained.utcoffset() == timedelta(0)
