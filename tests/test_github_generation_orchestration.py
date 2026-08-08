from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from packageurl import PackageURL
from typer.testing import CliRunner

import vexcalibur.api as api
import vexcalibur.generate as generate_module
from vexcalibur import cli
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.generate_command import GenerateCommandRequest
from vexcalibur.generation_result import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    InventorySourceCategory,
)
from vexcalibur.source_options import GenerateSourceOptions
from vexcalibur.sources.local import LocalFindingsError, LocalFindingsSource
from vexcalibur.sources.osv import (
    OsvConfigurationError,
    OsvPackageQuery,
    OsvQueryResult,
    OsvSource,
)

runner = CliRunner()


def _component() -> ComponentIdentity:
    return ComponentIdentity(
        ref="SPDXRef-package",
        name="package",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/package@1.0.0"),
    )


class _RecordingRenderer:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        del components, findings, timestamp
        self._events.append("render")
        return "{}\n"


def _install_github_boundary_recorders(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> None:
    def resolve_token(**kwargs: object) -> None:
        assert kwargs["allow_gh_cli"] is False
        events.append("github-auth")

    class RecordingGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            assert api_url == "https://api.github.com"
            assert token is None
            events.append("github-client")

        def component_identities(self, repository: str) -> tuple[ComponentIdentity, ...]:
            assert repository == "vexcalibur-dev/vexcalibur"
            events.append("github-inventory")
            return (_component(),)

    monkeypatch.setattr(generate_module, "resolve_github_token", resolve_token)
    monkeypatch.setattr(
        generate_module,
        "GithubSbomClient",
        RecordingGithubSbomClient,
    )


@pytest.mark.parametrize(
    ("osv_url", "allow_public_osv"),
    (
        (None, True),
        ("https://osv.internal.example", False),
    ),
)
def test_command_request_osv_modes_use_one_ordered_github_owner(
    monkeypatch: pytest.MonkeyPatch,
    osv_url: str | None,
    allow_public_osv: bool,
) -> None:
    events: list[str] = []
    real_preflight = OsvSource.validate_before_inventory_load

    def record_preflight(source: OsvSource) -> None:
        events.append("source-preflight")
        real_preflight(source)

    class RecordingOsvClient:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url
            events.append("source-client")

        def query_batch_packages(
            self,
            queries: list[OsvPackageQuery],
        ) -> list[OsvQueryResult]:
            assert len(queries) == 1
            events.append("source-query")
            return []

    _install_github_boundary_recorders(monkeypatch, events)
    monkeypatch.setattr(OsvSource, "validate_before_inventory_load", record_preflight)
    monkeypatch.setattr("vexcalibur.sources.osv.OsvClient", RecordingOsvClient)

    request = GenerateCommandRequest(
        input_file=None,
        github_repository="vexcalibur-dev/vexcalibur",
        github_api_url="https://api.github.com",
        github_token_env=None,
        use_gh_auth=False,
        source_options=GenerateSourceOptions(
            findings_file=None,
            offline=False,
            osv_url=osv_url,
            allow_public_osv=allow_public_osv,
        ),
        timestamp=None,
        renderer=_RecordingRenderer(events),
    )

    request.execute()

    assert events == [
        "source-preflight",
        "github-auth",
        "github-client",
        "github-inventory",
        "source-client",
        "source-query",
        "render",
    ]


@pytest.mark.parametrize("source_mode", ("public-osv", "private-osv", "local"))
def test_cli_source_modes_use_one_ordered_github_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_mode: str,
) -> None:
    events: list[str] = []
    real_preflight = OsvSource.validate_before_inventory_load
    real_local_findings = LocalFindingsSource.findings_for_components

    def record_preflight(source: OsvSource) -> None:
        events.append("source-preflight")
        real_preflight(source)

    def record_local_findings(
        source: LocalFindingsSource,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        events.append("local-findings")
        return real_local_findings(source, components)

    class RecordingOsvClient:
        def __init__(self, *, base_url: str) -> None:
            expected_url = (
                "https://api.osv.dev"
                if source_mode == "public-osv"
                else "https://osv.internal.example"
            )
            assert base_url == expected_url
            events.append("source-client")

        def query_batch_packages(
            self,
            queries: list[OsvPackageQuery],
        ) -> list[OsvQueryResult]:
            assert len(queries) == 1
            events.append("source-query")
            return []

    _install_github_boundary_recorders(monkeypatch, events)
    monkeypatch.setattr(OsvSource, "validate_before_inventory_load", record_preflight)
    monkeypatch.setattr(
        LocalFindingsSource,
        "findings_for_components",
        record_local_findings,
    )
    monkeypatch.setattr("vexcalibur.sources.osv.OsvClient", RecordingOsvClient)

    arguments = [
        "generate",
        "--github-repo",
        "vexcalibur-dev/vexcalibur",
        "--no-gh-auth",
    ]
    if source_mode == "public-osv":
        arguments.append("--allow-public-osv")
    elif source_mode == "private-osv":
        arguments.extend(("--osv-url", "https://osv.internal.example"))
    else:
        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}', encoding="utf-8")
        arguments.extend(("--findings-file", str(findings_path)))

    result = runner.invoke(cli.app, arguments)

    assert result.exit_code == 0, result.output
    if source_mode == "local":
        assert events == [
            "github-auth",
            "github-client",
            "github-inventory",
            "local-findings",
        ]
    else:
        assert events == [
            "source-preflight",
            "github-auth",
            "github-client",
            "github-inventory",
            "source-client",
            "source-query",
        ]


def test_supported_api_preflights_injected_source_once_before_github_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class RecordingSource:
        def validate_before_inventory_load(self) -> None:
            events.append("source-preflight")

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            assert components == (_component(),)
            events.append("source-query")
            return ()

    _install_github_boundary_recorders(monkeypatch, events)

    api.generate_vex_from_github_source_result(
        repository="vexcalibur-dev/vexcalibur",
        source=RecordingSource(),
        use_gh_auth=False,
        renderer=_RecordingRenderer(events),
    )

    assert events == [
        "source-preflight",
        "github-auth",
        "github-client",
        "github-inventory",
        "source-query",
        "render",
    ]


@pytest.mark.parametrize(
    "helper_name",
    ("generate_vex_from_github_sbom", "generate_vex_from_github_sbom_result"),
)
@pytest.mark.parametrize(
    ("osv_url", "allow_public_osv"),
    (
        ("https://api.osv.dev", True),
        ("https://osv.internal.example", False),
    ),
)
def test_supported_osv_api_helpers_preflight_once_before_github_io(
    monkeypatch: pytest.MonkeyPatch,
    helper_name: str,
    osv_url: str,
    allow_public_osv: bool,
) -> None:
    events: list[str] = []
    real_preflight = OsvSource.validate_before_inventory_load

    def record_preflight(source: OsvSource) -> None:
        events.append("source-preflight")
        real_preflight(source)

    class RecordingOsvClient:
        def __init__(self, *, base_url: str) -> None:
            assert base_url == osv_url
            events.append("source-client")

        def query_batch_packages(
            self,
            queries: list[OsvPackageQuery],
        ) -> list[OsvQueryResult]:
            assert len(queries) == 1
            events.append("source-query")
            return []

    _install_github_boundary_recorders(monkeypatch, events)
    monkeypatch.setattr(OsvSource, "validate_before_inventory_load", record_preflight)
    monkeypatch.setattr("vexcalibur.sources.osv.OsvClient", RecordingOsvClient)

    helper = getattr(api, helper_name)
    helper(
        repository="vexcalibur-dev/vexcalibur",
        use_gh_auth=False,
        osv_base_url=osv_url,
        allow_public_osv=allow_public_osv,
        renderer=_RecordingRenderer(events),
    )

    assert events == [
        "source-preflight",
        "github-auth",
        "github-client",
        "github-inventory",
        "source-client",
        "source-query",
        "render",
    ]


@pytest.mark.parametrize(
    "helper_name",
    ("generate_vex_from_github_sbom", "generate_vex_from_github_sbom_result"),
)
def test_supported_osv_api_helpers_reject_invalid_private_url_before_github_io(
    monkeypatch: pytest.MonkeyPatch,
    helper_name: str,
) -> None:
    events: list[str] = []
    real_preflight = OsvSource.validate_before_inventory_load

    def record_preflight(source: OsvSource) -> None:
        events.append("source-preflight")
        real_preflight(source)

    _install_github_boundary_recorders(monkeypatch, events)
    monkeypatch.setattr(OsvSource, "validate_before_inventory_load", record_preflight)
    helper = getattr(api, helper_name)

    with pytest.raises(OsvConfigurationError, match="port is invalid"):
        helper(
            repository="vexcalibur-dev/vexcalibur",
            use_gh_auth=False,
            osv_base_url="https://osv.internal.example:bad",
        )

    assert events == ["source-preflight"]


def test_supported_api_validates_context_before_github_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class RecordingSource:
        def validate_before_inventory_load(self) -> None:
            events.append("source-preflight")

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            raise AssertionError(components)

    _install_github_boundary_recorders(monkeypatch, events)
    invalid_context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )

    with pytest.raises(ValueError, match="inventory_source contradicts"):
        api.generate_vex_from_github_source_result(
            repository="vexcalibur-dev/vexcalibur",
            source=RecordingSource(),
            use_gh_auth=False,
            renderer=_RecordingRenderer(events),
            execution_context=invalid_context,
        )

    assert events == ["source-preflight"]


def test_local_findings_validation_follows_github_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        '{"findings": [{"id": "CVE-2026-0001", "component_ref": "SPDXRef-missing"}]}',
        encoding="utf-8",
    )
    real_findings = LocalFindingsSource.findings_for_components

    def record_findings(
        source: LocalFindingsSource,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        events.append("local-findings")
        return real_findings(source, components)

    _install_github_boundary_recorders(monkeypatch, events)
    monkeypatch.setattr(LocalFindingsSource, "findings_for_components", record_findings)
    request = GenerateCommandRequest(
        input_file=None,
        github_repository="vexcalibur-dev/vexcalibur",
        github_api_url="https://api.github.com",
        github_token_env=None,
        use_gh_auth=False,
        source_options=GenerateSourceOptions(
            findings_file=findings_path,
            offline=False,
            osv_url=None,
            allow_public_osv=False,
        ),
        timestamp=None,
        renderer=_RecordingRenderer(events),
    )

    with pytest.raises(LocalFindingsError, match="unknown component_ref"):
        request.execute()

    assert events == [
        "github-auth",
        "github-client",
        "github-inventory",
        "local-findings",
    ]


@pytest.mark.parametrize("failure_stage", ("source", "renderer"))
def test_supported_api_preserves_custom_exception_identity(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    events: list[str] = []
    failure = RuntimeError(f"{failure_stage} failed")

    class FailingSource:
        def validate_before_inventory_load(self) -> None:
            events.append("source-preflight")

        def findings_for_components(
            self,
            components: tuple[ComponentIdentity, ...],
        ) -> tuple[VulnerabilityFinding, ...]:
            assert components == (_component(),)
            events.append("source-query")
            if failure_stage == "source":
                raise failure
            return ()

    class FailingRenderer(_RecordingRenderer):
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            if failure_stage == "renderer":
                events.append("render")
                raise failure
            return super().render(
                components=components,
                findings=findings,
                timestamp=timestamp,
            )

    _install_github_boundary_recorders(monkeypatch, events)

    with pytest.raises(RuntimeError) as captured:
        api.generate_vex_from_github_source_result(
            repository="vexcalibur-dev/vexcalibur",
            source=FailingSource(),
            use_gh_auth=False,
            renderer=FailingRenderer(events),
        )

    assert captured.value is failure
    expected = [
        "source-preflight",
        "github-auth",
        "github-client",
        "github-inventory",
        "source-query",
    ]
    if failure_stage == "renderer":
        expected.append("render")
    assert events == expected


def test_legacy_github_api_preserves_custom_renderer_exception_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    failure = RuntimeError("renderer failed")
    real_preflight = OsvSource.validate_before_inventory_load

    def record_preflight(source: OsvSource) -> None:
        events.append("source-preflight")
        real_preflight(source)

    class RecordingOsvClient:
        def __init__(self, *, base_url: str) -> None:
            assert base_url == "https://api.osv.dev"
            events.append("source-client")

        def query_batch_packages(
            self,
            queries: list[OsvPackageQuery],
        ) -> list[OsvQueryResult]:
            assert len(queries) == 1
            events.append("source-query")
            return []

    class FailingRenderer(_RecordingRenderer):
        def render(
            self,
            *,
            components: tuple[ComponentIdentity, ...],
            findings: tuple[VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            del components, findings, timestamp
            events.append("render")
            raise failure

    _install_github_boundary_recorders(monkeypatch, events)
    monkeypatch.setattr(OsvSource, "validate_before_inventory_load", record_preflight)
    monkeypatch.setattr("vexcalibur.sources.osv.OsvClient", RecordingOsvClient)

    with pytest.raises(RuntimeError) as captured:
        api.generate_vex_from_github_sbom(
            repository="vexcalibur-dev/vexcalibur",
            use_gh_auth=False,
            allow_public_osv=True,
            renderer=FailingRenderer(events),
        )

    assert captured.value is failure
    assert events == [
        "source-preflight",
        "github-auth",
        "github-client",
        "github-inventory",
        "source-client",
        "source-query",
        "render",
    ]
