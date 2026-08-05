"""Contract tests for the supported Python API facade."""

import json
import runpy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from packageurl import PackageURL

import vexcalibur.api as api

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED_PUBLIC_EXPORTS = (
    "EXECUTION_REPORT_SCHEMA_VERSION",
    "ComponentIdentity",
    "ComponentVersionError",
    "Csaf20DocumentMetadata",
    "Csaf20VexJsonRenderer",
    "CsafDocumentStatus",
    "CsafPublisherCategory",
    "CsafRenderError",
    "CycloneDxJsonRenderer",
    "ExecutionReportOutputFormat",
    "FindingSourceCategory",
    "GeneratedDocumentMetadata",
    "GeneratedDocumentMetadataDict",
    "GenerationExecutionContext",
    "GenerationExecutionReport",
    "GenerationExecutionReportDict",
    "GenerationExecutionReportParseError",
    "GenerationReportMetadataError",
    "GenerationResult",
    "GenerationSourcePreflight",
    "GithubSbomClientError",
    "GithubSbomConfigurationError",
    "GithubSbomError",
    "InventorySourceCategory",
    "LocalFindingsError",
    "OpenVexJsonRenderer",
    "OpenVexRenderError",
    "OsvClientError",
    "OsvConfigurationError",
    "OsvResponseError",
    "SbomError",
    "VexAnalysisState",
    "VexRemediationCategory",
    "VexRenderError",
    "VexRenderer",
    "VulnerabilityFinding",
    "VulnerabilitySource",
    "VulnerabilitySourceError",
    "VulnerabilitySourceInputError",
    "generate_vex_from_components",
    "generate_vex_from_components_result",
    "generate_vex_from_github_sbom",
    "generate_vex_from_github_sbom_result",
    "generate_vex_from_github_source_result",
    "generate_vex_from_local_findings",
    "generate_vex_from_local_findings_result",
    "generate_vex_from_sbom",
    "generate_vex_from_sbom_result",
    "generate_vex_from_source",
    "generate_vex_from_source_result",
    "load_cyclonedx_sbom",
    "parse_generation_execution_report",
)


def test_public_api_exports_only_declared_names() -> None:
    assert tuple(api.__all__) == EXPECTED_PUBLIC_EXPORTS
    assert len(api.__all__) == len(set(api.__all__))
    for name in api.__all__:
        assert getattr(api, name) is not None


def test_public_api_pins_enum_names_and_values() -> None:
    assert {member.name: member.value for member in api.VexAnalysisState} == {
        "RESOLVED": "resolved",
        "EXPLOITABLE": "exploitable",
        "IN_TRIAGE": "in_triage",
        "FALSE_POSITIVE": "false_positive",
        "NOT_AFFECTED": "not_affected",
    }
    assert {member.name: member.value for member in api.VexRemediationCategory} == {
        "MITIGATION": "mitigation",
        "NO_FIX_PLANNED": "no_fix_planned",
        "NONE_AVAILABLE": "none_available",
        "VENDOR_FIX": "vendor_fix",
        "WORKAROUND": "workaround",
    }
    assert {member.name: member.value for member in api.CsafDocumentStatus} == {
        "DRAFT": "draft",
        "FINAL": "final",
        "INTERIM": "interim",
    }
    assert {member.name: member.value for member in api.CsafPublisherCategory} == {
        "COORDINATOR": "coordinator",
        "DISCOVERER": "discoverer",
        "OTHER": "other",
        "USER": "user",
        "VENDOR": "vendor",
    }
    assert {member.name: member.value for member in api.InventorySourceCategory} == {
        "SBOM_FILE": "sbom_file",
        "GITHUB_DEPENDENCY_GRAPH": "github_dependency_graph",
        "CUSTOM": "custom",
    }
    assert {member.name: member.value for member in api.FindingSourceCategory} == {
        "LOCAL_FILE": "local_file",
        "PUBLIC_OSV": "public_osv",
        "CUSTOM_OSV": "custom_osv",
        "CUSTOM": "custom",
    }
    assert {member.name: member.value for member in api.ExecutionReportOutputFormat} == {
        "CYCLONEDX": "cyclonedx",
        "OPENVEX": "openvex",
        "CSAF": "csaf",
        "CUSTOM": "custom",
    }


def test_public_api_requires_consent_before_querying_public_osv() -> None:
    assert "OsvClient" not in api.__all__
    assert "OsvSource" not in api.__all__

    with pytest.raises(api.OsvConfigurationError, match="explicit opt-in"):
        api.generate_vex_from_sbom(
            input_file=FIXTURES / "sbom" / "cyclonedx-json-simple.json",
        )


def test_public_api_normalizes_credential_configuration_errors(monkeypatch) -> None:
    with pytest.raises(api.OsvConfigurationError, match="OSV header values"):
        api.generate_vex_from_sbom(
            input_file=FIXTURES / "sbom" / "cyclonedx-json-simple.json",
            osv_base_url="https://osv.example.test",
            osv_headers={"X-Label": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"},
        )

    monkeypatch.setenv("VEXCALIBUR_TEST_GITHUB_TOKEN", "caf\N{LATIN SMALL LETTER E WITH ACUTE}")
    with pytest.raises(api.GithubSbomConfigurationError, match="printable ASCII"):
        api.generate_vex_from_github_sbom(
            repository="example/project",
            github_token_env="VEXCALIBUR_TEST_GITHUB_TOKEN",  # noqa: S106
            use_gh_auth=False,
            osv_base_url="https://osv.example.test",
        )


def test_public_api_rejects_invalid_osv_headers_before_github_io(monkeypatch) -> None:
    github_client_created = False

    class FailIfCreatedGithubClient:
        def __init__(self, **kwargs: object) -> None:
            nonlocal github_client_created
            github_client_created = True
            raise AssertionError(kwargs)

    monkeypatch.setattr(
        "vexcalibur.generate.GithubSbomClient",
        FailIfCreatedGithubClient,
    )

    with pytest.raises(api.OsvConfigurationError, match="OSV header values"):
        api.generate_vex_from_github_sbom(
            repository="example/project",
            use_gh_auth=False,
            osv_base_url="https://osv.example.test",
            osv_headers={"X-Label": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"},
        )

    assert github_client_created is False


def test_public_api_preflights_custom_source_before_github_auth(monkeypatch) -> None:
    auth_attempted = False

    def fail_if_auth_attempted(**kwargs: object) -> str:
        nonlocal auth_attempted
        auth_attempted = True
        raise AssertionError(kwargs)

    class RejectingSource:
        def validate_before_inventory_load(self) -> None:
            raise api.VulnerabilitySourceInputError("source policy rejected inventory")

        def findings_for_components(
            self,
            components: tuple[api.ComponentIdentity, ...],
        ) -> tuple[api.VulnerabilityFinding, ...]:
            raise AssertionError(components)

    monkeypatch.setattr("vexcalibur.api._resolve_github_token", fail_if_auth_attempted)

    with pytest.raises(api.SbomError, match="source policy"):
        api.generate_vex_from_github_source_result(
            repository="example/project",
            source=RejectingSource(),
            use_gh_auth=False,
        )

    assert auth_attempted is False


def test_public_api_resolves_github_auth_and_private_osv_headers(monkeypatch) -> None:
    captured: dict[str, object] = {}
    timestamp = datetime(2026, 8, 5, tzinfo=timezone.utc)
    component = api.ComponentIdentity(
        ref="component",
        name="example",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/example@1.0.0"),
    )

    def fake_resolve_github_token(
        *,
        api_url: str,
        token_env: str | None,
        allow_gh_cli: bool,
    ) -> str:
        captured["token_resolution"] = (api_url, token_env, allow_gh_cli)
        return "resolved-token"

    class FakeGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            captured["github_client"] = (api_url, token)

        def component_identities(
            self,
            repository: str,
        ) -> tuple[api.ComponentIdentity, ...]:
            captured["repository"] = repository
            return (component,)

    class FakeOsvSource:
        def __init__(self, **kwargs: object) -> None:
            captured["osv_source"] = kwargs

        def findings_for_components(
            self,
            components: tuple[api.ComponentIdentity, ...],
        ) -> tuple[api.VulnerabilityFinding, ...]:
            captured["components"] = components
            return ()

    class RecordingRenderer:
        def render(
            self,
            *,
            components: tuple[api.ComponentIdentity, ...],
            findings: tuple[api.VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            captured["renderer_call"] = (components, findings, timestamp)
            return '{"format":"recording"}'

    monkeypatch.setattr(
        "vexcalibur.generate.resolve_github_token",
        fake_resolve_github_token,
    )
    monkeypatch.setattr(
        "vexcalibur.generate.GithubSbomClient",
        FakeGithubSbomClient,
    )
    monkeypatch.setattr("vexcalibur.generate.OsvSource", FakeOsvSource)

    renderer = RecordingRenderer()
    rendered = api.generate_vex_from_github_sbom(
        repository="example/project",
        timestamp=timestamp,
        github_api_url="https://github.example.test/api/v3",
        github_token_env="GH_ENTERPRISE_TOKEN",  # noqa: S106
        use_gh_auth=False,
        osv_base_url="https://osv.example.test",
        allow_public_osv=True,
        osv_source_name="Example Security Feed",
        osv_source_url="https://security.example.test/vulnerability-data",
        osv_headers={"Authorization": "Bearer mirror-token"},
        renderer=renderer,
    )

    assert rendered == '{"format":"recording"}'
    assert captured["token_resolution"] == (
        "https://github.example.test/api/v3",
        "GH_ENTERPRISE_TOKEN",
        False,
    )
    assert captured["github_client"] == (
        "https://github.example.test/api/v3",
        "resolved-token",
    )
    assert captured["repository"] == "example/project"
    assert captured["components"] == (component,)
    assert captured["renderer_call"] == ((component,), (), timestamp)
    assert captured["osv_source"] == {
        "client": None,
        "osv_base_url": "https://osv.example.test",
        "allow_public_osv": True,
        "source_name": "Example Security Feed",
        "source_url": "https://security.example.test/vulnerability-data",
        "headers": {"Authorization": "Bearer mirror-token"},
    }


def test_public_api_forwards_private_osv_generation_options(monkeypatch) -> None:
    captured: dict[str, object] = {}
    timestamp = datetime(2026, 8, 5, tzinfo=timezone.utc)

    class FakeOsvSource:
        def __init__(self, **kwargs: object) -> None:
            captured["source_options"] = kwargs

        def findings_for_components(
            self,
            components: tuple[api.ComponentIdentity, ...],
        ) -> tuple[api.VulnerabilityFinding, ...]:
            captured["source_components"] = components
            return ()

    class RecordingRenderer:
        def render(
            self,
            *,
            components: tuple[api.ComponentIdentity, ...],
            findings: tuple[api.VulnerabilityFinding, ...],
            timestamp: datetime | None = None,
        ) -> str:
            captured["renderer_call"] = (components, findings, timestamp)
            return '{"format":"recording"}'

    monkeypatch.setattr("vexcalibur.generate.OsvSource", FakeOsvSource)
    renderer = RecordingRenderer()

    rendered = api.generate_vex_from_sbom(
        input_file=FIXTURES / "sbom" / "cyclonedx-json-simple.json",
        timestamp=timestamp,
        osv_base_url="https://osv.example.test/api",
        osv_source_name="Example Security Feed",
        osv_source_url="https://security.example.test/vulnerability-data",
        osv_headers={"Authorization": "Bearer mirror-token"},
        renderer=renderer,
    )

    assert rendered == '{"format":"recording"}'
    assert captured["source_options"] == {
        "client": None,
        "osv_base_url": "https://osv.example.test/api",
        "allow_public_osv": False,
        "source_name": "Example Security Feed",
        "source_url": "https://security.example.test/vulnerability-data",
        "headers": {"Authorization": "Bearer mirror-token"},
    }
    components = captured["source_components"]
    assert isinstance(components, tuple)
    assert captured["renderer_call"] == (components, (), timestamp)


def test_public_api_generates_vex_from_local_findings() -> None:
    rendered = api.generate_vex_from_local_findings(
        input_file=FIXTURES / "sbom" / "cyclonedx-json-simple.json",
        findings_file=FIXTURES / "findings" / "all-analysis-states.json",
    )

    assert '"bomFormat": "CycloneDX"' in rendered


def test_public_api_generates_and_parses_execution_report() -> None:
    result = api.generate_vex_from_local_findings_result(
        input_file=FIXTURES / "sbom" / "cyclonedx-json-simple.json",
        findings_file=FIXTURES / "findings" / "all-analysis-states.json",
    )

    assert isinstance(result, api.GenerationResult)
    assert result.execution_context == api.GenerationExecutionContext(
        inventory_source=api.InventorySourceCategory.SBOM_FILE,
        finding_source=api.FindingSourceCategory.LOCAL_FILE,
        output_format=api.ExecutionReportOutputFormat.CYCLONEDX,
    )
    serialized = result.execution_report().to_json()
    parsed = api.parse_generation_execution_report(serialized)

    assert parsed.schema_version == api.EXECUTION_REPORT_SCHEMA_VERSION
    assert parsed.document.bytes == len(result.rendered_bytes)


def test_public_api_rejects_conflicting_component_versions() -> None:
    with pytest.raises(api.ComponentVersionError, match="does not match"):
        api.ComponentIdentity(
            ref="component",
            name="example",
            version="2.0.0",
            purl=PackageURL.from_string("pkg:pypi/example@1.0.0"),
        )


def test_public_api_preserves_provider_failure() -> None:
    class FailingSource:
        def findings_for_components(
            self,
            components: tuple[api.ComponentIdentity, ...],
        ) -> tuple[api.VulnerabilityFinding, ...]:
            del components
            raise api.VulnerabilitySourceError("provider unavailable")

    component = api.ComponentIdentity(
        ref="component",
        name="example",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/example@1.0.0"),
    )

    with pytest.raises(api.VulnerabilitySourceError, match="provider unavailable"):
        api.generate_vex_from_components(
            components=(component,),
            source=FailingSource(),
            timestamp=None,
        )


def test_public_api_reports_sbom_io_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    with pytest.raises(api.SbomError, match="Could not read SBOM"):
        api.load_cyclonedx_sbom(missing)


def test_documented_python_api_example_runs(tmp_path: Path) -> None:
    namespace = runpy.run_path(str(Path("docs/examples/use_python_api.py")))

    namespace["main"](tmp_path / "vex.json")

    parsed = json.loads((tmp_path / "vex.json").read_text(encoding="utf-8"))
    assert parsed["bomFormat"] == "CycloneDX"
    assert len(parsed["vulnerabilities"]) == 5
