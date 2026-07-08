import json
from pathlib import Path

import pytest
from cyclonedx.output import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator
from packageurl import PackageURL

import vexcalibur.sources.osv as osv_module
from vexcalibur.domain import (
    DEFAULT_ANALYSIS_DETAIL,
    ComponentIdentity,
    VulnerabilityFinding,
    VulnerabilitySourceError,
)
from vexcalibur.generate import (
    generate_vex_from_components,
    generate_vex_from_github_sbom,
    generate_vex_from_local_findings,
    generate_vex_from_sbom,
    generate_vex_from_source,
)
from vexcalibur.sbom import SbomError
from vexcalibur.sources.osv import (
    OsvClient,
    OsvConfigurationError,
    OsvPackageQuery,
    OsvQueryResult,
    OsvSource,
    OsvVulnerabilitySummary,
)
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
FINDINGS_ROOT = Path(__file__).parent / "fixtures" / "findings"
GOLDEN_ROOT = Path(__file__).parent / "golden"
VALIDATOR = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_6)


class FakeOsvClient:
    def __init__(self, results: list[OsvQueryResult] | None = None, **kwargs) -> None:
        self.queries: list[OsvPackageQuery] = []
        self.kwargs = kwargs
        self._results = results or []

    def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
        self.queries.extend(queries)
        return self._results


class FakeVulnerabilitySource:
    def __init__(self, findings: tuple[VulnerabilityFinding, ...]) -> None:
        self.components: tuple[ComponentIdentity, ...] = ()
        self._findings = findings

    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        self.components = components
        return self._findings


def test_generate_vex_from_source_uses_provider_neutral_source() -> None:
    source = FakeVulnerabilitySource(
        (
            VulnerabilityFinding(
                id="CVE-2026-0001",
                source_name="Unit Test",
                source_url="https://security.example.test/CVE-2026-0001",
                component_ref="component:django",
                purl="pkg:pypi/django@1.2",
            ),
        )
    )

    generated = generate_vex_from_source(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        source=source,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert sorted(component.ref for component in source.components) == [
        "component:django",
        "pkg:npm/minimist@0.0.8",
    ]
    assert '"name": "Unit Test"' in generated
    assert DEFAULT_ANALYSIS_DETAIL in generated
    assert "Detected by OSV" not in generated
    assert VALIDATOR.validate_str(generated) is None


def test_generate_vex_from_source_accepts_cyclonedx_xml_sbom() -> None:
    source = FakeVulnerabilitySource(())

    generated = generate_vex_from_source(
        input_file=FIXTURE_ROOT / "cyclonedx-xml-simple.xml",
        source=source,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert [(component.ref, component.purl.to_string()) for component in source.components] == [
        ("component:django", "pkg:pypi/django@1.2")
    ]
    assert VALIDATOR.validate_str(generated) is None


def test_generate_vex_from_components_uses_provider_neutral_components() -> None:
    source = FakeVulnerabilitySource(())

    generated = generate_vex_from_components(
        components=(
            ComponentIdentity(
                ref="SPDXRef-pypi-django-1.2",
                name="django",
                version="1.2",
                purl=PackageURL.from_string("pkg:pypi/django@1.2"),
            ),
        ),
        source=source,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert [(component.ref, component.purl.to_string()) for component in source.components] == [
        ("SPDXRef-pypi-django-1.2", "pkg:pypi/django@1.2")
    ]
    assert VALIDATOR.validate_str(generated) is None


def test_source_errors_share_provider_neutral_base_class() -> None:
    from vexcalibur.sources.local import LocalFindingsError
    from vexcalibur.sources.osv import OsvClientError

    assert issubclass(LocalFindingsError, VulnerabilitySourceError)
    assert issubclass(OsvClientError, VulnerabilitySourceError)


def test_generate_vex_from_source_requires_public_osv_opt_in_for_osv_source() -> None:
    client = FakeOsvClient()

    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        generate_vex_from_source(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            source=OsvSource(client=client),
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        )

    assert client.queries == []


def test_generate_vex_from_source_allows_osv_source_with_public_opt_in() -> None:
    client = FakeOsvClient()

    generate_vex_from_source(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        source=OsvSource(client=client, allow_public_osv=True),
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert [(query.purl.to_string(), query.version) for query in client.queries] == [
        ("pkg:npm/minimist@0.0.8", None),
        ("pkg:pypi/django@1.2", None),
    ]


def test_generate_vex_from_sbom_queries_osv_and_renders_vex() -> None:
    client = FakeOsvClient(
        results=[
            OsvQueryResult(
                purl="pkg:npm/minimist@0.0.8",
                vulnerabilities=(
                    OsvVulnerabilitySummary(
                        id="GHSA-minimist-0001",
                        modified=parse_timestamp("2026-01-02T00:00:00Z"),
                    ),
                ),
            ),
            OsvQueryResult(
                purl="pkg:pypi/django@1.2",
                vulnerabilities=(
                    OsvVulnerabilitySummary(
                        id="GHSA-django-0001",
                        modified=parse_timestamp("2026-01-01T00:00:00Z"),
                    ),
                ),
            ),
        ]
    )

    generated = generate_vex_from_sbom(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        osv_client=client,
        allow_public_osv=True,
    )

    assert [(query.purl.to_string(), query.version) for query in client.queries] == [
        ("pkg:npm/minimist@0.0.8", None),
        ("pkg:pypi/django@1.2", None),
    ]
    assert generated == (GOLDEN_ROOT / "cyclonedx-vex-simple.json").read_text(encoding="utf-8")


def test_generate_vex_from_github_sbom_queries_osv() -> None:
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

    osv_client = FakeOsvClient()

    generated = generate_vex_from_github_sbom(
        repository="vexcalibur-dev/vexcalibur",
        github_client=FakeGithubSbomClient(),
        osv_client=osv_client,
        allow_public_osv=True,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert [(query.purl.to_string(), query.version) for query in osv_client.queries] == [
        ("pkg:pypi/django@1.2", None)
    ]
    assert VALIDATOR.validate_str(generated) is None


def test_generate_vex_from_github_sbom_requires_public_osv_opt_in_before_fetching() -> None:
    class FakeGithubSbomClient:
        def component_identities(self, repository: str) -> tuple[ComponentIdentity, ...]:
            raise AssertionError("GitHub SBOM should not be fetched before OSV policy validation")

    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        generate_vex_from_github_sbom(
            repository="vexcalibur-dev/vexcalibur",
            github_client=FakeGithubSbomClient(),
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        )


def test_generate_vex_from_local_findings_renders_without_osv(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "source_name": "Internal Review",
              "source_url": "https://security.example.test/vulns/CVE-2026-0001",
              "analysis_state": "not_affected",
              "analysis_detail": "Reviewed and not affected."
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        findings_file=findings_path,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert '"id": "CVE-2026-0001"' in generated
    assert '"name": "Internal Review"' in generated
    assert '"state": "not_affected"' in generated
    assert VALIDATOR.validate_str(generated) is None

    document = json.loads(generated)
    vulnerability = document["vulnerabilities"][0]
    assert vulnerability["source"] == {
        "name": "Internal Review",
        "url": "https://security.example.test/vulns/CVE-2026-0001",
    }
    assert vulnerability["analysis"]["detail"] == "Reviewed and not affected."


def test_generate_vex_from_local_findings_matches_all_states_golden_and_schema() -> None:
    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        findings_file=FINDINGS_ROOT / "all-analysis-states.json",
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert generated == (GOLDEN_ROOT / "cyclonedx-vex-all-analysis-states.json").read_text(
        encoding="utf-8"
    )
    assert VALIDATOR.validate_str(generated) is None
    assert [
        vulnerability["analysis"]["state"]
        for vulnerability in json.loads(generated)["vulnerabilities"]
    ] == [
        "resolved",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    ]


def test_generate_vex_from_empty_local_findings_is_schema_valid(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text('{"findings": []}', encoding="utf-8")

    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        findings_file=findings_path,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert VALIDATOR.validate_str(generated) is None
    assert json.loads(generated).get("vulnerabilities", []) == []


def test_generate_vex_from_sbom_uses_component_version_for_unversioned_purl(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "components": [
            {
              "type": "library",
              "name": "django",
              "version": "1.2",
              "purl": "pkg:pypi/django"
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    client = FakeOsvClient()

    generate_vex_from_sbom(
        input_file=sbom_path,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        osv_client=client,
        allow_public_osv=True,
    )

    assert [(query.purl.to_string(), query.version) for query in client.queries] == [
        ("pkg:pypi/django", "1.2")
    ]


def test_generate_vex_from_xml_sbom_uses_component_version_for_unversioned_purl(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "sbom.xml"
    sbom_path.write_text(
        """
        <bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
          <components>
            <component type="library" bom-ref="component:django">
              <name>django</name>
              <version>1.2</version>
              <purl>pkg:pypi/django</purl>
            </component>
          </components>
        </bom>
        """,
        encoding="utf-8",
    )
    client = FakeOsvClient()

    generate_vex_from_sbom(
        input_file=sbom_path,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        osv_client=client,
        allow_public_osv=True,
    )

    assert [(query.purl.to_string(), query.version) for query in client.queries] == [
        ("pkg:pypi/django", "1.2")
    ]


def test_generate_vex_from_xml_sbom_with_local_findings(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "source_name": "Internal Review",
              "source_url": "https://security.example.test/vulns/CVE-2026-0001",
              "analysis_state": "not_affected",
              "analysis_detail": "Reviewed and not affected."
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    generated = generate_vex_from_local_findings(
        input_file=FIXTURE_ROOT / "cyclonedx-xml-simple.xml",
        findings_file=findings_path,
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
    )

    assert '"id": "CVE-2026-0001"' in generated
    assert VALIDATOR.validate_str(generated) is None


def test_generate_vex_from_sbom_requires_public_osv_opt_in() -> None:
    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        generate_vex_from_sbom(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        )


def test_generate_vex_from_sbom_requires_injected_public_client_opt_in() -> None:
    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        generate_vex_from_sbom(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
            osv_client=FakeOsvClient(),
        )


def test_generate_vex_from_sbom_rejects_injected_public_client_with_private_claim() -> None:
    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        generate_vex_from_sbom(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
            osv_client=OsvClient(),
            osv_base_url="https://osv.internal.example",
        )


def test_generate_vex_from_sbom_allows_injected_non_public_client_without_opt_in() -> None:
    client = FakeOsvClient()

    generate_vex_from_sbom(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        osv_client=client,
        osv_base_url="https://osv.internal.example",
    )

    assert [(query.purl.to_string(), query.version) for query in client.queries] == [
        ("pkg:npm/minimist@0.0.8", None),
        ("pkg:pypi/django@1.2", None),
    ]


@pytest.mark.parametrize(
    "osv_base_url",
    (
        "https://api.osv.dev",
        "https://api.osv.dev/",
        "https://API.OSV.DEV",
        "https://api.osv.dev.",
        "https://api.osv.dev./",
        "https://api.osv.dev\u3002",
        "https://api.osv.dev\uff0e",
        "https://api.osv.dev\uff61",
    ),
)
def test_generate_vex_from_sbom_rejects_public_osv_url_variants(
    osv_base_url: str,
) -> None:
    with pytest.raises(OsvConfigurationError, match="--allow-public-osv"):
        generate_vex_from_sbom(
            input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
            osv_base_url=osv_base_url,
        )


def test_generate_vex_from_sbom_allows_public_osv_with_explicit_opt_in(monkeypatch) -> None:
    created_clients: list[FakeOsvClient] = []

    def fake_osv_client(**kwargs) -> FakeOsvClient:
        client = FakeOsvClient(**kwargs)
        created_clients.append(client)
        return client

    monkeypatch.setattr(osv_module, "OsvClient", fake_osv_client)

    generate_vex_from_sbom(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        allow_public_osv=True,
    )

    assert [client.kwargs["base_url"] for client in created_clients] == ["https://api.osv.dev"]


def test_generate_vex_from_sbom_allows_private_osv_url_without_public_opt_in(monkeypatch) -> None:
    created_clients: list[FakeOsvClient] = []

    def fake_osv_client(**kwargs) -> FakeOsvClient:
        client = FakeOsvClient(**kwargs)
        created_clients.append(client)
        return client

    monkeypatch.setattr(osv_module, "OsvClient", fake_osv_client)

    generate_vex_from_sbom(
        input_file=FIXTURE_ROOT / "cyclonedx-json-simple.json",
        timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
        osv_base_url="https://osv.internal.example",
    )

    assert [client.kwargs["base_url"] for client in created_clients] == [
        "https://osv.internal.example"
    ]


def test_generate_vex_from_sbom_rejects_sboms_without_versioned_purls(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "components": [
            {
              "type": "library",
              "name": "django",
              "purl": "pkg:pypi/django"
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    client = FakeOsvClient()

    with pytest.raises(SbomError, match="versioned package URLs"):
        generate_vex_from_sbom(
            input_file=sbom_path,
            timestamp=parse_timestamp("2026-06-23T00:00:00Z"),
            osv_client=client,
        )

    assert client.queries == []
