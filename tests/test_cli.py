import json
import shlex
from pathlib import Path

import pytest
from packageurl import PackageURL
from typer.testing import CliRunner

import vexcalibur.csaf as csaf_module
import vexcalibur.sources.osv as osv_module
from vexcalibur import cli
from vexcalibur.compat import vexy
from vexcalibur.domain import ComponentIdentity
from vexcalibur.sources.osv import (
    OsvClientError,
    OsvPackageQuery,
    OsvQueryResult,
    OsvVulnerabilitySummary,
)
from vexcalibur.vex import parse_timestamp

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
FINDINGS_ROOT = Path(__file__).parent / "fixtures" / "findings"
GOLDEN_ROOT = Path(__file__).parent / "golden"
DOCS_ROOT = Path(__file__).parent.parent / "docs"


def test_query_osv_prints_vulnerability_ids(monkeypatch) -> None:
    captured_purls: list[str] = []
    captured_base_urls: list[str] = []

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            captured_base_urls.append(base_url)

        def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
            captured_purls.extend(purl.to_string() for purl in purls)
            return [
                OsvQueryResult(
                    purl="pkg:pypi/example@1.0.0",
                    vulnerabilities=(OsvVulnerabilitySummary(id="GHSA-test-0001"),),
                ),
                OsvQueryResult(
                    purl="pkg:npm/example@2.0.0",
                    vulnerabilities=(),
                ),
            ]

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "pkg:npm/example@2.0.0",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 0
    assert captured_base_urls == ["https://api.osv.dev"]
    assert captured_purls == [
        "pkg:pypi/example@1.0.0",
        "pkg:npm/example@2.0.0",
    ]
    assert "pkg:pypi/example@1.0.0: GHSA-test-0001" in result.output
    assert "pkg:npm/example@2.0.0: no vulnerabilities found" in result.output


def test_query_osv_prints_server_controlled_ids_without_rich_markup(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            pass

        def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
            return [
                OsvQueryResult(
                    purl="pkg:pypi/example@1.0.0",
                    vulnerabilities=(
                        OsvVulnerabilitySummary(
                            id="[link=https://evil.example]GHSA-test-0001[/link]"
                        ),
                    ),
                )
            ]

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 0
    assert (
        "pkg:pypi/example@1.0.0: [link=https://evil.example]GHSA-test-0001[/link]" in result.output
    )


def test_query_osv_requires_public_osv_opt_in_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("public OSV client should not be constructed")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(cli.app, ["query-osv", "pkg:pypi/example@1.0.0"])

    assert result.exit_code == 1
    assert "OSV query failed" in result.output
    assert "--allow-public-osv" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "osv_url",
    (
        "https://api.osv.dev",
        " https://api.osv.dev ",
        "\thttps://api.osv.dev\n",
        "https://api.osv.dev/",
        "https://API.OSV.DEV",
        "https://api.osv.dev.",
        "https://api.osv.dev./",
        "https://api.osv.dev\u3002",
        "https://api.osv.dev\uff0e",
        "https://api.osv.dev\uff61",
    ),
)
def test_query_osv_rejects_public_osv_url_variants_without_traceback(
    monkeypatch,
    osv_url: str,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("public OSV client should not be constructed")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "--osv-url",
            osv_url,
        ],
    )

    assert result.exit_code == 1
    assert "OSV query failed" in result.output
    assert "--allow-public-osv" in result.output
    assert "Traceback" not in result.output


def test_query_osv_allows_private_osv_url_without_public_opt_in(monkeypatch) -> None:
    captured_base_urls: list[str] = []

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            captured_base_urls.append(base_url)

        def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
            return []

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "--osv-url",
            "https://osv.internal.example",
        ],
    )

    assert result.exit_code == 0
    assert captured_base_urls == ["https://osv.internal.example"]


@pytest.mark.parametrize(
    ("osv_url", "expected_message"),
    (
        ("api.osv.dev", "absolute https URL"),
        ("http://osv.internal.example", "must use https"),
        ("https://[::1", "absolute https URL"),
        ("https://osv.internal.example:bad", "port"),
        ("https://user@osv.internal.example", "userinfo"),
        ("https://osv.internal.example?debug=true", "params, query, or fragment"),
        ("https://osv.internal.example#fragment", "params, query, or fragment"),
    ),
)
def test_query_osv_rejects_invalid_osv_url_without_traceback(
    monkeypatch,
    osv_url: str,
    expected_message: str,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV client should not be constructed for invalid URL")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "--osv-url",
            osv_url,
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "OSV query failed" in result.output
    assert expected_message in result.output
    assert "Traceback" not in result.output


def test_query_osv_allows_cleartext_loopback_osv_url(monkeypatch) -> None:
    captured_base_urls: list[str] = []

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            captured_base_urls.append(base_url)

        def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
            return []

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "--osv-url",
            "http://127.0.0.1:8080/",
        ],
    )

    assert result.exit_code == 0
    assert captured_base_urls == ["http://127.0.0.1:8080"]


def test_query_osv_requires_at_least_one_purl() -> None:
    result = runner.invoke(cli.app, ["query-osv"])

    assert result.exit_code != 0
    assert "Missing argument" in result.output


def test_query_osv_reports_invalid_purl_without_traceback() -> None:
    result = runner.invoke(cli.app, ["query-osv", "not a purl"])

    assert result.exit_code != 0
    assert "not a purl" in result.output
    assert "not a valid package URL" in result.output
    assert "Traceback" not in result.output


def test_query_osv_reports_osv_client_errors_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            pass

        def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
            raise OsvClientError("OSV API POST /v1/querybatch failed with HTTP 503")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        ["query-osv", "pkg:pypi/example@1.0.0", "--allow-public-osv"],
    )

    assert result.exit_code == 1
    assert "OSV query failed: OSV API POST /v1/querybatch failed with HTTP 503" in result.output
    assert "Traceback" not in result.output


def test_generate_prints_deterministic_vex_json(monkeypatch) -> None:
    captured_queries: list[OsvPackageQuery] = []
    captured_base_urls: list[str] = []

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            captured_base_urls.append(base_url)

        def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
            captured_queries.extend(queries)
            return [
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

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 0
    assert captured_base_urls == ["https://api.osv.dev"]
    assert [(query.purl.to_string(), query.version) for query in captured_queries] == [
        ("pkg:npm/minimist@0.0.8", None),
        ("pkg:pypi/django@1.2", None),
    ]
    assert result.output == (GOLDEN_ROOT / "cyclonedx-vex-simple.json").read_text(encoding="utf-8")


def test_generate_accepts_github_repo_source(monkeypatch) -> None:
    captured_repositories: list[str] = []
    captured_github_clients: list[tuple[str, str | None]] = []
    captured_queries: list[OsvPackageQuery] = []

    class FakeGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            captured_github_clients.append((api_url, token))

        def component_identities(self, repository: str):
            captured_repositories.append(repository)
            return (
                ComponentIdentity(
                    ref="SPDXRef-pypi-django-1.2",
                    name="django",
                    version="1.2",
                    purl=PackageURL.from_string("pkg:pypi/django@1.2"),
                ),
            )

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            assert base_url == "https://api.osv.dev"

        def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
            captured_queries.extend(queries)
            return []

    def fake_resolve_github_token(**kwargs) -> str:
        assert kwargs["token_env"] == "TOKEN"  # noqa: S105
        return "resolved-token"

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)
    monkeypatch.setattr(cli, "resolve_github_token", fake_resolve_github_token)
    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--github-token-env",
            "TOKEN",
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 0
    assert captured_github_clients == [("https://api.github.com", "resolved-token")]
    assert captured_repositories == ["vexcalibur-dev/vexcalibur"]
    assert [(query.purl.to_string(), query.version) for query in captured_queries] == [
        ("pkg:pypi/django@1.2", None)
    ]
    assert '"bomFormat": "CycloneDX"' in result.output


def test_generate_accepts_github_repo_with_local_findings(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            pass

        def component_identities(self, repository: str):
            return (
                ComponentIdentity(
                    ref="SPDXRef-pypi-django-1.2",
                    name="django",
                    version="1.2",
                    purl=PackageURL.from_string("pkg:pypi/django@1.2"),
                ),
            )

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "SPDXRef-pypi-django-1.2",
              "analysis_state": "not_affected"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--no-gh-auth",
            "--findings-file",
            str(findings_path),
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert '"id": "CVE-2026-0001"' in result.output
    assert '"state": "not_affected"' in result.output


def test_generate_requires_input_file_or_github_repo() -> None:
    result = runner.invoke(cli.app, ["generate", "--allow-public-osv"])

    assert result.exit_code == 1
    assert "either INPUT_FILE or --github-repo is required" in result.output
    assert "Traceback" not in result.output


def test_generate_disallows_input_file_with_github_repo() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "INPUT_FILE cannot be combined with --github-repo" in result.output
    assert "Traceback" not in result.output


def test_generate_disallows_offline_with_github_repo() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--offline",
        ],
    )

    assert result.exit_code == 1
    assert "--offline cannot be combined with --github-repo" in result.output
    assert "Traceback" not in result.output


def test_generate_reports_github_sbom_errors_without_traceback(monkeypatch) -> None:
    class FakeGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            pass

        def component_identities(self, repository: str):
            raise cli.GithubSbomError("GitHub SBOM API GET failed")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--allow-public-osv",
            "--no-gh-auth",
        ],
    )

    assert result.exit_code == 1
    assert "GitHub SBOM ingest failed" in result.output
    assert "GitHub SBOM API GET failed" in result.output
    assert "Traceback" not in result.output


def test_generate_requires_public_osv_opt_in_before_fetching_github_sbom(monkeypatch) -> None:
    class FakeGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            raise AssertionError("GitHub SBOM should not be fetched before OSV policy validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--no-gh-auth",
        ],
    )

    assert result.exit_code == 1
    assert "VEX generation failed" in result.output
    assert "--allow-public-osv" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("marker", "expected_repository", "expected_api_url", "expected_token_env", "expected_osv_url"),
    (
        (
            "github-repo-public-example",
            "vexcalibur-dev/vexcalibur",
            "https://api.github.com",
            None,
            "https://api.osv.dev",
        ),
        (
            "github-repo-enterprise-example",
            "internal/example",
            "https://github.example.test/api/v3",
            "GH_ENTERPRISE_TOKEN",
            "https://osv.internal.example",
        ),
    ),
)
def test_documented_github_repo_generate_examples_execute(
    monkeypatch,
    tmp_path: Path,
    marker: str,
    expected_repository: str,
    expected_api_url: str,
    expected_token_env: str | None,
    expected_osv_url: str,
) -> None:
    output_path = tmp_path / "vex.json"
    captured_base_urls: list[str] = []
    captured_github_clients: list[tuple[str, str | None]] = []
    captured_repositories: list[str] = []
    captured_token_requests: list[dict[str, object]] = []

    class FakeGithubSbomClient:
        def __init__(self, *, api_url: str, token: str | None) -> None:
            captured_github_clients.append((api_url, token))

        def component_identities(self, repository: str):
            captured_repositories.append(repository)
            return (
                ComponentIdentity(
                    ref="SPDXRef-pypi-django-1.2",
                    name="django",
                    version="1.2",
                    purl=PackageURL.from_string("pkg:pypi/django@1.2"),
                ),
            )

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            captured_base_urls.append(base_url)

        def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
            return [
                OsvQueryResult(
                    purl="pkg:pypi/django@1.2",
                    vulnerabilities=(
                        OsvVulnerabilitySummary(
                            id="GHSA-django-0001",
                            modified=parse_timestamp("2026-01-01T00:00:00Z"),
                        ),
                    ),
                )
            ]

    def fake_resolve_github_token(**kwargs) -> str | None:
        captured_token_requests.append(dict(kwargs))
        if expected_token_env is None:
            return None
        return "resolved-token"

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)
    monkeypatch.setattr(cli, "resolve_github_token", fake_resolve_github_token)
    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    args = _documented_vexcalibur_generate_args(marker)
    args = [str(output_path) if arg.endswith("/vexcalibur-vex.json") else arg for arg in args]

    result = runner.invoke(cli.app, args)

    assert result.exit_code == 0
    assert result.output == ""
    assert captured_base_urls == [expected_osv_url]
    expected_token = None if expected_token_env is None else "resolved-token"
    assert captured_github_clients == [(expected_api_url, expected_token)]
    assert captured_repositories == [expected_repository]
    assert captured_token_requests == [
        {
            "api_url": expected_api_url,
            "token_env": expected_token_env,
            "allow_gh_cli": True,
        }
    ]
    generated = json.loads(output_path.read_text(encoding="utf-8"))
    assert generated["bomFormat"] == "CycloneDX"
    assert generated["components"] == [
        {
            "bom-ref": "SPDXRef-pypi-django-1.2",
            "name": "django",
            "purl": "pkg:pypi/django@1.2",
            "type": "library",
            "version": "1.2",
        }
    ]


def test_generate_requires_public_osv_opt_in_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("public OSV client should not be constructed")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        ["generate", str(FIXTURE_ROOT / "cyclonedx-json-simple.json")],
    )

    assert result.exit_code == 1
    assert "VEX generation failed" in result.output
    assert "--allow-public-osv" in result.output
    assert "Traceback" not in result.output


def test_generate_rejects_unversioned_sbom_before_public_osv_policy(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV client should not be constructed without a query set")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)
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

    result = runner.invoke(cli.app, ["generate", str(sbom_path)])

    assert result.exit_code == 1
    assert "SBOM ingest failed" in result.output
    assert "versioned package URLs" in result.output
    assert "--allow-public-osv" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "osv_url",
    (
        "https://api.osv.dev",
        " https://api.osv.dev ",
        "\thttps://api.osv.dev\n",
        "https://api.osv.dev/",
        "https://API.OSV.DEV",
        "https://api.osv.dev.",
        "https://api.osv.dev./",
        "https://api.osv.dev\u3002",
        "https://api.osv.dev\uff0e",
        "https://api.osv.dev\uff61",
    ),
)
def test_generate_rejects_public_osv_url_variants_without_traceback(
    monkeypatch,
    osv_url: str,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("public OSV client should not be constructed")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--osv-url",
            osv_url,
        ],
    )

    assert result.exit_code == 1
    assert "--allow-public-osv" in result.output
    assert "Traceback" not in result.output


def test_generate_rejects_empty_osv_url_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV client should not be constructed for an empty URL")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--osv-url",
            "",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "--osv-url must not be empty" in result.output
    assert "Traceback" not in result.output


def test_generate_rejects_invalid_osv_url_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV client should not be constructed for an invalid URL")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--osv-url",
            "https://osv.internal.example:bad",
        ],
    )

    assert result.exit_code == 1
    assert "VEX generation failed" in result.output
    assert "--osv-url port is invalid" in result.output
    assert "Traceback" not in result.output


def test_generate_allows_private_osv_url_without_public_opt_in(monkeypatch) -> None:
    captured_base_urls: list[str] = []

    class FakeOsvClient:
        def __init__(self, *, base_url: str) -> None:
            captured_base_urls.append(base_url)

        def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
            return []

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--osv-url",
            "https://osv.internal.example",
        ],
    )

    assert result.exit_code == 0
    assert captured_base_urls == ["https://osv.internal.example"]


def test_generate_offline_uses_local_findings_without_osv_client(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("offline generation should not construct an OSV client")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "analysis_state": "not_affected",
              "analysis_detail": "Reviewed and not affected."
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--offline",
            "--findings-file",
            str(findings_path),
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert '"id": "CVE-2026-0001"' in result.output
    assert '"state": "not_affected"' in result.output
    assert "Traceback" not in result.output


def test_generate_offline_accepts_xml_input_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("offline generation should not construct an OSV client")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "analysis_state": "not_affected",
              "analysis_detail": "Reviewed and not affected."
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-xml-simple.xml"),
            "--offline",
            "--findings-file",
            str(findings_path),
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert '"id": "CVE-2026-0001"' in result.output
    assert '"state": "not_affected"' in result.output
    assert "Traceback" not in result.output


def test_generate_findings_file_uses_local_findings_without_osv_client(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("local findings generation should not construct an OSV client")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert '"id": "CVE-2026-0001"' in result.output
    assert "Traceback" not in result.output


def test_generate_findings_file_disallows_public_osv_opt_in(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text('{"findings": []}', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
            "--allow-public-osv",
        ],
    )

    assert result.exit_code != 0
    assert "--allow-public-osv cannot be combined with --findings-file" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("osv_url", ("https://osv.internal.example", "https://api.osv.dev"))
def test_generate_findings_file_disallows_osv_url(tmp_path: Path, osv_url: str) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text('{"findings": []}', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
            "--osv-url",
            osv_url,
        ],
    )

    assert result.exit_code != 0
    assert "--osv-url cannot be combined with --findings-file" in result.output
    assert "Traceback" not in result.output


def test_generate_offline_requires_findings_file() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--offline",
        ],
    )

    assert result.exit_code != 0
    assert "--offline requires --findings-file" in result.output
    assert "Traceback" not in result.output


def test_generate_reports_local_findings_errors_without_traceback(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        '{"findings": [{"id": "CVE-2026-0001", "component_ref": "component:missing"}]}',
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
        ],
    )

    assert result.exit_code == 1
    assert "Local findings ingest failed" in result.output
    assert "unknown component_ref" in result.output
    assert "Traceback" not in result.output


def test_generate_writes_output_file(monkeypatch, tmp_path: Path) -> None:
    def fake_generate_vex_from_sbom(**kwargs) -> str:
        return "{}\n"

    monkeypatch.setattr(cli, "generate_vex_from_sbom", fake_generate_vex_from_sbom)
    output_path = tmp_path / "vex.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert result.output == ""
    assert output_path.read_text(encoding="utf-8") == "{}\n"


def test_generate_accepts_xml_input_file(monkeypatch) -> None:
    captured_input_files: list[Path] = []

    def fake_generate_vex_from_sbom(**kwargs) -> str:
        captured_input_files.append(kwargs["input_file"])
        return "{}\n"

    monkeypatch.setattr(cli, "generate_vex_from_sbom", fake_generate_vex_from_sbom)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-xml-simple.xml"),
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert result.output == "{}\n"
    assert captured_input_files == [FIXTURE_ROOT / "cyclonedx-xml-simple.xml"]


def test_generate_reports_invalid_timestamp_without_traceback() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--timestamp",
            "not a timestamp",
        ],
    )

    assert result.exit_code != 0
    assert "not a valid ISO-8601 timestamp" in result.output
    assert "Traceback" not in result.output


def test_generate_reports_sbom_errors_without_traceback(tmp_path: Path) -> None:
    sbom_path = tmp_path / "invalid.json"
    sbom_path.write_text("{not json", encoding="utf-8")

    result = runner.invoke(cli.app, ["generate", str(sbom_path)])

    assert result.exit_code == 1
    assert "SBOM ingest failed" in result.output
    assert "not valid JSON" in result.output
    assert "Traceback" not in result.output


def test_generate_reports_osv_errors_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            pass

        def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
            raise OsvClientError("OSV API POST /v1/querybatch failed with HTTP 503")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "OSV query failed: OSV API POST /v1/querybatch failed with HTTP 503" in result.output
    assert "Traceback" not in result.output


def test_generate_reports_output_write_errors_without_traceback(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def fake_generate_vex_from_sbom(**kwargs) -> str:
        return "{}\n"

    monkeypatch.setattr(cli, "generate_vex_from_sbom", fake_generate_vex_from_sbom)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert "Could not write VEX output" in result.output
    assert "Traceback" not in result.output


def test_vexcalibur_root_shows_help_without_args() -> None:
    result = runner.invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "query-osv" in result.output
    assert "generate" in result.output


def test_generate_openvex_matches_golden() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--format",
            "openvex",
            "--author",
            "Vexcalibur Test Maintainers",
            "--author-role",
            "Document producer",
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert result.output == (GOLDEN_ROOT / "openvex-vex-all-analysis-states.json").read_text(
        encoding="utf-8"
    )


def test_documented_openvex_local_example_executes(tmp_path: Path) -> None:
    output_path = tmp_path / "openvex.json"
    args = _documented_generate_args(
        DOCS_ROOT / "how-to" / "generate-openvex.md",
        "openvex-local-example",
    )
    args = [str(output_path) if arg.endswith("/vexcalibur-openvex.json") else arg for arg in args]

    result = runner.invoke(cli.app, args)

    assert result.exit_code == 0
    assert result.output == ""
    document = json.loads(output_path.read_text(encoding="utf-8"))
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["author"] == "Example Security Team"
    assert len(document["statements"]) == 5


def test_generate_openvex_requires_author_before_network(monkeypatch) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before OpenVEX option validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "openvex",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "--author is required with --format openvex" in result.output
    assert "Traceback" not in result.output


def test_generate_rejects_openvex_metadata_with_cyclonedx_before_network(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV must not be contacted before format option validation")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--author",
            "Example Security Team",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "--author and --author-role require --format openvex" in result.output
    assert "Traceback" not in result.output


def test_generate_openvex_rejects_empty_author_without_traceback() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--format",
            "openvex",
            "--author",
            " ",
        ],
    )

    assert result.exit_code == 1
    assert "VEX generation failed: OpenVEX output requires a nonempty author" in result.output
    assert "Traceback" not in result.output


def test_generate_openvex_rejects_empty_findings_without_writing_output(
    tmp_path: Path,
) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text('{"findings": []}', encoding="utf-8")
    output_path = tmp_path / "openvex.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
            "--offline",
            "--format",
            "openvex",
            "--author",
            "Example Security Team",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "requires at least one vulnerability finding" in result.output
    assert not output_path.exists()
    assert "Traceback" not in result.output


def test_generate_openvex_rejects_affected_finding_without_action(
    tmp_path: Path,
) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        """
        {
          "findings": [
            {
              "id": "CVE-2026-0001",
              "component_ref": "component:django",
              "analysis_state": "exploitable",
              "analysis_detail": "The vulnerable feature is reachable."
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
            "--offline",
            "--format",
            "openvex",
            "--author",
            "Example Security Team",
        ],
    )

    assert result.exit_code == 1
    assert "requires an action_statement" in result.output
    assert "Traceback" not in result.output


def test_generate_csaf_matches_golden(monkeypatch) -> None:
    monkeypatch.setattr(csaf_module, "__version__", "0.3.0")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--format",
            "csaf",
            *_csaf_metadata_args(namespace="https://security.example.com", status="final"),
            "--timestamp",
            "2026-07-15T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    assert result.output == (GOLDEN_ROOT / "csaf-vex-all-analysis-states.json").read_text(
        encoding="utf-8"
    )


def test_documented_csaf_local_example_executes(tmp_path: Path) -> None:
    output_path = tmp_path / "acme-vex-2026-001.json"
    args = _documented_generate_args(
        DOCS_ROOT / "how-to" / "generate-csaf.md",
        "csaf-local-example",
    )
    args = [str(output_path) if arg.endswith("/acme-vex-2026-001.json") else arg for arg in args]

    result = runner.invoke(cli.app, args)

    assert result.exit_code == 0
    assert result.output == ""
    document = json.loads(output_path.read_text(encoding="utf-8"))
    assert document["document"]["category"] == "csaf_vex"
    assert document["document"]["tracking"]["id"] == "ACME-VEX-2026-001"
    assert len(document["vulnerabilities"]) == 5


def test_generate_csaf_lists_every_missing_required_option_before_network(monkeypatch) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before CSAF option validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "csaf",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    for option in (
        "--csaf-document-id",
        "--csaf-document-title",
        "--csaf-publisher-name",
        "--csaf-publisher-namespace",
        "--csaf-publisher-category",
    ):
        assert option in result.output
    assert "required with --format csaf" in result.output
    assert "Traceback" not in result.output


def test_generate_csaf_defaults_to_version_2_and_draft_status() -> None:
    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--format",
            "csaf",
            *_csaf_metadata_args(),
            "--timestamp",
            "2026-07-15T00:00:00Z",
        ],
    )

    assert result.exit_code == 0
    document = json.loads(result.output)
    assert document["document"]["csaf_version"] == "2.0"
    assert document["document"]["tracking"]["status"] == "draft"


def test_generate_csaf_rejects_unsupported_version_before_network(monkeypatch) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before CSAF option validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "csaf",
            *_csaf_metadata_args(),
            "--csaf-version",
            "2.1",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "--csaf-version must be 2.0" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("option", "value"),
    (
        ("--csaf-document-status", "withdrawn"),
        ("--csaf-publisher-category", "translator"),
    ),
)
def test_generate_csaf_rejects_unsupported_metadata_enum(
    option: str,
    value: str,
) -> None:
    args = [
        "generate",
        str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        "--format",
        "csaf",
        *_csaf_metadata_args(),
        option,
        value,
    ]

    result = runner.invoke(cli.app, args)

    assert result.exit_code != 0
    assert value in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "namespace",
    (
        "ftp://security.example.test",
        "https://exa mple.test",
        "https://security.example.test/%zz",
        "https://sécurity.example.test",
        "https://security.example.test/\x7f",
        "https://security.example.test/path|value",
    ),
)
def test_generate_csaf_rejects_invalid_namespace_before_network(
    monkeypatch,
    namespace: str,
) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before CSAF option validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "csaf",
            *_csaf_metadata_args(namespace=namespace),
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "publisher_namespace" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("output_format", ("cyclonedx", "openvex"))
def test_generate_rejects_csaf_metadata_with_other_formats_before_network(
    monkeypatch,
    output_format: str,
) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before format option validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)
    args = [
        "generate",
        "--github-repo",
        "vexcalibur-dev/vexcalibur",
        "--format",
        output_format,
        "--csaf-document-id",
        "ACME-VEX-2026-001",
        "--allow-public-osv",
    ]
    if output_format == "openvex":
        args.extend(("--author", "Example Security Team"))

    result = runner.invoke(cli.app, args)

    assert result.exit_code == 1
    assert "--csaf-document-id require --format csaf" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("author_option", ("--author", "--author-role"))
def test_generate_csaf_rejects_openvex_metadata_before_network(
    monkeypatch,
    author_option: str,
) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before format option validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "csaf",
            *_csaf_metadata_args(),
            author_option,
            "Document producer",
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "--author and --author-role require --format openvex" in result.output
    assert "Traceback" not in result.output


def test_generate_csaf_enforces_output_filename_before_network(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before filename validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)
    output_path = tmp_path / "wrong-name.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "csaf",
            *_csaf_metadata_args(),
            "--output",
            str(output_path),
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "basename must be 'acme-vex-2026-001.json'" in result.output
    assert not output_path.exists()
    assert "Traceback" not in result.output


@pytest.mark.parametrize("line_terminator", ("\n", "\r", "\u2028", "\u2029"))
def test_generate_csaf_rejects_document_id_line_terminators_before_filename_and_network(
    monkeypatch,
    tmp_path: Path,
    line_terminator: str,
) -> None:
    class FakeGithubSbomClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("GitHub must not be contacted before CSAF ID validation")

    monkeypatch.setattr(cli, "GithubSbomClient", FakeGithubSbomClient)
    output_path = tmp_path / "acme_vex.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--github-repo",
            "vexcalibur-dev/vexcalibur",
            "--format",
            "csaf",
            *_csaf_metadata_args(document_id=f"ACME{line_terminator}VEX"),
            "--output",
            str(output_path),
            "--allow-public-osv",
        ],
    )

    assert result.exit_code == 1
    assert "document_id must not contain line terminators" in result.output
    assert not output_path.exists()
    assert "Traceback" not in result.output


def test_generate_csaf_accepts_the_derived_output_filename(tmp_path: Path) -> None:
    output_path = tmp_path / "acme-vex-2026-001.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--format",
            "csaf",
            *_csaf_metadata_args(),
            "--timestamp",
            "2026-07-15T00:00:00Z",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert result.output == ""
    assert json.loads(output_path.read_text(encoding="utf-8"))["document"]["category"] == "csaf_vex"


def test_vexy_compat_root_shows_help_without_args() -> None:
    result = runner.invoke(vexy.app, ["--help"])

    assert result.exit_code == 0
    assert "legacy vexy" in result.output


def test_vexy_rejects_invalid_osv_url_without_traceback(monkeypatch) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV client should not be constructed for an invalid URL")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        vexy.app,
        [
            "--in-file",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--output",
            "-",
            "--osv-url",
            "https://osv.internal.example:bad",
        ],
    )

    assert result.exit_code == 1
    assert "VEX generation failed" in result.output
    assert "--osv-url port is invalid" in result.output
    assert "Traceback" not in result.output


def _documented_vexcalibur_generate_args(marker: str) -> list[str]:
    return _documented_generate_args(
        DOCS_ROOT / "how-to" / "generate-cyclonedx-vex.md",
        marker,
    )


def _csaf_metadata_args(
    *,
    document_id: str = "ACME-VEX-2026-001",
    namespace: str = "https://security.example.test",
    status: str | None = None,
) -> list[str]:
    args = [
        "--csaf-document-id",
        document_id,
        "--csaf-document-title",
        "ACME component exploitability assessment",
        "--csaf-publisher-name",
        "ACME Product Security",
        "--csaf-publisher-namespace",
        namespace,
        "--csaf-publisher-category",
        "vendor",
    ]
    if status is not None:
        args.extend(("--csaf-document-status", status))
    return args


def _documented_generate_args(path: Path, marker: str) -> list[str]:
    command = _extract_marked_bash_command(path, marker)
    args = shlex.split(command)
    assert args[:4] == ["uv", "run", "--frozen", "vexcalibur"]
    assert args[4] == "generate"
    return args[4:]


def _extract_marked_bash_command(path: Path, marker: str) -> str:
    content = path.read_text(encoding="utf-8")
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    marked = content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]
    command_block = marked.split("```bash", maxsplit=1)[1].split("```", maxsplit=1)[0]
    return command_block.strip().replace("\\\n", " ")
