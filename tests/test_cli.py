from pathlib import Path

import pytest
from packageurl import PackageURL
from typer.testing import CliRunner

import vexcalibur.sources.osv as osv_module
from vexcalibur import cli
from vexcalibur.compat import vexy
from vexcalibur.sources.osv import (
    OsvClientError,
    OsvPackageQuery,
    OsvQueryResult,
    OsvVulnerabilitySummary,
)
from vexcalibur.vex import parse_timestamp

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
GOLDEN_ROOT = Path(__file__).parent / "golden"


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


@pytest.mark.parametrize(
    "osv_url",
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


def test_vexy_compat_root_shows_help_without_args() -> None:
    result = runner.invoke(vexy.app, ["--help"])

    assert result.exit_code == 0
    assert "legacy vexy" in result.output
