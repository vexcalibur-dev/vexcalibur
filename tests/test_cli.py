from packageurl import PackageURL
from typer.testing import CliRunner

from vexcalibur import cli
from vexcalibur.compat import vexy
from vexcalibur.sources.osv import OsvClientError, OsvQueryResult, OsvVulnerabilitySummary

runner = CliRunner()


def test_query_osv_prints_vulnerability_ids(monkeypatch) -> None:
    captured_purls: list[str] = []

    class FakeOsvClient:
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

    monkeypatch.setattr(cli, "OsvClient", FakeOsvClient)

    result = runner.invoke(
        cli.app,
        [
            "query-osv",
            "pkg:pypi/example@1.0.0",
            "pkg:npm/example@2.0.0",
        ],
    )

    assert result.exit_code == 0
    assert captured_purls == [
        "pkg:pypi/example@1.0.0",
        "pkg:npm/example@2.0.0",
    ]
    assert "pkg:pypi/example@1.0.0: GHSA-test-0001" in result.output
    assert "pkg:npm/example@2.0.0: no vulnerabilities found" in result.output


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
        def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
            raise OsvClientError("OSV API POST /v1/querybatch failed with HTTP 503")

    monkeypatch.setattr(cli, "OsvClient", FakeOsvClient)

    result = runner.invoke(cli.app, ["query-osv", "pkg:pypi/example@1.0.0"])

    assert result.exit_code == 1
    assert "OSV query failed: OSV API POST /v1/querybatch failed with HTTP 503" in result.output
    assert "Traceback" not in result.output


def test_vexcalibur_root_shows_help_without_args() -> None:
    result = runner.invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "query-osv" in result.output


def test_vexy_compat_root_shows_help_without_args() -> None:
    result = runner.invoke(vexy.app, ["--help"])

    assert result.exit_code == 0
    assert "legacy vexy" in result.output
