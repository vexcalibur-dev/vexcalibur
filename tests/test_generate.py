from pathlib import Path

import pytest

import vexcalibur.sources.osv as osv_module
from vexcalibur.generate import generate_vex_from_sbom
from vexcalibur.sbom import SbomError
from vexcalibur.sources.osv import (
    OsvClient,
    OsvConfigurationError,
    OsvPackageQuery,
    OsvQueryResult,
    OsvVulnerabilitySummary,
)
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
GOLDEN_ROOT = Path(__file__).parent / "golden"


class FakeOsvClient:
    def __init__(self, results: list[OsvQueryResult] | None = None, **kwargs) -> None:
        self.queries: list[OsvPackageQuery] = []
        self.kwargs = kwargs
        self._results = results or []

    def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
        self.queries.extend(queries)
        return self._results


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
