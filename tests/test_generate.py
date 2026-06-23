from pathlib import Path

import pytest

from vexcalibur.generate import generate_vex_from_sbom
from vexcalibur.sbom import SbomError
from vexcalibur.sources.osv import OsvPackageQuery, OsvQueryResult, OsvVulnerabilitySummary
from vexcalibur.vex import parse_timestamp

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
GOLDEN_ROOT = Path(__file__).parent / "golden"


class FakeOsvClient:
    def __init__(self, results: list[OsvQueryResult] | None = None) -> None:
        self.queries: list[OsvPackageQuery] = []
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
    )

    assert [(query.purl.to_string(), query.version) for query in client.queries] == [
        ("pkg:pypi/django", "1.2")
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
