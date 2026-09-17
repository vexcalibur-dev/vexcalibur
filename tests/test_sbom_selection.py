import json
from pathlib import Path

import pytest

from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sbom_selection import load_sbom
from vexcalibur.spdx3_sbom import SUPPORTED_SPDX3_CONTEXT, load_spdx3_sbom

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"


def test_selects_cyclonedx_for_xml_content() -> None:
    path = FIXTURE_ROOT / "cyclonedx-xml-simple.xml"

    assert load_sbom(path) == load_cyclonedx_sbom(path)


def test_selects_cyclonedx_for_bom_format_json() -> None:
    path = FIXTURE_ROOT / "cyclonedx-json-simple.json"

    assert load_sbom(path) == load_cyclonedx_sbom(path)


def test_selects_spdx3_for_graph_json() -> None:
    path = FIXTURE_ROOT / "spdx3-json-simple.json"

    components = load_sbom(path)

    assert components == load_spdx3_sbom(path)
    assert [component.purl.to_string() for component in components] == [
        "pkg:npm/minimist@0.0.8",
        "pkg:pypi/django@1.2",
    ]


def test_rejects_a_document_with_both_format_markers(tmp_path: Path) -> None:
    path = tmp_path / "ambiguous.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "@context": SUPPORTED_SPDX3_CONTEXT,
                "@graph": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="both CycloneDX and SPDX 3 format markers"):
        load_sbom(path)


def test_rejects_a_document_without_format_markers(tmp_path: Path) -> None:
    path = tmp_path / "unknown.json"
    path.write_text('{"components": []}', encoding="utf-8")

    with pytest.raises(SbomError, match=r"expected CycloneDX 1\.4-1\.6 JSON or XML"):
        load_sbom(path)


def test_rejects_a_nonobject_document(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(SbomError, match="must be a JSON object"):
        load_sbom(path)


def test_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(b"{")

    with pytest.raises(SbomError, match="not valid JSON"):
        load_sbom(path)


def test_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}', encoding="utf-8")

    with pytest.raises(SbomError, match="duplicate JSON object keys"):
        load_sbom(path)


def test_reports_cyclonedx_errors_from_the_selected_parser(tmp_path: Path) -> None:
    path = tmp_path / "unsupported.json"
    path.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.0"}', encoding="utf-8")

    with pytest.raises(SbomError, match="unsupported CycloneDX specVersion"):
        load_sbom(path)


def test_reports_spdx3_errors_from_the_selected_parser(tmp_path: Path) -> None:
    path = tmp_path / "unsupported.spdx3.json"
    path.write_text(json.dumps({"@context": "https://example.test", "@graph": []}))

    with pytest.raises(SbomError, match=r"must declare the SPDX 3\.0\.1 JSON-LD context"):
        load_sbom(path)
