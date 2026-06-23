from pathlib import Path

import pytest

from vexcalibur.sbom import SbomError, load_cyclonedx_json

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"


def test_load_cyclonedx_json_extracts_components_with_purls() -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8"),
        ("component:django", "pkg:pypi/django@1.2"),
    ]


def test_load_cyclonedx_json_rejects_invalid_json(tmp_path: Path) -> None:
    sbom_path = tmp_path / "invalid.json"
    sbom_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(SbomError, match="not valid JSON"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_non_object_json(tmp_path: Path) -> None:
    sbom_path = tmp_path / "array.json"
    sbom_path.write_text("[]", encoding="utf-8")

    with pytest.raises(SbomError, match="must be a JSON object"):
        load_cyclonedx_json(sbom_path)
