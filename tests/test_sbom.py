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


def test_load_cyclonedx_json_includes_metadata_component(tmp_path: Path) -> None:
    sbom_path = tmp_path / "metadata-component.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "metadata": {
            "component": {
              "type": "application",
              "bom-ref": "component:app",
              "name": "app",
              "version": "1.0.0",
              "purl": "pkg:pypi/app@1.0.0"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    components = load_cyclonedx_json(sbom_path)

    assert [
        (component.ref, component.type, component.purl.to_string()) for component in components
    ] == [("component:app", "application", "pkg:pypi/app@1.0.0")]


def test_load_cyclonedx_json_includes_nested_metadata_components(tmp_path: Path) -> None:
    sbom_path = tmp_path / "metadata-nested-component.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "metadata": {
            "component": {
              "type": "application",
              "bom-ref": "component:app",
              "name": "app",
              "version": "1.0.0",
              "purl": "pkg:pypi/app@1.0.0",
              "components": [
                {
                  "type": "library",
                  "bom-ref": "component:child",
                  "name": "child",
                  "version": "2.0.0",
                  "purl": "pkg:pypi/child@2.0.0"
                }
              ]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    components = load_cyclonedx_json(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:app", "pkg:pypi/app@1.0.0"),
        ("component:child", "pkg:pypi/child@2.0.0"),
    ]


def test_load_cyclonedx_json_accepts_defaulted_bom_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "defaulted-bom-version.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "components": [
            {
              "type": "library",
              "bom-ref": "component:demo",
              "name": "demo",
              "version": "1.0.0",
              "purl": "pkg:pypi/demo@1.0.0"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    components = load_cyclonedx_json(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_json_rejects_duplicate_component_refs(tmp_path: Path) -> None:
    sbom_path = tmp_path / "duplicate-refs.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "components": [
            {
              "type": "library",
              "bom-ref": "component:dup",
              "name": "django",
              "version": "1.2",
              "purl": "pkg:pypi/django@1.2"
            },
            {
              "type": "library",
              "bom-ref": "component:dup",
              "name": "flask",
              "version": "2.0.0",
              "purl": "pkg:pypi/flask@2.0.0"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="duplicate component bom-ref"):
        load_cyclonedx_json(sbom_path)


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


def test_load_cyclonedx_json_rejects_wrong_bom_format(tmp_path: Path) -> None:
    sbom_path = tmp_path / "wrong-format.json"
    sbom_path.write_text(
        '{"bomFormat": "NotCycloneDX", "specVersion": "1.6", "version": 1}',
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="bomFormat 'CycloneDX'"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_unsupported_spec_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "unsupported-version.json"
    sbom_path.write_text(
        '{"bomFormat": "CycloneDX", "specVersion": "9.9", "version": 1}',
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="unsupported CycloneDX specVersion"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_malformed_components(tmp_path: Path) -> None:
    sbom_path = tmp_path / "bad-components.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "components": [
            "bad"
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="components must be objects"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_malformed_metadata(tmp_path: Path) -> None:
    sbom_path = tmp_path / "bad-metadata.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": 1,
          "metadata": "bad"
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=r"metadata.*object"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_non_integer_bom_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "bad-version.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "version": "1"
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=r"version.*integer"):
        load_cyclonedx_json(sbom_path)
