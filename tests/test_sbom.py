import os
from pathlib import Path

import pytest

from vexcalibur.sbom import (
    SbomError,
    load_cyclonedx_json,
    load_cyclonedx_sbom,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
XML_NAMESPACE = "http://cyclonedx.org/schema/bom/1.6"
EXTENSION_NAMESPACE = "https://example.test/cyclonedx-extension"


def _xml_component(
    *,
    ref: str,
    component_type: str = "library",
    name: str = "demo",
    version: str = "1.0.0",
    purl: str | None = "pkg:pypi/demo@1.0.0",
    children: str = "",
) -> str:
    purl_xml = "" if purl is None else f"<purl>{purl}</purl>"
    children_xml = "" if children == "" else f"<components>{children}</components>"
    return (
        f'<component type="{component_type}" bom-ref="{ref}">'
        f"<name>{name}</name>"
        f"<version>{version}</version>"
        f"{purl_xml}"
        f"{children_xml}"
        "</component>"
    )


def _xml_component_without_type(
    *,
    ref: str,
    purl: str = "pkg:pypi/demo@1.0.0",
) -> str:
    return (
        f'<component bom-ref="{ref}">'
        "<name>demo</name>"
        "<version>1.0.0</version>"
        f"<purl>{purl}</purl>"
        "</component>"
    )


def _xml_bom(body: str) -> str:
    return f'<bom xmlns="{XML_NAMESPACE}" version="1">{body}</bom>'


def test_load_cyclonedx_json_extracts_components_with_purls() -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-json-simple.json")

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8"),
        ("component:django", "pkg:pypi/django@1.2"),
    ]


def test_load_cyclonedx_sbom_extracts_components_from_json() -> None:
    components = load_cyclonedx_sbom(FIXTURE_ROOT / "cyclonedx-json-simple.json")

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8"),
        ("component:django", "pkg:pypi/django@1.2"),
    ]


def test_load_cyclonedx_sbom_extracts_components_from_xml() -> None:
    components = load_cyclonedx_sbom(FIXTURE_ROOT / "cyclonedx-xml-simple.xml")

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:django", "pkg:pypi/django@1.2")
    ]


@pytest.mark.parametrize(
    "fixture_name",
    (
        "cyclonedx-json-1.4-simple.json",
        "cyclonedx-json-1.5-simple.json",
        "cyclonedx-json-simple.json",
    ),
)
def test_load_cyclonedx_json_accepts_supported_fixture_versions(fixture_name: str) -> None:
    components = load_cyclonedx_json(FIXTURE_ROOT / fixture_name)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8"),
        ("component:django", "pkg:pypi/django@1.2"),
    ]


@pytest.mark.parametrize(
    ("fixture_name", "expected_components"),
    (
        (
            "cyclonedx-xml-1.4-simple.xml",
            (
                ("pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8"),
                ("component:django", "pkg:pypi/django@1.2"),
            ),
        ),
        (
            "cyclonedx-xml-1.5-simple.xml",
            (
                ("pkg:npm/minimist@0.0.8", "pkg:npm/minimist@0.0.8"),
                ("component:django", "pkg:pypi/django@1.2"),
            ),
        ),
        (
            "cyclonedx-xml-simple.xml",
            (("component:django", "pkg:pypi/django@1.2"),),
        ),
    ),
)
def test_load_cyclonedx_sbom_accepts_supported_xml_fixture_versions(
    fixture_name: str,
    expected_components: tuple[tuple[str, str], ...],
) -> None:
    components = load_cyclonedx_sbom(FIXTURE_ROOT / fixture_name)

    assert [(component.ref, component.purl.to_string()) for component in components] == list(
        expected_components
    )


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


def test_load_cyclonedx_sbom_includes_xml_metadata_component(tmp_path: Path) -> None:
    sbom_path = tmp_path / "metadata-component.xml"
    sbom_path.write_text(
        _xml_bom(
            "<metadata>"
            + _xml_component(
                ref="component:app",
                component_type="application",
                name="app",
                version="1.0.0",
                purl="pkg:pypi/app@1.0.0",
            )
            + "</metadata>"
        ),
        encoding="utf-8",
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [
        (component.ref, component.type, component.purl.to_string()) for component in components
    ] == [("component:app", "application", "pkg:pypi/app@1.0.0")]


def test_load_cyclonedx_sbom_includes_xml_nested_components(tmp_path: Path) -> None:
    sbom_path = tmp_path / "nested-components.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(
                ref="component:app",
                name="app",
                version="1.0.0",
                purl="pkg:pypi/app@1.0.0",
                children=_xml_component(
                    ref="component:child",
                    name="child",
                    version="2.0.0",
                    purl="pkg:pypi/child@2.0.0",
                ),
            )
            + "</components>"
        ),
        encoding="utf-8",
    )

    components = load_cyclonedx_sbom(sbom_path)

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


def test_load_cyclonedx_json_rejects_xml_with_sbom_loader_hint() -> None:
    with pytest.raises(SbomError, match="load_cyclonedx_sbom"):
        load_cyclonedx_json(FIXTURE_ROOT / "cyclonedx-xml-simple.xml")


def test_load_cyclonedx_json_rejects_xml_after_long_leading_whitespace(tmp_path: Path) -> None:
    sbom_path = tmp_path / "leading-whitespace.xml"
    sbom_path.write_text(" " * 512 + _xml_bom(""), encoding="utf-8")

    with pytest.raises(SbomError, match="load_cyclonedx_sbom"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_sbom_accepts_xml_after_long_leading_whitespace(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "leading-whitespace.xml"
    sbom_path.write_text(
        " " * 8192
        + _xml_bom("<components>" + _xml_component(ref="component:demo") + "</components>"),
        encoding="utf-8",
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


@pytest.mark.parametrize(
    "xml_content",
    (
        """\
        <cdx:bom xmlns:cdx="http://cyclonedx.org/schema/bom/1.6" version="1">
          <cdx:components>
            <cdx:component type="library" bom-ref="component:demo">
              <cdx:name>demo</cdx:name>
              <cdx:version>1.0.0</cdx:version>
              <cdx:purl>pkg:pypi/demo@1.0.0</cdx:purl>
            </cdx:component>
          </cdx:components>
        </cdx:bom>
        """,
        (
            '\ufeff<?xml version="1.0" encoding="UTF-8"?>'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">'
            "<components>"
            '<component type="library" bom-ref="component:demo">'
            "<name>demo</name>"
            "<version>1.0.0</version>"
            "<purl>pkg:pypi/demo@1.0.0</purl>"
            "</component>"
            "</components>"
            "</bom>"
        ),
        "<!---->" * 1_000
        + """\
        <bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
          <components>
            <component type="library" bom-ref="component:demo">
              <name>demo</name>
              <version>1.0.0</version>
              <purl>pkg:pypi/demo@1.0.0</purl>
            </component>
          </components>
        </bom>
        """,
    ),
)
def test_load_cyclonedx_sbom_accepts_xml_variants(
    tmp_path: Path,
    xml_content: str,
) -> None:
    sbom_path = tmp_path / "cyclonedx.xml"
    sbom_path.write_text(xml_content, encoding="utf-8")

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_sbom_ignores_foreign_namespace_component_elements(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "foreign-components.xml"
    sbom_path.write_text(
        f"""\
        <bom xmlns="{XML_NAMESPACE}" xmlns:ext="{EXTENSION_NAMESPACE}" version="1">
          <ext:components>
            <ext:component type="library" bom-ref="component:foreign">
              <ext:name>foreign</ext:name>
              <ext:version>1.0.0</ext:version>
              <ext:purl>pkg:pypi/foreign@1.0.0</ext:purl>
            </ext:component>
          </ext:components>
        </bom>
        """,
        encoding="utf-8",
    )

    assert load_cyclonedx_sbom(sbom_path) == ()


def test_load_cyclonedx_sbom_ignores_foreign_namespace_components_inside_cdx_container(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "foreign-component-child.xml"
    sbom_path.write_text(
        f"""\
        <bom xmlns="{XML_NAMESPACE}" xmlns:ext="{EXTENSION_NAMESPACE}" version="1">
          <components>
            <ext:component type="library" bom-ref="component:foreign">
              <name>foreign</name>
              <version>1.0.0</version>
              <purl>pkg:pypi/foreign@1.0.0</purl>
            </ext:component>
          </components>
        </bom>
        """,
        encoding="utf-8",
    )

    assert load_cyclonedx_sbom(sbom_path) == ()


def test_load_cyclonedx_sbom_rejects_components_without_cyclonedx_required_fields(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "missing-cyclonedx-fields.xml"
    sbom_path.write_text(
        f"""\
        <bom xmlns="{XML_NAMESPACE}" xmlns:ext="{EXTENSION_NAMESPACE}" version="1">
          <components>
            <component type="library" bom-ref="component:foreign-fields">
              <ext:name>foreign</ext:name>
              <ext:version>1.0.0</ext:version>
              <ext:purl>pkg:pypi/foreign@1.0.0</ext:purl>
            </component>
          </components>
        </bom>
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="not a supported CycloneDX XML document"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_xml_dtd_declarations(tmp_path: Path) -> None:
    sbom_path = tmp_path / "doctype.xml"
    sbom_path.write_text(
        """
        <!DOCTYPE bom [
          <!ENTITY demo "pkg:pypi/demo@1.0.0">
        ]>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
          <components>
            <component type="library" bom-ref="component:demo">
              <name>demo</name>
              <version>1.0.0</version>
              <purl>&demo;</purl>
            </component>
          </components>
        </bom>
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="DTD, entity, or external reference declarations"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_xml_dtd_without_entities(tmp_path: Path) -> None:
    sbom_path = tmp_path / "doctype-only.xml"
    sbom_path.write_text(
        '<!DOCTYPE bom []><bom xmlns="http://cyclonedx.org/schema/bom/1.6" />',
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="DTD, entity, or external reference declarations"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_external_xml_dtd(tmp_path: Path) -> None:
    sbom_path = tmp_path / "external-doctype.xml"
    sbom_path.write_text(
        (
            '<!DOCTYPE bom SYSTEM "https://example.test/bom.dtd">'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" />'
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="DTD, entity, or external reference declarations"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_accepts_xml_declaration_text_in_comments(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "comment.xml"
    sbom_path.write_text(
        "<!-- <!DOCTYPE bom> -->"
        + _xml_bom("<components>" + _xml_component(ref="component:demo") + "</components>"),
        encoding="utf-8",
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_sbom_rejects_unsupported_xml_namespace(tmp_path: Path) -> None:
    sbom_path = tmp_path / "unsupported.xml"
    sbom_path.write_text(
        '<bom xmlns="http://cyclonedx.org/schema/bom/9.9" version="1" />',
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="unsupported CycloneDX XML schema version"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_non_cyclonedx_xml(tmp_path: Path) -> None:
    sbom_path = tmp_path / "other.xml"
    sbom_path.write_text("<not-bom />", encoding="utf-8")

    with pytest.raises(SbomError, match="CycloneDX XML"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_accepts_sparse_xml_bom(tmp_path: Path) -> None:
    sbom_path = tmp_path / "empty.xml"
    sbom_path.write_text(f'<bom xmlns="{XML_NAMESPACE}" />', encoding="utf-8")

    assert load_cyclonedx_sbom(sbom_path) == ()


def test_load_cyclonedx_sbom_accepts_deep_same_namespace_non_component_xml(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "deep-extension.xml"
    sbom_path.write_text(
        f'<bom xmlns="{XML_NAMESPACE}" version="1">'
        + "<extension>" * 1200
        + "</extension>" * 1200
        + "</bom>",
        encoding="utf-8",
    )

    assert load_cyclonedx_sbom(sbom_path) == ()


def test_load_cyclonedx_sbom_accepts_utf16_xml(tmp_path: Path) -> None:
    sbom_path = tmp_path / "utf16.xml"
    sbom_path.write_bytes(
        (
            '<?xml version="1.0" encoding="UTF-16"?>'
            + _xml_bom("<components>" + _xml_component(ref="component:demo") + "</components>")
        ).encode("utf-16")
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_sbom_accepts_utf16be_xml_without_bom(tmp_path: Path) -> None:
    sbom_path = tmp_path / "utf16be.xml"
    sbom_path.write_bytes(
        (
            " \n\t"
            + _xml_bom("<components>" + _xml_component(ref="component:demo") + "</components>")
        ).encode("utf-16-be")
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_sbom_accepts_utf16le_xml_without_bom_and_leading_whitespace(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "utf16le.xml"
    sbom_path.write_bytes(
        (
            " \n\t"
            + _xml_bom("<components>" + _xml_component(ref="component:demo") + "</components>")
        ).encode("utf-16-le")
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:demo", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_sbom_accepts_xml_declared_iso_8859_1(tmp_path: Path) -> None:
    sbom_path = tmp_path / "latin1.xml"
    xml_content = (
        '<?xml version="1.0" encoding="ISO-8859-1"?>'
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">'
        "<components>"
        '<component type="library" bom-ref="component:cafe">'
        "<name>caf\xe9</name>"
        "<version>1.0.0</version>"
        "<purl>pkg:pypi/cafe@1.0.0</purl>"
        "</component>"
        "</components>"
        "</bom>"
    )
    sbom_path.write_bytes(xml_content.encode("iso-8859-1"))

    components = load_cyclonedx_sbom(sbom_path)

    assert [
        (component.ref, component.name, component.purl.to_string()) for component in components
    ] == [("component:cafe", "café", "pkg:pypi/cafe@1.0.0")]


def test_load_cyclonedx_sbom_rejects_unsupported_xml_encoding(tmp_path: Path) -> None:
    sbom_path = tmp_path / "bad-encoding.xml"
    sbom_path.write_bytes(
        (
            '<?xml version="1.0" encoding="NOPE"?>'
            + _xml_bom("<components>" + _xml_component(ref="component:demo") + "</components>")
        ).encode("utf-8")
    )

    with pytest.raises(SbomError, match="unsupported or invalid XML encoding"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_invalid_xml_component_type(tmp_path: Path) -> None:
    sbom_path = tmp_path / "invalid-type.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(ref="component:demo", component_type="not-a-type")
            + "</components>"
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="component type"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_missing_xml_component_type(tmp_path: Path) -> None:
    sbom_path = tmp_path / "missing-type.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>" + _xml_component_without_type(ref="component:demo") + "</components>"
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="must include a type"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_blank_xml_component_type(tmp_path: Path) -> None:
    sbom_path = tmp_path / "blank-type.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(ref="component:demo", component_type=" ")
            + "</components>"
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="must include a type"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_xml_component_type_unsupported_by_version(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "unsupported-type.xml"
    sbom_path.write_text(
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">'
        "<components>"
        + _xml_component(ref="component:crypto", component_type="cryptographic-asset")
        + "</components>"
        "</bom>",
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=r"not supported for CycloneDX 1\.5"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_nested_xml_component_type_unsupported_by_version(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "unsupported-nested-type.xml"
    sbom_path.write_text(
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">'
        "<components>"
        '<component type="library" bom-ref="component:parent">'
        "<name>parent</name>"
        "<version>1.0.0</version>"
        "<purl>pkg:pypi/parent@1.0.0</purl>"
        "<components>"
        + _xml_component(ref="component:child", purl="pkg:pypi/child@1.0.0")
        + "</components>"
        "<components>"
        + _xml_component(
            ref="component:crypto",
            component_type="cryptographic-asset",
            purl="pkg:pypi/crypto@1.0.0",
        )
        + "</components>"
        "</component>"
        "</components>"
        "</bom>",
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=r"not supported for CycloneDX 1\.5"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_non_integer_xml_bom_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "bad-version.xml"
    sbom_path.write_text(f'<bom xmlns="{XML_NAMESPACE}" version="1.0" />', encoding="utf-8")

    with pytest.raises(SbomError, match=r"version.*integer"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_non_positive_xml_bom_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "zero-version.xml"
    sbom_path.write_text(f'<bom xmlns="{XML_NAMESPACE}" version="0" />', encoding="utf-8")

    with pytest.raises(SbomError, match=r"version.*positive integer"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_huge_zero_xml_bom_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "huge-zero-version.xml"
    sbom_path.write_text(
        f'<bom xmlns="{XML_NAMESPACE}" version="{"0" * 5000}" />', encoding="utf-8"
    )

    with pytest.raises(SbomError, match=r"version.*positive integer"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_wraps_huge_xml_bom_version_conversion_errors(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "huge-version.xml"
    sbom_path.write_text(
        f'<bom xmlns="{XML_NAMESPACE}" version="{"1" * 5000}" />', encoding="utf-8"
    )

    with pytest.raises(SbomError, match="not a supported CycloneDX XML document"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_duplicate_xml_component_refs(tmp_path: Path) -> None:
    sbom_path = tmp_path / "duplicate-refs.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(ref="component:dup", name="django", purl="pkg:pypi/django@1.2")
            + _xml_component(ref="component:dup", name="flask", purl="pkg:pypi/flask@2.0.0")
            + "</components>"
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="duplicate component bom-ref"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_identical_duplicate_xml_component_refs(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "identical-duplicate-refs.xml"
    component = _xml_component(ref="component:dup", name="django", purl="pkg:pypi/django@1.2")
    sbom_path.write_text(
        _xml_bom("<components>" + component + component + "</components>"),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="duplicate component bom-ref"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_filters_xml_components_without_purls(tmp_path: Path) -> None:
    sbom_path = tmp_path / "missing-purl.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(ref="component:with-purl")
            + _xml_component(ref="component:no-purl", purl=None)
            + "</components>"
        ),
        encoding="utf-8",
    )

    components = load_cyclonedx_sbom(sbom_path)

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("component:with-purl", "pkg:pypi/demo@1.0.0")
    ]


def test_load_cyclonedx_sbom_rejects_xml_component_depth_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("vexcalibur.sbom.MAX_COMPONENT_DEPTH", 1)
    nested_components = _xml_component(
        ref="component:root",
        children=_xml_component(
            ref="component:child",
            children=_xml_component(ref="component:grandchild"),
        ),
    )
    sbom_path = tmp_path / "too-deep.xml"
    sbom_path.write_text(
        _xml_bom("<components>" + nested_components + "</components>"),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="component nesting limit"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_rejects_xml_component_count_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    component_limit = 1
    monkeypatch.setattr("vexcalibur.sbom.MAX_COMPONENTS", component_limit)
    sbom_path = tmp_path / "too-many.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(ref="component:first", purl="pkg:pypi/first@1.0.0")
            + _xml_component(ref="component:second", purl="pkg:pypi/second@1.0.0")
            + "</components>"
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=f"more than {component_limit} components"):
        load_cyclonedx_sbom(sbom_path)


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


@pytest.mark.parametrize(
    "document",
    (
        '{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6"}',
        (
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":['
            '{"type":"library","name":"demo","version":"1.0","version":"2.0",'
            '"purl":"pkg:pypi/demo@1.0"}]}'
        ),
    ),
)
def test_load_cyclonedx_json_rejects_duplicate_keys_at_every_depth(
    tmp_path: Path,
    document: str,
) -> None:
    sbom_path = tmp_path / "duplicate-key.json"
    sbom_path.write_text(document, encoding="utf-8")

    with pytest.raises(SbomError, match="duplicate JSON object keys"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_excessive_json_nesting(tmp_path: Path) -> None:
    sbom_path = tmp_path / "deep.json"
    nested = "[" * 2_000 + "]" * 2_000
    sbom_path.write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"extra":' + nested + "}}",
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="too deeply nested"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_rejects_oversized_json_integer(tmp_path: Path) -> None:
    sbom_path = tmp_path / "oversized-integer.json"
    sbom_path.write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":' + "1" * 1_001 + "}",
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="oversized JSON integer"):
        load_cyclonedx_json(sbom_path)


@pytest.mark.parametrize("loader", (load_cyclonedx_json, load_cyclonedx_sbom))
def test_cyclonedx_loaders_reject_fifo_as_typed_sbom_error(
    tmp_path: Path,
    loader: object,
) -> None:
    fifo = tmp_path / "sbom.json"
    os.mkfifo(fifo)

    with pytest.raises(SbomError, match="must resolve to a regular file"):
        loader(fifo)  # type: ignore[operator]


def test_load_cyclonedx_json_rejects_conflicting_component_versions(tmp_path: Path) -> None:
    sbom_path = tmp_path / "conflicting-version.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "components": [{
            "type": "library",
            "name": "demo",
            "version": "2.0",
            "purl": "pkg:pypi/demo@1.0"
          }]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=r"component version '2.0'.*version '1.0'"):
        load_cyclonedx_json(sbom_path)


def test_load_cyclonedx_json_compares_decoded_purl_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "encoded-version.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "components": [{
            "type": "library",
            "name": "demo",
            "version": "1.0",
            "purl": "pkg:pypi/demo@1%2E0"
          }]
        }
        """,
        encoding="utf-8",
    )

    assert load_cyclonedx_json(sbom_path)[0].purl.to_string() == "pkg:pypi/demo@1.0"


def test_load_cyclonedx_sbom_rejects_conflicting_xml_component_versions(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "conflicting-version.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(ref="component:demo", version="2.0", purl="pkg:pypi/demo@1.0")
            + "</components>"
        ),
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match=r"component version '2.0'.*version '1.0'"):
        load_cyclonedx_sbom(sbom_path)


def test_load_cyclonedx_sbom_compares_decoded_xml_purl_version(tmp_path: Path) -> None:
    sbom_path = tmp_path / "encoded-version.xml"
    sbom_path.write_text(
        _xml_bom(
            "<components>"
            + _xml_component(
                ref="component:demo",
                version="1.0",
                purl="pkg:pypi/demo@1%2E0",
            )
            + "</components>"
        ),
        encoding="utf-8",
    )

    assert load_cyclonedx_sbom(sbom_path)[0].purl.to_string() == "pkg:pypi/demo@1.0"
