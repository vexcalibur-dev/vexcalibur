import json
from pathlib import Path
from typing import Any

import pytest

from vexcalibur.sbom import MAX_COMPONENTS, SbomError
from vexcalibur.spdx3_sbom import (
    SUPPORTED_SPDX3_CONTEXT,
    component_identities_from_spdx3_document,
    load_spdx3_sbom,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
FIXTURE_PATH = FIXTURE_ROOT / "spdx3-json-simple.json"


def _document(
    *packages: dict[str, Any],
    context: object = SUPPORTED_SPDX3_CONTEXT,
    extra_elements: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    return {
        "@context": context,
        "@graph": [
            {
                "@id": "_:creationinfo",
                "type": "CreationInfo",
                "specVersion": "3.0.1",
                "created": "2026-06-01T00:00:00Z",
                "createdBy": ["https://sbom.example.test/unit#agent"],
            },
            *extra_elements,
            *packages,
        ],
    }


def _package(**overrides: Any) -> dict[str, Any]:
    package: dict[str, Any] = {
        "type": "software_Package",
        "spdxId": "https://sbom.example.test/unit#package",
        "creationInfo": "_:creationinfo",
        "name": "demo",
        "software_packageVersion": "1.0.0",
        "software_packageUrl": "pkg:pypi/demo@1.0.0",
    }
    package.update(overrides)
    return package


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "sbom.spdx3.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_loads_packages_from_the_committed_fixture() -> None:
    components = load_spdx3_sbom(FIXTURE_PATH)

    assert [
        (component.ref, component.name, component.version, component.purl.to_string())
        for component in components
    ] == [
        ("pkg:npm/minimist@0.0.8", "minimist", "0.0.8", "pkg:npm/minimist@0.0.8"),
        ("https://sbom.example.test/demo#django", "django", "1.2", "pkg:pypi/django@1.2"),
    ]


def test_omits_packages_without_package_urls() -> None:
    components = load_spdx3_sbom(FIXTURE_PATH)

    assert all(component.name != "no-purl" for component in components)


@pytest.mark.parametrize(
    "package_type", ("software_Package", "ai_AIPackage", "dataset_DatasetPackage")
)
def test_rejects_inline_packages_instead_of_partial_inventory(
    tmp_path: Path, package_type: str
) -> None:
    document = _document(
        _package(),
        extra_elements=({"type": "SpdxDocument", "element": [None, _package(type=package_type)]},),
    )

    with pytest.raises(SbomError, match="package definitions must be top-level"):
        load_spdx3_sbom(_write(tmp_path, document))


@pytest.mark.parametrize("over_limit", (False, True))
def test_bounds_expanded_referenced_purls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, over_limit: bool
) -> None:
    purl = "pkg:pypi/demo@1.0.0"
    monkeypatch.setattr(
        "vexcalibur.spdx3_sbom.MAX_EXPANDED_PURL_BYTES", 2 * len(purl) - int(over_limit)
    )
    packages = []
    for index in range(2):
        package = _package(spdxId=f"https://example.test/{index}", externalIdentifier=["_:purl"])
        del package["software_packageUrl"]
        packages.append(package)
    document = _document(
        *packages,
        extra_elements=(
            {
                "type": "ExternalIdentifier",
                "@id": "_:purl",
                "externalIdentifierType": "packageUrl",
                "identifier": purl,
            },
        ),
    )
    path = _write(tmp_path, document)

    if over_limit:
        with pytest.raises(SbomError, match="expanded package URL byte limit"):
            load_spdx3_sbom(path)
    else:
        components = load_spdx3_sbom(path)
        assert len(components) == 2
        assert components[0].purl is components[1].purl


def test_rejects_unencodable_package_urls(tmp_path: Path) -> None:
    document = _document(_package(software_packageUrl="pkg:pypi/\ud800@1.0.0"))

    with pytest.raises(SbomError, match="purl is invalid"):
        load_spdx3_sbom(_write(tmp_path, document))


def test_ignores_elements_that_are_not_packages(tmp_path: Path) -> None:
    document = _document(
        _package(),
        extra_elements=(
            {
                "type": "security_Vulnerability",
                "spdxId": "https://sbom.example.test/unit#vulnerability",
                "creationInfo": "_:creationinfo",
                "name": "CVE-2026-0001",
            },
        ),
    )

    components = load_spdx3_sbom(_write(tmp_path, document))

    assert [component.name for component in components] == ["demo"]


def test_accepts_a_package_url_from_an_external_identifier(tmp_path: Path) -> None:
    package = _package()
    del package["software_packageUrl"]
    package["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": "pkg:pypi/demo@1.0.0",
        }
    ]

    components = load_spdx3_sbom(_write(tmp_path, _document(package)))

    assert components[0].purl.to_string() == "pkg:pypi/demo@1.0.0"


@pytest.mark.parametrize("package_type", ("ai_AIPackage", "dataset_DatasetPackage"))
def test_accepts_derived_software_package_types(tmp_path: Path, package_type: str) -> None:
    package = _package(type=package_type)

    components = load_spdx3_sbom(_write(tmp_path, _document(package)))

    assert [component.purl.to_string() for component in components] == ["pkg:pypi/demo@1.0.0"]


def test_package_type_selection_matches_the_vendored_schema() -> None:
    schema = json.loads(
        (FIXTURE_ROOT.parent / "schemas" / "spdx-3.0.1.schema.json").read_text(encoding="utf-8")
    )
    derived = schema["$defs"]["software_Package_derived"]["anyOf"][0]["anyOf"]
    schema_types = {reference["$ref"].removeprefix("#/$defs/") for reference in derived}

    from vexcalibur.spdx3_sbom import _PACKAGE_TYPES

    assert schema_types == _PACKAGE_TYPES


def test_resolves_a_referenced_external_identifier(tmp_path: Path) -> None:
    package = _package()
    del package["software_packageUrl"]
    package["externalIdentifier"] = ["_:package-url"]
    document = _document(
        package,
        extra_elements=(
            {
                "@id": "_:package-url",
                "type": "ExternalIdentifier",
                "externalIdentifierType": "packageUrl",
                "identifier": "pkg:pypi/demo@1.0.0",
            },
        ),
    )

    components = load_spdx3_sbom(_write(tmp_path, document))

    assert [component.purl.to_string() for component in components] == ["pkg:pypi/demo@1.0.0"]


def test_ignores_a_referenced_identifier_of_another_type(tmp_path: Path) -> None:
    package = _package()
    package["externalIdentifier"] = ["_:cve"]
    document = _document(
        package,
        extra_elements=(
            {
                "@id": "_:cve",
                "type": "ExternalIdentifier",
                "externalIdentifierType": "cve",
                "identifier": "CVE-2026-0001",
            },
        ),
    )

    components = load_spdx3_sbom(_write(tmp_path, document))

    assert [component.purl.to_string() for component in components] == ["pkg:pypi/demo@1.0.0"]


def test_collapses_equivalent_package_url_identities(tmp_path: Path) -> None:
    package = _package()
    package["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": "pkg:pypi/demo@1.0.0",
        }
    ]

    components = load_spdx3_sbom(_write(tmp_path, _document(package)))

    assert len(components) == 1


def test_rejects_distinct_package_url_identities(tmp_path: Path) -> None:
    package = _package()
    package["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": "pkg:pypi/other@2.0.0",
        }
    ]

    with pytest.raises(SbomError, match="multiple distinct package URL identities"):
        load_spdx3_sbom(_write(tmp_path, _document(package)))


def test_ignores_external_identifiers_of_other_types(tmp_path: Path) -> None:
    package = _package()
    del package["software_packageUrl"]
    package["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "cve",
            "identifier": "CVE-2026-0001",
        }
    ]

    components = load_spdx3_sbom(_write(tmp_path, _document(package)))

    assert components == ()


def test_falls_back_to_the_package_url_name_and_ref(tmp_path: Path) -> None:
    package = _package()
    del package["spdxId"]
    del package["name"]

    components = load_spdx3_sbom(_write(tmp_path, _document(package)))

    assert components[0].ref == "pkg:pypi/demo@1.0.0"
    assert components[0].name == "demo"


def test_uses_the_package_version_for_an_unversioned_package_url(tmp_path: Path) -> None:
    package = _package(software_packageUrl="pkg:pypi/demo")

    components = load_spdx3_sbom(_write(tmp_path, _document(package)))

    assert components[0].version == "1.0.0"
    assert components[0].purl.version is None


def test_rejects_conflicting_version_identity(tmp_path: Path) -> None:
    package = _package(software_packageVersion="9.9")

    with pytest.raises(SbomError, match="conflicting version identity"):
        load_spdx3_sbom(_write(tmp_path, _document(package)))


def test_rejects_duplicate_spdx_ids(tmp_path: Path) -> None:
    first = _package()
    second = _package(
        software_packageUrl="pkg:pypi/other@2.0.0",
        software_packageVersion="2.0.0",
        name="other",
    )

    with pytest.raises(SbomError, match="duplicate package spdxId values"):
        load_spdx3_sbom(_write(tmp_path, _document(first, second)))


@pytest.mark.parametrize("value", ([], {}, None, 7, True))
def test_rejects_nonstrings_in_graph_type(tmp_path: Path, value: Any) -> None:
    document = _document(_package(type=value))
    with pytest.raises(SbomError, match=r"type.*must be.*string"):
        load_spdx3_sbom(_write(tmp_path, document))


@pytest.mark.parametrize("second_purl", ("pkg:pypi/demo@1.0.0", "pkg:pypi/other@1.0.0"))
def test_rejects_duplicate_external_identifier_ids(tmp_path: Path, second_purl: str) -> None:
    identifiers = tuple(
        {
            "@id": "_:package-url",
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": purl,
        }
        for purl in ("pkg:pypi/demo@1.0.0", second_purl)
    )
    package = _package(externalIdentifier=["_:package-url"])
    del package["software_packageUrl"]
    with pytest.raises(SbomError, match=r"duplicate.*identifier"):
        load_spdx3_sbom(_write(tmp_path, _document(package, extra_elements=identifiers)))


def test_rejects_an_unsupported_context(tmp_path: Path) -> None:
    document = _document(
        _package(),
        context="https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
    )

    with pytest.raises(SbomError, match=r"must declare the SPDX 3\.0\.1 JSON-LD context"):
        load_spdx3_sbom(_write(tmp_path, document))


def test_rejects_a_context_list(tmp_path: Path) -> None:
    document = _document(_package(), context=[SUPPORTED_SPDX3_CONTEXT])

    with pytest.raises(SbomError, match="'@context' string"):
        load_spdx3_sbom(_write(tmp_path, document))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda document: document.pop("@graph"), "'@graph' must be a list"),
        (
            lambda document: document.__setitem__("@graph", {}),
            "'@graph' must be a list",
        ),
        (
            lambda document: document.__setitem__("@graph", ["text"]),
            "'@graph' entries must be objects",
        ),
    ),
)
def test_rejects_malformed_graphs(tmp_path: Path, mutation: Any, message: str) -> None:
    document = _document(_package())
    mutation(document)

    with pytest.raises(SbomError, match=message):
        load_spdx3_sbom(_write(tmp_path, document))


def test_rejects_a_nonobject_document(tmp_path: Path) -> None:
    with pytest.raises(SbomError, match="must be a JSON object"):
        load_spdx3_sbom(_write(tmp_path, ["not", "an", "object"]))


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("spdxId", 7, "spdxId values must be strings"),
        ("name", 7, "names must be strings"),
        ("software_packageVersion", 7, "software_packageVersion values must be strings"),
        ("software_packageUrl", 7, "software_packageUrl values must be strings"),
        ("software_packageUrl", " ", "software_packageUrl values must be strings"),
        ("software_packageUrl", "not-a-purl", "purl is invalid"),
        ("externalIdentifier", {}, "externalIdentifier values must be lists"),
        ("externalIdentifier", [7], "entries must be objects or references"),
        (
            "externalIdentifier",
            ["_:missing"],
            "does not resolve to an ExternalIdentifier",
        ),
    ),
)
def test_rejects_malformed_package_fields(
    tmp_path: Path,
    field_name: str,
    value: Any,
    message: str,
) -> None:
    package = _package(**{field_name: value})

    with pytest.raises(SbomError, match=message):
        load_spdx3_sbom(_write(tmp_path, _document(package)))


@pytest.mark.parametrize("identifier", (7, "", " "))
def test_rejects_malformed_package_url_identifiers(tmp_path: Path, identifier: Any) -> None:
    package = _package()
    package["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": identifier,
        }
    ]

    with pytest.raises(SbomError, match="packageUrl identifier values must be strings"):
        load_spdx3_sbom(_write(tmp_path, _document(package)))


def test_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "sbom.spdx3.json"
    path.write_text(
        '{"@context": "x", "@context": "y", "@graph": []}',
        encoding="utf-8",
    )

    with pytest.raises(SbomError, match="duplicate JSON object keys"):
        load_spdx3_sbom(path)


def test_rejects_more_packages_than_the_component_limit() -> None:
    packages = [
        {
            "type": "software_Package",
            "spdxId": f"https://sbom.example.test/unit#package-{index}",
            "name": "demo",
        }
        for index in range(MAX_COMPONENTS + 1)
    ]
    document = {"@context": SUPPORTED_SPDX3_CONTEXT, "@graph": packages}

    with pytest.raises(SbomError, match=f"more than {MAX_COMPONENTS} packages"):
        component_identities_from_spdx3_document(document, path=Path("unit.spdx3.json"))
