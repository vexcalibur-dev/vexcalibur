import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from vexcalibur import api, cli
from vexcalibur.github_sbom import (
    GithubSbomClientError,
    component_identities_from_github_spdx_sbom,
)
from vexcalibur.sbom import MAX_COMPONENTS, SbomError
from vexcalibur.spdx2_sbom import component_identities_from_spdx2_document

FIXTURES = Path(__file__).parent / "fixtures"
SBOM = FIXTURES / "sbom" / "spdx2-json-simple.json"


def _package(purl: Any = "pkg:pypi/demo@1.0", **overrides: Any) -> dict[str, Any]:
    return {
        "SPDXID": "SPDXRef-demo",
        "name": "demo",
        "versionInfo": "1.0",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
        **overrides,
    }


def _document(*packages: Any) -> dict[str, Any]:
    return {"spdxVersion": "SPDX-2.3", "packages": list(packages)}


def _write(tmp_path: Path, document: Any) -> Path:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_public_loaders_and_github_share_component_mapping() -> None:
    components = api.load_sbom(SBOM)
    assert components == api.load_spdx2_sbom(SBOM)
    assert components == component_identities_from_github_spdx_sbom(
        json.loads(SBOM.read_text()), source="example/repo"
    )
    assert [(c.ref, c.version, c.purl.to_string()) for c in components] == [
        ("SPDXRef-minimist", "0.0.8", "pkg:npm/minimist@0.0.8"),
        ("SPDXRef-django", "1.2", "pkg:pypi/django@1.2"),
    ]


@pytest.mark.parametrize("spdx_id", ["SPDXRef-Repository", "SPDXRef-root"])
def test_local_inventory_keeps_github_repository_packages(tmp_path: Path, spdx_id: str) -> None:
    document = _document(_package("pkg:github/example/repo@1.0", SPDXID=spdx_id))
    document["relationships"] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        }
    ]
    assert len(api.load_sbom(_write(tmp_path, document))) == 1
    assert component_identities_from_github_spdx_sbom(document, source="example/repo") == ()


@pytest.mark.parametrize(
    ("purl", "version", "expected"),
    [
        ("pkg:pypi/demo@1.0", None, "1.0"),
        ("pkg:pypi/demo", "1.0", "1.0"),
        ("pkg:pypi/demo@1%2B2", "1+2", "1+2"),
    ],
)
def test_version_identity(tmp_path: Path, purl: str, version: str | None, expected: str) -> None:
    components = api.load_sbom(_write(tmp_path, _document(_package(purl, versionInfo=version))))
    assert (components[0].purl.version or components[0].version) == expected


def test_equivalent_purl_references_collapse(tmp_path: Path) -> None:
    package = _package()
    package["externalRefs"].append(
        {**package["externalRefs"][0], "referenceLocator": "pkg:PyPI/demo@1.0"}
    )
    assert len(api.load_sbom(_write(tmp_path, _document(package)))) == 1


def test_missing_name_and_id_fall_back_to_purl(tmp_path: Path) -> None:
    package = _package()
    del package["name"], package["SPDXID"]
    component = api.load_sbom(_write(tmp_path, _document(package)))[0]
    assert component.ref == "pkg:pypi/demo@1.0"
    assert component.name == "demo"


def test_packages_without_purls_are_omitted(tmp_path: Path) -> None:
    package = _package(
        externalRefs=[{"referenceCategory": "SECURITY", "referenceType": "cpe23Type"}]
    )
    assert api.load_sbom(_write(tmp_path, _document(package))) == ()


@pytest.mark.parametrize(
    ("package", "message"),
    [
        (7, "packages must be objects"),
        (_package(SPDXID=7), "SPDXID values must be strings"),
        (_package(name=7), "names must be strings"),
        (_package(versionInfo=7), "versionInfo values must be strings"),
        (_package(versionInfo="2.0"), "conflicting version"),
        (_package(externalRefs={}), "externalRefs values must be lists"),
        (_package(externalRefs=[7]), "externalRefs entries must be objects"),
        (_package(7), "referenceLocator values must be strings"),
        (_package(" "), "referenceLocator values must be strings"),
        (_package("invalid"), "purl is invalid"),
        (_package("pkg:pypi/\ud800@1.0"), "purl is invalid"),
    ],
)
def test_shared_rejections_are_typed(tmp_path: Path, package: Any, message: str) -> None:
    document = _document(package)
    with pytest.raises(SbomError, match=message):
        api.load_spdx2_sbom(_write(tmp_path, document))
    with pytest.raises(GithubSbomClientError, match=message):
        component_identities_from_github_spdx_sbom(document, source="example/repo")


def test_multiple_distinct_purls_are_rejected(tmp_path: Path) -> None:
    package = _package()
    package["externalRefs"].extend(_package("pkg:npm/demo@1.0")["externalRefs"])
    with pytest.raises(SbomError, match="multiple distinct package URL"):
        api.load_sbom(_write(tmp_path, _document(package)))


def test_duplicate_package_ids_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(SbomError, match="duplicate component"):
        api.load_sbom(_write(tmp_path, _document(_package(), _package("pkg:npm/demo@1.0"))))


@pytest.mark.parametrize("version", [None, "SPDX-2.2", "SPDX-3.0", {}, 3])
def test_rejects_unsupported_versions(tmp_path: Path, version: Any) -> None:
    with pytest.raises(SbomError, match="unsupported spdxVersion"):
        api.load_sbom(_write(tmp_path, {**_document(), "spdxVersion": version}))


@pytest.mark.parametrize("document", [[], {"spdxVersion": "SPDX-2.3"}, {"sbom": _document()}])
def test_dedicated_loader_rejects_invalid_documents(tmp_path: Path, document: Any) -> None:
    with pytest.raises(SbomError):
        api.load_spdx2_sbom(_write(tmp_path, document))


@pytest.mark.parametrize("other_marker", ["bomFormat", "@graph"])
def test_selector_rejects_mixed_formats(tmp_path: Path, other_marker: str) -> None:
    with pytest.raises(SbomError, match="conflicting SBOM format markers"):
        api.load_sbom(_write(tmp_path, {**_document(), other_marker: None}))


@pytest.mark.parametrize("loader", [api.load_spdx2_sbom, api.load_sbom])
@pytest.mark.parametrize(
    "content",
    [
        b'{"spdxVersion":"SPDX-2.3","packages":[],"packages":[]}',
        b'{"spdxVersion":"SPDX-2.3","packages":[NaN]}',
        b'{"spdxVersion":"SPDX-2.3","packages":["\xff"]}',
        b'{"spdxVersion":"SPDX-2.3","packages":' + b"[" * 200 + b"]" * 200 + b"}",
    ],
)
def test_file_loaders_enforce_json_boundary(tmp_path: Path, loader, content: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    with pytest.raises(SbomError):
        loader(path)


def test_file_loader_enforces_byte_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vexcalibur.sbom.MAX_SBOM_BYTES", 10)
    with pytest.raises(SbomError, match="byte limit"):
        api.load_spdx2_sbom(_write(tmp_path, _document()))


def test_file_loader_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(SbomError):
        api.load_spdx2_sbom(tmp_path)


@pytest.mark.parametrize("count", [MAX_COMPONENTS, MAX_COMPONENTS + 1])
def test_package_limit_includes_packages_without_purls(count: int) -> None:
    document = _document(*({"name": "no-purl"} for _ in range(count)))
    if count > MAX_COMPONENTS:
        with pytest.raises(SbomError, match="more than"):
            component_identities_from_spdx2_document(document, source="test")
    else:
        assert component_identities_from_spdx2_document(document, source="test") == ()


def test_cli_generates_offline_from_spdx2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_client(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("local input must not construct a network client")

    monkeypatch.setattr("vexcalibur.sources.osv.OsvClient", forbidden_client)
    monkeypatch.setattr("vexcalibur.github_sbom.GithubSbomClient", forbidden_client)
    output = tmp_path / "vex.json"
    result = CliRunner().invoke(
        cli.app,
        [
            "generate",
            str(SBOM),
            "--offline",
            "--findings-file",
            str(FIXTURES / "findings" / "spdx2-input-findings.json"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text())
    assert document["bomFormat"] == "CycloneDX"
    assert [component["bom-ref"] for component in document["components"]] == ["SPDXRef-django"]
    assert document["vulnerabilities"][0]["id"] == "CVE-2026-0001"


def test_result_retains_sbom_file_report_category() -> None:
    result = api.generate_vex_from_local_findings_result(
        input_file=SBOM,
        findings_file=FIXTURES / "findings" / "spdx2-input-findings.json",
    )
    assert result.execution_context is not None
    assert result.execution_context.inventory_source is api.InventorySourceCategory.SBOM_FILE
    assert result.execution_report().component_count == 2
