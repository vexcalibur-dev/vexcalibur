from __future__ import annotations

import copy
import json
import stat
import subprocess
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import scripts.release_evidence as release_evidence

ROOT = Path(__file__).parents[1]
LOCK = ROOT / "uv.lock"
PRODUCTION_REVIEW = ROOT / "release-evidence" / "review.json"
PRODUCTION_FINDINGS = ROOT / "release-evidence" / "findings.json"
FIXTURE_REVIEW = ROOT / "tests" / "fixtures" / "release-evidence" / "review.json"
FIXTURE_FINDINGS = ROOT / "tests" / "fixtures" / "release-evidence" / "findings.json"


def _grouped_digest(path: Path) -> str:
    digest = release_evidence.sha256_file(path)
    return ":".join(digest[index : index + 16] for index in range(0, 64, 16))


def _write_test_wheel(
    path: Path,
    *,
    commit: str,
    dirty: bool = False,
    metadata_members: int = 1,
    metadata: object | None = None,
    scm_unix_mode: int | None = None,
) -> None:
    scm_metadata = {"node": f"g{commit}", "dirty": dirty} if metadata is None else metadata
    with zipfile.ZipFile(path, "w") as wheel:
        wheel.writestr(
            "vexcalibur-0.4.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: vexcalibur\nVersion: 0.4.0\n",
        )
        for index in range(metadata_members):
            member = zipfile.ZipInfo(f"vexcalibur-0.4.{index}.dist-info/scm_version.json")
            if scm_unix_mode is not None:
                member.create_system = 3
                member.external_attr = scm_unix_mode << 16
            wheel.writestr(member, release_evidence.canonical_json(scm_metadata))


def _write_test_sdist(path: Path, *, version: str = "0.4.0", commit: str = "a" * 40) -> None:
    metadata = (f"Metadata-Version: 2.4\nName: vexcalibur\nVersion: {version}\n").encode()
    member = tarfile.TarInfo(f"vexcalibur-{version}/PKG-INFO")
    member.size = len(metadata)
    version_source = (
        f"__version__ = version = '{version}'\n__commit_id__ = commit_id = 'g{commit[:10]}'\n"
    ).encode()
    version_member = tarfile.TarInfo(f"vexcalibur-{version}/src/vexcalibur/_version.py")
    version_member.size = len(version_source)
    with tarfile.open(path, "w:gz") as sdist:
        sdist.addfile(member, BytesIO(metadata))
        sdist.addfile(version_member, BytesIO(version_source))


def _write_integrity_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "integrity-bundle"
    bundle.mkdir()
    artifact = bundle / "one.txt"
    artifact.write_text("one\n")
    manifest = {
        "artifacts": [
            {
                "name": artifact.name,
                "sha256": release_evidence.sha256_file(artifact),
                "size": artifact.stat().st_size,
            }
        ]
    }
    (bundle / "manifest.json").write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(bundle)
    return bundle


def _write_zero_publication_inventory(
    tmp_path: Path, *, source_tree_clean: bool = True
) -> tuple[Path, Path]:
    inputs = tmp_path / "inventory-inputs"
    inputs.mkdir()
    for source, name in (
        (PRODUCTION_REVIEW, "review.json"),
        (PRODUCTION_FINDINGS, "findings.json"),
    ):
        (inputs / name).write_bytes(source.read_bytes())
    (inputs / "runtime-constraints.txt").write_text(
        "--require-hashes\n--only-binary :all:\n\nexample==1 \\\n"
        "    --hash=sha256:" + "a" * 64 + "\n"
    )
    (inputs / "sbom.cdx.json").write_text(
        release_evidence.canonical_json(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": {
                    "timestamp": "2026-07-15T17:05:56Z",
                    "component": {
                        "type": "application",
                        "name": "vexcalibur",
                        "version": "0.4.0",
                        "purl": "pkg:pypi/vexcalibur@0.4.0",
                        "bom-ref": "pkg:pypi/vexcalibur@0.4.0",
                        "properties": [
                            {
                                "name": "vexcalibur:source:uv-lock-sha256",
                                "value": release_evidence.sha256_file(LOCK),
                            }
                        ],
                    },
                },
                "components": [],
            }
        )
    )
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(wheel, commit="a" * 40)
    inventory = tmp_path / "inventory"
    release_evidence.prepare_publication_inventory(
        output_dir=inventory,
        release_sha="a" * 40,
        release_version="0.4.0",
        source_date_epoch=1_784_135_156,
        lock_path=LOCK,
        review_path=inputs / "review.json",
        findings_path=inputs / "findings.json",
        constraints_path=inputs / "runtime-constraints.txt",
        sbom_path=inputs / "sbom.cdx.json",
        uv_version="0.11.17",
        source_tree_clean=source_tree_clean,
    )
    return inventory, wheel


def _write_zero_vex_output(path: Path) -> None:
    path.mkdir()
    (path / "vex.cdx.json").write_text(
        release_evidence.canonical_json(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
        )
    )


def test_checked_production_review_is_bound_to_the_lock_and_has_zero_findings() -> None:
    review = release_evidence.load_json(PRODUCTION_REVIEW)
    findings_document = release_evidence.load_json(PRODUCTION_FINDINGS)

    review_kind, findings = release_evidence.validate_review(
        review,
        findings_document,
        lock_path=LOCK,
        findings_path=PRODUCTION_FINDINGS,
    )

    assert review_kind == "production"
    assert findings == ()
    assert review["policy"]["allowed_analysis_states"] == ["in_triage"]
    assert review["inventory"]["sha256"].replace(":", "") == release_evidence.sha256_file(LOCK)


def test_synthetic_review_requires_explicit_opt_in() -> None:
    review = release_evidence.load_json(FIXTURE_REVIEW)
    findings_document = release_evidence.load_json(FIXTURE_FINDINGS)

    with pytest.raises(release_evidence.EvidenceError, match="explicit --allow-synthetic"):
        release_evidence.validate_review(
            review,
            findings_document,
            lock_path=LOCK,
            findings_path=FIXTURE_FINDINGS,
        )

    review_kind, findings = release_evidence.validate_review(
        review,
        findings_document,
        lock_path=LOCK,
        findings_path=FIXTURE_FINDINGS,
        allow_synthetic=True,
    )
    assert review_kind == "synthetic_fixture"
    assert len(findings) == 1
    assert findings[0]["analysis_state"] == "in_triage"


def test_review_rejects_a_stale_lock_binding() -> None:
    review = copy.deepcopy(release_evidence.load_json(PRODUCTION_REVIEW))
    review["inventory"]["sha256"] = ":".join(["0" * 16] * 4)

    with pytest.raises(release_evidence.EvidenceError, match=r"does not match uv\.lock"):
        release_evidence.validate_review(
            review,
            release_evidence.load_json(PRODUCTION_FINDINGS),
            lock_path=LOCK,
            findings_path=PRODUCTION_FINDINGS,
        )


def test_review_rejects_canonical_purl_aliases(tmp_path: Path) -> None:
    review = copy.deepcopy(release_evidence.load_json(FIXTURE_REVIEW))
    findings_document = copy.deepcopy(release_evidence.load_json(FIXTURE_FINDINGS))
    duplicate = copy.deepcopy(findings_document["findings"][0])
    duplicate["purl"] = "pkg:pypi/HTTPX@0.28.1"
    findings_document["findings"].append(duplicate)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(release_evidence.canonical_json(findings_document))
    review["findings"]["sha256"] = _grouped_digest(findings_path)

    with pytest.raises(release_evidence.EvidenceError, match="duplicate reviewed assertion"):
        release_evidence.validate_review(
            review,
            findings_document,
            lock_path=LOCK,
            findings_path=findings_path,
            allow_synthetic=True,
        )


@pytest.mark.parametrize(
    ("metadata_members", "metadata", "error"),
    [
        (0, None, "exactly one"),
        (2, None, "exactly one"),
        (1, {"node": "not-a-commit", "dirty": False}, "full Git commit"),
    ],
)
def test_wheel_source_rejects_missing_multiple_or_malformed_metadata(
    tmp_path: Path,
    metadata_members: int,
    metadata: object | None,
    error: str,
) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(
        wheel,
        commit="a" * 40,
        metadata_members=metadata_members,
        metadata=metadata,
    )

    with pytest.raises(release_evidence.EvidenceError, match=error):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


def test_wheel_source_requires_the_exact_clean_commit(tmp_path: Path) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(wheel, commit="a" * 40)
    assert release_evidence.validate_wheel_source(wheel, release_sha="a" * 40) == "a" * 40

    _write_test_wheel(wheel, commit="b" * 40)
    with pytest.raises(release_evidence.EvidenceError, match="does not match release SHA"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)

    _write_test_wheel(wheel, commit="a" * 40, dirty=True)
    with pytest.raises(release_evidence.EvidenceError, match="dirty=false"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


@pytest.mark.parametrize("unix_mode", [stat.S_IFLNK | 0o777, stat.S_IFCHR | 0o600])
def test_wheel_source_rejects_nonregular_unix_members(tmp_path: Path, unix_mode: int) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(wheel, commit="a" * 40, scm_unix_mode=unix_mode)

    with pytest.raises(release_evidence.EvidenceError, match="regular member"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


def test_wheel_source_rejects_duplicate_and_traversal_members(tmp_path: Path) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../outside", "bad")
        archive.writestr(
            "vexcalibur-0.4.0.dist-info/METADATA",
            "Name: vexcalibur\nVersion: 0.4.0\n",
        )
        archive.writestr(
            "vexcalibur-0.4.0.dist-info/scm_version.json",
            release_evidence.canonical_json({"node": "g" + "a" * 40, "dirty": False}),
        )

    with pytest.raises(release_evidence.EvidenceError, match="unsafe archive member"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


@pytest.mark.parametrize(
    "member_name",
    ["C:/outside.txt", "c:relative.txt", "vexcalibur/control\nname", "vexcalibur/del\x7fname"],
)
def test_archive_member_names_reject_drive_qualified_and_control_characters(
    member_name: str,
) -> None:
    with pytest.raises(release_evidence.EvidenceError, match="unsafe archive member"):
        release_evidence._validate_archive_member_name(member_name, artifact="archive")


def test_archive_member_budget_rejects_decompression_bombs() -> None:
    member = zipfile.ZipInfo("large.bin")
    member.file_size = release_evidence.MAX_ARCHIVE_UNCOMPRESSED_BYTES + 1

    with pytest.raises(release_evidence.EvidenceError, match="uncompressed byte limit"):
        release_evidence._validate_zip_members([member])


def test_distribution_metadata_rejects_sdist_from_another_commit(tmp_path: Path) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(wheel, commit="a" * 40)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist, commit="b" * 40)

    with pytest.raises(release_evidence.EvidenceError, match="sdist SCM commit"):
        release_evidence._validate_distribution_metadata(
            wheel_path=wheel,
            sdist_path=sdist,
            expected_version="0.4.0",
            expected_release_sha="a" * 40,
        )


@pytest.mark.parametrize("analysis_state", ["not_affected", "resolved", None])
def test_review_rejects_stronger_or_implicit_analysis_states(
    analysis_state: str | None,
) -> None:
    review = copy.deepcopy(release_evidence.load_json(FIXTURE_REVIEW))
    findings_document = copy.deepcopy(release_evidence.load_json(FIXTURE_FINDINGS))
    finding = findings_document["findings"][0]
    if analysis_state is None:
        finding.pop("analysis_state")
    else:
        finding["analysis_state"] = analysis_state

    with pytest.raises(release_evidence.EvidenceError, match="explicitly set to in_triage"):
        release_evidence.validate_review(
            review,
            findings_document,
            lock_path=LOCK,
            findings_path=FIXTURE_FINDINGS,
            allow_synthetic=True,
        )


def test_uv_sbom_normalization_removes_random_fields_and_sorts_inventory() -> None:
    raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "metadata": {
            "timestamp": "2020-01-01T00:00:00Z",
            "tools": [
                {"vendor": "Z", "name": "tool", "version": "1"},
                {"vendor": "Astral Software Inc.", "name": "uv", "version": "0.11.17"},
            ],
            "component": {
                "type": "library",
                "bom-ref": "vexcalibur-1",
                "name": "vexcalibur",
                "properties": [
                    {"name": "uv:package:is_project_root", "value": "true"},
                ],
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "z-2@2.0",
                "name": "z",
                "version": "2.0",
                "purl": "pkg:pypi/z@2.0",
            },
            {
                "type": "library",
                "bom-ref": "a-1@1.0",
                "name": "a",
                "version": "1.0",
                "purl": "pkg:pypi/a@1.0",
            },
        ],
        "dependencies": [
            {"ref": "z-2@2.0"},
            {"ref": "vexcalibur-1", "dependsOn": ["z-2@2.0", "a-1@1.0"]},
            {"ref": "a-1@1.0"},
        ],
    }

    normalized = release_evidence.normalize_sbom(
        raw,
        release_version="0.4.0",
        timestamp="2026-07-15T17:05:56Z",
        lock_sha256="a" * 64,
    )
    same_semantics_with_new_random_values = copy.deepcopy(raw)
    same_semantics_with_new_random_values["serialNumber"] = (
        "urn:uuid:00000000-0000-4000-8000-000000000002"
    )
    same_semantics_with_new_random_values["metadata"]["timestamp"] = "2030-01-01T00:00:00Z"

    assert normalized == release_evidence.normalize_sbom(
        same_semantics_with_new_random_values,
        release_version="0.4.0",
        timestamp="2026-07-15T17:05:56Z",
        lock_sha256="a" * 64,
    )
    assert "serialNumber" not in normalized
    assert normalized["metadata"]["timestamp"] == "2026-07-15T17:05:56Z"
    assert normalized["metadata"]["component"]["bom-ref"] == "pkg:pypi/vexcalibur@0.4.0"
    assert normalized["metadata"]["component"]["version"] == "0.4.0"
    assert [component["name"] for component in normalized["components"]] == ["a", "z"]
    assert [dependency["ref"] for dependency in normalized["dependencies"]] == [
        "a-1@1.0",
        "pkg:pypi/vexcalibur@0.4.0",
        "z-2@2.0",
    ]


def test_existing_nonempty_goldens_are_cross_format_equivalent() -> None:
    golden_root = ROOT / "tests" / "golden"

    assertions = release_evidence.compare_vex_formats(
        release_evidence.load_json(golden_root / "cyclonedx-vex-all-analysis-states.json"),
        release_evidence.load_json(golden_root / "openvex-vex-all-analysis-states.json"),
        release_evidence.load_json(golden_root / "csaf-vex-all-analysis-states.json"),
    )

    assert len(assertions) == 5
    assert {state for _, _, state in assertions} == {
        "resolved",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }


def test_cyclonedx_assertions_reject_ambiguous_component_identity() -> None:
    document = {
        "components": [
            {"bom-ref": "duplicate", "purl": "pkg:pypi/evil@1"},
            {"bom-ref": "duplicate", "purl": "pkg:pypi/expected@1"},
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2099-1",
                "analysis": {"state": "in_triage"},
                "affects": [{"ref": "duplicate"}],
            }
        ],
    }

    with pytest.raises(release_evidence.EvidenceError, match="duplicate bom-ref"):
        release_evidence._cyclonedx_assertions(document)


def test_csaf_assertions_reject_ambiguous_product_identity() -> None:
    document = {
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "duplicate",
                    "product_identification_helper": {"purl": "pkg:pypi/evil@1"},
                },
                {
                    "product_id": "duplicate",
                    "product_identification_helper": {"purl": "pkg:pypi/expected@1"},
                },
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2099-1",
                "notes": [{"text": "Original Vexcalibur analysis state: in_triage"}],
                "product_status": {"under_investigation": ["duplicate"]},
            }
        ],
    }

    with pytest.raises(release_evidence.EvidenceError, match="duplicate product_id"):
        release_evidence._csaf_assertions(document)


@pytest.mark.parametrize(
    "product",
    [
        {
            "@id": "pkg:pypi/evil@1",
            "identifiers": {"purl": "pkg:pypi/expected@1"},
        },
        {
            "@id": "pkg:pypi/expected@1",
            "identifiers": {"purl": "pkg:pypi/expected@1"},
            "subcomponents": [{"@id": "pkg:pypi/evil@1"}],
        },
    ],
)
def test_openvex_assertions_reject_ambiguous_product_identity(
    product: dict[str, object],
) -> None:
    document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2099-1"},
                "status": "under_investigation",
                "status_notes": "Original Vexcalibur analysis state: in_triage",
                "products": [product],
            }
        ]
    }

    with pytest.raises(release_evidence.EvidenceError, match="OpenVEX product"):
        release_evidence._openvex_assertions(document)


def test_openvex_assertions_reject_ambiguous_vulnerability_identity() -> None:
    document = {
        "statements": [
            {
                "vulnerability": {
                    "name": "CVE-2099-1",
                    "@id": "https://evil.example/CVE-2099-2",
                },
                "status": "under_investigation",
                "status_notes": "Original Vexcalibur analysis state: in_triage",
                "products": [
                    {
                        "@id": "pkg:pypi/expected@1",
                        "identifiers": {"purl": "pkg:pypi/expected@1"},
                    }
                ],
            }
        ]
    }

    with pytest.raises(release_evidence.EvidenceError, match="vulnerability identity"):
        release_evidence._openvex_assertions(document)


def test_zero_finding_manifest_records_omissions_and_sorted_checksums(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for source, name in (
        (PRODUCTION_REVIEW, "review.json"),
        (PRODUCTION_FINDINGS, "findings.json"),
    ):
        (bundle / name).write_bytes(source.read_bytes())
    (bundle / "runtime-constraints.txt").write_text("example==1 --hash=sha256:abc\n")
    (bundle / "sbom.cdx.json").write_text("{}\n")
    (bundle / "vex.cdx.json").write_text("{}\n")
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(wheel, commit="a" * 40)

    manifest = release_evidence.build_manifest(
        bundle_dir=bundle,
        release_sha="a" * 40,
        release_version="0.4.0",
        source_date_epoch=1_784_135_156,
        lock_path=LOCK,
        wheel_path=wheel,
        review_path=bundle / "review.json",
        findings_path=bundle / "findings.json",
        uv_version="0.11.17",
        source_tree_clean=True,
    )
    (bundle / "manifest.json").write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(bundle)
    release_evidence.verify_bundle(bundle)

    assert manifest["review"]["assertion_count"] == 0
    assert manifest["review"]["state_counts"] == {}
    assert manifest["intended_use"] == "release_evidence_candidate"
    assert manifest["source_tree_clean"] is True
    assert manifest["generator"]["wheel_source_commit"] == "a" * 40
    assert manifest["generator"]["wheel_source_dirty"] is False
    assert manifest["formats"]["openvex"]["status"] == "omitted"
    assert "zero findings" in manifest["formats"]["openvex"]["reason"]
    assert "zero VEX assertions" in manifest["formats"]["csaf"]["reason"]
    checksum_lines = (bundle / "SHA256SUMS").read_text().splitlines()
    checksum_names = [line.split("  ", maxsplit=1)[1] for line in checksum_lines]
    assert checksum_names == sorted(checksum_names)
    assert checksum_lines[-1].endswith("  vex.cdx.json")


def test_manifest_rejects_selector_alias_assertion_overcount(tmp_path: Path) -> None:
    review = copy.deepcopy(release_evidence.load_json(FIXTURE_REVIEW))
    findings_document = copy.deepcopy(release_evidence.load_json(FIXTURE_FINDINGS))
    alias = copy.deepcopy(findings_document["findings"][0])
    alias.pop("purl")
    alias["component_ref"] = "httpx-ref"
    findings_document["findings"].append(alias)

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    findings_path = bundle / "findings.json"
    findings_path.write_text(release_evidence.canonical_json(findings_document))
    review["findings"]["sha256"] = _grouped_digest(findings_path)
    review_path = bundle / "review.json"
    review_path.write_text(release_evidence.canonical_json(review))
    (bundle / "runtime-constraints.txt").write_text("example==1 --hash=sha256:abc\n")
    (bundle / "sbom.cdx.json").write_text("{}\n")
    (bundle / "vex.openvex.json").write_text("{}\n")
    (bundle / "vexcalibur-vex.json").write_text("{}\n")
    cyclonedx = {
        "components": [
            {
                "bom-ref": "httpx-ref",
                "purl": "pkg:pypi/httpx@0.28.1",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2099-999999",
                "analysis": {"state": "in_triage"},
                "affects": [{"ref": "httpx-ref"}],
            }
        ],
    }
    (bundle / "vex.cdx.json").write_text(release_evidence.canonical_json(cyclonedx))
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    _write_test_wheel(wheel, commit="a" * 40)

    with pytest.raises(
        release_evidence.EvidenceError,
        match="reviewed assertion count does not match canonical CycloneDX output",
    ):
        release_evidence.build_manifest(
            bundle_dir=bundle,
            release_sha="a" * 40,
            release_version="0.4.0",
            source_date_epoch=1_784_135_156,
            lock_path=LOCK,
            wheel_path=wheel,
            review_path=review_path,
            findings_path=findings_path,
            uv_version="0.11.17",
            source_tree_clean=True,
        )


def test_checksum_verifier_rejects_a_modified_artifact(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name in ("manifest.json", "one.txt"):
        (bundle / name).write_text("{}\n")
    release_evidence.write_checksums(bundle)
    (bundle / "one.txt").write_text("changed\n")

    with pytest.raises(release_evidence.EvidenceError, match="digest mismatch"):
        release_evidence.verify_bundle(bundle)


def test_checksum_verifier_rejects_duplicate_manifest_artifacts(tmp_path: Path) -> None:
    bundle = _write_integrity_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
    manifest_path.write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(bundle)

    with pytest.raises(release_evidence.EvidenceError, match="duplicate manifest artifact"):
        release_evidence.verify_bundle(bundle)


def test_checksum_verifier_rejects_incorrect_manifest_size(tmp_path: Path) -> None:
    bundle = _write_integrity_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"][0]["size"] += 1
    manifest_path.write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(bundle)

    with pytest.raises(release_evidence.EvidenceError, match="artifact size mismatch"):
        release_evidence.verify_bundle(bundle)


def test_hashed_file_uri_is_absolute_encoded_and_digest_bound(tmp_path: Path) -> None:
    artifact = tmp_path / "wheel with spaces.whl"
    artifact.write_bytes(b"wheel bytes")

    uri = release_evidence.hashed_file_uri(artifact)

    assert uri.startswith("file://")
    assert "wheel%20with%20spaces.whl" in uri
    assert uri.endswith(f"#sha256={release_evidence.sha256_file(artifact)}")


@pytest.mark.parametrize(
    "body",
    [
        "example>=1 \\\n    --hash=sha256:" + "a" * 64 + "\n",
        "example @ https://example.test/example.whl \\\n    --hash=sha256:" + "a" * 64 + "\n",
        "--find-links https://example.test/simple\n",
        "-r another.txt\n",
        "example==1\n",
        "example==1 \\\n    --hash=sha256:" + "a" * 64 + " \\\n    --no-binary :all:\n",
    ],
)
def test_runtime_constraints_reject_weakened_entries(tmp_path: Path, body: str) -> None:
    constraints = tmp_path / "constraints.txt"
    constraints.write_text("--require-hashes\n--only-binary :all:\n\n" + body)

    with pytest.raises(release_evidence.EvidenceError, match="runtime constraint"):
        release_evidence._validate_runtime_constraints(constraints)


def test_publication_inventory_rejects_self_checksummed_constraint_forgery(
    tmp_path: Path,
) -> None:
    inventory, _ = _write_zero_publication_inventory(tmp_path)
    constraints = inventory / "runtime-constraints.txt"
    constraints.write_text(
        "--require-hashes\n--only-binary :all:\n\n--find-links https://example.test/simple\n"
    )
    manifest_path = inventory / "manifest.json"
    manifest = release_evidence.load_json(manifest_path)
    record = next(
        item for item in manifest["artifacts"] if item["name"] == "runtime-constraints.txt"
    )
    record["sha256"] = release_evidence.sha256_file(constraints)
    record["size"] = constraints.stat().st_size
    manifest_path.write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(inventory)

    with pytest.raises(release_evidence.EvidenceError, match="runtime constraint"):
        release_evidence.verify_publication_inventory(
            inventory_dir=inventory,
            expected_release_sha="a" * 40,
            expected_release_version="0.4.0",
        )


def test_publication_finalization_binds_distributions_and_action_output(tmp_path: Path) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)
    action_commit = release_evidence.PUBLICATION_ACTION_COMMIT
    bundle = tmp_path / "publication"

    release_evidence.finalize_publication_bundle(
        output_dir=bundle,
        inventory_dir=inventory,
        wheel_path=wheel,
        sdist_path=sdist,
        direct_output_dir=direct_output,
        action_output_dir=action_output,
        release_tag="v0.4.0",
        action_commit=action_commit,
        expected_wheel_sha256=release_evidence.sha256_file(wheel),
        expected_sdist_sha256=release_evidence.sha256_file(sdist),
    )
    release_evidence.verify_publication_bundle(
        bundle_dir=bundle,
        expected_release_tag="v0.4.0",
        expected_release_sha="a" * 40,
        expected_action_commit=action_commit,
    )
    release_evidence.verify_publication_bundle(
        bundle_dir=bundle,
        expected_release_tag="v0.4.0",
        expected_release_sha="a" * 40,
        expected_action_commit=None,
    )

    manifest = release_evidence.load_json(bundle / "manifest.json")
    assert manifest["schema_version"] == 2
    assert manifest["intended_use"] == "immutable_release_candidate"
    assert manifest["publication"]["release_tag"] == "v0.4.0"
    assert manifest["publication"]["action"]["commit"] == action_commit
    assert (
        manifest["publication"]["payload_digest_algorithm"]
        == release_evidence.PAYLOAD_DIGEST_ALGORITHM
    )
    assert (
        manifest["publication"]["action"]["payload_sha256"]
        == manifest["publication"]["direct_generation"]["payload_sha256"]
    )
    assert manifest["validation"]["action_local_wheel_equivalence"] == "passed"
    assert (bundle / wheel.name).read_bytes() == wheel.read_bytes()
    assert (bundle / sdist.name).read_bytes() == sdist.read_bytes()
    assert (bundle / "uv.lock").read_bytes() == LOCK.read_bytes()
    checksum_names = {
        line.split("  ", maxsplit=1)[1] for line in (bundle / "SHA256SUMS").read_text().splitlines()
    }
    assert wheel.name in checksum_names
    assert sdist.name in checksum_names


def test_publication_assets_are_reproducible_across_recovery_runs(tmp_path: Path) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)

    bundles = [tmp_path / "first-publication", tmp_path / "recovery-publication"]
    for bundle in bundles:
        release_evidence.finalize_publication_bundle(
            output_dir=bundle,
            inventory_dir=inventory,
            wheel_path=wheel,
            sdist_path=sdist,
            direct_output_dir=direct_output,
            action_output_dir=action_output,
            release_tag="v0.4.0",
            action_commit=release_evidence.PUBLICATION_ACTION_COMMIT,
            expected_wheel_sha256=release_evidence.sha256_file(wheel),
            expected_sdist_sha256=release_evidence.sha256_file(sdist),
        )

    first_files = {path.name: path.read_bytes() for path in bundles[0].iterdir()}
    recovery_files = {path.name: path.read_bytes() for path in bundles[1].iterdir()}
    assert recovery_files == first_files


def test_publication_finalization_rejects_action_mismatch_before_copy(
    tmp_path: Path,
) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    action_output.mkdir()
    (action_output / "vex.cdx.json").write_text("different\n")
    bundle = tmp_path / "publication"

    with pytest.raises(release_evidence.EvidenceError, match="Action output differs"):
        release_evidence.finalize_publication_bundle(
            output_dir=bundle,
            inventory_dir=inventory,
            wheel_path=wheel,
            sdist_path=sdist,
            direct_output_dir=direct_output,
            action_output_dir=action_output,
            release_tag="v0.4.0",
            action_commit=release_evidence.PUBLICATION_ACTION_COMMIT,
            expected_wheel_sha256=release_evidence.sha256_file(wheel),
            expected_sdist_sha256=release_evidence.sha256_file(sdist),
        )

    assert not bundle.exists()


def test_publication_finalization_never_clobbers_an_existing_asset(tmp_path: Path) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)
    bundle = tmp_path / "publication"
    bundle.mkdir()
    existing = bundle / wheel.name
    existing.write_bytes(b"must not be replaced")

    with pytest.raises(release_evidence.EvidenceError, match="output already exists"):
        release_evidence.finalize_publication_bundle(
            output_dir=bundle,
            inventory_dir=inventory,
            wheel_path=wheel,
            sdist_path=sdist,
            direct_output_dir=direct_output,
            action_output_dir=action_output,
            release_tag="v0.4.0",
            action_commit=release_evidence.PUBLICATION_ACTION_COMMIT,
            expected_wheel_sha256=release_evidence.sha256_file(wheel),
            expected_sdist_sha256=release_evidence.sha256_file(sdist),
        )

    assert existing.read_bytes() == b"must not be replaced"


def test_publication_verifier_rejects_a_coherently_checksummed_extra_asset(
    tmp_path: Path,
) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)
    action_commit = release_evidence.PUBLICATION_ACTION_COMMIT
    bundle = tmp_path / "publication"
    release_evidence.finalize_publication_bundle(
        output_dir=bundle,
        inventory_dir=inventory,
        wheel_path=wheel,
        sdist_path=sdist,
        direct_output_dir=direct_output,
        action_output_dir=action_output,
        release_tag="v0.4.0",
        action_commit=action_commit,
        expected_wheel_sha256=release_evidence.sha256_file(wheel),
        expected_sdist_sha256=release_evidence.sha256_file(sdist),
    )
    extra = bundle / "unexpected.txt"
    extra.write_text("unexpected\n")
    manifest_path = bundle / "manifest.json"
    manifest = release_evidence.load_json(manifest_path)
    manifest["artifacts"].append(
        {
            "name": extra.name,
            "sha256": release_evidence.sha256_file(extra),
            "size": extra.stat().st_size,
        }
    )
    manifest["artifacts"].sort(key=lambda record: record["name"])
    manifest_path.write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(bundle)

    with pytest.raises(release_evidence.EvidenceError, match="asset file set differs"):
        release_evidence.verify_publication_bundle(
            bundle_dir=bundle,
            expected_release_tag="v0.4.0",
            expected_release_sha="a" * 40,
            expected_action_commit=action_commit,
        )


def test_publication_requires_clean_production_evidence(tmp_path: Path) -> None:
    with pytest.raises(release_evidence.EvidenceError, match="clean source tree"):
        _write_zero_publication_inventory(tmp_path, source_tree_clean=False)


@pytest.mark.parametrize(
    "timestamp",
    ["2026-07-15 17:05:56Z", "20260715T170556Z", "2026-07-15T17:05Z"],
)
def test_timestamp_parser_requires_rfc3339_extended_utc(timestamp: str) -> None:
    with pytest.raises(release_evidence.EvidenceError, match="RFC 3339 UTC"):
        release_evidence._parse_timestamp(timestamp, field="reviewed_at")


def test_review_digests_require_grouped_hexadecimal() -> None:
    review = copy.deepcopy(release_evidence.load_json(PRODUCTION_REVIEW))
    review["inventory"]["sha256"] = release_evidence.sha256_file(LOCK)

    with pytest.raises(release_evidence.EvidenceError, match="colon-delimited groups"):
        release_evidence.validate_review(
            review,
            release_evidence.load_json(PRODUCTION_FINDINGS),
            lock_path=LOCK,
            findings_path=PRODUCTION_FINDINGS,
        )


def test_output_move_is_no_clobber_and_no_target_directory(tmp_path: Path) -> None:
    script = (ROOT / "scripts" / "generate-release-evidence.sh").read_text()
    assert 'mv --no-clobber --no-target-directory -- "$staging_dir" "$output_dir"' in script
    assert 'if [[ -d "$staging_dir" ]]; then' in script

    staging = tmp_path / "staging"
    output = tmp_path / "output"
    staging.mkdir()
    output.mkdir()
    (staging / "artifact").write_text("must not move\n")
    completed = subprocess.run(  # noqa: S603 - fixed GNU mv and test-owned paths
        ["/usr/bin/mv", "--no-clobber", "--no-target-directory", "--", staging, output],
        check=False,
        capture_output=True,
    )
    # GNU coreutils 8 reports a no-clobber collision as success, while newer
    # versions report failure. The security invariant is identical either way.
    assert completed.returncode in {0, 1}
    assert (staging / "artifact").is_file()
    assert list(output.iterdir()) == []
