from __future__ import annotations

import copy
import json
import stat
import subprocess
import zipfile
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
    )
    assert completed.returncode == 0
    assert (staging / "artifact").is_file()
    assert list(output.iterdir()) == []
