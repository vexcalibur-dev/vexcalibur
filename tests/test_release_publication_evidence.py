from __future__ import annotations

import copy
import hashlib
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
        f"__version__ = version = '{version}'\n__commit_id__ = commit_id = 'g{commit}'\n"
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
    document = release_evidence.canonical_json(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
    )
    (path / "vex.cdx.json").write_text(document)
    (path / "vex.cdx.execution.json").write_text(
        release_evidence._canonical_execution_report_json(
            {
                "analysis_state_counts": {},
                "command": "generate",
                "component_count": 1,
                "document": {
                    "bytes": len(document.encode()),
                    "sha256": hashlib.sha256(document.encode()).hexdigest(),
                },
                "finding_count": 0,
                "finding_source": "local_file",
                "inventory_source": "sbom_file",
                "output_format": "cyclonedx",
                "schema_version": 1,
                "vexcalibur_version": "0.4.0",
            }
        )
    )


def _valid_execution_report_document() -> dict[str, object]:
    document = b'{"ok":true}\n'
    return {
        "analysis_state_counts": {"in_triage": 1},
        "command": "generate",
        "component_count": 1,
        "document": {
            "bytes": len(document),
            "sha256": hashlib.sha256(document).hexdigest(),
        },
        "finding_count": 1,
        "finding_source": "local_file",
        "inventory_source": "sbom_file",
        "output_format": "cyclonedx",
        "schema_version": 1,
        "vexcalibur_version": "0.5.0",
    }


def test_publication_report_binds_analysis_states_to_reviewed_findings(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "vex.cdx.json").write_bytes(b'{"ok":true}\n')
    (output / "vex.cdx.execution.json").write_text(
        release_evidence._canonical_execution_report_json(_valid_execution_report_document())
    )

    with pytest.raises(release_evidence.EvidenceError, match="analysis-state counts"):
        release_evidence._verify_execution_reports(
            output_dir=output,
            assertion_count=1,
            expected_state_counts={"exploitable": 1},
            expected_component_count=1,
            release_version="0.5.0",
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


def test_publication_bundle_requires_exact_integer_schema_version(tmp_path: Path) -> None:
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
    manifest_path = bundle / "manifest.json"
    manifest = release_evidence.load_json(manifest_path)
    manifest["schema_version"] = 2.0
    manifest_path.write_text(release_evidence.canonical_json(manifest))
    release_evidence.write_checksums(bundle)

    with pytest.raises(
        release_evidence.EvidenceError,
        match="publication manifest schema version must be 2",
    ):
        release_evidence.verify_publication_bundle(
            bundle_dir=bundle,
            expected_release_tag="v0.4.0",
            expected_release_sha="a" * 40,
            expected_action_commit=action_commit,
        )


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
    _write_zero_vex_output(action_output)
    changed_document = b"different\n"
    (action_output / "vex.cdx.json").write_bytes(changed_document)
    action_report_path = action_output / "vex.cdx.execution.json"
    action_report = release_evidence.load_json(action_report_path)
    action_report["document"] = {
        "bytes": len(changed_document),
        "sha256": hashlib.sha256(changed_document).hexdigest(),
    }
    action_report_path.write_text(release_evidence._canonical_execution_report_json(action_report))
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


def test_publication_finalization_rejects_invalid_execution_report(
    tmp_path: Path,
) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)
    for output in (direct_output, action_output):
        report_path = output / "vex.cdx.execution.json"
        report = release_evidence.load_json(report_path)
        report["document"]["sha256"] = "0" * 64
        report_path.write_text(release_evidence._canonical_execution_report_json(report))
    bundle = tmp_path / "publication"

    with pytest.raises(release_evidence.EvidenceError, match="document binding"):
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


def test_publication_finalization_rejects_coherently_forged_component_counts(
    tmp_path: Path,
) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)
    for output in (direct_output, action_output):
        report_path = output / "vex.cdx.execution.json"
        report = release_evidence.load_json(report_path)
        report["component_count"] = 999_999
        report_path.write_text(release_evidence._canonical_execution_report_json(report))
    bundle = tmp_path / "publication"

    with pytest.raises(release_evidence.EvidenceError, match="component count"):
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


def test_publication_finalization_rejects_noncanonical_execution_report_bytes(
    tmp_path: Path,
) -> None:
    inventory, wheel = _write_zero_publication_inventory(tmp_path)
    sdist = tmp_path / "vexcalibur-0.4.0.tar.gz"
    _write_test_sdist(sdist)
    direct_output = tmp_path / "direct-output"
    _write_zero_vex_output(direct_output)
    action_output = tmp_path / "action-output"
    _write_zero_vex_output(action_output)
    for output in (direct_output, action_output):
        report_path = output / "vex.cdx.execution.json"
        report = release_evidence.load_json(report_path)
        report_path.write_text(release_evidence.canonical_json(report))
    bundle = tmp_path / "publication"

    with pytest.raises(release_evidence.EvidenceError, match="not canonical JSON"):
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
