from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import scripts.execution_report_oracle as oracle_module
from scripts.execution_report_oracle import (
    MAX_FINDINGS_BYTES,
    ExecutionReportOracleError,
    _component_identity_count,
    canonical_execution_report_json,
    verify_action_generation,
    verify_publication_manifest,
)

ROOT = Path(__file__).parents[1]
ORACLE = ROOT / "scripts" / "execution_report_oracle.py"
VERSION = "1.2.3"
RELEASE_SHA = ("0123456789abcdef" * 2) + "01234567"
RELEASE_TIMESTAMP = "2026-07-29T12:00:00Z"


def _write_valid_inputs(root: Path) -> dict[str, Path]:
    document = root / "vex.json"
    report = root / "execution-report.json"
    findings = root / "findings.json"
    sbom = root / "sbom.cdx.json"
    manifest = root / "manifest.json"
    document_bytes = b'{"bomFormat":"CycloneDX"}\n'
    document.write_bytes(document_bytes)
    findings.write_text(
        '{"findings":[{"analysis_state":"in_triage"}]}\n',
        encoding="utf-8",
    )
    sbom.write_text(
        '{"components":[{"bom-ref":"component-a","purl":"pkg:pypi/component-a@1"}]}\n',
        encoding="utf-8",
    )
    report.write_text(
        canonical_execution_report_json(
            {
                "schema_version": 1,
                "command": "generate",
                "vexcalibur_version": VERSION,
                "inventory_source": "sbom_file",
                "finding_source": "local_file",
                "output_format": "cyclonedx",
                "component_count": 1,
                "finding_count": 1,
                "analysis_state_counts": {"in_triage": 1},
                "document": {
                    "sha256": hashlib.sha256(document_bytes).hexdigest(),
                    "bytes": len(document_bytes),
                },
            }
        ),
        encoding="ascii",
    )
    manifest.write_text(
        json.dumps(
            {
                "artifacts": [],
                "inventory": {},
                "inventory_kind": "publication_oracle",
                "release": {
                    "commit": RELEASE_SHA,
                    "purl": f"pkg:pypi/vexcalibur@{VERSION}",
                    "source_date_epoch": 1_785_326_400,
                    "timestamp": RELEASE_TIMESTAMP,
                    "version": VERSION,
                },
                "review": {},
                "schema_version": 1,
                "source_tree_clean": True,
                "uv_version": "0.11.17",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "report": report,
        "document": document,
        "findings": findings,
        "sbom": sbom,
        "manifest": manifest,
    }


def _verify(paths: dict[str, Path]) -> None:
    verify_publication_manifest(
        manifest_path=paths["manifest"],
        expected_sha=RELEASE_SHA,
        expected_version=VERSION,
        expected_timestamp=RELEASE_TIMESTAMP,
    )
    verify_action_generation(
        report_path=paths["report"],
        document_path=paths["document"],
        findings_path=paths["findings"],
        sbom_path=paths["sbom"],
        expected_version=VERSION,
    )


def test_action_generation_oracle_accepts_bound_inputs(tmp_path: Path) -> None:
    _verify(_write_valid_inputs(tmp_path))


def test_oracle_opens_bound_inputs_in_binary_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "binary-input.json"
    payload = b"before\r\nafter\x1aend"
    path.write_bytes(payload)
    real_open = oracle_module.os.open
    native_binary_flag = hasattr(oracle_module.os, "O_BINARY")
    binary_flag = getattr(oracle_module.os, "O_BINARY", 1 << 29)
    observed_flags = 0

    def track_binary_flag(selected_path: Path, flags: int) -> int:
        nonlocal observed_flags
        observed_flags = flags
        native_flags = flags if native_binary_flag else flags & ~binary_flag
        return real_open(selected_path, native_flags)

    monkeypatch.setattr(oracle_module.os, "O_BINARY", binary_flag, raising=False)
    monkeypatch.setattr(oracle_module.os, "open", track_binary_flag)

    result = oracle_module.read_bounded_regular_file(
        path,
        max_bytes=len(payload),
        field="test input",
    )

    assert observed_flags & binary_flag
    assert result == payload


def test_component_oracle_accepts_production_depth_boundary() -> None:
    component: dict[str, object] = {
        "bom-ref": "component-50",
        "purl": "pkg:pypi/component-50@1",
    }
    for depth in reversed(range(50)):
        component = {
            "bom-ref": f"component-{depth}",
            "purl": f"pkg:pypi/component-{depth}@1",
            "components": [component],
        }

    assert _component_identity_count({"components": [component]}) == 51


def test_component_oracle_rejects_beyond_production_depth_boundary() -> None:
    component: dict[str, object] = {
        "bom-ref": "component-51",
        "purl": "pkg:pypi/component-51@1",
    }
    for depth in reversed(range(51)):
        component = {
            "bom-ref": f"component-{depth}",
            "purl": f"pkg:pypi/component-{depth}@1",
            "components": [component],
        }

    with pytest.raises(ExecutionReportOracleError, match="nesting limit"):
        _component_identity_count({"components": [component]})


def test_publication_manifest_oracle_rejects_boolean_schema_version(
    tmp_path: Path,
) -> None:
    paths = _write_valid_inputs(tmp_path)
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    manifest["schema_version"] = True
    paths["manifest"].write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    with pytest.raises(ExecutionReportOracleError, match="schema_version"):
        _verify(paths)


def test_publication_manifest_oracle_rejects_release_mismatch(
    tmp_path: Path,
) -> None:
    paths = _write_valid_inputs(tmp_path)
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    manifest["release"]["commit"] = "f" * 40
    paths["manifest"].write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    with pytest.raises(ExecutionReportOracleError, match="release commit"):
        _verify(paths)


def test_action_generation_oracle_rejects_boolean_schema_version(
    tmp_path: Path,
) -> None:
    paths = _write_valid_inputs(tmp_path)
    report = json.loads(paths["report"].read_text(encoding="ascii"))
    report["schema_version"] = True
    paths["report"].write_text(
        canonical_execution_report_json(report),
        encoding="ascii",
    )

    with pytest.raises(ExecutionReportOracleError, match="schema_version"):
        _verify(paths)


def test_action_generation_oracle_rejects_replaced_inventory(tmp_path: Path) -> None:
    paths = _write_valid_inputs(tmp_path)
    paths["sbom"].write_text('{"components":[]}\n', encoding="utf-8")

    with pytest.raises(
        ExecutionReportOracleError,
        match="no reportable component",
    ):
        _verify(paths)


def test_action_generation_oracle_bounds_inventory_before_parsing(
    tmp_path: Path,
) -> None:
    paths = _write_valid_inputs(tmp_path)
    paths["findings"].write_bytes(b"x" * (MAX_FINDINGS_BYTES + 1))

    with pytest.raises(ExecutionReportOracleError, match="byte limit"):
        _verify(paths)


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"),
    reason="symlinks are unavailable",
)
def test_action_generation_oracle_rejects_report_symlink(tmp_path: Path) -> None:
    paths = _write_valid_inputs(tmp_path)
    target = paths["report"].with_name("report-target.json")
    paths["report"].replace(target)
    paths["report"].symlink_to(target)

    with pytest.raises(ExecutionReportOracleError, match="could not open"):
        _verify(paths)


def test_optimized_python_cannot_disable_boolean_rejection(tmp_path: Path) -> None:
    paths = _write_valid_inputs(tmp_path)
    report = json.loads(paths["report"].read_text(encoding="ascii"))
    report["schema_version"] = True
    paths["report"].write_text(
        canonical_execution_report_json(report),
        encoding="ascii",
    )

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed local script
        [
            sys.executable,
            "-I",
            "-O",
            str(ORACLE),
            "--report",
            str(paths["report"]),
            "--document",
            str(paths["document"]),
            "--findings",
            str(paths["findings"]),
            "--sbom",
            str(paths["sbom"]),
            "--manifest",
            str(paths["manifest"]),
            "--expected-sha",
            RELEASE_SHA,
            "--expected-version",
            VERSION,
            "--expected-timestamp",
            RELEASE_TIMESTAMP,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "schema_version" in completed.stderr
