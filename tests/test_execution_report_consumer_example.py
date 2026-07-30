from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "examples" / "validate_execution_report.py"
GENERATION_EXAMPLE = ROOT / "docs" / "examples" / "generate_execution_report.py"
CUSTOM_GENERATION_EXAMPLE = ROOT / "docs" / "examples" / "generate_custom_execution_report.py"
SCHEMA = Path(
    os.environ.get(
        "VEXCALIBUR_EXECUTION_REPORT_SCHEMA",
        ROOT / "docs" / "execution-report-v1.schema.json",
    )
)
SPEC = importlib.util.spec_from_file_location(
    "vexcalibur_execution_report_consumer_example",
    EXAMPLE,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load execution-report consumer example")
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


def _report(document: bytes) -> dict[str, object]:
    return {
        "schema_version": 1,
        "command": "generate",
        "vexcalibur_version": "0.5.0",
        "inventory_source": "sbom_file",
        "finding_source": "local_file",
        "output_format": "cyclonedx",
        "component_count": 1,
        "finding_count": 1,
        "analysis_state_counts": {"in_triage": 1},
        "document": {
            "sha256": hashlib.sha256(document).hexdigest(),
            "bytes": len(document),
        },
    }


def _write_pair(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    document = b'{"bomFormat":"CycloneDX"}\n'
    document_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    report = _report(document)
    document_path.write_bytes(document)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path, document_path, report


def test_consumer_example_accepts_a_matching_report(tmp_path: Path) -> None:
    report_path, document_path, expected_report = _write_pair(tmp_path)

    assert consumer.validate_execution_report(report_path, document_path, SCHEMA) == expected_report

    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(EXAMPLE),
            str(report_path),
            str(document_path),
            str(SCHEMA),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "execution report verified\n"


def test_consumer_example_applies_an_exploitable_count_policy(
    tmp_path: Path,
) -> None:
    report_path, document_path, report = _write_pair(tmp_path)
    report["analysis_state_counts"] = {"exploitable": 1}
    report_path.write_text(json.dumps(report), encoding="utf-8")

    accepted = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(EXAMPLE),
            str(report_path),
            str(document_path),
            str(SCHEMA),
            "--max-exploitable",
            "1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    rejected = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(EXAMPLE),
            str(report_path),
            str(document_path),
            str(SCHEMA),
            "--max-exploitable",
            "0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert accepted.returncode == 0
    assert accepted.stdout == "execution report verified\n"
    assert accepted.stderr == ""
    assert rejected.returncode == 1
    assert rejected.stdout == ""
    assert rejected.stderr == ("execution report rejected: exploitable count 1 exceeds maximum 0\n")


def test_consumer_example_rejects_a_negative_policy_limit(tmp_path: Path) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)

    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(EXAMPLE),
            str(report_path),
            str(document_path),
            str(SCHEMA),
            "--max-exploitable",
            "-1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "must be a nonnegative integer" in result.stderr


def test_python_api_generation_example_writes_a_matching_pair(
    tmp_path: Path,
) -> None:
    output_directory = tmp_path / "generated"
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GENERATION_EXAMPLE), str(output_directory)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    document_path = output_directory / "vex.json"
    report_path = output_directory / "execution-report.json"
    consumer.validate_execution_report(report_path, document_path, SCHEMA)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    document = document_path.read_bytes()
    assert report["document"] == {
        "bytes": len(document),
        "sha256": hashlib.sha256(document).hexdigest(),
    }
    if os.name != "nt":
        assert output_directory.stat().st_mode & 0o777 == 0o700
        assert document_path.stat().st_mode & 0o777 == 0o600
        assert report_path.stat().st_mode & 0o777 == 0o600
    assert str(document_path) in result.stdout
    assert str(report_path) in result.stdout


def test_custom_python_api_execution_report_example_runs() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(CUSTOM_GENERATION_EXAMPLE)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert '"output_format":"custom"' in result.stdout


def test_consumer_example_rejects_duplicate_keys(tmp_path: Path) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    report_path.write_text(
        report_path.read_text(encoding="utf-8").replace(
            '"command": "generate"',
            '"command": "generate", "command": "generate"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON key"):
        consumer.validate_execution_report(report_path, document_path, SCHEMA)


def test_consumer_example_rejects_an_oversized_report(tmp_path: Path) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    report_path.write_text(
        report_path.read_text(encoding="utf-8") + (" " * (16 * 1024)),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exceeds 16 KiB"):
        consumer.validate_execution_report(report_path, document_path, SCHEMA)


@pytest.mark.parametrize(
    "role",
    ("execution report", "execution report schema"),
)
def test_consumer_example_normalizes_json_recursion_errors(
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    def raise_recursion_error(*_args: object, **_kwargs: object) -> object:
        raise RecursionError

    monkeypatch.setattr(consumer.json, "loads", raise_recursion_error)
    with pytest.raises(ValueError, match=rf"^{role} is too deeply nested$"):
        consumer._decode_json_object(b"{}", role=role)


def test_consumer_example_normalizes_schema_validation_recursion_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    nested_schema: dict[str, object] = {"type": "object"}
    for _ in range(150):
        nested_schema = {"allOf": [nested_schema]}
    monkeypatch.setattr(consumer, "_read_schema", lambda _path: nested_schema)

    with pytest.raises(ValueError, match="schema is too deeply nested"):
        consumer.validate_execution_report(report_path, document_path, SCHEMA)


def test_consumer_example_checks_its_document_limit_before_schema_validation(
    tmp_path: Path,
) -> None:
    report_path, _, report = _write_pair(tmp_path)
    document = report["document"]
    assert isinstance(document, dict)
    document["bytes"] = consumer.MAX_DOCUMENT_BYTES + 1
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds the 25 MiB"):
        consumer.validate_execution_report(
            report_path,
            tmp_path / "document-must-not-be-opened",
            SCHEMA,
        )


def test_consumer_example_rejects_inconsistent_counts(tmp_path: Path) -> None:
    report_path, document_path, report = _write_pair(tmp_path)
    report["finding_count"] = 2
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="do not sum"):
        consumer.validate_execution_report(report_path, document_path, SCHEMA)


def test_consumer_example_rejects_substituted_schemas_before_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    schema_path = tmp_path / "remote-reference.schema.json"
    schema_path.write_text(
        '{"$ref":"https://schemas.example.test/execution-report.json"}',
        encoding="utf-8",
    )

    def unexpected_schema_validation(_schema: object) -> None:
        raise AssertionError("substituted schema reached jsonschema")

    monkeypatch.setattr(
        consumer.Draft202012Validator,
        "check_schema",
        unexpected_schema_validation,
    )
    with pytest.raises(ValueError, match="does not match the reviewed schema"):
        consumer.validate_execution_report(report_path, document_path, schema_path)


def test_consumer_example_rejects_pathological_regex_schema_before_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, document_path, report = _write_pair(tmp_path)
    report["vexcalibur_version"] = ("a" * 30) + "!"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    schema_path = tmp_path / "pathological.schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "type": "object",
                "properties": {
                    "vexcalibur_version": {
                        "type": "string",
                        "pattern": "^(a+)+$",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    def unexpected_schema_validation(_schema: object) -> None:
        raise AssertionError("pathological schema reached jsonschema")

    monkeypatch.setattr(
        consumer.Draft202012Validator,
        "check_schema",
        unexpected_schema_validation,
    )
    with pytest.raises(ValueError, match="does not match the reviewed schema"):
        consumer.validate_execution_report(report_path, document_path, schema_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("bytes", 1, "byte count"),
        ("sha256", "0" * 64, "digest"),
    ),
)
def test_consumer_example_rejects_document_metadata_mismatch(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    report_path, document_path, report = _write_pair(tmp_path)
    document = report["document"]
    assert isinstance(document, dict)
    document[field] = value
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        consumer.validate_execution_report(report_path, document_path, SCHEMA)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
@pytest.mark.parametrize("fifo_role", ("report", "document", "schema"))
def test_consumer_example_rejects_fifos_without_blocking(
    tmp_path: Path,
    fifo_role: str,
) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    schema_path = SCHEMA
    fifo_path = tmp_path / f"{fifo_role}.fifo"
    os.mkfifo(fifo_path)
    if fifo_role == "report":
        report_path = fifo_path
    elif fifo_role == "document":
        document_path = fifo_path
    else:
        schema_path = fifo_path

    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(EXAMPLE),
            str(report_path),
            str(document_path),
            str(schema_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode != 0
    assert "must be a regular file" in result.stderr


@pytest.mark.skipif(not Path("/dev/null").exists(), reason="device file requires POSIX")
@pytest.mark.parametrize("device_role", ("report", "document", "schema"))
def test_consumer_example_rejects_device_files(
    tmp_path: Path,
    device_role: str,
) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    schema_path = SCHEMA
    if device_role == "report":
        report_path = Path("/dev/null")
    elif device_role == "document":
        document_path = Path("/dev/null")
    else:
        schema_path = Path("/dev/null")

    with pytest.raises(ValueError, match="must be a regular file"):
        consumer.validate_execution_report(report_path, document_path, schema_path)


@pytest.mark.parametrize("link_role", ("report", "document", "schema"))
def test_consumer_example_rejects_symbolic_links(
    tmp_path: Path,
    link_role: str,
) -> None:
    report_path, document_path, _ = _write_pair(tmp_path)
    schema_path = SCHEMA
    target = {
        "report": report_path,
        "document": document_path,
        "schema": schema_path,
    }[link_role]
    link = tmp_path / f"{link_role}.link"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")
    if link_role == "report":
        report_path = link
    elif link_role == "document":
        document_path = link
    else:
        schema_path = link

    with pytest.raises(ValueError, match="must not be a symbolic link"):
        consumer.validate_execution_report(report_path, document_path, schema_path)
