from __future__ import annotations

import hashlib
import importlib.metadata
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from packageurl import PackageURL

from tests.integration.check_installed_windows import verify_python_api_report
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VulnerabilityFinding,
)
from vexcalibur.generate import MAX_VEX_OUTPUT_BYTES
from vexcalibur.generation_result import (
    MAX_EXECUTION_REPORT_BYTES,
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GeneratedDocumentMetadata,
    GeneratedDocumentMetadataDict,
    GenerationExecutionContext,
    GenerationExecutionReport,
    GenerationExecutionReportDict,
    GenerationExecutionReportParseError,
    GenerationResult,
    InventorySourceCategory,
    parse_generation_execution_report,
)

EXECUTION_REPORT_SCHEMA_PATH = (
    Path(__file__).parents[1] / "docs" / "execution-report-v1.schema.json"
)


def test_windows_python_api_oracle_matches_cross_platform_contract() -> None:
    verify_python_api_report()


def _component() -> ComponentIdentity:
    return ComponentIdentity(
        ref="component:private-widget",
        name="private-widget",
        version="1.2.3",
        purl=PackageURL.from_string("pkg:pypi/private-widget@1.2.3"),
    )


def _finding(
    state: VexAnalysisState = VexAnalysisState.IN_TRIAGE,
) -> VulnerabilityFinding:
    component = _component()
    return VulnerabilityFinding(
        id="PRIVATE-2026-0001",
        source_name="Internal vulnerability service",
        source_url="https://vulnerabilities.internal.example/PRIVATE-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
        analysis_state=state,
    )


def _report(
    monkeypatch: pytest.MonkeyPatch,
    *,
    findings: tuple[VulnerabilityFinding, ...] = (),
    output_format: ExecutionReportOutputFormat = ExecutionReportOutputFormat.CYCLONEDX,
) -> GenerationExecutionReport:
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2.dev1+g1234567",
    )
    result = GenerationResult(
        rendered_document='{"bomFormat":"CycloneDX"}\n',
        components=(_component(),),
        findings=findings,
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=FindingSourceCategory.LOCAL_FILE,
            output_format=output_format,
        ),
    )
    return result.execution_report()


def test_execution_report_records_exact_document_and_zero_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(monkeypatch)
    document = b'{"bomFormat":"CycloneDX"}\n'

    assert report.to_dict() == {
        "schema_version": 1,
        "command": "generate",
        "vexcalibur_version": "0.4.2.dev1+g1234567",
        "inventory_source": "sbom_file",
        "finding_source": "local_file",
        "output_format": "cyclonedx",
        "component_count": 1,
        "finding_count": 0,
        "analysis_state_counts": {},
        "document": {
            "sha256": hashlib.sha256(document).hexdigest(),
            "bytes": len(document),
        },
    }
    assert report.to_json() == (
        '{"analysis_state_counts":{},"command":"generate","component_count":1,'
        f'"document":{{"bytes":{len(document)},"sha256":'
        f'"{hashlib.sha256(document).hexdigest()}"}},'
        '"finding_count":0,"finding_source":"local_file",'
        '"inventory_source":"sbom_file","output_format":"cyclonedx",'
        '"schema_version":1,"vexcalibur_version":"0.4.2.dev1+g1234567"}\n'
    )


def test_canonical_execution_report_parser_round_trips_typed_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(
        monkeypatch,
        findings=tuple(_finding(state) for state in VexAnalysisState),
        output_format=ExecutionReportOutputFormat.OPENVEX,
    )

    parsed = parse_generation_execution_report(report.to_json().encode("utf-8"))

    assert parsed == report
    assert parsed.to_json() == report.to_json()


def test_execution_report_schema_and_parser_contracts_are_exhaustively_aligned() -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    properties = schema["properties"]

    assert set(schema["required"]) == set(GenerationExecutionReportDict.__required_keys__)
    assert properties["schema_version"]["const"] == 1
    assert properties["command"]["const"] == "generate"
    assert properties["vexcalibur_version"] == {
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[0-9A-Za-z][0-9A-Za-z.!+_-]*$",
        "not": {"pattern": "[^0-9A-Za-z.!+_-]"},
    }
    assert set(properties["inventory_source"]["enum"]) == {
        value.value for value in InventorySourceCategory
    }
    assert set(properties["finding_source"]["enum"]) == {
        value.value for value in FindingSourceCategory
    }
    assert set(properties["output_format"]["enum"]) == {
        value.value for value in ExecutionReportOutputFormat
    }
    assert set(properties["analysis_state_counts"]["properties"]) == {
        state.value for state in VexAnalysisState
    }
    assert set(properties["document"]["required"]) == set(
        GeneratedDocumentMetadataDict.__required_keys__
    )
    assert properties["document"]["properties"]["bytes"]["maximum"] == MAX_VEX_OUTPUT_BYTES


@pytest.mark.parametrize(
    ("field_path", "invalid_value"),
    (
        (("schema_version",), 2),
        (("command",), "scan"),
        (("vexcalibur_version",), ""),
        (("inventory_source",), "private_repository"),
        (("finding_source",), "unknown"),
        (("output_format",), "json"),
        (("component_count",), -1),
        (("finding_count",), -1),
        (("analysis_state_counts", "in_triage"), 0),
        (("analysis_state_counts", "unknown"), 1),
        (("document", "sha256"), "A" * 64),
        (("document", "bytes"), MAX_VEX_OUTPUT_BYTES + 1),
    ),
)
def test_canonical_execution_report_parser_rejects_every_invalid_contract_field(
    monkeypatch: pytest.MonkeyPatch,
    field_path: tuple[str, ...],
    invalid_value: object,
) -> None:
    document = _report(
        monkeypatch,
        findings=(_finding(),),
    ).to_dict()
    target = document
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = invalid_value
    serialized = (
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    )

    with pytest.raises(GenerationExecutionReportParseError):
        parse_generation_execution_report(serialized)


@pytest.mark.parametrize("removed_field", tuple(GenerationExecutionReportDict.__required_keys__))
def test_canonical_execution_report_parser_rejects_missing_root_fields(
    monkeypatch: pytest.MonkeyPatch,
    removed_field: str,
) -> None:
    document = _report(monkeypatch).to_dict()
    del document[removed_field]
    serialized = (
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    )

    with pytest.raises(GenerationExecutionReportParseError, match="unexpected fields"):
        parse_generation_execution_report(serialized)


def test_canonical_execution_report_parser_rejects_duplicate_and_noncanonical_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serialized = _report(monkeypatch).to_json()
    duplicate = serialized.replace(
        '"command":"generate",',
        '"command":"generate","command":"generate",',
    )

    with pytest.raises(GenerationExecutionReportParseError, match="duplicate"):
        parse_generation_execution_report(duplicate)
    with pytest.raises(GenerationExecutionReportParseError, match="canonical"):
        parse_generation_execution_report(json.dumps(json.loads(serialized), indent=2))


def test_execution_report_matches_the_published_json_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    report = _report(
        monkeypatch,
        findings=tuple(_finding(state) for state in VexAnalysisState),
        output_format=ExecutionReportOutputFormat.OPENVEX,
    )

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(report.to_json()))


def test_execution_report_schema_enums_exactly_match_python_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    base_document = _report(monkeypatch).to_dict()
    categories = {
        "inventory_source": InventorySourceCategory,
        "finding_source": FindingSourceCategory,
        "output_format": ExecutionReportOutputFormat,
    }

    for field, category_type in categories.items():
        expected_values = {category.value for category in category_type}
        assert set(schema["properties"][field]["enum"]) == expected_values
        for category in category_type:
            document = dict(base_document)
            document[field] = category.value
            validator.validate(document)


def test_execution_report_schema_bounds_generated_document_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    maximum = schema["properties"]["document"]["properties"]["bytes"]["maximum"]
    assert maximum == MAX_VEX_OUTPUT_BYTES
    document = _report(monkeypatch).to_dict()
    document["document"]["bytes"] = maximum + 1

    assert list(Draft202012Validator(schema).iter_errors(document))


@pytest.mark.parametrize(
    "required_field",
    (
        "schema_version",
        "command",
        "vexcalibur_version",
        "inventory_source",
        "finding_source",
        "output_format",
        "component_count",
        "finding_count",
        "analysis_state_counts",
        "document",
    ),
)
def test_execution_report_schema_requires_every_root_field(
    monkeypatch: pytest.MonkeyPatch,
    required_field: str,
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    document = json.loads(_report(monkeypatch).to_json())
    del document[required_field]

    assert list(Draft202012Validator(schema).iter_errors(document))


@pytest.mark.parametrize("required_field", ("sha256", "bytes"))
def test_execution_report_schema_requires_document_metadata(
    monkeypatch: pytest.MonkeyPatch,
    required_field: str,
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    document = json.loads(_report(monkeypatch).to_json())
    del document["document"][required_field]

    assert list(Draft202012Validator(schema).iter_errors(document))


@pytest.mark.parametrize(
    "field_path",
    (
        ("unexpected",),
        ("analysis_state_counts", "unexpected"),
        ("document", "unexpected"),
    ),
)
def test_execution_report_schema_rejects_unknown_properties(
    monkeypatch: pytest.MonkeyPatch,
    field_path: tuple[str, ...],
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    document = json.loads(_report(monkeypatch).to_json())
    target = document
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = 1

    assert list(Draft202012Validator(schema).iter_errors(document))


@pytest.mark.parametrize(
    ("field_path", "invalid_value"),
    (
        (("schema_version",), True),
        (("schema_version",), 2),
        (("command",), "scan"),
        (("vexcalibur_version",), ""),
        (("vexcalibur_version",), "0.4.2\n"),
        (("vexcalibur_version",), "v" * 129),
        (("inventory_source",), "private_repository"),
        (("finding_source",), "unknown"),
        (("output_format",), "json"),
        (("component_count",), True),
        (("component_count",), -1),
        (("finding_count",), True),
        (("finding_count",), -1),
        (("analysis_state_counts", "resolved"), True),
        (("analysis_state_counts", "resolved"), 0),
        (("document", "sha256"), "A" * 64),
        (("document", "sha256"), f"{'0' * 63}\n"),
        (("document", "bytes"), True),
        (("document", "bytes"), -1),
        (("document",), []),
    ),
)
def test_execution_report_schema_rejects_invalid_values(
    monkeypatch: pytest.MonkeyPatch,
    field_path: tuple[str, ...],
    invalid_value: object,
) -> None:
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    document = json.loads(
        _report(monkeypatch, findings=(_finding(VexAnalysisState.RESOLVED),)).to_json()
    )
    target = document
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = invalid_value

    assert list(Draft202012Validator(schema).iter_errors(document))


def test_execution_report_counts_every_analysis_state_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = tuple(_finding(state) for state in VexAnalysisState)

    report = _report(monkeypatch, findings=findings)

    assert report.finding_count == len(VexAnalysisState)
    assert report.to_dict()["analysis_state_counts"] == {
        state.value: 1 for state in VexAnalysisState
    }
    document = b'{"bomFormat":"CycloneDX"}\n'
    assert report.to_json() == (
        '{"analysis_state_counts":{"exploitable":1,"false_positive":1,'
        '"in_triage":1,"not_affected":1,"resolved":1},"command":"generate",'
        f'"component_count":1,"document":{{"bytes":{len(document)},"sha256":'
        f'"{hashlib.sha256(document).hexdigest()}"}},'
        '"finding_count":5,"finding_source":"local_file",'
        '"inventory_source":"sbom_file","output_format":"cyclonedx",'
        '"schema_version":1,"vexcalibur_version":"0.4.2.dev1+g1234567"}\n'
    )


def test_execution_report_counts_repeated_analysis_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = (
        _finding(VexAnalysisState.RESOLVED),
        _finding(VexAnalysisState.RESOLVED),
        _finding(VexAnalysisState.IN_TRIAGE),
    )

    report = _report(monkeypatch, findings=findings)

    assert report.finding_count == 3
    assert report.to_dict()["analysis_state_counts"] == {
        "in_triage": 1,
        "resolved": 2,
    }


@pytest.mark.parametrize("invalid_version", (None, 42))
def test_execution_report_rejects_non_string_package_versions(
    monkeypatch: pytest.MonkeyPatch,
    invalid_version: object,
) -> None:
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: invalid_version,
    )
    result = GenerationResult(
        rendered_document="{}\n",
        components=(),
        findings=(),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=FindingSourceCategory.LOCAL_FILE,
            output_format=ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )

    with pytest.raises(ValueError, match="version is not report-safe"):
        result.execution_report()


def test_generation_result_snapshots_the_installed_package_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_versions: list[str] = []

    def first_version(name: str) -> str:
        requested_versions.append(name)
        return "0.4.2.dev1+first"

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        first_version,
    )
    result = GenerationResult(
        rendered_document="{}\n",
        components=(),
        findings=(),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=FindingSourceCategory.LOCAL_FILE,
            output_format=ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )

    assert requested_versions == []
    assert result.execution_report().vexcalibur_version == "0.4.2.dev1+first"
    assert requested_versions == ["vexcalibur"]

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2.dev1+second",
    )

    assert result.execution_report().vexcalibur_version == "0.4.2.dev1+first"


def test_direct_report_factory_snapshots_the_installed_package_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_versions: list[str] = []

    def installed_version(name: str) -> str:
        requested_versions.append(name)
        return "0.4.2.dev1+direct"

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        installed_version,
    )
    result = GenerationResult(
        rendered_document="{}\n",
        components=(),
        findings=(),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=FindingSourceCategory.LOCAL_FILE,
            output_format=ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )

    first = GenerationExecutionReport.from_result(result=result)
    second = GenerationExecutionReport.from_result(result=result)

    assert first.vexcalibur_version == "0.4.2.dev1+direct"
    assert second.vexcalibur_version == first.vexcalibur_version
    assert requested_versions == ["vexcalibur"]


def test_package_version_snapshot_does_not_change_result_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2.dev1+stable",
    )
    context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.SBOM_FILE,
        finding_source=FindingSourceCategory.LOCAL_FILE,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
    )
    result = GenerationResult("{}\n", (), (), context)
    equal_result = GenerationResult("{}\n", (), (), context)
    original_hash = hash(result)
    retained_results = {result}

    result.execution_report()

    assert result == equal_result
    assert hash(result) == original_hash
    assert result in retained_results
    assert equal_result in retained_results


@pytest.mark.parametrize("output_format", tuple(ExecutionReportOutputFormat))
def test_execution_report_uses_the_selected_output_format_without_reparsing(
    monkeypatch: pytest.MonkeyPatch,
    output_format: ExecutionReportOutputFormat,
) -> None:
    report = _report(
        monkeypatch,
        findings=(_finding(),),
        output_format=output_format,
    )

    assert report.output_format is output_format
    assert report.component_count == 1
    assert report.finding_count == 1


def test_execution_report_supports_custom_extension_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2.dev1+g1234567",
    )
    result = GenerationResult(
        rendered_document='{"custom":true}\n',
        components=(_component(),),
        findings=(_finding(),),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.CUSTOM,
            finding_source=FindingSourceCategory.CUSTOM,
            output_format=ExecutionReportOutputFormat.CUSTOM,
        ),
    )

    report = result.execution_report()
    schema = json.loads(EXECUTION_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report.to_dict())

    assert report.to_dict()["inventory_source"] == "custom"
    assert report.to_dict()["finding_source"] == "custom"
    assert report.to_dict()["output_format"] == "custom"


def test_execution_report_omits_sensitive_normalized_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(monkeypatch, findings=(_finding(),))
    serialized = report.to_json()

    for sensitive_value in (
        "private-widget",
        "pkg:pypi",
        "PRIVATE-2026-0001",
        "vulnerabilities.internal.example",
        "component:private-widget",
    ):
        assert sensitive_value not in serialized


def test_generation_result_and_report_are_immutable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = GenerationResult("{}\n", (_component(),), ())
    report = _report(monkeypatch)

    with pytest.raises(FrozenInstanceError):
        result.rendered_document = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        report.finding_count = 3  # type: ignore[misc]


def test_execution_report_rejects_inconsistent_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(monkeypatch, findings=(_finding(),))

    with pytest.raises(ValueError, match="sum to finding_count"):
        replace(report, finding_count=2)
    with pytest.raises(ValueError, match="positive integers"):
        replace(
            report,
            analysis_state_counts=((VexAnalysisState.IN_TRIAGE, 0),),
            finding_count=0,
        )


def test_execution_report_rejects_boolean_schema_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(monkeypatch)

    with pytest.raises(ValueError, match="schema version"):
        replace(report, schema_version=True)


def test_execution_report_reports_missing_package_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_version(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        missing_version,
    )
    result = GenerationResult(
        "{}\n",
        (),
        (),
        GenerationExecutionContext(
            InventorySourceCategory.SBOM_FILE,
            FindingSourceCategory.LOCAL_FILE,
            ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )

    with pytest.raises(ValueError, match="package metadata is unavailable"):
        result.execution_report()


@pytest.mark.parametrize(
    "metadata_error",
    (
        OSError("package metadata cannot be read"),
        UnicodeError("package metadata cannot be decoded"),
    ),
)
def test_execution_report_normalizes_package_metadata_read_failures(
    monkeypatch: pytest.MonkeyPatch,
    metadata_error: Exception,
) -> None:
    def fail_version(name: str) -> str:
        raise metadata_error

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        fail_version,
    )
    result = GenerationResult(
        "{}\n",
        (),
        (),
        GenerationExecutionContext(
            InventorySourceCategory.SBOM_FILE,
            FindingSourceCategory.LOCAL_FILE,
            ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )

    with pytest.raises(ValueError, match="package metadata is unavailable") as captured:
        result.execution_report()

    assert captured.value.__cause__ is metadata_error


def test_generation_result_without_context_rejects_execution_report() -> None:
    result = GenerationResult("{}\n", (), ())

    with pytest.raises(ValueError, match="context is unavailable"):
        result.execution_report()


def test_execution_report_enforces_serialized_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(monkeypatch)
    monkeypatch.setattr(
        "vexcalibur.generation_result.MAX_EXECUTION_REPORT_BYTES",
        32,
    )

    with pytest.raises(ValueError, match="execution report exceeds"):
        report.to_json()


def test_production_execution_report_limit_is_16_kib() -> None:
    assert MAX_EXECUTION_REPORT_BYTES == 16 * 1024


def test_execution_report_accepts_exact_size_limit_and_rejects_one_byte_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(monkeypatch)
    serialized = report.to_json()
    serialized_size = len(serialized.encode("utf-8"))
    monkeypatch.setattr(
        "vexcalibur.generation_result.MAX_EXECUTION_REPORT_BYTES",
        serialized_size,
    )

    assert report.to_json() == serialized

    monkeypatch.setattr(
        "vexcalibur.generation_result.MAX_EXECUTION_REPORT_BYTES",
        serialized_size - 1,
    )
    with pytest.raises(ValueError, match="execution report exceeds"):
        report.to_json()


@pytest.mark.parametrize(
    ("sha256", "byte_count"),
    (("A" * 64, 1), ("0" * 64, -1), ("0" * 63, 1)),
)
def test_document_metadata_rejects_invalid_values(
    sha256: str,
    byte_count: int,
) -> None:
    with pytest.raises(ValueError):
        GeneratedDocumentMetadata(sha256=sha256, bytes=byte_count)
