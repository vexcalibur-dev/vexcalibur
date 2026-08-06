from __future__ import annotations

from dataclasses import replace

import pytest
from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity, VexAnalysisState, VulnerabilityFinding
from vexcalibur.generation_result import (
    MAX_EXECUTION_REPORT_COUNT,
    MAX_GENERATED_DOCUMENT_BYTES,
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GeneratedDocumentMetadata,
    GenerationExecutionContext,
    GenerationExecutionReport,
    GenerationResult,
    InventorySourceCategory,
)
from vexcalibur.render import VexRenderError


def _component() -> ComponentIdentity:
    return ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )


def _finding() -> VulnerabilityFinding:
    component = _component()
    return VulnerabilityFinding(
        id="DEMO-2026-0001",
        source_name="Example source",
        source_url="https://security.example.test/DEMO-2026-0001",
        component_ref=component.ref,
        purl=component.purl.to_string(),
        analysis_state=VexAnalysisState.IN_TRIAGE,
    )


def _context() -> GenerationExecutionContext:
    return GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )


def _report() -> GenerationExecutionReport:
    return GenerationExecutionReport(
        schema_version=1,
        command="generate",
        vexcalibur_version="0.4.2",
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CUSTOM,
        component_count=1,
        finding_count=1,
        analysis_state_counts=((VexAnalysisState.IN_TRIAGE, 1),),
        document=GeneratedDocumentMetadata("0" * 64, 2),
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("inventory_source", "custom", "inventory_source"),
        ("finding_source", "custom", "finding_source"),
        ("output_format", "custom", "output_format"),
    ),
)
def test_execution_context_rejects_mistyped_categories(
    field: str,
    value: object,
    message: str,
) -> None:
    values = {
        "inventory_source": InventorySourceCategory.CUSTOM,
        "finding_source": FindingSourceCategory.CUSTOM,
        "output_format": ExecutionReportOutputFormat.CUSTOM,
    }
    values[field] = value

    with pytest.raises(TypeError, match=message):
        GenerationExecutionContext(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"rendered_document": b"{}\n"}, "rendered_document"),
        ({"components": [_component()]}, "components"),
        ({"components": ("not a component",)}, "components"),
        ({"findings": [_finding()]}, "findings"),
        ({"findings": ("not a finding",)}, "findings"),
        ({"execution_context": "custom"}, "execution_context"),
    ),
)
def test_generation_result_rejects_invalid_public_values(
    changes: dict[str, object],
    message: str,
) -> None:
    values = {
        "rendered_document": "{}\n",
        "components": (_component(),),
        "findings": (_finding(),),
        "execution_context": _context(),
    }
    values.update(changes)

    with pytest.raises(TypeError, match=message):
        GenerationResult(**values)  # type: ignore[arg-type]


def test_generation_result_rejects_unpaired_surrogate_during_utf8_encoding() -> None:
    result = GenerationResult(
        rendered_document='{"invalid":"\udcff"}\n',
        components=(_component(),),
        findings=(_finding(),),
        execution_context=_context(),
    )

    with pytest.raises(VexRenderError, match="valid UTF-8"):
        _ = result.rendered_bytes


@pytest.mark.parametrize(
    ("sha256", "byte_count", "message"),
    (
        ("A" * 64, 1, "sha256"),
        (None, 1, "sha256"),
        ("0" * 64, -1, "bytes"),
        ("0" * 64, True, "bytes"),
        ("0" * 64, MAX_GENERATED_DOCUMENT_BYTES + 1, "bytes"),
    ),
)
def test_document_metadata_rejects_invalid_values(
    sha256: str,
    byte_count: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        GeneratedDocumentMetadata(sha256=sha256, bytes=byte_count)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "error", "message"),
    (
        ({"schema_version": 2}, ValueError, "schema version"),
        ({"command": "convert"}, ValueError, "command"),
        ({"vexcalibur_version": "../secret"}, ValueError, "version"),
        ({"vexcalibur_version": None}, ValueError, "version"),
        ({"inventory_source": "custom"}, TypeError, "inventory_source"),
        ({"finding_source": "custom"}, TypeError, "finding_source"),
        ({"output_format": "custom"}, TypeError, "output_format"),
        ({"component_count": -1}, ValueError, "component_count"),
        (
            {"component_count": MAX_EXECUTION_REPORT_COUNT + 1},
            ValueError,
            "component_count",
        ),
        ({"component_count": True}, ValueError, "component_count"),
        ({"finding_count": -1}, ValueError, "finding_count"),
        (
            {"finding_count": MAX_EXECUTION_REPORT_COUNT + 1},
            ValueError,
            "finding_count",
        ),
        ({"finding_count": True}, ValueError, "finding_count"),
        ({"analysis_state_counts": []}, TypeError, "analysis_state_counts"),
        (
            {"analysis_state_counts": ((VexAnalysisState.IN_TRIAGE,),)},
            TypeError,
            "analysis_state_counts",
        ),
        (
            {"analysis_state_counts": (("in_triage", 1),)},
            TypeError,
            "analysis_state_counts",
        ),
        (
            {"analysis_state_counts": ((VexAnalysisState.IN_TRIAGE, 0),)},
            ValueError,
            "positive",
        ),
        (
            {
                "analysis_state_counts": (
                    (VexAnalysisState.IN_TRIAGE, MAX_EXECUTION_REPORT_COUNT + 1),
                )
            },
            ValueError,
            "greater than",
        ),
        (
            {
                "analysis_state_counts": (
                    (VexAnalysisState.IN_TRIAGE, 1),
                    (VexAnalysisState.IN_TRIAGE, 1),
                )
            },
            ValueError,
            "unique",
        ),
        (
            {"analysis_state_counts": ((VexAnalysisState.IN_TRIAGE, 2),)},
            ValueError,
            "sum",
        ),
        ({"document": {"sha256": "0" * 64, "bytes": 2}}, TypeError, "document"),
    ),
)
def test_execution_report_rejects_invalid_public_values(
    changes: dict[str, object],
    error: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error, match=message):
        replace(_report(), **changes)


def test_execution_report_rejects_a_hostile_command_subclass() -> None:
    class HostileCommand(str):
        def __ne__(self, other: object) -> bool:
            return False

    with pytest.raises(ValueError, match="command"):
        replace(_report(), command=HostileCommand("scan"))  # type: ignore[arg-type]


def test_execution_report_snapshots_nested_tuple_and_metadata_subclasses() -> None:
    class CountsSubclass(tuple):
        pass

    class PairSubclass(tuple):
        pass

    class MetadataSubclass(GeneratedDocumentMetadata):
        pass

    report = replace(
        _report(),
        analysis_state_counts=CountsSubclass((PairSubclass((VexAnalysisState.IN_TRIAGE, 1)),)),
        document=MetadataSubclass("0" * 64, 2),
    )

    assert type(report.analysis_state_counts) is tuple
    assert type(report.analysis_state_counts[0]) is tuple
    assert type(report.document) is GeneratedDocumentMetadata
    assert report.to_dict()["analysis_state_counts"] == {"in_triage": 1}
