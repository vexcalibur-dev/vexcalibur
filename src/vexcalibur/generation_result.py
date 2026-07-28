"""Generation results and versioned execution reports."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import cached_property
from typing import Literal, TypedDict

from vexcalibur.domain import (
    ComponentIdentity,
    ExecutionReportFindingSourceDeclaration,
    VexAnalysisState,
    VulnerabilityFinding,
)
from vexcalibur.generation_context import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    InventorySourceCategory,
)
from vexcalibur.render import (
    ExecutionReportOutputFormatDeclaration,
    VexRenderError,
)

__all__ = [
    "EXECUTION_REPORT_SCHEMA_VERSION",
    "MAX_EXECUTION_REPORT_BYTES",
    "MAX_GENERATED_DOCUMENT_BYTES",
    "ExecutionReportFindingSourceDeclaration",
    "ExecutionReportOutputFormat",
    "ExecutionReportOutputFormatDeclaration",
    "FindingSourceCategory",
    "GeneratedDocumentMetadata",
    "GeneratedDocumentMetadataDict",
    "GenerationExecutionContext",
    "GenerationExecutionReport",
    "GenerationExecutionReportDict",
    "GenerationReportMetadataError",
    "GenerationResult",
    "InventorySourceCategory",
]

EXECUTION_REPORT_SCHEMA_VERSION = 1
MAX_EXECUTION_REPORT_BYTES = 16 * 1024
MAX_GENERATED_DOCUMENT_BYTES = 25 * 1024 * 1024
_VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.!+_-]{0,127}", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)


class GenerationReportMetadataError(ValueError):
    """Raised when installed package metadata cannot identify a report."""


class GeneratedDocumentMetadataDict(TypedDict):
    """JSON representation of generated-document metadata."""

    sha256: str
    bytes: int


class GenerationExecutionReportDict(TypedDict):
    """JSON representation of one generation execution report."""

    schema_version: int
    command: Literal["generate"]
    vexcalibur_version: str
    inventory_source: str
    finding_source: str
    output_format: str
    component_count: int
    finding_count: int
    analysis_state_counts: dict[str, int]
    document: GeneratedDocumentMetadataDict


@dataclass(frozen=True)
class GenerationResult:
    """Rendered VEX and the normalized inputs used to render it."""

    rendered_document: str
    components: tuple[ComponentIdentity, ...]
    findings: tuple[VulnerabilityFinding, ...]
    execution_context: GenerationExecutionContext | None = None
    _vexcalibur_version: str | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
        hash=False,
    )

    def __post_init__(self) -> None:
        if type(self.rendered_document) is not str:
            raise TypeError("rendered_document must be exact built-in text")
        if type(self.components) is not tuple or not all(
            type(component) is ComponentIdentity for component in self.components
        ):
            raise TypeError("components must be an exact tuple of ComponentIdentity values")
        if type(self.findings) is not tuple or not all(
            type(finding) is VulnerabilityFinding for finding in self.findings
        ):
            raise TypeError("findings must be an exact tuple of VulnerabilityFinding values")
        if (
            self.execution_context is not None
            and type(self.execution_context) is not GenerationExecutionContext
        ):
            raise TypeError("execution_context must be a GenerationExecutionContext")

    @cached_property
    def rendered_bytes(self) -> bytes:
        """Return and retain the strict UTF-8 representation of the document."""
        try:
            return str.encode(self.rendered_document, "utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise VexRenderError("rendered VEX must be valid UTF-8 text") from exc

    def execution_report(self) -> GenerationExecutionReport:
        """Build the public execution report from retained generation facts."""
        if self.execution_context is None:
            msg = (
                "execution report context is unavailable; use a built-in source "
                "and renderer or supply GenerationExecutionContext during generation"
            )
            raise ValueError(msg)
        return GenerationExecutionReport.from_result(result=self)

    def _execution_report_version(self) -> str:
        version = self._vexcalibur_version
        if version is None:
            version = _installed_vexcalibur_version()
            object.__setattr__(
                self,
                "_vexcalibur_version",
                version,
            )
        return version


@dataclass(frozen=True)
class GeneratedDocumentMetadata:
    """Digest and byte size of the exact rendered VEX document."""

    sha256: str
    bytes: int

    def __post_init__(self) -> None:
        if type(self.sha256) is not str or _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("document sha256 must be 64 lowercase hexadecimal characters")
        if (
            type(self.bytes) is not int
            or self.bytes < 0
            or self.bytes > MAX_GENERATED_DOCUMENT_BYTES
        ):
            raise ValueError(f"document bytes must be between 0 and {MAX_GENERATED_DOCUMENT_BYTES}")


@dataclass(frozen=True)
class GenerationExecutionReport:
    """Versioned summary of one successful ``generate`` operation."""

    schema_version: int
    command: Literal["generate"]
    vexcalibur_version: str
    inventory_source: InventorySourceCategory
    finding_source: FindingSourceCategory
    output_format: ExecutionReportOutputFormat
    component_count: int
    finding_count: int
    analysis_state_counts: tuple[tuple[VexAnalysisState, int], ...]
    document: GeneratedDocumentMetadata

    def __post_init__(self) -> None:
        if not isinstance(self.analysis_state_counts, tuple):
            raise TypeError("analysis_state_counts must contain analysis-state pairs")
        snapshot: list[tuple[object, ...]] = []
        for item in tuple(self.analysis_state_counts):
            if not isinstance(item, tuple):
                raise TypeError("analysis_state_counts must contain analysis-state pairs")
            snapshot.append(tuple(item))
        analysis_state_counts = tuple(snapshot)
        object.__setattr__(self, "analysis_state_counts", analysis_state_counts)

        if not isinstance(self.document, GeneratedDocumentMetadata):
            raise TypeError("document must be GeneratedDocumentMetadata")
        document = GeneratedDocumentMetadata(
            sha256=self.document.sha256,
            bytes=self.document.bytes,
        )
        object.__setattr__(self, "document", document)

        if (
            type(self.schema_version) is not int
            or self.schema_version != EXECUTION_REPORT_SCHEMA_VERSION
        ):
            raise ValueError("unsupported execution report schema version")
        if type(self.command) is not str or self.command != "generate":
            raise ValueError("execution report command must be generate")
        if (
            type(self.vexcalibur_version) is not str
            or _VERSION_PATTERN.fullmatch(self.vexcalibur_version) is None
        ):
            raise ValueError("Vexcalibur package version is not report-safe")
        if not isinstance(self.inventory_source, InventorySourceCategory):
            raise TypeError("inventory_source must be an InventorySourceCategory")
        if not isinstance(self.finding_source, FindingSourceCategory):
            raise TypeError("finding_source must be a FindingSourceCategory")
        if not isinstance(self.output_format, ExecutionReportOutputFormat):
            raise TypeError("output_format must be an ExecutionReportOutputFormat")
        if type(self.component_count) is not int or self.component_count < 0:
            raise ValueError("component_count must be a nonnegative integer")
        if type(self.finding_count) is not int or self.finding_count < 0:
            raise ValueError("finding_count must be a nonnegative integer")
        if any(
            type(item) is not tuple or len(item) != 2 or not isinstance(item[0], VexAnalysisState)
            for item in self.analysis_state_counts
        ):
            raise TypeError("analysis_state_counts must contain analysis-state pairs")
        if any(type(count) is not int or count <= 0 for _, count in self.analysis_state_counts):
            raise ValueError("analysis-state counts must be positive integers")
        counts = dict(self.analysis_state_counts)
        expected_states = [state for state in VexAnalysisState if counts.get(state, 0) > 0]
        actual_states = [state for state, _ in self.analysis_state_counts]
        if actual_states != expected_states:
            raise ValueError("analysis_state_counts must use unique analysis-state order")
        if sum(count for _, count in self.analysis_state_counts) != self.finding_count:
            raise ValueError("analysis-state counts must sum to finding_count")

    @classmethod
    def from_result(
        cls,
        *,
        result: GenerationResult,
    ) -> GenerationExecutionReport:
        """Calculate a report from the same normalized values used to render VEX."""
        execution_context = result.execution_context
        if execution_context is None:
            raise ValueError("generation result has no execution report context")
        version = result._execution_report_version()
        rendered_bytes = result.rendered_bytes
        counts = Counter(finding.analysis_state for finding in result.findings)
        report = cls(
            schema_version=EXECUTION_REPORT_SCHEMA_VERSION,
            command="generate",
            vexcalibur_version=version,
            inventory_source=execution_context.inventory_source,
            finding_source=execution_context.finding_source,
            output_format=execution_context.output_format,
            component_count=len(result.components),
            finding_count=len(result.findings),
            analysis_state_counts=tuple(
                (state, counts[state]) for state in VexAnalysisState if counts[state] > 0
            ),
            document=GeneratedDocumentMetadata(
                sha256=hashlib.sha256(rendered_bytes).hexdigest(),
                bytes=len(rendered_bytes),
            ),
        )
        report.to_json()
        return report

    def to_dict(self) -> GenerationExecutionReportDict:
        """Return the complete public report as JSON-compatible values."""
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "vexcalibur_version": self.vexcalibur_version,
            "inventory_source": self.inventory_source.value,
            "finding_source": self.finding_source.value,
            "output_format": self.output_format.value,
            "component_count": self.component_count,
            "finding_count": self.finding_count,
            "analysis_state_counts": {
                state.value: count for state, count in self.analysis_state_counts
            },
            "document": {
                "sha256": self.document.sha256,
                "bytes": self.document.bytes,
            },
        }

    def to_json(self) -> str:
        """Serialize a bounded canonical report with one trailing newline."""
        serialized = (
            json.dumps(
                self.to_dict(),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        if len(serialized.encode("utf-8")) > MAX_EXECUTION_REPORT_BYTES:
            msg = f"execution report exceeds the {MAX_EXECUTION_REPORT_BYTES} byte limit"
            raise ValueError(msg)
        return serialized


def _installed_vexcalibur_version() -> str:
    try:
        version = importlib.metadata.version("vexcalibur")
    except (importlib.metadata.PackageNotFoundError, OSError, UnicodeError) as exc:
        msg = "installed Vexcalibur package metadata is unavailable"
        raise GenerationReportMetadataError(msg) from exc
    if type(version) is not str or _VERSION_PATTERN.fullmatch(version) is None:
        msg = "installed Vexcalibur package version is not report-safe"
        raise GenerationReportMetadataError(msg)
    return version
