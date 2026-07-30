"""Generation results and versioned execution reports."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from typing import Literal, TypedDict, TypeVar, cast

import vexcalibur
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
from vexcalibur.generation_snapshot import GenerationInputSnapshot
from vexcalibur.json_boundary import StrictJsonError, strict_json_loads
from vexcalibur.limits import MAX_GENERATED_DOCUMENT_BYTES
from vexcalibur.render import (
    ExecutionReportOutputFormatDeclaration,
    VexRenderError,
)
from vexcalibur.version_identity import (
    SourceVersionIdentityError,
    verify_source_checkout_version,
)

__all__ = [
    "EXECUTION_REPORT_SCHEMA_VERSION",
    "MAX_EXECUTION_REPORT_BYTES",
    "MAX_EXECUTION_REPORT_COUNT",
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
    "GenerationExecutionReportParseError",
    "GenerationReportMetadataError",
    "GenerationResult",
    "InventorySourceCategory",
    "parse_generation_execution_report",
]

EXECUTION_REPORT_SCHEMA_VERSION = 1
MAX_EXECUTION_REPORT_BYTES = 16 * 1024
MAX_EXECUTION_REPORT_COUNT = 10_000_000
_VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.!+_-]{0,127}", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_EnumValue = TypeVar("_EnumValue")
_V1_INVENTORY_SOURCES = (
    InventorySourceCategory.SBOM_FILE,
    InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
    InventorySourceCategory.CUSTOM,
)
_V1_FINDING_SOURCES = (
    FindingSourceCategory.LOCAL_FILE,
    FindingSourceCategory.PUBLIC_OSV,
    FindingSourceCategory.CUSTOM_OSV,
    FindingSourceCategory.CUSTOM,
)
_V1_OUTPUT_FORMATS = (
    ExecutionReportOutputFormat.CYCLONEDX,
    ExecutionReportOutputFormat.OPENVEX,
    ExecutionReportOutputFormat.CSAF,
    ExecutionReportOutputFormat.CUSTOM,
)
_V1_ANALYSIS_STATES = (
    VexAnalysisState.RESOLVED,
    VexAnalysisState.EXPLOITABLE,
    VexAnalysisState.IN_TRIAGE,
    VexAnalysisState.FALSE_POSITIVE,
    VexAnalysisState.NOT_AFFECTED,
)


class GenerationReportMetadataError(ValueError):
    """Raised when installed package metadata cannot identify a report."""


class GenerationExecutionReportParseError(ValueError):
    """Raised when serialized execution-report bytes violate the public contract."""


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


_EXECUTION_REPORT_KEYS = frozenset(GenerationExecutionReportDict.__required_keys__)
_DOCUMENT_METADATA_KEYS = frozenset(GeneratedDocumentMetadataDict.__required_keys__)


@dataclass(frozen=True, init=False)
class GenerationResult:
    """Rendered VEX and an immutable snapshot of the normalized render inputs."""

    rendered_document: str
    execution_context: GenerationExecutionContext | None
    _input_snapshot: GenerationInputSnapshot = field(repr=False)
    _vexcalibur_version: str | None = field(
        default=None,
        repr=False,
        compare=False,
        hash=False,
    )

    def __init__(
        self,
        rendered_document: str,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        execution_context: GenerationExecutionContext | None = None,
    ) -> None:
        if type(rendered_document) is not str:
            raise TypeError("rendered_document must be exact built-in text")
        if type(components) is not tuple or not all(
            type(component) is ComponentIdentity for component in components
        ):
            raise TypeError("components must be an exact tuple of ComponentIdentity values")
        if type(findings) is not tuple or not all(
            type(finding) is VulnerabilityFinding for finding in findings
        ):
            raise TypeError("findings must be an exact tuple of VulnerabilityFinding values")
        if (
            execution_context is not None
            and type(execution_context) is not GenerationExecutionContext
        ):
            raise TypeError("execution_context must be a GenerationExecutionContext")
        input_snapshot = GenerationInputSnapshot.capture_components(components).capture_findings(
            findings
        )
        self._initialize(
            rendered_document=rendered_document,
            input_snapshot=input_snapshot,
            execution_context=execution_context,
        )

    @classmethod
    def _from_input_snapshot(
        cls,
        *,
        rendered_document: str,
        input_snapshot: GenerationInputSnapshot,
        execution_context: GenerationExecutionContext | None,
    ) -> GenerationResult:
        result = object.__new__(cls)
        result._initialize(
            rendered_document=rendered_document,
            input_snapshot=input_snapshot,
            execution_context=execution_context,
        )
        return result

    def _initialize(
        self,
        *,
        rendered_document: str,
        input_snapshot: GenerationInputSnapshot,
        execution_context: GenerationExecutionContext | None,
    ) -> None:
        if type(rendered_document) is not str:
            raise TypeError("rendered_document must be exact built-in text")
        if type(input_snapshot) is not GenerationInputSnapshot:
            raise TypeError("input_snapshot must be a GenerationInputSnapshot")
        if (
            execution_context is not None
            and type(execution_context) is not GenerationExecutionContext
        ):
            raise TypeError("execution_context must be a GenerationExecutionContext")
        object.__setattr__(self, "rendered_document", rendered_document)
        object.__setattr__(self, "execution_context", execution_context)
        object.__setattr__(self, "_input_snapshot", input_snapshot)
        object.__setattr__(self, "_vexcalibur_version", _loaded_vexcalibur_version())

    @property
    def components(self) -> tuple[ComponentIdentity, ...]:
        """Return independent ordinary package objects from the retained snapshot."""
        return self._input_snapshot.materialize_components()

    @property
    def findings(self) -> tuple[VulnerabilityFinding, ...]:
        """Return independent ordinary findings from the retained snapshot."""
        return self._input_snapshot.materialize_findings()

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
            raise GenerationReportMetadataError("loaded Vexcalibur version is unavailable")
        try:
            verify_source_checkout_version(version)
        except SourceVersionIdentityError as exc:
            raise GenerationReportMetadataError(str(exc)) from exc
        installed_version = _installed_vexcalibur_version()
        if installed_version != version:
            raise GenerationReportMetadataError(
                "loaded Vexcalibur code version does not match installed package metadata"
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
        if self.inventory_source not in _V1_INVENTORY_SOURCES:
            raise ValueError("inventory_source is not supported by schema version 1")
        if not isinstance(self.finding_source, FindingSourceCategory):
            raise TypeError("finding_source must be a FindingSourceCategory")
        if self.finding_source not in _V1_FINDING_SOURCES:
            raise ValueError("finding_source is not supported by schema version 1")
        if not isinstance(self.output_format, ExecutionReportOutputFormat):
            raise TypeError("output_format must be an ExecutionReportOutputFormat")
        if self.output_format not in _V1_OUTPUT_FORMATS:
            raise ValueError("output_format is not supported by schema version 1")
        if (
            type(self.component_count) is not int
            or self.component_count < 0
            or self.component_count > MAX_EXECUTION_REPORT_COUNT
        ):
            raise ValueError(f"component_count must be between 0 and {MAX_EXECUTION_REPORT_COUNT}")
        if (
            type(self.finding_count) is not int
            or self.finding_count < 0
            or self.finding_count > MAX_EXECUTION_REPORT_COUNT
        ):
            raise ValueError(f"finding_count must be between 0 and {MAX_EXECUTION_REPORT_COUNT}")
        if any(
            type(item) is not tuple or len(item) != 2 or not isinstance(item[0], VexAnalysisState)
            for item in self.analysis_state_counts
        ):
            raise TypeError("analysis_state_counts must contain analysis-state pairs")
        if any(
            type(count) is not int or count <= 0 or count > MAX_EXECUTION_REPORT_COUNT
            for _, count in self.analysis_state_counts
        ):
            raise ValueError(
                "analysis-state counts must be positive integers no greater than "
                f"{MAX_EXECUTION_REPORT_COUNT}"
            )
        counts = dict(self.analysis_state_counts)
        if set(counts).difference(_V1_ANALYSIS_STATES):
            raise ValueError(
                "analysis_state_counts contains a state unsupported by schema version 1"
            )
        expected_states = [state for state in _V1_ANALYSIS_STATES if counts.get(state, 0) > 0]
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
                (state, counts[state]) for state in _V1_ANALYSIS_STATES if counts[state] > 0
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


def parse_generation_execution_report(
    serialized: bytes | str,
) -> GenerationExecutionReport:
    """Parse one bounded, canonical execution report into its typed value."""
    if type(serialized) is str:
        if len(serialized) > MAX_EXECUTION_REPORT_BYTES:
            raise GenerationExecutionReportParseError(
                f"execution report exceeds the {MAX_EXECUTION_REPORT_BYTES} byte limit"
            )
        try:
            report_bytes = serialized.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise GenerationExecutionReportParseError(
                "execution report is not valid UTF-8"
            ) from exc
    elif type(serialized) is bytes:
        report_bytes = serialized
    else:
        raise TypeError("serialized execution report must be exact bytes or text")
    if len(report_bytes) > MAX_EXECUTION_REPORT_BYTES:
        raise GenerationExecutionReportParseError(
            f"execution report exceeds the {MAX_EXECUTION_REPORT_BYTES} byte limit"
        )

    try:
        decoded = strict_json_loads(report_bytes)
    except StrictJsonError as exc:
        raise GenerationExecutionReportParseError(
            f"execution report is invalid JSON: {exc}"
        ) from exc
    report = _require_exact_report_object(
        decoded,
        expected_keys=_EXECUTION_REPORT_KEYS,
        field="execution report",
    )
    state_counts = _require_exact_report_object(
        report["analysis_state_counts"],
        expected_keys=None,
        field="analysis_state_counts",
    )
    document = _require_exact_report_object(
        report["document"],
        expected_keys=_DOCUMENT_METADATA_KEYS,
        field="document",
    )

    try:
        command = _require_report_string(report["command"], field="command")
        if command != "generate":
            raise GenerationExecutionReportParseError("execution report command must be generate")
        inventory_source = _v1_enum_value(
            InventorySourceCategory,
            _V1_INVENTORY_SOURCES,
            _require_report_string(report["inventory_source"], field="inventory_source"),
            field="inventory_source",
        )
        finding_source = _v1_enum_value(
            FindingSourceCategory,
            _V1_FINDING_SOURCES,
            _require_report_string(report["finding_source"], field="finding_source"),
            field="finding_source",
        )
        output_format = _v1_enum_value(
            ExecutionReportOutputFormat,
            _V1_OUTPUT_FORMATS,
            _require_report_string(report["output_format"], field="output_format"),
            field="output_format",
        )
        invalid_states = set(state_counts).difference(state.value for state in _V1_ANALYSIS_STATES)
        if invalid_states:
            raise GenerationExecutionReportParseError(
                "analysis_state_counts contains an unsupported analysis state"
            )
        parsed = GenerationExecutionReport(
            schema_version=_require_report_integer(
                report["schema_version"],
                field="schema_version",
            ),
            command=cast(Literal["generate"], command),
            vexcalibur_version=_require_report_string(
                report["vexcalibur_version"],
                field="vexcalibur_version",
            ),
            inventory_source=inventory_source,
            finding_source=finding_source,
            output_format=output_format,
            component_count=_require_report_integer(
                report["component_count"],
                field="component_count",
            ),
            finding_count=_require_report_integer(
                report["finding_count"],
                field="finding_count",
            ),
            analysis_state_counts=tuple(
                (
                    state,
                    _require_report_integer(
                        state_counts[state.value],
                        field=f"analysis_state_counts.{state.value}",
                    ),
                )
                for state in _V1_ANALYSIS_STATES
                if state.value in state_counts
            ),
            document=GeneratedDocumentMetadata(
                sha256=_require_report_string(
                    document["sha256"],
                    field="document.sha256",
                ),
                bytes=_require_report_integer(
                    document["bytes"],
                    field="document.bytes",
                ),
            ),
        )
    except GenerationExecutionReportParseError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise GenerationExecutionReportParseError(str(exc)) from exc

    if report_bytes != parsed.to_json().encode("utf-8"):
        raise GenerationExecutionReportParseError("execution report is not canonical JSON")
    return parsed


def _require_exact_report_object(
    value: object,
    *,
    expected_keys: frozenset[str] | None,
    field: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise GenerationExecutionReportParseError(f"{field} must be a JSON object")
    result = value
    if expected_keys is not None and set(result) != expected_keys:
        raise GenerationExecutionReportParseError(f"{field} contains unexpected fields")
    return result


def _require_report_string(
    value: object,
    *,
    field: str,
) -> str:
    if type(value) is not str:
        raise GenerationExecutionReportParseError(f"{field} must be a string")
    return value


def _require_report_integer(
    value: object,
    *,
    field: str,
) -> int:
    if type(value) is not int:
        raise GenerationExecutionReportParseError(f"{field} must be an integer")
    return value


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


def _loaded_vexcalibur_version() -> str:
    version = vexcalibur.__version__
    if type(version) is not str or _VERSION_PATTERN.fullmatch(version) is None:
        raise GenerationReportMetadataError("loaded Vexcalibur version is not report-safe")
    return version


def _v1_enum_value(
    enum_type: Callable[[str], _EnumValue],
    supported_values: tuple[_EnumValue, ...],
    value: str,
    *,
    field: str,
) -> _EnumValue:
    parsed = enum_type(value)
    if parsed not in supported_values:
        raise GenerationExecutionReportParseError(f"{field} is not supported by schema version 1")
    return parsed
