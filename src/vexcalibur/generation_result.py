"""Generation results and versioned execution reports."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from typing import Literal, TypedDict, cast

from packageurl import PackageURL

import vexcalibur
from vexcalibur.domain import (
    ComponentIdentity,
    ExecutionReportFindingSourceDeclaration,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.generation_context import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    InventorySourceCategory,
)
from vexcalibur.json_boundary import StrictJsonError, strict_json_loads
from vexcalibur.render import (
    ExecutionReportOutputFormatDeclaration,
    VexRenderError,
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
MAX_GENERATED_DOCUMENT_BYTES = 25 * 1024 * 1024
MAX_EXECUTION_REPORT_COUNT = 10_000_000
_VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.!+_-]{0,127}", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)


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


@dataclass(frozen=True)
class _ComponentSnapshot:
    """Primitive retained representation of one normalized component."""

    ref: str
    name: str
    version: str | None
    purl_type: str
    purl_namespace: str | None
    purl_name: str
    purl_version: str | None
    purl_qualifiers: tuple[tuple[str, str], ...]
    purl_subpath: str | None
    component_type: str

    @classmethod
    def from_component(cls, component: ComponentIdentity) -> _ComponentSnapshot:
        return cls(
            ref=_snapshot_text(component.ref, field="component ref"),
            name=_snapshot_text(component.name, field="component name"),
            version=_snapshot_optional_text(component.version, field="component version"),
            purl_type=_snapshot_text(component.purl.type, field="PURL type"),
            purl_namespace=_snapshot_optional_text(
                component.purl.namespace,
                field="PURL namespace",
            ),
            purl_name=_snapshot_text(component.purl.name, field="PURL name"),
            purl_version=_snapshot_optional_text(component.purl.version, field="PURL version"),
            purl_qualifiers=tuple(
                sorted(
                    (
                        _snapshot_text(key, field="PURL qualifier key"),
                        _snapshot_text(value, field="PURL qualifier value"),
                    )
                    for key, value in component.purl.qualifiers.items()
                )
            ),
            purl_subpath=_snapshot_optional_text(component.purl.subpath, field="PURL subpath"),
            component_type=_snapshot_text(component.type, field="component type"),
        )

    def materialize(self) -> ComponentIdentity:
        return ComponentIdentity(
            ref=self.ref,
            name=self.name,
            version=self.version,
            purl=PackageURL(
                type=self.purl_type,
                namespace=self.purl_namespace,
                name=self.purl_name,
                version=self.purl_version,
                qualifiers=dict(self.purl_qualifiers),
                subpath=self.purl_subpath,
            ),
            type=self.component_type,
        )


@dataclass(frozen=True)
class _FindingSnapshot:
    """Primitive retained representation of one normalized finding."""

    id: str
    source_name: str
    source_url: str
    component_ref: str
    purl: str
    modified: datetime | None
    analysis_state: VexAnalysisState
    analysis_detail: str
    action_statement: str | None
    impact_statement: str | None
    fixed_version: str | None
    remediation_category: VexRemediationCategory | None

    @classmethod
    def from_finding(cls, finding: VulnerabilityFinding) -> _FindingSnapshot:
        return cls(
            id=_snapshot_text(finding.id, field="finding id"),
            source_name=_snapshot_text(finding.source_name, field="finding source name"),
            source_url=_snapshot_text(finding.source_url, field="finding source URL"),
            component_ref=_snapshot_text(finding.component_ref, field="finding component ref"),
            purl=_snapshot_text(finding.purl, field="finding PURL"),
            modified=_snapshot_datetime(finding.modified),
            analysis_state=VexAnalysisState(finding.analysis_state),
            analysis_detail=_snapshot_text(
                finding.analysis_detail,
                field="finding analysis detail",
            ),
            action_statement=_snapshot_optional_text(
                finding.action_statement,
                field="finding action statement",
            ),
            impact_statement=_snapshot_optional_text(
                finding.impact_statement,
                field="finding impact statement",
            ),
            fixed_version=_snapshot_optional_text(
                finding.fixed_version,
                field="finding fixed version",
            ),
            remediation_category=(
                None
                if finding.remediation_category is None
                else VexRemediationCategory(finding.remediation_category)
            ),
        )

    def materialize(self) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            id=self.id,
            source_name=self.source_name,
            source_url=self.source_url,
            component_ref=self.component_ref,
            purl=self.purl,
            modified=self.modified,
            analysis_state=self.analysis_state,
            analysis_detail=self.analysis_detail,
            action_statement=self.action_statement,
            impact_statement=self.impact_statement,
            fixed_version=self.fixed_version,
            remediation_category=self.remediation_category,
        )


@dataclass(frozen=True, init=False)
class GenerationResult:
    """Rendered VEX and an immutable snapshot of the normalized render inputs."""

    rendered_document: str
    execution_context: GenerationExecutionContext | None
    _component_snapshots: tuple[_ComponentSnapshot, ...] = field(repr=False)
    _finding_snapshots: tuple[_FindingSnapshot, ...] = field(repr=False)
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
        object.__setattr__(self, "rendered_document", rendered_document)
        object.__setattr__(self, "execution_context", execution_context)
        object.__setattr__(
            self,
            "_component_snapshots",
            tuple(_ComponentSnapshot.from_component(component) for component in components),
        )
        object.__setattr__(
            self,
            "_finding_snapshots",
            tuple(_FindingSnapshot.from_finding(finding) for finding in findings),
        )
        object.__setattr__(self, "_vexcalibur_version", _loaded_vexcalibur_version())

    @property
    def components(self) -> tuple[ComponentIdentity, ...]:
        """Return independent ordinary package objects from the retained snapshot."""
        return tuple(snapshot.materialize() for snapshot in self._component_snapshots)

    @property
    def findings(self) -> tuple[VulnerabilityFinding, ...]:
        """Return independent ordinary findings from the retained snapshot."""
        return tuple(snapshot.materialize() for snapshot in self._finding_snapshots)

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
        if not isinstance(self.finding_source, FindingSourceCategory):
            raise TypeError("finding_source must be a FindingSourceCategory")
        if not isinstance(self.output_format, ExecutionReportOutputFormat):
            raise TypeError("output_format must be an ExecutionReportOutputFormat")
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
        inventory_source = InventorySourceCategory(
            _require_report_string(
                report["inventory_source"],
                field="inventory_source",
            )
        )
        finding_source = FindingSourceCategory(
            _require_report_string(
                report["finding_source"],
                field="finding_source",
            )
        )
        output_format = ExecutionReportOutputFormat(
            _require_report_string(
                report["output_format"],
                field="output_format",
            )
        )
        invalid_states = set(state_counts).difference(state.value for state in VexAnalysisState)
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
                for state in VexAnalysisState
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


def _snapshot_text(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text")
    return value if type(value) is str else str.__str__(value)


def _snapshot_optional_text(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _snapshot_text(value, field=field)


def _snapshot_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise TypeError("finding modified timestamp must be a datetime")
    offset = value.utcoffset()
    fixed_timezone = None if offset is None else timezone(offset)
    return datetime(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        tzinfo=fixed_timezone,
        fold=value.fold,
    )
