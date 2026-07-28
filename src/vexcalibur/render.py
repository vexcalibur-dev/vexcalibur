"""Format-neutral VEX renderer contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

import vexcalibur.errors as _errors
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.generation_context import ExecutionReportOutputFormat

VexRenderError = _errors.VexRenderError

if TYPE_CHECKING:
    from vexcalibur.document import VexDocument


class VexOutputFormat(str, Enum):
    """VEX output formats supported by the primary CLI."""

    CYCLONEDX = "cyclonedx"
    OPENVEX = "openvex"
    CSAF = "csaf"


class VexRenderer(Protocol):
    """Render provider-neutral components and findings as one VEX format."""

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Return a serialized VEX document."""


@runtime_checkable
class ExecutionReportOutputFormatDeclaration(Protocol):
    """Report-format capability for a custom renderer."""

    def execution_report_output_format(
        self,
    ) -> Literal[ExecutionReportOutputFormat.CUSTOM]:
        """Return the custom execution-report output category."""


def execution_report_output_format(
    renderer: VexRenderer,
) -> ExecutionReportOutputFormat | None:
    """Resolve a custom renderer's declared execution-report format."""
    if not isinstance(renderer, ExecutionReportOutputFormatDeclaration):
        return None
    output_format = renderer.execution_report_output_format()
    if not isinstance(output_format, ExecutionReportOutputFormat):
        raise TypeError(
            f"{type(renderer).__name__} execution report category must be "
            "an ExecutionReportOutputFormat"
        )
    if output_format is not ExecutionReportOutputFormat.CUSTOM:
        raise ValueError(
            f"{type(renderer).__name__} execution report category must be "
            "ExecutionReportOutputFormat.CUSTOM"
        )
    return output_format


class VexDocumentRenderer(Protocol):
    """Render an immutable, format-neutral VEX document."""

    def render_document(
        self,
        *,
        document: VexDocument,
        timestamp: datetime | None = None,
    ) -> str:
        """Return a serialized VEX document."""
