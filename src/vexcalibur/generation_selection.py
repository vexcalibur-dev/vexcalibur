"""Typed source and renderer selections with report-safe provenance."""

from __future__ import annotations

from dataclasses import dataclass

from vexcalibur.csaf import Csaf20VexJsonRenderer
from vexcalibur.domain import (
    VulnerabilitySource,
    execution_report_finding_source,
)
from vexcalibur.generation_context import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
)
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import VexRenderer, execution_report_output_format
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    OsvClient,
    OsvSource,
    is_canonical_public_osv_endpoint,
)
from vexcalibur.vex import CycloneDxJsonRenderer


@dataclass(frozen=True)
class SelectedFindingSource:
    """One finding source and the provenance it may place in a report."""

    source: VulnerabilitySource
    report_category: FindingSourceCategory | None


@dataclass(frozen=True)
class SelectedRenderer:
    """One renderer and the output category it may place in a report."""

    renderer: VexRenderer
    report_format: ExecutionReportOutputFormat | None


def select_finding_source(source: VulnerabilitySource) -> SelectedFindingSource:
    """Classify exact built-ins while reserving custom declarations for extensions."""
    source_type = type(source)
    category: FindingSourceCategory | None
    if source_type is LocalFindingsSource:
        category = FindingSourceCategory.LOCAL_FILE
    elif source_type is OsvSource:
        assert isinstance(source, OsvSource)
        category = _osv_source_category(source)
    else:
        category = execution_report_finding_source(source)
    return SelectedFindingSource(source=source, report_category=category)


def select_renderer(renderer: VexRenderer | None) -> SelectedRenderer:
    """Select the default renderer and classify exact built-in implementations."""
    selected = CycloneDxJsonRenderer() if renderer is None else renderer
    renderer_type = type(selected)
    output_format: ExecutionReportOutputFormat | None
    if renderer_type is CycloneDxJsonRenderer:
        output_format = ExecutionReportOutputFormat.CYCLONEDX
    elif renderer_type is OpenVexJsonRenderer:
        output_format = ExecutionReportOutputFormat.OPENVEX
    elif renderer_type is Csaf20VexJsonRenderer:
        output_format = ExecutionReportOutputFormat.CSAF
    else:
        output_format = execution_report_output_format(selected)
    return SelectedRenderer(renderer=selected, report_format=output_format)


def _osv_source_category(source: OsvSource) -> FindingSourceCategory:
    client = source.client
    if client is not None and type(client) is not OsvClient:
        return FindingSourceCategory.CUSTOM
    if is_canonical_public_osv_endpoint(source.effective_base_url):
        return FindingSourceCategory.PUBLIC_OSV
    return FindingSourceCategory.CUSTOM_OSV
