"""Internal report classification for exact built-in sources and renderers."""

from __future__ import annotations

from vexcalibur.csaf import Csaf20VexJsonRenderer
from vexcalibur.domain import VulnerabilitySource
from vexcalibur.generation_context import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
)
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import VexRenderer
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    OsvSource,
    is_canonical_public_osv_endpoint,
)
from vexcalibur.vex import CycloneDxJsonRenderer


def finding_source_category(
    source: VulnerabilitySource,
) -> FindingSourceCategory | None:
    """Return report provenance only for an exact built-in source."""
    source_type = type(source)
    if source_type is LocalFindingsSource:
        return FindingSourceCategory.LOCAL_FILE
    if source_type is OsvSource:
        assert isinstance(source, OsvSource)
        return _osv_source_category(source)
    return None


def select_renderer(renderer: VexRenderer | None) -> VexRenderer:
    """Return the requested renderer or the built-in default."""
    return CycloneDxJsonRenderer() if renderer is None else renderer


def renderer_output_format(
    renderer: VexRenderer,
) -> ExecutionReportOutputFormat | None:
    """Return report provenance only for an exact built-in renderer."""
    renderer_type = type(renderer)
    if renderer_type is CycloneDxJsonRenderer:
        return ExecutionReportOutputFormat.CYCLONEDX
    if renderer_type is OpenVexJsonRenderer:
        return ExecutionReportOutputFormat.OPENVEX
    if renderer_type is Csaf20VexJsonRenderer:
        return ExecutionReportOutputFormat.CSAF
    return None


def _osv_source_category(source: OsvSource) -> FindingSourceCategory:
    if source.client is not None:
        return FindingSourceCategory.CUSTOM
    if is_canonical_public_osv_endpoint(source.effective_base_url):
        return FindingSourceCategory.PUBLIC_OSV
    return FindingSourceCategory.CUSTOM_OSV
