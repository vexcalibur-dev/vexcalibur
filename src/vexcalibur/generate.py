"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from vexcalibur.domain import (
    ComponentIdentity,
    VulnerabilityFinding,
    VulnerabilitySource,
    VulnerabilitySourceInputError,
    validate_source_before_inventory_load,
)
from vexcalibur.generation_result import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)
from vexcalibur.generation_selection import (
    SelectedFindingSource,
    SelectedRenderer,
    select_finding_source,
    select_renderer,
)
from vexcalibur.generation_snapshot import GenerationInputSnapshot
from vexcalibur.github_sbom import GithubSbomClient, GithubSbomComponentLoader
from vexcalibur.limits import MAX_GENERATED_DOCUMENT_BYTES
from vexcalibur.render import (
    VexRenderer,
    VexRenderError,
)
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClient,
    OsvSource,
)
from vexcalibur.vex import CycloneDxJsonRenderer

MAX_VEX_OUTPUT_BYTES = MAX_GENERATED_DOCUMENT_BYTES
_OUTPUT_MEASUREMENT_CHUNK_CHARACTERS = 64 * 1024


def generate_vex_from_source(
    *,
    input_file: Path,
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM and source provider."""
    return _render_legacy_generation(
        components=load_cyclonedx_sbom(input_file),
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_source_result(
    *,
    input_file: Path,
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a report-aware result from a CycloneDX SBOM and provider."""
    components = load_cyclonedx_sbom(input_file)
    selected_source = select_finding_source(source)
    selected_renderer = select_renderer(renderer)
    return _generate_result(
        components=components,
        source=selected_source,
        timestamp=timestamp,
        renderer=selected_renderer,
        execution_context=_execution_context_for_generation(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=selected_source.report_category,
            output_format=selected_renderer.report_format,
            execution_context=execution_context,
        ),
    )


def generate_vex_from_components(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from component identities and a source provider."""
    return _render_legacy_generation(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_components_result(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a result from embedding-supplied components.

    Direct component input has the ``CUSTOM`` inventory category. An explicit
    execution context must use that category; built-in inventory categories are
    reserved for Vexcalibur's local SBOM and GitHub loaders.
    """
    return _generate_vex_from_components_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
        inventory_source=InventorySourceCategory.CUSTOM,
        execution_context=execution_context,
    )


def _generate_vex_from_components_result(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None = None,
    inventory_source: InventorySourceCategory,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a result with inventory provenance established by a trusted loader."""
    selected_source = select_finding_source(source)
    selected_renderer = select_renderer(renderer)
    return _generate_result(
        components=components,
        source=selected_source,
        timestamp=timestamp,
        renderer=selected_renderer,
        execution_context=_execution_context_for_generation(
            inventory_source=inventory_source,
            finding_source=selected_source.report_category,
            output_format=selected_renderer.report_format,
            execution_context=execution_context,
        ),
    )


def _require_components(components: tuple[ComponentIdentity, ...]) -> None:
    """Reject an empty normalized inventory."""
    if not components:
        msg = "no components with package URLs were found"
        raise SbomError(msg)


def _render_legacy_generation(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None,
) -> str:
    """Render through the compatibility path without copying extension values."""
    _require_components(components)
    findings = _findings_for_components(source, components)
    selected_renderer = CycloneDxJsonRenderer() if renderer is None else renderer
    return _render_generation_document(
        components=components,
        findings=findings,
        timestamp=timestamp,
        renderer=selected_renderer,
        preserve_extension_value=True,
    )


def _generate_result(
    *,
    components: tuple[ComponentIdentity, ...],
    source: SelectedFindingSource,
    timestamp: datetime | None,
    renderer: SelectedRenderer,
    execution_context: GenerationExecutionContext | None,
) -> GenerationResult:
    """Render from isolated snapshots and retain only independently owned values."""
    _require_components(components)
    input_snapshot = GenerationInputSnapshot.capture_components(components)
    source_findings = _findings_for_components(
        source.source,
        input_snapshot.materialize_components(),
    )
    input_snapshot = input_snapshot.capture_findings(source_findings)
    rendered = _render_generation_document(
        components=input_snapshot.materialize_components(),
        findings=input_snapshot.materialize_findings(),
        timestamp=timestamp,
        renderer=renderer.renderer,
        preserve_extension_value=False,
    )
    return GenerationResult._from_input_snapshot(
        rendered_document=rendered,
        input_snapshot=input_snapshot,
        execution_context=execution_context,
    )


def _render_generation_document(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    timestamp: datetime | None,
    renderer: VexRenderer,
    preserve_extension_value: bool,
) -> str:
    """Render and validate a document for either public generation path."""
    rendered = renderer.render(
        components=components,
        findings=findings,
        timestamp=timestamp,
    )
    canonical = _canonical_rendered_text(rendered)
    return rendered if preserve_extension_value else canonical


def _findings_for_components(
    source: VulnerabilitySource,
    components: tuple[ComponentIdentity, ...],
) -> tuple[VulnerabilityFinding, ...]:
    try:
        return source.findings_for_components(components)
    except VulnerabilitySourceInputError as exc:
        raise SbomError(str(exc)) from exc


def _validate_source_before_inventory_load(source: VulnerabilitySource) -> None:
    try:
        validate_source_before_inventory_load(source)
    except VulnerabilitySourceInputError as exc:
        raise SbomError(str(exc)) from exc


def _raise_output_limit_error() -> None:
    msg = f"rendered VEX exceeds the {MAX_VEX_OUTPUT_BYTES} byte output limit"
    raise VexRenderError(msg)


def _canonical_rendered_text(rendered: object) -> str:
    """Return exact built-in UTF-8 text after enforcing the output limit."""
    if not isinstance(rendered, str):
        raise VexRenderError("rendered VEX must be text")
    _validate_rendered_output(rendered)
    return rendered if type(rendered) is str else str.__str__(rendered)


def _validate_rendered_output(rendered: str) -> None:
    encoded_bytes = 0
    try:
        for index in range(
            0,
            str.__len__(rendered),
            _OUTPUT_MEASUREMENT_CHUNK_CHARACTERS,
        ):
            chunk = str.__getitem__(
                rendered,
                slice(index, index + _OUTPUT_MEASUREMENT_CHUNK_CHARACTERS),
            )
            encoded_bytes += len(str.encode(chunk, "utf-8", errors="strict"))
            if encoded_bytes > MAX_VEX_OUTPUT_BYTES:
                _raise_output_limit_error()
    except UnicodeEncodeError as exc:
        msg = "rendered VEX must be valid UTF-8 text"
        raise VexRenderError(msg) from exc


def generate_vex_from_sbom(
    *,
    input_file: Path,
    timestamp: datetime | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM."""
    return _render_legacy_generation(
        components=load_cyclonedx_sbom(input_file),
        source=_osv_source(
            client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
            source_name=osv_source_name,
            source_url=osv_source_url,
        ),
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_sbom_result(
    *,
    input_file: Path,
    timestamp: datetime | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a report-aware result from a local CycloneDX SBOM."""
    components = load_cyclonedx_sbom(input_file)
    source = select_finding_source(
        _osv_source(
            client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
            source_name=osv_source_name,
            source_url=osv_source_url,
        )
    )
    selected_renderer = select_renderer(renderer)
    return _generate_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=selected_renderer,
        execution_context=_execution_context_for_generation(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=source.report_category,
            output_format=selected_renderer.report_format,
            execution_context=execution_context,
        ),
    )


def generate_vex_from_github_sbom(
    *,
    repository: str,
    timestamp: datetime | None = None,
    github_client: GithubSbomComponentLoader | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a GitHub Dependency Graph SBOM."""
    raw_source = _osv_source(
        client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=osv_source_name,
        source_url=osv_source_url,
    )
    _validate_source_before_inventory_load(raw_source)
    return _render_legacy_generation(
        components=_github_components(repository, github_client),
        source=raw_source,
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_github_source_result(
    *,
    repository: str,
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
    github_client: GithubSbomComponentLoader | None = None,
    github_client_factory: Callable[[], GithubSbomComponentLoader] | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a report-aware result from GitHub inventory and one source."""
    if github_client is not None and github_client_factory is not None:
        raise ValueError("github_client and github_client_factory are mutually exclusive")
    _validate_source_before_inventory_load(source)
    selected_source = select_finding_source(source)
    if github_client_factory is not None:
        github_client = github_client_factory()
    return _generate_vex_from_github_selected_source_result(
        repository=repository,
        source=selected_source,
        timestamp=timestamp,
        github_client=github_client,
        renderer=renderer,
        execution_context=execution_context,
    )


def _generate_vex_from_github_selected_source_result(
    *,
    repository: str,
    source: SelectedFindingSource,
    timestamp: datetime | None = None,
    github_client: GithubSbomComponentLoader | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate after the caller has completed remote-source preflight."""
    selected_renderer = select_renderer(renderer)
    retained_context = _execution_context_for_generation(
        inventory_source=_github_inventory_source(github_client),
        finding_source=source.report_category,
        output_format=selected_renderer.report_format,
        execution_context=execution_context,
    )
    return _generate_result(
        components=_github_components(repository, github_client),
        source=source,
        timestamp=timestamp,
        renderer=selected_renderer,
        execution_context=retained_context,
    )


def generate_vex_from_github_sbom_result(
    *,
    repository: str,
    timestamp: datetime | None = None,
    github_client: GithubSbomComponentLoader | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a report-aware result from a GitHub Dependency Graph SBOM."""
    source = _osv_source(
        client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=osv_source_name,
        source_url=osv_source_url,
    )
    return generate_vex_from_github_source_result(
        repository=repository,
        source=source,
        timestamp=timestamp,
        github_client=github_client,
        renderer=renderer,
        execution_context=execution_context,
    )


def _github_inventory_source(
    github_client: GithubSbomComponentLoader | None,
) -> InventorySourceCategory:
    return (
        InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH
        if github_client is None or type(github_client) is GithubSbomClient
        else InventorySourceCategory.CUSTOM
    )


def _github_components(
    repository: str,
    github_client: GithubSbomComponentLoader | None,
) -> tuple[ComponentIdentity, ...]:
    client = GithubSbomClient() if github_client is None else github_client
    return client.component_identities(repository)


def _osv_source(
    *,
    client: OsvClient | None,
    osv_base_url: str,
    allow_public_osv: bool,
    source_name: str | None,
    source_url: str | None,
) -> OsvSource:
    return OsvSource(
        client=client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=source_name,
        source_url=source_url,
    )


def generate_vex_from_local_findings(
    *,
    input_file: Path,
    findings_file: Path,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM and local findings."""
    return generate_vex_from_source(
        input_file=input_file,
        source=LocalFindingsSource(path=findings_file),
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_local_findings_result(
    *,
    input_file: Path,
    findings_file: Path,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a report-aware result from a local SBOM and findings file."""
    return generate_vex_from_source_result(
        input_file=input_file,
        source=LocalFindingsSource(path=findings_file),
        timestamp=timestamp,
        renderer=renderer,
        execution_context=execution_context,
    )


def _execution_context_for_generation(
    *,
    inventory_source: InventorySourceCategory,
    finding_source: FindingSourceCategory | None,
    output_format: ExecutionReportOutputFormat | None,
    execution_context: GenerationExecutionContext | None,
) -> GenerationExecutionContext | None:
    if execution_context is not None:
        if type(execution_context) is not GenerationExecutionContext:
            raise TypeError("execution_context must be a GenerationExecutionContext")
        if execution_context.inventory_source is not inventory_source:
            raise ValueError("execution context inventory_source contradicts the generation input")
        if finding_source is not None and execution_context.finding_source is not finding_source:
            raise ValueError("execution context finding_source contradicts the generation source")
        if (
            finding_source is None
            and execution_context.finding_source is not FindingSourceCategory.CUSTOM
        ):
            raise ValueError("custom generation source requires a custom finding_source")
        if output_format is not None and execution_context.output_format is not output_format:
            raise ValueError("execution context output_format contradicts the generation renderer")
        if (
            output_format is None
            and execution_context.output_format is not ExecutionReportOutputFormat.CUSTOM
        ):
            raise ValueError("custom generation renderer requires a custom output_format")
        return execution_context
    if finding_source is None or output_format is None:
        return None
    return GenerationExecutionContext(
        inventory_source=inventory_source,
        finding_source=finding_source,
        output_format=output_format,
    )
