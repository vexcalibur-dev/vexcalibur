"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from packageurl import PackageURL

from vexcalibur.csaf import Csaf20VexJsonRenderer
from vexcalibur.domain import (
    ComponentIdentity,
    VulnerabilityFinding,
    VulnerabilitySource,
    VulnerabilitySourceInputError,
    validate_source_before_inventory_load,
)
from vexcalibur.domain import (
    execution_report_finding_source as declared_execution_report_finding_source,
)
from vexcalibur.generation_result import (
    MAX_GENERATED_DOCUMENT_BYTES,
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)
from vexcalibur.github_sbom import GithubSbomClient, GithubSbomComponentLoader
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import (
    VexRenderer,
    VexRenderError,
)
from vexcalibur.render import (
    execution_report_output_format as declared_execution_report_output_format,
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
_BUILTIN_RENDER_BASE_BYTES = 4 * 1024
_BUILTIN_RENDER_COMPONENT_BYTES = 512
# Each built-in format emits a caller-controlled string at most four times. The
# fixed budgets cover keys, indentation, enums, timestamps, and derived UUIDs.
_BUILTIN_RENDER_FINDING_BYTES = 1024
_BUILTIN_RENDER_TEXT_COPIES = 4
_PREFLIGHT_BUDGET_RENDERER_TYPES = frozenset(
    {
        CycloneDxJsonRenderer,
        OpenVexJsonRenderer,
        Csaf20VexJsonRenderer,
    }
)


class _FrozenPackageURL(PackageURL):
    """A PackageURL snapshot whose qualifier mapping has no mutation surface."""

    __slots__ = ()

    @classmethod
    def from_package_url(cls, purl: PackageURL) -> _FrozenPackageURL:
        """Normalize and retain one package URL with immutable qualifiers."""
        normalized = PackageURL(
            type=purl.type,
            namespace=purl.namespace,
            name=purl.name,
            version=purl.version,
            qualifiers=dict(purl.qualifiers),
            subpath=purl.subpath,
        )
        return cls._make(
            (
                normalized.type,
                normalized.namespace,
                normalized.name,
                normalized.version,
                MappingProxyType(dict(normalized.qualifiers)),
                normalized.subpath,
            )
        )

    def _mutable_package_url(self) -> PackageURL:
        return PackageURL(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
            version=self.version,
            qualifiers=dict(self.qualifiers),
            subpath=self.subpath,
            normalize_purl=False,
        )

    def to_string(self, encode: bool | None = True) -> str:
        return self._mutable_package_url().to_string(encode=encode)

    def to_dict(self, encode: bool | None = False, empty: Any = None) -> dict[str, Any]:
        return self._mutable_package_url().to_dict(encode=encode, empty=empty)

    def validate(self, strict: bool = False) -> list[Any]:
        return self._mutable_package_url().validate(strict=strict)


_PURL_UNRESERVED_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)


def generate_vex_from_source(
    *,
    input_file: Path,
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM and source provider."""
    components = load_cyclonedx_sbom(input_file)
    return generate_vex_from_components(
        components=components,
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
    return _generate_vex_from_components_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
        inventory_source=InventorySourceCategory.SBOM_FILE,
        execution_context=execution_context,
    )


def generate_vex_from_components(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from component identities and a source provider."""
    _require_components(components)
    return _render_vex_from_components_document(
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
    _require_components(components)
    retained_context = _execution_context_for_generation(
        inventory_source=inventory_source,
        source=source,
        renderer=renderer,
        execution_context=execution_context,
    )
    return _render_vex_from_components_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
        execution_context=retained_context,
    )


def _require_components(components: tuple[ComponentIdentity, ...]) -> None:
    """Reject an empty normalized inventory."""
    if not components:
        msg = "no components with package URLs were found"
        raise SbomError(msg)


def _render_vex_from_components_document(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None,
) -> str:
    """Render through the object-preserving legacy extension path."""
    try:
        findings = source.findings_for_components(components)
    except VulnerabilitySourceInputError as exc:
        raise SbomError(str(exc)) from exc

    selected_renderer = CycloneDxJsonRenderer() if renderer is None else renderer
    _validate_builtin_render_input(
        components=components,
        findings=findings,
        renderer=selected_renderer,
    )
    rendered = selected_renderer.render(
        components=components,
        findings=findings,
        timestamp=timestamp,
    )
    _validate_rendered_output(rendered)
    return rendered


def _render_vex_from_components_result(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None,
    execution_context: GenerationExecutionContext | None,
) -> GenerationResult:
    components = tuple(_snapshot_component(component) for component in components)
    try:
        findings = tuple(
            _snapshot_finding(finding) for finding in source.findings_for_components(components)
        )
    except VulnerabilitySourceInputError as exc:
        raise SbomError(str(exc)) from exc

    selected_renderer = CycloneDxJsonRenderer() if renderer is None else renderer
    _validate_builtin_render_input(
        components=components,
        findings=findings,
        renderer=selected_renderer,
    )
    rendered = _canonical_rendered_text(
        selected_renderer.render(
            components=components,
            findings=findings,
            timestamp=timestamp,
        )
    )
    return GenerationResult(
        rendered_document=rendered,
        components=components,
        findings=findings,
        execution_context=execution_context,
    )


def _snapshot_component(component: ComponentIdentity) -> ComponentIdentity:
    """Copy one extension-supplied component into the exact domain type."""
    if not isinstance(component, ComponentIdentity):
        raise TypeError("components must contain ComponentIdentity values")
    return ComponentIdentity(
        ref=component.ref,
        name=component.name,
        version=component.version,
        purl=_FrozenPackageURL.from_package_url(component.purl),
        type=component.type,
    )


def _snapshot_finding(finding: VulnerabilityFinding) -> VulnerabilityFinding:
    """Copy one extension-supplied finding into the exact domain type."""
    if not isinstance(finding, VulnerabilityFinding):
        raise TypeError("findings must contain VulnerabilityFinding values")
    return VulnerabilityFinding(
        id=finding.id,
        source_name=finding.source_name,
        source_url=finding.source_url,
        component_ref=finding.component_ref,
        purl=finding.purl,
        modified=finding.modified,
        analysis_state=finding.analysis_state,
        analysis_detail=finding.analysis_detail,
        action_statement=finding.action_statement,
        impact_statement=finding.impact_statement,
        fixed_version=finding.fixed_version,
        remediation_category=finding.remediation_category,
    )


def _validate_builtin_render_input(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    renderer: VexRenderer,
) -> None:
    """Reject built-in output that cannot fit before constructing its document graph."""
    renderer_type = type(renderer)
    if renderer_type not in _PREFLIGHT_BUDGET_RENDERER_TYPES:
        return

    budget = _BuiltinRenderBudget(MAX_VEX_OUTPUT_BYTES)
    budget.add_fixed(_BUILTIN_RENDER_BASE_BYTES)
    components_by_ref = {component.ref: component for component in components}
    referenced_component_refs = {finding.component_ref for finding in findings}
    for component in components:
        if component.ref not in referenced_component_refs:
            continue
        budget.add_package_url(component, copies=1)
        budget.add_fixed(_BUILTIN_RENDER_COMPONENT_BYTES)
        for value in (
            component.ref,
            component.name,
            component.version,
            component.type,
        ):
            budget.add_text(value)
        if renderer_type is not OpenVexJsonRenderer:
            budget.add_package_url(component, copies=1)

    for finding in findings:
        budget.add_fixed(_BUILTIN_RENDER_FINDING_BYTES)
        for field_name in (
            "id",
            "source_name",
            "source_url",
            "component_ref",
            "purl",
            "analysis_detail",
            "action_statement",
            "impact_statement",
            "fixed_version",
        ):
            budget.add_text(getattr(finding, field_name, None))
        if renderer_type is OpenVexJsonRenderer:
            referenced_component = components_by_ref.get(finding.component_ref)
            if referenced_component is not None:
                # A distinct OpenVEX statement can emit the synthesized,
                # versioned PURL twice. Per-finding accounting safely bounds
                # the worst case even when some findings later group together.
                budget.add_package_url(referenced_component, copies=2)

    if isinstance(renderer, OpenVexJsonRenderer):
        budget.add_text(renderer.author)
        budget.add_text(renderer.role)
    elif isinstance(renderer, Csaf20VexJsonRenderer):
        metadata = renderer.metadata
        for value in (
            metadata.document_id,
            metadata.title,
            metadata.publisher_name,
            metadata.publisher_namespace,
            renderer.tool_version,
        ):
            budget.add_text(value)


class _BuiltinRenderBudget:
    """Conservative upper budget for JSON emitted by Vexcalibur renderers."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used = 0

    def add_fixed(self, size: int) -> None:
        self._used += size
        if self._used > self._limit:
            _raise_preflight_output_limit_error()

    def add_text(self, value: object) -> None:
        if value is None or not isinstance(value, str):
            return

        self.add_fixed(2 * _BUILTIN_RENDER_TEXT_COPIES)  # JSON string delimiters.
        for character in value:
            character_size = _json_escaped_character_size(character)
            self.add_fixed(character_size * _BUILTIN_RENDER_TEXT_COPIES)

    def add_package_url(self, component: ComponentIdentity, *, copies: int) -> None:
        """Budget canonical and version-derived PURLs without constructing them."""
        purl = component.purl
        effective_version = purl.version if purl.version is not None else component.version
        qualifiers = purl.qualifiers
        syntax_bytes = 16 + (4 * len(qualifiers))
        self.add_fixed(syntax_bytes * copies)
        for value in (
            purl.type,
            purl.namespace,
            purl.name,
            effective_version,
            purl.subpath,
        ):
            self._add_percent_encoded_text(value, copies=copies)
        for key, value in qualifiers.items():
            self._add_percent_encoded_text(key, copies=copies)
            self._add_percent_encoded_text(value, copies=copies)

    def _add_percent_encoded_text(self, value: str | None, *, copies: int) -> None:
        if value is None:
            return
        for character in value:
            encoded_size = _percent_encoded_character_size(character)
            self.add_fixed(encoded_size * copies)


def _json_escaped_character_size(character: str) -> int:
    codepoint = ord(character)
    if character in {'"', "\\"}:
        return 2
    if codepoint <= 0x1F:
        return 6
    if codepoint <= 0x7F:
        return 1
    if codepoint <= 0xFFFF:
        return 6
    return 12


def _percent_encoded_character_size(character: str) -> int:
    if character in _PURL_UNRESERVED_CHARACTERS:
        return 1
    codepoint = ord(character)
    if codepoint <= 0x7F:
        return 3
    if codepoint <= 0x7FF:
        return 6
    if codepoint <= 0xFFFF:
        return 9
    return 12


def _raise_output_limit_error() -> None:
    msg = f"rendered VEX exceeds the {MAX_VEX_OUTPUT_BYTES} byte output limit"
    raise VexRenderError(msg)


def _raise_preflight_output_limit_error() -> None:
    msg = f"VEX input exceeds the conservative {MAX_VEX_OUTPUT_BYTES} byte output limit estimate"
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
    components = load_cyclonedx_sbom(input_file)
    source = OsvSource(
        client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=osv_source_name,
        source_url=osv_source_url,
    )
    return generate_vex_from_components(
        components=components,
        source=source,
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
    source = OsvSource(
        client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=osv_source_name,
        source_url=osv_source_url,
    )

    return _generate_vex_from_components_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
        inventory_source=InventorySourceCategory.SBOM_FILE,
        execution_context=execution_context,
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
    source = OsvSource(
        client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=osv_source_name,
        source_url=osv_source_url,
    )
    validate_source_before_inventory_load(source)
    client = GithubSbomClient() if github_client is None else github_client
    components = client.component_identities(repository)
    return generate_vex_from_components(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_github_source_result(
    *,
    repository: str,
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
    github_client: GithubSbomComponentLoader | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate a report-aware result from GitHub inventory and one source."""
    validate_source_before_inventory_load(source)
    retained_context = _execution_context_for_generation(
        inventory_source=InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH,
        source=source,
        renderer=renderer,
        execution_context=execution_context,
    )
    client = GithubSbomClient() if github_client is None else github_client
    components = client.component_identities(repository)
    _require_components(components)
    return _render_vex_from_components_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
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
    source = OsvSource(
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
    source: VulnerabilitySource,
    renderer: VexRenderer | None,
    execution_context: GenerationExecutionContext | None,
) -> GenerationExecutionContext | None:
    finding_source = _execution_report_finding_source(source)
    selected_renderer = CycloneDxJsonRenderer() if renderer is None else renderer
    output_format = _execution_report_output_format(selected_renderer)
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


def _execution_report_finding_source(
    source: VulnerabilitySource,
) -> FindingSourceCategory | None:
    """Reserve built-in provenance for Vexcalibur's exact source types."""
    if isinstance(source, LocalFindingsSource) and type(source) is LocalFindingsSource:
        return source._vexcalibur_execution_report_finding_source()
    if isinstance(source, OsvSource) and type(source) is OsvSource:
        return source._vexcalibur_execution_report_finding_source()
    return declared_execution_report_finding_source(source)


def _execution_report_output_format(
    renderer: VexRenderer,
) -> ExecutionReportOutputFormat | None:
    """Reserve built-in formats for Vexcalibur's exact renderer types."""
    if isinstance(renderer, CycloneDxJsonRenderer) and type(renderer) is CycloneDxJsonRenderer:
        return renderer._vexcalibur_execution_report_output_format()
    if isinstance(renderer, OpenVexJsonRenderer) and type(renderer) is OpenVexJsonRenderer:
        return renderer._vexcalibur_execution_report_output_format()
    if isinstance(renderer, Csaf20VexJsonRenderer) and type(renderer) is Csaf20VexJsonRenderer:
        return renderer._vexcalibur_execution_report_output_format()
    return declared_execution_report_output_format(renderer)
