"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from vexcalibur.domain import (
    ComponentIdentity,
    VulnerabilityFinding,
    VulnerabilitySource,
    VulnerabilitySourceInputError,
)
from vexcalibur.github_sbom import (
    DEFAULT_GITHUB_API_URL,
    GithubSbomClient,
    resolve_github_token,
)
from vexcalibur.render import VexRenderer, VexRenderError
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClient,
    OsvSource,
    ensure_osv_client_allowed,
)
from vexcalibur.vex import CycloneDxJsonRenderer

MAX_VEX_OUTPUT_BYTES = 25 * 1024 * 1024
_OUTPUT_MEASUREMENT_CHUNK_CHARACTERS = 64 * 1024
_BUILTIN_RENDER_BASE_BYTES = 4 * 1024
_BUILTIN_RENDER_COMPONENT_BYTES = 512
# Each built-in format emits a caller-controlled string at most four times. The
# fixed budgets cover keys, indentation, enums, timestamps, and derived UUIDs.
_BUILTIN_RENDER_FINDING_BYTES = 1024
_BUILTIN_RENDER_TEXT_COPIES = 4
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
    """Generate VEX JSON from a CycloneDX SBOM and source provider.

    Args:
        input_file: CycloneDX JSON or XML file to read.
        source: Provider used to find vulnerabilities for the SBOM components.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        SbomError: The SBOM is unreadable, invalid, unsupported, or contains no
            usable components.
        VulnerabilitySourceError: The source cannot produce findings.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    components = load_cyclonedx_sbom(input_file)

    return generate_vex_from_components(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_components(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from component identities and a source provider.

    Args:
        components: Components to query and include in the VEX document.
        source: Provider used to find vulnerabilities for the components.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        SbomError: No usable components were supplied or the source rejects
            their identities.
        VulnerabilitySourceError: The source cannot produce findings.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    if not components:
        msg = "no components with package URLs were found"
        raise SbomError(msg)

    return _render_vex_from_components(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def _render_vex_from_components(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None,
) -> str:
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


def _validate_builtin_render_input(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    renderer: VexRenderer,
) -> None:
    """Reject built-in output that cannot fit before constructing its document graph."""
    from vexcalibur.csaf import Csaf20VexJsonRenderer
    from vexcalibur.openvex import OpenVexJsonRenderer

    renderer_type = type(renderer)
    if renderer_type not in {
        CycloneDxJsonRenderer,
        OpenVexJsonRenderer,
        Csaf20VexJsonRenderer,
    }:
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


def _validate_rendered_output(rendered: str) -> None:
    encoded_bytes = 0
    try:
        for index in range(0, len(rendered), _OUTPUT_MEASUREMENT_CHUNK_CHARACTERS):
            encoded_bytes += len(
                rendered[index : index + _OUTPUT_MEASUREMENT_CHUNK_CHARACTERS].encode("utf-8")
            )
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
    osv_headers: Mapping[str, str] | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM using an OSV-compatible source.

    Public OSV receives package inventory only when ``allow_public_osv`` is
    true. A private mirror may be selected with ``osv_base_url``.

    Args:
        input_file: CycloneDX JSON or XML file to read.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        osv_client: Injected OSV client, primarily for private endpoints and
            tests. Its effective URL remains subject to the consent check.
        osv_base_url: OSV-compatible endpoint used when no client is supplied.
        allow_public_osv: Consent to send package inventory to public OSV.
        osv_source_name: Provenance name for a private OSV-compatible endpoint.
        osv_source_url: Provenance URL paired with ``osv_source_name``.
        osv_headers: ASCII request headers sent only to the configured OSV
            endpoint.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        SbomError: The SBOM is unreadable, invalid, unsupported, or contains no
            usable versioned components.
        OsvClientError: OSV configuration, transport, or response handling
            fails.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    components = load_cyclonedx_sbom(input_file)

    return generate_vex_from_components(
        components=components,
        source=OsvSource(
            client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
            source_name=osv_source_name,
            source_url=osv_source_url,
            headers=osv_headers,
        ),
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_github_sbom(
    *,
    repository: str,
    timestamp: datetime | None = None,
    github_api_url: str = DEFAULT_GITHUB_API_URL,
    github_token_env: str | None = None,
    use_gh_auth: bool = True,
    github_client: GithubSbomClient | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    osv_headers: Mapping[str, str] | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a GitHub Dependency Graph SBOM.

    Fetching from GitHub does not grant consent to send the resulting package
    inventory to public OSV. Set ``allow_public_osv`` explicitly for that
    separate transfer.

    Args:
        repository: GitHub repository in ``OWNER/REPO`` form.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        github_api_url: GitHub REST API base URL.
        github_token_env: Environment variable containing a printable ASCII
            GitHub token without whitespace. When omitted, standard GitHub
            token variables are checked.
        use_gh_auth: Fall back to ``gh auth token`` when environment variables
            do not provide a token.
        github_client: Injected GitHub SBOM client. The default resolves its
            token from supported GitHub environment and CLI sources.
        osv_client: Injected OSV client, primarily for private endpoints and
            tests. Its effective URL remains subject to the consent check.
        osv_base_url: OSV-compatible endpoint used when no client is supplied.
        allow_public_osv: Consent to send package inventory to public OSV.
        osv_source_name: Provenance name for a private OSV-compatible endpoint.
        osv_source_url: Provenance URL paired with ``osv_source_name``.
        osv_headers: ASCII request headers sent only to the configured OSV
            endpoint.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        GithubSbomError: GitHub configuration, transport, or SBOM parsing
            fails.
        SbomError: The fetched SBOM contains no usable versioned components.
        OsvClientError: OSV configuration, transport, or response handling
            fails.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    ensure_osv_client_allowed(
        osv_client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
    )
    source = OsvSource(
        client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        source_name=osv_source_name,
        source_url=osv_source_url,
        headers=osv_headers,
    )
    client = (
        GithubSbomClient(
            api_url=github_api_url,
            token=resolve_github_token(
                api_url=github_api_url,
                token_env=github_token_env,
                allow_gh_cli=use_gh_auth,
            ),
        )
        if github_client is None
        else github_client
    )
    return generate_vex_from_components(
        components=client.component_identities(repository),
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_local_findings(
    *,
    input_file: Path,
    findings_file: Path,
    timestamp: datetime | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM and local findings.

    Args:
        input_file: CycloneDX JSON or XML file to read.
        findings_file: Local findings JSON file to read.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        SbomError: The SBOM is unreadable, invalid, unsupported, or contains no
            usable components.
        LocalFindingsError: The findings file is unreadable or invalid.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    return generate_vex_from_source(
        input_file=input_file,
        source=LocalFindingsSource(path=findings_file),
        timestamp=timestamp,
        renderer=renderer,
    )
