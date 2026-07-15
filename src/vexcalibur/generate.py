"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vexcalibur.domain import ComponentIdentity, VulnerabilitySource, VulnerabilitySourceInputError
from vexcalibur.github_sbom import GithubSbomClient
from vexcalibur.render import VexRenderer
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClient,
    OsvSource,
    ensure_osv_client_allowed,
)
from vexcalibur.vex import CycloneDxJsonRenderer


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


def generate_vex_from_components(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from component identities and a source provider."""
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
    return selected_renderer.render(
        components=components,
        findings=findings,
        timestamp=timestamp,
    )


def generate_vex_from_sbom(
    *,
    input_file: Path,
    timestamp: datetime | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM."""
    components = load_cyclonedx_sbom(input_file)

    return generate_vex_from_components(
        components=components,
        source=OsvSource(
            client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
        ),
        timestamp=timestamp,
        renderer=renderer,
    )


def generate_vex_from_github_sbom(
    *,
    repository: str,
    timestamp: datetime | None = None,
    github_client: GithubSbomClient | None = None,
    osv_client: OsvClient | None = None,
    osv_base_url: str = DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a GitHub Dependency Graph SBOM."""
    ensure_osv_client_allowed(
        osv_client=osv_client,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
    )
    client = GithubSbomClient() if github_client is None else github_client
    return generate_vex_from_components(
        components=client.component_identities(repository),
        source=OsvSource(
            client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
        ),
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
    """Generate VEX JSON from a CycloneDX SBOM and local findings."""
    return generate_vex_from_source(
        input_file=input_file,
        source=LocalFindingsSource(path=findings_file),
        timestamp=timestamp,
        renderer=renderer,
    )
