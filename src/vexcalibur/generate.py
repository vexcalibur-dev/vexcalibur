"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vexcalibur.domain import ComponentIdentity, VulnerabilitySource, VulnerabilitySourceInputError
from vexcalibur.sbom import SbomError, load_cyclonedx_json
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClient,
    OsvSource,
)
from vexcalibur.vex import render_cyclonedx_vex_json


def generate_vex_from_source(
    *,
    input_file: Path,
    source: VulnerabilitySource,
    timestamp: datetime | None = None,
) -> str:
    """Generate CycloneDX VEX JSON from a CycloneDX JSON SBOM and source provider."""
    components = load_cyclonedx_json(input_file)
    if not components:
        msg = "no components with package URLs were found"
        raise SbomError(msg)

    return _render_vex_from_components(
        components=components,
        source=source,
        timestamp=timestamp,
    )


def _render_vex_from_components(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: datetime | None,
) -> str:
    try:
        findings = source.findings_for_components(components)
    except VulnerabilitySourceInputError as exc:
        raise SbomError(str(exc)) from exc

    return render_cyclonedx_vex_json(
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
) -> str:
    """Generate CycloneDX VEX JSON from a CycloneDX JSON SBOM."""
    components = load_cyclonedx_json(input_file)
    if not components:
        msg = "no components with package URLs were found"
        raise SbomError(msg)

    return _render_vex_from_components(
        components=components,
        source=OsvSource(
            client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
        ),
        timestamp=timestamp,
    )


def generate_vex_from_local_findings(
    *,
    input_file: Path,
    findings_file: Path,
    timestamp: datetime | None = None,
) -> str:
    """Generate CycloneDX VEX JSON from a CycloneDX JSON SBOM and local findings."""
    return generate_vex_from_source(
        input_file=input_file,
        source=LocalFindingsSource(path=findings_file),
        timestamp=timestamp,
    )
