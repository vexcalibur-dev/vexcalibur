"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vexcalibur.sbom import SbomError, load_cyclonedx_json
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClient,
    ensure_osv_client_allowed,
    findings_from_osv_results,
    osv_client_for_url,
    osv_queries_for_components,
)
from vexcalibur.vex import render_cyclonedx_vex_json


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

    queries = osv_queries_for_components(components)
    if not queries:
        msg = "no components with versioned package URLs were found"
        raise SbomError(msg)

    if osv_client is None:
        client = osv_client_for_url(
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
        )
    else:
        ensure_osv_client_allowed(
            osv_client=osv_client,
            osv_base_url=osv_base_url,
            allow_public_osv=allow_public_osv,
        )
        client = osv_client

    results = client.query_batch_packages(queries)
    return render_cyclonedx_vex_json(
        components=components,
        findings=findings_from_osv_results(components=components, results=results),
        timestamp=timestamp,
    )
