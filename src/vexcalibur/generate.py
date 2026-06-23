"""SBOM-to-VEX generation workflow."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vexcalibur.sbom import SbomError, load_cyclonedx_json
from vexcalibur.sources.osv import OsvClient, findings_from_osv_results, osv_queries_for_components
from vexcalibur.vex import render_cyclonedx_vex_json


def generate_vex_from_sbom(
    *,
    input_file: Path,
    timestamp: datetime | None = None,
    osv_client: OsvClient | None = None,
) -> str:
    """Generate CycloneDX VEX JSON from a CycloneDX JSON SBOM."""
    components = load_cyclonedx_json(input_file)
    if not components:
        msg = "no components with package URLs were found"
        raise SbomError(msg)

    client = osv_client or OsvClient()
    queries = osv_queries_for_components(components)
    if not queries:
        msg = "no components with versioned package URLs were found"
        raise SbomError(msg)

    results = client.query_batch_packages(queries)
    return render_cyclonedx_vex_json(
        components=components,
        findings=findings_from_osv_results(components=components, results=results),
        timestamp=timestamp,
    )
