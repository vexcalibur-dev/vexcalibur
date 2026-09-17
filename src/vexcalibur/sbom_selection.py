"""Local SBOM format selection for supported inventory documents."""

from __future__ import annotations

from pathlib import Path

from vexcalibur.domain import ComponentIdentity
from vexcalibur.json_boundary import StrictJsonError, strict_json_loads
from vexcalibur.sbom import (
    SbomError,
    _looks_like_xml,
    _read_sbom_bytes,
    _sbom_json_error_message,
    component_identities_from_cyclonedx_json,
    component_identities_from_cyclonedx_xml,
)
from vexcalibur.spdx3_sbom import component_identities_from_spdx3_document


def load_sbom(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load component identities from a CycloneDX or SPDX 3 SBOM file.

    XML content is CycloneDX. JSON content selects its format from one
    top-level marker: ``bomFormat`` for CycloneDX or ``@graph`` for SPDX 3
    JSON-LD. A document carrying both markers is rejected instead of guessed.

    Args:
        path: Regular file containing a supported SBOM document.

    Returns:
        Immutable component identities sorted by package URL and reference.
        Components without package URLs are omitted.

    Raises:
        SbomError: The file is unreadable, oversized, malformed, unsupported,
            ambiguous, or contains unsafe or contradictory component data.
    """
    raw_content = _read_sbom_bytes(path)
    if _looks_like_xml(raw_content):
        return component_identities_from_cyclonedx_xml(raw_content, path=path)

    try:
        raw_document = strict_json_loads(raw_content)
    except StrictJsonError as exc:
        msg = _sbom_json_error_message(path=path, error=exc)
        raise SbomError(msg) from exc
    if not isinstance(raw_document, dict):
        msg = f"SBOM {path} must be a JSON object"
        raise SbomError(msg)

    is_cyclonedx = "bomFormat" in raw_document
    is_spdx3 = "@graph" in raw_document
    if is_cyclonedx and is_spdx3:
        msg = f"SBOM {path} carries both CycloneDX and SPDX 3 format markers"
        raise SbomError(msg)
    if is_cyclonedx:
        return component_identities_from_cyclonedx_json(raw_document, path=path)
    if is_spdx3:
        return component_identities_from_spdx3_document(raw_document, path=path)
    msg = (
        f"SBOM {path} is not a supported SBOM document; expected CycloneDX "
        "1.4-1.6 JSON or XML, or SPDX 3.0.1 JSON-LD"
    )
    raise SbomError(msg)
