"""CycloneDX SBOM ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyclonedx.exception import CycloneDxException
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component

from vexcalibur.domain import ComponentIdentity


class SbomError(ValueError):
    """Raised when an SBOM cannot be parsed into supported component data."""


def load_cyclonedx_json(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load supported component identities from a CycloneDX JSON SBOM."""
    try:
        with path.open(encoding="utf-8") as stream:
            raw_bom = json.load(stream)
    except OSError as exc:
        msg = f"Could not read SBOM {path}: {exc}"
        raise SbomError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"SBOM {path} is not valid JSON: {exc.msg}"
        raise SbomError(msg) from exc

    if not isinstance(raw_bom, dict):
        msg = f"SBOM {path} must be a JSON object"
        raise SbomError(msg)

    try:
        bom = Bom.from_json(data=raw_bom)  # type: ignore[attr-defined]
    except (CycloneDxException, KeyError, TypeError, ValueError) as exc:
        msg = f"SBOM {path} is not a supported CycloneDX JSON document: {exc}"
        raise SbomError(msg) from exc

    components = tuple(_iter_components(bom.components))
    identities = tuple(_component_identity(component) for component in components if component.purl)
    return tuple(
        sorted(identities, key=lambda component: (component.purl.to_string(), component.ref))
    )


def _iter_components(components: Any) -> tuple[Component, ...]:
    collected: list[Component] = []
    for component in components or ():
        if isinstance(component, Component):
            collected.append(component)
            collected.extend(_iter_components(component.components))
    return tuple(collected)


def _component_identity(component: Component) -> ComponentIdentity:
    if component.purl is None:
        msg = "component must have a package URL"
        raise SbomError(msg)

    ref = component.bom_ref.value or component.purl.to_string()
    return ComponentIdentity(
        ref=ref,
        name=component.name,
        version=component.version,
        purl=component.purl,
    )
