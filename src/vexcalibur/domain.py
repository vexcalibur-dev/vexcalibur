"""Provider-neutral Vexcalibur domain objects."""

from __future__ import annotations

from dataclasses import dataclass

from packageurl import PackageURL


@dataclass(frozen=True)
class ComponentIdentity:
    """Minimal component data needed by vulnerability sources and VEX output."""

    ref: str
    name: str
    version: str | None
    purl: PackageURL


@dataclass(frozen=True)
class VulnerabilityFinding:
    """Provider-neutral vulnerability finding for one affected component."""

    id: str
    source_name: str
    source_url: str
    component_ref: str
    purl: str
    modified: str | None = None
