"""Provider-neutral Vexcalibur domain objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from packageurl import PackageURL

DEFAULT_ANALYSIS_DETAIL = "Detected by OSV; manual exploitability analysis required."


class VexAnalysisState(str, Enum):
    """CycloneDX VEX analysis states supported by the domain model."""

    RESOLVED = "resolved"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"


@dataclass(frozen=True)
class ComponentIdentity:
    """Minimal component data needed by vulnerability sources and VEX output."""

    ref: str
    name: str
    version: str | None
    purl: PackageURL
    type: str = "library"


@dataclass(frozen=True)
class VulnerabilityFinding:
    """Provider-neutral vulnerability finding for one affected component."""

    id: str
    source_name: str
    source_url: str
    component_ref: str
    purl: str
    modified: datetime | None = None
    analysis_state: VexAnalysisState = VexAnalysisState.IN_TRIAGE
    analysis_detail: str = DEFAULT_ANALYSIS_DETAIL
