"""Provider-neutral Vexcalibur domain objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

from packageurl import PackageURL

DEFAULT_ANALYSIS_DETAIL = (
    "Detected by vulnerability source; manual exploitability analysis required."
)


class ComponentVersionError(ValueError):
    """Raised when a component carries contradictory version identities."""


def canonical_component_version(*, version: str | None, purl: PackageURL) -> str | None:
    """Return the effective version after checking explicit and PURL values."""
    purl_version = purl.version
    if version is not None and purl_version is not None and version != purl_version:
        msg = f"component version {version!r} does not match package URL version {purl_version!r}"
        raise ComponentVersionError(msg)
    return purl_version if purl_version is not None else version


class VexAnalysisState(str, Enum):
    """Vulnerability analysis states supported by the domain model."""

    RESOLVED = "resolved"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"


class VexRemediationCategory(str, Enum):
    """Remediation categories that a VEX output format may represent."""

    MITIGATION = "mitigation"
    NO_FIX_PLANNED = "no_fix_planned"
    NONE_AVAILABLE = "none_available"
    VENDOR_FIX = "vendor_fix"
    WORKAROUND = "workaround"


@dataclass(frozen=True)
class ComponentIdentity:
    """Minimal component data needed by vulnerability sources and VEX output.

    Attributes:
        ref: Source document identifier used to associate findings.
        name: Human-readable component name.
        version: Explicit component version, if supplied separately from its
            package URL.
        purl: Canonical package URL identifying the component.
        type: CycloneDX component type used by applicable renderers.

    Raises:
        ComponentVersionError: ``version`` contradicts the package URL version.
    """

    ref: str
    name: str
    version: str | None
    purl: PackageURL
    type: str = "library"

    def __post_init__(self) -> None:
        canonical_component_version(version=self.version, purl=self.purl)


@dataclass(frozen=True)
class VulnerabilityFinding:
    """Provider-neutral vulnerability finding for one affected component.

    Attributes:
        id: Vulnerability identifier.
        source_name: Display name for the vulnerability source.
        source_url: HTTP or HTTPS provenance URL for the source.
        component_ref: Reference of the affected ``ComponentIdentity``.
        purl: Package URL reported by the source.
        modified: Source modification timestamp, when known.
        analysis_state: Exploitability assessment represented in the VEX.
        analysis_detail: Human-readable reason for the assessment.
        action_statement: Action that a consumer should take, when applicable.
        impact_statement: Reason the product is not affected, when applicable.
        fixed_version: First known fixed version, when applicable.
        remediation_category: Kind of remediation represented by the action.
    """

    id: str
    source_name: str
    source_url: str
    component_ref: str
    purl: str
    modified: datetime | None = None
    analysis_state: VexAnalysisState = VexAnalysisState.IN_TRIAGE
    analysis_detail: str = DEFAULT_ANALYSIS_DETAIL
    action_statement: str | None = None
    impact_statement: str | None = None
    fixed_version: str | None = None
    remediation_category: VexRemediationCategory | None = None


class VulnerabilitySourceError(RuntimeError):
    """Base error raised by provider-neutral vulnerability sources."""


class VulnerabilitySourceInputError(VulnerabilitySourceError, ValueError):
    """Raised when source-specific findings cannot be produced from the input components."""


class VulnerabilitySource(Protocol):
    """Provider-neutral contract for vulnerability finding sources."""

    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        """Return VEX-ready vulnerability findings for SBOM components.

        Args:
            components: Immutable component identities to inspect.

        Returns:
            Immutable findings whose component references identify members of
            ``components``.

        Raises:
            VulnerabilitySourceError: The source cannot produce findings.
        """
