"""Provider-neutral Vexcalibur domain objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal, Protocol, runtime_checkable

from packageurl import PackageURL

from vexcalibur.generation_context import FindingSourceCategory

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
    """Minimal component data needed by vulnerability sources and VEX output."""

    ref: str
    name: str
    version: str | None
    purl: PackageURL
    type: str = "library"

    def __post_init__(self) -> None:
        canonical_component_version(version=self.version, purl=self.purl)


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
        """Return VEX-ready vulnerability findings for SBOM components."""


@runtime_checkable
class ExecutionReportFindingSourceDeclaration(Protocol):
    """Report-provenance capability for a custom finding source."""

    def execution_report_finding_source(
        self,
    ) -> Literal[FindingSourceCategory.CUSTOM]:
        """Return the custom finding-source report category."""


@runtime_checkable
class GenerationSourcePreflight(Protocol):
    """Source policy checks that must run before loading remote inventory."""

    def validate_before_inventory_load(self) -> None:
        """Validate source policy without making a request."""


def execution_report_finding_source(
    source: VulnerabilitySource,
) -> FindingSourceCategory | None:
    """Resolve a custom source's declared execution-report provenance."""
    if not isinstance(source, ExecutionReportFindingSourceDeclaration):
        return None
    category = source.execution_report_finding_source()
    if not isinstance(category, FindingSourceCategory):
        raise TypeError(
            f"{type(source).__name__} execution report category must be a FindingSourceCategory"
        )
    if category is not FindingSourceCategory.CUSTOM:
        raise ValueError(
            f"{type(source).__name__} execution report category must be "
            "FindingSourceCategory.CUSTOM"
        )
    return category


def validate_source_before_inventory_load(source: VulnerabilitySource) -> None:
    """Run a source-owned preflight when the source provides one."""
    if isinstance(source, GenerationSourcePreflight):
        source.validate_before_inventory_load()
