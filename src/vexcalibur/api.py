"""Supported Python API for Vexcalibur applications and extensions.

Only names exported by this module are covered by Vexcalibur's public API
compatibility policy. Other package modules remain importable so Vexcalibur can
test and develop them, but applications should not depend on those modules.
"""

from __future__ import annotations

import datetime as _datetime
import pathlib as _pathlib
from collections.abc import Mapping as _Mapping

from vexcalibur.csaf import (
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafDocumentStatus,
    CsafPublisherCategory,
    CsafRenderError,
)
from vexcalibur.domain import (
    ComponentIdentity,
    ComponentVersionError,
    GenerationSourcePreflight,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
    VulnerabilitySource,
    VulnerabilitySourceError,
    VulnerabilitySourceInputError,
)
from vexcalibur.generate import (
    generate_vex_from_components,
    generate_vex_from_local_findings,
    generate_vex_from_source,
)
from vexcalibur.generate import (
    generate_vex_from_components_result as _generate_vex_from_components_result,
)
from vexcalibur.generate import (
    generate_vex_from_github_sbom as _generate_vex_from_github_sbom,
)
from vexcalibur.generate import (
    generate_vex_from_github_sbom_result as _generate_vex_from_github_sbom_result,
)
from vexcalibur.generate import (
    generate_vex_from_github_source_result as _generate_vex_from_github_source_result,
)
from vexcalibur.generate import (
    generate_vex_from_local_findings_result as _generate_vex_from_local_findings_result,
)
from vexcalibur.generate import (
    generate_vex_from_sbom as _generate_vex_from_sbom,
)
from vexcalibur.generate import (
    generate_vex_from_sbom_result as _generate_vex_from_sbom_result,
)
from vexcalibur.generate import (
    generate_vex_from_source_result as _generate_vex_from_source_result,
)
from vexcalibur.generation_result import (
    EXECUTION_REPORT_SCHEMA_VERSION,
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GeneratedDocumentMetadata,
    GeneratedDocumentMetadataDict,
    GenerationExecutionContext,
    GenerationExecutionReport,
    GenerationExecutionReportDict,
    GenerationExecutionReportParseError,
    GenerationReportMetadataError,
    GenerationResult,
    InventorySourceCategory,
    parse_generation_execution_report,
)
from vexcalibur.github_sbom import (
    DEFAULT_GITHUB_API_URL as _DEFAULT_GITHUB_API_URL,
)
from vexcalibur.github_sbom import (
    GithubSbomClient as _GithubSbomClient,
)
from vexcalibur.github_sbom import (
    GithubSbomClientError,
    GithubSbomConfigurationError,
    GithubSbomError,
)
from vexcalibur.github_sbom import resolve_github_token as _resolve_github_token
from vexcalibur.openvex import OpenVexJsonRenderer, OpenVexRenderError
from vexcalibur.render import VexRenderer, VexRenderError
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsError
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL as _DEFAULT_OSV_API_URL,
)
from vexcalibur.sources.osv import (
    OsvClientError,
    OsvConfigurationError,
    OsvResponseError,
)
from vexcalibur.vex import CycloneDxJsonRenderer


def generate_vex_from_sbom(
    *,
    input_file: _pathlib.Path,
    timestamp: _datetime.datetime | None = None,
    osv_base_url: str = _DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    osv_headers: _Mapping[str, str] | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a CycloneDX SBOM using an OSV-compatible source.

    Args:
        input_file: CycloneDX JSON or XML file to read.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        osv_base_url: OSV-compatible endpoint.
        allow_public_osv: Consent to send package inventory to public OSV.
        osv_source_name: Provenance name for a private compatible endpoint.
        osv_source_url: Provenance URL paired with ``osv_source_name``.
        osv_headers: ASCII request headers sent only to the configured OSV
            endpoint.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        SbomError: The SBOM is unreadable, invalid, unsupported, or contains no
            usable versioned components.
        OsvClientError: OSV configuration, transport, or response handling
            fails.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    return _generate_vex_from_sbom(
        input_file=input_file,
        timestamp=timestamp,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        osv_source_name=osv_source_name,
        osv_source_url=osv_source_url,
        osv_headers=osv_headers,
        renderer=renderer,
    )


def generate_vex_from_sbom_result(
    *,
    input_file: _pathlib.Path,
    timestamp: _datetime.datetime | None = None,
    osv_base_url: str = _DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    osv_headers: _Mapping[str, str] | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate report-aware VEX from a local CycloneDX SBOM."""
    return _generate_vex_from_sbom_result(
        input_file=input_file,
        timestamp=timestamp,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        osv_source_name=osv_source_name,
        osv_source_url=osv_source_url,
        osv_headers=osv_headers,
        renderer=renderer,
        execution_context=execution_context,
    )


def generate_vex_from_github_sbom(
    *,
    repository: str,
    timestamp: _datetime.datetime | None = None,
    github_api_url: str = _DEFAULT_GITHUB_API_URL,
    github_token_env: str | None = None,
    use_gh_auth: bool = True,
    osv_base_url: str = _DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    osv_headers: _Mapping[str, str] | None = None,
    renderer: VexRenderer | None = None,
) -> str:
    """Generate VEX JSON from a GitHub Dependency Graph SBOM.

    Fetching from GitHub does not grant consent to send the resulting package
    inventory to public OSV. Set ``allow_public_osv`` explicitly for that
    separate transfer.

    Args:
        repository: GitHub repository in ``OWNER/REPO`` form.
        timestamp: Document timestamp. The renderer uses the current UTC time
            when this is ``None``.
        github_api_url: GitHub REST API base URL.
        github_token_env: Environment variable containing a printable ASCII
            GitHub token without whitespace. When omitted, standard GitHub
            token variables are checked.
        use_gh_auth: Fall back to ``gh auth token`` when environment variables
            do not provide a token.
        osv_base_url: OSV-compatible endpoint.
        allow_public_osv: Consent to send package inventory to public OSV.
        osv_source_name: Provenance name for a private compatible endpoint.
        osv_source_url: Provenance URL paired with ``osv_source_name``.
        osv_headers: ASCII request headers sent only to the configured OSV
            endpoint.
        renderer: Output renderer. The default emits CycloneDX 1.6 JSON.

    Returns:
        The serialized VEX document.

    Raises:
        GithubSbomError: GitHub configuration, transport, or SBOM parsing
            fails.
        SbomError: The fetched SBOM contains no usable versioned components.
        OsvClientError: OSV configuration, transport, or response handling
            fails.
        VexRenderError: The findings cannot be rendered within output limits.
    """
    return _generate_vex_from_github_sbom(
        repository=repository,
        timestamp=timestamp,
        github_api_url=github_api_url,
        github_token_env=github_token_env,
        use_gh_auth=use_gh_auth,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        osv_source_name=osv_source_name,
        osv_source_url=osv_source_url,
        osv_headers=osv_headers,
        renderer=renderer,
    )


def generate_vex_from_github_sbom_result(
    *,
    repository: str,
    timestamp: _datetime.datetime | None = None,
    github_api_url: str = _DEFAULT_GITHUB_API_URL,
    github_token_env: str | None = None,
    use_gh_auth: bool = True,
    osv_base_url: str = _DEFAULT_OSV_API_URL,
    allow_public_osv: bool = False,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
    osv_headers: _Mapping[str, str] | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate report-aware VEX from a GitHub Dependency Graph SBOM."""
    return _generate_vex_from_github_sbom_result(
        repository=repository,
        timestamp=timestamp,
        github_api_url=github_api_url,
        github_token_env=github_token_env,
        use_gh_auth=use_gh_auth,
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
        osv_source_name=osv_source_name,
        osv_source_url=osv_source_url,
        osv_headers=osv_headers,
        renderer=renderer,
        execution_context=execution_context,
    )


def generate_vex_from_github_source_result(
    *,
    repository: str,
    source: VulnerabilitySource,
    timestamp: _datetime.datetime | None = None,
    github_api_url: str = _DEFAULT_GITHUB_API_URL,
    github_token_env: str | None = None,
    use_gh_auth: bool = True,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate report-aware VEX from GitHub inventory and a custom source."""

    def create_github_client() -> _GithubSbomClient:
        return _GithubSbomClient(
            api_url=github_api_url,
            token=_resolve_github_token(
                api_url=github_api_url,
                token_env=github_token_env,
                allow_gh_cli=use_gh_auth,
            ),
        )

    return _generate_vex_from_github_source_result(
        repository=repository,
        source=source,
        timestamp=timestamp,
        github_client_factory=create_github_client,
        renderer=renderer,
        execution_context=execution_context,
    )


def generate_vex_from_source_result(
    *,
    input_file: _pathlib.Path,
    source: VulnerabilitySource,
    timestamp: _datetime.datetime | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate report-aware VEX from a CycloneDX SBOM and custom source."""
    return _generate_vex_from_source_result(
        input_file=input_file,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
        execution_context=execution_context,
    )


def generate_vex_from_components_result(
    *,
    components: tuple[ComponentIdentity, ...],
    source: VulnerabilitySource,
    timestamp: _datetime.datetime | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate report-aware VEX from caller-supplied components and source."""
    return _generate_vex_from_components_result(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
        execution_context=execution_context,
    )


def generate_vex_from_local_findings_result(
    *,
    input_file: _pathlib.Path,
    findings_file: _pathlib.Path,
    timestamp: _datetime.datetime | None = None,
    renderer: VexRenderer | None = None,
    execution_context: GenerationExecutionContext | None = None,
) -> GenerationResult:
    """Generate report-aware VEX from local CycloneDX and findings files."""
    return _generate_vex_from_local_findings_result(
        input_file=input_file,
        findings_file=findings_file,
        timestamp=timestamp,
        renderer=renderer,
        execution_context=execution_context,
    )


__all__ = [
    "EXECUTION_REPORT_SCHEMA_VERSION",
    "ComponentIdentity",
    "ComponentVersionError",
    "Csaf20DocumentMetadata",
    "Csaf20VexJsonRenderer",
    "CsafDocumentStatus",
    "CsafPublisherCategory",
    "CsafRenderError",
    "CycloneDxJsonRenderer",
    "ExecutionReportOutputFormat",
    "FindingSourceCategory",
    "GeneratedDocumentMetadata",
    "GeneratedDocumentMetadataDict",
    "GenerationExecutionContext",
    "GenerationExecutionReport",
    "GenerationExecutionReportDict",
    "GenerationExecutionReportParseError",
    "GenerationReportMetadataError",
    "GenerationResult",
    "GenerationSourcePreflight",
    "GithubSbomClientError",
    "GithubSbomConfigurationError",
    "GithubSbomError",
    "InventorySourceCategory",
    "LocalFindingsError",
    "OpenVexJsonRenderer",
    "OpenVexRenderError",
    "OsvClientError",
    "OsvConfigurationError",
    "OsvResponseError",
    "SbomError",
    "VexAnalysisState",
    "VexRemediationCategory",
    "VexRenderError",
    "VexRenderer",
    "VulnerabilityFinding",
    "VulnerabilitySource",
    "VulnerabilitySourceError",
    "VulnerabilitySourceInputError",
    "generate_vex_from_components",
    "generate_vex_from_components_result",
    "generate_vex_from_github_sbom",
    "generate_vex_from_github_sbom_result",
    "generate_vex_from_github_source_result",
    "generate_vex_from_local_findings",
    "generate_vex_from_local_findings_result",
    "generate_vex_from_sbom",
    "generate_vex_from_sbom_result",
    "generate_vex_from_source",
    "generate_vex_from_source_result",
    "load_cyclonedx_sbom",
    "parse_generation_execution_report",
]
