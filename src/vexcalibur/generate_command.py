"""Typed application request for the ``generate`` CLI command."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from vexcalibur.domain import VulnerabilitySource, validate_source_before_inventory_load
from vexcalibur.generate import (
    generate_vex_from_github_source_result,
    generate_vex_from_local_findings_result,
    generate_vex_from_sbom_result,
)
from vexcalibur.generation_result import GenerationResult
from vexcalibur.github_sbom import (
    GithubSbomClient,
    normalize_github_api_url,
    parse_github_repository,
    resolve_github_token,
)
from vexcalibur.render import VexRenderer
from vexcalibur.source_options import (
    GenerateSourceOptionError,
    GenerateSourceOptions,
)
from vexcalibur.sources.local import LocalFindingsSource
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvSource,
)


@dataclass(frozen=True)
class GenerateCommandRequest:
    """Validated inventory, source, and rendering choices for one command."""

    input_file: Path | None
    github_repository: str | None
    github_api_url: str
    github_token_env: str | None
    use_gh_auth: bool
    source_options: GenerateSourceOptions
    timestamp: datetime | None
    renderer: VexRenderer | None

    def __post_init__(self) -> None:
        self.validate_input_selection(
            input_file=self.input_file,
            github_repository=self.github_repository,
            offline=self.source_options.offline,
        )
        if self.github_repository is not None:
            repository = parse_github_repository(self.github_repository)
            object.__setattr__(self, "github_repository", repository.full_name)
            object.__setattr__(
                self,
                "github_api_url",
                normalize_github_api_url(self.github_api_url),
            )

    @staticmethod
    def validate_input_selection(
        *,
        input_file: Path | None,
        github_repository: str | None,
        offline: bool,
    ) -> None:
        """Validate inventory options before resolving provider options."""
        if input_file is None and github_repository is None:
            raise GenerateSourceOptionError("either INPUT_FILE or --github-repo is required")
        if input_file is not None and github_repository is not None:
            raise GenerateSourceOptionError("INPUT_FILE cannot be combined with --github-repo")
        if github_repository is not None and offline:
            msg = (
                "--offline cannot be combined with --github-repo because fetching "
                "a GitHub SBOM uses network"
            )
            raise GenerateSourceOptionError(msg)

    def execute(self) -> GenerationResult:
        """Load the selected inventory and return its rendered generation result."""
        if self.github_repository is not None:
            return self._execute_github()
        if self.input_file is None:
            raise AssertionError("generate request input validation failed")
        if self.source_options.findings_file is not None:
            return generate_vex_from_local_findings_result(
                input_file=self.input_file,
                findings_file=self.source_options.findings_file,
                timestamp=self.timestamp,
                renderer=self.renderer,
            )
        return generate_vex_from_sbom_result(
            input_file=self.input_file,
            timestamp=self.timestamp,
            osv_base_url=self._osv_url,
            allow_public_osv=self.source_options.allow_public_osv,
            osv_source_name=self.source_options.osv_source_name,
            osv_source_url=self.source_options.osv_source_url,
            renderer=self.renderer,
        )

    def _execute_github(self) -> GenerationResult:
        repository = self.github_repository
        if repository is None:
            raise AssertionError("generate request repository validation failed")
        source = self._source
        validate_source_before_inventory_load(source)
        client = GithubSbomClient(
            api_url=self.github_api_url,
            token=resolve_github_token(
                api_url=self.github_api_url,
                token_env=self.github_token_env,
                allow_gh_cli=self.use_gh_auth,
            ),
        )
        return generate_vex_from_github_source_result(
            repository=repository,
            source=source,
            timestamp=self.timestamp,
            github_client=client,
            renderer=self.renderer,
        )

    @property
    def _source(self) -> VulnerabilitySource:
        if self.source_options.findings_file is not None:
            return LocalFindingsSource(path=self.source_options.findings_file)
        return OsvSource(
            osv_base_url=self._osv_url,
            allow_public_osv=self.source_options.allow_public_osv,
            source_name=self.source_options.osv_source_name,
            source_url=self.source_options.osv_source_url,
        )

    @property
    def _osv_url(self) -> str:
        return (
            DEFAULT_OSV_API_URL
            if self.source_options.osv_url is None
            else self.source_options.osv_url
        )
