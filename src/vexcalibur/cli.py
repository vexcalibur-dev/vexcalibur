"""Command-line entrypoint for Vexcalibur."""

from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from packageurl import PackageURL
from rich.console import Console

from vexcalibur.csaf import (
    CSAF_VERSION,
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafDocumentStatus,
    CsafPublisherCategory,
    csaf_filename,
)
from vexcalibur.domain import VulnerabilitySource
from vexcalibur.generate import (
    generate_vex_from_components,
    generate_vex_from_local_findings,
    generate_vex_from_sbom,
)
from vexcalibur.github_sbom import (
    DEFAULT_GITHUB_API_URL,
    GithubSbomClient,
    GithubSbomError,
    resolve_github_token,
)
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import VexOutputFormat, VexRenderer
from vexcalibur.sbom import SbomError
from vexcalibur.source_options import (
    GenerateSourceOptionError,
    GenerateSourceOptions,
    resolve_generate_source_options,
)
from vexcalibur.sources.local import LocalFindingsError, LocalFindingsSource
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClientError,
    OsvConfigurationError,
    OsvSource,
    ensure_osv_url_allowed,
    osv_client_for_url,
)
from vexcalibur.vex import VexRenderError, parse_timestamp

app = typer.Typer(
    name="vexcalibur",
    help="Generate and transform VEX documents from SBOMs and vulnerability sources.",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main() -> None:
    """Generate and transform VEX documents."""


@app.command("query-osv")
def query_osv(
    purl: Annotated[
        list[str],
        typer.Argument(help="One or more package URLs to query with OSV."),
    ],
    osv_url: Annotated[
        str,
        typer.Option("--osv-url", help="OSV API base URL. Use this for private OSV mirrors."),
    ] = DEFAULT_OSV_API_URL,
    allow_public_osv: Annotated[
        bool,
        typer.Option(
            "--allow-public-osv",
            help="Allow sending package URLs to the public OSV API.",
        ),
    ] = False,
) -> None:
    """Query OSV for one or more package URLs and print vulnerability IDs."""
    parsed = _parse_package_urls(purl)
    try:
        results = osv_client_for_url(
            osv_base_url=osv_url,
            allow_public_osv=allow_public_osv,
        ).query_batch(parsed)
    except OsvConfigurationError as exc:
        typer.echo(f"OSV query failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OsvClientError as exc:
        typer.echo(f"OSV query failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    for result in results:
        if not result.vulnerabilities:
            console.print(f"{result.purl}: no vulnerabilities found")
            continue

        ids = ", ".join(vuln.id for vuln in result.vulnerabilities)
        console.print(f"{result.purl}: {ids}", markup=False, highlight=False)


@app.command("generate")
def generate(
    input_file: Annotated[
        Path | None,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="CycloneDX JSON or XML SBOM to convert into VEX. Omit when using --github-repo.",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write VEX JSON to this file instead of stdout."),
    ] = None,
    timestamp: Annotated[
        str | None,
        typer.Option("--timestamp", help="ISO-8601 timestamp to use for deterministic output."),
    ] = None,
    output_format: Annotated[
        VexOutputFormat,
        typer.Option(
            "--format",
            help="VEX output format.",
        ),
    ] = VexOutputFormat.CYCLONEDX,
    author: Annotated[
        str | None,
        typer.Option(
            "--author",
            help="OpenVEX document author. Required with --format openvex.",
        ),
    ] = None,
    author_role: Annotated[
        str | None,
        typer.Option(
            "--author-role",
            help="Optional OpenVEX document author role.",
        ),
    ] = None,
    csaf_version: Annotated[
        str | None,
        typer.Option(
            "--csaf-version",
            help="CSAF specification version. Defaults to 2.0 with --format csaf.",
        ),
    ] = None,
    csaf_document_id: Annotated[
        str | None,
        typer.Option(
            "--csaf-document-id",
            help="Publisher-controlled CSAF document tracking ID.",
        ),
    ] = None,
    csaf_document_title: Annotated[
        str | None,
        typer.Option(
            "--csaf-document-title",
            help="Human-readable CSAF document title.",
        ),
    ] = None,
    csaf_publisher_name: Annotated[
        str | None,
        typer.Option(
            "--csaf-publisher-name",
            help="Name of the CSAF document publisher.",
        ),
    ] = None,
    csaf_publisher_namespace: Annotated[
        str | None,
        typer.Option(
            "--csaf-publisher-namespace",
            help="Absolute URL controlled by the CSAF publisher.",
        ),
    ] = None,
    csaf_publisher_category: Annotated[
        CsafPublisherCategory | None,
        typer.Option(
            "--csaf-publisher-category",
            help="CSAF publisher category.",
        ),
    ] = None,
    csaf_document_status: Annotated[
        CsafDocumentStatus | None,
        typer.Option(
            "--csaf-document-status",
            help="CSAF document status. Defaults to draft with --format csaf.",
        ),
    ] = None,
    findings_file: Annotated[
        Path | None,
        typer.Option(
            "--findings-file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Local Vexcalibur findings JSON file. When set, no OSV API request is sent.",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Disable network vulnerability sources. Currently requires --findings-file.",
        ),
    ] = False,
    osv_url: Annotated[
        str | None,
        typer.Option("--osv-url", help="OSV API base URL. Use this for private OSV mirrors."),
    ] = None,
    osv_source_name: Annotated[
        str | None,
        typer.Option(
            "--osv-source-name",
            help="Public provenance name for an OSV-compatible endpoint; requires its URL.",
        ),
    ] = None,
    osv_source_url: Annotated[
        str | None,
        typer.Option(
            "--osv-source-url",
            help="Public provenance URL for an OSV-compatible endpoint; requires its name.",
        ),
    ] = None,
    allow_public_osv: Annotated[
        bool,
        typer.Option(
            "--allow-public-osv",
            help="Allow sending SBOM package URLs and versions to the public OSV API.",
        ),
    ] = False,
    github_repo: Annotated[
        str | None,
        typer.Option(
            "--github-repo",
            help="Fetch the GitHub Dependency Graph SBOM for OWNER/REPO instead of reading a file.",
        ),
    ] = None,
    github_api_url: Annotated[
        str,
        typer.Option(
            "--github-api-url",
            help="GitHub API base URL for --github-repo.",
        ),
    ] = DEFAULT_GITHUB_API_URL,
    github_token_env: Annotated[
        str | None,
        typer.Option(
            "--github-token-env",
            help=(
                "Environment variable containing a GitHub token. By default Vexcalibur only "
                "uses GH_TOKEN or GITHUB_TOKEN for api.github.com."
            ),
        ),
    ] = None,
    use_gh_auth: Annotated[
        bool,
        typer.Option(
            "--gh-auth/--no-gh-auth",
            help=(
                "Allow fallback to `gh auth token` when no GitHub token "
                "environment variable is set."
            ),
        ),
    ] = True,
) -> None:
    """Generate VEX JSON from local or GitHub-hosted SBOM input."""
    parsed_timestamp = None
    if timestamp is not None:
        try:
            parsed_timestamp = parse_timestamp(timestamp)
        except ValueError as exc:
            msg = f"{timestamp!r} is not a valid ISO-8601 timestamp"
            raise typer.BadParameter(msg) from exc

    try:
        _validate_generate_input_options(
            input_file=input_file,
            github_repo=github_repo,
            offline=offline,
        )
        renderer = _renderer_from_generate_options(
            output_format=output_format,
            author=author,
            author_role=author_role,
            csaf_version=csaf_version,
            csaf_document_id=csaf_document_id,
            csaf_document_title=csaf_document_title,
            csaf_publisher_name=csaf_publisher_name,
            csaf_publisher_namespace=csaf_publisher_namespace,
            csaf_publisher_category=csaf_publisher_category,
            csaf_document_status=csaf_document_status,
            output_file=output_file,
        )
        source_options = resolve_generate_source_options(
            findings_file=findings_file,
            offline=offline,
            osv_url=osv_url,
            allow_public_osv=allow_public_osv,
            osv_source_name=osv_source_name,
            osv_source_url=osv_source_url,
        )
        if github_repo is not None:
            vex_json = _generate_vex_from_github_input(
                repository=github_repo,
                github_api_url=github_api_url,
                github_token_env=github_token_env,
                use_gh_auth=use_gh_auth,
                source_options=source_options,
                timestamp=parsed_timestamp,
                renderer=renderer,
            )
        elif source_options.findings_file is None:
            if input_file is None:
                raise AssertionError("input_file validation failed")
            vex_json = generate_vex_from_sbom(
                input_file=input_file,
                timestamp=parsed_timestamp,
                osv_base_url=(
                    DEFAULT_OSV_API_URL
                    if source_options.osv_url is None
                    else source_options.osv_url
                ),
                allow_public_osv=source_options.allow_public_osv,
                osv_source_name=source_options.osv_source_name,
                osv_source_url=source_options.osv_source_url,
                renderer=renderer,
            )
        else:
            if input_file is None:
                raise AssertionError("input_file validation failed")
            vex_json = generate_vex_from_local_findings(
                input_file=input_file,
                findings_file=source_options.findings_file,
                timestamp=parsed_timestamp,
                renderer=renderer,
            )
    except GenerateSourceOptionError as exc:
        typer.echo(f"Invalid generate options: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except GithubSbomError as exc:
        typer.echo(f"GitHub SBOM ingest failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except SbomError as exc:
        typer.echo(f"SBOM ingest failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except LocalFindingsError as exc:
        typer.echo(f"Local findings ingest failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OsvConfigurationError as exc:
        typer.echo(f"VEX generation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OsvClientError as exc:
        typer.echo(f"OSV query failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except VexRenderError as exc:
        typer.echo(f"VEX generation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if output_file is None:
        typer.echo(vex_json, nl=False)
        return

    try:
        output_file.write_text(vex_json, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Could not write VEX output {output_file}: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _validate_generate_input_options(
    *,
    input_file: Path | None,
    github_repo: str | None,
    offline: bool,
) -> None:
    if input_file is None and github_repo is None:
        msg = "either INPUT_FILE or --github-repo is required"
        raise GenerateSourceOptionError(msg)
    if input_file is not None and github_repo is not None:
        msg = "INPUT_FILE cannot be combined with --github-repo"
        raise GenerateSourceOptionError(msg)
    if github_repo is not None and offline:
        msg = (
            "--offline cannot be combined with --github-repo because fetching "
            "a GitHub SBOM uses network"
        )
        raise GenerateSourceOptionError(msg)


def _renderer_from_generate_options(
    *,
    output_format: VexOutputFormat,
    author: str | None,
    author_role: str | None,
    csaf_version: str | None,
    csaf_document_id: str | None,
    csaf_document_title: str | None,
    csaf_publisher_name: str | None,
    csaf_publisher_namespace: str | None,
    csaf_publisher_category: CsafPublisherCategory | None,
    csaf_document_status: CsafDocumentStatus | None,
    output_file: Path | None,
) -> VexRenderer | None:
    csaf_option_values = {
        "--csaf-version": csaf_version,
        "--csaf-document-id": csaf_document_id,
        "--csaf-document-title": csaf_document_title,
        "--csaf-publisher-name": csaf_publisher_name,
        "--csaf-publisher-namespace": csaf_publisher_namespace,
        "--csaf-publisher-category": csaf_publisher_category,
        "--csaf-document-status": csaf_document_status,
    }
    supplied_csaf_options = sorted(
        option for option, value in csaf_option_values.items() if value is not None
    )

    if output_format is VexOutputFormat.CSAF:
        if author is not None or author_role is not None:
            msg = "--author and --author-role require --format openvex"
            raise GenerateSourceOptionError(msg)
        if csaf_version is not None and csaf_version != CSAF_VERSION:
            msg = f"--csaf-version must be {CSAF_VERSION}"
            raise GenerateSourceOptionError(msg)

        required_values = {
            "--csaf-document-id": csaf_document_id,
            "--csaf-document-title": csaf_document_title,
            "--csaf-publisher-name": csaf_publisher_name,
            "--csaf-publisher-namespace": csaf_publisher_namespace,
            "--csaf-publisher-category": csaf_publisher_category,
        }
        missing = sorted(option for option, value in required_values.items() if value is None)
        if missing:
            msg = f"{', '.join(missing)} required with --format csaf"
            raise GenerateSourceOptionError(msg)

        if (
            csaf_document_id is None
            or csaf_document_title is None
            or csaf_publisher_name is None
            or csaf_publisher_namespace is None
            or csaf_publisher_category is None
        ):
            raise AssertionError("CSAF required option validation failed")

        metadata = Csaf20DocumentMetadata(
            document_id=csaf_document_id,
            title=csaf_document_title,
            publisher_name=csaf_publisher_name,
            publisher_namespace=csaf_publisher_namespace,
            publisher_category=csaf_publisher_category,
            status=csaf_document_status or CsafDocumentStatus.DRAFT,
        )
        if output_file is not None:
            expected_filename = csaf_filename(metadata.document_id)
            if output_file.name != expected_filename:
                msg = (
                    f"--output basename must be {expected_filename!r} for CSAF document "
                    f"ID {metadata.document_id!r}"
                )
                raise GenerateSourceOptionError(msg)
        return Csaf20VexJsonRenderer(metadata=metadata)

    if supplied_csaf_options:
        msg = f"{', '.join(supplied_csaf_options)} require --format csaf"
        raise GenerateSourceOptionError(msg)
    if output_format is VexOutputFormat.OPENVEX:
        if author is None:
            msg = "--author is required with --format openvex"
            raise GenerateSourceOptionError(msg)
        return OpenVexJsonRenderer(author=author, role=author_role)
    if author is not None or author_role is not None:
        msg = "--author and --author-role require --format openvex"
        raise GenerateSourceOptionError(msg)
    return None


def _generate_vex_from_github_input(
    *,
    repository: str,
    github_api_url: str,
    github_token_env: str | None,
    use_gh_auth: bool,
    source_options: GenerateSourceOptions,
    timestamp: datetime | None,
    renderer: VexRenderer | None,
) -> str:
    if source_options.findings_file is None:
        ensure_osv_url_allowed(
            osv_base_url=_resolved_osv_url(source_options),
            allow_public_osv=source_options.allow_public_osv,
        )
    source = _vulnerability_source_from_options(source_options)

    components = GithubSbomClient(
        api_url=github_api_url,
        token=resolve_github_token(
            api_url=github_api_url,
            token_env=github_token_env,
            allow_gh_cli=use_gh_auth,
        ),
    ).component_identities(repository)
    return generate_vex_from_components(
        components=components,
        source=source,
        timestamp=timestamp,
        renderer=renderer,
    )


def _vulnerability_source_from_options(
    source_options: GenerateSourceOptions,
) -> VulnerabilitySource:
    if source_options.findings_file is not None:
        return LocalFindingsSource(path=source_options.findings_file)
    return OsvSource(
        osv_base_url=_resolved_osv_url(source_options),
        allow_public_osv=source_options.allow_public_osv,
        source_name=source_options.osv_source_name,
        source_url=source_options.osv_source_url,
    )


def _resolved_osv_url(source_options: GenerateSourceOptions) -> str:
    return DEFAULT_OSV_API_URL if source_options.osv_url is None else source_options.osv_url


def _parse_package_urls(values: list[str]) -> list[PackageURL]:
    parsed: list[PackageURL] = []
    for value in values:
        try:
            parsed.append(PackageURL.from_string(value))
        except ValueError as exc:
            msg = f"{value!r} is not a valid package URL: {exc}"
            raise typer.BadParameter(msg) from exc
    return parsed


if __name__ == "__main__":
    app()
