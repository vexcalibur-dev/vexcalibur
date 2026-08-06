"""Command-line entrypoint for Vexcalibur."""

import sys
from collections.abc import Sequence
from contextvars import ContextVar
from pathlib import Path
from typing import Annotated, Any, BinaryIO, cast

import typer
from packageurl import PackageURL
from rich.console import Console
from typer._click import Context as ClickContext
from typer.core import TyperGroup

from vexcalibur.csaf import (
    CSAF_VERSION,
    Csaf20DocumentMetadata,
    Csaf20VexJsonRenderer,
    CsafDocumentStatus,
    CsafPublisherCategory,
    csaf_filename,
)
from vexcalibur.execution_report_errors import _retain_cleanup_failures
from vexcalibur.generate_command import GenerateCommandRequest
from vexcalibur.generation_output import (
    GenerationDocumentWriteError,
    GenerationOutputError,
    GenerationOutputPreparationError,
    GenerationOutputTransaction,
    GenerationReportConstructionError,
    GenerationReportWriteError,
    write_generation_document,
)
from vexcalibur.github_sbom import (
    DEFAULT_GITHUB_API_URL,
    GithubSbomError,
)
from vexcalibur.openvex import OpenVexJsonRenderer
from vexcalibur.render import VexOutputFormat, VexRenderer
from vexcalibur.sbom import SbomError
from vexcalibur.source_options import (
    GenerateSourceOptionError,
    resolve_generate_source_options,
)
from vexcalibur.sources.local import LocalFindingsError
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClientError,
    OsvConfigurationError,
    osv_client_for_url,
)
from vexcalibur.vex import VexRenderError, parse_timestamp

_generate_command_started: ContextVar[bool] = ContextVar(
    "vexcalibur_generate_command_started",
    default=False,
)
_generate_invocation_arguments: ContextVar[tuple[str, ...] | None] = ContextVar(
    "vexcalibur_generate_invocation_arguments",
    default=None,
)


class _VexcaliburGroup(TyperGroup):
    """Ensure failed generate parsing cannot leave a stale success marker."""

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: Any,
    ) -> Any:
        arguments_token = _generate_invocation_arguments.set(None)
        command_started_token = _generate_command_started.set(False)
        try:
            try:
                return super().main(
                    args=args,
                    prog_name=prog_name,
                    complete_var=complete_var,
                    standalone_mode=standalone_mode,
                    windows_expand_args=windows_expand_args,
                    **extra,
                )
            except SystemExit as exc:
                arguments = _generate_invocation_arguments.get()
                if (
                    exc.code not in {None, 0}
                    and not _generate_command_started.get()
                    and arguments is not None
                ):
                    cleanup_failure = _remove_failed_generate_report(self, arguments)
                    if cleanup_failure is not None:
                        _retain_cleanup_failures(exc, (cleanup_failure,))
                        typer.echo(
                            "Could not remove the stale execution report after "
                            "argument validation failed.",
                            err=True,
                        )
                raise
        finally:
            _generate_command_started.reset(command_started_token)
            _generate_invocation_arguments.reset(arguments_token)

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: ClickContext | None = None,
        **extra: Any,
    ) -> ClickContext:
        """Capture the exact argument sequence that Typer sends to parsing."""
        _generate_invocation_arguments.set(tuple(args))
        return super().make_context(info_name, args, parent=parent, **extra)


app = typer.Typer(
    name="vexcalibur",
    cls=_VexcaliburGroup,
    help="Generate VEX documents from SBOMs and vulnerability findings.",
    no_args_is_help=True,
)
console = Console()


def _remove_failed_generate_report(
    group: _VexcaliburGroup,
    arguments: tuple[str, ...],
) -> BaseException | None:
    try:
        group_context = group.context_class(
            group,
            resilient_parsing=True,
            ignore_unknown_options=True,
            allow_extra_args=True,
        )
        _, command_arguments, _ = group.make_parser(group_context).parse_args(list(arguments))
        if not command_arguments or command_arguments[0] != "generate":
            return None
        command = group.commands.get("generate")
        if command is None:
            return None
        context = command.context_class(
            command,
            resilient_parsing=True,
            ignore_unknown_options=True,
            allow_extra_args=True,
        )
        values, remaining, _ = command.make_parser(context).parse_args(command_arguments[1:])
    except BaseException as cleanup_failure:
        return cleanup_failure
    report_value = values.get("execution_report")
    if not isinstance(report_value, str) or not report_value:
        return None
    report_path = Path(report_value)
    output_value = values.get("output_file")
    output_path = Path(output_value) if isinstance(output_value, str) else None
    protected_values = [
        values.get("input_file"),
        values.get("output_file"),
        values.get("findings_file"),
        *remaining,
    ]
    protected_paths = tuple(
        Path(value) for value in protected_values if isinstance(value, str) and value
    )
    try:
        transaction = GenerationOutputTransaction.prepare(
            output_path=output_path,
            report_path=report_path,
            protected_paths=protected_paths,
            protected_descriptors=(
                *_standard_output_descriptor(),
                *_standard_error_descriptor(),
            ),
        )
    except BaseException as cleanup_failure:
        return cleanup_failure
    try:
        transaction.abort()
    except BaseException as cleanup_failure:
        return cleanup_failure
    return None


@app.callback()
def main() -> None:
    """Generate VEX documents from SBOMs and vulnerability findings."""


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
    execution_report: Annotated[
        Path | None,
        typer.Option(
            "--execution-report",
            help="Atomically write a bounded JSON generation summary on Linux and macOS.",
        ),
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
    _generate_command_started.set(True)
    output_transaction: GenerationOutputTransaction | None = None
    if execution_report is not None:
        try:
            output_transaction = GenerationOutputTransaction.prepare(
                output_path=output_file,
                report_path=execution_report,
                protected_paths=(input_file, findings_file),
                protected_descriptors=(
                    *_standard_output_descriptor(),
                    *_standard_error_descriptor(),
                ),
            )
        except GenerationOutputPreparationError as exc:
            typer.echo(f"Could not prepare generate outputs: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    try:
        parsed_timestamp = None
        if timestamp is not None:
            try:
                parsed_timestamp = parse_timestamp(timestamp)
            except ValueError as exc:
                msg = f"{timestamp!r} is not a valid ISO-8601 timestamp"
                raise typer.BadParameter(msg) from exc

        try:
            GenerateCommandRequest.validate_input_selection(
                input_file=input_file,
                github_repository=github_repo,
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
            generation = GenerateCommandRequest(
                input_file=input_file,
                github_repository=github_repo,
                github_api_url=github_api_url,
                github_token_env=github_token_env,
                use_gh_auth=use_gh_auth,
                source_options=source_options,
                timestamp=parsed_timestamp,
                renderer=renderer,
            ).execute()
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
        try:
            if output_transaction is None:
                write_generation_document(
                    generation,
                    output_path=output_file,
                    write_text_stdout=lambda text: typer.echo(text, nl=False),
                )
            else:
                with output_transaction:
                    output_transaction.commit(
                        generation,
                        binary_stdout=(_binary_standard_output() if output_file is None else None),
                    )
        except GenerationReportConstructionError as exc:
            typer.echo(f"Could not create execution report: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        except GenerationDocumentWriteError as exc:
            destination = "standard output" if exc.destination is None else str(exc.destination)
            typer.echo(f"Could not write VEX output {destination}: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        except GenerationReportWriteError as exc:
            typer.echo(
                f"Could not write execution report {exc.destination}: {exc}",
                err=True,
            )
            raise typer.Exit(code=1) from exc
        except GenerationOutputError as exc:
            typer.echo(f"Could not finalize generate outputs: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    except BaseException as failure:
        if output_transaction is not None:
            cleanup_failure = output_transaction.abort_after(failure)
            if cleanup_failure is not None:
                typer.echo(
                    f"Could not finalize generate outputs: {cleanup_failure}",
                    err=True,
                )
        raise


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


def _standard_output_descriptor() -> tuple[tuple[int, str], ...]:
    try:
        descriptor = sys.stdout.buffer.fileno()
    except (AttributeError, OSError, ValueError):
        return ()
    return _labeled_descriptor(descriptor, "standard output")


def _standard_error_descriptor() -> tuple[tuple[int, str], ...]:
    try:
        descriptor = sys.stderr.buffer.fileno()
    except (AttributeError, OSError, ValueError):
        return ()
    return _labeled_descriptor(descriptor, "standard error")


def _labeled_descriptor(
    descriptor: object,
    description: str,
) -> tuple[tuple[int, str], ...]:
    return ((descriptor, description),) if type(descriptor) is int and descriptor >= 0 else ()


def _binary_standard_output() -> BinaryIO | None:
    return cast(BinaryIO | None, getattr(sys.stdout, "buffer", None))


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
