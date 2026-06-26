"""Command-line entrypoint for Vexcalibur."""

from pathlib import Path
from typing import Annotated

import typer
from packageurl import PackageURL
from rich.console import Console

from vexcalibur.generate import generate_vex_from_local_findings, generate_vex_from_sbom
from vexcalibur.sbom import SbomError
from vexcalibur.sources.local import LocalFindingsError
from vexcalibur.sources.osv import (
    DEFAULT_OSV_API_URL,
    OsvClientError,
    OsvConfigurationError,
    osv_client_for_url,
)
from vexcalibur.vex import parse_timestamp


class _GenerateSourceOptionError(Exception):
    """Raised when generate source options are mutually incompatible."""


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
        console.print(f"{result.purl}: {ids}")


@app.command("generate")
def generate(
    input_file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="CycloneDX JSON or XML SBOM to convert into VEX.",
        ),
    ],
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write VEX JSON to this file instead of stdout."),
    ] = None,
    timestamp: Annotated[
        str | None,
        typer.Option("--timestamp", help="ISO-8601 timestamp to use for deterministic output."),
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
    allow_public_osv: Annotated[
        bool,
        typer.Option(
            "--allow-public-osv",
            help="Allow sending SBOM package URLs and versions to the public OSV API.",
        ),
    ] = False,
) -> None:
    """Generate CycloneDX VEX JSON from a CycloneDX SBOM and vulnerability findings."""
    parsed_timestamp = None
    if timestamp is not None:
        try:
            parsed_timestamp = parse_timestamp(timestamp)
        except ValueError as exc:
            msg = f"{timestamp!r} is not a valid ISO-8601 timestamp"
            raise typer.BadParameter(msg) from exc

    try:
        _validate_generate_source_options(
            findings_file=findings_file,
            offline=offline,
            osv_url=osv_url,
            allow_public_osv=allow_public_osv,
        )
        if findings_file is None:
            vex_json = generate_vex_from_sbom(
                input_file=input_file,
                timestamp=parsed_timestamp,
                osv_base_url=DEFAULT_OSV_API_URL if osv_url is None else osv_url,
                allow_public_osv=allow_public_osv,
            )
        else:
            vex_json = generate_vex_from_local_findings(
                input_file=input_file,
                findings_file=findings_file,
                timestamp=parsed_timestamp,
            )
    except _GenerateSourceOptionError as exc:
        typer.echo(f"Invalid generate options: {exc}", err=True)
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

    if output_file is None:
        typer.echo(vex_json, nl=False)
        return

    try:
        output_file.write_text(vex_json, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Could not write VEX output {output_file}: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _parse_package_urls(values: list[str]) -> list[PackageURL]:
    parsed: list[PackageURL] = []
    for value in values:
        try:
            parsed.append(PackageURL.from_string(value))
        except ValueError as exc:
            msg = f"{value!r} is not a valid package URL: {exc}"
            raise typer.BadParameter(msg) from exc
    return parsed


def _validate_generate_source_options(
    *,
    findings_file: Path | None,
    offline: bool,
    osv_url: str | None,
    allow_public_osv: bool,
) -> None:
    if offline and findings_file is None:
        msg = "--offline requires --findings-file in this release"
        raise _GenerateSourceOptionError(msg)
    if osv_url is not None and not osv_url.strip():
        msg = "--osv-url must not be empty"
        raise _GenerateSourceOptionError(msg)
    if findings_file is None:
        return
    if allow_public_osv:
        msg = "--allow-public-osv cannot be combined with --findings-file"
        raise _GenerateSourceOptionError(msg)
    if osv_url is not None:
        msg = "--osv-url cannot be combined with --findings-file"
        raise _GenerateSourceOptionError(msg)


if __name__ == "__main__":
    app()
