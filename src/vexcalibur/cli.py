"""Command-line entrypoint for Vexcalibur."""

from pathlib import Path
from typing import Annotated

import typer
from packageurl import PackageURL
from rich.console import Console

from vexcalibur.sbom import SbomError, load_cyclonedx_json
from vexcalibur.sources.osv import OsvClient, OsvClientError
from vexcalibur.vex import (
    VexAnalysisState,
    findings_from_osv_results,
    parse_timestamp,
    render_cyclonedx_vex_json,
)

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
) -> None:
    """Query OSV for one or more package URLs and print vulnerability IDs."""
    parsed = _parse_package_urls(purl)
    try:
        results = OsvClient().query_batch(parsed)
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
            help="CycloneDX JSON SBOM to convert into VEX.",
        ),
    ],
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write VEX JSON to this file instead of stdout."),
    ] = None,
    analysis_state: Annotated[
        VexAnalysisState,
        typer.Option("--analysis-state", help="CycloneDX VEX analysis state for OSV findings."),
    ] = VexAnalysisState.IN_TRIAGE,
    timestamp: Annotated[
        str | None,
        typer.Option("--timestamp", help="ISO-8601 timestamp to use for deterministic output."),
    ] = None,
) -> None:
    """Generate CycloneDX VEX JSON from a CycloneDX SBOM and OSV findings."""
    try:
        components = load_cyclonedx_json(input_file)
    except SbomError as exc:
        typer.echo(f"SBOM ingest failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not components:
        typer.echo("SBOM ingest failed: no components with package URLs were found", err=True)
        raise typer.Exit(code=1)

    parsed_timestamp = None
    if timestamp is not None:
        try:
            parsed_timestamp = parse_timestamp(timestamp)
        except ValueError as exc:
            msg = f"{timestamp!r} is not a valid ISO-8601 timestamp"
            raise typer.BadParameter(msg) from exc

    purls_by_value = {component.purl.to_string(): component.purl for component in components}
    try:
        results = OsvClient().query_batch([purls_by_value[purl] for purl in sorted(purls_by_value)])
    except OsvClientError as exc:
        typer.echo(f"OSV query failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    vex_json = render_cyclonedx_vex_json(
        findings=findings_from_osv_results(components=components, results=results),
        analysis_state=analysis_state,
        timestamp=parsed_timestamp,
    )

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


if __name__ == "__main__":
    app()
