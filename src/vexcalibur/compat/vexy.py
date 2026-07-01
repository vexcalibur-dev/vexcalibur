"""Legacy vexy-compatible command surface."""

from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from vexcalibur.generate import generate_vex_from_local_findings, generate_vex_from_sbom
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
)
from vexcalibur.vex import parse_timestamp

DEFAULT_OUTPUT_FILE = Path("cyclonedx-vex.json")
SUPPORTED_FORMAT = "json"
SUPPORTED_SCHEMA_VERSION = "1.6"


class _VexyCompatError(Exception):
    """Raised when a legacy vexy option cannot map to Vexcalibur behavior."""


app = typer.Typer(
    name="vexy",
    help="Compatibility command for legacy vexy workflows.",
    no_args_is_help=True,
)


@app.command(
    help="Compatibility command for legacy vexy workflows.",
    no_args_is_help=True,
)
def main(
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help=(
                "Legacy vexy configuration file. Accepted for argument compatibility; "
                "use --findings-file, --osv-url, or --allow-public-osv to select the "
                "Vexcalibur source mode."
            ),
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("-q", help="Accepted for legacy vexy compatibility."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("-X", help="Print compatibility debug output to standard error."),
    ] = False,
    input_file: Annotated[
        str,
        typer.Option(
            "--in-file",
            "-i",
            help="CycloneDX JSON or XML SBOM file to read. Stdin input is not supported.",
        ),
    ] = "",
    output_format: Annotated[
        str,
        typer.Option("--format", help="VEX output format. Compatibility supports json only."),
    ] = SUPPORTED_FORMAT,
    schema_version: Annotated[
        str,
        typer.Option(
            "--schema-version",
            help="CycloneDX VEX schema version. Compatibility supports 1.6 only.",
        ),
    ] = SUPPORTED_SCHEMA_VERSION,
    output_file: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            "--o",
            help="Output file path. Use '-' to write VEX JSON to standard output.",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite an existing output file."),
    ] = False,
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
    """Run the vexy-compatible interface."""
    del quiet

    try:
        _debug(debug, f"legacy config accepted without parsing: {config_file}")
        _validate_output_contract(
            output_format=output_format,
            schema_version=schema_version,
        )
        source_options = resolve_generate_source_options(
            findings_file=findings_file,
            offline=offline,
            osv_url=osv_url,
            allow_public_osv=allow_public_osv,
        )
        sbom_path = _resolve_input_file(input_file)
        resolved_output = _resolve_output(output_file=output_file, force=force)
        parsed_timestamp = _parse_timestamp(timestamp)

        if source_options.findings_file is None:
            vex_json = generate_vex_from_sbom(
                input_file=sbom_path,
                timestamp=parsed_timestamp,
                osv_base_url=(
                    DEFAULT_OSV_API_URL
                    if source_options.osv_url is None
                    else source_options.osv_url
                ),
                allow_public_osv=source_options.allow_public_osv,
            )
        else:
            vex_json = generate_vex_from_local_findings(
                input_file=sbom_path,
                findings_file=source_options.findings_file,
                timestamp=parsed_timestamp,
            )

        _write_output(vex_json, output=resolved_output, force=force)
    except GenerateSourceOptionError as exc:
        typer.echo(f"vexy compatibility failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except _VexyCompatError as exc:
        typer.echo(f"vexy compatibility failed: {exc}", err=True)
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


def _validate_output_contract(*, output_format: str, schema_version: str) -> None:
    normalized_format = output_format.strip().lower()
    if normalized_format != SUPPORTED_FORMAT:
        msg = (
            f"only --format {SUPPORTED_FORMAT} is supported; legacy --format "
            f"{output_format} is not available"
        )
        raise _VexyCompatError(msg)

    normalized_schema = schema_version.strip()
    if normalized_schema != SUPPORTED_SCHEMA_VERSION:
        msg = (
            f"only --schema-version {SUPPORTED_SCHEMA_VERSION} is supported; legacy "
            f"--schema-version {schema_version} is not available"
        )
        raise _VexyCompatError(msg)


def _resolve_input_file(input_file: str) -> Path:
    if not input_file:
        msg = "missing required legacy input option -i/--in-file"
        raise _VexyCompatError(msg)
    if input_file == "-":
        msg = "reading CycloneDX SBOM input from stdin is not supported; pass a file path"
        raise _VexyCompatError(msg)

    path = Path(input_file)
    if not path.is_file():
        msg = f"input SBOM file does not exist or is not a file: {path}"
        raise _VexyCompatError(msg)
    return path


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    if timestamp is None:
        return None
    try:
        return parse_timestamp(timestamp)
    except ValueError as exc:
        msg = f"{timestamp!r} is not a valid ISO-8601 timestamp"
        raise _VexyCompatError(msg) from exc


def _resolve_output(*, output_file: str | None, force: bool) -> Path | None:
    if output_file == "-":
        return None

    output_path = DEFAULT_OUTPUT_FILE if output_file is None else Path(output_file)
    if output_path.exists() and not force:
        msg = f"output file already exists; pass --force to overwrite: {output_path}"
        raise _VexyCompatError(msg)
    return output_path


def _write_output(vex_json: str, *, output: Path | None, force: bool) -> None:
    if output is None:
        typer.echo(vex_json, nl=False)
        return

    try:
        if force:
            output.write_text(vex_json, encoding="utf-8")
            return
        with output.open("x", encoding="utf-8") as output_stream:
            output_stream.write(vex_json)
    except FileExistsError as exc:
        msg = f"output file already exists; pass --force to overwrite: {output}"
        raise _VexyCompatError(msg) from exc
    except OSError as exc:
        msg = f"could not write VEX output {output}: {exc}"
        raise _VexyCompatError(msg) from exc


def _debug(enabled: bool, message: str) -> None:
    if enabled:
        typer.echo(f"[DEBUG] vexy compatibility: {message}", err=True)
