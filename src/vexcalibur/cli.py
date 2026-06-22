"""Command-line entrypoint for Vexcalibur."""

from typing import Annotated

import typer
from packageurl import PackageURL
from rich.console import Console

from vexcalibur.sources.osv import OsvClient

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
    parsed = [PackageURL.from_string(value) for value in purl]
    results = OsvClient().query_batch(parsed)

    for result in results:
        if not result.vulnerabilities:
            console.print(f"{result.purl}: no vulnerabilities found")
            continue

        ids = ", ".join(vuln.id for vuln in result.vulnerabilities)
        console.print(f"{result.purl}: {ids}")


if __name__ == "__main__":
    app()
