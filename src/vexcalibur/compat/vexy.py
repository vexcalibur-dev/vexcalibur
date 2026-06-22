"""Legacy vexy-compatible command surface."""

import typer

app = typer.Typer(
    name="vexy",
    help="Compatibility command for legacy vexy workflows.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Run the vexy-compatible interface."""
