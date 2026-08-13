"""Command-line entry point.

The first CLI intentionally exposes only a health check. Scan commands will
be added after the Trivy adapter and risk scorer are implemented.
"""

import typer

from . import __version__

app = typer.Typer(
    name="vulnproof",
    help="Evidence-driven vulnerability validation platform.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed VulnProof version."""

    typer.echo(__version__)
