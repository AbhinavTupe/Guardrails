"""Command-line interface for mcp-audit."""

import typer

from mcp_audit.models import ScanResult

app = typer.Typer()


@app.callback()
def main() -> None:
    """Audit MCP servers for security risks."""


@app.command()
def scan(
    command: str,
    json_output: bool = typer.Option(False, "--json"),
    probe: bool = typer.Option(False, "--probe"),
) -> None:
    """Scan an MCP server launched by COMMAND."""
    del probe
    result = ScanResult(server_command=command)

    if json_output:
        typer.echo(result.to_json())
    else:
        typer.echo(f"Server command: {result.server_command}")
        typer.echo(f"Tools found: {len(result.tools)}")
        typer.echo(f"Findings: {len(result.findings)}")
        typer.echo(f"Score: {result.score}")


if __name__ == "__main__":
    app()
