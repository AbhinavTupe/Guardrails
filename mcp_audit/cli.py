"""Command-line interface for mcp-audit."""

import asyncio

import typer

from mcp_audit.connector import ConnectorError, enumerate_server
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
    try:
        server = asyncio.run(enumerate_server(command))
    except ConnectorError as exc:
        message = str(exc).replace("\r", " ").replace("\n", " ")
        typer.echo(f"Error: {message}", err=True)
        raise typer.Exit(code=2) from exc

    result = ScanResult(server_command=command, tools=server.tools)

    if json_output:
        typer.echo(result.to_json())
    else:
        typer.echo(f"Server command: {result.server_command}")
        typer.echo(f"Tools found: {len(result.tools)}")
        typer.echo(f"Findings: {len(result.findings)}")
        typer.echo(f"Score: {result.score}")


if __name__ == "__main__":
    app()
