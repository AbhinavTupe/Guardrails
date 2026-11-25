"""Command-line interface for mcp-audit."""

import asyncio
from collections import defaultdict

import typer

from mcp_audit.connector import ConnectorError, enumerate_server
from mcp_audit.models import Finding, ScanResult
from mcp_audit.rules import load_all_rules, run_rules
from mcp_audit.scoring import score_findings

app = typer.Typer()


@app.callback()
def main() -> None:
    """Audit MCP servers for security risks."""


@app.command()
def scan(
    command: str,
    json_output: bool = typer.Option(False, "--json"),
    probe: bool = typer.Option(False, "--probe"),
    fail_on: str = typer.Option("high", "--fail-on"),
) -> None:
    """Scan an MCP server launched by COMMAND."""
    del probe
    try:
        server = asyncio.run(enumerate_server(command))
    except ConnectorError as exc:
        message = str(exc).replace("\r", " ").replace("\n", " ")
        typer.echo(f"Error: {message}", err=True)
        raise typer.Exit(code=2) from exc

    load_all_rules()
    findings = run_rules(server.tools)
    result = ScanResult(
        server_command=command,
        tools=server.tools,
        findings=findings,
        score=score_findings(findings),
    )

    if json_output:
        typer.echo(result.to_json())
    else:
        typer.echo(f"Server command: {result.server_command}")
        typer.echo(f"Score: {result.score}")
        typer.echo(f"Verdict: {result.verdict}")
        typer.echo(f"Tools found: {len(result.tools)}")

        if not result.findings:
            typer.echo("No findings.")
        else:
            grouped: dict[str, list[Finding]] = defaultdict(list)
            for finding in result.findings:
                grouped[finding.tool_name].append(finding)

            for tool_name, tool_findings in grouped.items():
                typer.echo(f"\nTool: {tool_name}")
                for finding in tool_findings:
                    typer.echo(
                        f"[{finding.severity.value}] {finding.rule_id}\n"
                        f"  Evidence: {finding.evidence}\n"
                        f"  Fix: {finding.fix}"
                    )

    threshold = fail_on.upper()
    ranks = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5,
    }
    if threshold not in ranks:
        raise typer.BadParameter(
            "must be one of info, low, medium, high, critical",
            param_hint="--fail-on",
        )
    if any(ranks[finding.severity.name] >= ranks[threshold] for finding in findings):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
