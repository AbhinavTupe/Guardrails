"""Command-line interface for mcp-audit."""

import asyncio
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

import typer

from mcp_audit.connector import ConnectorError, enumerate_server
from mcp_audit.kb.retriever import KeywordRetriever
from mcp_audit.models import Finding, ScanResult
from mcp_audit.probes import run_probes
from mcp_audit.report.html import render_html
from mcp_audit.rules import load_all_rules, run_rules
from mcp_audit.rules.registry import get_rule_title
from mcp_audit.scoring import score_findings

app = typer.Typer()
PROBE_WARNING = (
    "Probes make harmless test calls to the target. Use only on servers you trust to run locally."
)
HTML_OPTION = typer.Option(None, "--html")


@app.callback()
def main() -> None:
    """Audit MCP servers for security risks."""


def run_scan(
    command: str,
    probe: bool = False,
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    enumeration_timeout: float = 30.0,
) -> ScanResult:
    """Enumerate a server and apply the CLI's standard rule and probe path."""
    server = (
        asyncio.run(enumerate_server(command, timeout=enumeration_timeout, env=env, cwd=cwd))
        if env is not None or cwd is not None
        else asyncio.run(enumerate_server(command, timeout=enumeration_timeout))
    )
    load_all_rules()
    findings = run_rules(server.tools)
    if probe:
        probe_result = (
            run_probes(command, server.tools, env=env, cwd=cwd)
            if env is not None or cwd is not None
            else run_probes(command, server.tools)
        )
        findings.extend(asyncio.run(probe_result))
    return ScanResult(
        server_command=command,
        tools=server.tools,
        findings=findings,
        score=score_findings(findings),
    )


@app.command()
def scan(
    command: str,
    json_output: bool = typer.Option(False, "--json"),
    probe: bool = typer.Option(False, "--probe"),
    html: Path | None = HTML_OPTION,
    fail_on: str = typer.Option("high", "--fail-on"),
) -> None:
    """Scan an MCP server launched by COMMAND."""
    try:
        if probe:
            typer.echo(PROBE_WARNING, err=True)
        result = run_scan(command, probe=probe)
    except ConnectorError as exc:
        message = str(exc).replace("\r", " ").replace("\n", " ")
        typer.echo(f"Error: {message}", err=True)
        raise typer.Exit(code=2) from exc

    findings = result.findings

    if html is not None:
        html.write_text(render_html(result), encoding="utf-8")
        typer.echo(f"Report written to {html}")
    elif json_output:
        typer.echo(result.to_json())
    else:
        typer.echo(f"Server command: {result.server_command}")
        typer.echo(f"Score: {result.score}")
        counts = result.severity_counts
        typer.echo(
            f"Findings: {len(result.findings)} "
            f"({counts['CRITICAL']} critical, {counts['HIGH']} high, "
            f"{counts['MEDIUM']} medium, {counts['LOW']} low)"
        )
        typer.echo(f"Verdict: {result.verdict}")
        typer.echo(f"Tools found: {len(result.tools)}")

        if not result.findings:
            typer.echo("No findings.")
        else:
            grouped: dict[str, list[Finding]] = defaultdict(list)
            for finding in result.findings:
                grouped[finding.tool_name].append(finding)

            retriever = KeywordRetriever()
            for tool_name, tool_findings in grouped.items():
                typer.echo(f"\nTool: {tool_name}")
                for finding in tool_findings:
                    explanation = retriever.explain(finding)
                    why_it_matters = (
                        f"\n  Why it matters: {explanation.why_it_matters}"
                        if explanation is not None
                        else ""
                    )
                    typer.echo(
                        f"[{finding.severity.value}] {finding.rule_id} "
                        f"{get_rule_title(finding.rule_id)}\n"
                        f"  Evidence: {finding.evidence}\n"
                        f"  Fix: {finding.fix}"
                        f"{why_it_matters}"
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
