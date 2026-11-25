import json
import shlex
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mcp_audit.cli as cli
from mcp_audit.cli import app
from mcp_audit.models import Finding, ToolInfo

runner = CliRunner()
FIXTURE = Path(__file__).parent / "fixtures" / "echo_server.py"
SERVER_COMMAND = shlex.join([sys.executable, str(FIXTURE)])
TESTBED = Path(__file__).parents[1] / "testbed"


def test_help_works() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0


def test_scan_echo_exits_zero() -> None:
    result = runner.invoke(app, ["scan", SERVER_COMMAND])

    assert result.exit_code == 0


def test_scan_json_output_is_valid_json() -> None:
    result = runner.invoke(app, ["scan", "--json", SERVER_COMMAND])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["server_command"] == SERVER_COMMAND
    assert {tool["name"] for tool in parsed["tools"]} == {"echo", "add"}
    assert parsed["findings"] == []


def test_scan_connector_error_exits_two_with_one_line() -> None:
    result = runner.invoke(app, ["scan", "mcp-audit-command-that-does-not-exist"])

    assert result.exit_code == 2
    assert len(result.output.strip().splitlines()) == 1


def test_poisoned_testbed_exits_one() -> None:
    server_command = shlex.join([
        sys.executable,
        str(Path(__file__).parents[1] / "testbed" / "vuln_poisoned.py"),
    ])
    result = runner.invoke(app, ["scan", server_command])

    assert result.exit_code == 1


def test_clean_testbed_exits_zero() -> None:
    server_command = shlex.join([
        sys.executable,
        str(Path(__file__).parents[1] / "testbed" / "clean_calc.py"),
    ])
    result = runner.invoke(app, ["scan", server_command])

    assert result.exit_code == 0


def test_scan_probe_runs_and_warns() -> None:
    server_command = shlex.join([sys.executable, str(TESTBED / "vuln_shell.py")])
    result = runner.invoke(app, ["scan", "--probe", server_command])

    assert result.exit_code == 1
    assert cli.PROBE_WARNING in result.output
    assert "PRB-002" in result.output
    assert result.output.index(cli.PROBE_WARNING) < result.output.index("PRB-002")


def test_scan_without_probe_does_not_run_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def unexpected_probe(
        _command: str, _tools: list[ToolInfo]
    ) -> list[Finding]:
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(cli, "run_probes", unexpected_probe)
    server_command = shlex.join([sys.executable, str(TESTBED / "vuln_shell.py")])
    result = runner.invoke(app, ["scan", server_command])

    assert result.exit_code == 1
    assert not called
