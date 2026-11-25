import json
import shlex
import sys
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()
FIXTURE = Path(__file__).parent / "fixtures" / "echo_server.py"
SERVER_COMMAND = shlex.join([sys.executable, str(FIXTURE)])


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
