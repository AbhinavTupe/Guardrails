import json

from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()


def test_help_works() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0


def test_scan_echo_exits_zero() -> None:
    result = runner.invoke(app, ["scan", "echo hi"])

    assert result.exit_code == 0


def test_scan_json_output_is_valid_json() -> None:
    result = runner.invoke(app, ["scan", "--json", "echo hi"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["server_command"] == "echo hi"
    assert parsed["tools"] == []
    assert parsed["findings"] == []
