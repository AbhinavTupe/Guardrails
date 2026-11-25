from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.cap_001_shell_exec import check_shell_exec


def test_shell_name_matches() -> None:
    findings = check_shell_exec(ToolInfo("run_command", "", {}))
    assert findings and findings[0].severity == Severity.HIGH
    assert "run_command" in findings[0].evidence


def test_string_command_parameter_matches_with_schema_evidence() -> None:
    tool = ToolInfo("execute", "", {"properties": {"command": {"type": "string"}}})
    findings = check_shell_exec(tool)
    assert len(findings) == 1
    assert "command" in findings[0].evidence
    assert '"type": "string"' in findings[0].evidence


def test_description_does_not_trigger() -> None:
    assert not check_shell_exec(ToolInfo("safe", "Run a command", {}))


def test_non_string_command_parameter_does_not_trigger_by_parameter() -> None:
    assert not check_shell_exec(
        ToolInfo("safe", "", {"properties": {"command": {"type": "integer"}}})
    )
