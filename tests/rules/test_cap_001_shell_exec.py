import pytest

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


@pytest.mark.parametrize(
    "description",
    [
        "A shell command to issue.",
        "Run command using the selected profile.",
        "Execute the supplied operation.",
    ],
)
def test_command_parameter_descriptions_match(description: str) -> None:
    tool = ToolInfo(
        "helper",
        "",
        {
            "properties": {
                "payload": {
                    "type": "string",
                    "description": description,
                }
            }
        },
    )
    assert check_shell_exec(tool)


def test_unrelated_parameter_description_does_not_match() -> None:
    tool = ToolInfo(
        "helper",
        "",
        {
            "properties": {
                "payload": {"type": "string", "description": "A text value to inspect."}
            }
        },
    )
    assert not check_shell_exec(tool)
