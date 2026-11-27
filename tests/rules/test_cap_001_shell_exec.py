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
        "Execute the supplied task through the local command interpreter.",
        "Use bash to run the supplied operation.",
        "Run through PowerShell.",
        "Launch with subprocess.",
        "Uses os.system for execution.",
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


@pytest.mark.parametrize(
    "parameter",
    ["code", "expression"],
)
def test_eval_name_requires_corroborating_parameter(parameter: str) -> None:
    tool = ToolInfo(
        "anyforge_run_triage_eval",
        "Run triage evaluation.",
        {"properties": {parameter: {"type": "string"}}},
    )
    assert check_shell_exec(tool)


def test_eval_name_without_corroboration_does_not_match() -> None:
    tool = ToolInfo("anyforge_run_triage_eval", "Run triage evaluation.", {})
    assert not check_shell_exec(tool)


def test_eval_name_with_running_code_description_matches() -> None:
    tool = ToolInfo("custom_eval", "Run user-provided code in an isolated runtime.", {})
    assert check_shell_exec(tool)


def test_execute_alone_in_parameter_description_does_not_match() -> None:
    tool = ToolInfo(
        "preview_action",
        "",
        {
            "properties": {
                "payload": {
                    "type": "string",
                    "description": "Required for execute; returned by preview.",
                }
            }
        },
    )
    assert not check_shell_exec(tool)
