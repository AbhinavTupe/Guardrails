"""Detect tools that appear to execute shell commands."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._cap_common import parameter_evidence, parameters
from mcp_audit.rules.registry import register

NAME_INDICATORS = ("run_command", "exec", "shell", "bash", "eval", "system")
PARAMETER_NAMES = {"command", "cmd", "script"}
PARAMETER_DESCRIPTION = re.compile(
    r"\bshell\s+command\b|\brun\s+command\b|\bexecute\b",
    re.IGNORECASE,
)


def _is_command_parameter(name: str, schema: dict[str, object]) -> bool:
    description = schema.get("description")
    return name.casefold() in PARAMETER_NAMES or (
        isinstance(description, str) and bool(PARAMETER_DESCRIPTION.search(description))
    )


@register("CAP-001", "Shell command execution", "shell_exec")
def check_shell_exec(tool: ToolInfo) -> list[Finding]:
    matching_parameters = [
        (name, schema)
        for name, schema in parameters(tool)
        if schema.get("type") == "string"
        and _is_command_parameter(name, schema)
    ]
    if matching_parameters:
        return [
            Finding(
                rule_id="CAP-001",
                severity=Severity.HIGH,
                confidence=0.9,
                tool_name=tool.name,
                evidence=parameter_evidence(tool, name, schema),
                fix="Avoid passing unrestricted user input to shell commands.",
            )
            for name, schema in matching_parameters
        ]

    matched_indicator = next(
        (indicator for indicator in NAME_INDICATORS if indicator in tool.name.casefold()),
        None,
    )
    if matched_indicator is None:
        return []
    return [
        Finding(
            rule_id="CAP-001",
            severity=Severity.HIGH,
            confidence=0.9,
            tool_name=tool.name,
            evidence=(
                f"tool name: {tool.name}; matched substring: {matched_indicator!r}"
            ),
            fix="Avoid passing unrestricted user input to shell commands.",
        )
    ]
