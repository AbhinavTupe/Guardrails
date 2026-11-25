"""Detect tools that appear to execute shell commands."""

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._cap_common import parameter_evidence, parameters
from mcp_audit.rules.registry import register

NAME_INDICATORS = ("run_command", "exec", "shell", "bash", "eval", "system")
PARAMETER_NAMES = {"command", "cmd", "script"}


@register("CAP-001", "Shell command execution", "shell_exec")
def check_shell_exec(tool: ToolInfo) -> list[Finding]:
    matching_parameters = [
        (name, schema)
        for name, schema in parameters(tool)
        if name.casefold() in PARAMETER_NAMES and schema.get("type") == "string"
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
