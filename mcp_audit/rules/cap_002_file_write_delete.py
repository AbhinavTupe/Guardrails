"""Detect tools with names associated with file modification."""

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules.registry import register

NAME_INDICATORS = ("write", "delete", "remove", "unlink", "rmdir", "overwrite", "move")


@register("CAP-002", "File write/delete capability", "file_write_delete")
def check_file_write_delete(tool: ToolInfo) -> list[Finding]:
    matched_indicator = next(
        (indicator for indicator in NAME_INDICATORS if indicator in tool.name.casefold()),
        None,
    )
    if matched_indicator is None:
        return []
    return [
        Finding(
            rule_id="CAP-002",
            severity=Severity.MEDIUM,
            confidence=0.8,
            tool_name=tool.name,
            evidence=f"tool name: {tool.name}; matched substring: {matched_indicator!r}",
            fix="Restrict file modifications to explicitly authorized operations and locations.",
        )
    ]
