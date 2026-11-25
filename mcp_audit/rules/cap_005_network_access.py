"""Detect tools with names associated with network access."""

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules.registry import register

NAME_INDICATORS = ("fetch", "download", "http", "request", "webhook", "email")


@register("CAP-005", "Network access", "network_access")
def check_network_access(tool: ToolInfo) -> list[Finding]:
    matched_indicator = next(
        (indicator for indicator in NAME_INDICATORS if indicator in tool.name.casefold()),
        None,
    )
    if matched_indicator is None:
        return []
    return [
        Finding(
            rule_id="CAP-005",
            severity=Severity.LOW,
            confidence=0.6,
            tool_name=tool.name,
            evidence=f"tool name: {tool.name}; matched substring: {matched_indicator!r}",
            fix="Limit network destinations and require authorization for outbound requests.",
        )
    ]
