"""Detect unusually long MCP descriptions."""

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._poi_common import description_texts, evidence_for_range
from mcp_audit.rules.registry import register


@register(
    "POI-005",
    "Abnormally long description",
    "poisoned_description",
)
def check_abnormal_description_length(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for description in description_texts(tool.description, tool.input_schema):
        if len(description) > 1000:
            start = 970
            end = min(len(description), 1000)
            findings.append(
                Finding(
                    rule_id="POI-005",
                    severity=Severity.LOW,
                    confidence=0.5,
                    tool_name=tool.name,
                    evidence=evidence_for_range(description, start, end),
                    fix=(
                        "Shorten the description to 1000 characters or fewer "
                        "and move details elsewhere."
                    ),
                )
            )
    return findings
