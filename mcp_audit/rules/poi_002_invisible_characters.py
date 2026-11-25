"""Detect invisible and bidi characters in MCP descriptions."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._poi_common import (
    description_texts,
    evidence_for_range,
    merge_match_contexts,
)
from mcp_audit.rules.registry import register

PATTERN = re.compile("[\u200b-\u200d\u2060\uFEFF\u202a-\u202e\u2066-\u2069]")

@register(
    "POI-002",
    "Invisible or bidi characters in description",
    "poisoned_description",
)
def check_invisible_characters(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for description in description_texts(tool.description, tool.input_schema):
        ranges = [(match.start(), match.end()) for match in PATTERN.finditer(description)]
        for start, end in merge_match_contexts(description, ranges):
            findings.append(
                Finding(
                    rule_id="POI-002",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    tool_name=tool.name,
                    evidence=evidence_for_range(description, start, end),
                    fix=(
                        "Remove zero-width and bidirectional control characters "
                        "from the description."
                    ),
                )
            )
    return findings
