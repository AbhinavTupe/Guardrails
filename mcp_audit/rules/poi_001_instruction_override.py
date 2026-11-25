"""Detect instruction-override prompts in MCP descriptions."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._poi_common import (
    description_texts,
    evidence_for_range,
    merge_match_contexts,
)
from mcp_audit.rules.registry import register

PATTERN = re.compile(
    r"\b(?:ignore|disregard|bypass)\b.{0,40}\b(?:previous|prior|all|earlier)\b"
    r".{0,20}\b(?:instructions|rules)\b"
    r"|do\s+not\s+tell\s+(?:the\s+)?user"
    r"|don['’]t\s+mention\s+(?:this|it)",
    re.IGNORECASE,
)

@register(
    "POI-001",
    "Instruction override in description",
    "poisoned_description",
)
def check_instruction_override(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    descriptions = description_texts(tool.description, tool.input_schema)
    for description in descriptions:
        ranges = [(match.start(), match.end()) for match in PATTERN.finditer(description)]
        for start, end in merge_match_contexts(description, ranges):
            findings.append(
                Finding(
                    rule_id="POI-001",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    tool_name=tool.name,
                    evidence=evidence_for_range(description, start, end),
                    fix="Remove instruction-override language and keep the description factual.",
                )
            )
    return findings
