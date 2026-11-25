"""Detect hidden AI directives and sensitive targets in MCP descriptions."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._poi_common import (
    description_texts,
    evidence_for_range,
    merge_match_contexts,
)
from mcp_audit.rules.registry import register

TAG_PATTERN = re.compile(r"<important>|<system>|SYSTEM\s*:", re.IGNORECASE)
SENSITIVE_PATTERN = re.compile(
    r"~/\.ssh|id_rsa|\.env|credentials",
    re.IGNORECASE,
)


@register(
    "POI-004",
    "Hidden AI directive or sensitive target",
    "poisoned_description",
)
def check_hidden_ai_blocks(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for description in description_texts(tool.description, tool.input_schema):
        for pattern in (TAG_PATTERN, SENSITIVE_PATTERN):
            ranges = [
                (match.start(), match.end())
                for match in pattern.finditer(description)
            ]
            for start, end in merge_match_contexts(description, ranges):
                findings.append(
                    Finding(
                        rule_id="POI-004",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        tool_name=tool.name,
                        evidence=evidence_for_range(description, start, end),
                        fix=(
                            "Remove hidden AI directives and references to sensitive "
                            "files or credentials."
                        ),
                    )
                )
    return findings
