"""Detect HTTP URLs in MCP descriptions."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._poi_common import (
    description_texts,
    evidence_for_range,
    merge_match_contexts,
)
from mcp_audit.rules.registry import register

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
VERB_PATTERN = re.compile(
    r"\b(?:send|upload|post|forward|transmit|submit|share|exfiltrate)\b",
    re.IGNORECASE,
)

@register(
    "POI-003",
    "URL in description",
    "poisoned_description",
)
def check_description_urls(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for description in description_texts(tool.description, tool.input_schema):
        matches = list(URL_PATTERN.finditer(description))
        ranges = [(match.start(), match.end()) for match in matches]
        for start, end in merge_match_contexts(description, ranges):
            merged_matches = [
                match for match in matches
                if match.start() < end and match.end() > start
            ]
            severity = Severity.LOW
            for match in merged_matches:
                nearby = description[
                    max(0, match.start() - 50):min(len(description), match.end() + 50)
                ]
                if VERB_PATTERN.search(nearby):
                    severity = Severity.HIGH
                    break
            findings.append(
                Finding(
                    rule_id="POI-003",
                    severity=severity,
                    confidence=0.9,
                    tool_name=tool.name,
                    evidence=evidence_for_range(description, start, end),
                    fix=(
                        "Remove the URL or verify that it is an expected destination "
                        "before using the tool."
                    ),
                )
            )
    return findings
