"""Detect unconstrained string URL parameters."""

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._cap_common import parameter_evidence, parameters
from mcp_audit.rules.registry import register

PARAMETER_NAMES = {"url", "uri", "endpoint", "host"}


@register("CAP-004", "Unrestricted URL parameter", "unrestricted_url")
def check_unrestricted_url(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for name, schema in parameters(tool):
        if name.casefold() not in PARAMETER_NAMES or schema.get("type") != "string":
            continue
        if "pattern" in schema or "enum" in schema:
            continue
        findings.append(
            Finding(
                rule_id="CAP-004",
                severity=Severity.MEDIUM,
                confidence=0.8,
                tool_name=tool.name,
                evidence=parameter_evidence(tool, name, schema),
                fix="Validate URL inputs against an allowlist of permitted destinations.",
            )
        )
    return findings
