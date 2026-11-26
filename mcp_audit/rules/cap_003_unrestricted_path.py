"""Detect unconstrained string path parameters."""

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._cap_common import (
    has_path_indicator,
    parameter_evidence,
    parameters,
)
from mcp_audit.rules.registry import register


def _looks_like_path(name: str, schema: dict[str, object]) -> bool:
    description = schema.get("description")
    return bool(
        has_path_indicator(name)
        or (
            isinstance(description, str)
            and has_path_indicator(description)
        )
    )


@register("CAP-003", "Unrestricted path parameter", "unrestricted_path")
def check_unrestricted_path(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for name, schema in parameters(tool):
        if schema.get("type") != "string" or not _looks_like_path(name, schema):
            continue
        if any(constraint in schema for constraint in ("pattern", "enum", "maxLength")):
            continue
        findings.append(
            Finding(
                rule_id="CAP-003",
                severity=Severity.MEDIUM,
                confidence=0.8,
                tool_name=tool.name,
                evidence=parameter_evidence(tool, name, schema),
                fix=(
                    "Constrain path inputs to an allowlisted directory and validate "
                    "them before use."
                ),
            )
        )
    return findings
