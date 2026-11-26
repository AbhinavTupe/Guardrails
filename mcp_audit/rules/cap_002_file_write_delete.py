"""Detect tools with names associated with file modification."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._cap_common import (
    has_file_path_indicator,
    parameter_evidence,
    parameters,
)
from mcp_audit.rules._poi_common import description_texts
from mcp_audit.rules.registry import register

NAME_INDICATORS = ("write", "delete", "remove", "unlink", "rmdir", "overwrite", "move")
FILE_OPERATION = re.compile(
    r"\b(?:writes?|deletes?|removes?|unlinks?|rmdirs?|overwrites?|moves?)\b",
    re.IGNORECASE,
)
FILE_RESOURCE = re.compile(
    r"\b(?:file|files|path|paths|directory|directories|folder|folders|disk|filesystem)\b",
    re.IGNORECASE,
)


def _file_context_evidence(tool: ToolInfo) -> str | None:
    for name, schema in parameters(tool):
        if has_file_path_indicator(name):
            return parameter_evidence(tool, name, schema)
        if schema.get("format") == "path":
            return parameter_evidence(tool, name, schema)
    for description in description_texts(tool.description, tool.input_schema):
        if FILE_OPERATION.search(description) and FILE_RESOURCE.search(description):
            return f"description: {description!r}"
    return None


@register("CAP-002", "File write/delete capability", "file_write_delete")
def check_file_write_delete(tool: ToolInfo) -> list[Finding]:
    matched_indicator = next(
        (indicator for indicator in NAME_INDICATORS if indicator in tool.name.casefold()),
        None,
    )
    file_context = _file_context_evidence(tool)
    if matched_indicator is None or file_context is None:
        return []
    return [
        Finding(
            rule_id="CAP-002",
            severity=Severity.MEDIUM,
            confidence=0.8,
            tool_name=tool.name,
            evidence=(
                f"tool name: {tool.name}; matched substring: {matched_indicator!r}; "
                f"{file_context}"
            ),
            fix="Restrict file modifications to explicitly authorized operations and locations.",
        )
    ]
