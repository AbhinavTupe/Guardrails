"""Detect unconstrained string path parameters."""

import re

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._cap_common import (
    parameter_evidence,
    parameters,
)
from mcp_audit.rules.registry import register

_EXCLUDED_SUFFIXES = {"at", "count", "date", "id", "ids", "key"}
_PATH_NAME_PARTS = {
    "cwd",
    "dir",
    "directory",
    "file",
    "filename",
    "filepath",
    "folder",
    "path",
    "root",
}
_PATH_SYNONYMS = {
    "dest",
    "destination",
    "location",
    "locator",
    "source",
    "src",
    "target",
}
_PATH_VALUE_DESCRIPTION_PATTERNS = (
    re.compile(r"\b(?:path|pathname)\s+(?:to|of|for|from)\b", re.IGNORECASE),
    re.compile(r"\b(?:file|directory|folder|filesystem)\s+(?:path|pathname)\b", re.IGNORECASE),
    re.compile(r"\bfilesystem\s+location\b", re.IGNORECASE),
    re.compile(r"\b(?:a|an|the|this|that)\s+(?:file|directory|folder|filesystem)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:is|are|as|be|represents?|refers?\s+to)\s+"
        r"(?:a|an|the)?\s*(?:file|directory|folder|filesystem|path|pathname)\b",
        re.IGNORECASE,
    ),
)


def _name_tokens(name: str) -> list[str]:
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    return re.findall(r"[a-z0-9]+", separated.casefold())


def _has_excluded_suffix(name: str) -> bool:
    tokens = _name_tokens(name)
    return bool(tokens and tokens[-1] in _EXCLUDED_SUFFIXES)


def _looks_like_path(name: str) -> bool:
    return bool(set(_name_tokens(name)).intersection(_PATH_NAME_PARTS))


def _description_identifies_path(description: object) -> bool:
    return isinstance(description, str) and any(
        pattern.search(description) for pattern in _PATH_VALUE_DESCRIPTION_PATTERNS
    )


def _synonym_identifies_path(name: str, schema: dict[str, object]) -> bool:
    if name.casefold() not in _PATH_SYNONYMS:
        return False
    description = schema.get("description")
    if not isinstance(description, str) or not description.strip():
        return True
    return _description_identifies_path(description)


@register("CAP-003", "Unrestricted path parameter", "unrestricted_path")
def check_unrestricted_path(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    for name, schema in parameters(tool):
        if _has_excluded_suffix(name):
            continue
        schema_format = schema.get("format")
        if isinstance(schema_format, str) and schema_format.casefold() in {
            "date",
            "date-time",
            "uuid",
        }:
            continue
        if schema.get("type") != "string":
            continue
        if not _looks_like_path(name):
            if not _synonym_identifies_path(name, schema):
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
