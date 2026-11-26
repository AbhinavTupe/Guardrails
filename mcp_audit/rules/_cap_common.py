"""Shared helpers for capability rules."""

import json
import re

from mcp_audit.models import ToolInfo

PATH_INDICATORS = {
    "dir",
    "directory",
    "file",
    "filepath",
    "filename",
    "path",
    "pathname",
    "target",
}
FILE_PATH_INDICATORS = PATH_INDICATORS - {"target"}


def parameters(tool: ToolInfo) -> list[tuple[str, dict[str, object]]]:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return []
    return [
        (name, schema)
        for name, schema in properties.items()
        if isinstance(name, str) and isinstance(schema, dict)
    ]


def _words(value: str) -> list[str]:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    return re.findall(r"[a-z0-9]+", separated.casefold())


def has_path_indicator(value: str) -> bool:
    return any(word in PATH_INDICATORS for word in _words(value))


def has_file_path_indicator(value: str) -> bool:
    return any(word in FILE_PATH_INDICATORS for word in _words(value))


def parameter_evidence(tool: ToolInfo, name: str, schema: dict[str, object]) -> str:
    excerpt = json.dumps(schema, ensure_ascii=True, sort_keys=True)
    return f"tool name: {tool.name}; parameter {name!r} schema: {excerpt}"
