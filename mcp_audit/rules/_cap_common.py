"""Shared helpers for capability rules."""

import json

from mcp_audit.models import ToolInfo


def parameters(tool: ToolInfo) -> list[tuple[str, dict[str, object]]]:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return []
    return [
        (name, schema)
        for name, schema in properties.items()
        if isinstance(name, str) and isinstance(schema, dict)
    ]


def parameter_evidence(tool: ToolInfo, name: str, schema: dict[str, object]) -> str:
    excerpt = json.dumps(schema, ensure_ascii=True, sort_keys=True)
    return f"tool name: {tool.name}; parameter {name!r} schema: {excerpt}"
