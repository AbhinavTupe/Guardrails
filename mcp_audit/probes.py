"""Optional MCP server probes for mcp-audit."""

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from mcp_audit.connector import open_server_session
from mcp_audit.models import Finding, Severity, ToolInfo

LOGGER = logging.getLogger(__name__)
CALL_TIMEOUT_SECONDS = 5.0
DESTRUCTIVE_NAME_PARTS = (
    "write",
    "delete",
    "remove",
    "unlink",
    "rmdir",
    "overwrite",
    "move",
)
PATH_NAME_PARTS = DESTRUCTIVE_NAME_PARTS + ("exec", "shell", "command")
PATH_PARAMETERS = {"path", "file", "filename", "filepath"}
COMMAND_PARAMETERS = {"command", "cmd", "script"}


def _parameter_name(tool: ToolInfo, names: set[str]) -> str | None:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return None
    for name, schema in properties.items():
        if (
            isinstance(name, str)
            and name.casefold() in names
            and isinstance(schema, dict)
            and schema.get("type") == "string"
        ):
            return name
    return None


def _is_destructive(tool: ToolInfo) -> bool:
    name = tool.name.casefold()
    return any(part in name for part in DESTRUCTIVE_NAME_PARTS)


def _response_text(result: CallToolResult) -> str:
    text = "\n".join(
        item.text for item in result.content if isinstance(item, TextContent)
    )
    if result.structured_content is not None:
        return f"{text}\n{json.dumps(result.structured_content, ensure_ascii=True)}"
    return text


def _response_snippet(response: str, tokens: tuple[str, ...]) -> str:
    if not tokens:
        return ""

    matches: list[tuple[int, int]] = []
    for token in tokens:
        index = response.find(token)
        if index < 0:
            return ""
        matches.append((index, index + len(token)))

    start = min(index for index, _ in matches)
    end = max(index for _, index in matches)
    if end - start <= 120:
        snippet = response[start:end]
    else:
        first_token_start = matches[0][0]
        first_token_end = matches[0][1]
        first_token_length = first_token_end - first_token_start
        before = min(20, max(0, first_token_start))
        start = max(0, first_token_start - before)
        end = min(len(response), start + 120)
        if end - start < first_token_length:
            end = start + first_token_length
        snippet = response[start:end]

    return snippet.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")[
        :120
    ]


async def _call_tool(
    session: ClientSession,
    tool: ToolInfo,
    arguments: dict[str, str],
) -> str:
    try:
        async with asyncio.timeout(CALL_TIMEOUT_SECONDS):
            result = await session.call_tool(tool.name, arguments)
    except TimeoutError:
        LOGGER.warning("Probe call timed out for tool %s", tool.name)
        return ""
    except MCPError as exc:
        LOGGER.warning("Probe call failed for tool %s: %s", tool.name, exc)
        return ""
    if not isinstance(result, CallToolResult):
        return ""
    return _response_text(result)


async def _probe_path(
    session: ClientSession,
    tool: ToolInfo,
    parameter: str,
    canary_path: Path,
    token: str,
) -> Finding | None:
    absolute_path = str(canary_path)
    _, path_without_drive = os.path.splitdrive(absolute_path)
    payloads = (absolute_path, "../" * 8 + path_without_drive)
    evidence: str | None = None

    for payload in payloads:
        response = await _call_tool(session, tool, {parameter: payload})
        snippet = _response_snippet(response, (token,))
        if snippet and evidence is None:
            evidence = f"payload: {payload!r}; response snippet: {snippet!r}"

    if evidence is None:
        return None
    return Finding(
        rule_id="PRB-001",
        severity=Severity.HIGH,
        confidence=0.95,
        tool_name=tool.name,
        evidence=evidence,
        fix="Resolve paths within an allowlisted root and reject traversal outside it.",
    )


async def _probe_command(
    session: ClientSession,
    tool: ToolInfo,
    parameter: str,
) -> Finding | None:
    token_a = f"MCPAUDIT-{uuid.uuid4()}"
    token_b = f"MCPAUDIT-{uuid.uuid4()}"
    tokens = (token_a, token_b)
    payload = f"echo {token_a} && echo {token_b}"
    response = await _call_tool(session, tool, {parameter: payload})
    snippet = _response_snippet(response, tokens)
    if not snippet or payload in response:
        return None
    return Finding(
        rule_id="PRB-002",
        severity=Severity.CRITICAL,
        confidence=0.95,
        tool_name=tool.name,
        evidence=f"payload: {payload!r}; response snippet: {snippet!r}",
        fix="Avoid shell execution; use a fixed executable with validated arguments.",
    )


async def run_probes(command: str, tools: list[ToolInfo]) -> list[Finding]:
    """Run bounded, non-destructive probes against eligible tools."""
    candidates = [
        (
            tool,
            _parameter_name(tool, PATH_PARAMETERS)
            if not any(part in tool.name.casefold() for part in PATH_NAME_PARTS)
            else None,
            _parameter_name(tool, COMMAND_PARAMETERS),
        )
        for tool in tools
        if not _is_destructive(tool)
    ]
    candidates = [candidate for candidate in candidates if candidate[1] or candidate[2]]
    if not candidates:
        return []

    with TemporaryDirectory(prefix="mcp-audit-probe-") as sandbox:
        canary_token = f"MCPAUDIT-{uuid.uuid4()}"
        canary_path = Path(sandbox) / "canary.txt"
        canary_path.write_text(canary_token, encoding="utf-8")
        findings: list[Finding] = []
        async with open_server_session(command) as session:
            for tool, path_parameter, command_parameter in candidates:
                if path_parameter is not None:
                    finding = await _probe_path(
                        session, tool, path_parameter, canary_path, canary_token
                    )
                    if finding is not None:
                        findings.append(finding)
                if command_parameter is not None:
                    finding = await _probe_command(session, tool, command_parameter)
                    if finding is not None:
                        findings.append(finding)
        return findings
