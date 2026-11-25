"""MCP server connection support for mcp-audit."""

import asyncio
import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from mcp_audit.models import ServerInfo, ToolInfo


class ConnectorError(Exception):
    """Raised when an MCP server cannot be enumerated."""


@asynccontextmanager
async def open_server_session(command: str) -> AsyncIterator[ClientSession]:
    """Launch a server command over stdio and yield its initialized session."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ConnectorError(f"Invalid server command: {exc}") from exc
    if not parts:
        raise ConnectorError("Server command is empty")

    try:
        async with stdio_client(
            StdioServerParameters(command=parts[0], args=parts[1:])
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session
    except ConnectorError:
        raise
    except Exception as exc:
        raise ConnectorError(f"MCP server launch or protocol error: {exc}") from exc


async def enumerate_server(command: str, timeout: float = 30.0) -> ServerInfo:
    """Launch a server command over stdio and enumerate its MCP capabilities."""

    async def enumerate_session() -> ServerInfo:
        async with open_server_session(command) as session:
            tool_result = await session.list_tools()
            tools = [
                ToolInfo(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=tool.input_schema,
                )
                for tool in tool_result.tools
            ]
            try:
                resource_result = await session.list_resources()
                resources = [resource.uri for resource in resource_result.resources]
            except MCPError as exc:
                if exc.code != -32601:
                    raise
                resources = []
            try:
                prompt_result = await session.list_prompts()
                prompts = [prompt.name for prompt in prompt_result.prompts]
            except MCPError as exc:
                if exc.code != -32601:
                    raise
                prompts = []
            return ServerInfo(tools=tools, resources=resources, prompts=prompts)

    try:
        async with asyncio.timeout(timeout):
            return await enumerate_session()
    except TimeoutError as exc:
        raise ConnectorError(f"MCP server operation timed out after {timeout} seconds") from exc
