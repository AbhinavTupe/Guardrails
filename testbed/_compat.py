"""Compatibility helpers for testbed MCP stdio servers."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer as FastMCP
else:
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError:
        from mcp.server.mcpserver import MCPServer as FastMCP


def create_server(name: str) -> FastMCP:
    return FastMCP(name)
