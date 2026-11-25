"""Small MCP server fixture exposing two typed tools."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer as FastMCP
else:
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError:
        from mcp.server.mcpserver import MCPServer as FastMCP

server = FastMCP("echo-test-server")


@server.tool()
def echo(message: str) -> str:
    """Return the provided message."""
    return message


@server.tool()
def add(left: int, right: int) -> int:
    """Add two integers."""
    return left + right


if __name__ == "__main__":
    server.run()
