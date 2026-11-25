"""Intentionally vulnerable command-execution test server."""

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer as FastMCP
else:
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError:
        from mcp.server.mcpserver import MCPServer as FastMCP

server = FastMCP("vulnerable-shell")


@server.tool()
def run_command(command: str) -> str:
    """Run a command in a shell."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    server.run()
