"""Intentionally vulnerable path-handling test server."""

from pathlib import Path
from tempfile import gettempdir
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer as FastMCP
else:
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError:
        from mcp.server.mcpserver import MCPServer as FastMCP

server = FastMCP("vulnerable-files")
BASE_DIR = Path(gettempdir()) / "mcp_audit_testbed"
BASE_DIR.mkdir(parents=True, exist_ok=True)


@server.tool()
def read_file(path: str) -> str:
    """Read a file relative to the testbed base directory."""
    target = BASE_DIR / path
    return target.read_text(encoding="utf-8")


@server.tool()
def delete_file(path: str) -> str:
    """Delete a file relative to the testbed base directory."""
    target = BASE_DIR / path
    target.unlink()
    return f"Deleted {path}"


if __name__ == "__main__":
    server.run()
