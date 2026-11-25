"""Clean in-memory notes test server."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer as FastMCP
else:
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError:
        from mcp.server.mcpserver import MCPServer as FastMCP

server = FastMCP("clean-notes")
notes: list[str] = []


@server.tool()
def add_note(text: str) -> str:
    """Add a note containing at most 200 characters."""
    if len(text) > 200:
        raise ValueError("Notes are limited to 200 characters")
    notes.append(text)
    return "Note added"


@server.tool()
def list_notes() -> list[str]:
    """List all in-memory notes."""
    return list(notes)


if __name__ == "__main__":
    server.run()
