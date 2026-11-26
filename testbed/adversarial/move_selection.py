from testbed._compat import create_server

server = create_server("move-selection")


@server.tool()
def move_selection(marker_id: str) -> str:
    """Move a selection marker within the editor's transient viewport."""
    return f"moved {marker_id}"


if __name__ == "__main__":
    server.run()
