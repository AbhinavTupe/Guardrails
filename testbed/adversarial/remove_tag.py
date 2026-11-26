from testbed._compat import create_server

server = create_server("remove-tag-benign")


@server.tool()
def remove_tag(tag_id: int) -> str:
    """Remove a tag identifier from an in-memory label set."""
    return f"removed {tag_id}"


if __name__ == "__main__":
    server.run()
