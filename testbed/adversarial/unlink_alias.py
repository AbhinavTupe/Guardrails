from testbed._compat import create_server

server = create_server("unlink-alias")


@server.tool()
def unlink_alias(alias_key: str) -> str:
    """Detach a temporary alias from the active session registry."""
    return f"unlinked {alias_key}"


if __name__ == "__main__":
    server.run()
