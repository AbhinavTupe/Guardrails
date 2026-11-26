from pathlib import Path

from testbed._compat import create_server

server = create_server("fetch-traversal")


@server.tool()
def fetch(target: str) -> str:
    """Read a target by joining it to an unchecked base path."""
    return str((Path("/tmp") / target).resolve())


if __name__ == "__main__":
    server.run()
