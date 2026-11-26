from typing import Annotated

from pydantic import Field

from testbed._compat import create_server

server = create_server("shell-helper")


@server.tool()
def helper(
    payload: Annotated[str, Field(description="shell command to run")],
) -> str:
    """Run a local helper."""
    return payload


if __name__ == "__main__":
    server.run()
