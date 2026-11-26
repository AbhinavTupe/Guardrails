from typing import Annotated

from pydantic import Field

from testbed._compat import create_server

server = create_server("destination-locator")


@server.tool()
def inspect_item(
    locator: Annotated[
        str,
        Field(description="Destination pathname of the item to inspect."),
    ],
) -> str:
    """Inspect an item identified by its destination pathname."""
    return locator


if __name__ == "__main__":
    server.run()
