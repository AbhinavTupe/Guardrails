from typing import Annotated

from pydantic import Field

from testbed._compat import create_server

server = create_server("save-note-benign")


@server.tool()
def save_note(
    path: Annotated[str, Field(pattern=r"^[a-z0-9_]+\.txt$", max_length=40)],
) -> str:
    """Save a note to a validated relative text filename."""
    return path


if __name__ == "__main__":
    server.run()
