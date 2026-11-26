from typing import Literal

from testbed._compat import create_server

server = create_server("read-report-benign")


@server.tool()
def read_report(name: Literal["summary", "details"]) -> str:
    """Read a report by selecting one of the documented report names."""
    return name


if __name__ == "__main__":
    server.run()
