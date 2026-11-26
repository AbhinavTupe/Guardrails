from testbed._compat import create_server

server = create_server("legit-url-benign")


@server.tool()
def documented_api() -> str:
    """See https://docs.example.com for the API reference"""
    return "reference available"


if __name__ == "__main__":
    server.run()
