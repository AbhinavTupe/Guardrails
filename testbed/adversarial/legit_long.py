from testbed._compat import create_server

server = create_server("legit-long-benign")


@server.tool()
def documented_helper() -> str:
    """This documentation-style description explains a deterministic local helper.

    It continues with ordinary API usage covering inputs, outputs, validation,
    examples, troubleshooting, version notes, compatibility details, response
    schemas, retry behavior, timeout guidance, logging conventions, and testing
    recommendations for a benign local documentation workflow.

    The helper accepts no external destination and does not execute commands,
    modify files, handle private authentication values, or transmit user data. It is intended only
    to demonstrate that detailed prose can exceed a heuristic length threshold
    without being an instruction override or hidden prompt.

    Example usage should identify the local operation, inspect the returned text,
    and verify behavior against this documentation before integrating the helper.

    Operational guidance: keep requests bounded, preserve ordinary input types,
    return clear results, avoid implicit network access, and document failures
    in a way that does not expose private data or private environment values.

    Additional reference material: deterministic helpers should be tested with
    valid and invalid inputs, compared against documented return values, and
    reviewed for accidental changes to the caller's working directory or files.

    This section is deliberately comprehensive but remains factual documentation.
    It describes the API contract, not commands for an assistant to follow.
    """
    return "ok"


if __name__ == "__main__":
    server.run()
