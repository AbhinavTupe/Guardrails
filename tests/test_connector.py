import asyncio
import shlex
import sys
from pathlib import Path
from typing import cast

import pytest

from mcp_audit.connector import ConnectorError, enumerate_server

FIXTURE = Path(__file__).parent / "fixtures" / "echo_server.py"


def _fixture_command() -> str:
    return shlex.join([sys.executable, str(FIXTURE)])


def test_enumerate_server_lists_tools_and_schemas() -> None:
    result = asyncio.run(enumerate_server(_fixture_command()))

    tools = {tool.name: tool for tool in result.tools}
    assert set(tools) == {"echo", "add"}
    assert tools["echo"].description == "Return the provided message."
    echo_properties = cast(dict[str, dict[str, object]], tools["echo"].input_schema["properties"])
    assert echo_properties["message"]["type"] == "string"
    assert tools["echo"].input_schema["required"] == ["message"]
    add_properties = cast(dict[str, dict[str, object]], tools["add"].input_schema["properties"])
    assert add_properties["left"]["type"] == "integer"
    assert add_properties["right"]["type"] == "integer"
    assert tools["add"].input_schema["required"] == ["left", "right"]


def test_bad_command_raises_connector_error() -> None:
    with pytest.raises(ConnectorError, match="launch or protocol error"):
        asyncio.run(enumerate_server("mcp-audit-command-that-does-not-exist"))


def test_timeout_raises_connector_error() -> None:
    with pytest.raises(ConnectorError, match="timed out"):
        command = shlex.join([sys.executable, "-c", "import time; time.sleep(5)"])
        asyncio.run(enumerate_server(command, timeout=0.1))
