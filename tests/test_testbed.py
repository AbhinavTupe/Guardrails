import asyncio
import shlex
import sys
from pathlib import Path

import pytest

from mcp_audit.connector import enumerate_server

TESTBED = Path(__file__).parents[1] / "testbed"

EXPECTED_TOOLS = {
    "vuln_shell.py": {"run_command"},
    "vuln_poisoned.py": {"get_weather"},
    "vuln_files.py": {"read_file", "delete_file"},
    "clean_calc.py": {"add", "multiply"},
    "clean_notes.py": {"add_note", "list_notes"},
}


@pytest.mark.parametrize("server_file", sorted(EXPECTED_TOOLS))
def test_testbed_server_enumerates_expected_tools(server_file: str) -> None:
    command = shlex.join([sys.executable, str(TESTBED / server_file)])
    result = asyncio.run(enumerate_server(command))
    tool_names = {tool.name for tool in result.tools}
    assert EXPECTED_TOOLS[server_file] <= tool_names
