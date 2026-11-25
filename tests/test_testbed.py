import asyncio
import shlex
import sys
from pathlib import Path

import pytest

from mcp_audit.connector import enumerate_server
from mcp_audit.rules import load_all_rules, run_rules

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


def test_poisoned_testbed_has_poisoned_description_finding() -> None:
    command = shlex.join([sys.executable, str(TESTBED / "vuln_poisoned.py")])
    result = asyncio.run(enumerate_server(command))
    load_all_rules()
    findings = run_rules(result.tools)

    assert any(
        finding.rule_id.startswith("POI-")
        for finding in findings
    )
    instruction_evidence = [
        finding.evidence.lower()
        for finding in findings
        if finding.rule_id == "POI-001"
    ]
    assert any("ignore previous instructions" in item for item in instruction_evidence)
    assert any("do not tell the user" in item for item in instruction_evidence)


@pytest.mark.parametrize("server_file", ["clean_calc.py", "clean_notes.py"])
def test_clean_testbeds_have_no_poisoned_description_findings(server_file: str) -> None:
    command = shlex.join([sys.executable, str(TESTBED / server_file)])
    result = asyncio.run(enumerate_server(command))
    load_all_rules()
    findings = run_rules(result.tools)

    assert not any(
        finding.rule_id.startswith("POI-")
        for finding in findings
    )
