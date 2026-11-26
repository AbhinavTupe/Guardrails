import asyncio
import shlex
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

import pytest
from mcp import ClientSession
from mcp.types import CallToolResult, TextContent

import mcp_audit.probes as probes
from mcp_audit.connector import enumerate_server
from mcp_audit.models import ToolInfo
from mcp_audit.rules import get_rule_category

TESTBED = Path(__file__).parents[1] / "testbed"


def _command(server_file: str) -> str:
    return shlex.join([sys.executable, str(TESTBED / server_file)])


@pytest.mark.parametrize(
    ("server_file", "rule_id", "category"),
    [
        ("vuln_files.py", "PRB-001", "unrestricted_path"),
        ("vuln_shell.py", "PRB-002", "shell_exec"),
    ],
)
def test_vulnerable_testbeds_are_detected(
    server_file: str, rule_id: str, category: str
) -> None:
    command = _command(server_file)
    tools = asyncio.run(enumerate_server(command)).tools
    findings = asyncio.run(probes.run_probes(command, tools))

    finding = next(item for item in findings if item.rule_id == rule_id)
    assert get_rule_category(rule_id) == category
    assert "payload:" in finding.evidence
    assert "response snippet:" in finding.evidence
    assert "MCPAUDIT-" in finding.evidence
    if rule_id == "PRB-001":
        assert finding.confidence == 0.95
        assert finding.severity.name == "HIGH"
    else:
        assert finding.confidence == 0.95
        assert finding.severity.name == "CRITICAL"

    evidence = finding.evidence
    snippet = evidence.split("response snippet:", 1)[1].strip().strip("'")
    assert len(snippet) <= 120
    assert "\n" not in snippet


def test_response_snippet_is_single_escaped_120_char_window() -> None:
    token_a = "MCPAUDIT-token-a"
    token_b = "MCPAUDIT-token-b"
    response = "x" * 80 + token_a + "\n" + "y" * 80 + "\n" + token_b

    snippet = probes._response_snippet(response, (token_a, token_b))

    assert len(snippet) <= 120
    assert "\n" not in snippet
    assert "\\n" in snippet
    assert snippet.count(token_a) == 1


@pytest.mark.parametrize("server_file", ["clean_calc.py", "clean_notes.py"])
def test_clean_testbeds_have_no_probe_findings(server_file: str) -> None:
    command = _command(server_file)
    tools = asyncio.run(enumerate_server(command)).tools

    assert asyncio.run(probes.run_probes(command, tools)) == []


def test_delete_file_is_never_selected_as_probe_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called_tools: list[str] = []

    class RecordingSession:
        async def call_tool(
            self, name: str, _arguments: dict[str, str]
        ) -> object:
            called_tools.append(name)
            return object()

    @asynccontextmanager
    async def fake_open_server_session(_command: str) -> AsyncIterator[ClientSession]:
        yield cast(ClientSession, RecordingSession())

    monkeypatch.setattr(probes, "open_server_session", fake_open_server_session)
    tools = [
        ToolInfo(
            name="read_file",
            description="",
            input_schema={"properties": {"path": {"type": "string"}}},
        ),
        ToolInfo(
            name="delete_file",
            description="",
            input_schema={"properties": {"path": {"type": "string"}}},
        ),
    ]

    asyncio.run(probes.run_probes("unused", tools))

    assert called_tools == ["read_file", "read_file"]


def test_command_echo_is_not_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    class EchoSession:
        async def call_tool(
            self, _name: str, arguments: dict[str, str]
        ) -> CallToolResult:
            return CallToolResult(
                content=[TextContent(type="text", text=arguments["command"])]
            )

    @asynccontextmanager
    async def fake_open_server_session(_command: str) -> AsyncIterator[ClientSession]:
        yield cast(ClientSession, EchoSession())

    monkeypatch.setattr(probes, "open_server_session", fake_open_server_session)
    tools = [
        ToolInfo(
            name="run_command",
            description="",
            input_schema={"properties": {"command": {"type": "string"}}},
        )
    ]

    assert asyncio.run(probes.run_probes("unused", tools)) == []


def test_rule_description_parameters_are_probed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    class RecordingSession:
        async def call_tool(
            self, name: str, arguments: dict[str, str]
        ) -> object:
            calls.append((name, next(iter(arguments))))
            return object()

    @asynccontextmanager
    async def fake_open_server_session(_command: str) -> AsyncIterator[ClientSession]:
        yield cast(ClientSession, RecordingSession())

    monkeypatch.setattr(probes, "open_server_session", fake_open_server_session)
    tools = [
        ToolInfo(
            "prepare_payload",
            "",
            {
                "properties": {
                    "directive": {
                        "type": "string",
                        "description": "Execute the supplied task.",
                    }
                }
            },
        ),
        ToolInfo(
            "inspect_item",
            "",
            {
                "properties": {
                    "locator": {
                        "type": "string",
                        "description": "Destination pathname to inspect.",
                    }
                }
            },
        ),
    ]

    asyncio.run(probes.run_probes("unused", tools))

    assert calls == [
        ("prepare_payload", "directive"),
        ("inspect_item", "locator"),
        ("inspect_item", "locator"),
    ]
