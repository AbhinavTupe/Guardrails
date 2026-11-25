import json
from typing import cast

import pytest

from mcp_audit.models import Finding, ScanResult, Severity, ToolInfo


def test_model_creation() -> None:
    tool = ToolInfo(
        name="search",
        description="Search documents",
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
    )
    finding = Finding(
        rule_id="RULE-1",
        severity=Severity.HIGH,
        confidence=0.9,
        tool_name="search",
        evidence="query parameter accepts arbitrary text",
        fix="Validate and restrict the query",
    )
    result = ScanResult(
        server_command="python server.py",
        tools=[tool],
        findings=[finding],
        score=80,
    )

    assert result.server_command == "python server.py"
    assert result.tools == [tool]
    assert result.findings == [finding]
    assert result.score == 80


def test_empty_evidence_raises() -> None:
    with pytest.raises(ValueError):
        Finding(
            rule_id="RULE-1",
            severity=Severity.LOW,
            confidence=0.5,
            tool_name="search",
            evidence="",
            fix="Fix it",
        )


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("nan")])
def test_bad_confidence_raises(confidence: float) -> None:
    with pytest.raises(ValueError):
        Finding(
            rule_id="RULE-1",
            severity=Severity.MEDIUM,
            confidence=confidence,
            tool_name="search",
            evidence="Concrete evidence",
            fix="Fix it",
        )


def test_json_output_contains_severity_name() -> None:
    finding = Finding(
        rule_id="RULE-1",
        severity=Severity.CRITICAL,
        confidence=1.0,
        tool_name="shell",
        evidence="Command execution is exposed",
        fix="Disable command execution",
    )
    result = ScanResult(server_command="python server.py", findings=[finding])

    data = result.to_dict()
    findings = cast(list[dict[str, object]], data["findings"])
    assert findings[0]["severity"] == "CRITICAL"

    parsed = json.loads(result.to_json())
    assert parsed["findings"][0]["severity"] == "CRITICAL"
    assert "explanations" in parsed


def test_scan_result_includes_verdict_and_severity_counts() -> None:
    finding = Finding(
        rule_id="RULE-1",
        severity=Severity.HIGH,
        confidence=0.9,
        tool_name="shell",
        evidence="Concrete evidence",
        fix="Disable command execution",
    )
    result = ScanResult(
        server_command="python server.py",
        findings=[finding],
        score=22,
    )

    data = result.to_dict()
    assert data["verdict"] == "REVIEW"
    assert data["severity_counts"] == {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 1,
        "CRITICAL": 0,
    }
