from mcp_audit.models import Finding, ScanResult, Severity, ToolInfo
from scripts.scan_public import (
    TargetResult,
    build_findings_markdown,
    build_markdown_table,
    build_totals,
    main,
    scrub_text,
)


def make_result(score: int, severities: list[Severity]) -> ScanResult:
    tool = ToolInfo(name="echo", description="", input_schema={})
    findings = [
        Finding(
            rule_id=f"RULE-{index}",
            severity=severity,
            confidence=1.0,
            tool_name="echo",
            evidence="exact evidence",
            fix="fix",
        )
        for index, severity in enumerate(severities)
    ]
    return ScanResult(
        server_command="python server.py",
        tools=[tool],
        findings=findings,
        score=score,
    )


def test_table_builder_handles_success_error_and_timeout() -> None:
    results = [
        TargetResult("ok", result=make_result(75, [Severity.HIGH, Severity.LOW])),
        TargetResult("error", error="launch failed"),
        TargetResult("timeout", timed_out=True, error="Timed out after 60 seconds"),
    ]

    table = build_markdown_table(results)

    assert "| ok | 1 | 75 | FAIL |" in table
    assert "error" in table
    assert "timeout" in table
    assert "| ok" in table


def test_totals_math() -> None:
    results = [
        TargetResult("one", result=make_result(75, [Severity.CRITICAL])),
        TargetResult("two", result=make_result(20, [Severity.MEDIUM])),
        TargetResult("three", timed_out=True, error="Timed out"),
    ]

    assert build_totals(results) == (3, 2, 1, 50.0)
    markdown = build_findings_markdown(results)
    assert "| 3 | 2 | 1 | 50.0% |" in markdown


def test_i_understand_guard() -> None:
    assert main([]) == 2


def test_scrubbing_absolute_paths_and_username() -> None:
    text = r"C:\Users\someone\repo\server.py"

    scrubbed = scrub_text(text)

    assert r"C:\Users\someone" not in scrubbed
    assert "someone" not in scrubbed
    assert scrubbed
