from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules import (
    get_rule_category,
    register,
    run_rules,
    unregister_rule,
)


def test_dummy_rule_fires_and_unregisters() -> None:
    rule_id = "TEST_DUMMY"

    @register(rule_id, "Dummy rule", "shell_exec")
    def dummy_rule(tool: ToolInfo) -> list[Finding]:
        return [
            Finding(
                rule_id=rule_id,
                severity=Severity.HIGH,
                confidence=1.0,
                tool_name=tool.name,
                evidence=tool.description,
                fix="Fix it",
            )
        ]

    try:
        tool = ToolInfo(
            name="danger",
            description="Runs commands",
            input_schema={},
        )
        findings = run_rules([tool])

        assert any(finding.rule_id == rule_id for finding in findings)
        assert get_rule_category(rule_id) == "shell_exec"
    finally:
        unregister_rule(rule_id)


def test_duplicate_rule_id_raises() -> None:
    rule_id = "TEST_DUPLICATE"

    @register(rule_id, "First", "shell_exec")
    def first(tool: ToolInfo) -> list[Finding]:
        del tool
        return []

    try:
        with __import__("pytest").raises(ValueError, match="duplicate rule_id"):

            @register(rule_id, "Second", "shell_exec")
            def second(tool: ToolInfo) -> list[Finding]:
                del tool
                return []
    finally:
        unregister_rule(rule_id)


def test_crashing_rule_does_not_stop_other_rules() -> None:
    crash_id = "TEST_CRASH"
    working_id = "TEST_WORKING"

    @register(crash_id, "Crash", "shell_exec")
    def crash(tool: ToolInfo) -> list[Finding]:
        del tool
        raise RuntimeError("boom")

    @register(working_id, "Working", "shell_exec")
    def working(tool: ToolInfo) -> list[Finding]:
        return [
            Finding(
                rule_id=working_id,
                severity=Severity.LOW,
                confidence=1.0,
                tool_name=tool.name,
                evidence="worked",
                fix="none",
            )
        ]

    try:
        findings = run_rules([ToolInfo("safe", "Safe", {})])
        assert [finding.rule_id for finding in findings] == [working_id]
    finally:
        unregister_rule(crash_id)
        unregister_rule(working_id)


def test_findings_sort_by_severity_tool_and_rule() -> None:
    tool_a = ToolInfo("a", "A", {})
    tool_b = ToolInfo("b", "B", {})

    rule_id = "TEST_SORT_SOURCE"

    @register(rule_id, "Sort source", "shell_exec")
    def sort_source(tool: ToolInfo) -> list[Finding]:
        if tool.name == "a":
            return [Finding("RULE_A", Severity.HIGH, 1.0, "a", "e", "f")]
        return [
            Finding("RULE_B", Severity.LOW, 1.0, "b", "e", "f"),
            Finding("RULE_Z", Severity.HIGH, 1.0, "b", "e", "f"),
            Finding("RULE_A", Severity.HIGH, 1.0, "b", "e", "f"),
        ]

    try:
        result = run_rules([tool_a, tool_b])
        sorted_findings = [finding for finding in result if finding.rule_id.startswith("RULE_")]
        assert [(f.severity, f.tool_name, f.rule_id) for f in sorted_findings] == [
            (Severity.HIGH, "a", "RULE_A"),
            (Severity.HIGH, "b", "RULE_A"),
            (Severity.HIGH, "b", "RULE_Z"),
            (Severity.LOW, "b", "RULE_B"),
        ]
    finally:
        unregister_rule(rule_id)
