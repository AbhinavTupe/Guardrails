from pathlib import Path

import pytest

import scripts.scan_public as scan_public
from mcp_audit.models import Finding, ScanResult, Severity, ToolInfo
from scripts.scan_public import (
    TargetResult,
    build_findings_markdown,
    build_markdown_table,
    build_minimal_env,
    build_totals,
    classify_failure_reason,
    get_failure_evidence,
    get_failure_reason,
    load_saved_results,
    main,
    prepare_relative_directories,
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
    assert "Failure category" in table
    assert "Failure evidence" in table


def test_totals_math() -> None:
    results = [
        TargetResult("one", result=make_result(75, [Severity.CRITICAL])),
        TargetResult("two", result=make_result(20, [Severity.MEDIUM])),
        TargetResult("three", timed_out=True, error="Timed out"),
    ]

    assert build_totals(results) == (3, 2, 1, 50.0)
    markdown = build_findings_markdown(results)
    assert "| 3 | 2 | 1 | 50.0% |" in markdown
    assert "% with HIGH+ (enumerated servers denominator)" in markdown
    assert "| unclassified | 1 |" in markdown


def test_report_groups_all_rules_and_classifies_failure_reasons() -> None:
    result = make_result(75, [Severity.HIGH, Severity.HIGH])
    result.findings[1] = Finding(
        rule_id=result.findings[0].rule_id,
        severity=Severity.HIGH,
        confidence=1.0,
        tool_name="different",
        evidence="second evidence",
        fix="fix",
    )
    rows = [
        TargetResult("ok", result=result),
        TargetResult("bad-protocol", error="JSON-RPC parse error"),
        TargetResult("blocked", error="Operation not permitted by sandbox"),
        TargetResult("offline", error="ECONNRESET while downloading"),
        TargetResult("launch", error="executable not found"),
    ]

    markdown = build_findings_markdown(rows)

    assert "RULE-0 x 2" in markdown
    assert "| bad-protocol | - | - | failed |" in markdown
    assert "| unclassified | 2 |" in markdown
    assert "| blocked by sandbox policy | 1 |" in markdown
    assert "| network error | 1 |" in markdown


def test_failure_notes_override_categories_and_findings_are_target_scoped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    (findings_dir / "known.json").write_text(
        '{"name":"known","error":"could not resolve package index"}',
        encoding="utf-8",
    )
    (findings_dir / "not-a-target.json").write_text(
        '{"name":"not-a-target","error":"launch failed"}',
        encoding="utf-8",
    )
    testbed_dir = findings_dir / "testbed"
    testbed_dir.mkdir()
    (testbed_dir / "vuln_shell.json").write_text(
        '{"name":"vuln_shell","tools":[],"findings":[]}',
        encoding="utf-8",
    )
    notes_path = tmp_path / "failure_notes.json"
    notes_path.write_text(
        '{"known":{"category":"requires credentials","evidence":"Requires API_TOKEN."}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(scan_public, "FINDINGS_DIR", findings_dir)
    monkeypatch.setattr(scan_public, "FAILURE_NOTES_PATH", notes_path)
    monkeypatch.setattr(
        scan_public,
        "load_targets",
        lambda: [{"name": "known", "command": "fake", "source_url": "", "install_note": ""}],
    )

    results = load_saved_results()

    assert [item.name for item in results] == ["known"]
    assert get_failure_reason(results[0]) == "requires credentials"
    assert get_failure_evidence(results[0]) == "Requires API_TOKEN."


def test_unnoted_failures_use_allowed_automatic_categories() -> None:
    assert get_failure_reason(TargetResult("offline", error="ECONNRESET")) == "network error"
    assert (
        get_failure_reason(TargetResult("unknown", error="launch failed"))
        == "unclassified"
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("operation timed out", "timeout"),
        ("protocol error: invalid message", "not an MCP server (protocol error)"),
        ("spawn failed", "launch error"),
        ("permission denied by sandbox", "blocked by sandbox policy"),
        ("ECONNREFUSED", "network error"),
    ],
)
def test_classifies_failure_reason(error: str, expected: str) -> None:
    assert classify_failure_reason(error) == expected


def test_scan_target_prepares_relative_dirs_and_uses_long_enumeration_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run_scan(
        command: str,
        probe: bool,
        *,
        env: dict[str, str],
        cwd: str,
        enumeration_timeout: float,
    ) -> ScanResult:
        observed["directory_exists"] = (Path(cwd) / "sandbox-empty").is_dir()
        observed["probe"] = probe
        observed["timeout"] = enumeration_timeout
        observed["env"] = env
        return make_result(0, [])

    monkeypatch.setattr(scan_public, "run_scan", fake_run_scan)
    target: dict[str, object] = {
        "name": "filesystem",
        "command": "npx server ./sandbox-empty",
        "source_url": "",
        "install_note": "",
    }

    result = scan_public.scan_target(target)

    assert result.result is not None
    assert observed["directory_exists"] is True
    assert observed["probe"] is False
    assert observed["timeout"] == 120.0
    assert isinstance(observed["env"], dict)


def test_relative_directory_creation_rejects_parent_escape(tmp_path: Path) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()

    prepare_relative_directories("npx package ./sandbox-empty ../outside", cwd)

    assert (cwd / "sandbox-empty").is_dir()
    assert not (tmp_path / "outside").exists()


def test_i_understand_guard() -> None:
    assert main([]) == 2


def test_scrubbing_absolute_paths_and_username() -> None:
    text = r"C:\Users\someone\repo\server.py"

    scrubbed = scrub_text(text)

    assert r"C:\Users\someone" not in scrubbed
    assert "someone" not in scrubbed
    assert scrubbed


def test_minimal_environment_drops_sensitive_variables(tmp_path: Path) -> None:
    home = tmp_path / "home"
    env = build_minimal_env(
        {
            "PATH": "/usr/bin",
            "GITHUB_TOKEN": "token",
            "api_KEY": "key",
            "CLIENT_SECRET": "secret",
            "DATABASE_PASSWORD": "password",
            "AWS_CREDENTIAL": "credential",
            "NORMAL": "not-passed",
            "UV_NATIVE_TLS": "true",
            "UV_HTTP_TIMEOUT": "30",
        },
        home=home,
    )

    assert env == {
        "PATH": "/usr/bin",
        "HOME": str(home),
        "npm_config_ignore_scripts": "true",
        "UV_NATIVE_TLS": "true",
        "UV_HTTP_TIMEOUT": "30",
    }
    assert home.is_dir()


def test_only_scans_requested_target_and_merges_existing_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    findings_dir = tmp_path / "findings"
    report_path = tmp_path / "findings.md"
    old_result = make_result(25, [Severity.HIGH])
    findings_dir.mkdir()
    (findings_dir / "existing.json").write_text(
        ScanResult(
            server_command="old",
            tools=old_result.tools,
            findings=old_result.findings,
            score=25,
        ).to_json().replace('"server_command":', '"name": "existing", "server_command":'),
        encoding="utf-8",
    )
    targets = [
        {"name": name, "command": "fake", "source_url": "", "install_note": ""}
        for name in ("existing", "fresh")
    ]
    scanned: list[str] = []

    monkeypatch.setattr(scan_public, "FINDINGS_DIR", findings_dir)
    monkeypatch.setattr(scan_public, "REPORT_PATH", report_path)
    monkeypatch.setattr(scan_public, "ROOT", tmp_path)
    monkeypatch.setattr(scan_public, "load_targets", lambda: targets)

    def fake_scan_target(target: dict[str, object]) -> TargetResult:
        scanned.append(str(target["name"]))
        return TargetResult(str(target["name"]), result=make_result(0, []))

    monkeypatch.setattr(scan_public, "scan_target", fake_scan_target)

    assert main(["--i-understand", "--only", "fresh"]) == 0

    report = report_path.read_text(encoding="utf-8")
    assert scanned == ["fresh"]
    assert "| existing |" in report
    assert "| fresh |" in report


def test_checked_in_report_matches_saved_findings() -> None:
    assert build_findings_markdown(load_saved_results()) == scan_public.REPORT_PATH.read_text(
        encoding="utf-8"
    )
