import json
from pathlib import Path

from scripts.triage_medium import build_report


def test_build_report_groups_medium_findings_and_excludes_testbed(tmp_path: Path) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    (findings_dir / "server_b.json").write_text(
        json.dumps(
            {
                "name": "server-b",
                "findings": [
                    {
                        "rule_id": "RULE-2",
                        "severity": "MEDIUM",
                        "tool_name": "second",
                        "evidence": "e" * 101,
                    },
                    {
                        "rule_id": "RULE-1",
                        "severity": "LOW",
                        "tool_name": "ignored",
                        "evidence": "not medium",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "server_a.json").write_text(
        json.dumps(
            {
                "name": "server-a",
                "findings": [
                    {
                        "rule_id": "RULE-2",
                        "severity": "MEDIUM",
                        "tool_name": "first",
                        "evidence": "specific evidence",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    testbed_dir = findings_dir / "testbed"
    testbed_dir.mkdir()
    (testbed_dir / "vulnerability.json").write_text(
        json.dumps(
            {
                "name": "testbed",
                "findings": [
                    {
                        "rule_id": "RULE-0",
                        "severity": "MEDIUM",
                        "tool_name": "testbed_tool",
                        "evidence": "excluded",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = build_report(findings_dir)

    assert report.index("## RULE-2") < report.index("### server-a")
    assert report.index("### server-a") < report.index("### server-b")
    assert "- **first** - specific evidence" in report
    assert "- **second** - " + "e" * 97 + "..." in report
    assert "ignored" not in report
    assert "testbed" not in report
