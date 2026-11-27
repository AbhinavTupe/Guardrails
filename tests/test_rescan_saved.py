import json
from pathlib import Path

import pytest

import scripts.scan_public as scan_public
from scripts.rescan_saved import rescan_saved


def test_rescan_saved_reapplies_rules_and_rebuilds_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    report_path = tmp_path / "findings.md"
    finding_path = findings_dir / "sample.json"
    finding_path.write_text(
        json.dumps(
            {
                "name": "sample",
                "server_command": "unused",
                "tools": [
                    {
                        "name": "run_command",
                        "description": "Run a command.",
                        "input_schema": {},
                    },
                    {
                        "name": "safe",
                        "description": "Does not expose credentials.",
                        "input_schema": {},
                    },
                ],
                "findings": [
                    {
                        "rule_id": "POI-004",
                        "severity": "HIGH",
                        "confidence": 0.85,
                        "tool_name": "safe",
                        "evidence": "credentials",
                        "fix": "old fix",
                    }
                ],
                "score": 25,
                "verdict": "REVIEW",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(scan_public, "FINDINGS_DIR", findings_dir)
    monkeypatch.setattr(scan_public, "REPORT_PATH", report_path)
    monkeypatch.setattr(scan_public, "ROOT", tmp_path)
    monkeypatch.setattr(
        scan_public,
        "load_targets",
        lambda: [
            {"name": "sample", "command": "unused", "source_url": "", "install_note": ""}
        ],
    )
    def reject_launch(*args: object, **kwargs: object) -> None:
        raise AssertionError("saved rescan must not launch targets")

    monkeypatch.setattr(scan_public, "run_scan", reject_launch)

    counts = rescan_saved(findings_dir, report_path)
    updated = json.loads(finding_path.read_text(encoding="utf-8"))

    assert counts == {"sample": 1}
    assert [finding["rule_id"] for finding in updated["findings"]] == ["CAP-001"]
    assert updated["score"] == 22
    assert updated["verdict"] == "REVIEW"
    assert updated["severity_counts"]["HIGH"] == 1
    assert "| sample | 2 | 22 | REVIEW |" in report_path.read_text(encoding="utf-8")


def test_saved_rescan_preserves_error_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    report_path = tmp_path / "findings.md"
    error_path = findings_dir / "failed.json"
    original = {"name": "failed", "error": "offline", "failure_reason": "network error"}
    error_path.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(scan_public, "FINDINGS_DIR", findings_dir)
    monkeypatch.setattr(scan_public, "REPORT_PATH", report_path)
    monkeypatch.setattr(scan_public, "load_targets", lambda: [])
    monkeypatch.setattr(scan_public, "load_failure_notes", lambda: {})

    assert rescan_saved(findings_dir, report_path) == {}
    assert json.loads(error_path.read_text(encoding="utf-8")) == original
    assert report_path.exists()
