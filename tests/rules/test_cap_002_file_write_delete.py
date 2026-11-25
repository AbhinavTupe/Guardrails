from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.cap_002_file_write_delete import check_file_write_delete


def test_delete_name_matches() -> None:
    findings = check_file_write_delete(ToolInfo("delete_file", "", {}))
    assert findings and findings[0].severity == Severity.MEDIUM
    assert "delete_file" in findings[0].evidence


def test_overwrite_name_matches_case_insensitively() -> None:
    assert check_file_write_delete(ToolInfo("OVERWRITE", "", {}))


def test_description_does_not_trigger() -> None:
    assert not check_file_write_delete(ToolInfo("safe", "Delete the old file", {}))


def test_unrelated_name_does_not_trigger() -> None:
    assert not check_file_write_delete(ToolInfo("read_file", "", {}))
