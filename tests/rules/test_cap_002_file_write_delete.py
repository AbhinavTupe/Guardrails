from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.cap_002_file_write_delete import check_file_write_delete


def test_delete_name_matches() -> None:
    findings = check_file_write_delete(
        ToolInfo(
            "delete_file",
            "",
            {"properties": {"path": {"type": "string"}}},
        )
    )
    assert findings and findings[0].severity == Severity.MEDIUM
    assert "delete_file" in findings[0].evidence


def test_overwrite_name_matches_case_insensitively() -> None:
    assert check_file_write_delete(
        ToolInfo("OVERWRITE", "Overwrites the file contents.", {})
    )


def test_description_does_not_trigger() -> None:
    assert not check_file_write_delete(ToolInfo("safe", "Delete the old file", {}))


def test_unrelated_name_does_not_trigger() -> None:
    assert not check_file_write_delete(ToolInfo("read_file", "", {}))


def test_tool_name_alone_does_not_trigger() -> None:
    assert not check_file_write_delete(ToolInfo("delete_file", "", {}))


def test_non_file_operation_description_does_not_trigger() -> None:
    assert not check_file_write_delete(
        ToolInfo("remove_badge", "Remove a badge from in-memory session state.", {})
    )


def test_path_format_parameter_qualifies() -> None:
    tool = ToolInfo(
        "move_item",
        "",
        {"properties": {"destination": {"type": "string", "format": "path"}}},
    )
    assert check_file_write_delete(tool)
