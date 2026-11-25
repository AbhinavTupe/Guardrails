from mcp_audit.models import ToolInfo
from mcp_audit.rules.poi_002_invisible_characters import check_invisible_characters


def test_zero_width_character_description() -> None:
    tool = ToolInfo("zero", "Safe text\u200bwith hidden content", {})
    findings = check_invisible_characters(tool)
    assert findings and "\\u200B" in findings[0].evidence


def test_bidi_character_in_nested_description() -> None:
    tool = ToolInfo(
        "bidi",
        "Safe",
        {"properties": {"arg": {"description": "Normal\u202e text"}}},
    )
    findings = check_invisible_characters(tool)
    assert findings and "\\u202E" in findings[0].evidence


def test_plain_description() -> None:
    assert not check_invisible_characters(ToolInfo("safe", "A normal description.", {}))


def test_regular_unicode_description() -> None:
    assert not check_invisible_characters(ToolInfo("safe", "Add caf\u00e9 notes.", {}))


def test_newline_is_displayed_as_escape() -> None:
    from mcp_audit.rules._poi_common import escape_evidence

    assert escape_evidence("line one\nline two\tend") == "line one\\nline two\\tend"


def test_two_adjacent_zero_width_characters_merge_one_finding() -> None:
    tool = ToolInfo("zero", "Safe\u200b\u200dtext", {})
    findings = check_invisible_characters(tool)
    assert len(findings) == 1
    assert "\\u200B" in findings[0].evidence
