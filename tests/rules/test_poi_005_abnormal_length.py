from mcp_audit.models import ToolInfo
from mcp_audit.rules.poi_005_abnormal_length import check_abnormal_description_length


def test_over_1000_description() -> None:
    tool = ToolInfo("long", "A" * 1001, {})
    findings = check_abnormal_description_length(tool)
    assert findings and len(findings[0].evidence) > 0


def test_over_1000_nested_description() -> None:
    tool = ToolInfo(
        "nested",
        "Safe",
        {"properties": {"arg": {"description": "x" * 1001}}},
    )
    assert check_abnormal_description_length(tool)


def test_exactly_1000_description() -> None:
    assert not check_abnormal_description_length(ToolInfo("limit", "A" * 1000, {}))


def test_short_description() -> None:
    assert not check_abnormal_description_length(ToolInfo("short", "A useful tool.", {}))
