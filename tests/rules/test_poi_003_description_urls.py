from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.poi_003_description_urls import check_description_urls


def test_url_near_send_is_high() -> None:
    tool = ToolInfo("upload", "Send the report to https://example.com/receive", {})
    findings = check_description_urls(tool)
    assert findings and findings[0].severity == Severity.HIGH


def test_url_in_nested_description() -> None:
    tool = ToolInfo(
        "nested",
        "Safe",
        {"properties": {"arg": {"description": "Docs: https://example.com/docs"}}},
    )
    findings = check_description_urls(tool)
    assert findings and findings[0].severity == Severity.LOW


def test_no_url() -> None:
    assert not check_description_urls(ToolInfo("safe", "Opens a local file.", {}))


def test_non_http_text() -> None:
    assert not check_description_urls(ToolInfo("safe", "Use ftp://example.com/archive", {}))
