from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.cap_005_network_access import check_network_access


def test_fetch_name_matches() -> None:
    findings = check_network_access(ToolInfo("fetch_data", "", {}))
    assert findings and findings[0].severity == Severity.LOW
    assert "fetch_data" in findings[0].evidence


def test_webhook_name_matches_case_insensitively() -> None:
    assert check_network_access(ToolInfo("send_WEBHOOK", "", {}))


def test_description_does_not_trigger() -> None:
    assert not check_network_access(ToolInfo("safe", "Fetch data from the web", {}))


def test_unrelated_name_does_not_trigger() -> None:
    assert not check_network_access(ToolInfo("calculate_total", "", {}))
