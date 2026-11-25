from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.cap_004_unrestricted_url import check_unrestricted_url


def test_unconstrained_string_url_matches() -> None:
    tool = ToolInfo("visit", "", {"properties": {"url": {"type": "string"}}})
    findings = check_unrestricted_url(tool)
    assert findings and findings[0].severity == Severity.MEDIUM
    assert '"type": "string"' in findings[0].evidence


def test_each_unrestricted_url_parameter_matches() -> None:
    tool = ToolInfo(
        "request",
        "",
        {
            "properties": {
                "uri": {"type": "string"},
                "endpoint": {"type": "string"},
            }
        },
    )
    assert len(check_unrestricted_url(tool)) == 2


def test_url_with_enum_does_not_match() -> None:
    tool = ToolInfo(
        "visit",
        "",
        {"properties": {"url": {"type": "string", "enum": ["https://example.com"]}}},
    )
    assert not check_unrestricted_url(tool)


def test_non_string_or_unrelated_parameter_does_not_match() -> None:
    tool = ToolInfo(
        "visit",
        "",
        {
            "properties": {
                "url": {"type": "integer"},
                "address": {"type": "string"},
            }
        },
    )
    assert not check_unrestricted_url(tool)
