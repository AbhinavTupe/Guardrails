from mcp_audit.models import Severity, ToolInfo
from mcp_audit.rules.cap_003_unrestricted_path import check_unrestricted_path


def test_unconstrained_string_path_matches() -> None:
    tool = ToolInfo("read_file", "", {"properties": {"path": {"type": "string"}}})
    findings = check_unrestricted_path(tool)
    assert findings and findings[0].severity == Severity.MEDIUM
    assert '"type": "string"' in findings[0].evidence


def test_each_unconstrained_path_parameter_matches() -> None:
    tool = ToolInfo(
        "read",
        "",
        {
            "properties": {
                "file": {"type": "string"},
                "directory": {"type": "string"},
            }
        },
    )
    assert len(check_unrestricted_path(tool)) == 2


def test_constrained_path_does_not_match() -> None:
    tool = ToolInfo(
        "read",
        "",
        {"properties": {"path": {"type": "string", "maxLength": 120}}},
    )
    assert not check_unrestricted_path(tool)


def test_non_string_or_unrelated_parameter_does_not_match() -> None:
    tool = ToolInfo(
        "read",
        "",
        {
            "properties": {
                "path": {"type": "integer"},
                "name": {"type": "string"},
            }
        },
    )
    assert not check_unrestricted_path(tool)


def test_target_parameter_matches() -> None:
    tool = ToolInfo("fetch", "", {"properties": {"target": {"type": "string"}}})
    assert check_unrestricted_path(tool)


def test_path_description_matches_unusual_parameter_name() -> None:
    tool = ToolInfo(
        "fetch",
        "",
        {
            "properties": {
                "locator": {
                    "type": "string",
                    "description": "Path of the resource to inspect.",
                }
            }
        },
    )
    assert check_unrestricted_path(tool)


def test_constrained_description_matched_parameter_does_not_match() -> None:
    tool = ToolInfo(
        "fetch",
        "",
        {
            "properties": {
                "target": {
                    "type": "string",
                    "pattern": r"^[a-z]+$",
                }
            }
        },
    )
    assert not check_unrestricted_path(tool)
