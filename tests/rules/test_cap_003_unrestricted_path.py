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
    tool = ToolInfo(
        "fetch",
        "",
        {
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to the requested item.",
                }
            }
        },
    )
    assert check_unrestricted_path(tool)


def test_target_without_description_matches() -> None:
    tool = ToolInfo("fetch", "", {"properties": {"target": {"type": "string"}}})
    assert check_unrestricted_path(tool)


def test_empty_description_on_synonym_matches() -> None:
    tool = ToolInfo(
        "fetch",
        "",
        {"properties": {"target": {"type": "string", "description": "  "}}},
    )
    assert check_unrestricted_path(tool)


def test_target_completion_date_description_does_not_match() -> None:
    tool = ToolInfo(
        "schedule",
        "",
        {
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target completion date.",
                }
            }
        },
    )
    assert not check_unrestricted_path(tool)


def test_email_to_does_not_match() -> None:
    tool = ToolInfo(
        "send_email",
        "",
        {
            "properties": {
                "to": {
                    "type": "string",
                    "description": "Email address to send the message to.",
                }
            }
        },
    )
    assert not check_unrestricted_path(tool)


def test_path_description_does_not_match_unrelated_parameter_name() -> None:
    tool = ToolInfo(
        "fetch",
        "",
        {
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Path of the resource to inspect.",
                }
            }
        },
    )
    assert not check_unrestricted_path(tool)


def test_path_synonyms_require_a_description_identifying_the_value() -> None:
    for name in ("target", "locator", "destination", "dest", "location", "source", "src"):
        tool = ToolInfo(
            "read",
            "",
            {"properties": {name: {"type": "string", "description": "The value to read."}}},
        )
        assert not check_unrestricted_path(tool), name

    for name in ("target", "locator", "destination", "dest", "location", "source", "src"):
        tool = ToolInfo(
            "read",
            "",
            {
                "properties": {
                    name: {
                        "type": "string",
                        "description": "Path to the requested item.",
                    }
                }
            },
        )
        assert check_unrestricted_path(tool), name


def test_filesystem_location_description_identifies_synonym() -> None:
    tool = ToolInfo(
        "read",
        "",
        {
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The value is a filesystem location.",
                }
            }
        },
    )
    assert check_unrestricted_path(tool)


def test_requested_path_parameter_names_match() -> None:
    for name in (
        "docx_path",
        "output_path",
        "file_path",
        "targetPath",
        "working_directory",
        "workingDirectory",
        "filename",
        "filepath",
        "directory",
        "folder",
        "cwd",
        "root",
        "dir",
        "file",
    ):
        tool = ToolInfo("read", "", {"properties": {name: {"type": "string"}}})
        assert check_unrestricted_path(tool), name


def test_non_path_metadata_names_do_not_match_even_if_description_mentions_path() -> None:
    for name in (
        "targetDate",
        "dueDate",
        "originalCreatedAt",
        "parentId",
        "fileId",
        "snapshotId",
        "codebaseId",
        "idempotencyKey",
        "question",
        "repo",
        "name",
        "content",
    ):
        tool = ToolInfo(
            "metadata",
            "",
            {
                "properties": {
                    name: {
                        "type": "string",
                        "description": "Filesystem path for this metadata value.",
                    }
                }
            },
        )
        assert not check_unrestricted_path(tool), name


def test_metadata_suffixes_and_formats_never_match() -> None:
    for name in (
        "targetDate",
        "due_date",
        "createdAt",
        "updated_at",
        "fileId",
        "file_ids",
        "idempotencyKey",
        "item_count",
    ):
        tool = ToolInfo(
            "read",
            "",
            {"properties": {name: {"type": "string", "description": "Path to the value."}}},
        )
        assert not check_unrestricted_path(tool), name

    for schema_format in ("date", "date-time", "uuid"):
        tool = ToolInfo(
            "read",
            "",
            {"properties": {"file_path": {"type": "string", "format": schema_format}}},
        )
        assert not check_unrestricted_path(tool), schema_format


def test_constrained_description_matched_parameter_does_not_match() -> None:
    tool = ToolInfo(
        "fetch",
        "",
        {
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to a target.",
                    "pattern": r"^[a-z]+$",
                }
            }
        },
    )
    assert not check_unrestricted_path(tool)
