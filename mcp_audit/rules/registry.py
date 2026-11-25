"""Registry support for MCP audit rules."""

from collections.abc import Callable
from dataclasses import dataclass

from mcp_audit.models import Finding, ToolInfo

Rule = Callable[[ToolInfo], list[Finding]]

ALLOWED_CATEGORIES = {
    "shell_exec",
    "poisoned_description",
    "unrestricted_path",
    "file_write_delete",
    "unrestricted_url",
    "network_access",
}


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    category: str
    check: Rule


RULES: dict[str, RuleDefinition] = {}
PROBE_CATEGORIES = {
    "PRB-001": "unrestricted_path",
    "PRB-002": "shell_exec",
}
PROBE_TITLES = {
    "PRB-001": "Path traversal probe",
    "PRB-002": "Shell command injection probe",
}


def get_rule_title(rule_id: str) -> str:
    """Return a registered rule title or the title for a probe rule."""
    if rule_id in RULES:
        return RULES[rule_id].title
    return PROBE_TITLES.get(rule_id, rule_id)


def register(rule_id: str, title: str, category: str) -> Callable[[Rule], Rule]:
    """Register a rule function under a unique rule ID."""
    if category not in ALLOWED_CATEGORIES:
        raise ValueError(f"unsupported rule category: {category}")

    def decorator(check: Rule) -> Rule:
        if rule_id in RULES:
            raise ValueError(f"duplicate rule_id: {rule_id}")
        RULES[rule_id] = RuleDefinition(
            rule_id=rule_id,
            title=title,
            category=category,
            check=check,
        )
        return check

    return decorator


def unregister_rule(rule_id: str) -> None:
    """Remove a registered rule, mainly for test isolation."""
    RULES.pop(rule_id, None)


def get_rule_category(rule_id: str) -> str:
    """Return the category for a registered rule ID."""
    if rule_id in RULES:
        return RULES[rule_id].category
    return PROBE_CATEGORIES[rule_id]
