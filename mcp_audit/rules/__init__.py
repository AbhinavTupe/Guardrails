"""Security rules for mcp-audit."""

import importlib
import logging
import pkgutil

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules.registry import RULES, register, unregister_rule
from mcp_audit.rules.registry import get_rule_category as get_rule_category

__all__ = [
    "get_rule_category",
    "load_all_rules",
    "register",
    "run_rules",
    "unregister_rule",
]

LOGGER = logging.getLogger(__name__)


def load_all_rules() -> None:
    """Import every rule module so decorators register their rules."""
    for module_info in pkgutil.iter_modules(__path__, f"{__name__}."):
        if module_info.name != f"{__name__}.registry":
            importlib.import_module(module_info.name)


def run_rules(tools: list[ToolInfo]) -> list[Finding]:
    """Run all registered rules for all tools and return sorted findings."""
    findings: list[Finding] = []
    for definition in RULES.values():
        for tool in tools:
            try:
                findings.extend(definition.check(tool))
            except Exception as exc:
                LOGGER.warning(
                    "Rule %s failed for tool %s: %s",
                    definition.rule_id,
                    tool.name,
                    exc,
                )

    severity_rank = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    return sorted(
        findings,
        key=lambda finding: (
            -severity_rank[finding.severity],
            finding.tool_name,
            finding.rule_id,
        ),
    )
