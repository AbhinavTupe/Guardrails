"""Re-apply static rules to saved public-scan tool metadata."""

import json
from pathlib import Path

from mcp_audit.models import ScanResult, ToolInfo
from mcp_audit.rules import load_all_rules, run_rules
from mcp_audit.scoring import score_findings
from scripts import scan_public


def _read_tools(path: Path, payload: dict[str, object]) -> list[ToolInfo]:
    tools_data = payload.get("tools")
    if not isinstance(tools_data, list):
        raise ValueError(f"{path} contains invalid tools")

    tools: list[ToolInfo] = []
    for tool in tools_data:
        if not isinstance(tool, dict):
            raise ValueError(f"{path} contains an invalid tool entry")
        name = tool.get("name")
        description = tool.get("description", "")
        input_schema = tool.get("input_schema", {})
        if not isinstance(name, str) or not isinstance(description, str):
            raise ValueError(f"{path} contains an invalid tool name or description")
        if not isinstance(input_schema, dict):
            raise ValueError(f"{path} contains an invalid tool input schema")
        tools.append(ToolInfo(name, description, input_schema))
    return tools


def rescan_saved(findings_dir: Path, report_path: Path) -> dict[str, int]:
    """Re-score saved reports from tool metadata without starting any server."""
    load_all_rules()
    for path in sorted(findings_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} must contain a JSON object")
        if "error" in payload:
            continue

        tools = _read_tools(path, payload)
        findings = run_rules(tools)
        result = ScanResult(
            server_command=str(payload.get("server_command", "")),
            tools=tools,
            findings=findings,
            score=score_findings(findings),
        )
        serialized = result.to_dict()
        for key in ("findings", "score", "verdict", "severity_counts", "explanations"):
            payload[key] = serialized[key]
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    results = scan_public.load_saved_results()
    report_path.write_text(scan_public.build_findings_markdown(results), encoding="utf-8")
    return {
        item.name: sum(
            finding.severity.name in {"HIGH", "CRITICAL"}
            for finding in item.result.findings
        )
        for item in results
        if item.result is not None
    }


def main() -> int:
    counts = rescan_saved(scan_public.FINDINGS_DIR, scan_public.REPORT_PATH)
    for server, count in sorted(counts.items()):
        print(f"{server}: {count} HIGH+")
    print(f"Regenerated {scan_public.REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
