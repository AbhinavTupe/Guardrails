"""Generate a grouped triage report for saved medium-severity findings."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FINDINGS_DIR = ROOT / "docs" / "findings"
REPORT_PATH = ROOT / "docs" / "medium_triage.md"


def _evidence_snippet(evidence: str) -> str:
    normalized = " ".join(evidence.split())
    if len(normalized) > 100:
        return normalized[:97] + "..."
    return normalized


def build_report(findings_dir: Path) -> str:
    grouped: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for path in sorted(findings_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} must contain a JSON object")
        if "error" in payload:
            continue

        server = payload.get("name", path.stem)
        if not isinstance(server, str):
            raise ValueError(f"{path} contains an invalid server name")
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError(f"{path} contains invalid findings")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError(f"{path} contains an invalid finding")
            if finding.get("severity") != "MEDIUM":
                continue
            rule_id = finding.get("rule_id")
            tool_name = finding.get("tool_name")
            evidence = finding.get("evidence")
            if (
                not isinstance(rule_id, str)
                or not isinstance(tool_name, str)
                or not isinstance(evidence, str)
            ):
                raise ValueError(f"{path} contains an invalid medium finding")
            grouped.setdefault(rule_id, {}).setdefault(server, []).append(
                (tool_name, _evidence_snippet(evidence))
            )

    lines = ["# Medium Finding Triage", ""]
    if not grouped:
        lines.extend(["No MEDIUM findings found.", ""])
        return "\n".join(lines)

    for rule_id in sorted(grouped):
        lines.extend([f"## {rule_id}", ""])
        for server in sorted(grouped[rule_id]):
            lines.extend([f"### {server}", ""])
            for tool_name, evidence in sorted(grouped[rule_id][server]):
                lines.append(f"- **{tool_name}** - {evidence}")
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    report = build_report(FINDINGS_DIR)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"Wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
