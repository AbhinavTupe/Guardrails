from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_audit.cli import run_scan
from mcp_audit.connector import ConnectorError
from mcp_audit.models import ScanResult

ROOT = Path(__file__).resolve().parents[1]
TARGETS_PATH = ROOT / "docs" / "targets.json"
FINDINGS_DIR = ROOT / "docs" / "findings"
REPORT_PATH = ROOT / "docs" / "findings.md"
TARGET_TIMEOUT_SECONDS = 60.0
WARNING = (
    "WARNING: This launches third-party code. Run only in a sandbox; "
    "scanned servers must be trusted and no probes are enabled."
)


@dataclass(frozen=True)
class TargetResult:
    name: str
    result: ScanResult | None = None
    error: str | None = None
    timed_out: bool = False


def scrub_text(text: str) -> str:
    scrubbed = text
    replacements = [
        str(ROOT),
        str(ROOT).replace("\\", "/"),
        str(Path.home()),
        str(Path.home()).replace("\\", "/"),
        os.getcwd(),
        os.getcwd().replace("\\", "/"),
    ]
    for value in sorted(set(value for value in replacements if value), key=len, reverse=True):
        scrubbed = scrubbed.replace(value, "<workspace>")
    scrubbed = re.sub(
        r"(?i)([A-Za-z]:[\\/](?:Users|Users)[\\/])[^\\/]+",
        r"\1<username>",
        scrubbed,
    )
    username = os.environ.get("USERNAME")
    if username:
        scrubbed = re.sub(re.escape(username), "<username>", scrubbed, flags=re.IGNORECASE)
    return scrubbed


def scrub_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): scrub_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_data(item) for item in value]
    if isinstance(value, str):
        return scrub_text(value)
    return value


def severity_counts(result: ScanResult) -> dict[str, int]:
    counts = result.severity_counts
    return {severity: counts.get(severity, 0) for severity in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    )}


def top_rule_ids(result: ScanResult, limit: int = 3) -> str:
    rule_counts: dict[str, int] = {}
    for finding in result.findings:
        rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
    ordered = sorted(rule_counts, key=lambda rule_id: (-rule_counts[rule_id], rule_id))
    return ", ".join(ordered[:limit]) if ordered else "-"


def build_markdown_table(results: list[TargetResult]) -> str:
    lines = [
        (
            "| Server | Tools found | Score | Verdict | CRITICAL | HIGH | "
            "MEDIUM | LOW | INFO | Top rule IDs |"
        ),
        "|---|---:|---:|---|---:|---:|---:|---:|---:|---|",
    ]
    for item in results:
        if item.result is None:
            status = "timeout" if item.timed_out else "failed"
            lines.append(
                f"| {scrub_text(item.name)} | - | - | {status} | - | - | - | - | - | - |"
            )
            continue
        result = item.result
        counts = severity_counts(result)
        lines.append(
            f"| {scrub_text(item.name)} | {len(result.tools)} | {result.score} | "
            f"{result.verdict} | {counts['CRITICAL']} | {counts['HIGH']} | "
            f"{counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} | "
            f"{top_rule_ids(result)} |"
        )
    return "\n".join(lines)


def build_totals(results: list[TargetResult]) -> tuple[int, int, int, float]:
    scanned = len(results)
    enumerated = sum(item.result is not None for item in results)
    failed = scanned - enumerated
    high_plus = sum(
        item.result is not None
        and any(
            finding.severity.name in {"HIGH", "CRITICAL"}
            for finding in item.result.findings
        )
        for item in results
    )
    percent = (100.0 * high_plus / enumerated) if enumerated else 0.0
    return scanned, enumerated, failed, percent


def build_totals_markdown(results: list[TargetResult]) -> str:
    scanned, enumerated, failed, percent = build_totals(results)
    return (
        "\n\n## Totals\n\n"
        "| Scanned | Enumerated | Failed | % with at least one HIGH+ finding |\n"
        "|---:|---:|---:|---:|\n"
        f"| {scanned} | {enumerated} | {failed} | {percent:.1f}% |"
    )


def build_findings_markdown(results: list[TargetResult]) -> str:
    table = build_markdown_table(results)
    totals = build_totals_markdown(results)
    return f"# Public Target Findings\n\n{table}{totals}\n"


def scan_target(target: dict[str, object]) -> TargetResult:
    name = str(target["name"])
    command = str(target["command"])
    if command.startswith("python "):
        command = shlex.join([sys.executable, *shlex.split(command)[1:]])
    try:
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_scan, command, False)
        try:
            result = future.result(timeout=TARGET_TIMEOUT_SECONDS)
        except FuturesTimeoutError:
            executor.shutdown(wait=False, cancel_futures=True)
            return TargetResult(name=name, timed_out=True, error="Timed out after 60 seconds")
        executor.shutdown(wait=True)
        return TargetResult(name=name, result=result)
    except ConnectorError as exc:
        return TargetResult(name=name, error=scrub_text(str(exc)))
    except TimeoutError:
        return TargetResult(name=name, timed_out=True, error="Timed out after 60 seconds")
    except Exception as exc:
        return TargetResult(name=name, error=scrub_text(str(exc)))


def save_outputs(results: list[TargetResult]) -> None:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    for item in results:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", item.name).strip("._") or "target"
        output_path = FINDINGS_DIR / f"{safe_name}.json"
        if item.result is not None:
            payload: dict[str, object] = scrub_data(item.result.to_dict())
        else:
            payload = {
                "name": scrub_text(item.name),
                "error": scrub_text(
                    item.error
                    or ("Timed out after 60 seconds" if item.timed_out else "Unknown error")
                ),
            }
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    REPORT_PATH.write_text(build_findings_markdown(results), encoding="utf-8")


def load_targets(path: Path = TARGETS_PATH) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("docs/targets.json must contain a JSON array")
    targets: list[dict[str, object]] = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Each target must be a JSON object")
        if not all(key in entry for key in ("name", "command", "source_url", "install_note")):
            raise ValueError(
                "Each target requires name, command, source_url, and install_note"
            )
        targets.append(entry)
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch scan MCP audit targets")
    parser.add_argument("--i-understand", action="store_true")
    args = parser.parse_args(argv)
    if not args.i_understand:
        print(WARNING, file=sys.stderr)
        print("Refusing to scan: pass --i-understand.", file=sys.stderr)
        return 2

    targets = load_targets()
    results = [scan_target(target) for target in targets]
    save_outputs(results)
    print(
        f"Scanned {len(results)} targets; "
        f"saved JSON under {FINDINGS_DIR.relative_to(ROOT)} "
        f"and report to {REPORT_PATH.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
