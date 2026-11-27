from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shlex
import sys
import tempfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_audit.cli import run_scan
from mcp_audit.connector import ConnectorError
from mcp_audit.models import Finding, ScanResult, Severity, ToolInfo
from mcp_audit.scoring import score_findings

ROOT = Path(__file__).resolve().parents[1]
TARGETS_PATH = ROOT / "docs" / "targets.json"
FINDINGS_DIR = ROOT / "docs" / "findings"
REPORT_PATH = ROOT / "docs" / "findings.md"
ENUMERATION_TIMEOUT_SECONDS = 120.0
TARGET_TIMEOUT_SECONDS = 150.0
FAILURE_REASONS = (
    "timeout",
    "not an MCP server (protocol error)",
    "launch error",
    "blocked by sandbox policy",
    "network error",
)
WARNING = (
    "WARNING: This launches third-party code. Run only in a sandbox; "
    "scanned servers must be trusted and no probes are enabled."
)

logging.getLogger("mcp.client.stdio").setLevel(logging.CRITICAL)


def build_minimal_environment(
    source_env: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> dict[str, str]:
    """Build the environment allowed for a public target launch."""
    source = os.environ if source_env is None else source_env
    if home is None:
        home = tempfile.mkdtemp(prefix="mcp-audit-home-")
    home_path = Path(home)
    home_path.mkdir(parents=True, exist_ok=True)

    path = source.get("PATH", "")
    return {
        "PATH": path,
        "HOME": str(home_path),
        "npm_config_ignore_scripts": "true",
        **{
            key: source[key]
            for key in ("UV_NATIVE_TLS", "UV_HTTP_TIMEOUT")
            if key in source
        },
    }


def build_minimal_env(
    source_env: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> dict[str, str]:
    """Backward-compatible shorthand for build_minimal_environment."""
    return build_minimal_environment(source_env, home)


@dataclass(frozen=True)
class TargetResult:
    name: str
    result: ScanResult | None = None
    error: str | None = None
    timed_out: bool = False
    failure_reason: str | None = None


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
    return {
        severity: counts.get(severity, 0)
        for severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        )
    }


def rule_counts(result: ScanResult) -> str:
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    ordered = sorted(counts, key=lambda rule_id: (-counts[rule_id], rule_id))
    return ", ".join(f"{rule_id} x {counts[rule_id]}" for rule_id in ordered) or "-"


def classify_failure_reason(error: str | None, timed_out: bool = False) -> str:
    if timed_out:
        return "timeout"
    message = (error or "").lower()
    if any(token in message for token in ("timed out", "timeout")):
        return "timeout"
    if any(
        token in message
        for token in (
            "operation not permitted",
            "permission denied",
            "access denied",
            "sandbox",
            "blocked by policy",
            "not allowed by policy",
        )
    ):
        return "blocked by sandbox policy"
    if any(
        token in message
        for token in (
            "econnrefused",
            "econnreset",
            "enotfound",
            "eai_again",
            "network is unreachable",
            "connection refused",
            "connection reset",
            "getaddrinfo failed",
            "temporary failure in name resolution",
            "name or service not known",
            "could not resolve",
            "certificate verify failed",
            "ssl error",
        )
    ):
        return "network error"
    if any(
        token in message
        for token in (
            "protocol error",
            "json-rpc",
            "jsonrpc",
            "failed to parse",
            "invalid json",
            "expecting value",
            "connection closed",
        )
    ):
        return "not an MCP server (protocol error)"
    return "launch error"


def get_failure_reason(item: TargetResult) -> str:
    if item.result is not None:
        return "-"
    if item.failure_reason in FAILURE_REASONS:
        return item.failure_reason
    return classify_failure_reason(item.error, item.timed_out)


def build_markdown_table(results: list[TargetResult]) -> str:
    lines = [
        (
            "| Server | Tools found | Score | Verdict | CRITICAL | HIGH | "
            "MEDIUM | LOW | INFO | Rules (count) | Failure reason |"
        ),
        "|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for item in results:
        if item.result is None:
            status = "timeout" if get_failure_reason(item) == "timeout" else "failed"
            lines.append(
                f"| {scrub_text(item.name)} | - | - | {status} | - | - | - | - | - | "
                f"- | {get_failure_reason(item)} |"
            )
            continue
        result = item.result
        counts = severity_counts(result)
        lines.append(
            f"| {scrub_text(item.name)} | {len(result.tools)} | {result.score} | "
            f"{result.verdict} | {counts['CRITICAL']} | {counts['HIGH']} | "
            f"{counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} | "
            f"{rule_counts(result)} | - |"
        )
    return "\n".join(lines)


def build_totals(results: list[TargetResult]) -> tuple[int, int, int, float]:
    scanned = len(results)
    enumerated = sum(item.result is not None for item in results)
    failed = scanned - enumerated
    high_plus = sum(
        item.result is not None
        and any(finding.severity.name in {"HIGH", "CRITICAL"} for finding in item.result.findings)
        for item in results
    )
    percent = (100.0 * high_plus / enumerated) if enumerated else 0.0
    return scanned, enumerated, failed, percent


def build_totals_markdown(results: list[TargetResult]) -> str:
    scanned, enumerated, failed, percent = build_totals(results)
    reason_counts = {reason: 0 for reason in FAILURE_REASONS}
    for item in results:
        if item.result is None:
            reason_counts[get_failure_reason(item)] += 1
    failures = "\n".join(
        f"| {reason} | {reason_counts[reason]} |" for reason in FAILURE_REASONS
    )
    return (
        "\n\n## Totals\n\n"
        "| Scanned | Enumerated | Failed | % with HIGH+ (enumerated servers denominator) |\n"
        "|---:|---:|---:|---:|\n"
        f"| {scanned} | {enumerated} | {failed} | {percent:.1f}% |\n\n"
        "### Failure reasons\n\n"
        "| Category | Servers |\n|---|---:|\n"
        f"{failures}"
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
        with (
            tempfile.TemporaryDirectory(prefix="mcp-audit-public-home-") as home,
            tempfile.TemporaryDirectory(prefix="mcp-audit-public-cwd-") as cwd,
        ):
            env = build_minimal_environment(home=home)
            prepare_relative_directories(command, Path(cwd))
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(
                run_scan,
                command,
                False,
                env=env,
                cwd=cwd,
                enumeration_timeout=ENUMERATION_TIMEOUT_SECONDS,
            )
            try:
                result = future.result(timeout=TARGET_TIMEOUT_SECONDS)
            except FuturesTimeoutError:
                executor.shutdown(wait=False, cancel_futures=True)
                return TargetResult(
                    name=name,
                    timed_out=True,
                    error=f"Timed out after {TARGET_TIMEOUT_SECONDS:g} seconds",
                    failure_reason="timeout",
                )
            except Exception:
                executor.shutdown(wait=True)
                raise
            executor.shutdown(wait=True)
            return TargetResult(name=name, result=result)
    except ConnectorError as exc:
        error = scrub_text(str(exc))
        return TargetResult(
            name=name,
            error=error,
            timed_out=classify_failure_reason(error) == "timeout",
            failure_reason=classify_failure_reason(error),
        )
    except TimeoutError:
        return TargetResult(
            name=name,
            timed_out=True,
            error=f"Timed out after {TARGET_TIMEOUT_SECONDS:g} seconds",
            failure_reason="timeout",
        )
    except Exception as exc:
        error = scrub_text(str(exc))
        return TargetResult(name=name, error=error, failure_reason=classify_failure_reason(error))


def prepare_relative_directories(command: str, cwd: Path) -> None:
    base = cwd.resolve()
    for argument in shlex.split(command)[1:]:
        if not argument.startswith(("./", "../", ".\\", "..\\")):
            continue
        relative_path = Path(argument)
        if relative_path.is_absolute():
            continue
        target_path = (base / relative_path).resolve()
        try:
            target_path.relative_to(base)
        except ValueError:
            continue
        target_path.mkdir(parents=True, exist_ok=True)


def save_outputs(results: list[TargetResult]) -> None:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    for item in results:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", item.name).strip("._") or "target"
        output_path = FINDINGS_DIR / f"{safe_name}.json"
        if item.result is not None:
            payload: dict[str, object] = scrub_data(item.result.to_dict())
            payload["name"] = scrub_text(item.name)
        else:
            payload = {
                "name": scrub_text(item.name),
                "error": scrub_text(
                    item.error
                    or (
                        f"Timed out after {TARGET_TIMEOUT_SECONDS:g} seconds"
                        if item.timed_out
                        else "Unknown error"
                    )
                ),
                "failure_reason": get_failure_reason(item),
            }
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    merged_results = load_saved_results()
    for item in merged_results:
        if item.result is None:
            continue
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", item.name).strip("._") or "target"
        output_path = FINDINGS_DIR / f"{safe_name}.json"
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        payload["score"] = item.result.score
        payload["verdict"] = item.result.verdict
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    REPORT_PATH.write_text(build_findings_markdown(merged_results), encoding="utf-8")


def load_saved_results() -> list[TargetResult]:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    target_names = {
        (
            re.sub(r"[^A-Za-z0-9_.-]+", "_", str(target["name"])).strip("._") or "target"
        ): str(target["name"])
        for target in load_targets()
    }
    results: list[TargetResult] = []
    for path in sorted(FINDINGS_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} must contain a JSON object")
        name = str(payload.get("name", target_names.get(path.stem, path.stem)))
        if "error" in payload:
            error = str(payload["error"])
            timed_out = payload.get("failure_reason") == "timeout"
            results.append(
                TargetResult(
                    name=name,
                    error=error,
                    timed_out=timed_out,
                    failure_reason=str(payload.get("failure_reason", ""))
                    or classify_failure_reason(error, timed_out),
                )
            )
            continue

        tools_data = payload.get("tools", [])
        findings_data = payload.get("findings", [])
        if not isinstance(tools_data, list) or not isinstance(findings_data, list):
            raise ValueError(f"{path} contains invalid tools or findings")
        tools: list[ToolInfo] = []
        for tool in tools_data:
            if not isinstance(tool, dict):
                raise ValueError(f"{path} contains an invalid tool entry")
            input_schema = tool.get("input_schema", {})
            if not isinstance(input_schema, dict):
                raise ValueError(f"{path} contains an invalid tool input schema")
            tools.append(
                ToolInfo(
                    name=str(tool["name"]),
                    description=str(tool.get("description", "")),
                    input_schema=input_schema,
                )
            )
        findings: list[Finding] = []
        for finding in findings_data:
            if not isinstance(finding, dict):
                raise ValueError(f"{path} contains an invalid finding entry")
            findings.append(
                Finding(
                    rule_id=str(finding["rule_id"]),
                    severity=Severity[str(finding["severity"])],
                    confidence=float(finding["confidence"]),
                    tool_name=str(finding["tool_name"]),
                    evidence=str(finding["evidence"]),
                    fix=str(finding["fix"]),
                )
            )
        result = ScanResult(
            server_command=str(payload.get("server_command", "")),
            tools=tools,
            findings=findings,
            score=score_findings(findings),
        )
        results.append(TargetResult(name=name, result=result))
    return results


def load_targets(path: Path = TARGETS_PATH) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("docs/targets.json must contain a JSON array")
    targets: list[dict[str, object]] = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Each target must be a JSON object")
        if not all(key in entry for key in ("name", "command", "source_url", "install_note")):
            raise ValueError("Each target requires name, command, source_url, and install_note")
        targets.append(entry)
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch scan MCP audit targets")
    parser.add_argument("--i-understand", action="store_true")
    parser.add_argument("--only", help="Comma-separated target names to scan")
    args = parser.parse_args(argv)
    if not args.i_understand:
        print(WARNING, file=sys.stderr)
        print("Refusing to scan: pass --i-understand.", file=sys.stderr)
        return 2

    targets = load_targets()
    if args.only is not None:
        requested = [name.strip() for name in args.only.split(",")]
        if not requested or any(not name for name in requested):
            parser.error("--only requires a comma-separated list of target names")
        target_names = {str(target["name"]) for target in targets}
        unknown = sorted(set(requested) - target_names)
        if unknown:
            parser.error(f"--only contains unknown target names: {', '.join(unknown)}")
        requested_names = set(requested)
        targets = [target for target in targets if str(target["name"]) in requested_names]
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
