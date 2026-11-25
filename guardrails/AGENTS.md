# mcp-audit: rules for AI coding agents

Project: CLI that scans an MCP server and reports security risks with evidence.

## Tech
- Python 3.11+, uv, official `mcp` SDK, typer (CLI), pytest, ruff, mypy
- Full type hints. No new dependency without asking.

## Design rules
- One rule = one file in mcp_audit/rules/, a pure function: tool -> list[Finding]
- Finding fields: rule_id, severity, confidence, tool_name, evidence, fix
- NEVER emit a finding without concrete evidence (exact text or schema field).
- Modules stay independent: connector, rules, probes, scoring, report.

## Safety rules
- Probes are OFF by default; run only with --probe, only on local servers.
- Never execute anything from a scanned server beyond launching it as the user specified.
- Probes use temp sandbox files only; never read or send real real user files or secrets.

## Quality rules
- Every rule has tests: at least 2 positive and 2 negative cases.
- One task = one small commit. Run ruff, mypy, pytest before finishing.
- Do not change the Finding schema without updating tests and docs.
- If something is unclear, ask instead of guessing.
