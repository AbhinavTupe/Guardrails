# mcp-audit

A CLI that scans an MCP server and reports security risks with evidence.

Use `mcp-audit scan --probe <command>` to enable bounded path-traversal and
shell-execution checks. Probes are off by default and should only be used with
servers you trust to run locally.

Reports include curated knowledge-base explanations for findings. JSON output
includes an `explanations` list with the matching pattern and remediation.

Use `mcp-audit scan --html report.html <command>` to write a self-contained
interactive HTML report; this uses the committed web build and does not require
Node.js at runtime.