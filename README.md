# mcp-audit

A CLI that scans an MCP server and reports security risks with evidence.

Use `mcp-audit scan --probe <command>` to enable bounded path-traversal and
shell-execution checks. Probes are off by default and should only be used with
servers you trust to run locally.