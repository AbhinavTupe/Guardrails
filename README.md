# mcp-audit

mcp-audit is a local CLI that enumerates an MCP server and reports security risks
with rule evidence and remediation guidance. It supports static tool-schema and
description checks plus optional bounded runtime probes.

## Install

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync
uv run mcp-audit --help
```

## Usage

Scan a server launched by a command:

```bash
uv run mcp-audit scan "python testbed/vuln_shell.py"
```

Output a JSON report:

```bash
uv run mcp-audit scan --json "python testbed/vuln_shell.py"
```

Write a self-contained HTML report:

```bash
uv run mcp-audit scan --html report.html "python testbed/vuln_shell.py"
```

Enable bounded path-traversal and shell-execution probes only for a server you
trust and run locally:

```bash
uv run mcp-audit scan --probe "python testbed/vuln_shell.py"
```

Exit unsuccessfully when findings meet a severity threshold:

```bash
uv run mcp-audit scan --fail-on medium "python testbed/vuln_shell.py"
```

Valid `--fail-on` values are `info`, `low`, `medium`, `high`, and `critical`.

## Architecture

```text
CLI
 |
 v
Connector ---> enumerate tools/resources/prompts
 |
 v
Static rules ---> Finding list
 |
 v
Optional probes ---> additional Finding list
 |
 v
Scoring + knowledge base --> text / JSON / HTML report
```

The modules are independent: the connector launches and enumerates a server,
rule modules classify MCP tools, probes perform bounded test calls, scoring
summarizes findings, and the report layer renders output.

See a committed [sample HTML report](docs/sample-report.html).

## Evaluation

The local testbed evaluation covers static findings followed by the optional
probe path. See [the evaluation report](docs/evaluation.md) for category TP,
FP, FN, precision, and recall. The current result is 4 TP, 0 FP, 0 FN,
with 1.000 precision and 1.000 recall.

## Public-scan summary

The latest public-target report scanned 3 targets, successfully enumerated 3,
and found at least one HIGH-or-higher finding on 66.7% of them. Full tables and
tool findings are available in [Public Target Findings](docs/findings.md).

## Limitations

The testbed is tiny and the rules and labels were created by the same author.
Static checks can produce false positives and probes cover only selected path
and command behaviors. Reports are risk signals, not proof of exploitability or
a complete security certification.

## Responsible use

Only scan systems and MCP servers you are authorized to run. Use probes only
locally and on servers you trust. The probes use a temporary sandbox and do not
run against real user files or secrets. The vulnerable test servers in
`testbed/` must not be exposed to a network or used with real credentials.