# mcp-audit

## 1. What it is

mcp-audit is a local command-line tool that launches an MCP server, enumerates its tools, and checks tool names, descriptions, and parameter schemas for risk signals. It produces text, JSON, or a self-contained HTML report with evidence and suggested fixes.

```sh
pip install -e .
mcp-audit scan "python testbed/vuln_shell.py"
mcp-audit scan --html report.html "python testbed/vuln_shell.py"
```

Open `report.html` to view the HTML report.

## 2. What it checks

| ID | Name | What it flags |
|---|---|---|
| CAP-001 | Shell command execution | Tool names or parameters that indicate shell command execution |
| CAP-002 | File write/delete capability | File-modification tool names combined with file or path context |
| CAP-003 | Unrestricted path parameter | String path parameters without a pattern, enum, or maximum length |
| CAP-004 | Unrestricted URL parameter | String URL, URI, endpoint, or host parameters without a pattern or enum |
| CAP-005 | Network access | Tool names associated with fetching, downloading, HTTP, requests, webhooks, or email |
| POI-001 | Instruction override in description | Description text that asks an agent to ignore instructions or hide actions |
| POI-002 | Invisible or bidi characters in description | Zero-width or bidirectional control characters |
| POI-003 | URL in description | HTTP URLs in descriptions, with stronger severity near upload or exfiltration wording |
| POI-004 | Hidden AI directive or sensitive target | Hidden AI tags or references to sensitive credential paths |
| POI-005 | Abnormally long description | Descriptions longer than 1000 characters |

## 3. Scoring

- **PASS:** score below 10
- **REVIEW:** score from 10 to 49
- **FAIL:** score 50 or higher

The first finding for a rule contributes its full confidence-adjusted severity weight. Later findings for the same rule contribute only 25% of that weight each, with each rule capped at twice its rule weight. The final score is capped at 100.

## 4. Real-world scan

[docs/findings.md](docs/findings.md) records 30 public servers scanned: 14 enumerated and 16 failed. The 16 failures fall into these categories: network (4; the sandbox could not reach PyPI, not a server fault), credentials (2), platform (1), launch command (3), CLI not MCP (3), sandbox policy (1), and unclassified (2).

A manual review checked 18 HIGH findings. It found 0 true positives and 18 false positives; the rules were tightened afterwards. The result is 0 HIGH+ findings on the 14 enumerated servers. These reports describe findings that were **flagged by heuristic**, not confirmed exploitation or security properties.

## 5. Evaluation

[docs/evaluation.md](docs/evaluation.md) reports:

- Core: 4/4 detected categories
- Adversarial v0: 0.500 precision / 0.167 recall
- Adversarial v1: 1.000 precision / 0.833 recall
- Reworded set: 2/2
- The regression set is not held-out

v1 fixes were made after seeing v0 failures, and v2 rules were tightened after the public scan, so these are not held-out results.

Known miss: `adversarial/paraphrased_override.py` requires an LLM for reliable paraphrase detection.

## 6. Limitations

- Results come from heuristics, not proof of exploitability.
- Only 14 of 30 public targets were enumerated.
- 25 of 30 targets came from the `ai.*` registry namespace, which introduces selection bias.
- MEDIUM findings have not been manually triaged.
- The filesystem server enforces its allowlist server-side, so CAP-003 hits are expected.

## 7. Responsible use

Scanning launches the target, so run unknown servers only in a throwaway sandbox. See [docs/SANDBOX.md](docs/SANDBOX.md). Reports are heuristic signals; disclose real findings privately to maintainers.
