# Public Target Findings

| Server | Tools found | Score | Verdict | CRITICAL | HIGH | MEDIUM | LOW | INFO | Rules (count) | Failure reason |
|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|
| vuln_files | 2 | 18 | REVIEW | 0 | 0 | 3 | 0 | 0 | CAP-003 x 2, CAP-002 x 1 | - |
| vuln_poisoned | 1 | 100 | FAIL | 0 | 6 | 0 | 0 | 0 | POI-001 x 2, POI-004 x 2, POI-002 x 1, POI-003 x 1 | - |
| vuln_shell | 1 | 22 | REVIEW | 0 | 1 | 0 | 0 | 0 | CAP-001 x 1 | - |

## Totals

| Scanned | Enumerated | Failed | % with HIGH+ (enumerated servers denominator) |
|---:|---:|---:|---:|
| 3 | 3 | 0 | 66.7% |

### Failure reasons

| Category | Servers |
|---|---:|
| timeout | 0 |
| not an MCP server (protocol error) | 0 |
| launch error | 0 |
| blocked by sandbox policy | 0 |
| network error | 0 |
