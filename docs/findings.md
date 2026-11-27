# Public Target Findings

| Server | Tools found | Score | Verdict | CRITICAL | HIGH | MEDIUM | LOW | INFO | Rules (count) | Failure reason |
|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|
| ai.achromat/mcp-server | 2 | 23 | REVIEW | 0 | 1 | 0 | 1 | 0 | POI-004 x 1, POI-005 x 1 | - |
| ai.achurch/church | 10 | 0 | PASS | 0 | 0 | 0 | 0 | 0 | - | - |
| ai.adeu/adeu | 9 | 24 | REVIEW | 0 | 0 | 10 | 3 | 0 | CAP-003 x 10, CAP-005 x 2, POI-005 x 1 | - |
| ai.agentutility/mcp-browser-workflow | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.agentutility/mcp-mediakit | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.ankimcp/anki-mcp-server | - | - | timeout | - | - | - | - | - | - | timeout |
| ai.anyforge/anyforge | 285 | 100 | FAIL | 0 | 16 | 27 | 29 | 0 | CAP-003 x 25, POI-005 x 18, CAP-001 x 8, CAP-005 x 8, POI-004 x 8, POI-003 x 3, CAP-002 x 2 | - |
| ai.aquex/reasonbook | 15 | 47 | REVIEW | 0 | 1 | 7 | 0 | 0 | CAP-003 x 6, CAP-004 x 1, POI-004 x 1 | - |
| ai.aquex/stage1 | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.autonomad/travel | 12 | 4 | PASS | 0 | 0 | 0 | 5 | 0 | POI-005 x 4, CAP-005 x 1 | - |
| ai.cappz/cappz-market | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.casama/casama | 25 | 23 | REVIEW | 0 | 0 | 4 | 1 | 0 | CAP-003 x 2, CAP-004 x 2, POI-003 x 1 | - |
| ai.certscore/mcp | 14 | 13 | REVIEW | 0 | 0 | 1 | 3 | 0 | POI-005 x 2, CAP-004 x 1, POI-003 x 1 | - |
| ai.chronary/mcp | 1 | 3 | PASS | 0 | 0 | 0 | 1 | 0 | POI-003 x 1 | - |
| ai.counterparts/memory | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.glassflow/tares | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.haymon/dbmcp | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.huddo/huddo | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.hypaware/hypaware | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.imboard/dossier | 10 | 16 | REVIEW | 0 | 0 | 5 | 0 | 0 | CAP-003 x 5 | - |
| ai.kadmo/kadmo-agent | - | - | timeout | - | - | - | - | - | - | timeout |
| ai.kawacode/mcp | 20 | 24 | REVIEW | 0 | 0 | 43 | 7 | 0 | CAP-003 x 43, POI-005 x 7 | - |
| ai.keepstate/ks | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.memcell/memcell | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| ai.mroffice/office | 11 | 8 | PASS | 0 | 0 | 1 | 0 | 0 | CAP-004 x 1 | - |
| fetch | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| filesystem | 16 | 30 | REVIEW | 0 | 0 | 19 | 0 | 0 | CAP-003 x 17, CAP-002 x 2 | - |
| git | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| memory | 9 | 0 | PASS | 0 | 0 | 0 | 0 | 0 | - | - |
| time | - | - | failed | - | - | - | - | - | - | not an MCP server (protocol error) |
| vuln_files | 2 | 18 | REVIEW | 0 | 0 | 3 | 0 | 0 | CAP-003 x 2, CAP-002 x 1 | - |
| vuln_poisoned | 1 | 100 | FAIL | 0 | 6 | 0 | 0 | 0 | POI-001 x 2, POI-004 x 2, POI-002 x 1, POI-003 x 1 | - |
| vuln_shell | 1 | 22 | REVIEW | 0 | 1 | 0 | 0 | 0 | CAP-001 x 1 | - |

## Totals

| Scanned | Enumerated | Failed | % with HIGH+ (enumerated servers denominator) |
|---:|---:|---:|---:|
| 33 | 17 | 16 | 29.4% |

### Failure reasons

| Category | Servers |
|---|---:|
| timeout | 2 |
| not an MCP server (protocol error) | 14 |
| launch error | 0 |
| blocked by sandbox policy | 0 |
| network error | 0 |
