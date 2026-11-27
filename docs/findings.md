# Public Target Findings

| Server | Tools found | Score | Verdict | CRITICAL | HIGH | MEDIUM | LOW | INFO | Rules (count) | Failure category | Failure evidence |
|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|---|
| ai.achromat/mcp-server | 2 | 2 | PASS | 0 | 0 | 0 | 1 | 0 | POI-005 x 1 | - | - |
| ai.achurch/church | 10 | 0 | PASS | 0 | 0 | 0 | 0 | 0 | - | - | - |
| ai.adeu/adeu | 9 | 24 | REVIEW | 0 | 0 | 10 | 3 | 0 | CAP-003 x 10, CAP-005 x 2, POI-005 x 1 | - | - |
| ai.agentutility/mcp-browser-workflow | - | - | failed | - | - | - | - | - | - | requires credentials | Startup requires the X402_PRIVATE_KEY environment variable. |
| ai.agentutility/mcp-mediakit | - | - | failed | - | - | - | - | - | - | requires credentials | Startup requires the X402_PRIVATE_KEY environment variable. |
| ai.ankimcp/anki-mcp-server | - | - | failed | - | - | - | - | - | - | launch command incomplete | The CLI requires an mcp/stdio argument that is absent from the launch command. |
| ai.anyforge/anyforge | 285 | 45 | REVIEW | 0 | 0 | 27 | 29 | 0 | CAP-003 x 25, POI-005 x 18, CAP-005 x 8, POI-003 x 3, CAP-002 x 2 | - | - |
| ai.aquex/reasonbook | 15 | 26 | REVIEW | 0 | 0 | 7 | 0 | 0 | CAP-003 x 6, CAP-004 x 1 | - | - |
| ai.aquex/stage1 | - | - | failed | - | - | - | - | - | - | CLI printed help, not MCP | The launched CLI printed help instead of starting an MCP server. |
| ai.autonomad/travel | 12 | 4 | PASS | 0 | 0 | 0 | 5 | 0 | POI-005 x 4, CAP-005 x 1 | - | - |
| ai.cappz/cappz-market | - | - | failed | - | - | - | - | - | - | CLI printed help, not MCP | The launched CLI printed help instead of starting an MCP server. |
| ai.casama/casama | 25 | 23 | REVIEW | 0 | 0 | 4 | 1 | 0 | CAP-003 x 2, CAP-004 x 2, POI-003 x 1 | - | - |
| ai.certscore/mcp | 14 | 13 | REVIEW | 0 | 0 | 1 | 3 | 0 | POI-005 x 2, CAP-004 x 1, POI-003 x 1 | - | - |
| ai.chronary/mcp | 1 | 3 | PASS | 0 | 0 | 0 | 1 | 0 | POI-003 x 1 | - | - |
| ai.counterparts/memory | - | - | failed | - | - | - | - | - | - | unclassified | The saved scan error is: MCP server launch or protocol error: unhandled errors in a TaskGroup (1 sub-exception). |
| ai.glassflow/tares | - | - | failed | - | - | - | - | - | - | network error | uv could not reach PyPI while resolving the package. |
| ai.haymon/dbmcp | - | - | failed | - | - | - | - | - | - | incompatible platform | The package requires glibc, which is unavailable on the target platform. |
| ai.huddo/huddo | - | - | failed | - | - | - | - | - | - | launch command incomplete | The CLI requires an mcp/stdio argument that is absent from the launch command. |
| ai.hypaware/hypaware | - | - | failed | - | - | - | - | - | - | CLI printed help, not MCP | The launched CLI printed help instead of starting an MCP server. |
| ai.imboard/dossier | 10 | 16 | REVIEW | 0 | 0 | 5 | 0 | 0 | CAP-003 x 5 | - | - |
| ai.kadmo/kadmo-agent | - | - | failed | - | - | - | - | - | - | launch command incomplete | The CLI requires an mcp/stdio argument that is absent from the launch command. |
| ai.kawacode/mcp | 20 | 24 | REVIEW | 0 | 0 | 43 | 7 | 0 | CAP-003 x 43, POI-005 x 7 | - | - |
| ai.keepstate/ks | - | - | failed | - | - | - | - | - | - | blocked by sandbox policy | The package install script was blocked by sandbox policy. |
| ai.memcell/memcell | - | - | failed | - | - | - | - | - | - | unclassified | The saved scan error is: MCP server launch or protocol error: unhandled errors in a TaskGroup (1 sub-exception). |
| ai.mroffice/office | 11 | 8 | PASS | 0 | 0 | 1 | 0 | 0 | CAP-004 x 1 | - | - |
| fetch | - | - | failed | - | - | - | - | - | - | network error | uv could not reach PyPI while resolving the package. |
| filesystem | 16 | 30 | REVIEW | 0 | 0 | 19 | 0 | 0 | CAP-003 x 17, CAP-002 x 2 | - | - |
| git | - | - | failed | - | - | - | - | - | - | network error | uv could not reach PyPI while resolving the package. |
| memory | 9 | 0 | PASS | 0 | 0 | 0 | 0 | 0 | - | - | - |
| time | - | - | failed | - | - | - | - | - | - | network error | uv could not reach PyPI while resolving the package. |

## Totals

| Scanned | Enumerated | Failed | % with HIGH+ (enumerated servers denominator) |
|---:|---:|---:|---:|
| 30 | 14 | 16 | 0.0% |

### Failure breakdown

| Category | Servers |
|---|---:|
| network error | 4 |
| requires credentials | 2 |
| incompatible platform | 1 |
| blocked by sandbox policy | 1 |
| launch command incomplete | 3 |
| CLI printed help, not MCP | 3 |
| unclassified | 2 |
