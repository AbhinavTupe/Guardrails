# Testbed Evaluation

## Core

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 1 | 0 | 0 | 1.000 | 1.000 |
| poisoned_description | 1 | 0 | 0 | 1.000 | 1.000 |
| shell_exec | 1 | 0 | 0 | 1.000 | 1.000 |
| unrestricted_path | 1 | 0 | 0 | 1.000 | 1.000 |
| **Overall** | **4** | **0** | **0** | **1.000** | **1.000** |

## Adversarial v0 (before fixes)

Static snapshot (0.500 / 0.167).

## Adversarial v1 snapshot

Static snapshot (1.000 / 0.833).
Reworded set: 2/2.

## Current rules (v2)

## Old adversarial set

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 0 | 0 | 0 | n/a | n/a |
| poisoned_description | 3 | 0 | 1 | 1.000 | 0.750 |
| shell_exec | 1 | 0 | 0 | 1.000 | 1.000 |
| unrestricted_path | 1 | 0 | 0 | 1.000 | 1.000 |
| **Overall** | **5** | **0** | **1** | **1.000** | **0.833** |

#### Old adversarial set per-case outcomes

| Case | Ground truth | Detected | Result |
|---|---|---|---|
| `adversarial/base64_instruction.py` | poisoned_description | poisoned_description | PASS |
| `adversarial/fetch_traversal.py` | unrestricted_path | unrestricted_path | PASS |
| `adversarial/hidden_parameter.py` | poisoned_description | poisoned_description | PASS |
| `adversarial/homoglyph_ignore.py` | poisoned_description | poisoned_description | PASS |
| `adversarial/legit_long.py` | none | none | PASS |
| `adversarial/legit_url.py` | none | none | PASS |
| `adversarial/paraphrased_override.py` | poisoned_description | none | MISMATCH |
| `adversarial/read_report.py` | none | none | PASS |
| `adversarial/remove_tag.py` | none | none | PASS |
| `adversarial/save_note.py` | none | none | PASS |
| `adversarial/shell_helper.py` | shell_exec | shell_exec | PASS |

## Reworded set

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 0 | 0 | 0 | n/a | n/a |
| poisoned_description | 0 | 0 | 0 | n/a | n/a |
| shell_exec | 1 | 0 | 0 | 1.000 | 1.000 |
| unrestricted_path | 1 | 0 | 0 | 1.000 | 1.000 |
| **Overall** | **2** | **0** | **0** | **1.000** | **1.000** |

#### Reworded set per-case outcomes

| Case | Ground truth | Detected | Result |
|---|---|---|---|
| `adversarial/destination_locator.py` | unrestricted_path | unrestricted_path | PASS |
| `adversarial/move_selection.py` | none | none | PASS |
| `adversarial/parameter_shell_description.py` | shell_exec | shell_exec | PASS |
| `adversarial/unlink_alias.py` | none | none | PASS |

## Regression set

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 0 | 0 | 0 | n/a | n/a |
| poisoned_description | 0 | 0 | 0 | n/a | n/a |
| shell_exec | 0 | 0 | 0 | n/a | n/a |
| unrestricted_path | 0 | 0 | 0 | n/a | n/a |
| **Overall** | **0** | **0** | **0** | **n/a** | **n/a** |

#### Regression set per-case outcomes

| Case | Ground truth | Detected | Result |
|---|---|---|---|
| `cap_eval_name` | none | none | PASS |
| `cap_execute_parameter_description` | none | none | PASS |
| `poi_credentials_disclaimer` | none | none | PASS |
| `poi_credentials_instruction` | none | none | PASS |
| `poi_external_system_field` | none | none | PASS |
| `poi_other_system` | none | none | PASS |

## Version note

The v1 fixes were made after seeing the v0 adversarial cases. The v2 rules (POI-004, CAP-001) were tightened after seeing public-scan false positives. The regression cases are NOT held-out. Reworded-set ground truth was written before evaluation.

## Severity Threshold

Only findings with severity `MEDIUM`, `HIGH`, or `CRITICAL` are counted.

## Method

For each file in `testbed/expected.json`, `testbed/expected_adversarial.json`, `testbed/expected_unseen.json`, and `testbed/expected_regression.json`, mcp-audit launches each server and applies the same static rule path used by the CLI, then runs the CLI probe path with `--probe`. Finding rule IDs are mapped to the existing categories, plus category presence is evaluated per server.

TP means a category is both expected and detected, FP means it is detected but not expected, and FN means it is expected but not detected.

## Known misses and false alarms

- `adversarial/paraphrased_override.py`: missed poisoned_description (no qualifying rule fired; observed rule IDs: none)

## Limitations

- This is a tiny local testbed, not a representative benchmark.
- Results are category-level presence checks and do not measure individual finding accuracy or severity calibration.
- Probes are intentionally bounded and should only be enabled for local servers.

## Future work

- Paraphrase detection is not implemented; reliable detection requires an LLM.
