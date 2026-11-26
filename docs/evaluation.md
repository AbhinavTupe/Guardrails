# Testbed Evaluation

## Core Testbed

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 1 | 0 | 0 | 1.000 | 1.000 |
| poisoned_description | 1 | 0 | 0 | 1.000 | 1.000 |
| shell_exec | 1 | 0 | 0 | 1.000 | 1.000 |
| unrestricted_path | 1 | 0 | 0 | 1.000 | 1.000 |
| **Overall** | **4** | **0** | **0** | **1.000** | **1.000** |

## Adversarial Testbed — v0 (before fixes)

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 0 | 1 | 0 | 0.000 | 0.000 |
| poisoned_description | 1 | 0 | 3 | 1.000 | 0.250 |
| shell_exec | 0 | 0 | 1 | 0.000 | 0.000 |
| unrestricted_path | 0 | 0 | 1 | 0.000 | 0.000 |
| **Overall** | **1** | **1** | **5** | **0.500** | **0.167** |

## Adversarial Testbed — v1 (old cases)

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 0 | 0 | 0 | 0.000 | 0.000 |
| poisoned_description | 3 | 0 | 1 | 1.000 | 0.750 |
| shell_exec | 1 | 0 | 0 | 1.000 | 1.000 |
| unrestricted_path | 1 | 0 | 0 | 1.000 | 1.000 |
| **Overall** | **5** | **0** | **1** | **1.000** | **0.833** |

## New Unseen Adversarial Testbed — v1

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| file_write_delete | 0 | 0 | 0 | 0.000 | 0.000 |
| poisoned_description | 0 | 0 | 0 | 0.000 | 0.000 |
| shell_exec | 1 | 0 | 0 | 1.000 | 1.000 |
| unrestricted_path | 1 | 0 | 0 | 1.000 | 1.000 |
| **Overall** | **2** | **0** | **0** | **1.000** | **1.000** |

### New unseen case outcomes

| Server | Ground truth | Detected | Result |
|---|---|---|---|
| `adversarial/destination_locator.py` | unrestricted_path | unrestricted_path | PASS |
| `adversarial/move_selection.py` | none | none | PASS |
| `adversarial/parameter_shell_description.py` | shell_exec | shell_exec | PASS |
| `adversarial/unlink_alias.py` | none | none | PASS |

## Version note

The v1 fixes were made after seeing the v0 adversarial cases; v0 is retained as the pre-fix baseline. Unseen-case ground truth was recorded before the new servers were evaluated.

## Severity Threshold

Only findings with severity `MEDIUM`, `HIGH`, or `CRITICAL` are counted.

## Method

For each file in `testbed/expected.json`, `testbed/expected_adversarial.json`, and `testbed/expected_unseen.json`, mcp-audit launches each server and applies the same static rule path used by the CLI, then runs the CLI probe path with `--probe`. Finding rule IDs are mapped to the existing categories, plus category presence is evaluated per server.

TP means a category is both expected and detected, FP means it is detected but not expected, and FN means it is expected but not detected.

## Known misses and false alarms

- `adversarial/paraphrased_override.py`: missed poisoned_description (no qualifying rule fired; observed rule IDs: none)

## Limitations

- This is a tiny local testbed, not a representative benchmark.
- Results are category-level presence checks and do not measure individual finding accuracy or severity calibration.
- Probes are intentionally bounded and should only be enabled for local servers.

## Future work

- Paraphrase detection is not implemented; reliable detection requires an LLM.
