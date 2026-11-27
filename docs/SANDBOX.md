# Sandboxed public scans
Open this repository in a GitHub Codespace. Never run public scans on a personal machine.

From the repository root in the Codespace terminal, run:

```sh
mkdir sandbox-empty && python scripts/scan_public.py --i-understand
```

This launches the pinned third-party MCP servers; probes are disabled.
Review the generated `docs/findings.md` and target reports in
`docs/findings/*.json`, then commit them. Testbed reports are kept separately
under `docs/findings/testbed/` and are excluded from the public report:

```sh
git add docs/findings* && git commit -m "Update public scan findings"
```

To re-scan selected target names, pass a comma-separated `--only` list. The report
is rebuilt only from top-level JSON files whose names match entries in
`docs/targets.json`, preserving findings for targets not included in that run.
Failure categories and their evidence can be documented in
`docs/failure_notes.json`:

```sh
python scripts/scan_public.py --i-understand --only name1,name2
```
