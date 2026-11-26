# Sandboxed public scans
Open this repository in a GitHub Codespace. Never run public scans on a personal machine.

From the repository root in the Codespace terminal, run:

```sh
mkdir sandbox-empty && python scripts/scan_public.py --i-understand
```

This launches the pinned third-party MCP servers; probes are disabled.
Review the generated `docs/findings.md` and `docs/findings/*.json`, then commit them:

```sh
git add docs/findings* && git commit -m "Update public scan findings"
```
