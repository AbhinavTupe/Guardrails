import { useMemo, useState, type DragEvent } from "react";
import type { Finding, ScanResult, Severity } from "./types";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function readEmbeddedData(): ScanResult | null {
  const element = document.getElementById("scan-data");
  if (!element) return null;
  try {
    return JSON.parse(element.textContent ?? "") as ScanResult;
  } catch {
    return null;
  }
}

function explanationFor(finding: Finding, result: ScanResult) {
  return result.explanations.find(
    (item) => item.rule_id === finding.rule_id && item.tool_name === finding.tool_name,
  );
}

interface AppProps {
  initialData?: ScanResult | null;
}

export default function App({ initialData }: AppProps) {
  const [result, setResult] = useState<ScanResult | null>(
    initialData === undefined ? readEmbeddedData() : initialData,
  );
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [search, setSearch] = useState("");
  const [dragging, setDragging] = useState(false);
  const [loadError, setLoadError] = useState("");

  const filteredFindings = useMemo(() => {
    if (!result) return [];
    const needle = search.trim().toLowerCase();
    return result.findings.filter((finding) => {
      if (severity !== "ALL" && finding.severity !== severity) return false;
      if (!needle) return true;
      const explanation = explanationFor(finding, result);
      return [
        finding.rule_id,
        finding.tool_name,
        finding.evidence,
        finding.fix,
        explanation?.title,
        explanation?.why_it_matters,
      ].some((value) => value?.toLowerCase().includes(needle));
    });
  }, [result, severity, search]);

  async function loadFile(file: File) {
    setLoadError("");
    try {
      const parsed = JSON.parse(await file.text()) as ScanResult;
      setResult(parsed);
      setSeverity("ALL");
      setSearch("");
    } catch {
      setLoadError("Could not read that file as scan JSON.");
    }
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) void loadFile(file);
  }

  if (!result) {
    return (
      <main className="upload-shell">
        <div
          className={dragging ? "dropzone dragging" : "dropzone"}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
        >
          <h1>MCP Audit Report</h1>
          <p>Drop a scan JSON file here</p>
          <label className="file-button">
            Choose JSON file
            <input
              type="file"
              accept="application/json,.json"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void loadFile(file);
              }}
            />
          </label>
          {loadError && <p className="error" role="alert">{loadError}</p>}
        </div>
      </main>
    );
  }

  const grouped = new Map<string, Finding[]>();
  filteredFindings.forEach((finding) => {
    const items = grouped.get(finding.tool_name) ?? [];
    items.push(finding);
    grouped.set(finding.tool_name, items);
  });

  return (
    <main>
      <header className="header">
        <div>
          <p className="eyebrow">MCP Audit Report</p>
          <code className="command">{result.server_command}</code>
        </div>
        <div className="score-row">
          <div className="score" aria-label={`Risk score ${result.score}`}>
            <strong>{result.score}</strong>
            <span>score</span>
          </div>
          <span className={`verdict verdict-${result.verdict.toLowerCase()}`}>
            {result.verdict}
          </span>
        </div>
        <div className="tool-count">
          <strong>{result.tools.length}</strong>
          <span>tools found</span>
        </div>
      </header>

      <section className="controls" aria-label="Finding controls">
        <div className="severity-chips">
          <button
            className={severity === "ALL" ? "chip active" : "chip"}
            onClick={() => setSeverity("ALL")}
            aria-pressed={severity === "ALL"}
          >
            All <b>{result.findings.length}</b>
          </button>
          {SEVERITIES.map((item) => (
            <button
              key={item}
              className={severity === item ? `chip active severity-${item.toLowerCase()}` : `chip severity-${item.toLowerCase()}`}
              onClick={() => setSeverity(item)}
              aria-pressed={severity === item}
            >
              {item} <b>{result.severity_counts[item] ?? 0}</b>
            </button>
          ))}
        </div>
        <label className="search">
          <span className="sr-only">Search findings</span>
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search findings..."
          />
        </label>
      </section>

      <section>
        <h2>Tools found</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Name</th><th>Description</th></tr>
            </thead>
            <tbody>
              {result.tools.map((tool) => (
                <tr key={tool.name}>
                  <td><code>{tool.name}</code></td>
                  <td>{tool.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="findings">
        <h2>Findings</h2>
        {filteredFindings.length === 0 ? (
          <div className="empty-state">
            <strong>No findings</strong>
            <span>{result.findings.length === 0 ? "This scan found no security issues." : "No findings match the current filters."}</span>
          </div>
        ) : (
          Array.from(grouped.entries()).map(([toolName, findings]) => (
            <article className="tool-group" key={toolName}>
              <h3>Tool: <code>{toolName}</code></h3>
              {findings.map((finding, index) => {
                const explanation = explanationFor(finding, result);
                return (
                  <details className="finding" key={`${finding.rule_id}-${finding.evidence}-${index}`}>
                    <summary>
                      <span className={`severity-badge badge-${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                      <span className="finding-id">{finding.rule_id}</span>
                      {explanation && <span className="finding-title">{explanation.title}</span>}
                      {finding.rule_id.startsWith("PRB-") && (
                        <span className="probe-badge">Confirmed by probe</span>
                      )}
                    </summary>
                    <div className="finding-body">
                      <section>
                        <h4>Evidence</h4>
                        <pre>{finding.evidence}</pre>
                      </section>
                      <section>
                        <h4>Fix</h4>
                        <p>{finding.fix}</p>
                      </section>
                      {explanation && (
                        <section>
                          <h4>Why it matters</h4>
                          <p>{explanation.why_it_matters}</p>
                        </section>
                      )}
                    </div>
                  </details>
                );
              })}
            </article>
          ))
        )}
      </section>
    </main>
  );
}
