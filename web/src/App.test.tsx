import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";
import type { ScanResult } from "./types";

const baseResult: ScanResult = {
  server_command: "test-server",
  tools: [
    {
      name: "unsafe",
      description: "<script>alert(1)</script>",
      input_schema: { type: "object" },
    },
  ],
  findings: [
    {
      rule_id: "CAP-001",
      severity: "HIGH",
      confidence: 0.9,
      tool_name: "unsafe",
      evidence: "shell parameter",
      fix: "Remove shell access",
    },
  ],
  explanations: [],
  score: 25,
  verdict: "REVIEW",
  severity_counts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0 },
};

describe("App", () => {
  it("renders tool descriptions as text without creating script elements", () => {
    const { container } = render(<App initialData={baseResult} />);
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).not.toBeInTheDocument();
  });

  it("filters findings by severity", () => {
    const result: ScanResult = {
      ...baseResult,
      findings: [
        ...baseResult.findings,
        {
          rule_id: "POI-001",
          severity: "LOW",
          confidence: 0.8,
          tool_name: "unsafe",
          evidence: "low evidence",
          fix: "low fix",
        },
      ],
      severity_counts: { INFO: 0, LOW: 1, MEDIUM: 0, HIGH: 1, CRITICAL: 0 },
    };
    render(<App initialData={result} />);
    const lowButton = screen.getByRole("button", { name: /LOW 1/ });
    fireEvent.click(lowButton);
    expect(lowButton).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("POI-001")).toBeInTheDocument();
    return waitFor(() => {
      expect(screen.queryByText("CAP-001")).not.toBeInTheDocument();
    });
  });

  it("renders a clear empty state", () => {
    const result: ScanResult = {
      ...baseResult,
      findings: [],
      score: 0,
      verdict: "PASS",
      severity_counts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    };
    render(<App initialData={result} />);
    expect(screen.getByText("No findings")).toBeInTheDocument();
  });
});
