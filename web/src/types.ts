export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ToolInfo {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface Finding {
  rule_id: string;
  severity: Severity;
  confidence: number;
  tool_name: string;
  evidence: string;
  fix: string;
}

export interface Explanation {
  rule_id: string;
  tool_name: string;
  pattern_id: string;
  title: string;
  why_it_matters: string;
  remediation: string;
}

export interface ScanResult {
  server_command: string;
  tools: ToolInfo[];
  findings: Finding[];
  score: number;
  explanations: Explanation[];
  verdict: "PASS" | "REVIEW" | "FAIL";
  severity_counts: Record<Severity, number>;
}
