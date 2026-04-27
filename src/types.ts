export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  evidence?: string;
  remediation: string;
}

export interface DecodedJwt {
  raw: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  headerB64: string;
  payloadB64: string;
}

export interface ScanContext {
  token?: DecodedJwt;
  target?: HttpTarget;
  wordlist?: string[];
  publicKey?: string;
}

export interface HttpTarget {
  url: string;
  method: "GET" | "POST" | "PUT" | "DELETE";
  headerName: string;
  headerPrefix: string;
  body?: string;
  contentType?: string;
}

export interface Check {
  id: string;
  title: string;
  applies: (ctx: ScanContext) => boolean;
  run: (ctx: ScanContext) => Promise<Finding[]>;
}

export interface ScanReport {
  scannedAt: string;
  target: { type: "token" | "http"; value: string };
  findings: Finding[];
}
