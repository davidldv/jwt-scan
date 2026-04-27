import chalk from "chalk";
import type { ScanReport, Severity } from "../types.js";

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  info: chalk.gray,
  low: chalk.blue,
  medium: chalk.yellow,
  high: chalk.hex("#ff8800"),
  critical: chalk.red.bold,
};

export function renderTerminal(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(chalk.bold(`\njwt-scan report — ${report.scannedAt}`));
  lines.push(chalk.dim(`target: ${report.target.type} → ${truncate(report.target.value, 80)}`));
  lines.push("");

  if (report.findings.length === 0) {
    lines.push(chalk.green("✓ no findings"));
    return lines.join("\n");
  }

  for (const f of report.findings) {
    const tag = SEV_COLOR[f.severity](`[${f.severity.toUpperCase()}]`);
    lines.push(`${tag} ${chalk.bold(f.title)} ${chalk.dim(`(${f.id})`)}`);
    lines.push(`  ${f.description}`);
    if (f.evidence) {
      lines.push(chalk.dim("  evidence:"));
      for (const ln of f.evidence.split("\n")) lines.push(chalk.dim(`    ${truncate(ln, 200)}`));
    }
    lines.push(chalk.cyan(`  fix: ${f.remediation}`));
    lines.push("");
  }

  const counts = report.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  lines.push(
    chalk.bold("summary: ") +
      Object.entries(counts)
        .map(([k, v]) => SEV_COLOR[k as Severity](`${v} ${k}`))
        .join("  "),
  );
  return lines.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
