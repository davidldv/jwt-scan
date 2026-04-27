import type { Check, ScanContext, ScanReport } from "./types.js";
import { algNoneCheck } from "./checks/algNone.js";
import { claimsCheck } from "./checks/claims.js";
import { weakSecretCheck } from "./checks/weakSecret.js";
import { keyConfusionCheck } from "./checks/keyConfusion.js";
import { kidInjectionCheck } from "./checks/kidInjection.js";

export const ALL_CHECKS: Check[] = [
  algNoneCheck,
  claimsCheck,
  weakSecretCheck,
  keyConfusionCheck,
  kidInjectionCheck,
];

export async function scan(ctx: ScanContext): Promise<ScanReport> {
  const findings = [];
  for (const check of ALL_CHECKS) {
    if (!check.applies(ctx)) continue;
    try {
      const result = await check.run(ctx);
      findings.push(...result);
    } catch (err) {
      findings.push({
        id: `${check.id}-error`,
        title: `Check ${check.id} failed`,
        severity: "info" as const,
        description: String(err),
        remediation: "Investigate scanner error; the check did not complete.",
      });
    }
  }
  return {
    scannedAt: new Date().toISOString(),
    target: ctx.target
      ? { type: "http", value: `${ctx.target.method} ${ctx.target.url}` }
      : { type: "token", value: ctx.token?.raw ?? "" },
    findings,
  };
}
