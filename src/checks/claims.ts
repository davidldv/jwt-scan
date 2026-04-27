import type { Check, Finding } from "../types.js";

export const claimsCheck: Check = {
  id: "JWT-005",
  title: "Missing or invalid standard claims",
  applies: (ctx) => Boolean(ctx.token),
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    if (!ctx.token) return findings;
    const p = ctx.token.payload;
    const now = Math.floor(Date.now() / 1000);

    if (typeof p.exp !== "number") {
      findings.push({
        id: `${this.id}-exp`,
        title: "Missing 'exp' claim",
        severity: "high",
        description: "Token has no expiration. Stolen tokens remain valid forever.",
        remediation: "Issue tokens with a short 'exp' (e.g. 15 minutes) and refresh via a separate flow.",
      });
    } else if (p.exp < now) {
      findings.push({
        id: `${this.id}-expired`,
        title: "Token already expired",
        severity: "info",
        description: `Token expired at ${new Date((p.exp as number) * 1000).toISOString()}.`,
        remediation: "Verify the server rejects this token. If accepted, exp validation is broken.",
      });
    }

    if (typeof p.iss !== "string" || p.iss.length === 0) {
      findings.push({
        id: `${this.id}-iss`,
        title: "Missing 'iss' claim",
        severity: "medium",
        description: "Without 'iss', a server cannot enforce which issuer a token came from.",
        remediation: "Set 'iss' on issuance and validate it against an allowlist.",
      });
    }

    if (typeof p.aud !== "string" && !Array.isArray(p.aud)) {
      findings.push({
        id: `${this.id}-aud`,
        title: "Missing 'aud' claim",
        severity: "medium",
        description: "Without 'aud', tokens issued for one service can be replayed against another.",
        remediation: "Set 'aud' on issuance and validate it on the resource server.",
      });
    }

    if (typeof p.nbf === "number" && p.nbf > now + 60) {
      findings.push({
        id: `${this.id}-nbf`,
        title: "Token not yet valid",
        severity: "info",
        description: `'nbf' is in the future (${new Date((p.nbf as number) * 1000).toISOString()}).`,
        remediation: "Verify clock skew handling and that the server rejects nbf-future tokens.",
      });
    }

    return findings;
  },
};
