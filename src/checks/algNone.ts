import type { Check, Finding } from "../types.js";
import { buildUnsigned, b64urlEncode } from "../jwt.js";
import { probe } from "../targets/httpTarget.js";

const VARIANTS = ["none", "None", "NONE", "nOnE"];

export const algNoneCheck: Check = {
  id: "JWT-001",
  title: "alg=none accepted",
  applies: (ctx) => Boolean(ctx.token || ctx.target),
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    if (!ctx.token) return findings;

    if (ctx.target) {
      for (const alg of VARIANTS) {
        const forged = buildUnsigned({ ...ctx.token.header, alg, typ: "JWT" }, ctx.token.payload);
        const res = await probe(ctx.target, forged);
        if (res.accepted) {
          findings.push({
            id: `${this.id}-${alg}`,
            title: `Endpoint accepts JWT with alg="${alg}"`,
            severity: "critical",
            description:
              `The server accepted a forged token with alg="${alg}" (status ${res.status}). ` +
              `An attacker can mint arbitrary tokens with no signing key.`,
            evidence: `Forged: ${forged}\nStatus: ${res.status}`,
            remediation:
              "Allowlist algorithms explicitly (e.g. only HS256 or RS256). Reject the 'none' algorithm and any case-variant.",
          });
        }
      }
      return findings;
    }

    // Token-only mode: cannot prove acceptance, but flag if header alg is none.
    const alg = String(ctx.token.header.alg ?? "");
    if (alg.toLowerCase() === "none") {
      findings.push({
        id: this.id,
        title: `Token uses alg="${alg}"`,
        severity: "high",
        description: "Token header declares the 'none' algorithm. Any server that accepts it permits forged tokens.",
        evidence: `Header: ${JSON.stringify(ctx.token.header)}`,
        remediation: "Reissue tokens signed with HS256 or RS256, and allowlist algorithms server-side.",
      });
    }
    return findings;
  },
};
