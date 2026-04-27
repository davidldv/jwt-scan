import type { Check, Finding } from "../types.js";
import { signHs256 } from "../jwt.js";
import { probe } from "../targets/httpTarget.js";

export const keyConfusionCheck: Check = {
  id: "JWT-002",
  title: "HS256/RS256 key confusion",
  applies: (ctx) => Boolean(ctx.token && ctx.target && ctx.publicKey),
  async run(ctx): Promise<Finding[]> {
    if (!ctx.token || !ctx.target || !ctx.publicKey) return [];

    const forgedHeader = { ...ctx.token.header, alg: "HS256" };
    const forged = signHs256(forgedHeader, ctx.token.payload, ctx.publicKey);
    const res = await probe(ctx.target, forged);

    if (res.accepted) {
      return [
        {
          id: this.id,
          title: "Server accepts HS256 token signed with the RSA public key",
          severity: "critical",
          description:
            "Endpoint validates the JWT using the RSA public key as if it were an HMAC secret. " +
            "An attacker who knows the public key can forge arbitrary tokens.",
          evidence: `Forged: ${forged}\nStatus: ${res.status}`,
          remediation:
            "Allowlist the expected algorithm (RS256) when verifying. Never let the token's alg header pick the verifier.",
        },
      ];
    }
    return [];
  },
};
