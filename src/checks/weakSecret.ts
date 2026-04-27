import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { Check, Finding } from "../types.js";
import { verifyHs256 } from "../jwt.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export const weakSecretCheck: Check = {
  id: "JWT-003",
  title: "Weak HS256 secret (dictionary)",
  applies: (ctx) =>
    Boolean(ctx.token) && String(ctx.token?.header.alg ?? "").toUpperCase() === "HS256",
  async run(ctx): Promise<Finding[]> {
    if (!ctx.token) return [];
    const wordlist = ctx.wordlist ?? (await loadDefaultWordlist());

    for (const secret of wordlist) {
      if (verifyHs256(ctx.token.raw, secret)) {
        return [
          {
            id: this.id,
            title: `Weak HS256 secret cracked: "${secret}"`,
            severity: "critical",
            description:
              "The HMAC secret was found in a small dictionary. An attacker who cracks the secret can forge any token.",
            evidence: `Secret: ${secret}`,
            remediation:
              "Rotate to a 256-bit random secret stored in a secret manager. Consider switching to RS256 with key rotation.",
          },
        ];
      }
    }
    return [];
  },
};

async function loadDefaultWordlist(): Promise<string[]> {
  const path = resolve(__dirname, "../../wordlists/weak-secrets.txt");
  try {
    const txt = await readFile(path, "utf8");
    return txt.split("\n").map((s) => s.trim()).filter(Boolean);
  } catch {
    return ["secret", "password", "123456", "changeme", "jwt", "test", "admin"];
  }
}
