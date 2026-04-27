import { describe, it, expect } from "vitest";
import { decodeJwt, signHs256, buildUnsigned } from "../src/jwt.js";
import { scan } from "../src/scanner.js";

describe("checks (token-only mode)", () => {
  it("flags alg=none in header", async () => {
    const t = buildUnsigned({ alg: "none", typ: "JWT" }, { sub: "admin", exp: 9999999999, iss: "x", aud: "y" });
    const report = await scan({ token: decodeJwt(t + "x") });
    expect(report.findings.some((f) => f.id.startsWith("JWT-001"))).toBe(true);
  });

  it("cracks weak HS256 secret", async () => {
    const t = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "1", exp: 9999999999, iss: "x", aud: "y" }, "secret");
    const report = await scan({ token: decodeJwt(t), wordlist: ["wrong", "secret"] });
    expect(report.findings.some((f) => f.id === "JWT-003")).toBe(true);
  });

  it("flags missing exp/iss/aud", async () => {
    const t = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "1" }, "x");
    const report = await scan({ token: decodeJwt(t), wordlist: [] });
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain("JWT-005-exp");
    expect(ids).toContain("JWT-005-iss");
    expect(ids).toContain("JWT-005-aud");
  });
});
