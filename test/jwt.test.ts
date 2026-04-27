import { describe, it, expect } from "vitest";
import { decodeJwt, signHs256, verifyHs256, buildUnsigned } from "../src/jwt.js";

describe("jwt", () => {
  it("decodes a known token", () => {
    const t = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "1", name: "alice" }, "secret");
    const d = decodeJwt(t);
    expect(d.header.alg).toBe("HS256");
    expect(d.payload.sub).toBe("1");
  });

  it("verifies HS256", () => {
    const t = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "1" }, "secret");
    expect(verifyHs256(t, "secret")).toBe(true);
    expect(verifyHs256(t, "wrong")).toBe(false);
  });

  it("builds unsigned alg=none token", () => {
    const t = buildUnsigned({ alg: "none", typ: "JWT" }, { sub: "admin" });
    expect(t.endsWith(".")).toBe(true);
    const d = decodeJwt(t.replace(/\.$/, ".x"));
    expect(d.header.alg).toBe("none");
  });
});
