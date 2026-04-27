import { createHmac, createSign, createPrivateKey, KeyObject } from "node:crypto";
import type { DecodedJwt } from "./types.js";

export function b64urlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(input: string): Buffer {
  const pad = 4 - (input.length % 4 || 4);
  const padded = input + "=".repeat(pad === 4 ? 0 : pad);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT: expected 3 segments, got ${parts.length}`);
  }
  const [headerB64, payloadB64, signature] = parts;
  const header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  return { raw: token, header, payload, signature, headerB64, payloadB64 };
}

export function buildUnsigned(header: object, payload: object): string {
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  return `${h}.${p}.`;
}

export function signHs256(header: object, payload: object, secret: string | Buffer): string {
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export function signRs256(header: object, payload: object, privateKeyPem: string): string {
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const key: KeyObject = createPrivateKey(privateKeyPem);
  const sig = createSign("RSA-SHA256").update(`${h}.${p}`).sign(key);
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export function verifyHs256(token: string, secret: string | Buffer): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [h, p, s] = parts;
  const expected = b64urlEncode(createHmac("sha256", secret).update(`${h}.${p}`).digest());
  return expected === s;
}
