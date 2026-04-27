import { request } from "undici";
import type { HttpTarget } from "../types.js";

export interface ProbeResult {
  status: number;
  accepted: boolean;
  body: string;
}

export async function probe(target: HttpTarget, token: string): Promise<ProbeResult> {
  const headers: Record<string, string> = {
    [target.headerName]: `${target.headerPrefix}${token}`.trimStart(),
  };
  if (target.contentType) headers["content-type"] = target.contentType;

  try {
    const res = await request(target.url, {
      method: target.method,
      headers,
      body: target.body,
      bodyTimeout: 10_000,
      headersTimeout: 10_000,
    });
    const body = await res.body.text();
    return {
      status: res.statusCode,
      accepted: res.statusCode >= 200 && res.statusCode < 300,
      body: body.slice(0, 500),
    };
  } catch (err) {
    return { status: 0, accepted: false, body: String(err) };
  }
}

export function parseTarget(spec: string, opts: Partial<HttpTarget> = {}): HttpTarget {
  // spec form: "METHOD URL" e.g. "GET https://api.example.com/me"
  const [method, url] = spec.includes(" ") ? spec.split(/\s+/, 2) : ["GET", spec];
  return {
    url: url ?? spec,
    method: (method.toUpperCase() as HttpTarget["method"]) ?? "GET",
    headerName: opts.headerName ?? "authorization",
    headerPrefix: opts.headerPrefix ?? "Bearer ",
    body: opts.body,
    contentType: opts.contentType,
  };
}
