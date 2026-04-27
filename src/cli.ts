#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { decodeJwt } from "./jwt.js";
import { scan } from "./scanner.js";
import { renderTerminal } from "./report/terminal.js";
import { parseTarget } from "./targets/httpTarget.js";
import type { ScanContext } from "./types.js";

const program = new Command();
program
  .name("jwt-scan")
  .description("Scan a JWT and/or HTTP endpoint for common JWT misconfigurations.")
  .version("0.1.0")
  .option("-t, --token <jwt>", "JWT to analyze")
  .option("--token-file <path>", "read JWT from file")
  .option("-u, --url <method-url>", "HTTP target, e.g. \"GET https://api.example.com/me\"")
  .option("--header <name>", "auth header name", "authorization")
  .option("--prefix <prefix>", "auth header value prefix", "Bearer ")
  .option("--body <body>", "HTTP request body")
  .option("--content-type <ct>", "HTTP content-type")
  .option("--public-key <path>", "PEM public key (enables HS/RS confusion check)")
  .option("--wordlist <path>", "weak-secrets wordlist")
  .option("--json", "emit JSON report")
  .parse(process.argv);

const opts = program.opts();

const tokenStr =
  opts.token ??
  (opts.tokenFile ? (await readFile(opts.tokenFile, "utf8")).trim() : undefined);

if (!tokenStr && !opts.url) {
  program.error("provide --token, --token-file, or --url");
}

const ctx: ScanContext = {};
if (tokenStr) ctx.token = decodeJwt(tokenStr);
if (opts.url) {
  ctx.target = parseTarget(opts.url, {
    headerName: opts.header,
    headerPrefix: opts.prefix,
    body: opts.body,
    contentType: opts.contentType,
  });
}
if (opts.publicKey) ctx.publicKey = await readFile(opts.publicKey, "utf8");
if (opts.wordlist) {
  const txt = await readFile(opts.wordlist, "utf8");
  ctx.wordlist = txt.split("\n").map((s) => s.trim()).filter(Boolean);
}

const report = await scan(ctx);
if (opts.json) {
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
} else {
  process.stdout.write(renderTerminal(report) + "\n");
}
process.exit(report.findings.some((f) => f.severity === "high" || f.severity === "critical") ? 1 : 0);
