# jwt-scan

[![npm version](https://img.shields.io/npm/v/jwt-scan.svg)](https://www.npmjs.com/package/jwt-scan)
[![npm downloads](https://img.shields.io/npm/dm/jwt-scan.svg)](https://www.npmjs.com/package/jwt-scan)
[![license](https://img.shields.io/npm/l/jwt-scan.svg)](https://github.com/davidldv/jwt-scan/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/jwt-scan.svg)](https://www.npmjs.com/package/jwt-scan)

CLI scanner for common JWT misconfigurations. Probes a static token, a live HTTP endpoint, or both.

```bash
npx jwt-scan --token "$TOKEN" --url "GET https://api.example.com/me"
```

Checks:

| ID      | Issue                              | Mode             |
|---------|------------------------------------|------------------|
| JWT-001 | `alg=none` accepted (case variants)| token + http     |
| JWT-002 | HS256/RS256 key confusion          | http + pubkey    |
| JWT-003 | Weak HS256 secret (dictionary)     | token            |
| JWT-004 | `kid` header injection             | http             |
| JWT-005 | Missing/invalid `exp`/`iss`/`aud`  | token            |

## Install

```bash
npm install
npm run build
```

## Usage

Scan a token:

```bash
npm run dev -- --token "eyJhbGciOi..."
```

Probe a live endpoint with the token:

```bash
npm run dev -- \
  --token "eyJhbGciOi..." \
  --url "GET https://api.example.com/me"
```

Add HS/RS confusion check (needs the public key):

```bash
npm run dev -- \
  --token "$T" \
  --url "GET https://api.example.com/me" \
  --public-key ./pub.pem
```

JSON output and CI integration:

```bash
npm run dev -- --token "$T" --json
# exit code 1 if any high/critical findings
```

## Status

v0.1 — covers the five lab vulnerabilities. Roadmap: `jku`/`x5u` trust, JWKS endpoint probing, blind-target heuristics, npm publish.

## License

MIT
