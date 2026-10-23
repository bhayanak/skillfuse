# Security Policy

SkillChain is a security tool; we treat vulnerabilities in it with the same seriousness we expect from the skills
it scans.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Use [GitHub private vulnerability reporting](https://github.com/skillchain-dev/skillchain/security/advisories/new).
You will receive an acknowledgement within 3 business days and a remediation plan or status update within 14 days.

Please include: affected version, reproduction steps or a proof-of-concept skill package, and the impact you
believe it has (e.g. *detection bypass*, *sandbox escape*, *signature forgery*, *path traversal in the scanner*).

## Scope

In scope:

- **Detection bypasses** for deterministic rules (e.g. a zero-width character the `SC-HID-001` rule misses). Bypasses
  of heuristic rules are welcome as regular issues with a fixture, since heuristics are best-effort by design.
- **Sandbox escapes**: a detonated script that reaches the real network, real `$HOME`, or persists outside the
  sandbox root when using the documented backends.
- **Signature / lockfile / transparency-log integrity**: any way to make `skillchain verify`, `lock verify`, or
  `log verify` report success for tampered content.
- **Scanner safety**: the scanner reading or writing files outside the target (symlink following, path traversal),
  resource exhaustion from crafted inputs (ReDoS, zip bombs), or code execution during *static* scanning.
- **Broker bypasses**: a `tools/call` that reaches the upstream MCP server despite a `block` decision.

Out of scope:

- Findings about fixture packages in `tests/fixtures/corpus/malicious/` — they are intentionally malicious.
- Vulnerabilities in optional third-party tools (Sigstore, cosign, OPA, Docker) themselves.

## Hardening notes for operators

- Run `skillchain detonate` with the Docker backend in CI; the subprocess backend relies on runtime shims and is
  designed for developer machines.
- Pin the action (`skillchain-dev/skillchain@<sha>`) and the container image by digest.
- Keep private signing keys out of repositories; prefer Sigstore keyless signing in CI.
- Treat `skillchain.lock` as code: require review for changes.
