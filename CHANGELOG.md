# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-23

### Added
- Static scanner with 50+ rules across ten categories (`SC-PI`, `SC-HID`, `SC-EXF`, `SC-SH`, `SC-NET`, `SC-TOOL`,
  `SC-DEP`, `SC-META`, `SC-MAN`, `SC-DYN`) and custom YAML rule packs.
- Discovery of `SKILL.md`, VS Code agent/prompt/instruction files, `AGENTS.md`/`CLAUDE.md`, Cursor rules, MCP
  configs, and plugin bundles.
- Capability taxonomy, inference (scripts, tool declarations, MCP configs, prose with negation handling), and
  declared-vs-inferred manifest diff with strong/weak evidence separation.
- Reporters: Rich console, JSON, Markdown, SARIF 2.1.0 with rule metadata, fingerprints and security-severity.
- Policy engine (`allow`/`quarantine`/`block`) with publisher, capability, rule-ID and ordered-rule conditions;
  heuristic findings cannot block by default. OPA/Rego bridge.
- Sandbox detonation: canary secrets, fake HOME/workspace, PATH + Python + Node shims, mock HTTP recorder, fake
  MCP server, subprocess and Docker backends; `SC-DYN-*` findings and observed-vs-inferred drift (`SC-MAN-004`).
- Signing: deterministic tree digest, reproducible tar.gz, Ed25519 DSSE/in-toto attestations, Sigstore and cosign
  adapters, hash-chained transparency log with inclusion proofs.
- `skillfuse.lock` generation and verification (digest, capabilities, accepted findings, signer).
- MCP permission broker with per-call decisions, secret-argument blocking, rate limiting, audit log and drift alerts.
- `skillfuse ci` gate with exit-code contract, GitHub annotations, step summary and outputs; composite GitHub Action.
- CI workflows (lint, matrix tests, self-scan with SARIF upload, build, Docker, action smoke test), CodeQL, Scorecard,
  Dependabot, and a release pipeline producing SBOM, Sigstore signatures, SLSA provenance, PyPI (trusted publishing)
  and GHCR images.

[Unreleased]: https://github.com/bhayanak/skillfuse/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bhayanak/skillfuse/releases/tag/v0.1.0
