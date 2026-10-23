# SkillChain

**Supply-chain security for AI agent skills.** Scan, infer capabilities, detonate, sign, lock, and broker the
`SKILL.md`, agent, prompt, and MCP packages your agents install — before they can act.

[![CI](https://github.com/skillchain-dev/skillchain/actions/workflows/ci.yml/badge.svg)](https://github.com/skillchain-dev/skillchain/actions/workflows/ci.yml)
[![CodeQL](https://github.com/skillchain-dev/skillchain/actions/workflows/codeql.yml/badge.svg)](https://github.com/skillchain-dev/skillchain/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/skillchain-dev/skillchain/badge)](https://scorecard.dev/viewer/?uri=github.com/skillchain-dev/skillchain)
[![PyPI](https://img.shields.io/pypi/v/skillchain.svg)](https://pypi.org/project/skillchain/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

Agent skills are executable instructions with tools and ambient credentials, yet they are installed like harmless
Markdown. Package scanners cannot see prompt injection, deceptive instructions, tool overreach, or behaviour that
activates only under certain inputs. SkillChain can.

```text
$ skillchain scan ./skills/helpful-formatter

╭─ helpful-formatter  [skill]  BLOCK ──────────────────────────────────────────────────╮
│ SKILL.md · digest sha256:8a1f…                                                       │
│ capabilities: env.read, filesystem.delete, network.egress, package.install, …        │
│ policy: block-deterministic-critical: Deterministic critical finding                 │
╰──────────────────────────────────────────────────────────────────────────────────────╯
sev       conf  rule         location              message
critical  det   SC-HID-001   SKILL.md:19           1 invisible character(s): ZERO WIDTH SPACE
critical  det   SC-SH-001    scripts/setup.sh:4    Remote script piped to a shell
critical  heu   SC-EXF-005   scripts/setup.sh:5    File reads '~/.aws/credentials' and performs outbound transfer
high      det   SC-HID-003   SKILL.md:10           HTML comment (188 chars) contains 7 instruction-like keyword(s)
high      heu   SC-PI-002    SKILL.md:10           Concealment directive
high      det   SC-NET-003   SKILL.md:17           Endpoint matches suspicious host pattern 'bit.ly'
…
```

## What it does

| Layer | Capability |
|---|---|
| **Static scanner** | 50+ rules across prompt injection, hidden content (zero-width, bidi, HTML comments, homoglyphs), credential exfiltration, dangerous shell, URL hygiene, MCP tool overreach, dependency pinning, package hygiene. Custom YAML rules. |
| **Capability manifest** | Infers `network.egress`, `filesystem.write`, `jira.write`, `shell.exec`, … from scripts, tool declarations, MCP configs *and* prose; diffs against what the skill declares. |
| **Sandbox detonation** | Runs scripts in a fake workspace seeded with canary secrets and an adversarial README. Records every egress attempt, credential read, spawn, and persistence hook via PATH / Python / Node shims and a mock HTTP + MCP service. Divergence from static analysis is itself a critical finding. |
| **Policy** | YAML policy → `allow` / `quarantine` / `block` by findings, capabilities, publisher, signature, lock membership. Optional OPA/Rego. **Heuristic findings never block by default.** |
| **Signing & provenance** | Deterministic tree digest, reproducible `.tar.gz`, Ed25519 DSSE/in-toto attestations (offline), optional Sigstore/cosign keyless signing, hash-chained Rekor-style transparency log. |
| **Lockfile** | `skillchain.lock` pins digest, capabilities, accepted findings and signer per approved skill; CI fails on drift. |
| **Runtime broker** | MCP stdio proxy enforcing per-call permissions, blocking secret-bearing arguments, rate-limiting, and alerting on behaviour drift from the approved capability set. |
| **Reports & CI** | Rich console, JSON, Markdown, **SARIF 2.1.0** (GitHub code scanning), GitHub annotations + step summary, composite GitHub Action, container image, exit-code contract. |

## Install

```bash
pip install skillchain            # or: uv tool install skillchain
pip install "skillchain[sigstore]" # keyless signing via the sigstore CLI
docker run --rm -v "$PWD:/src:ro" ghcr.io/skillchain-dev/skillchain scan /src
```

Requires Python 3.11+. No external services are needed for the core workflow.

## Quick start

```bash
# 1. Scan anything: a SKILL.md directory, an .agent.md, an mcp.json, or a whole repo
skillchain scan ./skills
skillchain scan . -f sarif -o skillchain.sarif

# 2. See what a skill can do, with evidence, and write a manifest for it
skillchain manifest ./skills/changelog-writer --write

# 3. Detonate scripts in the canary sandbox (observed vs. inferred behaviour)
skillchain detonate ./skills/helpful-formatter

# 4. Decide with policy, then pin what you approved
skillchain policy eval ./skills -p examples/policy.yaml
skillchain lock generate ./skills

# 5. Sign a package and log it
skillchain keys generate
skillchain sign ./skills/changelog-writer -k .skillchain-keys/skillchain.key --publisher acme --log transparency.jsonl
skillchain verify ./skills/changelog-writer -t .skillchain-keys/skillchain.pub --log transparency.jsonl

# 6. Gate CI in one command (scan → policy → lock → SARIF → exit code)
skillchain ci ./skills --fail-on high

# 7. Put a permission broker in front of an MCP server
skillchain broker --lock skillchain.lock --skill jira-helper -- npx -y @acme/jira-mcp@1.4.2
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Deterministic findings at/above `--fail-on` |
| `2` | Policy **block** |
| `3` | Policy **quarantine** (only with `--fail-on-quarantine`) |
| `4` | Lockfile drift |
| `10` | Scanner error |

## GitHub Action

```yaml
- uses: skillchain-dev/skillchain@v0
  with:
    path: .github/skills
    policy: .skillchain/policy.yaml
    fail-on: high
    upload-sarif: "true"      # needs permissions: security-events: write
```

## Declaring capabilities

Add `capabilities:` to the frontmatter or a `skillchain.yaml` beside the entrypoint:

```yaml
---
name: changelog-writer
description: Summarise git history into a CHANGELOG section.
capabilities: [git.read, filesystem.write]
---
```

Undeclared capabilities with script/tool evidence are `SC-MAN-001` (high, deterministic); capabilities inferred
only from prose are reported as heuristic so a sentence like "run the tests" doesn't block a release.

## Supported formats

Agent Skills (`SKILL.md`), VS Code `*.agent.md` / `*.chatmode.md` / `*.prompt.md` / `*.instructions.md`,
`AGENTS.md` / `CLAUDE.md` / `GEMINI.md` / `copilot-instructions.md`, Cursor `.cursorrules` and `.cursor/rules/*.mdc`,
MCP configs (`mcp.json`, `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`), and plugin bundles
(`plugin.json`). Scripts in `sh/bash/zsh`, `python`, `javascript/typescript`, `powershell` are analysed.

## Documentation

- [Architecture](docs/architecture.md) · [Rule catalogue](docs/rules.md) · [Capabilities](docs/capabilities.md)
- [Policy](docs/policy.md) · [Sandbox](docs/sandbox.md) · [Signing & provenance](docs/signing.md)
- [CI & editor integration](docs/ci.md) · [Release process](docs/release.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) · [Plan & progress](PLAN.md)

## Design principles

1. **Deterministic vs heuristic is explicit.** Every finding is labelled; policies and CI gates can ignore suspicion
   and act only on facts.
2. **Explainable.** Every finding has a rule ID, location, snippet, remediation, and fingerprint; every capability has
   evidence.
3. **Static → runtime comparison.** Behaviour that only appears in the sandbox is the signature of obfuscation.
4. **Works offline.** No SaaS, no model calls. Semgrep, OPA, Sigstore, cosign and Docker are optional accelerators.

## License

Apache-2.0 — see [LICENSE](LICENSE).
