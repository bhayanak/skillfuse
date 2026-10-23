# CI & editor integration

## `skillfuse ci`

One command: scan → policy → lockfile verify → SARIF → GitHub annotations → exit code.

```bash
skillfuse ci ./skills \
  --policy .skillfuse/policy.yaml \
  --lock skillfuse.lock --require-lock \
  --fail-on high [--fail-on-heuristic] [--fail-on-quarantine] \
  --sarif skillfuse.sarif --json report.json [--detonate] [--rego policy.rego]
```

| Exit | Meaning |
|---|---|
| 0 | Clean |
| 1 | Deterministic finding ≥ `--fail-on` |
| 2 | Policy block |
| 3 | Policy quarantine (with `--fail-on-quarantine`) |
| 4 | Lock drift (`digest-changed`, `new-capabilities`, `new-findings`, `removed`, or `missing` with `--require-lock`) |
| 10 | Scanner error |

Inside GitHub Actions it also emits `::error`/`::warning` annotations, writes the Markdown report to the step summary,
and sets outputs `exit-code`, `findings`, `blocked`, `sarif`.

## GitHub Action

```yaml
name: skills
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  skillfuse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bhayanak/skillfuse@v0      # pin to a SHA in production
        with:
          path: .github/skills
          policy: .skillfuse/policy.yaml
          lock: skillfuse.lock
          require-lock: "true"
          fail-on: high
          detonate: "false"
```

Inputs mirror the CLI flags; outputs are the same four values.

## Other CI systems

Use the container image:

```bash
docker run --rm -v "$PWD:/src:ro" ghcr.io/bhayanak/skillfuse ci /src/skills --sarif /src/skillfuse.sarif
```

## Pre-commit

```yaml
- repo: local
  hooks:
    - id: skillfuse
      name: skillfuse
      entry: skillfuse scan --fail-on high
      language: python
      additional_dependencies: [skillfuse]
      files: (SKILL\.md|\.agent\.md|\.prompt\.md|\.instructions\.md|mcp\.json|\.mdc)$
```

## Editors

- **VS Code / Copilot**: scan `.github/agents`, `.github/prompts`, `.github/instructions`, `.vscode/mcp.json`.
  SARIF opens in the *SARIF Viewer* extension; `skillfuse scan -f sarif -o .vscode/skillfuse.sarif`.
- **Claude Code**: scan `.claude/skills`, `CLAUDE.md`, `.mcp.json`, and plugin directories.
- **Cursor**: scan `.cursorrules` and `.cursor/rules`.
- **Any MCP host**: wrap servers with `skillfuse broker -- <server command>` in the host's MCP config so every tool
  call passes through the permission broker.

## Suppressing findings

- Inline: append `skillfuse: ignore SC-NET-004` to the offending line, or put `# skillfuse: ignore` alone on the
  line above.
- Baseline: `skillfuse scan . -f json -o .skillfuse-baseline.json` then `baseline: .skillfuse-baseline.json` in
  `.skillfuse.yaml`. Fingerprints ignore line numbers.
- Policy: `rule_ids.ignore`.
- Config: `disabled_rules` (IDs or categories).
