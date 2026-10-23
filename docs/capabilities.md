# Capabilities

A capability is a dotted, hierarchical string describing something a skill can *do*. The taxonomy is intentionally
small and host-agnostic; host-specific tool names are mapped onto it.

List the taxonomy with `skillchain rules capabilities`.

| Capability | Meaning |
|---|---|
| `network.egress` / `network.listen` | Outbound requests / open sockets |
| `filesystem.read` / `.write` / `.delete` | Read outside the package / create-modify / delete |
| `shell.exec` / `process.spawn` | Run shell commands / spawn processes & servers |
| `env.read` / `secrets.read` | Read environment / access credential material |
| `package.install` | Install dependencies |
| `git.read` / `git.write` | Inspect / mutate git |
| `github.*`, `jira.*`, `confluence.*`, `slack.*` | Read / write on those systems |
| `cloud.read` / `cloud.write`, `database.read` / `database.write` | Cloud and DB access |
| `browser.automation`, `ssh.exec`, `email.send`, `ai.model` | Drive a browser, remote shells, mail, external LLMs |
| `mcp.tools` / `mcp.server` | Invoke MCP tools / define MCP servers |
| `system.admin` / `system.persistence` | Elevated privileges / hooks, cron, services |

## Declaring

Either in frontmatter or `skillchain.yaml` next to the entrypoint. All of these are accepted:

```yaml
capabilities: [git.read, filesystem.write]
capabilities: git.read, filesystem.write
permissions:
  network: [egress]
  filesystem: { write: true, delete: false }
```

A declared parent (`network`) covers its children (`network.egress`).

## Inference

| Source | Strength | Examples |
|---|---|---|
| `tools:` / `allowed-tools:` frontmatter, MCP `tools` | strong | `runCommands` → `shell.exec`; `mcp_atlassian_transitionJiraIssue` → `jira.write` |
| Scripts (`sh`, `py`, `js/ts`, `ps1`) | strong | `requests.post(` → `network.egress`; `crontab` → `system.persistence` |
| MCP configs | strong | `npx -y pkg` → `process.spawn`, `package.install`, `network.egress` |
| Prose in instructions | **weak** | "run the following command" → `shell.exec`; negated phrases ("never delete files") are ignored |

Weak capabilities appear in reports as *prose-only*. `SC-MAN-001` for them is `heuristic`/`medium`; for strong
evidence it is `deterministic`/`high`. Policy `capabilities.deny/quarantine` lists and `undeclared_capabilities`
conditions only consider strong evidence (set `include_weak: true` in a `capabilities:` condition to change this).

## Manifest rules

| ID | Meaning |
|---|---|
| `SC-MAN-001` | Undeclared capability (inferred but not declared) |
| `SC-MAN-002` | No manifest at all |
| `SC-MAN-003` | Over-declared (declared but never inferred) — informational |
| `SC-MAN-004` | **Runtime-only**: sandbox observed something static analysis did not predict — critical |
| `SC-MAN-005` | Unknown capability name |

`skillchain manifest <path> --write` generates a `skillchain.yaml` from strong evidence to bootstrap a manifest.
