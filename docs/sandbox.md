# Sandbox detonation

`skillfuse detonate <skill>` executes the skill's scripts inside a disposable, canary-seeded environment and turns
what it observes into `SC-DYN-*` findings plus an *observed* capability manifest. Observed behaviour that static
analysis did not predict becomes `SC-MAN-004` (critical) — the signature of obfuscation.

## What is seeded

| Location | Content |
|---|---|
| `$HOME/.aws/credentials`, `.ssh/id_ed25519`, `.netrc`, `.git-credentials`, `.npmrc`, `.config/gh/hosts.yml`, `.docker/config.json`, `.kube/config` | Unique canary secrets (prefix `SKFS`/`skfs`) |
| `$HOME/.bashrc`, `.zshrc` | Empty files to detect persistence writes |
| Workspace `.env`, `src/app.py`, `notes.txt`, `package.json`, `.git/config` | More canaries plus an adversarial `README.md` containing a prompt-injection marker |
| Environment | `AWS_*`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `SLACK_BOT_TOKEN`, `JIRA_API_TOKEN`, `DATABASE_URL`, `NPM_TOKEN` canaries |

Any canary appearing in an outbound request, DNS lookup, or MCP call ⇒ `SC-DYN-001` (critical).

## How behaviour is observed

| Layer | Mechanism |
|---|---|
| Shell tools | PATH shims for `curl`/`wget` (recorded and redirected to the mock recorder), `nc`/`ssh`/`scp`/`socat`/… (recorded and refused), `sudo`/`su` (refused, `SC-DYN-005`), `crontab`/`launchctl`/`systemctl` (refused, `SC-DYN-006`), package managers (recorded, not executed, `SC-DYN-007`), `git`/`rm`/`chmod` (recorded and forwarded) |
| Python | `sitecustomize` injected via `PYTHONPATH`: hooks `socket.connect`, `getaddrinfo`, `open`, `subprocess`, `os.system/exec*` |
| Node | `NODE_OPTIONS=--require preload.cjs`: hooks `net.Socket.connect`, `http(s).request`, `fetch`, `fs.*`, `child_process.*` |
| HTTP | Mock recorder on loopback; `HTTP(S)_PROXY` point at it; logs method, path, original host, body. HTTPS is terminated with a per-run **ephemeral CA** (trusted via `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, …) so request bodies sent over TLS are captured instead of failing the handshake |
| MCP | `fake_mcp.py` stdio server answers `initialize`/`tools/list`/`tools/call` and logs calls (`SC-DYN-010`) |
| Filesystem | Snapshot diff of `$HOME` and workspace before/after (`SC-DYN-004`, `SC-DYN-006`) |

## Backends

| Backend | Isolation | When |
|---|---|---|
| `subprocess` (default) | Fake HOME/TMP/PATH, rlimits, process group kill, shims. Egress is redirected/refused by shims and proxies but a determined script could still reach the network. | Developer machines, fast feedback |
| `docker` | `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit`, sandbox root bind-mounted | CI and untrusted packages |

Select with `--backend docker`; `auto` picks Docker only when `SKILLFUSE_PREFER_DOCKER=1` and a daemon is available.

## Options

```bash
skillfuse detonate ./skill --timeout 60 --backend docker
skillfuse detonate ./skill --markdown-blocks     # also run ```bash blocks from instructions
skillfuse detonate ./skill --keep ./sbx-debug    # keep the sandbox directory for inspection
skillfuse detonate ./skill -f json -o report.json # includes per-execution and per-event detail
skillfuse ci ./skills --detonate                 # inside the CI gate
```

## Rules

| ID | Severity | Trigger |
|---|---|---|
| `SC-DYN-001` | critical | Canary secret in outbound traffic |
| `SC-DYN-002` | high | Outbound connection attempted |
| `SC-DYN-003` | high | Credential file read |
| `SC-DYN-004` | high | File written outside the workspace |
| `SC-DYN-005` | high | Privilege escalation attempted |
| `SC-DYN-006` | critical | Persistence mechanism invoked / rc file modified |
| `SC-DYN-007` | medium | Package install attempted |
| `SC-DYN-008` | medium | DNS lookup of an external host |
| `SC-DYN-009` | low | Execution timed out |
| `SC-DYN-010` | medium | MCP tool invoked |
| `SC-DYN-011` | low | Sub-process spawned |
| `SC-DYN-012` | critical | Outbound payload contained the README injection marker |

## Limitations

- The sandbox executes **scripts**, not the model. Prompt-injection effectiveness against a specific LLM is out of
  scope; the injection marker in `README.md` only detects scripts that exfiltrate workspace content.
- Compiled binaries and languages without a shim (Go, Rust) are observed only through PATH shims and the mock
  proxy.
- Behaviour gated on real credentials or real network responses may not trigger.
