# Policy

A policy turns a scan into one of three decisions per skill: **allow**, **quarantine** (needs human review), or
**block**. The strictest matching action wins unless a rule is marked `final`.

```bash
skillfuse policy show-default           # print the built-in policy
skillfuse policy validate policy.yaml
skillfuse policy eval ./skills -p policy.yaml
skillfuse scan ./skills -p policy.yaml  # scan + verdicts in one go
```

## Schema

```yaml
version: 1
name: my-policy
default: allow                 # decision when nothing matches
heuristic_can_block: false     # heuristic findings can only quarantine unless true

publishers:
  allow: ["acme-*"]            # globs over the publisher string → allow (does not override block)
  block: ["*-untrusted"]

capabilities:                  # strong (non-prose) capabilities only
  deny: ["system.persistence"]
  quarantine: ["system.admin"]

rule_ids:
  block: ["SC-SH-007"]         # deterministic findings with these IDs block; heuristic ones quarantine
  quarantine: ["SC-PI-*"]
  ignore: ["SC-NET-004"]       # policy never sees these findings

rules:                         # evaluated in order
  - name: block-critical
    action: block
    final: false               # true = stop evaluating after this rule matches
    message: optional text shown as the reason
    when:
      findings:                # all fields optional
        min_severity: critical
        confidence: deterministic
        rule_ids: ["SC-*"]
        categories: [shell, exfiltration]
        min_count: 1
      capabilities: { any: [...], all: [...], none: [...], include_weak: false }
      undeclared_capabilities: true | [network.egress, shell.exec]
      publisher: ["acme-*"]
      publisher_missing: true
      signed: true | false     # only matches when the signing state is known (ci/lock commands)
      in_lock: true | false
      kinds: [skill, agent, prompt, instructions, cursor-rules, mcp-config, plugin]
      names: ["jira-*"]
```

## Default policy

- **block** deterministic critical findings and `SC-SH-007` (reverse shell) / `SC-DYN-001` (canary exfil).
- **block** strong `system.persistence`; **quarantine** strong `system.admin`.
- **quarantine** any high-severity finding and any undeclared write/exec/network capability.
- Heuristic findings never block.

## Why heuristics don't block

Prompt-injection detection is pattern matching over natural language. It is valuable as a *review signal* but
would create unacceptable false positives as a hard gate. Flip `heuristic_can_block: true` only for high-assurance
registries where every skill is reviewed anyway.

## OPA / Rego

If `opa` is on `PATH`, pass `--rego policy.rego` to `scan`, `ci`, or `policy eval`. The input document is the
per-skill JSON from `skillfuse scan -f json` plus `signed` and `in_lock`. The policy must set
`data.skillfuse.result = {"decision": ..., "reasons": [...]}`. See `examples/policy.rego`.
