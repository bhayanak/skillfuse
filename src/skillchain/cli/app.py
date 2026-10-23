"""SkillChain command-line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from skillchain import __version__
from skillchain.capabilities import CAPABILITIES
from skillchain.ci import (
    EXIT_ERROR,
    GateConfig,
    evaluate_gate,
    github_annotation,
    in_github_actions,
    set_output,
    write_step_summary,
)
from skillchain.core.config import ScanConfig
from skillchain.core.models import (
    CapabilityManifest,
    Decision,
    PolicyVerdict,
    ScanResult,
    Severity,
    SkillScan,
)
from skillchain.lockfile import LOCK_FILENAME, LockedSigner, Lockfile, generate_lock, verify_lock
from skillchain.policy import Policy, PolicyEngine, PolicyInput, evaluate_with_opa, opa_available
from skillchain.report import render_console, render_json, render_markdown, render_sarif
from skillchain.rules import registry_for
from skillchain.scanner import Scanner

app = typer.Typer(
    name="skillchain",
    help="Supply-chain security for AI agent skills: scan, infer capabilities, detonate, sign, lock, and broker.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
rules_app = typer.Typer(help="Inspect built-in and custom rules.", no_args_is_help=True)
policy_app = typer.Typer(help="Evaluate and validate policies.", no_args_is_help=True)
keys_app = typer.Typer(help="Manage signing keys.", no_args_is_help=True)
log_app = typer.Typer(help="Transparency log operations.", no_args_is_help=True)
lock_app = typer.Typer(help="Generate and verify skillchain.lock.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
app.add_typer(policy_app, name="policy")
app.add_typer(keys_app, name="keys")
app.add_typer(log_app, name="log")
app.add_typer(lock_app, name="lock")

console = Console()
err_console = Console(stderr=True)

Target = Annotated[Path, typer.Argument(exists=True, help="Skill package, file, or directory to scan.")]
ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="Path to .skillchain.yaml.")]
PolicyOpt = Annotated[
    Path | None, typer.Option("--policy", "-p", help="Policy YAML (default: built-in policy).")
]
FormatOpt = Annotated[str, typer.Option("--format", "-f", help="console | json | sarif | markdown")]
OutputOpt = Annotated[
    Path | None, typer.Option("--output", "-o", help="Write report to this file instead of stdout.")
]


def _version(value: bool) -> None:
    if value:
        console.print(f"skillchain {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    _version_flag: Annotated[
        bool, typer.Option("--version", "-V", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """SkillChain."""


def _load_policy(path: Path | None) -> Policy:
    return Policy.load(path) if path else Policy.default_policy()


def _passphrase(env_var: str | None) -> bytes | None:
    if not env_var:
        return None
    value = os.environ.get(env_var)
    return value.encode() if value else None


def _verdicts(
    result: ScanResult,
    policy: Policy,
    *,
    rego: Path | None = None,
    extra: dict[str, PolicyInput] | None = None,
) -> dict[str, PolicyVerdict]:
    engine = PolicyEngine(policy)
    out: dict[str, PolicyVerdict] = {}
    for scan in result.skills:
        inp = (extra or {}).get(scan.package.name, PolicyInput())
        if rego is not None:
            out[scan.package.name] = evaluate_with_opa(scan, rego, signed=inp.signed, in_lock=inp.in_lock)
        else:
            out[scan.package.name] = engine.evaluate(scan, inp)
    return out


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        err_console.print(f"[dim]wrote {output}[/dim]")


def _render(
    result: ScanResult,
    fmt: str,
    output: Path | None,
    verdicts: dict[str, PolicyVerdict] | None,
    config: ScanConfig,
    *,
    evidence: bool = False,
) -> None:
    fmt = fmt.lower()
    if fmt == "console":
        render_console(result, console, verdicts=verdicts, show_evidence=evidence)
    elif fmt == "json":
        _emit(render_json(result, verdicts), output)
    elif fmt == "sarif":
        _emit(render_sarif(result, registry_for(config), base_dir=Path(result.target)), output)
    elif fmt in {"markdown", "md"}:
        _emit(render_markdown(result, verdicts), output)
    else:
        err_console.print(f"[red]unknown format {fmt}[/red]")
        raise typer.Exit(EXIT_ERROR)


# ------------------------------------------------------------------------------------------------ scan
@app.command()
def scan(
    target: Target,
    fmt: FormatOpt = "console",
    output: OutputOpt = None,
    config: ConfigOpt = None,
    policy: PolicyOpt = None,
    no_policy: Annotated[bool, typer.Option("--no-policy", help="Skip policy evaluation.")] = False,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit 1 if any deterministic finding ≥ this severity (critical|high|medium|low|info).",
        ),
    ] = None,
    fail_on_heuristic: Annotated[
        bool, typer.Option("--fail-on-heuristic", help="Let heuristic findings trip --fail-on too.")
    ] = False,
    evidence: Annotated[
        bool, typer.Option("--evidence", help="Show matched snippets in console output.")
    ] = False,
    rego: Annotated[
        Path | None, typer.Option("--rego", help="Evaluate policy with OPA using this .rego file.")
    ] = None,
) -> None:
    """Statically scan skills, infer capabilities, and (optionally) apply policy."""
    cfg = ScanConfig.load(target, config)
    result = Scanner(cfg).scan(target)
    verdicts = None if no_policy else _verdicts(result, _load_policy(policy), rego=rego)
    _render(result, fmt, output, verdicts, cfg, evidence=evidence)
    gate = evaluate_gate(
        result,
        verdicts or {},
        None,
        GateConfig(fail_on=Severity(fail_on) if fail_on else None, fail_on_heuristic=fail_on_heuristic),
    )
    if not gate.ok and fmt == "console":
        for r in gate.reasons:
            err_console.print(f"[red]✖[/red] {r}")
    raise typer.Exit(gate.exit_code if (fail_on or verdicts) else 0)


# -------------------------------------------------------------------------------------------- manifest
@app.command()
def manifest(
    target: Target,
    config: ConfigOpt = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="console | json | yaml")] = "console",
    write: Annotated[
        bool,
        typer.Option(
            "--write", help="Write/refresh skillchain.yaml next to each skill with the inferred capabilities."
        ),
    ] = False,
) -> None:
    """Show inferred vs declared capabilities with evidence."""
    cfg = ScanConfig.load(target, config)
    result = Scanner(cfg).scan(target)
    docs: list[dict[str, Any]] = []
    for s in result.skills:
        doc = {
            "name": s.package.name,
            "inferred": list(s.inferred.capabilities),
            "weak": list(s.inferred.weak),
            "declared": list(s.declared.capabilities) if s.declared else None,
            "undeclared": list(s.diff.undeclared),
            "overdeclared": list(s.diff.overdeclared),
            "evidence": {k: list(v) for k, v in s.inferred.evidence.items()},
        }
        docs.append(doc)
        if write:
            import yaml

            path = s.package.root_path / "skillchain.yaml"
            path.write_text(
                yaml.safe_dump(
                    {"name": s.package.name, "capabilities": list(s.inferred.strong)}, sort_keys=False
                ),
                encoding="utf-8",
            )
            err_console.print(f"[dim]wrote {path}[/dim]")
    if fmt == "json":
        sys.stdout.write(json.dumps(docs, indent=2) + "\n")
        return
    if fmt == "yaml":
        import yaml

        sys.stdout.write(yaml.safe_dump(docs, sort_keys=False))
        return
    for doc in docs:
        table = Table(title=f"{doc['name']}", show_lines=False, title_justify="left")
        table.add_column("capability", style="bold")
        table.add_column("status")
        table.add_column("evidence", overflow="fold")
        declared_caps: set[str] = set(doc["declared"] or [])
        weak_caps: list[str] = list(doc["weak"] or [])
        raw_evidence = doc["evidence"]
        evidence: dict[str, list[str]] = dict(raw_evidence) if isinstance(raw_evidence, dict) else {}
        inferred_caps: list[str] = list(doc["inferred"] or [])
        overdeclared_caps: list[str] = list(doc["overdeclared"] or [])
        for cap in inferred_caps:
            status = (
                "[green]declared[/green]"
                if any(cap == d or cap.startswith(d + ".") for d in declared_caps)
                else ("[yellow]prose-only[/yellow]" if cap in weak_caps else "[red]undeclared[/red]")
            )
            table.add_row(cap, status, "\n".join(evidence.get(cap, [])[:3]))
        for cap in overdeclared_caps:
            table.add_row(cap, "[dim]over-declared[/dim]", "")
        console.print(table)


# -------------------------------------------------------------------------------------------- detonate
@app.command()
def detonate(
    target: Target,
    fmt: Annotated[str, typer.Option("--format", "-f", help="console | json | sarif")] = "console",
    output: OutputOpt = None,
    config: ConfigOpt = None,
    policy: PolicyOpt = None,
    timeout: Annotated[float, typer.Option(help="Per-command timeout in seconds.")] = 60.0,
    backend: Annotated[str, typer.Option(help="auto | subprocess | docker")] = "auto",
    markdown_blocks: Annotated[
        bool, typer.Option("--markdown-blocks", help="Also execute shell code blocks found in instructions.")
    ] = False,
    keep: Annotated[Path | None, typer.Option(help="Keep the sandbox directory here for inspection.")] = None,
) -> None:
    """Run the skill's scripts in a canary-seeded sandbox and compare observed vs inferred behaviour."""
    from skillchain.sandbox import RunnerConfig
    from skillchain.sandbox import detonate as _detonate

    cfg = ScanConfig.load(target, config)
    scanner = Scanner(cfg)
    static = scanner.scan(target)
    observed: dict[str, CapabilityManifest] = {}
    dyn_findings: dict[str, list[Any]] = {}
    reports: list[dict[str, Any]] = []
    for s in static.skills:
        det = _detonate(
            s.package,
            config=RunnerConfig(timeout=timeout, backend=backend),
            include_markdown_blocks=markdown_blocks,
            keep=keep,
        )
        observed[s.package.name] = det.observed
        dyn_findings[s.package.name] = det.findings
        reports.append(det.to_dict())
        if fmt == "console":
            err_console.print(
                f"[dim]detonated {s.package.name} ({det.backend}, {len(det.executions)} command(s), {len(det.events)} event(s))[/dim]"
            )
    merged = scanner.scan(target, observed=observed)
    skills: list[SkillScan] = []
    for s in merged.skills:
        extra = tuple(dyn_findings.get(s.package.name, []))
        findings = tuple(
            sorted(
                (*s.findings, *extra),
                key=lambda f: (-f.severity.rank, f.location.path, f.location.line, f.rule_id),
            )
        )
        skills.append(s.model_copy(update={"findings": findings}))
    result = merged.model_copy(update={"skills": tuple(skills)})
    verdicts = _verdicts(result, _load_policy(policy))
    if fmt == "json":
        doc = json.loads(render_json(result, verdicts))
        doc["detonations"] = reports
        _emit(json.dumps(doc, indent=2), output)
    else:
        _render(result, fmt, output, verdicts, cfg)
    raise typer.Exit(evaluate_gate(result, verdicts, None, GateConfig(fail_on=None)).exit_code)


# -------------------------------------------------------------------------------------------------- ci
@app.command()
def ci(
    target: Target,
    config: ConfigOpt = None,
    policy: PolicyOpt = None,
    sarif: Annotated[
        Path | None, typer.Option(help="Write SARIF here (upload with github/codeql-action/upload-sarif).")
    ] = Path("skillchain.sarif"),
    json_out: Annotated[Path | None, typer.Option("--json", help="Write the JSON report here.")] = None,
    lock: Annotated[
        Path | None, typer.Option(help="Verify against this lockfile (default: skillchain.lock if present).")
    ] = None,
    require_lock: Annotated[
        bool, typer.Option("--require-lock", help="Fail when a skill is missing from the lockfile.")
    ] = False,
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="Severity threshold for deterministic findings.")
    ] = "high",
    fail_on_heuristic: Annotated[bool, typer.Option("--fail-on-heuristic")] = False,
    fail_on_quarantine: Annotated[bool, typer.Option("--fail-on-quarantine")] = False,
    detonate_: Annotated[
        bool, typer.Option("--detonate", help="Also detonate scripts in the sandbox.")
    ] = False,
    rego: Annotated[Path | None, typer.Option("--rego", help="Use OPA with this .rego policy.")] = None,
) -> None:
    """One-shot CI gate: scan → policy → lock verify → SARIF + annotations → exit code."""
    cfg = ScanConfig.load(target, config)
    scanner = Scanner(cfg)
    result = scanner.scan(target)
    if detonate_:
        from skillchain.sandbox import RunnerConfig
        from skillchain.sandbox import detonate as _detonate

        observed = {
            s.package.name: _detonate(s.package, config=RunnerConfig()).observed for s in result.skills
        }
        result = scanner.scan(target, observed=observed)
    pol = _load_policy(policy)
    lock_path = lock or (Path(LOCK_FILENAME) if Path(LOCK_FILENAME).exists() else None)
    lockfile = Lockfile.load(lock_path) if lock_path and lock_path.exists() else None
    extra = {
        s.package.name: PolicyInput(in_lock=(s.package.name in lockfile.skills) if lockfile else None)
        for s in result.skills
    }
    verdicts = _verdicts(result, pol, rego=rego, extra=extra)
    lock_result = verify_lock(lockfile, result, verdicts) if lockfile else None
    gate = evaluate_gate(
        result,
        verdicts,
        lock_result,
        GateConfig(Severity(fail_on), fail_on_heuristic, fail_on_quarantine, require_lock),
    )
    if sarif:
        _emit(render_sarif(result, registry_for(cfg), base_dir=Path(result.target)), sarif)
    if json_out:
        _emit(render_json(result, verdicts), json_out)
    render_console(result, console, verdicts=verdicts, max_findings=40)
    if lock_result is not None:
        for lr in lock_result.results:
            style = "green" if lr.status.value == "ok" else "red"
            console.print(f"[{style}]lock {lr.status.value}[/{style}] {lr.name} {' '.join(lr.details[:2])}")
    if in_github_actions():
        for s in result.skills:
            for f in s.findings:
                if f.severity >= Severity.MEDIUM:
                    sys.stdout.write(github_annotation(f, Path(s.package.root)) + "\n")
        write_step_summary(render_markdown(result, verdicts))
        set_output("exit-code", str(gate.exit_code))
        set_output("findings", str(len(result.findings)))
        set_output("blocked", str(sum(1 for v in verdicts.values() if v.decision == Decision.BLOCK)))
        set_output("sarif", str(sarif) if sarif else "")
    for reason in gate.reasons:
        err_console.print(f"[red]✖[/red] {reason}")
    if gate.ok:
        err_console.print("[green]✔ skillchain gate passed[/green]")
    raise typer.Exit(gate.exit_code)


# ------------------------------------------------------------------------------------------------ sign
@app.command()
def sign(
    target: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Skill package directory.")],
    key: Annotated[
        Path, typer.Option("--key", "-k", help="Ed25519 private key (PEM). Use `skillchain keys generate`.")
    ],
    publisher: Annotated[
        str | None, typer.Option(help="Publisher identity recorded in the attestation.")
    ] = None,
    policy: PolicyOpt = None,
    log: Annotated[Path | None, typer.Option(help="Append to this transparency log (JSONL).")] = None,
    pack_to: Annotated[
        Path | None, typer.Option("--pack", help="Also write a reproducible .tar.gz here.")
    ] = None,
    sigstore: Annotated[
        bool, typer.Option("--sigstore", help="Additionally sign the attestation keylessly with Sigstore.")
    ] = False,
    cosign: Annotated[
        bool, typer.Option("--cosign", help="Additionally sign the attestation with cosign.")
    ] = False,
    passphrase_env: Annotated[str | None, typer.Option(help="Env var holding the key passphrase.")] = None,
) -> None:
    """Scan, evaluate policy, and sign the package (DSSE/in-toto attestation + optional transparency log entry)."""
    from skillchain.signing import (
        TransparencyLog,
        load_private_key,
        pack,
        sign_package,
        sign_with_cosign,
        sign_with_sigstore,
    )

    passphrase = _passphrase(passphrase_env)
    priv = load_private_key(key, passphrase)
    cfg = ScanConfig.load(target)
    result = Scanner(cfg).scan(target)
    scan_obj = result.skills[0] if result.skills else None
    verdict = _verdicts(result, _load_policy(policy)).get(scan_obj.package.name) if scan_obj else None
    if verdict and verdict.decision == Decision.BLOCK:
        err_console.print(
            f"[red]refusing to sign: policy blocks {verdict.skill}: {'; '.join(verdict.reasons[:3])}[/red]"
        )
        raise typer.Exit(2)
    archive_digest = pack(target, pack_to, include_signature=False) if pack_to else None
    res = sign_package(
        target, priv, publisher=publisher, scan=scan_obj, verdict=verdict, archive_digest=archive_digest
    )
    console.print(f"[green]signed[/green] {target} digest={res.digest} keyid={res.key_id}")
    console.print(f"  attestation: {res.attestation_path}")
    if pack_to:
        console.print(f"  archive: {pack_to} ({archive_digest})")
    if log:
        env = json.loads(res.attestation_path.read_text(encoding="utf-8"))
        entry = TransparencyLog(log).append(
            subject_name=res.statement["subject"][0]["name"],
            subject_digest=res.digest,
            key_id=res.key_id,
            signature_b64=env["signatures"][0]["sig"],
            public_key_pem=env.get("publicKey"),
        )
        console.print(f"  log entry #{entry.index} {entry.hash}")
    if sigstore:
        r = sign_with_sigstore(target)
        console.print(f"  sigstore bundle: {r.bundle_path}")
    if cosign:
        r = sign_with_cosign(target)
        console.print(f"  cosign bundle: {r.bundle_path}")


@app.command()
def verify(
    target: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    trusted_key: Annotated[
        list[Path] | None,
        typer.Option("--trusted-key", "-t", help="Public key(s) that must have signed the package."),
    ] = None,
    log: Annotated[Path | None, typer.Option(help="Require an inclusion in this transparency log.")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f")] = "console",
) -> None:
    """Verify the package digest and signature (and optionally transparency-log inclusion)."""
    from skillchain.signing import TransparencyLog, load_public_key, verify_package

    keys = [load_public_key(p.read_bytes()) for p in (trusted_key or [])]
    res = verify_package(target, trusted_keys=keys or None)
    included = None
    if log:
        tlog = TransparencyLog(log)
        chain_ok, chain_errors = tlog.verify()
        entries = tlog.inclusion(res.digest)
        included = chain_ok and bool(entries)
        if not chain_ok:
            res.errors.extend(chain_errors)
        if not entries:
            res.errors.append("digest not found in transparency log")
    ok = res.ok and (included is not False)
    if fmt == "json":
        sys.stdout.write(
            json.dumps(
                {
                    "ok": ok,
                    "digest": res.digest,
                    "expected": res.expected_digest,
                    "keyid": res.key_id,
                    "publisher": res.publisher,
                    "trusted": res.trusted,
                    "log_included": included,
                    "errors": res.errors,
                },
                indent=2,
            )
            + "\n"
        )
    else:
        console.print(
            ("[green]✔ verified[/green]" if ok else "[red]✖ verification failed[/red]") + f" {target}"
        )
        console.print(f"  digest:    {res.digest}")
        console.print(
            f"  keyid:     {res.key_id or '-'}   publisher: {res.publisher or '-'}   trusted: {res.trusted}"
        )
        if included is not None:
            console.print(f"  log:       {'included' if included else 'NOT included'}")
        for e in res.errors:
            console.print(f"  [red]•[/red] {e}")
    raise typer.Exit(0 if ok else 1)


@app.command()
def pack(
    target: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("skill.tar.gz"),
) -> None:
    """Create a reproducible archive of the package (same bytes for same content)."""
    from skillchain.signing import pack as _pack

    digest = _pack(target, output)
    console.print(f"[green]packed[/green] {output} {digest}")


# ------------------------------------------------------------------------------------------------ keys
@keys_app.command("generate")
def keys_generate(
    out_dir: Annotated[
        Path, typer.Option("--out", "-o", help="Directory for skillchain.key / skillchain.pub")
    ] = Path(".skillchain-keys"),
    name: Annotated[str, typer.Option()] = "skillchain",
    passphrase_env: Annotated[
        str | None, typer.Option(help="Env var holding a passphrase to encrypt the private key.")
    ] = None,
) -> None:
    """Generate an Ed25519 keypair."""
    from skillchain.signing import generate_keypair, write_keypair

    passphrase = _passphrase(passphrase_env)
    pair = generate_keypair(passphrase)
    priv, pub = write_keypair(pair, out_dir, name)
    console.print(
        f"[green]generated[/green] keyid={pair.key_id}\n  private: {priv} (mode 600 — keep secret)\n  public:  {pub}"
    )


# ------------------------------------------------------------------------------------------------- log
@log_app.command("verify")
def log_verify(path: Annotated[Path, typer.Argument(exists=True)]) -> None:
    """Verify the hash chain of a transparency log."""
    from skillchain.signing import TransparencyLog

    ok, errors = TransparencyLog(path).verify()
    for e in errors:
        console.print(f"[red]•[/red] {e}")
    console.print(
        f"[green]✔ chain intact ({len(TransparencyLog(path).entries())} entries)[/green]"
        if ok
        else "[red]✖ chain broken[/red]"
    )
    raise typer.Exit(0 if ok else 1)


@log_app.command("inclusion")
def log_inclusion(
    path: Annotated[Path, typer.Argument(exists=True)],
    digest: Annotated[str, typer.Argument(help="sha256:… tree digest")],
) -> None:
    """Show inclusion proof(s) for a digest."""
    from skillchain.signing import TransparencyLog

    tlog = TransparencyLog(path)
    entries = tlog.inclusion(digest)
    if not entries:
        console.print("[red]not included[/red]")
        raise typer.Exit(1)
    for e in entries:
        sys.stdout.write(json.dumps(tlog.inclusion_proof(e.index), indent=2) + "\n")


@log_app.command("list")
def log_list(path: Annotated[Path, typer.Argument(exists=True)]) -> None:
    """List entries."""
    from skillchain.signing import TransparencyLog

    table = Table("idx", "timestamp", "subject", "digest", "keyid")
    for e in TransparencyLog(path).entries():
        table.add_row(
            str(e.index), e.timestamp, e.subject_name, e.subject_digest[:23] + "…", e.key_id[:20] + "…"
        )
    console.print(table)


# ------------------------------------------------------------------------------------------------ lock
@lock_app.command("generate")
def lock_generate(
    target: Target,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(LOCK_FILENAME),
    config: ConfigOpt = None,
    policy: PolicyOpt = None,
    include_blocked: Annotated[
        bool, typer.Option("--include-blocked", help="Record blocked skills too (as blocked).")
    ] = False,
) -> None:
    """Scan, evaluate policy, and write the lockfile of approved skills."""
    cfg = ScanConfig.load(target, config)
    result = Scanner(cfg).scan(target)
    pol = _load_policy(policy)
    verdicts = _verdicts(result, pol)
    signers: dict[str, LockedSigner] = {}
    from skillchain.signing import verify_package

    for s in result.skills:
        if (s.package.root_path / ".skillchain").is_dir():
            v = verify_package(s.package.root_path)
            if v.ok:
                signers[s.package.name] = LockedSigner(keyid=v.key_id, publisher=v.publisher)
    lock = generate_lock(
        result,
        verdicts,
        base=Path(target).resolve() if Path(target).is_dir() else Path(target).parent.resolve(),
        policy_name=pol.name,
        policy_text=policy.read_text(encoding="utf-8") if policy else None,
        signers=signers,
        include_blocked=include_blocked,
    )
    lock.write(output)
    skipped = [n for n, v in verdicts.items() if v.decision == Decision.BLOCK and not include_blocked]
    console.print(
        f"[green]wrote[/green] {output} with {len(lock.skills)} skill(s)"
        + (f"; skipped blocked: {', '.join(skipped)}" if skipped else "")
    )


@lock_app.command("verify")
def lock_verify_cmd(
    target: Target,
    lock: Annotated[Path, typer.Option("--lock", "-l")] = Path(LOCK_FILENAME),
    config: ConfigOpt = None,
    policy: PolicyOpt = None,
    strict: Annotated[
        bool, typer.Option("--strict", help="Fail on skills missing from the lockfile.")
    ] = False,
) -> None:
    """Verify that the tree matches the lockfile (digests, capabilities, findings)."""
    cfg = ScanConfig.load(target, config)
    result = Scanner(cfg).scan(target)
    lockfile = Lockfile.load(lock)
    verdicts = _verdicts(result, _load_policy(policy))
    ver = verify_lock(lockfile, result, verdicts)
    bad = 0
    for r in ver.results:
        ok = r.status.value == "ok" or (r.status.value == "missing" and not strict)
        bad += 0 if ok else 1
        console.print(
            f"[{'green' if ok else 'red'}]{r.status.value:16}[/{'green' if ok else 'red'}] {r.name}  {'; '.join(r.details[:3])}"
        )
    raise typer.Exit(0 if bad == 0 else 4)


# ----------------------------------------------------------------------------------------------- rules
@rules_app.command("list")
def rules_list(
    config: ConfigOpt = None, fmt: Annotated[str, typer.Option("--format", "-f")] = "console"
) -> None:
    """List all rule IDs with severity, confidence and category."""
    cfg = ScanConfig.load(Path.cwd(), config)
    descs = registry_for(cfg).descriptors()
    from skillchain.capabilities.manifest import MANIFEST_RULE_IDS
    from skillchain.sandbox.detonate import DYN_RULES

    rows = [(d.id, d.title, d.severity.value, d.confidence.value, d.category.value) for d in descs]
    rows += [(rid, t, s.value, "deterministic", "manifest") for rid, t, s in MANIFEST_RULE_IDS]
    rows += [(rid, t, s.value, "deterministic", "sandbox") for rid, (t, s) in DYN_RULES.items()]
    rows.sort()
    if fmt == "json":
        sys.stdout.write(
            json.dumps(
                [
                    dict(zip(("id", "title", "severity", "confidence", "category"), r, strict=True))
                    for r in rows
                ],
                indent=2,
            )
            + "\n"
        )
        return
    table = Table("id", "title", "severity", "confidence", "category")
    for r in rows:
        table.add_row(*r)
    console.print(table)


@rules_app.command("show")
def rules_show(rule_id: str, config: ConfigOpt = None) -> None:
    """Show details for one rule."""
    cfg = ScanConfig.load(Path.cwd(), config)
    d = registry_for(cfg).descriptor(rule_id.upper())
    if d is None:
        err_console.print(f"[red]unknown rule {rule_id}[/red]")
        raise typer.Exit(1)
    console.print(
        f"[bold]{d.id}[/bold] — {d.title}\n{d.description}\n\nseverity: {d.severity.value}   confidence: {d.confidence.value}   category: {d.category.value}"
    )
    if d.remediation:
        console.print(f"remediation: {d.remediation}")
    for ref in d.references:
        console.print(f"ref: {ref}")


@rules_app.command("capabilities")
def rules_capabilities() -> None:
    """List the capability taxonomy."""
    table = Table("capability", "description")
    for k, v in CAPABILITIES.items():
        table.add_row(k, v)
    console.print(table)


# ---------------------------------------------------------------------------------------------- policy
@policy_app.command("validate")
def policy_validate(path: Annotated[Path, typer.Argument(exists=True)]) -> None:
    """Validate a policy YAML file."""
    pol = Policy.load(path)
    console.print(
        f"[green]✔ valid[/green] policy '{pol.name}' with {len(pol.rules)} rule(s), default={pol.default.value}"
    )


@policy_app.command("show-default")
def policy_show_default() -> None:
    """Print the built-in default policy as YAML."""
    import yaml

    from skillchain.policy import DEFAULT_POLICY

    sys.stdout.write(yaml.safe_dump(DEFAULT_POLICY, sort_keys=False))


@policy_app.command("eval")
def policy_eval(
    target: Target,
    policy: PolicyOpt = None,
    config: ConfigOpt = None,
    rego: Annotated[Path | None, typer.Option("--rego")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f")] = "console",
) -> None:
    """Evaluate policy against a scan and print verdicts."""
    cfg = ScanConfig.load(target, config)
    result = Scanner(cfg).scan(target)
    if rego and not opa_available():
        err_console.print("[red]opa binary not found[/red]")
        raise typer.Exit(EXIT_ERROR)
    verdicts = _verdicts(result, _load_policy(policy), rego=rego)
    if fmt == "json":
        sys.stdout.write(
            json.dumps({k: v.model_dump(mode="json") for k, v in verdicts.items()}, indent=2) + "\n"
        )
    else:
        for v in verdicts.values():
            color = {"allow": "green", "quarantine": "yellow", "block": "red"}[v.decision.value]
            console.print(f"[{color}]{v.decision.value:10}[/{color}] {v.skill}  {'; '.join(v.reasons[:3])}")
    worst = max((v.decision.rank for v in verdicts.values()), default=0)
    raise typer.Exit({0: 0, 1: 3, 2: 2}[worst])


# ---------------------------------------------------------------------------------------------- broker
@app.command()
def broker(
    server: Annotated[
        list[str],
        typer.Argument(help="MCP server command, e.g. -- npx -y @modelcontextprotocol/server-github"),
    ],
    policy: Annotated[Path | None, typer.Option("--policy", "-p", help="Broker policy YAML.")] = None,
    lock: Annotated[
        Path | None, typer.Option(help="Take approved capabilities for --skill from this lockfile.")
    ] = None,
    skill: Annotated[
        str | None,
        typer.Option(help="Skill name in the lockfile whose approved capabilities bound this server."),
    ] = None,
    audit: Annotated[
        Path | None, typer.Option(help="Append an audit record per tool call to this JSONL file.")
    ] = None,
    approve_all: Annotated[
        bool, typer.Option("--approve-all", help="Auto-approve quarantined calls (log only). For CI/testing.")
    ] = False,
    deny_all: Annotated[
        bool, typer.Option("--deny-all", help="Deny quarantined calls without prompting (non-interactive).")
    ] = False,
) -> None:
    """Proxy an MCP stdio server, enforcing per-call permissions and alerting on behaviour drift."""
    from skillchain.broker import Broker, BrokerPolicy, CallDecision

    pol = BrokerPolicy.load(policy) if policy else BrokerPolicy()
    if lock and skill:
        lf = Lockfile.load(lock)
        locked = lf.skills.get(skill)
        if locked is None:
            err_console.print(f"[red]{skill} not in {lock}[/red]")
            raise typer.Exit(1)
        pol = pol.model_copy(update={"approved_capabilities": list(locked.capabilities)})

    def ask(d: CallDecision, args: dict[str, Any]) -> bool:
        if approve_all:
            return True
        if deny_all or not sys.stderr.isatty():
            return False
        err_console.print(
            f"[yellow]⚠ {d.tool}[/yellow] → {', '.join(d.capabilities)}  ({'; '.join(d.reasons)})"
        )
        err_console.print(f"  args: {json.dumps(args)[:300]}")
        return typer.confirm("  allow this call?", default=False, err=True)

    code = Broker(server, pol, approver=ask, audit_log=audit).run()
    raise typer.Exit(code)


def main() -> None:  # pragma: no cover - thin wrapper
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
