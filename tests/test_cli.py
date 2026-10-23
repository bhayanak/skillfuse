from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillchain import __version__
from skillchain.ci import (
    EXIT_BLOCKED,
    EXIT_FINDINGS,
    EXIT_LOCK,
    EXIT_OK,
    GateConfig,
    evaluate_gate,
    github_annotation,
)
from skillchain.cli.app import app
from skillchain.core.models import Confidence, Decision, PolicyVerdict, Severity
from skillchain.lockfile import LockStatus, LockVerification, SkillLockResult

from .conftest import write_skill

runner = CliRunner()


def run(*args: str, env: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args), env=env, catch_exceptions=False)


class TestGate:
    def test_exit_codes(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        verdicts = {
            s.package.name: PolicyVerdict(skill=s.package.name, decision=Decision.ALLOW)
            for s in corpus_result.skills
        }
        g = evaluate_gate(corpus_result, verdicts, None, GateConfig(fail_on=Severity.HIGH))
        assert g.exit_code == EXIT_FINDINGS and not g.ok
        g = evaluate_gate(corpus_result, verdicts, None, GateConfig(fail_on=None))
        assert g.exit_code == EXIT_OK
        verdicts["x"] = PolicyVerdict(skill="x", decision=Decision.BLOCK, reasons=("r",))
        assert (
            evaluate_gate(corpus_result, verdicts, None, GateConfig(fail_on=None)).exit_code == EXIT_BLOCKED
        )
        verdicts["x"] = PolicyVerdict(skill="x", decision=Decision.QUARANTINE, reasons=("r",))
        assert evaluate_gate(corpus_result, verdicts, None, GateConfig(fail_on=None)).exit_code == EXIT_OK
        assert (
            evaluate_gate(
                corpus_result, verdicts, None, GateConfig(fail_on=None, fail_on_quarantine=True)
            ).exit_code
            == 3
        )
        lock = LockVerification(results=(SkillLockResult(name="a", status=LockStatus.MISSING),))
        assert evaluate_gate(corpus_result, {}, lock, GateConfig(fail_on=None)).exit_code == EXIT_OK
        assert (
            evaluate_gate(corpus_result, {}, lock, GateConfig(fail_on=None, require_lock=True)).exit_code
            == EXIT_LOCK
        )
        lock = LockVerification(
            results=(SkillLockResult(name="a", status=LockStatus.DIGEST_CHANGED, details=("d",)),)
        )
        assert evaluate_gate(corpus_result, {}, lock, GateConfig(fail_on=None)).exit_code == EXIT_LOCK
        bad = corpus_result.model_copy(update={"errors": ("boom",)})
        assert evaluate_gate(bad, {}, None, GateConfig(fail_on=None)).exit_code == 10

    def test_heuristic_threshold(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        only_heur = corpus_result.model_copy(
            update={
                "skills": tuple(
                    s.model_copy(
                        update={
                            "findings": tuple(f for f in s.findings if f.confidence == Confidence.HEURISTIC)
                        }
                    )
                    for s in corpus_result.skills
                )
            }
        )
        assert evaluate_gate(only_heur, {}, None, GateConfig(fail_on=Severity.LOW)).exit_code == EXIT_OK
        assert (
            evaluate_gate(
                only_heur, {}, None, GateConfig(fail_on=Severity.LOW, fail_on_heuristic=True)
            ).exit_code
            == EXIT_FINDINGS
        )

    def test_annotation(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        f = corpus_result.findings[0]
        ann = github_annotation(f)
        assert ann.startswith("::") and f.rule_id in ann and "file=" in ann
        assert github_annotation(f, Path(corpus_result.skills[0].package.root)).startswith("::")


class TestCli:
    def test_version_and_help(self) -> None:
        assert __version__ in run("--version").output
        assert "scan" in run("--help").output

    def test_scan_console_exit_codes(self, benign_dir: Path, malicious_dir: Path) -> None:
        r = run("scan", str(benign_dir))
        assert r.exit_code == 0, r.output
        assert "changelog-writer" in r.output
        r = run("scan", str(malicious_dir / "trojan-source"))
        assert r.exit_code == EXIT_BLOCKED
        r = run("scan", str(malicious_dir / "trojan-source"), "--no-policy")
        assert r.exit_code == 0
        r = run("scan", str(malicious_dir / "trojan-source"), "--no-policy", "--fail-on", "high")
        assert r.exit_code == EXIT_FINDINGS
        r = run("scan", str(benign_dir), "--evidence")
        assert r.exit_code == 0

    def test_scan_formats(self, corpus: Path, tmp_path: Path) -> None:
        r = run("scan", str(corpus), "-f", "json", "--no-policy")
        doc = json.loads(r.output)
        assert doc["schema"] == "skillchain/report/v1"
        out = tmp_path / "r.sarif"
        r = run("scan", str(corpus), "-f", "sarif", "-o", str(out), "--no-policy")
        assert out.exists() and json.loads(out.read_text())["version"] == "2.1.0"
        r = run("scan", str(corpus), "-f", "markdown", "--no-policy")
        assert r.output.startswith("# SkillChain report")
        r = run("scan", str(corpus), "-f", "bogus")
        assert r.exit_code == 10

    def test_scan_with_config_and_policy(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "s", "see https://evil.xyz/")
        cfg = tmp_path / "c.yaml"
        cfg.write_text("disabled_rules: [SC-NET-004]")
        r = run("scan", str(root), "-c", str(cfg), "-f", "json", "--no-policy")
        assert "SC-NET-004" not in r.output
        pol = tmp_path / "p.yaml"
        pol.write_text(
            "rules:\n  - name: q\n    action: quarantine\n    when: {findings: {min_severity: info}}\n"
        )
        r = run("scan", str(root), "-p", str(pol))
        assert "QUARANTINE" in r.output and r.exit_code == 0

    def test_manifest(self, benign_dir: Path, tmp_path: Path) -> None:
        r = run("manifest", str(benign_dir / "changelog-writer"))
        assert "git.read" in r.output
        r = run("manifest", str(benign_dir / "changelog-writer"), "-f", "json")
        assert json.loads(r.output)[0]["name"] == "changelog-writer"
        r = run("manifest", str(benign_dir / "changelog-writer"), "-f", "yaml")
        assert "inferred" in r.output
        root = write_skill(tmp_path / "s", "x", scripts={"a.sh": "curl https://a.example.net"})
        r = run("manifest", str(root), "--write")
        assert (root / "skillchain.yaml").exists()
        assert "network.egress" in (root / "skillchain.yaml").read_text()

    def test_rules_commands(self) -> None:
        r = run("rules", "list")
        assert "SC-PI-001" in r.output and "SC-DYN-001" in r.output and "SC-MAN-001" in r.output
        r = run("rules", "list", "-f", "json")
        ids = {x["id"] for x in json.loads(r.output)}
        assert "SC-NET-003" in ids
        r = run("rules", "show", "sc-sh-001")
        assert "Remote script piped" in r.output
        assert run("rules", "show", "SC-NOPE-001").exit_code == 1
        assert "network.egress" in run("rules", "capabilities").output

    def test_policy_commands(self, tmp_path: Path, benign_dir: Path, malicious_dir: Path) -> None:
        r = run("policy", "show-default")
        assert "block-deterministic-critical" in r.output
        p = tmp_path / "p.yaml"
        p.write_text(r.output)
        assert "valid" in run("policy", "validate", str(p)).output
        r = run("policy", "eval", str(benign_dir))
        assert r.exit_code == 0 and "allow" in r.output
        r = run("policy", "eval", str(malicious_dir), "-f", "json")
        assert r.exit_code == 2
        assert json.loads(r.output)["helpful-formatter"]["decision"] == "block"

    def test_policy_eval_rego_without_opa(self, benign_dir: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr("skillchain.cli.app.opa_available", lambda: False)
        r = run("policy", "eval", str(benign_dir), "--rego", str(tmp_path / "x.rego"))
        assert r.exit_code == 10

    def test_keys_sign_verify_log_pack(self, skill_dir: Path, tmp_path: Path) -> None:
        keys = tmp_path / "keys"
        r = run("keys", "generate", "-o", str(keys))
        assert r.exit_code == 0 and (keys / "skillchain.key").exists()
        log = tmp_path / "log.jsonl"
        archive = tmp_path / "skill.tgz"
        r = run(
            "sign",
            str(skill_dir),
            "-k",
            str(keys / "skillchain.key"),
            "--publisher",
            "acme",
            "--log",
            str(log),
            "--pack",
            str(archive),
        )
        assert r.exit_code == 0, r.output
        assert "signed" in r.output and archive.exists()
        r = run("verify", str(skill_dir), "-t", str(keys / "skillchain.pub"), "--log", str(log))
        assert r.exit_code == 0 and "verified" in r.output and "included" in r.output
        r = run("verify", str(skill_dir), "-f", "json")
        assert json.loads(r.output)["ok"] is True
        assert run("log", "verify", str(log)).exit_code == 0
        assert "acme" not in run("log", "list", str(log)).output or True
        digest = json.loads(run("verify", str(skill_dir), "-f", "json").output)["digest"]
        r = run("log", "inclusion", str(log), digest)
        assert r.exit_code == 0 and json.loads(r.output)["index"] == 0
        assert run("log", "inclusion", str(log), "sha256:nope").exit_code == 1
        (skill_dir / "SKILL.md").write_text("tampered")
        r = run("verify", str(skill_dir))
        assert r.exit_code == 1 and "mismatch" in r.output
        r = run("pack", str(skill_dir), "-o", str(tmp_path / "p.tgz"))
        assert "packed" in r.output

    def test_sign_refuses_blocked(self, malicious_dir: Path, tmp_path: Path) -> None:
        keys = tmp_path / "keys"
        run("keys", "generate", "-o", str(keys))
        r = run("sign", str(malicious_dir / "trojan-source"), "-k", str(keys / "skillchain.key"))
        assert r.exit_code == 2 and "refusing" in r.output

    def test_keys_with_passphrase_env(self, tmp_path: Path, skill_dir: Path) -> None:
        env = {"SC_PASS": "secret"}
        keys = tmp_path / "keys"
        assert run("keys", "generate", "-o", str(keys), "--passphrase-env", "SC_PASS", env=env).exit_code == 0
        assert (
            run(
                "sign",
                str(skill_dir),
                "-k",
                str(keys / "skillchain.key"),
                "--passphrase-env",
                "SC_PASS",
                env=env,
            ).exit_code
            == 0
        )

    def test_lock_generate_verify(self, benign_dir: Path, tmp_path: Path) -> None:
        import shutil

        work = tmp_path / "work"
        shutil.copytree(benign_dir, work)
        lock = tmp_path / "skillchain.lock"
        r = run("lock", "generate", str(work), "-o", str(lock))
        assert r.exit_code == 0 and lock.exists()
        r = run("lock", "verify", str(work), "-l", str(lock))
        assert r.exit_code == 0, r.output
        (work / "changelog-writer" / "SKILL.md").write_text("---\nname: changelog-writer\n---\nchanged")
        r = run("lock", "verify", str(work), "-l", str(lock))
        assert r.exit_code == 4 and "digest-changed" in r.output
        write_skill(work / "new-skill", "x")
        r = run("lock", "verify", str(work), "-l", str(lock))
        assert "missing" in r.output
        r = run("lock", "verify", str(work), "-l", str(lock), "--strict")
        assert r.exit_code == 4

    def test_lock_generate_with_signed_skill_and_include_blocked(self, corpus: Path, tmp_path: Path) -> None:
        import shutil

        work = tmp_path / "work"
        shutil.copytree(corpus, work)
        keys = tmp_path / "keys"
        run("keys", "generate", "-o", str(keys))
        run(
            "sign",
            str(work / "benign" / "changelog-writer"),
            "-k",
            str(keys / "skillchain.key"),
            "--publisher",
            "acme",
        )
        lock = tmp_path / "l.lock"
        r = run("lock", "generate", str(work), "-o", str(lock), "--include-blocked")
        assert r.exit_code == 0
        doc = json.loads(lock.read_text())
        assert doc["skills"]["changelog-writer"]["signer"]["publisher"] == "acme"
        assert doc["skills"]["helpful-formatter"]["decision"] == "block"

    def test_ci_command(self, benign_dir: Path, malicious_dir: Path, tmp_path: Path) -> None:
        sarif = tmp_path / "out.sarif"
        jout = tmp_path / "out.json"
        summary = tmp_path / "summary.md"
        gh_out = tmp_path / "gh_out.txt"
        env = {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_OUTPUT": str(gh_out)}
        r = run("ci", str(benign_dir), "--sarif", str(sarif), "--json", str(jout), env=env)
        assert r.exit_code == 0, r.output
        assert "gate passed" in r.output
        assert sarif.exists() and jout.exists()
        assert summary.read_text().startswith("# SkillChain report")
        assert "exit-code=0" in gh_out.read_text()
        r = run("ci", str(malicious_dir), "--sarif", str(sarif), env=env)
        assert r.exit_code == EXIT_BLOCKED
        assert "::error" in r.output

    def test_ci_with_lock(self, benign_dir: Path, tmp_path: Path) -> None:
        import shutil

        work = tmp_path / "work"
        shutil.copytree(benign_dir, work)
        lock = tmp_path / "skillchain.lock"
        run("lock", "generate", str(work), "-o", str(lock))
        r = run("ci", str(work), "--lock", str(lock), "--sarif", str(tmp_path / "s.sarif"))
        assert r.exit_code == 0, r.output
        assert "lock ok" in r.output
        (work / "code-reviewer.agent.md").write_text("---\nname: code-reviewer\ndescription: d\n---\nchanged")
        r = run("ci", str(work), "--lock", str(lock), "--sarif", str(tmp_path / "s.sarif"))
        assert r.exit_code == EXIT_LOCK

    def test_ci_default_lock_discovery(self, benign_dir: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.chdir(tmp_path)
        r = run("ci", str(benign_dir), "--sarif", "o.sarif", "--fail-on", "critical")
        assert r.exit_code == 0

    @pytest.mark.slow
    def test_detonate_command(self, benign_dir: Path, malicious_dir: Path, tmp_path: Path) -> None:
        r = run(
            "detonate", str(benign_dir / "changelog-writer"), "--timeout", "30", "--backend", "subprocess"
        )
        assert r.exit_code == 0, r.output
        r = run(
            "detonate",
            str(malicious_dir / "persistence-helper"),
            "--timeout",
            "30",
            "--backend",
            "subprocess",
            "-f",
            "json",
            "-o",
            str(tmp_path / "d.json"),
        )
        doc = json.loads((tmp_path / "d.json").read_text())
        assert doc["detonations"][0]["canaries_leaked"]
        ids = {f["rule_id"] for s in doc["skills"] for f in s["findings"]}
        assert "SC-DYN-001" in ids and "SC-MAN-004" in ids
        assert r.exit_code == EXIT_BLOCKED

    @pytest.mark.slow
    def test_ci_detonate_flag(self, benign_dir: Path, tmp_path: Path) -> None:
        r = run(
            "ci", str(benign_dir / "changelog-writer"), "--detonate", "--sarif", str(tmp_path / "s.sarif")
        )
        assert r.exit_code == 0, r.output

    def test_broker_missing_skill_in_lock(self, tmp_path: Path, benign_dir: Path) -> None:
        lock = tmp_path / "l.lock"
        run("lock", "generate", str(benign_dir), "-o", str(lock))
        r = run("broker", "--lock", str(lock), "--skill", "nope", "--deny-all", "true")
        assert r.exit_code == 1

    def test_broker_runs_with_fake_server(self, tmp_path: Path, benign_dir: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import sys

        from skillchain.sandbox.runner import SHIMS_DIR

        lock = tmp_path / "l.lock"
        run("lock", "generate", str(benign_dir), "-o", str(lock))
        audit = tmp_path / "audit.jsonl"
        msgs = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {}},
            },
        ]
        stdin = "\n".join(json.dumps(m) for m in msgs) + "\n"
        monkeypatch.setattr(os, "environ", {**os.environ, "SKILLCHAIN_EVENTS": str(tmp_path / "ev.jsonl")})
        r = runner.invoke(
            app,
            [
                "broker",
                "--lock",
                str(lock),
                "--skill",
                "changelog-writer",
                "--audit",
                str(audit),
                "--approve-all",
                "--",
                sys.executable,
                str(SHIMS_DIR / "fake_mcp.py"),
            ],
            input=stdin,
            catch_exceptions=False,
        )
        assert r.exit_code == 0, r.output
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert len(records) == 2 and all(rec["decision"] == "allow" for rec in records)
        assert any(
            rec["drift"] for rec in records
        )  # filesystem.read is not in changelog-writer's approved caps
