from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillfuse.core.models import Confidence, Decision, ScanResult
from skillfuse.policy import Policy, PolicyEngine, PolicyInput
from skillfuse.policy.opa import (
    OpaUnavailableError,
    evaluate_with_opa,
    opa_available,
    opa_input,
    parse_opa_output,
)


def _skill(result: ScanResult, name: str):  # type: ignore[no-untyped-def]
    return next(s for s in result.skills if s.package.name == name)


class TestDefaultPolicy:
    def test_verdicts_on_corpus(self, corpus_result: ScanResult) -> None:
        eng = PolicyEngine()
        v = {s.package.name: eng.evaluate(s) for s in corpus_result.skills}
        assert v["helpful-formatter"].decision == Decision.BLOCK
        assert v["persistence-helper"].decision == Decision.BLOCK
        assert v["trojan-source"].decision == Decision.BLOCK
        assert v["sneaky-reviewer"].decision == Decision.BLOCK
        assert v["malicious/mcp.json"].decision == Decision.BLOCK
        assert v["changelog-writer"].decision == Decision.ALLOW
        assert v["code-reviewer"].decision == Decision.ALLOW
        assert v[".vscode/mcp.json"].decision == Decision.ALLOW
        assert all(v[n].reasons for n in v)

    def test_heuristics_never_block_by_default(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "sneaky-reviewer")
        only_heuristic = skill.model_copy(
            update={"findings": tuple(f for f in skill.findings if f.confidence == Confidence.HEURISTIC)}
        )
        verdict = PolicyEngine().evaluate(only_heuristic)
        assert verdict.decision != Decision.BLOCK
        assert verdict.decision == Decision.QUARANTINE  # high heuristic -> quarantine

    def test_heuristic_can_block_flag(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "sneaky-reviewer")
        only_heuristic = skill.model_copy(
            update={"findings": tuple(f for f in skill.findings if f.confidence == Confidence.HEURISTIC)}
        )
        pol = Policy.model_validate(
            {
                "heuristic_can_block": True,
                "rules": [{"name": "b", "action": "block", "when": {"findings": {"min_severity": "high"}}}],
            }
        )
        assert PolicyEngine(pol).evaluate(only_heuristic).decision == Decision.BLOCK


class TestPolicyRules:
    def test_load_validate_show(self, tmp_path: Path) -> None:
        p = tmp_path / "p.yaml"
        p.write_text("name: t\ndefault: quarantine\nrules: []\n")
        pol = Policy.load(p)
        assert pol.default == Decision.QUARANTINE
        p.write_text("- list")
        with pytest.raises(ValueError, match="mapping"):
            Policy.load(p)
        p.write_text("unknown: 1")
        with pytest.raises(Exception):  # noqa: B017
            Policy.load(p)

    def test_publisher_lists(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "changelog-writer").model_copy(
            update={
                "package": _skill(corpus_result, "changelog-writer").package.model_copy(
                    update={"publisher": "evil-corp"}
                )
            }
        )
        pol = Policy.model_validate({"publishers": {"block": ["evil-*"]}})
        v = PolicyEngine(pol).evaluate(skill)
        assert v.decision == Decision.BLOCK
        assert "publishers.block" in v.matched_rules
        pol = Policy.model_validate({"publishers": {"allow": ["evil-*"]}})
        assert "publishers.allow" in PolicyEngine(pol).evaluate(skill).matched_rules

    def test_capability_lists(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "changelog-writer")
        pol = Policy.model_validate({"capabilities": {"deny": ["git"]}})
        # git.read is weak (prose) for changelog-writer -> deny lists only consider strong caps
        assert PolicyEngine(pol).evaluate(skill).decision == Decision.ALLOW
        strong = skill.model_copy(update={"inferred": skill.inferred.model_copy(update={"weak": ()})})
        assert PolicyEngine(pol).evaluate(strong).decision == Decision.BLOCK
        pol = Policy.model_validate({"capabilities": {"quarantine": ["git.read"]}})
        assert PolicyEngine(pol).evaluate(strong).decision == Decision.QUARANTINE

    def test_rule_id_lists(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "trojan-source")
        pol = Policy.model_validate({"rule_ids": {"block": ["SC-HID-*"]}})
        assert PolicyEngine(pol).evaluate(skill).decision == Decision.BLOCK
        pol = Policy.model_validate({"rule_ids": {"quarantine": ["SC-HID-*"]}})
        assert PolicyEngine(pol).evaluate(skill).decision == Decision.QUARANTINE
        pol = Policy.model_validate({"rule_ids": {"ignore": ["SC-*"]}})
        assert PolicyEngine(pol).evaluate(skill).decision == Decision.ALLOW

    def test_when_conditions(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "helpful-formatter")
        eng = PolicyEngine(
            Policy.model_validate({"rules": [{"name": "k", "action": "block", "when": {"kinds": ["agent"]}}]})
        )
        assert eng.evaluate(skill).decision == Decision.ALLOW
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {"name": "k", "action": "block", "when": {"kinds": ["skill"], "names": ["helpful-*"]}}
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.BLOCK
        eng = PolicyEngine(
            Policy.model_validate(
                {"rules": [{"name": "s", "action": "quarantine", "when": {"signed": False}}]}
            )
        )
        assert eng.evaluate(skill, PolicyInput(signed=False)).decision == Decision.QUARANTINE
        assert eng.evaluate(skill, PolicyInput(signed=True)).decision == Decision.ALLOW
        assert eng.evaluate(skill).decision == Decision.ALLOW  # unknown -> no match
        eng = PolicyEngine(
            Policy.model_validate({"rules": [{"name": "l", "action": "block", "when": {"in_lock": False}}]})
        )
        assert eng.evaluate(skill, PolicyInput(in_lock=False)).decision == Decision.BLOCK
        eng = PolicyEngine(
            Policy.model_validate(
                {"rules": [{"name": "p", "action": "block", "when": {"publisher_missing": True}}]}
            )
        )
        assert eng.evaluate(skill).decision == Decision.BLOCK
        eng = PolicyEngine(
            Policy.model_validate(
                {"rules": [{"name": "p", "action": "block", "when": {"publisher": ["acme"]}}]}
            )
        )
        assert eng.evaluate(skill).decision == Decision.ALLOW
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {
                            "name": "c",
                            "action": "quarantine",
                            "when": {"capabilities": {"any": ["network.egress"], "none": ["jira.write"]}},
                        }
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.QUARANTINE
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {
                            "name": "c",
                            "action": "quarantine",
                            "when": {"capabilities": {"all": ["network.egress", "jira.write"]}},
                        }
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.ALLOW
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {
                            "name": "f",
                            "action": "quarantine",
                            "when": {
                                "findings": {
                                    "categories": ["hidden-content"],
                                    "rule_ids": ["SC-HID-001"],
                                    "min_count": 1,
                                }
                            },
                        }
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.QUARANTINE
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {
                            "name": "f",
                            "action": "quarantine",
                            "when": {"findings": {"min_severity": "critical", "min_count": 99}},
                        }
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.ALLOW

    def test_final_rule_short_circuits(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "helpful-formatter")
        pol = Policy.model_validate(
            {
                "rules": [
                    {"name": "trusted", "action": "allow", "final": True, "when": {"kinds": ["skill"]}},
                    {"name": "b", "action": "block", "when": {"findings": {"min_severity": "info"}}},
                ]
            }
        )
        v = PolicyEngine(pol).evaluate(skill)
        assert v.decision == Decision.ALLOW
        assert "final" in v.reasons[0]

    def test_undeclared_condition_variants(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "persistence-helper")
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {
                            "name": "u",
                            "action": "block",
                            "when": {"undeclared_capabilities": ["system.persistence"]},
                        }
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.BLOCK
        eng = PolicyEngine(
            Policy.model_validate(
                {
                    "rules": [
                        {"name": "u", "action": "block", "when": {"undeclared_capabilities": ["jira.write"]}}
                    ]
                }
            )
        )
        assert eng.evaluate(skill).decision == Decision.ALLOW
        eng = PolicyEngine(
            Policy.model_validate(
                {"rules": [{"name": "u", "action": "block", "when": {"undeclared_capabilities": False}}]}
            )
        )
        assert eng.evaluate(skill).decision == Decision.ALLOW

    def test_default_decision_when_nothing_matches(self, corpus_result: ScanResult) -> None:
        skill = _skill(corpus_result, "changelog-writer")
        v = PolicyEngine(Policy.model_validate({"default": "quarantine"})).evaluate(skill)
        assert v.decision == Decision.QUARANTINE
        assert v.reasons == ("no policy rule matched",)


class TestOpa:
    def test_input_shape(self, corpus_result: ScanResult) -> None:
        doc = opa_input(corpus_result.skills[0], signed=True, in_lock=False)
        assert doc["signed"] is True
        assert "findings" in doc

    def test_parse_output(self) -> None:
        out = json.dumps({"result": [{"expressions": [{"value": {"decision": "block", "reasons": ["x"]}}]}]})
        v = parse_opa_output("s", out)
        assert v.decision == Decision.BLOCK
        assert v.reasons == ("x",)
        with pytest.raises(RuntimeError, match="shape"):
            parse_opa_output("s", json.dumps({"result": []}))

    def test_unavailable(self, corpus_result: ScanResult, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr("shutil.which", lambda _n: None)
        assert not opa_available()
        with pytest.raises(OpaUnavailableError):
            evaluate_with_opa(corpus_result.skills[0], tmp_path / "p.rego")

    def test_subprocess_path(self, corpus_result: ScanResult, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import subprocess

        monkeypatch.setattr("shutil.which", lambda _n: "/bin/fake-opa")
        out = json.dumps(
            {"result": [{"expressions": [{"value": {"decision": "quarantine", "reasons": ["r"]}}]}]}
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, out, ""))
        v = evaluate_with_opa(corpus_result.skills[0], tmp_path / "p.rego")
        assert v.decision == Decision.QUARANTINE
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "bad rego")
        )
        with pytest.raises(RuntimeError, match="opa eval failed"):
            evaluate_with_opa(corpus_result.skills[0], tmp_path / "p.rego")
