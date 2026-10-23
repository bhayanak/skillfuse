from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from skillfuse.broker import Broker, BrokerPolicy, BrokerStats, decide
from skillfuse.core.models import Decision


class TestDecide:
    def test_defaults(self) -> None:
        pol = BrokerPolicy()
        st = BrokerStats()
        assert decide("readFile", {}, pol, st).decision == Decision.ALLOW
        d = decide("editFiles", {}, pol, st)
        assert d.decision == Decision.QUARANTINE and "requires approval" in d.reasons
        assert decide("mcp_atlassian_transitionJiraIssue", {}, pol, st).decision == Decision.QUARANTINE
        assert decide("totally_unknown", {}, pol, st).capabilities == ("mcp.tools",)

    def test_deny_and_allow_lists(self) -> None:
        pol = BrokerPolicy(
            deny_tools=["*delete*"], allow_tools=["editFiles"], deny_capabilities=["jira.write"]
        )
        st = BrokerStats()
        assert decide("deleteFile", {}, pol, st).decision == Decision.BLOCK
        assert decide("editFiles", {}, pol, st).decision == Decision.ALLOW
        assert decide("mcp_atlassian_editJiraIssue", {}, pol, st).decision == Decision.BLOCK

    def test_secret_arguments_blocked(self) -> None:
        pol = BrokerPolicy()
        d = decide("readFile", {"content": "ghp_" + "A" * 36}, pol, BrokerStats())
        assert d.decision == Decision.BLOCK and "credential" in d.reasons[0]
        assert (
            decide(
                "readFile",
                {"content": "ghp_" + "A" * 36},
                BrokerPolicy(block_secret_arguments=False),
                BrokerStats(),
            ).decision
            == Decision.ALLOW
        )

    def test_drift(self) -> None:
        pol = BrokerPolicy(approved_capabilities=["filesystem.read"], ask_capabilities=[])
        st = BrokerStats()
        ok = decide("readFile", {}, pol, st)
        assert ok.decision == Decision.ALLOW and not ok.drift
        d = decide("fetch", {}, pol, st)
        assert d.drift and d.decision == Decision.QUARANTINE
        d2 = decide("fetch", {}, pol.model_copy(update={"drift_is_quarantine": False}), st)
        assert d2.drift and d2.decision == Decision.ALLOW
        # allow list does not override drift
        assert (
            decide("fetch", {}, pol.model_copy(update={"allow_tools": ["fetch"]}), st).decision
            == Decision.QUARANTINE
        )

    def test_rate_limit(self) -> None:
        pol = BrokerPolicy(max_calls_per_minute=2)
        st = BrokerStats()
        import time

        st.timestamps = [time.monotonic(), time.monotonic()]
        assert decide("readFile", {}, pol, st).decision == Decision.BLOCK

    def test_load(self, tmp_path: Path) -> None:
        p = tmp_path / "b.yaml"
        p.write_text("deny_tools: ['*rm*']\nmax_calls_per_minute: 5\n")
        pol = BrokerPolicy.load(p)
        assert pol.deny_tools == ["*rm*"] and pol.max_calls_per_minute == 5


class TestBrokerMessages:
    def _broker(self, pol: BrokerPolicy, approve: bool, tmp_path: Path, alerts: list[str]) -> Broker:
        return Broker(
            ["true"],
            pol,
            approver=lambda _d, _a: approve,
            audit_log=tmp_path / "audit.jsonl",
            alert=alerts.append,
        )

    def test_non_tool_messages_pass_through(self, tmp_path: Path) -> None:
        b = self._broker(BrokerPolicy(), False, tmp_path, [])
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert b.handle_host_message(raw) == (raw, None)
        assert b.handle_host_message("garbage") == ("garbage", None)

    def test_allow_deny_and_audit(self, tmp_path: Path) -> None:
        alerts: list[str] = []
        b = self._broker(BrokerPolicy(approved_capabilities=["filesystem.read"]), False, tmp_path, alerts)
        ok = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "readFile", "arguments": {"p": "x"}},
            }
        )
        fwd, reply = b.handle_host_message(ok)
        assert fwd == ok and reply is None
        bad = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "editFiles", "arguments": {}},
            }
        )
        fwd, reply = b.handle_host_message(bad)
        assert fwd is None and reply is not None
        err = json.loads(reply)
        assert err["id"] == 2 and err["error"]["code"] == -32001
        assert "filesystem.write" in err["error"]["data"]["capabilities"]
        assert alerts and "DRIFT" in alerts[0]
        assert (
            b.stats.calls == 2
            and b.stats.allowed == 1
            and b.stats.denied == 1
            and b.stats.asked == 1
            and b.stats.drift_alerts == 1
        )
        assert b.stats.per_tool == {"readFile": 1, "editFiles": 1}
        records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert [r["decision"] for r in records] == ["allow", "block"]

    def test_approver_allows(self, tmp_path: Path) -> None:
        b = self._broker(BrokerPolicy(), True, tmp_path, [])
        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "runCommands", "arguments": {}},
            }
        )
        fwd, reply = b.handle_host_message(msg)
        assert fwd == msg and reply is None and b.stats.asked == 1


@pytest.mark.skipif(sys.platform == "win32", reason="posix only")
def test_broker_run_end_to_end(tmp_path: Path) -> None:
    """Drive the broker against the bundled fake MCP server."""
    from skillfuse.sandbox.runner import SHIMS_DIR

    events = tmp_path / "ev.jsonl"
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "x"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"cmd": "ls"}},
        },
    ]
    host_in = io.StringIO("\n".join(json.dumps(m) for m in msgs) + "\n")
    host_out = io.StringIO()
    import os

    os.environ["SKILLFUSE_EVENTS"] = str(events)
    try:
        broker = Broker(
            [sys.executable, str(SHIMS_DIR / "fake_mcp.py")],
            BrokerPolicy(),
            approver=lambda _d, _a: False,
            host_in=host_in,
            host_out=host_out,
            alert=lambda _m: None,
        )
        code = broker.run()
    finally:
        os.environ.pop("SKILLFUSE_EVENTS", None)
    assert code == 0
    out = [json.loads(line) for line in host_out.getvalue().splitlines()]
    by_id = {o.get("id"): o for o in out}
    assert "result" in by_id[1]
    assert "result" in by_id[2]  # read_file allowed and answered by the server
    assert "error" in by_id[3]  # run_command denied by broker
    assert broker.stats.denied == 1
    recorded = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
    assert all(r["tool"] != "run_command" for r in recorded), "denied call must never reach the server"
