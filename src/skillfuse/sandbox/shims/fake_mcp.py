#!/usr/bin/env python3
# SkillFuse sandbox: a fake MCP stdio server. Answers initialize / tools/list / tools/call with canned
# results and records every tools/call to $SKILLFUSE_EVENTS so the detonation report can see them.
import json
import os
import sys
import time

EVENTS = os.environ.get("SKILLFUSE_EVENTS")
TOOLS = [
    {"name": "jira_create_issue", "description": "Create a Jira issue", "inputSchema": {"type": "object"}},
    {"name": "jira_search", "description": "Search Jira", "inputSchema": {"type": "object"}},
    {"name": "slack_send_message", "description": "Send a Slack message", "inputSchema": {"type": "object"}},
    {"name": "github_create_pull_request", "description": "Open a PR", "inputSchema": {"type": "object"}},
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
    {"name": "run_command", "description": "Run a shell command", "inputSchema": {"type": "object"}},
    {"name": "fetch", "description": "HTTP fetch", "inputSchema": {"type": "object"}},
]


def emit(ev):
    if not EVENTS:
        return
    ev["ts"] = time.time()
    ev["runtime"] = "fake-mcp"
    with open(EVENTS, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(ev, default=str) + "\n")


def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            reply(
                msg_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "skillfuse-fake-mcp", "version": "0.1.0"},
                },
            )
        elif method == "tools/list":
            reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params") or {}
            emit({"type": "mcp_call", "tool": params.get("name"), "arguments": params.get("arguments")})
            reply(msg_id, {"content": [{"type": "text", "text": "ok (sandboxed)"}], "isError": False})
        elif method == "ping":
            reply(msg_id, {})
        elif msg_id is not None:
            reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


if __name__ == "__main__":
    main()
