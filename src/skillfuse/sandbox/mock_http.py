"""Mock HTTP recorder: accepts anything, logs method/path/headers/body, replies 200."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _Handler(BaseHTTPRequestHandler):
    events_path: Path | None = None
    server_version = "skillfuse-mock/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 1 << 20)) if length else b""
        host = self.headers.get("X-Skillfuse-Host") or self.headers.get("Host")
        if self.command == "CONNECT":
            host = self.path  # proxied TLS: the destination is the request target
        ev = {
            "type": "http",
            "runtime": "mock-http",
            "ts": time.time(),
            "method": self.command,
            "path": self.path,
            "host": host,
            "headers": {k: v for k, v in self.headers.items() if k.lower() not in {"content-length"}},
            "data": body.decode("utf-8", "replace")[:8000],
        }
        if self.events_path is not None:
            with self.events_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev) + "\n")
        # Empty 200 so `curl … | sh` style scripts continue instead of aborting on garbage.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command == "CONNECT":
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_CONNECT = _handle  # noqa: N815


class MockHttpRecorder:
    def __init__(self, events_path: Path, host: str = "127.0.0.1") -> None:
        handler = type("Handler", (_Handler,), {"events_path": events_path})
        self._server = ThreadingHTTPServer((host, 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def address(self) -> str:
        host, port = self._server.server_address[:2]
        host_s = host.decode() if isinstance(host, bytes) else str(host)
        return f"{host_s}:{port}"

    def __enter__(self) -> MockHttpRecorder:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
