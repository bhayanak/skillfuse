"""Mock HTTP(S) recorder: accepts anything, logs method/host/path/headers/body, replies 200.

TLS is terminated with an ephemeral CA (:mod:`skillfuse.sandbox.tls`), so bodies sent over HTTPS — tunnelled via
``CONNECT`` from the proxy environment variables, or redirected straight here by the runtime shims — are captured
instead of dying at the handshake. The sandbox trusts the CA through the standard ``*_CA_BUNDLE`` variables.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from skillfuse.sandbox.tls import EphemeralCA

_TLS_HANDSHAKE_BYTE = 0x16
_MAX_BODY = 1 << 20


class _Handler(BaseHTTPRequestHandler):
    events_path: Path | None = None
    ca: EphemeralCA | None = None
    server_version = "skillfuse-mock/0.1"
    timeout = 30

    def log_message(self, format: str, *args: object) -> None:
        return

    # -- connection lifecycle -------------------------------------------------------------------
    def handle(self) -> None:
        self.close_connection = True
        self.tunnel_host: str | None = None
        self.tls_host: str | None = None
        if self._peek_is_tls() and not self._start_tls(None):
            return
        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def _peek_is_tls(self) -> bool:
        try:
            first = self.connection.recv(1, socket.MSG_PEEK)
        except OSError:
            return False
        return bool(first) and first[0] == _TLS_HANDSHAKE_BYTE

    def _start_tls(self, host: str | None) -> bool:
        if self.ca is None:
            return False
        try:
            self.connection = self.ca.server_context(host).wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError):
            return False
        self.tls_host = host or self.ca.last_sni()
        self.rfile = self.connection.makefile("rb", -1)
        self.wfile = self.connection.makefile("wb", 0)
        return True

    # -- requests -------------------------------------------------------------------------------
    def _record(self, extra: dict[str, Any]) -> None:
        ev: dict[str, Any] = {"type": "http", "runtime": "mock-http", "ts": time.time(), **extra}
        if self.events_path is not None:
            with self.events_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev) + "\n")

    def _connect(self) -> None:
        target = self.path
        self._record(
            {"method": "CONNECT", "path": target, "host": target, "headers": dict(self.headers), "data": ""}
        )
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        hostname = target.rsplit(":", 1)[0].strip("[]") if ":" in target else target
        if self._start_tls(hostname):
            self.tunnel_host = target
            self.close_connection = False  # read the first request inside the tunnel
        else:
            self.close_connection = True

    def _handle(self) -> None:
        if self.command == "CONNECT":
            self._connect()
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, _MAX_BODY)) if length else b""
        host = (
            self.headers.get("X-Skillfuse-Host")
            or self.tunnel_host
            or self.tls_host
            or self.headers.get("Host")
        )
        self._record(
            {
                "method": self.command,
                "path": self.path,
                "host": host,
                "tls": bool(self.tunnel_host or self.tls_host),
                "headers": {k: v for k, v in self.headers.items() if k.lower() != "content-length"},
                "data": body.decode("utf-8", "replace")[:8000],
            }
        )
        # Empty 200 so `curl … | sh` style scripts continue instead of aborting on garbage.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_CONNECT = _handle  # noqa: N815


class MockHttpRecorder:
    def __init__(self, events_path: Path, host: str = "127.0.0.1", *, ca_dir: Path | None = None) -> None:
        self.ca = EphemeralCA(ca_dir or events_path.parent / "ca")
        handler = type("Handler", (_Handler,), {"events_path": events_path, "ca": self.ca})
        self._server = ThreadingHTTPServer((host, 0), handler)
        self._server.block_on_close = False
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def address(self) -> str:
        host, port = self._server.server_address[:2]
        host_s = host.decode() if isinstance(host, bytes) else str(host)
        return f"{host_s}:{port}"

    @property
    def ca_file(self) -> Path:
        return self.ca.ca_file

    def __enter__(self) -> MockHttpRecorder:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
