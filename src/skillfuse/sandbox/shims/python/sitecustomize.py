# SkillFuse sandbox: Python runtime shim loaded via PYTHONPATH as `sitecustomize`.
# Records network connections, credential-file reads, and process spawns to $SKILLFUSE_EVENTS,
# and redirects every non-loopback connection to the mock recorder at $SKILLFUSE_MOCK_ADDR.
import builtins
import io
import json
import os
import socket
import subprocess
import sys
import time

_EVENTS = os.environ.get("SKILLFUSE_EVENTS")
_MOCK = os.environ.get("SKILLFUSE_MOCK_ADDR", "")  # host:port
_HOME = os.environ.get("HOME", "")
_WORKSPACE = os.environ.get("SKILLFUSE_WORKSPACE", "")
_CRED_MARKERS = (
    "/.aws/",
    "/.ssh/",
    "/.netrc",
    "/.git-credentials",
    "/.npmrc",
    "/.pypirc",
    "/.docker/config.json",
    "/.kube/config",
    "/.config/gh/",
    "/.env",
    "/.gnupg/",
    "/.azure/",
    "/.config/gcloud/",
)


_orig_open = builtins.open


def _emit(event):
    if not _EVENTS:
        return
    event.setdefault("ts", time.time())
    event.setdefault("runtime", "python")
    event.setdefault("pid", os.getpid())
    try:
        with _orig_open(_EVENTS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except OSError:
        pass


def _is_loopback(host):
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0") or host.startswith("127.")


def _mock_addr():
    if not _MOCK or ":" not in _MOCK:
        return None
    h, p = _MOCK.rsplit(":", 1)
    return h, int(p)


# --- sockets ------------------------------------------------------------------------------------
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex


def _rewrite(self, address):
    try:
        host, port = address[0], address[1]
    except (TypeError, IndexError):
        return address
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if _is_loopback(str(host)):
        return address
    _emit(
        {
            "type": "egress",
            "tool": "socket",
            "host": str(host),
            "port": int(port),
            "redirected": bool(_mock_addr()),
        }
    )
    mock = _mock_addr()
    if mock is None:
        raise ConnectionRefusedError(f"skillfuse sandbox: egress to {host}:{port} blocked")
    return mock


def _connect(self, address):
    return _orig_connect(self, _rewrite(self, address))


def _connect_ex(self, address):
    return _orig_connect_ex(self, _rewrite(self, address))


socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex

_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo(host, port, *args, **kwargs):
    if host and not _is_loopback(str(host)):
        _emit({"type": "dns", "host": str(host)})
        mock = _mock_addr()
        if mock is not None:
            return _orig_getaddrinfo(mock[0], port, *args, **kwargs)
    return _orig_getaddrinfo(host, port, *args, **kwargs)


socket.getaddrinfo = _getaddrinfo

# --- file access --------------------------------------------------------------------------------
_orig_io_open = io.open


def _check_path(path, mode):
    try:
        p = os.fspath(path)
    except TypeError:
        return
    if isinstance(p, bytes):
        p = p.decode("utf-8", "replace")
    if not isinstance(p, str):
        return
    full = os.path.abspath(p)
    if _EVENTS and full == os.path.abspath(_EVENTS):
        return
    reading = not any(c in mode for c in "wax+")
    if reading and any(m in full for m in _CRED_MARKERS):
        _emit({"type": "file_read", "path": full, "credential": True})
    elif not reading:
        inside = _WORKSPACE and full.startswith(_WORKSPACE)
        _emit({"type": "file_write", "path": full, "outside_workspace": not inside})


def _open(file, mode="r", *args, **kwargs):
    _check_path(file, mode)
    return _orig_open(file, mode, *args, **kwargs)


builtins.open = _open
io.open = _open

# --- processes ----------------------------------------------------------------------------------
_orig_popen_init = subprocess.Popen.__init__


def _popen_init(self, args, *a, **kw):
    argv = args if isinstance(args, (list, tuple)) else [str(args)]
    _emit({"type": "spawn", "argv": [str(x) for x in argv], "shell": bool(kw.get("shell"))})
    return _orig_popen_init(self, args, *a, **kw)


subprocess.Popen.__init__ = _popen_init

_orig_system = os.system


def _system(cmd):
    _emit({"type": "spawn", "argv": ["sh", "-c", str(cmd)], "shell": True})
    return _orig_system(cmd)


os.system = _system

for _name in ("execv", "execve", "execvp", "execvpe", "execl", "execlp", "execle", "execlpe"):
    _orig = getattr(os, _name, None)
    if _orig is None:
        continue

    def _wrap(*a, _orig=_orig, _name=_name, **kw):
        _emit({"type": "spawn", "argv": [str(x) for x in a[:3]], "exec": _name})
        return _orig(*a, **kw)

    setattr(os, _name, _wrap)

_emit({"type": "runtime_start", "argv": sys.argv[:4]})
