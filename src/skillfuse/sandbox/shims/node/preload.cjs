// SkillFuse sandbox: Node runtime shim loaded via NODE_OPTIONS=--require.
// Records network connections, credential-file reads and process spawns to $SKILLFUSE_EVENTS and
// redirects every non-loopback connection to the mock recorder at $SKILLFUSE_MOCK_ADDR.
"use strict";
const fs = require("fs");
const net = require("net");
const http = require("http");
const https = require("https");
const cp = require("child_process");
const path = require("path");

const EVENTS = process.env.SKILLFUSE_EVENTS;
const MOCK = process.env.SKILLFUSE_MOCK_ADDR || "";
const WORKSPACE = process.env.SKILLFUSE_WORKSPACE || "";
const CRED = ["/.aws/", "/.ssh/", "/.netrc", "/.git-credentials", "/.npmrc", "/.pypirc", "/.docker/config.json",
  "/.kube/config", "/.config/gh/", "/.env", "/.gnupg/", "/.azure/", "/.config/gcloud/"];

function emit(ev) {
  if (!EVENTS) return;
  ev.ts = Date.now() / 1000;
  ev.runtime = "node";
  ev.pid = process.pid;
  try { fs.appendFileSync(EVENTS, JSON.stringify(ev) + "\n"); } catch (e) { /* ignore */ }
}
function isLoopback(h) { return !h || h === "localhost" || h === "::1" || h.startsWith("127."); }
function mockAddr() {
  const i = MOCK.lastIndexOf(":");
  if (i < 0) return null;
  return { host: MOCK.slice(0, i), port: parseInt(MOCK.slice(i + 1), 10) };
}

// --- sockets ---------------------------------------------------------------------------------
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  let opts = args[0];
  let host, port;
  if (typeof opts === "object" && opts !== null && !Array.isArray(opts)) { host = opts.host; port = opts.port; }
  else { port = args[0]; host = typeof args[1] === "string" ? args[1] : "localhost"; }
  if (host && !isLoopback(String(host))) {
    const m = mockAddr();
    emit({ type: "egress", tool: "net", host: String(host), port: Number(port), redirected: !!m });
    if (!m) { const err = new Error(`skillfuse sandbox: egress to ${host}:${port} blocked`); err.code = "ECONNREFUSED";
      process.nextTick(() => this.emit("error", err)); return this; }
    if (typeof opts === "object" && opts !== null && !Array.isArray(opts)) { args[0] = Object.assign({}, opts, { host: m.host, port: m.port }); }
    else { args[0] = m.port; if (typeof args[1] === "string") args[1] = m.host; }
  }
  return origConnect.apply(this, args);
};

function wrapRequest(mod, name) {
  const orig = mod.request;
  mod.request = function (input, options, cb) {
    try {
      let url = null;
      if (typeof input === "string") url = new URL(input);
      else if (input instanceof URL) url = input;
      const host = url ? url.hostname : (input && input.hostname) || (input && input.host) || (options && options.hostname);
      if (host && !isLoopback(String(host))) {
        emit({ type: "egress", tool: name, host: String(host), url: url ? url.toString() : undefined, method: (options && options.method) || (input && input.method) || "GET" });
      }
    } catch (e) { /* ignore */ }
    return orig.apply(this, arguments);
  };
  mod.get = function (...a) { const req = mod.request(...a); req.end(); return req; };
}
wrapRequest(http, "http");
wrapRequest(https, "https");

if (typeof globalThis.fetch === "function") {
  const origFetch = globalThis.fetch;
  globalThis.fetch = async function (input, init) {
    try {
      const u = new URL(typeof input === "string" ? input : input.url);
      if (!isLoopback(u.hostname)) {
        let body = init && init.body;
        if (body && typeof body !== "string") body = "[non-string body]";
        emit({ type: "egress", tool: "fetch", host: u.hostname, url: u.toString(), method: (init && init.method) || "GET", data: body ? String(body).slice(0, 4000) : undefined });
        const m = mockAddr();
        if (!m) throw new TypeError("skillfuse sandbox: fetch blocked");
        const redirected = new URL(u.toString()); redirected.protocol = "http:"; redirected.hostname = m.host; redirected.port = String(m.port);
        return origFetch(redirected.toString(), init);
      }
    } catch (e) { if (String(e.message).includes("blocked")) throw e; }
    return origFetch(input, init);
  };
}

// --- files -------------------------------------------------------------------------------------
function checkRead(p) {
  const full = path.resolve(String(p));
  if (CRED.some((m) => full.includes(m))) emit({ type: "file_read", path: full, credential: true });
}
function checkWrite(p) {
  const full = path.resolve(String(p));
  emit({ type: "file_write", path: full, outside_workspace: !(WORKSPACE && full.startsWith(WORKSPACE)) });
}
for (const fn of ["readFileSync", "readFile", "createReadStream", "openSync", "open"]) {
  const orig = fs[fn];
  if (!orig) continue;
  fs[fn] = function (p, ...rest) { try { checkRead(p); } catch (e) {} return orig.call(this, p, ...rest); };
}
for (const fn of ["writeFileSync", "writeFile", "appendFileSync", "appendFile", "createWriteStream", "mkdirSync", "mkdir"]) {
  const orig = fs[fn];
  if (!orig) continue;
  fs[fn] = function (p, ...rest) { try { if (String(p) !== EVENTS) checkWrite(p); } catch (e) {} return orig.call(this, p, ...rest); };
}
if (fs.promises) {
  const pr = fs.promises;
  for (const fn of ["readFile"]) { const o = pr[fn]; pr[fn] = function (p, ...r) { try { checkRead(p); } catch (e) {} return o.call(this, p, ...r); }; }
  for (const fn of ["writeFile", "appendFile"]) { const o = pr[fn]; pr[fn] = function (p, ...r) { try { checkWrite(p); } catch (e) {} return o.call(this, p, ...r); }; }
}

// --- processes ---------------------------------------------------------------------------------
for (const fn of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
  const orig = cp[fn];
  if (!orig) continue;
  cp[fn] = function (cmd, args, ...rest) {
    const argv = Array.isArray(args) ? [String(cmd), ...args.map(String)] : [String(cmd)];
    emit({ type: "spawn", argv, shell: fn.startsWith("exec") && !fn.startsWith("execFile") });
    return orig.call(this, cmd, args, ...rest);
  };
}

emit({ type: "runtime_start", argv: process.argv.slice(0, 4) });
