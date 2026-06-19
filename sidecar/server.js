/**
 * Gamedash sidecar — minimal HTTP API for host-level firewall, connection
 * queries, and Docker container lifecycle. Runs as a privileged container
 * with pid:host so it can nsenter into the host's namespaces.
 *
 * Endpoints:
 *   POST /ufw/allow           {ip, port, proto}              → ufw route allow ...
 *   POST /ufw/delete          {ip, port, proto}              → ufw route delete allow ...
 *   GET  /connections/tcp                                     → ss -tnH state established
 *   GET  /connections/udp                                     → conntrack -L -p udp
 *   POST /docker/start        {container}                     → docker start <container>
 *   POST /docker/stop         {container, timeoutSeconds?}    → docker stop <container>
 *   POST /docker/restart      {container, timeoutSeconds?}    → docker restart <container>
 *   GET  /docker/logs?container=<name>&tail=<N>               → docker logs --tail N
 *   GET  /docker/inspect?container=<name>                     → docker inspect (minimal subset)
 *   GET  /healthz                                             → {ok: true}
 *
 * Input validation is strict: IPs must be dotted-quad or valid IPv6,
 * ports numeric, proto tcp|udp, container names alphanumeric+dash+underscore.
 * No shell is ever invoked — all commands use execFile with an explicit argv.
 */

"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");
const { URL } = require("node:url");

const PORT = parseInt(process.env.SIDECAR_PORT || "9090", 10);
const CMD_TIMEOUT_MS = 15_000;
const DOCKER_TIMEOUT_MS = parseInt(process.env.DOCKER_TIMEOUT_MS || "10000", 10);
const DOCKER_LOGS_TIMEOUT_MS = 15_000;
const DOCKER_INSPECT_TIMEOUT_MS = 3_000;
const SIDECAR_TOKEN = process.env.SIDECAR_TOKEN || "";
const DOCKER_PROXY_URL = process.env.DOCKER_PROXY_URL || "";

if (process.env.NODE_ENV === "production" && !SIDECAR_TOKEN) {
  console.error("FATAL: SIDECAR_TOKEN must be set in production mode");
  process.exit(1);
}

// ── Validation ──────────────────────────────────────────────────────

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;
const PORT_RE = /^\d{1,5}$/;
const PROTO_SET = new Set(["tcp", "udp"]);
const CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

function isValidIP(ip) {
  if (typeof ip !== "string") return false;
  if (IPV4_RE.test(ip)) {
    const octets = ip.split(".").map(Number);
    return octets.every((o) => o <= 255);
  }
  if (IPV6_RE.test(ip) && ip.includes(":") && ip.length >= 2 && ip.length <= 45) {
    return true;
  }
  return false;
}

function validateUfwBody(body) {
  if (!body || typeof body !== "object") return "invalid body";
  if (!isValidIP(body.ip)) return "invalid ip";
  if (typeof body.port !== "string" || !PORT_RE.test(body.port)) return "invalid port";
  if (!PROTO_SET.has(body.proto)) return "invalid proto";
  const portNum = parseInt(body.port, 10);
  if (portNum < 1 || portNum > 65535) return "invalid port range";
  return null;
}

function validateContainerName(name) {
  return typeof name === "string" && CONTAINER_RE.test(name);
}

// ── nsenter helper ──────────────────────────────────────────────────

function nsenter(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const full = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", ...args];
    execFile(full[0], full.slice(1), { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const msg = (stderr || "").trim() || err.message;
        reject(new Error(msg));
        return;
      }
      resolve(stdout || "");
    });
  });
}

// ── Docker helper (via DOCKER_HOST or DOCKER_PROXY_URL) ─────────────

function dockerExec(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (DOCKER_PROXY_URL) env.DOCKER_HOST = DOCKER_PROXY_URL;
    execFile("docker", args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env }, (err, stdout, stderr) => {
      if (err) {
        const msg = (stderr || "").trim() || err.message;
        reject(new Error(msg));
        return;
      }
      resolve({ stdout: stdout || "", stderr: stderr || "" });
    });
  });
}

// ── Route handlers ──────────────────────────────────────────────────

async function handleUfwAllow(body) {
  const err = validateUfwBody(body);
  if (err) return { status: 400, body: { success: false, error: err } };
  await nsenter(
    ["ufw", "route", "allow", "from", body.ip, "to", "any", "port", body.port, "proto", body.proto],
    CMD_TIMEOUT_MS,
  );
  return { status: 200, body: { success: true } };
}

async function handleUfwDelete(body) {
  const err = validateUfwBody(body);
  if (err) return { status: 400, body: { success: false, error: err } };
  await nsenter(
    ["ufw", "route", "delete", "allow", "from", body.ip, "to", "any", "port", body.port, "proto", body.proto],
    CMD_TIMEOUT_MS,
  );
  return { status: 200, body: { success: true } };
}

async function handleTcpConnections() {
  let stdout;
  try {
    stdout = await nsenter(["ss", "-tnH", "state", "established"], 5000);
  } catch (err) {
    if (/no such file|not found/i.test(err.message)) {
      return { status: 200, body: { success: true, raw: "" } };
    }
    throw err;
  }
  return { status: 200, body: { success: true, raw: stdout } };
}

async function handleUdpConnections() {
  let stdout;
  try {
    stdout = await nsenter(["conntrack", "-L", "-p", "udp"], 5000);
  } catch {
    return { status: 200, body: { success: true, raw: "" } };
  }
  return { status: 200, body: { success: true, raw: stdout } };
}

// ── Docker handlers ─────────────────────────────────────────────────

async function handleDockerLifecycle(action, body) {
  if (!body || !validateContainerName(body.container)) {
    return { status: 400, body: { success: false, error: "invalid container name" } };
  }
  const args = [action, body.container];
  if (body.timeoutSeconds && action !== "start") {
    args.push("-t", String(Math.max(1, Math.floor(Number(body.timeoutSeconds)))));
  }
  await dockerExec(args, DOCKER_TIMEOUT_MS);
  return { status: 200, body: { success: true } };
}

async function handleDockerLogs(url) {
  const params = url.searchParams;
  const container = params.get("container");
  if (!validateContainerName(container)) {
    return { status: 400, body: { success: false, error: "invalid container name" } };
  }
  const tail = Math.max(1, Math.floor(Number(params.get("tail") || "100")));
  const result = await dockerExec(
    ["logs", "--tail", String(tail), container],
    DOCKER_LOGS_TIMEOUT_MS,
  );
  const lines = (result.stdout + result.stderr).split("\n").filter(Boolean);
  return { status: 200, body: { success: true, lines } };
}

async function handleDockerInspect(url) {
  const container = url.searchParams.get("container");
  if (!validateContainerName(container)) {
    return { status: 400, body: { success: false, error: "invalid container name" } };
  }
  const result = await dockerExec(
    ["inspect", "--format", '{"running":{{.State.Running}},"startedAt":"{{.State.StartedAt}}","status":"{{.State.Status}}"}', container],
    DOCKER_INSPECT_TIMEOUT_MS,
  );
  const parsed = JSON.parse(result.stdout.trim());
  return { status: 200, body: { success: true, ...parsed } };
}

// ── HTTP server ─────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 8192) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { resolve(null); }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const respond = (status, obj) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(obj));
  };

  try {
    if (SIDECAR_TOKEN && req.url !== "/healthz") {
      const provided = req.headers["x-sidecar-token"] || "";
      const a = Buffer.from(provided);
      const b = Buffer.from(SIDECAR_TOKEN);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return respond(403, { success: false, error: "forbidden" });
      }
    }

    const parsed = new URL(req.url, `http://localhost:${PORT}`);
    const pathname = parsed.pathname;

    if (req.method === "GET" && pathname === "/healthz") {
      return respond(200, { ok: true });
    }
    if (req.method === "GET" && pathname === "/connections/tcp") {
      const r = await handleTcpConnections();
      return respond(r.status, r.body);
    }
    if (req.method === "GET" && pathname === "/connections/udp") {
      const r = await handleUdpConnections();
      return respond(r.status, r.body);
    }
    if (req.method === "POST" && pathname === "/ufw/allow") {
      const body = await readBody(req);
      const r = await handleUfwAllow(body);
      return respond(r.status, r.body);
    }
    if (req.method === "POST" && pathname === "/ufw/delete") {
      const body = await readBody(req);
      const r = await handleUfwDelete(body);
      return respond(r.status, r.body);
    }

    // ── Docker endpoints ─────────────────────────────────────────────
    if (req.method === "POST" && pathname === "/docker/start") {
      const body = await readBody(req);
      const r = await handleDockerLifecycle("start", body);
      return respond(r.status, r.body);
    }
    if (req.method === "POST" && pathname === "/docker/stop") {
      const body = await readBody(req);
      const r = await handleDockerLifecycle("stop", body);
      return respond(r.status, r.body);
    }
    if (req.method === "POST" && pathname === "/docker/restart") {
      const body = await readBody(req);
      const r = await handleDockerLifecycle("restart", body);
      return respond(r.status, r.body);
    }
    if (req.method === "GET" && pathname === "/docker/logs") {
      const r = await handleDockerLogs(parsed);
      return respond(r.status, r.body);
    }
    if (req.method === "GET" && pathname === "/docker/inspect") {
      const r = await handleDockerInspect(parsed);
      return respond(r.status, r.body);
    }

    respond(404, { success: false, error: "not found" });
  } catch (err) {
    console.error("sidecar error:", err.message);
    respond(500, { success: false, error: "internal error" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`gamedash-sidecar listening on :${PORT}`);
});

process.on("SIGTERM", () => { server.close(); process.exit(0); });
process.on("SIGINT", () => { server.close(); process.exit(0); });
