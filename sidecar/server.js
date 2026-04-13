/**
 * UFW sidecar — minimal HTTP API for host-level firewall and connection
 * queries. Runs as a privileged container with pid:host so it can
 * nsenter into the host's namespaces.
 *
 * Endpoints:
 *   POST /ufw/allow   {ip, port, proto}   → ufw route allow ...
 *   POST /ufw/delete  {ip, port, proto}   → ufw route delete allow ...
 *   GET  /connections/tcp                  → ss -tnH state established
 *   GET  /connections/udp                  → conntrack -L -p udp
 *   GET  /healthz                          → {ok: true}
 *
 * Input validation is strict: IPs must be dotted-quad, ports numeric,
 * proto tcp|udp. No shell is ever invoked — all commands use execFile
 * with an explicit argv.
 */

"use strict";

const http = require("node:http");
const { execFile } = require("node:child_process");

const PORT = parseInt(process.env.SIDECAR_PORT || "9090", 10);
const CMD_TIMEOUT_MS = 15_000;
const SIDECAR_TOKEN = process.env.SIDECAR_TOKEN || "";

// ── Validation ──────────────────────────────────────────────────────

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;
const PORT_RE = /^\d{1,5}$/;
const PROTO_SET = new Set(["tcp", "udp"]);

function isValidIP(ip) {
  if (typeof ip !== "string") return false;
  if (IPV4_RE.test(ip)) {
    const octets = ip.split(".").map(Number);
    return octets.every((o) => o <= 255);
  }
  // Basic IPv6 structural check — UFW validates further
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
    // conntrack may not be installed — degrade gracefully
    return { status: 200, body: { success: true, raw: "" } };
  }
  return { status: 200, body: { success: true, raw: stdout } };
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
    // Shared-secret gate — if SIDECAR_TOKEN is set, every request
    // (except healthz) must carry a matching x-sidecar-token header.
    if (SIDECAR_TOKEN && req.url !== "/healthz") {
      if (req.headers["x-sidecar-token"] !== SIDECAR_TOKEN) {
        return respond(403, { success: false, error: "forbidden" });
      }
    }
    if (req.method === "GET" && req.url === "/healthz") {
      return respond(200, { ok: true });
    }
    if (req.method === "GET" && req.url === "/connections/tcp") {
      const r = await handleTcpConnections();
      return respond(r.status, r.body);
    }
    if (req.method === "GET" && req.url === "/connections/udp") {
      const r = await handleUdpConnections();
      return respond(r.status, r.body);
    }
    if (req.method === "POST" && req.url === "/ufw/allow") {
      const body = await readBody(req);
      const r = await handleUfwAllow(body);
      return respond(r.status, r.body);
    }
    if (req.method === "POST" && req.url === "/ufw/delete") {
      const body = await readBody(req);
      const r = await handleUfwDelete(body);
      return respond(r.status, r.body);
    }
    respond(404, { success: false, error: "not found" });
  } catch (err) {
    console.error("sidecar error:", err.message);
    respond(500, { success: false, error: "internal error" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ufw-sidecar listening on :${PORT}`);
});

process.on("SIGTERM", () => { server.close(); process.exit(0); });
process.on("SIGINT", () => { server.close(); process.exit(0); });
