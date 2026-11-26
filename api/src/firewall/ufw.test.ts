/**
 * Failed UFW deletes must be queued and retried — otherwise the caller
 * drops the rule from firewall-rules.json and the allow is orphaned.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";

vi.mock("../lib/nsenter", () => ({
  sidecarUfwAllow: vi.fn().mockResolvedValue(undefined),
  sidecarUfwDelete: vi.fn().mockResolvedValue(undefined),
}));

import { sidecarUfwDelete } from "../lib/nsenter";
import { retryPendingDeletes, ufwDeleteMany } from "./ufw";

const node = { sidecarUrl: "http://x:9090", sidecarToken: "t" };
const resolveNode = () => node;
let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-ufw-"));
  process.env["DATA_DIR"] = tmpDir;
  process.env["LOG_LEVEL"] = "silent";
  resetConfigForTests();
  resetLoggerForTests();
  vi.mocked(sidecarUfwDelete).mockReset().mockResolvedValue(undefined);
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
  delete process.env["LOG_LEVEL"];
});

function pending(): Array<{ ip: string; port: string }> {
  const f = path.join(tmpDir, "ufw-pending-deletes.json");
  if (!fs.existsSync(f)) return [];
  return JSON.parse(fs.readFileSync(f, "utf8")).pending;
}

describe("ufwDeleteMany retry queue", () => {
  it("queues failed deletes and clears them once a retry succeeds", async () => {
    vi.mocked(sidecarUfwDelete).mockRejectedValueOnce(new Error("sidecar down"));
    const errors = await ufwDeleteMany(
      ["203.0.113.9"],
      new Map([["local", [{ port: "25565", proto: "tcp" as const }]]]),
      resolveNode,
    );
    expect(errors).toHaveLength(1);
    expect(pending()).toEqual([expect.objectContaining({ ip: "203.0.113.9", port: "25565" })]);

    const r = await retryPendingDeletes(resolveNode);
    expect(r).toEqual({ retried: 1, cleared: 1, abandoned: 0, remaining: 0 });
    expect(pending()).toEqual([]);
  });

  it("keeps still-failing deletes queued", async () => {
    vi.mocked(sidecarUfwDelete).mockRejectedValue(new Error("still down"));
    await ufwDeleteMany(
      ["203.0.113.9"],
      new Map([["local", [{ port: "22023", proto: "udp" as const }]]]),
      resolveNode,
    );
    const r = await retryPendingDeletes(resolveNode);
    expect(r.remaining).toBe(1);
    expect(pending()).toHaveLength(1);
  });

  it("an unknown node fails just its own deletes instead of aborting the batch", async () => {
    const errors = await ufwDeleteMany(
      ["203.0.113.9"],
      new Map([
        ["gone", [{ port: "7777", proto: "tcp" as const }]],
        ["local", [{ port: "25565", proto: "tcp" as const }]],
      ]),
      (id) => {
        if (id === "gone") throw new Error("unknown node");
        return node;
      },
    );
    expect(errors).toHaveLength(1);
    expect(vi.mocked(sidecarUfwDelete)).toHaveBeenCalledTimes(1);
  });
});

describe("ufw ops are sequential per node", () => {
  it("never has two in-flight ufw calls against the same node", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    vi.mocked(sidecarUfwDelete).mockImplementation(async () => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight--;
    });
    await ufwDeleteMany(
      ["203.0.113.1", "2001:db8::1"],
      new Map([["local", [
        { port: "25565", proto: "tcp" as const },
        { port: "19132", proto: "udp" as const },
        { port: "22023", proto: "udp" as const },
      ]]]),
      resolveNode,
    );
    expect(vi.mocked(sidecarUfwDelete)).toHaveBeenCalledTimes(6);
    expect(maxInFlight).toBe(1);
  });
});
