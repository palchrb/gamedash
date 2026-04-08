/**
 * Tests for the first-admin bootstrap window.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";
import {
  bootstrapStatus,
  closeBootstrap,
  initBootstrap,
  isBootstrapOpen,
  resetBootstrapForTests,
} from "./bootstrap";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-bootstrap-"));
  process.env["DATA_DIR"] = tmpDir;
  process.env["ADMIN_BOOTSTRAP_WINDOW_MINUTES"] = "15";
  resetConfigForTests();
  resetLoggerForTests();
  resetBootstrapForTests();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
  delete process.env["ADMIN_BOOTSTRAP_WINDOW_MINUTES"];
});

describe("bootstrap window", () => {
  it("opens when no admin credentials file exists", async () => {
    await initBootstrap();
    expect(isBootstrapOpen()).toBe(true);
    const status = bootstrapStatus();
    expect(status.open).toBe(true);
    expect(status.minutesRemaining).toBeGreaterThan(0);
    expect(status.minutesRemaining).toBeLessThanOrEqual(15);
  });

  it("stays closed when an admin already exists", async () => {
    // Seed an admin credentials file with one admin holding one credential.
    fs.writeFileSync(
      path.join(tmpDir, "admin-credentials.json"),
      JSON.stringify({
        admins: [
          {
            id: "a1",
            name: "root",
            createdAt: new Date().toISOString(),
            credentials: [
              {
                id: "cred-1",
                publicKey: "pk",
                counter: 0,
                transports: ["internal"],
                createdAt: new Date().toISOString(),
                lastUsedAt: null,
              },
            ],
          },
        ],
      }),
    );
    await initBootstrap();
    expect(isBootstrapOpen()).toBe(false);
  });

  it("closeBootstrap() permanently closes the window", async () => {
    await initBootstrap();
    expect(isBootstrapOpen()).toBe(true);
    closeBootstrap();
    expect(isBootstrapOpen()).toBe(false);
  });

  it("expires after the configured window", async () => {
    process.env["ADMIN_BOOTSTRAP_WINDOW_MINUTES"] = "0";
    resetConfigForTests();
    resetBootstrapForTests();
    // with 0-minute window the timer should show closed immediately.
    await initBootstrap();
    // The window is 0 ms wide → it is effectively already expired.
    // The first isBootstrapOpen() call after initBootstrap may still see
    // the state as open briefly because time hasn't advanced, so wait a
    // full millisecond to guarantee we're past expiresAt.
    await new Promise((r) => setTimeout(r, 2));
    expect(isBootstrapOpen()).toBe(false);
  });
});
