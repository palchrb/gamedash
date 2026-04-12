/**
 * Unit tests for the parts of knock-passkey that do not require a full
 * WebAuthn round-trip. The ceremony code is exercised at integration
 * level via the /u/:token/webauthn routes once supertest lands.
 */

import { describe, expect, it } from "vitest";
import { isRegistrationOpen } from "./knock-passkey";
import type { UserRecord } from "../schemas";

function fakeUser(overrides: Partial<UserRecord> = {}): UserRecord {
  return {
    id: "u1",
    name: "Test",
    tokenHash: "hash",
    allowedServices: [],
    locale: null,
    createdAt: new Date().toISOString(),
    history: [],
    credentials: [],
    registrationOpenUntil: null,
    suspended: false,
    ...overrides,
  };
}

describe("isRegistrationOpen", () => {
  it("returns false when no window is set", () => {
    expect(isRegistrationOpen(fakeUser())).toBe(false);
  });

  it("returns true when the window is in the future", () => {
    const until = new Date(Date.now() + 60_000).toISOString();
    expect(isRegistrationOpen(fakeUser({ registrationOpenUntil: until }))).toBe(true);
  });

  it("returns false when the window has expired", () => {
    const until = new Date(Date.now() - 60_000).toISOString();
    expect(isRegistrationOpen(fakeUser({ registrationOpenUntil: until }))).toBe(false);
  });
});
