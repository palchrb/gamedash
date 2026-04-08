/**
 * Hashing + constant-time comparison helpers.
 *
 * Tokens and session ids are stored only as SHA-256 hashes on disk so a
 * leaked users.json cannot be used to impersonate anyone. Lookups compare
 * the hash of the candidate against the stored hashes in constant time
 * to avoid leaking information via timing differences.
 */

import * as crypto from "node:crypto";

export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

export function generateToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function generateSessionId(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

/** Constant-time hex string comparison. Returns false on any length mismatch. */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

/** Constant-time equality for arbitrary strings. */
export function constantTimeEqualString(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
