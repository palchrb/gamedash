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

// Crockford base32 without the ambiguous letters (no I, L, O, U — and no
// 0/1 since they alias O/I). Share codes are meant to be read aloud and
// typed on another device, so every character must be unmistakable.
const SHARE_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ";
export const SHARE_CODE_LENGTH = 8;

/** Generate a share code like "ABCDEFGH" (caller formats with a dash). */
export function generateShareCode(): string {
  const bytes = crypto.randomBytes(SHARE_CODE_LENGTH);
  let out = "";
  for (let i = 0; i < SHARE_CODE_LENGTH; i++) {
    out += SHARE_CODE_ALPHABET[bytes[i]! % SHARE_CODE_ALPHABET.length];
  }
  return out;
}

/**
 * Normalize user-typed share-code input: uppercase and strip whitespace
 * and dashes. Because the alphabet contains no confusable characters
 * (no 0/O, 1/I/L, U), no character remapping is needed — anything
 * outside the alphabet is a genuine typo. Returns null when the result
 * is not a plausible code.
 */
export function normalizeShareCode(input: string): string | null {
  if (typeof input !== "string") return null;
  const cleaned = input.toUpperCase().replace(/[\s-]/gu, "");
  if (cleaned.length !== SHARE_CODE_LENGTH) return null;
  for (const ch of cleaned) {
    if (!SHARE_CODE_ALPHABET.includes(ch)) return null;
  }
  return cleaned;
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
