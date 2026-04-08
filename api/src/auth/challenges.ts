/**
 * Short-lived in-memory challenge store for WebAuthn ceremonies.
 *
 * Registration and authentication each create a random challenge on the
 * server, hand it to the browser, and expect it echoed back in the signed
 * response. We never persist these — a challenge is single-use and has a
 * short TTL (2 min). Losing them on restart is fine; the user just retries.
 *
 * Keys are opaque strings. For the admin flow we use:
 *   reg:<admin-id>        during /api/admin/webauthn/register/options
 *   auth                  during /api/admin/webauthn/authenticate/options
 *
 * A periodic sweep removes expired entries so a malicious or buggy client
 * can't wedge the map full of dead challenges.
 */

interface Entry {
  challenge: string;
  expiresAt: number;
}

const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const store = new Map<string, Entry>();

export function putChallenge(key: string, challenge: string, ttlMs = CHALLENGE_TTL_MS): void {
  store.set(key, { challenge, expiresAt: Date.now() + ttlMs });
}

export function takeChallenge(key: string): string | null {
  const entry = store.get(key);
  if (!entry) return null;
  store.delete(key);
  if (entry.expiresAt <= Date.now()) return null;
  return entry.challenge;
}

export function sweepChallenges(): number {
  const now = Date.now();
  let removed = 0;
  for (const [k, v] of store.entries()) {
    if (v.expiresAt <= now) {
      store.delete(k);
      removed += 1;
    }
  }
  return removed;
}

/** Test-only reset of the challenge map. */
export function resetChallengesForTests(): void {
  store.clear();
}
