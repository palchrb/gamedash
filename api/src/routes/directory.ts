/**
 * Directory endpoint — single read-only view of every human/identity that
 * touches the system. Aggregates admins and knock users into one shape so
 * the admin UI can render "who has access" in one place without having to
 * fan out to two endpoints.
 *
 * The two stores stay separate on disk because their identity models are
 * different (token-bound knock users vs. account-bound admins). This route
 * exists purely to merge them at the read boundary.
 */

import { Router } from "express";
import { asyncH } from "../middleware/async-handler";
import { loadAdminCredentials } from "../repos/admin";
import { listUsers } from "../repos/users";
import type { WebAuthnCredential } from "../schemas";

interface DirectoryCredential {
  id: string;
  deviceLabel: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

interface DirectoryEntry {
  kind: "admin" | "knock";
  id: string;
  name: string;
  role: "admin" | "child";
  createdAt: string;
  lastSeenAt: string | null;
  credentials: DirectoryCredential[];
  // knock-only fields
  registrationOpenUntil?: string | null;
  allowedServices?: string[];
}

function projectCredential(c: WebAuthnCredential): DirectoryCredential {
  return {
    id: c.id,
    deviceLabel: c.deviceLabel ?? null,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
  };
}

function lastSeenFromCredentials(creds: WebAuthnCredential[]): string | null {
  let best: string | null = null;
  for (const c of creds) {
    if (!c.lastUsedAt) continue;
    if (!best || c.lastUsedAt > best) best = c.lastUsedAt;
  }
  return best;
}

export function directoryRouter(): Router {
  const router = Router();

  router.get(
    "/api/directory",
    asyncH(async (_req, res) => {
      const [adminFile, knockUsers] = await Promise.all([
        loadAdminCredentials(),
        listUsers(),
      ]);

      const entries: DirectoryEntry[] = [];

      for (const a of adminFile.admins) {
        entries.push({
          kind: "admin",
          id: a.id,
          name: a.name,
          role: "admin",
          createdAt: a.createdAt,
          lastSeenAt: lastSeenFromCredentials(a.credentials),
          credentials: a.credentials.map(projectCredential),
        });
      }

      for (const u of knockUsers) {
        // Knock users also keep a history of accesses; the most recent
        // entry there is a better "last seen" than the credential lastUsedAt
        // because it covers users who haven't enrolled a passkey at all.
        const lastHistory =
          u.history.length > 0 ? u.history[u.history.length - 1]?.at ?? null : null;
        const lastCred = lastSeenFromCredentials(u.credentials);
        const lastSeen =
          lastHistory && (!lastCred || lastHistory > lastCred) ? lastHistory : lastCred;
        entries.push({
          kind: "knock",
          id: u.id,
          name: u.name,
          role: "child",
          createdAt: u.createdAt,
          lastSeenAt: lastSeen,
          credentials: u.credentials.map(projectCredential),
          registrationOpenUntil: u.registrationOpenUntil,
          allowedServices: u.allowedServices,
        });
      }

      // Sort: admins first, then knock users; within each group, by name.
      entries.sort((a, b) => {
        if (a.kind !== b.kind) return a.kind === "admin" ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

      res.json({ success: true, entries });
    }),
  );

  return router;
}
