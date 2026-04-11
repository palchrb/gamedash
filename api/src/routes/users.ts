/**
 * Admin CRUD for per-child knock users.
 *
 * Plaintext tokens are returned ONLY from POST /api/users and
 * POST /api/users/:id/rotate-token. At all other times we return a
 * sanitised projection via `toPublic` that does not include the hash.
 */

import { Router } from "express";
import { audit } from "../repos/audit";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import { CreateUserBodySchema, UpdateUserBodySchema } from "../schemas";
import {
  createUser,
  deleteUser,
  findById,
  listUsers,
  openRegistrationWindow,
  removeKnockCredential,
  rotateToken,
  toPublic,
  updateUser,
} from "../repos/users";
import { deleteKnockSessionsForUser } from "../repos/knock-sessions";
import { registry } from "../services/registry";
import {
  deleteRuleByUserId,
  findRuleByUserId,
  flattenPorts,
} from "../repos/firewall-rules";
import { ufwDeleteMany } from "../firewall/ufw";
import { revokeUser } from "../knock/smart-revoke";

export function usersRouter(): Router {
  const router = Router();

  router.get(
    "/api/users",
    asyncH(async (_req, res) => {
      const users = await listUsers();
      res.json({ success: true, users: users.map(toPublic) });
    }),
  );

  router.post(
    "/api/users",
    asyncH(async (req, res) => {
      const body = CreateUserBodySchema.parse(req.body);
      // Silently filter allowedServices against the registry so we don't
      // persist ids that don't exist.
      const allowed = body.allowedServices.filter((id) => registry().get(id) !== null);
      const created = await createUser({
        name: body.name,
        allowedServices: allowed,
        locale: body.locale ?? null,
      });
      await audit({ kind: "user.create", userId: created.user.id, name: created.user.name });
      res.json({
        success: true,
        user: toPublic(created.user),
        token: created.plainToken,
      });
    }),
  );

  router.put(
    "/api/users/:id",
    asyncH(async (req, res) => {
      const id = req.params["id"];
      if (!id) throw new HttpError(400, "missing id");
      const body = UpdateUserBodySchema.parse(req.body);
      const updated = await updateUser(id, body);
      await audit({ kind: "user.update", userId: id });
      res.json({ success: true, user: toPublic(updated) });
    }),
  );

  router.delete(
    "/api/users/:id",
    asyncH(async (req, res) => {
      const id = req.params["id"];
      if (!id) throw new HttpError(400, "missing id");
      // Revoke any active firewall rule first so UFW and state stay in sync.
      const rule = await findRuleByUserId(id);
      if (rule) {
        try {
          await ufwDeleteMany(rule.ips, flattenPorts(rule));
        } catch {
          // logged inside
        }
        await deleteRuleByUserId(id);
      }
      const removed = await deleteUser(id);
      if (!removed) throw new HttpError(404, "user not found");
      await audit({ kind: "user.delete", userId: id, name: removed.name });
      res.json({ success: true });
    }),
  );

  router.post(
    "/api/users/:id/rotate-token",
    asyncH(async (req, res) => {
      const id = req.params["id"];
      if (!id) throw new HttpError(400, "missing id");
      const user = await findById(id);
      if (!user) throw new HttpError(404, "user not found");
      const token = await rotateToken(id);
      await audit({ kind: "user.rotate_token", userId: id });
      res.json({ success: true, token });
    }),
  );

  router.post(
    "/api/users/:id/revoke",
    asyncH(async (req, res) => {
      const id = req.params["id"];
      if (!id) throw new HttpError(400, "missing id");
      const r = await revokeUser(id);
      res.json({ success: true, ...r });
    }),
  );

  // Open a fresh KNOCK_REGISTRATION_TTL_HOURS window so a new device
  // can enrol a passkey. Closes automatically on first successful
  // registration (via addKnockCredential in the users repo).
  router.post(
    "/api/users/:id/open-registration",
    asyncH(async (req, res) => {
      const id = req.params["id"];
      if (!id) throw new HttpError(400, "missing id");
      const user = await findById(id);
      if (!user) throw new HttpError(404, "user not found");
      const until = await openRegistrationWindow(id);
      await audit({ kind: "user.open_registration", userId: id, until });
      res.json({ success: true, registrationOpenUntil: until });
    }),
  );

  // Remove a specific knock credential (e.g. lost device). Does not
  // touch the active firewall rule, but does nuke all sessions for
  // that user so a browser with a stale cookie stops working.
  router.delete(
    "/api/users/:id/credentials/:credId",
    asyncH(async (req, res) => {
      const id = req.params["id"];
      const credId = req.params["credId"];
      if (!id || !credId) throw new HttpError(400, "missing id");
      const user = await findById(id);
      if (!user) throw new HttpError(404, "user not found");
      await removeKnockCredential(id, credId);
      await deleteKnockSessionsForUser(id);
      await audit({ kind: "user.credential_removed", userId: id, credId });
      res.json({ success: true });
    }),
  );

  return router;
}
