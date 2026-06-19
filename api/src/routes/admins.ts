/**
 * Admin management routes — invite, list, and remove admins.
 *
 * All routes live behind the requireAdmin gate (mounted at /admin/api
 * in app.ts), so only an authenticated admin can manage other admins.
 *
 * Routes:
 *   GET    /api/admins          list all admins (id, name, credential count)
 *   POST   /api/admins          create a new admin + invite token
 *   DELETE /api/admins/:id      remove an admin (cannot remove yourself)
 */

import { Router } from "express";
import { z } from "zod";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import {
  createAdminWithInvite,
  deleteAdmin,
  deleteAdminSessionsForAdmin,
  findAdminById,
  listAdmins,
  removeAdminCredential,
} from "../repos/admin";
import { audit } from "../repos/audit";
import { config } from "../config";

const CreateAdminBodySchema = z.object({
  name: z.string().min(1).max(64),
});

export function adminsRouter(): Router {
  const router = Router();

  router.get(
    "/api/admins",
    asyncH(async (_req, res) => {
      const admins = await listAdmins();
      res.json({ success: true, admins });
    }),
  );

  router.post(
    "/api/admins",
    asyncH(async (req, res) => {
      const body = CreateAdminBodySchema.parse(req.body);
      const { admin, plainInviteToken } = await createAdminWithInvite(body.name);
      const origin = config().ADMIN_ORIGIN;
      const inviteUrl = `${origin}/admin/invite.html?token=${encodeURIComponent(plainInviteToken)}`;
      await audit({
        kind: "admin.invite",
        adminId: admin.id,
        name: admin.name,
        invitedBy: req.adminId,
      });
      res.json({
        success: true,
        admin: { id: admin.id, name: admin.name, createdAt: admin.createdAt },
        inviteUrl,
      });
    }),
  );

  router.delete(
    "/api/admins/me/credentials/:credId",
    asyncH(async (req, res) => {
      const adminId = req.adminId;
      if (!adminId) throw new HttpError(401, "admin session required");
      const credId = req.params["credId"];
      if (!credId) throw new HttpError(400, "missing credential id");
      const admin = await findAdminById(adminId);
      if (!admin) throw new HttpError(404, "admin not found");
      if (admin.credentials.length <= 1) {
        throw new HttpError(400, "cannot remove your last passkey");
      }
      if (!admin.credentials.some((c) => c.id === credId)) {
        throw new HttpError(404, "credential not found");
      }
      await removeAdminCredential(adminId, credId);
      await audit({
        kind: "admin.credential_removed",
        adminId,
        credentialId: credId,
      });
      res.json({ success: true });
    }),
  );

  router.delete(
    "/api/admins/:id",
    asyncH(async (req, res) => {
      const targetId = req.params["id"];
      if (!targetId) throw new HttpError(400, "missing admin id");
      if (targetId === req.adminId) {
        throw new HttpError(400, "cannot delete yourself");
      }
      const removed = await deleteAdmin(targetId);
      if (!removed) throw new HttpError(404, "admin not found");
      const sessionsRemoved = await deleteAdminSessionsForAdmin(targetId);
      await audit({
        kind: "admin.delete",
        adminId: targetId,
        deletedBy: req.adminId,
        sessionsRevoked: sessionsRemoved,
      });
      res.json({ success: true });
    }),
  );

  return router;
}
