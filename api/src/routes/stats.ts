/**
 * Stats routes — per-user summaries and the leaderboard.
 */

import { Router } from "express";
import { asyncH } from "../middleware/async-handler";
import { leaderboard, loadStats } from "../repos/stats";

export function statsRouter(): Router {
  const router = Router();

  router.get(
    "/api/stats",
    asyncH(async (_req, res) => {
      const [stats, board] = await Promise.all([loadStats(), leaderboard()]);
      res.json({ success: true, stats, leaderboard: board });
    }),
  );

  return router;
}
