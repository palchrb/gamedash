/**
 * First-admin bootstrap window.
 *
 * On process start, if there is *no* admin credential on disk we open a
 * short window (default 15 min, configurable via ADMIN_BOOTSTRAP_WINDOW_MINUTES)
 * during which any unauthenticated client on the network can register the
 * very first passkey. Once any admin is registered the window closes
 * permanently for this process.
 *
 * After the window expires or an admin has been registered, first-admin
 * registration requires a restart — this is deliberate: the only time you
 * should ever see the bootstrap window is right after standing the app up.
 *
 * The window is a process-local concept, not persisted. A restart with
 * zero admins on disk re-opens the window.
 */

import { config } from "../config";
import { logger } from "../logger";
import { hasAnyAdmin } from "../repos/admin";

interface State {
  open: boolean;
  openedAt: number;
  expiresAt: number;
}

let state: State | null = null;

export async function initBootstrap(): Promise<void> {
  const hasAdmin = await hasAnyAdmin();
  if (hasAdmin) {
    state = { open: false, openedAt: 0, expiresAt: 0 };
    logger().info("admin bootstrap window closed: admin already registered");
    return;
  }
  const windowMs = config().ADMIN_BOOTSTRAP_WINDOW_MINUTES * 60 * 1000;
  const now = Date.now();
  state = { open: true, openedAt: now, expiresAt: now + windowMs };
  logger().warn(
    {
      minutes: config().ADMIN_BOOTSTRAP_WINDOW_MINUTES,
      expiresAt: new Date(state.expiresAt).toISOString(),
    },
    "admin bootstrap window OPEN — register first admin now",
  );
}

export function isBootstrapOpen(): boolean {
  if (!state) return false;
  if (!state.open) return false;
  if (Date.now() > state.expiresAt) {
    state.open = false;
    logger().info("admin bootstrap window expired");
    return false;
  }
  return true;
}

export function bootstrapStatus(): {
  open: boolean;
  expiresAt: string | null;
  minutesRemaining: number | null;
} {
  if (!state || !state.open) {
    return { open: false, expiresAt: null, minutesRemaining: null };
  }
  const now = Date.now();
  if (now > state.expiresAt) {
    state.open = false;
    return { open: false, expiresAt: null, minutesRemaining: null };
  }
  return {
    open: true,
    expiresAt: new Date(state.expiresAt).toISOString(),
    minutesRemaining: Math.ceil((state.expiresAt - now) / 60000),
  };
}

/** Force the window closed. Called the instant the first admin is registered. */
export function closeBootstrap(): void {
  if (state?.open) {
    state.open = false;
    logger().info("admin bootstrap window closed: first admin registered");
  }
}

/** Test-only reset. */
export function resetBootstrapForTests(): void {
  state = null;
}
