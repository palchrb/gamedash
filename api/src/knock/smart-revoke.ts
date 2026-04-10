/**
 * Core knock flow — shared by the per-user PWA and the admin "allow IP"
 * button. Handles:
 *
 *   - Input validation (IP format, requested services vs user permissions)
 *   - Smart-revoke: refuses to swap an existing rule to a new IP if the
 *     old IP still has a live game session, unless the caller passes
 *     `force: true` after confirming with the user
 *   - Idempotent renew on same IP
 *   - Atomic firewall rule write + user history append
 */

import { audit } from "../repos/audit";
import { config } from "../config";
import { isIpActiveOnPorts } from "../firewall/connections";
import { ufwAllowMany, ufwDeleteMany, type UfwError } from "../firewall/ufw";
import {
  flattenPorts,
  mutateRules,
} from "../repos/firewall-rules";
import { pushHistory } from "../repos/users";
import { isValidPublicIP } from "../lib/ip";
import type { Registry } from "../services/registry";
import type { FirewallRule, UserRecord } from "../schemas";

export type KnockResult =
  | {
      status: "ok";
      rule: FirewallRule;
      expiresAt: string;
      errors: UfwError[];
    }
  | {
      status: "requires_confirm";
      reason: "active_session";
      oldIp: string;
      matchCount: number;
      oldServices: string[];
    };

export interface KnockOptions {
  force?: boolean;
  ua?: string | null;
  skipAudit?: boolean;
}

function resolveServices(user: UserRecord, requested: string[] | "all"): string[] {
  const allowed = new Set(user.allowedServices);
  if (requested === "all") return Array.from(allowed);
  return requested.filter((id) => allowed.has(id));
}

export async function knockUser(
  user: UserRecord,
  ip: string,
  requestedServices: string[] | "all",
  registry: Registry,
  options: KnockOptions = {},
): Promise<KnockResult> {
  if (!isValidPublicIP(ip)) {
    throw new Error("Invalid or non-public IP address");
  }
  const serviceIds = resolveServices(user, requestedServices);
  if (serviceIds.length === 0) {
    throw new Error("No services requested or allowed");
  }
  const portList = registry.collectPorts(serviceIds);
  if (portList.length === 0) {
    throw new Error("No ports configured for requested services");
  }

  const c = config();
  const ttlMs = c.KNOCK_USER_TTL_HOURS * 3_600_000;

  // The entire read → check → mutate cycle runs under a single firewall
  // lock so no concurrent knock can see stale rule state (TOCTOU fix).
  return mutateRules(async (draft) => {
    const existingIdx = draft.rules.findIndex((r) => r.userId === user.id);
    const existing = existingIdx >= 0 ? draft.rules[existingIdx] : null;
    const now = Date.now();
    const expiresAt = new Date(now + ttlMs).toISOString();

    // ── Same IP: just bump the expiry ──
    // UFW rules are permanent until explicitly deleted (by sweep or
    // manual revoke), so all we do here is push out expiresAt.
    if (existing && existing.ip === ip) {
      draft.rules[existingIdx] = { ...existing, expiresAt };
      return { status: "ok" as const, rule: draft.rules[existingIdx], expiresAt, errors: [] };
    }

    // ── Different IP: smart-revoke check ──
    if (existing && !options.force) {
      const oldPorts = flattenPorts(existing);
      const active = await isIpActiveOnPorts(existing.ip, oldPorts);
      if (active.active) {
        await audit({
          kind: "knock.blocked_active_session",
          userId: user.id,
          oldIp: existing.ip,
          newIp: ip,
          matchCount: active.matchCount,
        });
        return {
          status: "requires_confirm" as const,
          reason: "active_session" as const,
          oldIp: existing.ip,
          matchCount: active.matchCount,
          oldServices: existing.services.map((s) => s.id),
        };
      }
    }

    // ── Different IP: safe to swap ──
    if (existing) {
      try {
        await ufwDeleteMany(existing.ip, flattenPorts(existing));
      } catch {
        // logged inside ufwDeleteMany
      }
      draft.rules.splice(existingIdx, 1);
      await audit({
        kind: "knock.revoke",
        userId: user.id,
        ip: existing.ip,
        reason: "ip_change",
      });
    }

    const errors = await ufwAllowMany(ip, portList);
    const rule: FirewallRule = {
      ip,
      addedAt: new Date().toISOString(),
      expiresAt,
      label: `${user.name} via ${serviceIds.join(",")}`,
      userId: user.id,
      services: registry.buildRuleServices(serviceIds),
    };
    draft.rules.push(rule);
    await pushHistory(user.id, {
      ip,
      at: rule.addedAt,
      services: serviceIds,
      ua: options.ua ?? null,
      kind: "knock",
    });
    if (!options.skipAudit) {
      await audit({ kind: "knock.allow", userId: user.id, ip, services: serviceIds });
    }
    return { status: "ok" as const, rule, expiresAt, errors };
  });
}

/** Manually revoke a user's active rule (admin or self-service). */
export async function revokeUser(userId: string): Promise<{ removed: boolean; ip?: string }> {
  return mutateRules(async (draft) => {
    const idx = draft.rules.findIndex((r) => r.userId === userId);
    if (idx < 0) return { removed: false };
    const rule = draft.rules[idx]!;
    try {
      await ufwDeleteMany(rule.ip, flattenPorts(rule));
    } catch {
      // logged inside
    }
    draft.rules.splice(idx, 1);
    await audit({ kind: "knock.revoke_manual", userId, ip: rule.ip });
    return { removed: true, ip: rule.ip };
  });
}

/** Periodic sweep to remove expired firewall rules. */
export async function sweepExpiredRules(): Promise<number> {
  const now = Date.now();
  let expiredCount = 0;
  const toRemove: FirewallRule[] = [];
  await mutateRules((draft) => {
    const remaining: FirewallRule[] = [];
    for (const rule of draft.rules) {
      if (rule.expiresAt && new Date(rule.expiresAt).getTime() < now) {
        toRemove.push(rule);
      } else {
        remaining.push(rule);
      }
    }
    draft.rules = remaining;
    expiredCount = toRemove.length;
  });
  for (const rule of toRemove) {
    try {
      await ufwDeleteMany(rule.ip, flattenPorts(rule));
    } catch {
      // logged inside
    }
    await audit({
      kind: "knock.auto_expire",
      userId: rule.userId ?? null,
      ip: rule.ip,
    });
  }
  return expiredCount;
}
