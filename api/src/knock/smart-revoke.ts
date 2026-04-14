/**
 * Core knock flow — shared by the per-user PWA and the admin "allow IP"
 * button. Handles:
 *
 *   - Input validation (IP format, requested services vs user permissions)
 *   - Dual-stack awareness: a single knock can carry both an IPv4 and an
 *     IPv6 address. Browsers and game clients pick v4 vs v6 independently
 *     (Happy Eyeballs), so opening only one of them leaves the player
 *     stuck. We open every detected IP and treat the set as one unit.
 *   - Smart-revoke: refuses to swap an existing rule to a new IP set if
 *     any of the old IPs still has a live game session, unless the
 *     caller passes `force: true` after confirming with the user.
 *   - Idempotent renew on overlapping IP sets. If the new knock shares
 *     at least one IP with the existing rule, we treat it as the same
 *     network and merge the two sets (adding any newly-detected IPs and
 *     bumping the expiry).
 *   - Atomic firewall rule write + user history append.
 */

import { audit } from "../repos/audit";
import { config } from "../config";
import { isAnyIpActiveOnPorts } from "../firewall/connections";
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
      oldIps: string[];
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

/** Dedupe + validate the requested IP list. Throws if nothing is valid. */
function sanitiseIps(input: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    if (typeof raw !== "string") continue;
    const ip = raw.trim();
    if (!ip || seen.has(ip)) continue;
    if (!isValidPublicIP(ip)) continue;
    seen.add(ip);
    out.push(ip);
  }
  return out;
}

export async function knockUser(
  user: UserRecord,
  ips: readonly string[],
  requestedServices: string[] | "all",
  registry: Registry,
  options: KnockOptions = {},
): Promise<KnockResult> {
  if (user.suspended) {
    throw new Error("Access suspended");
  }
  const newIps = sanitiseIps(ips);
  if (newIps.length === 0) {
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
    const existing = existingIdx >= 0 ? draft.rules[existingIdx] ?? null : null;
    const now = Date.now();
    const expiresAt = new Date(now + ttlMs).toISOString();

    // ── Overlap with existing rule → same network, merge + bump expiry ──
    // Any overlap in the IP sets means the client is on the same network
    // and one of the two stacks (v4/v6) is reachable via both knocks.
    // We merge to a superset so a client that newly acquired an IPv6
    // address gets it opened without losing the already-working IPv4.
    if (existing) {
      const existingSet = new Set(existing.ips);
      const overlap = newIps.some((ip) => existingSet.has(ip));
      if (overlap) {
        const mergedIps = [...new Set([...existing.ips, ...newIps])];
        const addedIps = mergedIps.filter((ip) => !existingSet.has(ip));
        let errors: UfwError[] = [];
        if (addedIps.length > 0) {
          errors = await ufwAllowMany(addedIps, portList);
        }
        draft.rules[existingIdx] = {
          ...existing,
          ips: mergedIps,
          expiresAt,
          // Re-bind the label in case requested services changed.
          label: `${user.name} via ${serviceIds.join(",")}`,
          services: registry.buildRuleServices(serviceIds),
        };
        if (addedIps.length > 0) {
          await pushHistory(user.id, {
            ips: addedIps,
            at: new Date().toISOString(),
            services: serviceIds,
            ua: options.ua ?? null,
            kind: "renew",
          });
        }
        return {
          status: "ok" as const,
          rule: draft.rules[existingIdx]!,
          expiresAt,
          errors,
        };
      }
    }

    // ── Different network: smart-revoke check ──
    if (existing && !options.force) {
      const oldPorts = flattenPorts(existing);
      const active = await isAnyIpActiveOnPorts(existing.ips, oldPorts);
      if (active.active) {
        await audit({
          kind: "knock.blocked_active_session",
          userId: user.id,
          oldIps: existing.ips,
          newIps,
          matchCount: active.matchCount,
        });
        return {
          status: "requires_confirm" as const,
          reason: "active_session" as const,
          oldIps: existing.ips,
          matchCount: active.matchCount,
          oldServices: existing.services.map((s) => s.id),
        };
      }
    }

    // ── Different network: safe to swap ──
    if (existing) {
      try {
        await ufwDeleteMany(existing.ips, flattenPorts(existing));
      } catch {
        // logged inside ufwDeleteMany
      }
      draft.rules.splice(existingIdx, 1);
      await audit({
        kind: "knock.revoke",
        userId: user.id,
        ips: existing.ips,
        reason: "ip_change",
      });
    }

    const errors = await ufwAllowMany(newIps, portList);
    const rule: FirewallRule = {
      ips: newIps,
      addedAt: new Date().toISOString(),
      expiresAt,
      label: `${user.name} via ${serviceIds.join(",")}`,
      userId: user.id,
      services: registry.buildRuleServices(serviceIds),
    };
    draft.rules.push(rule);
    await pushHistory(user.id, {
      ips: newIps,
      at: rule.addedAt,
      services: serviceIds,
      ua: options.ua ?? null,
      kind: "knock",
    });
    if (!options.skipAudit) {
      await audit({ kind: "knock.allow", userId: user.id, ips: newIps, services: serviceIds });
    }
    return { status: "ok" as const, rule, expiresAt, errors };
  });
}

/** Manually revoke a user's active rule (admin or self-service). */
export async function revokeUser(userId: string): Promise<{ removed: boolean; ips?: string[] }> {
  return mutateRules(async (draft) => {
    const idx = draft.rules.findIndex((r) => r.userId === userId);
    if (idx < 0) return { removed: false };
    const rule = draft.rules[idx]!;
    try {
      await ufwDeleteMany(rule.ips, flattenPorts(rule));
    } catch {
      // logged inside
    }
    draft.rules.splice(idx, 1);
    await audit({ kind: "knock.revoke_manual", userId, ips: rule.ips });
    return { removed: true, ips: rule.ips };
  });
}

/**
 * Admin self-knock — mirrors knockUser but keyed on adminId so each
 * admin has at most one auto-rule at a time. Re-knocking from a new
 * network replaces the old rule (with smart-revoke check for active
 * sessions), rather than adding a duplicate. Manual /firewall/add
 * rules (no adminId) are unaffected and can coexist.
 *
 * Admin rules have no TTL by design — admins keep the rule until they
 * explicitly revoke or re-knock from elsewhere.
 */
export async function knockAdmin(
  adminId: string,
  adminName: string,
  ips: readonly string[],
  registry: Registry,
  options: { force?: boolean; ua?: string | null } = {},
): Promise<KnockResult> {
  const newIps = sanitiseIps(ips);
  if (newIps.length === 0) {
    throw new Error("Invalid or non-public IP address");
  }
  const portList = registry.collectPorts();
  if (portList.length === 0) {
    throw new Error("No ports configured");
  }

  return mutateRules(async (draft) => {
    const existingIdx = draft.rules.findIndex((r) => r.adminId === adminId);
    const existing = existingIdx >= 0 ? draft.rules[existingIdx] ?? null : null;

    // ── Overlap (same network, e.g. v4+v6 from same ISP) → merge ──
    if (existing) {
      const existingSet = new Set(existing.ips);
      const overlap = newIps.some((ip) => existingSet.has(ip));
      if (overlap) {
        const mergedIps = [...new Set([...existing.ips, ...newIps])];
        const addedIps = mergedIps.filter((ip) => !existingSet.has(ip));
        let errors: UfwError[] = [];
        if (addedIps.length > 0) {
          errors = await ufwAllowMany(addedIps, portList);
        }
        draft.rules[existingIdx] = {
          ...existing,
          ips: mergedIps,
          services: registry.buildRuleServices(),
        };
        return {
          status: "ok" as const,
          rule: draft.rules[existingIdx]!,
          expiresAt: existing.expiresAt ?? "",
          errors,
        };
      }
    }

    // ── Different network: smart-revoke check ──
    if (existing && !options.force) {
      const oldPorts = flattenPorts(existing);
      const active = await isAnyIpActiveOnPorts(existing.ips, oldPorts);
      if (active.active) {
        await audit({
          kind: "admin.knock_blocked_active_session",
          adminId,
          oldIps: existing.ips,
          newIps,
          matchCount: active.matchCount,
        });
        return {
          status: "requires_confirm" as const,
          reason: "active_session" as const,
          oldIps: existing.ips,
          matchCount: active.matchCount,
          oldServices: existing.services.map((s) => s.id),
        };
      }
    }

    // ── Swap IP ──
    if (existing) {
      try {
        await ufwDeleteMany(existing.ips, flattenPorts(existing));
      } catch {
        // logged inside
      }
      draft.rules.splice(existingIdx, 1);
      await audit({
        kind: "admin.knock_replace",
        adminId,
        ips: existing.ips,
        reason: "ip_change",
      });
    }

    const errors = await ufwAllowMany(newIps, portList);
    const rule: FirewallRule = {
      ips: newIps,
      addedAt: new Date().toISOString(),
      label: `Admin: ${adminName}`,
      adminId,
      services: registry.buildRuleServices(),
    };
    draft.rules.push(rule);
    await audit({ kind: "admin.knock", adminId, ips: newIps });
    return { status: "ok" as const, rule, expiresAt: "", errors };
  });
}

/** Revoke the admin's auto-rule (leaves manual /firewall/add rules alone). */
export async function revokeAdmin(adminId: string): Promise<{ removed: boolean; ips?: string[] }> {
  return mutateRules(async (draft) => {
    // Prefer the adminId-tied rule. Fall back to legacy admin-type rules
    // (no userId and no adminId) that pre-date the self-knock migration —
    // removing one per call, so clicking revoke repeatedly cleans up
    // multiple stale rules without wiping unrelated manual entries in
    // one go.
    let idx = draft.rules.findIndex((r) => r.adminId === adminId);
    if (idx < 0) {
      idx = draft.rules.findIndex((r) => !r.userId && !r.adminId);
    }
    if (idx < 0) return { removed: false };
    const rule = draft.rules[idx]!;
    try {
      await ufwDeleteMany(rule.ips, flattenPorts(rule));
    } catch {
      // logged inside
    }
    draft.rules.splice(idx, 1);
    await audit({ kind: "admin.revoke", adminId, ips: rule.ips });
    return { removed: true, ips: rule.ips };
  });
}

/** Periodic sweep to remove expired firewall rules. */
export async function sweepExpiredRules(): Promise<number> {
  const now = Date.now();
  // UFW deletions run inside the same mutex that removes the rules from
  // the JSON file so a crash between the two cannot leave orphaned UFW
  // rules on the host.
  return mutateRules(async (draft) => {
    const remaining: FirewallRule[] = [];
    const expired: FirewallRule[] = [];
    for (const rule of draft.rules) {
      if (rule.expiresAt && new Date(rule.expiresAt).getTime() < now) {
        expired.push(rule);
      } else {
        remaining.push(rule);
      }
    }
    draft.rules = remaining;
    for (const rule of expired) {
      try {
        await ufwDeleteMany(rule.ips, flattenPorts(rule));
      } catch {
        // logged inside ufwDeleteMany
      }
      await audit({
        kind: "knock.auto_expire",
        userId: rule.userId ?? null,
        ips: rule.ips,
      });
    }
    return expired.length;
  });
}
