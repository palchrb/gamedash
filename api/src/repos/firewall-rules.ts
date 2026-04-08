/**
 * Firewall rules repository — the durable "who is allowed, on which
 * ports, until when" state. The live UFW rules should always match this
 * file; if they drift, this file wins (sweep + re-apply is the fix).
 */

import { config } from "../config";
import { readJson, withLock, writeJson } from "../lib/atomic-file";
import {
  type FirewallRule,
  type FirewallRulesFile,
  FirewallRulesFileSchema,
  type PortSpec,
} from "../schemas";

function filePath(): string {
  return config().firewallRulesFile;
}

export async function loadRules(): Promise<FirewallRulesFile> {
  return readJson(filePath(), FirewallRulesFileSchema, { rules: [] });
}

export async function saveRules(data: FirewallRulesFile): Promise<void> {
  await writeJson(filePath(), FirewallRulesFileSchema, data);
}

/** Run a transactional mutation: load → mutate → save under a per-file lock. */
export async function mutateRules(
  fn: (draft: FirewallRulesFile) => Promise<void> | void,
): Promise<void> {
  await withLock(`fw:${filePath()}`, async () => {
    const draft = await loadRules();
    await fn(draft);
    await saveRules(draft);
  });
}

export async function findRuleByIp(ip: string): Promise<FirewallRule | null> {
  const data = await loadRules();
  return data.rules.find((r) => r.ip === ip) ?? null;
}

export async function findRuleByUserId(userId: string): Promise<FirewallRule | null> {
  const data = await loadRules();
  return data.rules.find((r) => r.userId === userId) ?? null;
}

export async function upsertRule(rule: FirewallRule): Promise<void> {
  await mutateRules((draft) => {
    const idx = draft.rules.findIndex((r) =>
      rule.userId ? r.userId === rule.userId : r.ip === rule.ip,
    );
    if (idx >= 0) draft.rules[idx] = rule;
    else draft.rules.push(rule);
  });
}

export async function deleteRuleByIp(ip: string): Promise<void> {
  await mutateRules((draft) => {
    draft.rules = draft.rules.filter((r) => r.ip !== ip);
  });
}

export async function deleteRuleByUserId(userId: string): Promise<void> {
  await mutateRules((draft) => {
    draft.rules = draft.rules.filter((r) => r.userId !== userId);
  });
}

/** Flatten a rule's services into a deduplicated [{port,proto}] list. */
export function flattenPorts(rule: FirewallRule): PortSpec[] {
  const seen = new Set<string>();
  const out: PortSpec[] = [];
  for (const svc of rule.services) {
    for (const p of svc.ports) {
      const key = `${p.port}/${p.proto}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ port: String(p.port), proto: p.proto });
    }
  }
  return out;
}
