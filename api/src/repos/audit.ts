/**
 * Audit log — append-only JSONL file.
 *
 * One event per line, each event carries `at` (ISO timestamp) + `kind`
 * (string) + arbitrary payload. Rotation is handled by an external log
 * rotator (or Docker's default). We do not ever truncate this file
 * ourselves because it is the forensic record of who touched what.
 */

import { config } from "../config";
import { appendJsonLine } from "../lib/atomic-file";
import { logger } from "../logger";

export type AuditEvent = Record<string, unknown> & { kind: string };

export async function audit(event: AuditEvent): Promise<void> {
  try {
    await appendJsonLine(config().auditLog, {
      at: new Date().toISOString(),
      ...event,
    });
  } catch (err) {
    // Never let audit failure break the request. Log loudly instead.
    logger().error({ err: (err as Error).message, event }, "audit write failed");
  }
}
