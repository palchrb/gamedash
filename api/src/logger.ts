/**
 * Pino logger configured from env.
 *
 * JSON output in production (structured logs, easy to ship to any aggregator).
 * Pretty output opt-in via LOG_PRETTY=true for local dev.
 *
 * Secrets are redacted at serialization time so tokens, cookies and
 * WebAuthn signatures never appear in logs even if we accidentally log
 * an object containing them.
 */

import pino from "pino";
import { config } from "./config";

const REDACT_PATHS = [
  'req.headers["authorization"]',
  'req.headers["cookie"]',
  'req.headers["set-cookie"]',
  'res.headers["set-cookie"]',
  "*.token",
  "*.password",
  "*.publicKey",
  "*.privateKey",
  "*.sessionId",
  "*.clientDataJSON",
  "*.authenticatorData",
  "*.signature",
];

let _logger: pino.Logger | null = null;

export function logger(): pino.Logger {
  if (_logger) return _logger;
  const c = config();
  const opts: pino.LoggerOptions = {
    level: c.LOG_LEVEL,
    redact: { paths: REDACT_PATHS, censor: "[REDACTED]" },
    base: undefined, // drop hostname/pid from every record
    timestamp: pino.stdTimeFunctions.isoTime,
  };
  if (c.LOG_PRETTY) {
    _logger = pino({
      ...opts,
      transport: {
        target: "pino-pretty",
        options: { colorize: true, singleLine: true },
      },
    });
  } else {
    _logger = pino(opts);
  }
  return _logger;
}

export function resetLoggerForTests(): void {
  _logger = null;
}
