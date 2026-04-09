/**
 * Central error handler.
 *
 * Converts thrown errors into JSON {success: false, error} responses
 * with appropriate status codes. Logs the full error at debug/warn
 * depending on severity.
 */

import type { ErrorRequestHandler } from "express";
import { ZodError } from "zod";
import { logger } from "../logger";

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const log = logger().child({ path: req.path, method: req.method });
  if (err instanceof HttpError) {
    log.warn({ status: err.status, err: err.message }, "http error");
    res.status(err.status).json({ success: false, error: err.message });
    return;
  }
  if (err instanceof ZodError) {
    const msg = err.issues
      .map((i) => `${i.path.join(".") || "body"}: ${i.message}`)
      .join("; ");
    log.warn({ err: msg }, "validation error");
    res.status(400).json({ success: false, error: msg });
    return;
  }
  const error = err instanceof Error ? err : new Error(String(err));
  log.error({ err: error.message, stack: error.stack }, "unhandled error");
  res.status(500).json({ success: false, error: "internal server error" });
};
