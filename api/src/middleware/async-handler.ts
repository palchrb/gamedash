/**
 * Wrap an async Express route so rejected promises are forwarded to
 * the error handler instead of crashing the process with an unhandled
 * rejection.
 */

import type { NextFunction, Request, Response } from "express";

type AsyncHandler = (req: Request, res: Response, next: NextFunction) => Promise<unknown>;

export function asyncH(fn: AsyncHandler) {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };
}
