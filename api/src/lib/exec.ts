/**
 * Typed promise wrappers around child_process.
 *
 * All exec calls must have a timeout. Callers never pass user input into
 * `exec` — we always use `execFile` with an explicit argv, so shell
 * metacharacters cannot result in injection.
 */

import { execFile as execFileCb, type ExecFileOptions } from "node:child_process";

export interface ExecResult {
  stdout: string;
  stderr: string;
}

export interface RunOpts {
  timeoutMs: number;
  maxBufferBytes?: number;
  env?: NodeJS.ProcessEnv;
}

export function runCmd(
  cmd: string,
  args: readonly string[],
  opts: RunOpts,
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const execOpts: ExecFileOptions = {
      timeout: opts.timeoutMs,
      maxBuffer: opts.maxBufferBytes ?? 4 * 1024 * 1024,
      env: opts.env,
    };
    execFileCb(cmd, args, execOpts, (err, stdoutBuf, stderrBuf) => {
      const stdout = typeof stdoutBuf === "string" ? stdoutBuf : stdoutBuf.toString("utf8");
      const stderr = typeof stderrBuf === "string" ? stderrBuf : stderrBuf.toString("utf8");
      if (err) {
        const e = new Error(stderr.trim() || err.message) as Error & {
          code?: number | string;
          stdout?: string;
          stderr?: string;
        };
        e.code = (err as NodeJS.ErrnoException).code;
        e.stdout = stdout;
        e.stderr = stderr;
        reject(e);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}
