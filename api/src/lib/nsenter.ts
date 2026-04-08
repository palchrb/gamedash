/**
 * nsenter wrapper — runs a command from the host's namespaces via the
 * privileged `ufw-agent` sidecar. Used for UFW (firewall mutations) and
 * `ss` / `conntrack` (live connection state).
 *
 * Everything goes through docker exec into the agent container, which
 * has `pid: host` + `privileged: true`, so `nsenter -t 1` lands us in
 * the host's mount/net/pid/ipc/uts namespaces.
 */

import { config } from "../config";
import { runCmd, type ExecResult } from "./exec";

function agentArgs(): string[] {
  const c = config();
  return [
    "exec",
    c.UFW_AGENT_CONTAINER,
    "nsenter",
    "-t",
    "1",
    "-m",
    "-u",
    "-i",
    "-n",
    "-p",
    "--",
  ];
}

export function nsenterRun(args: readonly string[], timeoutMs: number): Promise<ExecResult> {
  return runCmd("docker", [...agentArgs(), ...args], { timeoutMs });
}
