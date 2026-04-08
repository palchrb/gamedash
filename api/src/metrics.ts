/**
 * Minimal in-process Prometheus metrics.
 *
 * We intentionally avoid the prom-client dependency: the surface area we
 * want is tiny (a handful of counters + gauges) and we'd rather keep
 * dependencies down. The exposition format is the Prometheus v0.0.4
 * text format, which is only a few lines of string concatenation.
 *
 * Register once at module load via the `metrics` singleton. Routes /
 * the error handler / the request logger bump counters. /metrics
 * simply serialises the current state.
 */

interface Counter {
  kind: "counter";
  name: string;
  help: string;
  values: Map<string, number>; // labelset → value
}

interface Gauge {
  kind: "gauge";
  name: string;
  help: string;
  compute: () => Promise<number> | number;
}

type Metric = Counter | Gauge;

class MetricsRegistry {
  private metrics = new Map<string, Metric>();

  counter(name: string, help: string): Counter {
    const existing = this.metrics.get(name);
    if (existing && existing.kind === "counter") return existing;
    const c: Counter = { kind: "counter", name, help, values: new Map() };
    this.metrics.set(name, c);
    return c;
  }

  gauge(name: string, help: string, compute: Gauge["compute"]): Gauge {
    const g: Gauge = { kind: "gauge", name, help, compute };
    this.metrics.set(name, g);
    return g;
  }

  inc(counter: Counter, labels?: Record<string, string>, delta = 1): void {
    const key = serialiseLabels(labels);
    counter.values.set(key, (counter.values.get(key) ?? 0) + delta);
  }

  async expose(): Promise<string> {
    const lines: string[] = [];
    for (const metric of this.metrics.values()) {
      lines.push(`# HELP ${metric.name} ${metric.help}`);
      lines.push(`# TYPE ${metric.name} ${metric.kind}`);
      if (metric.kind === "counter") {
        if (metric.values.size === 0) {
          lines.push(`${metric.name} 0`);
        } else {
          for (const [labelStr, value] of metric.values) {
            lines.push(
              `${metric.name}${labelStr ? `{${labelStr}}` : ""} ${value}`,
            );
          }
        }
      } else {
        try {
          const value = await metric.compute();
          lines.push(`${metric.name} ${Number.isFinite(value) ? value : 0}`);
        } catch {
          lines.push(`${metric.name} 0`);
        }
      }
    }
    return `${lines.join("\n")}\n`;
  }
}

function serialiseLabels(labels?: Record<string, string>): string {
  if (!labels) return "";
  const entries = Object.entries(labels);
  if (entries.length === 0) return "";
  return entries
    .map(([k, v]) => `${k}="${String(v).replace(/\\/gu, "\\\\").replace(/"/gu, '\\"')}"`)
    .join(",");
}

// ── singleton + named metrics ──────────────────────────────────────────

const registry = new MetricsRegistry();

export const httpRequests = registry.counter(
  "gd_http_requests_total",
  "HTTP requests handled, labelled by method / status bucket",
);

export const knockAttempts = registry.counter(
  "gd_knock_attempts_total",
  "Knock requests processed (any outcome)",
);

export const adminLogins = registry.counter(
  "gd_admin_logins_total",
  "Successful admin passkey logins",
);

export const knockLogins = registry.counter(
  "gd_knock_logins_total",
  "Successful knock passkey logins",
);

export const authFailures = registry.counter(
  "gd_auth_failures_total",
  "Authentication failures (401 / 403 on auth endpoints)",
);

export function metrics(): MetricsRegistry {
  return registry;
}

export function trackHttp(method: string, status: number): void {
  const bucket =
    status >= 500 ? "5xx" : status >= 400 ? "4xx" : status >= 300 ? "3xx" : "2xx";
  registry.inc(httpRequests, { method: method.toUpperCase(), status: bucket });
}

export function incCounter(
  counter: Counter,
  labels?: Record<string, string>,
  delta = 1,
): void {
  registry.inc(counter, labels, delta);
}

/**
 * Install the gauges that need a live callback. Called from server.ts
 * after the registry is initialised so the gauges can read it.
 */
export function registerRuntimeGauges(params: {
  countServices: () => number | Promise<number>;
  countAdminSessions: () => number | Promise<number>;
  countKnockSessions: () => number | Promise<number>;
  countFirewallRules: () => number | Promise<number>;
}): void {
  registry.gauge("gd_services", "Registered game services", params.countServices);
  registry.gauge(
    "gd_admin_sessions",
    "Active admin sessions (unexpired)",
    params.countAdminSessions,
  );
  registry.gauge(
    "gd_knock_sessions",
    "Active knock sessions (unexpired)",
    params.countKnockSessions,
  );
  registry.gauge(
    "gd_firewall_rules",
    "Active firewall rules",
    params.countFirewallRules,
  );
  registry.gauge("gd_process_uptime_seconds", "Node process uptime", () =>
    Math.round(process.uptime()),
  );
}
