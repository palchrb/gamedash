/**
 * Unit tests for the in-process metrics registry.
 *
 * We only touch pure behaviour here: counter increment + exposition
 * string, gauge callback. The HTTP surface (/metrics route) is exercised
 * at integration level.
 */

import { describe, expect, it } from "vitest";
import { metrics, trackHttp } from "./metrics";

describe("metrics", () => {
  it("increments the http counter and renders the prometheus format", async () => {
    trackHttp("get", 200);
    trackHttp("GET", 200);
    trackHttp("POST", 404);
    trackHttp("PUT", 500);

    const body = await metrics().expose();
    expect(body).toContain("# TYPE gd_http_requests_total counter");
    expect(body).toMatch(/gd_http_requests_total\{method="GET",status="2xx"\} 2/);
    expect(body).toMatch(/gd_http_requests_total\{method="POST",status="4xx"\} 1/);
    expect(body).toMatch(/gd_http_requests_total\{method="PUT",status="5xx"\} 1/);
  });

  it("supports gauges backed by a callback", async () => {
    let current = 3;
    metrics().gauge("gd_test_gauge", "unit test gauge", () => current);
    let body = await metrics().expose();
    expect(body).toContain("gd_test_gauge 3");

    current = 42;
    body = await metrics().expose();
    expect(body).toContain("gd_test_gauge 42");
  });

  it("emits zero for counters that have never been touched", async () => {
    metrics().counter("gd_fresh_counter", "brand new");
    const body = await metrics().expose();
    expect(body).toContain("gd_fresh_counter 0");
  });
});
