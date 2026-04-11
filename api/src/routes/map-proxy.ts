/**
 * BlueMap (and similar web-map) proxy.
 *
 * Each service can set a `mapProxy` block in services.json that points
 * at the game server's internal web-map port (BlueMap, dynmap, etc.).
 * The dashboard then proxies requests to `{context}/map/<id>/*` to that
 * internal address, so users can view the world map through the same
 * origin as the dashboard — no separate subdomain or upstream reverse
 * proxy required.
 *
 * Three mount contexts, each with its own auth gate:
 *
 *   /admin/map/:id/*        admin cookie (requireAdmin)
 *   /my/map/:id/*           portal cookie + allowedServices check
 *   /u/:token/map/:id/*     URL token + allowedServices check
 *
 * Each context's mapUrl resolver (in the services router, portal router,
 * knock-pwa router) returns the matching base path when `mapProxy` is
 * set, so the existing PWA/dashboard rendering code just sees `mapUrl`
 * and links to it.
 *
 * ── Limitations ────────────────────────────────────────────────────────
 * BlueMap must use relative asset paths for subpath hosting to work.
 * This is the default in BlueMap v5+. Older builds that emit absolute
 * `/assets/…` references will break — check the HTML of your BlueMap
 * index page if the map loads blank.
 *
 * WebSocket upgrades are intentionally NOT proxied in this first pass.
 * BlueMap's live-marker feature (which uses a WS channel) will fall
 * back to static tiles. Add WS upgrade handling if someone actually
 * uses the live feature.
 */

import type {
  NextFunction,
  Request,
  RequestHandler as ExpressRequestHandler,
  Response,
  Router,
} from "express";
import { Router as makeRouter } from "express";

/**
 * Narrow interface covering both Express `Application` and `Router`. We
 * declare exactly the `use(path, ...handlers)` overload we need, because
 * the full `Application | IRouter` union causes TS to collapse overload
 * resolution and lose the string-path form.
 */
interface Mountable {
  use(path: string, ...handlers: ExpressRequestHandler[]): unknown;
}
import { createProxyMiddleware, type RequestHandler } from "http-proxy-middleware";
import { requireAdmin } from "../auth/middleware";
import { readAndRefreshPortalSession } from "../auth/portal-sessions";
import { asyncH } from "../middleware/async-handler";
import { findById, findByToken } from "../repos/users";
import { registry } from "../services/registry";
import type { MapProxyTarget, ServiceAdapter } from "../services/types";

/** Build the absolute http://host:port target for a service's BlueMap. */
function targetUrl(mp: MapProxyTarget): string {
  return `${mp.scheme}://${mp.host}:${mp.port}`;
}

/**
 * Create the proxy middleware for a single service. The middleware
 * relies on `app.use("/.../:id", …)` to strip the mount prefix, so
 * `req.url` that reaches the proxy is already relative to the BlueMap
 * web-root (e.g. `/assets/index.js`).
 */
function buildProxy(svc: ServiceAdapter): RequestHandler {
  const mp = svc.mapProxy!;
  return createProxyMiddleware({
    target: targetUrl(mp),
    changeOrigin: true,
    // BlueMap sometimes redirects from `/` to `/index.html`; don't let
    // it leak its own hostname in the Location header.
    autoRewrite: true,
    followRedirects: false,
    // WebSocket support disabled for now — see file header.
    ws: false,
    // Keep log output sane in production.
    logLevel: "warn",
    onError: (err, _req, res) => {
      // Type-narrow: in the HTTP path the res is a ServerResponse.
      if ("headersSent" in res && !res.headersSent && "status" in res) {
        (res as Response).status(502).json({
          success: false,
          error: `map proxy error: ${err.message}`,
        });
      }
    },
  });
}

/**
 * Redirect bare `/…/map/:id` to `/…/map/:id/` so the browser's base
 * URL ends in a slash. Without this, relative asset paths in BlueMap's
 * index.html resolve one level too high and 404.
 */
function trailingSlashRedirect(basePath: string): (req: Request, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    // Express has already stripped the mount path, so req.url is just
    // what's left ("" or "/"). The original URL is in req.originalUrl.
    if (req.originalUrl === basePath) {
      res.redirect(301, `${basePath}/`);
      return;
    }
    next();
  };
}

/**
 * Admin map-proxy mount. Uses the existing `requireAdmin` middleware.
 * Admin cookie is scoped to `/admin`, so it is sent on these paths.
 */
export function mountAdminMapProxy(app: Mountable): void {
  for (const svc of registry().services.values()) {
    if (!svc.mapProxy) continue;
    const base = `/admin/map/${svc.id}`;
    const proxy = buildProxy(svc);
    app.use(base, trailingSlashRedirect(base), requireAdmin, proxy);
  }
}

/**
 * Portal map-proxy mount. Uses the portal cookie (gd_portal, scoped /),
 * and additionally requires the signed-in user to have the service in
 * `allowedServices`. Admins are not automatically granted here — they
 * use the /admin mount.
 */
export function mountPortalMapProxy(app: Mountable): void {
  for (const svc of registry().services.values()) {
    if (!svc.mapProxy) continue;
    const serviceId = svc.id;
    const base = `/my/map/${serviceId}`;
    const proxy = buildProxy(svc);

    const portalGate = asyncH(async (req: Request, res: Response, next: NextFunction) => {
      const session = await readAndRefreshPortalSession(req, res);
      if (!session) {
        res.status(401).json({ success: false, error: "portal login required" });
        return;
      }
      const user = await findById(session.userId);
      if (!user || !user.allowedServices.includes(serviceId)) {
        res.status(403).json({ success: false, error: "service not allowed" });
        return;
      }
      next();
    });

    app.use(base, trailingSlashRedirect(base), portalGate, proxy);
  }
}

/**
 * Token-URL map-proxy mount. Identity is carried in the URL path
 * (`/u/:token/map/:id/*`), the same way the rest of the knock PWA
 * works. We validate the token and the user's allowedServices before
 * forwarding.
 */
export function mountTokenMapProxy(app: Mountable): void {
  for (const svc of registry().services.values()) {
    if (!svc.mapProxy) continue;
    const serviceId = svc.id;
    const base = `/u/:token/map/${serviceId}`;
    const proxy = buildProxy(svc);

    const tokenGate = asyncH(async (req: Request, res: Response, next: NextFunction) => {
      const token = req.params["token"] ?? "";
      if (!token) {
        res.status(404).json({ success: false, error: "invalid token" });
        return;
      }
      const user = await findByToken(token);
      if (!user) {
        res.status(404).json({ success: false, error: "invalid token" });
        return;
      }
      if (!user.allowedServices.includes(serviceId)) {
        res.status(403).json({ success: false, error: "service not allowed" });
        return;
      }
      next();
    });

    // Trailing-slash redirect needs the concrete token-bearing URL, so
    // we compute it per-request instead of using a fixed `base`.
    app.use(base, (req: Request, res: Response, next: NextFunction) => {
      const concrete = `/u/${req.params["token"] ?? ""}/map/${serviceId}`;
      if (req.originalUrl === concrete) {
        res.redirect(301, `${concrete}/`);
        return;
      }
      next();
    }, tokenGate, proxy);
  }
}

/**
 * Resolve the mapUrl to surface to a given auth context. Returns the
 * proxied base path if the service has `mapProxy` set, otherwise the
 * adapter's raw `mapUrl` (which may be an absolute external URL),
 * otherwise undefined.
 */
export function resolveMapUrl(
  svc: ServiceAdapter,
  ctx: { kind: "admin" } | { kind: "portal" } | { kind: "token"; token: string },
): string | undefined {
  if (svc.mapProxy) {
    switch (ctx.kind) {
      case "admin":
        return `/admin/map/${svc.id}/`;
      case "portal":
        return `/my/map/${svc.id}/`;
      case "token":
        return `/u/${ctx.token}/map/${svc.id}/`;
    }
  }
  return svc.mapUrl;
}

/**
 * Convenience: build a Router that mounts all three contexts at once.
 * Unused today because each context is mounted in its own place for
 * middleware-ordering reasons, but kept for tests.
 */
export function buildMapProxyRouter(): Router {
  const router = makeRouter();
  mountAdminMapProxy(router);
  mountPortalMapProxy(router);
  mountTokenMapProxy(router);
  return router;
}
