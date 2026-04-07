/**
 * Service worker for the personal Knock PWA.
 *
 * Minimal by design: we deliberately do NOT do silent background knocks
 * here, because the auto-knock-on-launch flow combined with the anchor-IP
 * guard in u.js is the only safe pattern (see plan §7 for the security
 * rationale around silent push-knocks). The service worker exists primarily
 * so the app is installable as a real PWA on iOS / Android / desktop.
 *
 * If you later add opt-in reminder Web Push notifications, the `push`
 * handler below should ONLY display a notification — never call the knock
 * endpoint without explicit user interaction (notificationclick).
 */

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// No fetch handler — we want network-first behavior so the user always
// sees fresh state, and we don't want to cache the auto-knock response.

// Push handler: show a notification, do NOT auto-knock.
self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = { title: "Reminder", body: event.data ? event.data.text() : "" };
  }
  event.waitUntil(
    self.registration.showNotification(payload.title || "Game session reminder", {
      body: payload.body || "Tap to renew your session.",
      data: { url: payload.url || "/" },
    }),
  );
});

// Notification click: open the PWA (which will then auto-knock with the
// usual anchor-IP guard, requiring no extra logic here).
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(self.clients.openWindow(target));
});
