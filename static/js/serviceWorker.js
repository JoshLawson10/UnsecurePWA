const CACHE_NAME = "pwa-assets-v2";

const ASSETS = [
  "/",
  "/static/css/style.css",
  "/static/js/app.js",
  "/static/images/logo.svg",
  "/static/images/favicon.png",
  "/static/icons/icon-128x128.png",
  "/static/icons/icon-192x192.png",
  "/static/icons/icon-384x384.png",
  "/static/icons/icon-512x512.png",
];

self.addEventListener("install", (evt) => {
  evt.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
      .catch((e) => console.error("Service worker install failed:", e)),
  );
});

self.addEventListener("activate", (evt) => {
  evt.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (evt) => {
  const { request } = evt;

  if (request.method !== "GET") return;

  if (request.mode === "navigate") {
    evt.respondWith(
      fetch(request).catch(() =>
        caches.open(CACHE_NAME).then((cache) => cache.match("/")),
      ),
    );
    return;
  }

  evt.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      cache.match(request).then(
        (cached) =>
          cached ||
          fetch(request).then((response) => {
            // Only cache successful, same-origin responses.
            if (response.ok && response.type === "basic") {
              cache.put(request, response.clone());
            }
            return response;
          }),
      ),
    ),
  );
});
