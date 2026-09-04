const CACHE_NAME = 'billmate-v7';
const urlsToCache = [
  '/static/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png'
];

// Install service worker
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting();
});

// Activate — purge old cache versions so updated manifest/JS reaches installed devices
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Fetch event
self.addEventListener('fetch', event => {
  // POST /share-target is a one-shot upload with a fresh bridge page each
  // time — never cache or intercept it (network-only).
  if (event.request.method === 'POST' &&
      new URL(event.request.url).pathname === '/share-target') {
    return; // let it hit the network untouched
  }

  // Everything else: network-first, cache only as offline fallback.
  // Authenticated/API pages are never written to cache.
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
