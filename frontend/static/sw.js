const CACHE_NAME = 'billmate-v9';
const urlsToCache = [
  '/static/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png',
  '/static/icon-maskable-192.png',
  '/static/icon-maskable-512.png',
  '/static/share-store.js'
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
  const path = new URL(event.request.url).pathname;
  // Android WebView serves this URL from the staged attachment on the phone.
  if (path.startsWith('/share-target/native-file/')) return;
  if (event.request.method === 'POST' && path === '/share-target') {
    return; // let it hit the network untouched
  }

  // Everything else: network-first, cache only as offline fallback.
  // Authenticated/API pages are never written to cache.
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
