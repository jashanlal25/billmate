const CACHE_NAME = 'medlist-v6';
const urlsToCache = [
  '/',
  '/static/manifest.json'
];

// Install service worker
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting();
});

// Activate service worker
self.addEventListener('activate', event => {
  event.waitUntil(clients.claim());
});

// Fetch event
self.addEventListener('fetch', event => {
  // Handle share target
  if (event.request.url.includes('/share') && event.request.method === 'POST') {
    event.respondWith(Response.redirect('/?shared=true'));

    event.waitUntil(async function() {
      const data = await event.request.formData();
      const file = data.get('file');

      if (file) {
        const client = await self.clients.get(event.resultingClientId);
        client.postMessage({
          type: 'shared-file',
          file: file
        });
      }
    }());
    return;
  }

  // Normal fetch
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
