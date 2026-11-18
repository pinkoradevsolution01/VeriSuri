const CACHE = 'verisuri-v3';
const APP_SHELL = ['/', '/index.html', '/manifest.webmanifest'];
self.addEventListener('install', event => event.waitUntil(
  caches.open(CACHE)
    .then(cache => cache.addAll(APP_SHELL))
    .catch(() => undefined)
    .then(() => self.skipWaiting())
));
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key)))).then(() => self.clients.claim())));
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  if (new URL(event.request.url).origin !== self.location.origin) return;

  // Never replace an API failure with the HTML shell. The React client can then
  // show its normal retry message instead of crashing while parsing HTML as JSON.
  if (new URL(event.request.url).pathname.startsWith('/api/')) return;

  if (event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).catch(() => caches.match('/index.html').then(response => response || Response.error())));
    return;
  }
  event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request).catch(() => Response.error())));
});
