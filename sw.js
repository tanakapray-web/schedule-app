// Preparation version: never cache authenticated API responses.
const CACHE = 'schedule-auth-preparation-v2';
const OWN_OLD_CACHES = ['schedule-v1'];
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async()=>{
  for (const name of await caches.keys()) if (OWN_OLD_CACHES.includes(name) || (name.startsWith('schedule-auth-') && name !== CACHE)) await caches.delete(name);
  await self.clients.claim();
})()));
// Network-only by design. Offline data entry is not permitted during restoration.
