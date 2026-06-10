/**
 * Service Worker для «Три Короны»
 * 
 * Стратегия: Cache First для статических ассетов, Network Only для API.
 * Версия: tri-korony-shell-v4
 */

'use strict';

const CACHE_NAME    = 'tri-korony-shell-v6';
const SHELL_ASSETS  = ['/', '/index.html', '/manifest.json', '/icon.svg'];

// Паттерны запросов, которые НИКОГДА не кешируются
const NO_CACHE_PATTERNS = [
  /firestore\.googleapis\.com/,
  /firebase\.googleapis\.com/,
  /identitytoolkit\.googleapis\.com/,
  /securetoken\.googleapis\.com/,
  /fonts\.googleapis\.com/,        // шрифты — живые, не кешируем
  /fonts\.gstatic\.com/,
  /gstatic\.com\/firebasejs/,       // Firebase SDK — не кешируем
  /localhost:3001/,                 // push-сервер
  /\/api\//,                        // API-запросы
];

function shouldSkipCache(url) {
  return NO_CACHE_PATTERNS.some(pattern => pattern.test(url));
}

// ─── INSTALL ───
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW] Кешируем ассеты оболочки...');
        // addAll падает если хотя бы один ассет недоступен.
        // Используем Promise.allSettled для устойчивости.
        return Promise.allSettled(
          SHELL_ASSETS.map(url => cache.add(url).catch(err => {
            console.warn(`[SW] Не удалось закешировать ${url}:`, err.message);
          }))
        );
      })
      .then(() => {
        console.log('[SW] Установка завершена.');
        return self.skipWaiting();
      })
      .catch(err => console.error('[SW] Ошибка при установке:', err))
  );
});

// ─── ACTIVATE ───
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => {
            console.log('[SW] Удаляем старый кеш:', key);
            return caches.delete(key);
          })
      ))
      .then(() => {
        console.log('[SW] Активация завершена.');
        return self.clients.claim();
      })
      .catch(err => console.error('[SW] Ошибка при активации:', err))
  );
});

// ─── FETCH ───
self.addEventListener('fetch', (event) => {
  // Только GET
  if (event.request.method !== 'GET') return;

  const url = event.request.url;

  // API и внешние сервисы — только сеть, без кеша
  if (shouldSkipCache(url)) {
    event.respondWith(
      fetch(event.request).catch(err => {
        console.warn('[SW] Network error (no cache):', url, err.message);
        return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
      })
    );
    return;
  }

  // Статические ассеты — Cache First, fallback сеть → /index.html
  event.respondWith(
    caches.match(event.request)
      .then((cached) => {
        if (cached) return cached;
        return fetch(event.request)
          .then((response) => {
            // Кешируем только успешные ответы с того же origin или CDN-ассеты
            if (
              response.ok &&
              (response.type === 'basic' || response.type === 'cors') &&
              !shouldSkipCache(url)
            ) {
              const clone = response.clone();
              caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
            }
            return response;
          })
          .catch(() => {
            // Оффлайн — возвращаем оболочку приложения
            return caches.match('/index.html');
          });
      })
      .catch((err) => {
        console.warn('[SW] Ошибка кеша:', err.message);
        return caches.match('/index.html');
      })
  );
});

// ─── PUSH УВЕДОМЛЕНИЯ ───
self.addEventListener('push', (event) => {
  if (!event.data) return;
  let payload = { title: 'Три Короны', body: '', action: '', icon: '/icon.svg' };
  try {
    payload = { ...payload, ...event.data.json() };
  } catch (e) {
    payload.body = event.data.text();
  }

  const options = {
    body:    payload.body,
    icon:    payload.icon || '/icon.svg',
    badge:   payload.icon || '/icon.svg',
    tag:     payload.action || 'tri-korony',
    data:    { action: payload.action },
    vibrate: [200, 100, 200],
    requireInteraction: false
  };

  event.waitUntil(
    self.registration.showNotification(payload.title, options)
  );
});

// ─── NOTIFICATION CLICK ───
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const action = event.notification.data?.action || '';
  let url = '/';
  if (action === 'view-checkouts') url = '/?action=checkouts';
  if (action === 'view-guests')    url = '/?action=all-guests';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((windowClients) => {
        for (const client of windowClients) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            client.postMessage({ type: 'NOTIFICATION_CLICK', action });
            return client.focus();
          }
        }
        if (clients.openWindow) return clients.openWindow(url);
      })
  );
});

// ─── SKIP WAITING (от главной страницы) ───
self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting().then(() => {
      return self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    }).then((clients) => {
      clients.forEach((client) => client.postMessage({ type: 'SW_UPDATED' }));
    }).catch((err) => console.warn('[SW] skipWaiting failed:', err));
  }
});