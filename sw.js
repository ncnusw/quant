/* Service worker for the password-protected course site.
   Every file of the site is stored encrypted in enc/ under a name derived from its path.
   After the password is entered (index.html stores the keys in IndexedDB), this worker
   answers each request in its folder by fetching the encrypted file and decrypting it.
   Without keys it lets the password page through and sends everything else back to it. */
'use strict';
var SCOPE = self.registration.scope;            // e.g. https://ncnusw.github.io/quant/
var BASE = new URL(SCOPE).pathname;              // e.g. /quant/
var DB = 'quant-site', STORE = 'kv', SLOT = 'keys';
var VERSION = 'e6b33a37fa8c41f0';                     // changes when the password or salt changes
var keys = null;

var TYPES = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8', json: 'application/json; charset=utf-8',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  ico: 'image/x-icon', pdf: 'application/pdf', woff2: 'font/woff2', woff: 'font/woff', ttf: 'font/ttf',
  txt: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8', r: 'text/plain; charset=utf-8',
  qmd: 'text/plain; charset=utf-8', yml: 'text/plain; charset=utf-8', xml: 'application/xml',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  zip: 'application/zip', rds: 'application/octet-stream', rdata: 'application/octet-stream', sav: 'application/octet-stream',
  dta: 'application/octet-stream', mp4: 'video/mp4', mp3: 'audio/mpeg', html5: 'text/html'
};
var DOWNLOAD = { docx: 1, xlsx: 1, pptx: 1, zip: 1, rds: 1, rdata: 1, sav: 1, dta: 1, csv: 1, r: 1 };

function idb() {
  return new Promise(function (ok, no) {
    var r = indexedDB.open(DB, 1);
    r.onupgradeneeded = function () { r.result.createObjectStore(STORE); };
    r.onsuccess = function () { ok(r.result); }; r.onerror = function () { no(r.error); };
  });
}
function idbGet(k) {
  return idb().then(function (db) { return new Promise(function (ok) {
    var q = db.transaction(STORE).objectStore(STORE).get(k); q.onsuccess = function () { ok(q.result); }; q.onerror = function () { ok(undefined); };
  }); }).catch(function () { return undefined; });
}
function idbDel(k) {
  return idb().then(function (db) { return new Promise(function (ok) {
    var t = db.transaction(STORE, 'readwrite'); t.objectStore(STORE).delete(k); t.oncomplete = function () { ok(); }; t.onerror = function () { ok(); };
  }); }).catch(function () {});
}
function getKeys() {
  if (keys) return Promise.resolve(keys);
  return idbGet(SLOT).then(function (k) {
    if (k && k.version === VERSION) { keys = k; return k; }
    return null;
  });
}
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener('message', function (e) {
  if (e.data === 'lock') { keys = null; e.waitUntil(idbDel(SLOT)); }
  if (e.data === 'reload-keys') { keys = null; }
});

function gate(rel) {
  return Response.redirect(SCOPE + (rel && rel !== 'index.html' ? '?next=' + encodeURIComponent(rel) : ''), 302);
}

self.addEventListener('fetch', function (e) {
  var url = new URL(e.request.url);
  if (url.origin !== location.origin || url.pathname.indexOf(BASE) !== 0 || e.request.method !== 'GET') return;
  var rel = url.pathname.slice(BASE.length);
  if (rel === 'sw.js' || rel.indexOf('enc/') === 0) return;          // the worker itself and the encrypted files
  try { rel = decodeURIComponent(rel); } catch (err) {}
  if (rel === '' || rel.slice(-1) === '/') rel += 'index.html';
  var nav = e.request.mode === 'navigate';
  e.respondWith(getKeys().then(function (k) {
    if (!k) {
      if (rel === 'index.html' || rel === '404.html') return fetch(e.request);   // the password page
      return nav ? gate(rel) : new Response('Locked', { status: 401 });
    }
    if (nav) self.registration.update().catch(function () {});   // pick up a new password/version promptly
    return serve(rel, k, nav).then(function (res) {
      if (res) return res;
      if (rel === 'index.html') {        // the home page always exists, so the key is outdated (password changed)
        keys = null;
        return idbDel(SLOT).then(function () { return fetch(e.request); });
      }
      if (!/\.[a-z0-9]+$/i.test(rel)) return serve(rel + '/index.html', k, nav).then(function (r2) { return r2 || notFound(); });
      return notFound();
    });
  }));
});

function notFound() {
  return new Response('<!doctype html><meta charset="utf-8"><title>Not found</title><body style="font:16px system-ui;margin:3em">' +
    '<p>This page does not exist on the course site. 找不到此頁面。</p><p><a href="' + SCOPE + '">Course home 課程首頁</a></p>',
    { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function serve(rel, k, nav) {
  return crypto.subtle.sign('HMAC', k.mac, new TextEncoder().encode(rel)).then(function (sig) {
    return fetch(SCOPE + 'enc/' + hex(sig).slice(0, 32), { cache: 'no-cache' });
  }).then(function (r) {
    if (!r.ok) return null;
    return r.arrayBuffer().then(function (buf) {
      var iv = buf.slice(0, 12), ct = buf.slice(12);
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, k.aes, ct).then(function (plain) {
        var ext = (rel.match(/\.([a-z0-9]+)$/i) || [, ''])[1].toLowerCase();
        var h = { 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': 'no-store' };
        if (DOWNLOAD[ext]) h['Content-Disposition'] = 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(rel.split('/').pop());
        return new Response(plain, { status: 200, headers: h });
      }, function () {
        // wrong or outdated key (the password was changed): forget it and show the password page
        keys = null;
        return idbDel(SLOT).then(function () { return nav ? gate(rel) : new Response('Locked', { status: 401 }); });
      });
    });
  });
}
