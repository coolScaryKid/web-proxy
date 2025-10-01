// service-worker.js
const PROXY_ENDPOINT = '/_/proxy'; // internal proxy endpoint on same origin
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB request limit (example)

self.addEventListener('install', event => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

// small helper to copy headers to plain object
function headersToObject(headers) {
  const obj = {};
  for (const [k, v] of headers.entries()) obj[k] = v;
  return obj;
}

// sanitize request before sending to proxy
function buildProxyRequest(originalRequest) {
  const url = new URL(originalRequest.url);

  // enforce same-origin scope: allow only requests we intend to proxy
  // (customize allowlist rules here)
  if (!url.protocol.startsWith('http')) throw new Error('Non-http(s) not allowed');

  // Remove disallowed headers (Authorization, Cookie etc.) by default
  const forbidden = ['authorization', 'cookie', 'proxy-authorization', 'x-forwarded-for'];
  const headers = {};
  for (const [k, v] of originalRequest.headers.entries()) {
    if (!forbidden.includes(k.toLowerCase())) headers[k] = v;
  }

  return {
    method: originalRequest.method,
    url: originalRequest.url,
    headers,
    // note: body streaming in Service Worker is available via clone().arrayBuffer() or .blob()
    // keep small; for large streaming requests, implement chunked upload to /_/proxy/upload
  };
}

self.addEventListener('fetch', event => {
  const req = event.request;

  // You may want to limit which requests are proxied. Example: only top-level document & subresources.
  const isNavigation = req.mode === 'navigate';
  const shouldProxy = true; // implement allowlist logic here

  if (!shouldProxy) return; // let normal fetch proceed

  event.respondWith((async function() {
    try {
      const proxyReq = buildProxyRequest(req);
      let body = null;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        // small-body read; abort if too large
        const ab = await req.clone().arrayBuffer();
        if (ab.byteLength > MAX_BODY_BYTES) {
          return new Response('Request body too large', { status: 413 });
        }
        // we base64 encode binary body to keep JSON simple (or use multipart/stream)
        body = btoa(String.fromCharCode(...new Uint8Array(ab)));
      }

      const resp = await fetch(PROXY_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ proxyReq, body })
      });

      // Proxy server returns: { status, headers, bodyBase64 } streamed or in one chunk
      if (!resp.ok) return resp;

      // If server streams a real Response, we can instead do `return resp` directly.
      const proxyResp = await resp.json();
      const headers = new Headers(proxyResp.headers || {});
      // set safe headers, override Content-Security-Policy (example)
      headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline';");
      // ensure we do not allow top navigation by default
      headers.set('X-Frame-Options', 'DENY');

      const bodyBytes = proxyResp.bodyBase64 ? Uint8Array.from(atob(proxyResp.bodyBase64), c => c.charCodeAt(0)) : new Uint8Array();
      return new Response(bodyBytes, { status: proxyResp.status, headers });
    } catch (err) {
      console.error('Proxy SW error', err);
      return new Response('Proxy error', { status: 502 });
    }
  })());
});
