// service-worker.js
const PROXY_API = '/api/proxy';
const TOKEN_API = '/api/token'; // used by client to obtain a short-lived JWT
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB

self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

async function getToken() {
  // The page should fetch the token from a protected endpoint (e.g., admin UI or a cookie protected endpoint).
  // Here we request /api/token which should return { token } when the user is authenticated.
  try {
    const resp = await fetch(TOKEN_API, { credentials: 'include' });
    if (!resp.ok) throw new Error('token fetch failed');
    const j = await resp.json();
    return j.token;
  } catch (err) {
    console.error('token error', err);
    return null;
  }
}

function headersToObject(headers) {
  const o = {};
  for (const [k, v] of headers.entries()) o[k] = v;
  return o;
}

self.addEventListener('fetch', event => {
  const req = event.request;

  // Heuristic: only proxy navigations and subresource requests from your controlled pages.
  // Tweak `shouldProxy` allowlist as required.
  const url = new URL(req.url);
  const isSameOrigin = url.origin === self.location.origin;
  const shouldProxy = !isSameOrigin && (req.mode === 'navigate' || req.destination);

  if (!shouldProxy) return; // let normal fetch proceed

  event.respondWith((async () => {
    try {
      const token = await getToken();
      if (!token) return new Response('Unauthorized', { status: 401 });

      // Build proxy payload
      const proxyReq = {
        method: req.method,
        url: req.url,
        headers: headersToObject(req.headers)
      };

      let bodyBase64 = null;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const clone = req.clone();
        const ab = await clone.arrayBuffer();
        if (ab.byteLength > MAX_BODY_BYTES) return new Response('Request body too large', { status: 413 });
        bodyBase64 = btoa(String.fromCharCode(...new Uint8Array(ab)));
      }

      // POST to backend proxy endpoint with token in Authorization header
      const resp = await fetch(PROXY_API, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ proxyReq, bodyBase64 }),
        credentials: 'omit'
      });

      // If backend responds with a direct passthrough response (stream), return it
      if (!resp.ok) {
        // bubble up failure code & body
        const txt = await resp.text();
        return new Response(txt, { status: resp.status });
      }

      // We expect the backend to respond with a streamed Response body and safe headers.
      // For the example, backend sends full response as a normal fetch response we can just return.
      // If backend JSON-encodes body, adapt as needed.
      // To support streaming: backend should respond with what the SW can `return resp` directly.
      return resp;

    } catch (err) {
      console.error('SW proxy error', err);
      return new Response('Proxy failure', { status: 502 });
    }
  })());
});
