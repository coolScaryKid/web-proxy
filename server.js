// server.js (Node 18+)
// Minimal internal proxy handler. MUST be hardened before production (auth, allowlists, sanitizers).

import express from 'express';
import { request as undiciRequest } from 'undici'; // fast HTTP client
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' })); // incoming proxy-control payload limit

// simple admin / control endpoints would go here, protected by auth

// rate limiting to avoid abuse
const limiter = rateLimit({ windowMs: 1000, max: 20 });
app.use('/_/proxy', limiter);

// configure allowlist
const HOST_ALLOWLIST = new Set([
  'example.com',
  'example-internal.test'
  // add permitted hostnames
]);

function hostnameAllowed(urlStr) {
  try {
    const u = new URL(urlStr);
    return HOST_ALLOWLIST.has(u.hostname);
  } catch {
    return false;
  }
}

app.post('/_/proxy', async (req, res) => {
  try {
    // Basic auth: ensure request is from an authenticated SW (cookie / header / mTLS)
    // TODO: implement robust auth/CSRF protections
    const { proxyReq, body } = req.body;
    if (!proxyReq || !proxyReq.url) return res.status(400).send('bad request');

    if (!hostnameAllowed(proxyReq.url)) return res.status(403).send('destination not allowed');

    // recreate headers (but ensure we never forward certain headers)
    const outHeaders = {...(proxyReq.headers || {})};
    delete outHeaders['cookie'];
    delete outHeaders['authorization'];
    delete outHeaders['proxy-authorization'];
    // enforce a safe User-Agent
    outHeaders['user-agent'] = 'internal-sandbox-proxy/1.0';

    // handle body
    let bodyStream = null;
    if (body) {
      // body was base64-encoded
      const buf = Buffer.from(body, 'base64');
      bodyStream = buf;
    }

    // perform outbound request with timeouts and streaming
    const clientRes = await undiciRequest(proxyReq.url, {
      method: proxyReq.method,
      headers: outHeaders,
      body: bodyStream,
      maxRedirections: 5,
      throwOnError: true,
      // timeouts
      headersTimeout: 10_000,
      bodyTimeout: 30_000
    });

    // stream response back but do not forward dangerous headers
    const safeHeaders = {};
    for (const [k, v] of clientRes.headers) {
      const lk = k.toLowerCase();
      if (['set-cookie', 'set-cookie2', 'server'].includes(lk)) continue;
      safeHeaders[k] = v;
    }
    // stream body into memory up to a limit (example). For larger payloads, stream and chunk.
    const buffer = await clientRes.body.arrayBuffer();
    if (buffer.byteLength > 10 * 1024 * 1024) { // 10 MB cap (example)
      return res.status(502).send('Response too large');
    }

    res.json({
      status: clientRes.statusCode,
      headers: safeHeaders,
      bodyBase64: Buffer.from(buffer).toString('base64')
    });

  } catch (err) {
    console.error('Proxy error', err);
    res.status(502).send('proxy error');
  }
});

app.listen(8443, () => console.log('Proxy listening on 8443'));
