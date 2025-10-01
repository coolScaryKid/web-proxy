// server.js
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { request as undiciRequest } from 'undici';
import jwt from 'jsonwebtoken';
import { lookup } from 'dns/promises';
import ipaddr from 'ipaddr.js';
import sanitizeHtml from 'sanitize-html';
import fs from 'fs';
import { pipeline } from 'stream';
import { promisify } from 'util';

const pipe = promisify(pipeline);

const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// Config (use env variables in production)
const PORT = process.env.PORT ? Number(process.env.PORT) : 8443;
const JWT_SECRET = process.env.JWT_SECRET || 'replace-with-secure-random'; // rotate and store in KMS
const TOKEN_TTL_SECS = 60 * 5; // 5 minutes
const MAX_RESPONSE_BYTES = 25 * 1024 * 1024; // 25 MB per response
const PER_REQUEST_TIMEOUT_MS = 30_000; // 30s per request

// Allowlist of hostnames (only these hostnames may be proxied)
const HOSTNAME_ALLOWLIST = new Set((process.env.HOST_ALLOWLIST || 'example.com').split(',').map(h=>h.trim()).filter(Boolean));

// For special cases, allowlist specific IPs (CIDR supported). Example: '10.0.0.0/8'
const IP_ALLOWLIST_CIDRS = (process.env.IP_ALLOWLIST_CIDRS || '').split(',').map(s=>s.trim()).filter(Boolean);

// Rate limiter for proxy endpoint
app.use('/api/proxy', rateLimit({ windowMs: 1000, max: 20 }));

// Simple admin token endpoint (in production require admin auth + CSRF protection).
// This demo returns a JWT for the Service Worker to use. In production, mint tokens per-user/session.
app.post('/api/token', (req, res) => {
  // In production verify user session, cookie, or admin credentials.
  // This example allows only requests from same-origin with a cookie-based session (simulate).
  // For now: permit localhost calls as simple demo.
  const payload = { iss: 'sandbox-proxy', sub: 'sw-client' };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_TTL_SECS + 's' });
  res.json({ token, expiresIn: TOKEN_TTL_SECS });
});

// Helper: reject IPs in private ranges unless explicitly allowlisted
function isPrivateIP(ipStr) {
  try {
    const ip = ipaddr.parse(ipStr);
    if (ip.kind() === 'ipv6' && ip.isIPv4MappedAddress()) {
      return isPrivateIP(ip.toIPv4Address().toString());
    }
    // ipaddr provides range checks
    return ip.range() !== 'unicast' && ip.range() !== 'global' ? true : false;
  } catch (e) {
    return true; // fail closed
  }
}

function cidrAllows(ipStr) {
  if (!IP_ALLOWLIST_CIDRS.length) return false;
  try {
    const ip = ipaddr.parse(ipStr);
    for (const cidr of IP_ALLOWLIST_CIDRS) {
      const [net, bits] = cidr.split('/');
      if (!bits) continue;
      const parsedNet = ipaddr.parse(net);
      if (parsedNet.kind() !== ip.kind()) continue;
      if (ip.match(parsedNet, Number(bits))) return true;
    }
  } catch {}
  return false;
}

// Validate hostname against allowlist, then resolve and check IP ranges
async function validateDestination(urlStr) {
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error('invalid-url');
  }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('unsupported-protocol');

  const host = u.hostname;
  if (!HOSTNAME_ALLOWLIST.has(host)) throw new Error('host-not-allowed');

  // resolve to IPs (A/AAAA)
  const recordsA = await lookup(host, { all: true }).catch(err => { throw new Error('dns-failure'); });
  for (const rec of recordsA) {
    const ip = rec.address;
    // allow if not private, or explicitly allowlisted by CIDR
    if (isPrivateIP(ip) && !cidrAllows(ip)) throw new Error('destination-ip-not-allowed');
  }
  return true;
}

// Proxy endpoint: accepts JSON from SW, validates JWT, then streams response back
app.post('/api/proxy', async (req, res) => {
  const auth = (req.headers['authorization'] || '').split(' ')[1];
  if (!auth) return res.status(401).send('missing-auth');

  try {
    jwt.verify(auth, JWT_SECRET);
  } catch (e) {
    return res.status(401).send('invalid-token');
  }

  const { proxyReq, bodyBase64 } = req.body || {};
  if (!proxyReq || !proxyReq.url || !proxyReq.method) return res.status(400).send('invalid-payload');

  try {
    await validateDestination(proxyReq.url);
  } catch (err) {
    console.warn('dest validation failed', err.message);
    return res.status(403).send('destination-not-allowed');
  }

  // Build outgoing headers: whitelist-only, rewrite UA, remove cookies/authorization
  const outHeaders = {};
  const safeHeaderWhitelist = [
    'accept', 'accept-language', 'accept-encoding', 'content-type', 'if-modified-since', 'if-none-match', 'range', 'cache-control'
  ];
  for (const [k, v] of Object.entries(proxyReq.headers || {})) {
    const lk = k.toLowerCase();
    if (safeHeaderWhitelist.includes(lk)) outHeaders[k] = v;
  }
  outHeaders['user-agent'] = 'internal-sandbox-proxy/1.0 (+https://internal)';
  // force our own connection behavior
  outHeaders['connection'] = 'close';

  // prepare body
  let bodyStream = null;
  if (bodyBase64) {
    const buffer = Buffer.from(bodyBase64, 'base64');
    if (buffer.length > 5 * 1024 * 1024) return res.status(413).send('request-body-too-large');
    bodyStream = buffer;
  }

  // Make outbound request with undici; we will pipe response body to client
  let clientRes;
  try {
    clientRes = await undiciRequest(proxyReq.url, {
      method: proxyReq.method,
      headers: outHeaders,
      body: bodyStream,
      maxRedirections: 3,
      bodyTimeout: PER_REQUEST_TIMEOUT_MS,
      headersTimeout: 10_000
    });
  } catch (err) {
    console.error('upstream fetch error', err);
    return res.status(502).send('upstream-failure');
  }

  // Filter response headers: remove Set-Cookie, Server, and rewrite CSP
  const filteredHeaders = {};
  for (const [k, v] of Object.entries(clientRes.headers || {})) {
    const lk = k.toLowerCase();
    if (['set-cookie', 'set-cookie2', 'server', 'x-powered-by'].includes(lk)) continue;
    filteredHeaders[k] = v;
  }

  // Enforce a strict CSP for proxied HTML (override upstream)
  filteredHeaders['Content-Security-Policy'] = "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';";
  // forbids embedding the proxied document into other frames unless needed

  // send status & headers to client and stream body
  res.status(clientRes.statusCode);
  for (const [k, v] of Object.entries(filteredHeaders)) res.setHeader(k, v);

  // If the content-type is HTML and you want to sanitize, stream into sanitizer and then to res.
  const contentType = (clientRes.headers['content-type'] || '').toLowerCase();
  if (contentType.includes('text/html')) {
    // collect up to MAX_RESPONSE_BYTES into a buffer (sanitization needs whole HTML). For big HTML consider using a streaming sanitizer.
    try {
      const buf = await clientRes.body.arrayBuffer();
      if (buf.byteLength > MAX_RESPONSE_BYTES) return res.status(502).send('response-too-large');
      const html = Buffer.from(buf).toString('utf8');
      const safeHtml = sanitizeHtml(html, {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat([ 'img' ]),
        allowedAttributes: {
          a: ['href', 'name', 'target', 'rel'],
          img: ['src', 'alt']
        },
        transformTags: {
          'a': (tagName, attribs) => {
            // rewrite links to have rel="noopener noreferrer" and target to open in parent (or block)
            return { tagName: 'a', attribs: { ...attribs, rel: 'noopener noreferrer', target: '_top' } };
          }
        }
      });
      res.setHeader('Content-Length', Buffer.byteLength(safeHtml, 'utf8'));
      return res.send(safeHtml);
    } catch (err) {
      console.error('sanitize error', err);
      return res.status(502).send('sanitize-failure');
    }
  } else {
    // binary or non-HTML content: stream directly (with byte cap)
    let bytes = 0;
    try {
      const reader = clientRes.body.getReader ? clientRes.body.getReader() : null;
      // undici returns a Readable stream compatible with web streams; fallback to node stream piping
      if (clientRes.body.pipe) {
        // Node stream -> Node res
        clientRes.body.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            clientRes.body.destroy();
            res.end();
            console.warn('response truncated: exceeded max bytes');
          }
        });
        clientRes.body.pipe(res);
      } else if (reader) {
        // Web ReadableStream: pump to response
        const encoder = new TextEncoder(); // only if needed
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = Buffer.from(value);
          bytes += chunk.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            res.end();
            console.warn('response truncated: exceeded max bytes');
            break;
          }
          if (!res.write(chunk)) {
            // await drain
            await new Promise(resolve => res.once('drain', resolve));
          }
        }
        res.end();
      } else {
        // last fallback: read as arrayBuffer and send
        const buffer = await clientRes.body.arrayBuffer();
        if (buffer.byteLength > MAX_RESPONSE_BYTES) return res.status(502).send('response-too-large');
        res.send(Buffer.from(buffer));
      }
    } catch (err) {
      console.error('stream error', err);
      if (!res.headersSent) res.status(502).send('stream-failure');
      else res.end();
    }
  }
});

// Basic health endpoint
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Sandbox proxy listening on ${PORT}`));
