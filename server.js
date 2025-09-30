// server.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cheerio = require('cheerio');
const got = require('got');
const { CookieJar } = require('tough-cookie');
const cookie = require('cookie');

const PORT = process.env.PORT || 8080;
const app = express();

// ---- anti-fingerprinting + WebRTC blocker to inject into pages ----
const INJECT_SNIPPET = `<!-- injected-by-secure-proxy -->
<script>
(() => {
  // 1) WebRTC hard-disable
  const disabled = () => { throw new Error('WebRTC disabled by proxy'); };
  try { Object.defineProperty(window, 'RTCPeerConnection', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(window, 'webkitRTCPeerConnection', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(window, 'RTCDataChannel', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(window, 'RTCIceCandidate', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia: () => Promise.reject(new Error('disabled')) }, configurable: false }); } catch(e){}

  // 2) Basic fingerprint-reduction: block/override common APIs
  try {
    // override Canvas API to return blank data
    HTMLCanvasElement.prototype.getContext = function() { return null; };
    const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
    Object.defineProperty(HTMLCanvasElement.prototype, 'toDataURL', { value: function(){ try { return ''; } catch(e){ return ''; } } });
  } catch(e){}

  try {
    // block WebGL
    HTMLCanvasElement.prototype.getContext = function(type) {
      if (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl') return null;
      return null;
    };
  } catch(e){}

  try { Object.defineProperty(navigator, 'plugins', { value: [], configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'languages', { value: ['en-US','en'], configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'userAgent', { value: 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0', configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'hardwareConcurrency', { value: 2, configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'platform', { value: 'Win32', configurable: false }); } catch(e){}

  // 3) Block canvas fingerprinting attempts by intercepting toBlob/toDataURL
  try {
    HTMLCanvasElement.prototype.toBlob = function() { return null; };
    HTMLCanvasElement.prototype.toDataURL = function() { return ''; };
  } catch(e){}

  // 4) block certain JS sensor APIs
  try { if (window.DeviceMotionEvent) window.DeviceMotionEvent = undefined; } catch(e){}
  try { if (window.DeviceOrientationEvent) window.DeviceOrientationEvent = undefined; } catch(e){}

  // 5) prevent fingerprinting libraries from enumerating mime types
  try {
    Object.defineProperty(navigator, 'mimeTypes', { value: [], configurable: false });
  } catch(e){}
})();
</script>`;

// ---- app middleware ----
app.use(helmet({ contentSecurityPolicy: false })); // we will control CSP per-proxied response if needed
app.use(bodyParser.urlencoded({ extended: true }));

// Small, ephemeral in-memory session store (ok for free/test). For production, use a persistent session store.
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretproxykey',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // if using HTTPS on Render, set true
}));

// Helper: create or return per-session tough-cookie jar
function getSessionJar(req) {
  if (!req.session.cookieJar) {
    req.session.cookieJar = JSON.stringify(new CookieJar().toJSON());
  }
  // restore jar
  const j = CookieJar.fromJSON(JSON.parse(req.session.cookieJar));
  // store back before returning so changes persist
  req._cookieJar = j;
  return j;
}
function persistSessionJar(req) {
  if (req._cookieJar) {
    req.session.cookieJar = JSON.stringify(req._cookieJar.toJSON());
  }
}

// homepage with form
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`
    <html>
      <head><title>Secure Proxy</title></head>
      <body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#f5f7fa;">
        <div style="background:#fff;padding:24px;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.08);">
          <h2 style="margin-top:0">Secure Proxy</h2>
          <form method="get" action="/proxy">
            <input name="url" placeholder="https://example.com" style="width:360px;padding:10px" required />
            <button type="submit" style="padding:10px 14px;margin-left:8px">Go</button>
          </form>
          <p style="font-size:12px;color:#666">Cookies are isolated per session; WebRTC & common fingerprint surfaces are blocked.</p>
        </div>
      </body>
    </html>
  `);
});

// core proxy endpoint (all proxied browsing goes through here)
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('missing url');

  let parsed;
  try { parsed = new URL(target); } catch(e) { return res.status(400).send('invalid url'); }

  const sessionJar = getSessionJar(req);

  // Build headers to send upstream: strip identifying headers and use fixed UA
  const forwardHeaders = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0',
    'accept': req.headers.accept || '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9'
    // DO NOT copy x-forwarded-for / forwarded headers
  };

  // attach cookies from session jar for this target host
  const cookieString = await sessionJar.getCookieString(parsed.href);
  if (cookieString) forwardHeaders['cookie'] = cookieString;

  try {
    const upstreamResp = await got(target, {
      method: 'GET',
      headers: forwardHeaders,
      responseType: 'buffer',
      decompress: true,
      throwHttpErrors: false,
      retry: { limit: 0 },
      timeout: { request: 20000 }
    });

    // Handle Set-Cookie: store cookies server-side in the per-session jar; do NOT forward Set-Cookie to client.
    const setCookies = upstreamResp.headers['set-cookie'];
    if (setCookies) {
      const arr = Array.isArray(setCookies) ? setCookies : [setCookies];
      for (const sc of arr) {
        try {
          await sessionJar.setCookie(sc, parsed.href);
        } catch(e){}
      }
      // persist jar after updates
      persistSessionJar(req);
    }

    // Build response headers
    // Start from a minimal safe set and avoid forwarding upstream's Set-Cookie or certain headers.
    res.setHeader('content-type', upstreamResp.headers['content-type'] || 'application/octet-stream');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('referrer-policy', 'no-referrer');
    // deny origin sensor APIs
    res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');

    const contentType = upstreamResp.headers['content-type'] || '';

    // For HTML: rewrite links and inject protection
    if (/text\/html/i.test(contentType)) {
      const body = upstreamResp.body.toString('utf8');
      const $ = cheerio.load(body, { decodeEntities: false });

      // Inject anti-fingerprint / webrtc blocker at top of head
      if ($('head').length) $('head').prepend(INJECT_SNIPPET);
      else $('html').prepend(`<head>${INJECT_SNIPPET}</head>`);

      // rewrite attributes to stay within proxy: href, src, action, srcset
      const fixAttr = (sel, attr) => {
        $(sel).each((i, el) => {
          const val = $(el).attr(attr);
          if (!val) return;
          // ignore javascript: and mailto:
          if (/^\s*javascript:/i.test(val) || /^\s*mailto:/i.test(val) || /^\s*#/i.test(val)) return;
          try {
            const absolute = new URL(val, parsed.href).href;
            $(el).attr(attr, `/proxy?url=${encodeURIComponent(absolute)}`);
          } catch(e) {}
        });
      };

      fixAttr('a', 'href');
      fixAttr('img', 'src');
      fixAttr('script', 'src');
      fixAttr('link', 'href');
      fixAttr('form', 'action');

      // rewrite inline srcset attributes (basic)
      $('img[srcset]').each((i, el) => {
        const srcset = $(el).attr('srcset');
        const parts = srcset.split(',');
        const fixed = parts.map(p => {
          const [u, w] = p.trim().split(/\s+/);
          try { return `/proxy?url=${encodeURIComponent(new URL(u, parsed.href).href)} ${w || ''}`.trim(); } catch { return ''; }
        }).filter(Boolean).join(', ');
        $(el).attr('srcset', fixed);
      });

      const outHtml = $.html();
      // send rewritten HTML
      res.send(outHtml);
      return;
    }

    // For other content types (images, css, js), stream bytes directly
    // but remove upstream's set-cookie headers (we already stored cookies server-side)
    // Also strip ETag & other cache identifiers to avoid tracking
    ['etag', 'set-cookie', 'content-security-policy', 'content-security-policy-report-only'].forEach(h => { try { res.removeHeader(h); } catch(e){} });

    // Set content-length if present
    if (upstreamResp.headers['content-length']) {
      res.setHeader('content-length', upstreamResp.headers['content-length']);
    }

    // Pass through other headers cautiously
    const passthrough = ['content-type', 'content-length', 'last-modified', 'expires'];
    for (const h of passthrough) {
      if (upstreamResp.headers[h]) res.setHeader(h, upstreamResp.headers[h]);
    }

    res.status(upstreamResp.statusCode || 200).send(upstreamResp.body);
    return;

  } catch (err) {
    console.error('upstream error', err && err.message);
    return res.status(502).send('Bad gateway');
  }
});

// optional convenience: direct path style: /https://example.com/path
app.get('/:proto_https(*)', (req, res) => {
  // allow redirect-style path usage: /https://example.com
  const path = req.params.proto_https;
  if (path && (path.startsWith('http://') || path.startsWith('https://'))) {
    const url = path;
    // redirect into the query-based handler
    return res.redirect(`/proxy?url=${encodeURIComponent(url)}`);
  }
  res.status(404).send('not found');
});

app.listen(PORT, () => console.log(`Secure proxy listening on port ${PORT}`));
