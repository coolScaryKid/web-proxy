import express from "express";
import fetch from "node-fetch";
import cheerio from "cheerio";
import { URL } from "url";

const app = express();
const PORT = process.env.PORT || 8080;

const INJECT_SNIPPET = `<!-- injected-by-secure-proxy -->
<script>
(() => {
  // --- WebRTC hard-disable ---
  const disabled = () => { throw new Error('WebRTC disabled by proxy'); };
  try { Object.defineProperty(window, 'RTCPeerConnection', { value: disabled }); } catch(e){}
  try { Object.defineProperty(window, 'webkitRTCPeerConnection', { value: disabled }); } catch(e){}
  try { Object.defineProperty(window, 'RTCDataChannel', { value: disabled }); } catch(e){}
  try { Object.defineProperty(window, 'RTCIceCandidate', { value: disabled }); } catch(e){}
  try { Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia: () => Promise.reject(new Error('disabled')) } }); } catch(e){}

  // --- Anti-fingerprinting basics ---
  try { HTMLCanvasElement.prototype.toDataURL = () => ''; } catch(e){}
  try { HTMLCanvasElement.prototype.toBlob = cb => cb(null); } catch(e){}
  try { Object.defineProperty(navigator, 'plugins', { value: [] }); } catch(e){}
  try { Object.defineProperty(navigator, 'languages', { value: ['en-US','en'] }); } catch(e){}
  try { Object.defineProperty(navigator, 'userAgent', { value: 'Mozilla/5.0 (Win32) ProxyBrowser' }); } catch(e){}

  // --- Block service workers ---
  try { if (navigator.serviceWorker) navigator.serviceWorker.register = () => Promise.reject(new Error('SW disabled')); } catch(e){}
  try { delete navigator.serviceWorker; } catch(e){}

  // --- Block WebSockets ---
  try { window.WebSocket = function(){ throw new Error('WS disabled'); }; } catch(e){}

  // --- Monkeypatch fetch ---
  const _fetch = window.fetch.bind(window);
  window.fetch = function(input, init){
    try {
      const u = new URL(input, location.href);
      if (u.origin !== location.origin) {
        input = '/proxy?url=' + encodeURIComponent(u.href);
      }
    } catch(e){}
    return _fetch(input, init);
  };

  // --- Monkeypatch XHR ---
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m,u,a,us,p){
    try {
      const full = new URL(u, location.href);
      if (full.origin !== location.origin) {
        arguments[1] = '/proxy?url=' + encodeURIComponent(full.href);
      }
    } catch(e){}
    return _open.apply(this, arguments);
  };
})();
</script>`;

// home page
app.get("/", (req,res) => {
  res.send(`
    <h2>Secure Proxy</h2>
    <form action="/proxy">
      <input name="url" placeholder="https://example.com" size="50">
      <button>Go</button>
    </form>
  `);
});

// proxy endpoint
app.get("/proxy", async (req,res) => {
  let target = req.query.url;
  if (!target) return res.send("No URL provided.");

  if (!/^https?:/i.test(target)) target = "http://" + target;
  let parsed;
  try { parsed = new URL(target); } 
  catch { return res.status(400).send("Invalid URL"); }

  try {
    const upstream = await fetch(parsed.href, {
      headers: { "user-agent": "Mozilla/5.0 Proxy" }
    });

    const ct = upstream.headers.get("content-type") || "";
    const buf = await upstream.buffer();

    // Handle HTML
    if (/text\/html/i.test(ct)) {
      let body = buf.toString("utf8");
      const $ = cheerio.load(body, { decodeEntities: false });

      // inject snippet
      if ($("head").length) $("head").prepend(INJECT_SNIPPET);
      else $("html").prepend(`<head>${INJECT_SNIPPET}</head>`);

      // <base>
      const baseHref = `/proxy?url=${encodeURIComponent(parsed.href)}`;
      if ($("base").length) $("base").attr("href", baseHref);
      else $("head").prepend(`<base href="${baseHref}">`);

      // rewrite attributes
      const fixAttr = (sel, attr) => {
        $(sel).each((i,el) => {
          const val = $(el).attr(attr);
          if (!val) return;
          if (/^(#|javascript:|mailto:)/i.test(val)) return;
          try {
            const abs = new URL(val, parsed.href).href;
            $(el).attr(attr, `/proxy?url=${encodeURIComponent(abs)}`);
          } catch {}
        });
      };
      fixAttr("a","href"); fixAttr("img","src"); fixAttr("script","src");
      fixAttr("link","href"); fixAttr("form","action");

      // srcset
      $("img[srcset]").each((i,el) => {
        const srcset = $(el).attr("srcset");
        const fixed = srcset.split(",").map(p => {
          const [u,w] = p.trim().split(/\s+/);
          try { return `/proxy?url=${encodeURIComponent(new URL(u,parsed.href).href)} ${w||""}`.trim(); }
          catch { return ""; }
        }).filter(Boolean).join(", ");
        $(el).attr("srcset", fixed);
      });

      // inline styles url(...)
      $("[style]").each((i,el) => {
        let s = $(el).attr("style");
        s = s.replace(/url\\(([^)]+)\\)/g,(m,u)=>{
          u=u.replace(/['"]/g,"").trim();
          try { return `url('/proxy?url=${encodeURIComponent(new URL(u,parsed.href).href)}')`; }
          catch { return m; }
        });
        $(el).attr("style", s);
      });

      // <style> blocks
      $("style").each((i,el) => {
        let s = $(el).html();
        s = s.replace(/url\\(([^)]+)\\)/g,(m,u)=>{
          u=u.replace(/['"]/g,"").trim();
          try { return `url('/proxy?url=${encodeURIComponent(new URL(u,parsed.href).href)}')`; }
          catch { return m; }
        });
        $(el).html(s);
      });

      // meta refresh
      $("meta[http-equiv='refresh']").each((i,el)=>{
        const c = $(el).attr("content")||"";
        const m = c.match(/\\d+;\\s*url=(.*)/i);
        if (m && m[1]) {
          try {
            const abs = new URL(m[1], parsed.href).href;
            $(el).attr("content", c.replace(m[1], `/proxy?url=${encodeURIComponent(abs)}`));
          } catch {}
        }
      });

      res.setHeader("content-type","text/html");
      res.setHeader("referrer-policy","no-referrer");
      res.setHeader("permissions-policy","camera=(), microphone=(), geolocation=()");
      res.send($.html());
      return;
    }

    // Handle CSS
    if (/text\/css/i.test(ct)) {
      let css = buf.toString("utf8");
      css = css.replace(/url\\(([^)]+)\\)/g,(m,u)=>{
        u=u.replace(/['"]/g,"").trim();
        try { return `url('/proxy?url=${encodeURIComponent(new URL(u,parsed.href).href)}')`; }
        catch { return m; }
      });
      res.setHeader("content-type","text/css");
      return res.send(css);
    }

    // Default: just forward
    res.setHeader("content-type", ct);
    res.send(buf);

  } catch (e) {
    console.error(e);
    res.status(500).send("Proxy error: " + e.message);
  }
});

app.listen(PORT, () => console.log("Proxy running on " + PORT));
