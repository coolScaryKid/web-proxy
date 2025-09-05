const http = require("http");
const https = require("https");
const { URL } = require("url");
const zlib = require("zlib");
const { parse } = require("querystring");
const cheerio = require("cheerio");

const PORT = process.env.PORT || 8080;

// Script injected into every HTML page to kill WebRTC
const INJECT = `
<script>
(() => {
  const Fake = function(){ throw new Error('WebRTC disabled'); };
  ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCIceCandidate']
    .forEach(k => { try { Object.defineProperty(window, k, { value: Fake }); } catch(e){} });
  try { Object.defineProperty(navigator, 'mediaDevices', {
    value: { getUserMedia: ()=>Promise.reject(new Error('disabled')) }
  }); } catch(e){}
})();
</script>`;

// Simple homepage with a search bar
function homepage(res) {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(`
    <html>
      <head>
        <title>Free Web Proxy</title>
        <style>
          body { font-family: sans-serif; display:flex; height:100vh; align-items:center; justify-content:center; background:#f5f5f5; }
          .box { background:#fff; padding:30px; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.1); text-align:center; }
          input { width:300px; padding:10px; border-radius:5px; border:1px solid #ccc; }
          button { padding:10px 20px; margin-left:10px; border:none; background:#007BFF; color:#fff; border-radius:5px; cursor:pointer; }
          button:hover { background:#0056b3; }
        </style>
      </head>
      <body>
        <div class="box">
          <h2>Free Secure Proxy</h2>
          <form method="get" action="/">
            <input type="text" name="url" placeholder="Enter full URL (https://...)" required />
            <button type="submit">Go</button>
          </form>
        </div>
      </body>
    </html>
  `);
}

// Rewrite all links, images, scripts, CSS, and forms to go through proxy
function rewrite(html, base) {
  const $ = cheerio.load(html);

  // Inject WebRTC killer
  $("head").prepend(INJECT);

  const fixAttr = (selector, attr) => {
    $(selector).each((_, el) => {
      const val = $(el).attr(attr);
      if (val) {
        try {
          const abs = new URL(val, base).href;
          $(el).attr(attr, `/?url=${encodeURIComponent(abs)}`);
        } catch {}
      }
    });
  };

  fixAttr("a", "href");
  fixAttr("img", "src");
  fixAttr("script", "src");
  fixAttr("link", "href");
  fixAttr("form", "action");

  return $.html();
}

// Core proxy logic
function proxyPage(targetUrl, res) {
  try {
    const target = new URL(targetUrl);
    const proto = target.protocol === "https:" ? https : http;

    const opts = {
      headers: {
        "user-agent": "Mozilla/5.0",
        "accept-encoding": "gzip",
      },
    };

    proto.get(target, opts, (upRes) => {
      let chunks = [];
      const enc = upRes.headers["content-encoding"] || "";
      const type = upRes.headers["content-type"] || "";

      upRes.on("data", (d) => chunks.push(d));
      upRes.on("end", () => {
        let body = Buffer.concat(chunks);
        if (enc.includes("gzip")) body = zlib.gunzipSync(body);

        if (type.includes("text/html")) {
          body = Buffer.from(rewrite(body.toString(), targetUrl), "utf8");
        }

        res.writeHead(upRes.statusCode || 200, {
          ...upRes.headers,
          "content-encoding": "identity", // don’t double-compress
          "permissions-policy":
            "camera=(), microphone=(), geolocation=(), usb=(), interest-cohort=()",
          "referrer-policy": "no-referrer",
        });
        res.end(body);
      });
    }).on("error", () => {
      res.writeHead(502);
      res.end("Bad gateway");
    });
  } catch (e) {
    res.writeHead(400);
    res.end("Invalid URL");
  }
}

// HTTP server
http
  .createServer((req, res) => {
    if (req.url === "/" || req.url.startsWith("/?")) {
      const query = parse(req.url.split("?")[1]);
      if (query.url) {
        proxyPage(query.url, res);
      } else {
        homepage(res);
      }
    } else {
      homepage(res);
    }
  })
  .listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
