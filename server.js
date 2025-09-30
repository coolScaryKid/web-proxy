import express from "express";
import fetch from "node-fetch";
import cookieParser from "cookie-parser";
import * as cheerio from "cheerio";

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware: strip cookies and fingerprinting headers
app.use(cookieParser());
app.use((req, res, next) => {
  delete req.headers.cookie;
  delete req.headers["user-agent"];
  next();
});

// Main proxy route
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing ?url= parameter");

  try {
    const response = await fetch(target, {
      headers: {
        "User-Agent": "Mozilla/5.0 ProxyShield", // prevent leaking client UA
      },
    });
    const contentType = response.headers.get("content-type");

    // If HTML → rewrite it
    if (contentType && contentType.includes("text/html")) {
      const body = await response.text();
      const $ = cheerio.load(body);

      // Rewrite <a>, <script>, <link>, <img>, <iframe> so they go through proxy
      $("a").each((_, el) => {
        const href = $(el).attr("href");
        if (href && href.startsWith("http")) {
          $(el).attr("href", `/proxy?url=${href}`);
        }
      });

      $("script").each((_, el) => {
        const src = $(el).attr("src");
        if (src && src.startsWith("http")) {
          $(el).attr("src", `/proxy?url=${src}`);
        }
      });

      $("link").each((_, el) => {
        const href = $(el).attr("href");
        if (href && href.startsWith("http")) {
          $(el).attr("href", `/proxy?url=${href}`);
        }
      });

      $("img").each((_, el) => {
        const src = $(el).attr("src");
        if (src && src.startsWith("http")) {
          $(el).attr("src", `/proxy?url=${src}`);
        }
      });

      $("iframe").each((_, el) => {
        const src = $(el).attr("src");
        if (src && src.startsWith("http")) {
          $(el).attr("src", `/proxy?url=${src}`);
        }
      });

      res.set("Content-Type", "text/html");
      res.send($.html());
    } else {
      // Non-HTML (CSS, JS, images, etc.)
      res.set("Content-Type", contentType || "application/octet-stream");
      response.body.pipe(res);
    }
  } catch (err) {
    res.status(500).send("Proxy error: " + err.message);
  }
});

app.listen(PORT, () => {
  console.log(`✅ Proxy running at http://localhost:${PORT}`);
});
