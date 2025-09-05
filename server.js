// server.js
import http from 'http';
import https from 'https';
import { URL } from 'url';
import zlib from 'zlib';

// WebRTC-killer script injected into pages
const INJECT = `
<script>
(() => {
  const Fake = function(){ throw new Error('WebRTC disabled'); };
  ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCIceCandidate']
    .forEach(k => { try { Object.defineProperty(window, k, { value: Fake }); } catch(e){} });
  try { Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia: ()=>Promise.reject(new Error('disabled')) } }); } catch(e){}
})();
</script>`;

function inject(html) {
  return html.replace(/<\/head>/i, `${INJECT}</head>`);
}

function forward(req, res) {
  if (!req.url.startsWith('/http')) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Use like: /https://example.com');
    return;
  }

  const target = new URL(req.url.slice(1));
  const opts = { headers: { 'user-agent': 'Mozilla/5.0', 'accept-encoding': 'gzip' } };
  const proto = target.protocol === 'https:' ? https : http;

  proto.get(target, opts, (upRes) => {
    let chunks = [];
    const enc = upRes.headers['content-encoding'] || '';
    const type = upRes.headers['content-type'] || '';

    upRes.on('data', d => chunks.push(d));
    upRes.on('end', () => {
      let body = Buffer.concat(chunks);
      if (enc.includes('gzip')) body = zlib.gunzipSync(body);

      if (type.includes('text/html')) {
        body = Buffer.from(inject(body.toString()), 'utf8');
      }

      res.writeHead(upRes.statusCode || 200, { ...upRes.headers, 'content-encoding': 'identity' });
      res.end(body);
    });
  }).on('error', () => {
    res.writeHead(502); res.end('Bad gateway');
  });
}

http.createServer(forward).listen(process.env.PORT || 8080);
