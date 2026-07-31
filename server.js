const http = require('http');
const fs = require('fs');
const path = require('path');
const auth = require('./api/auth');
const scan = require('./api/scan');
const report = require('./api/report');

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
};

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

const handler = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (url.pathname.startsWith('/api/')) {
    const route = url.pathname.replace('/api/', '');
    const body = await parseBody(req);
    req.body = body;

    let apiFn;
    if (route === 'auth') apiFn = auth;
    else if (route === 'scan') apiFn = scan;
    else if (route === 'report') apiFn = report;
    else { res.statusCode = 404; res.end(JSON.stringify({ error: 'Not found' })); return; }

    try { await apiFn(req, res); }
    catch (err) { res.statusCode = 500; res.end(JSON.stringify({ error: err.message })); }
    return;
  }

  const filePath = url.pathname === '/' ? '/index.html' : url.pathname;
  const full = path.join(__dirname, filePath);

  if (!full.startsWith(__dirname) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) {
    res.statusCode = 404; res.end('Not found'); return;
  }

  const ext = path.extname(full);
  const type = MIME[ext] || 'application/octet-stream';
  res.setHeader('Content-Type', type);
  fs.createReadStream(full).pipe(res);
};

const PORT = process.env.PORT || 3000;
const server = http.createServer(handler);
server.listen(PORT, () => {
  console.log(`Sentinel running on http://localhost:${PORT}`);
});