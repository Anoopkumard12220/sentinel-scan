// Sentinel — passive scan engine. Developer: Anoop Dubey
const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const crypto = require('crypto');
const { URL } = require('url');

function verifyToken(req){
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if(!token || !token.includes('.')) return false;
  const [data, sig] = token.split('.');
  const secret = process.env.SESSION_SECRET || process.env.APP_PASSWORD || 'Anoop';
  const expected = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  if(sig !== expected) return false;
  try{
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    return payload.exp > Date.now();
  }catch(e){ return false; }
}

function fetchHead(targetUrl){
  return new Promise((resolve) => {
    const started = Date.now();
    let u;
    try{ u = new URL(targetUrl); }catch(e){ return resolve({ error: 'Invalid URL' }); }
    const lib = u.protocol === 'https:' ? https : http;
    const opts = { method: 'GET', timeout: 8000, headers: { 'User-Agent': 'Sentinel-Scanner/1.0 (passive; +authorized-use-only)' } };
    let settled = false;
    const reqObj = lib.request(u, opts, (resp) => {
      let body = '';
      resp.on('data', (c) => { if(body.length < 200000) body += c; });
      resp.on('end', () => {
        if(settled) return; settled = true;
        const elapsed = Date.now() - started;
        let tlsInfo = null;
        if(resp.socket && resp.socket.getPeerCertificate){
          try{
            const cert = resp.socket.getPeerCertificate();
            if(cert && cert.valid_to){
              tlsInfo = {
                issuer: cert.issuer && cert.issuer.O,
                subject: cert.subject && cert.subject.CN,
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                protocol: resp.socket.getProtocol ? resp.socket.getProtocol() : null
              };
            }
          }catch(e){}
        }
        resolve({
          statusCode: resp.statusCode,
          headers: resp.headers,
          body,
          elapsed,
          tlsInfo
        });
      });
    });
    reqObj.on('timeout', () => { if(settled) return; settled = true; reqObj.destroy(); resolve({ error: 'Timeout' }); });
    reqObj.on('error', (e) => { if(settled) return; settled = true; resolve({ error: e.message }); });
    reqObj.end();
  });
}

async function followRedirects(startUrl){
  let current = startUrl;
  let count = 0;
  const chain = [];
  while(count < 5){
    const r = await fetchHead(current);
    chain.push({ url: current, status: r.statusCode || null, error: r.error || null });
    if(r.error) return { error: r.error, chain };
    if([301,302,303,307,308].includes(r.statusCode) && r.headers.location){
      current = new URL(r.headers.location, current).toString();
      count++;
      continue;
    }
    return { final: r, chain };
  }
  return { final: null, chain, error: 'Too many redirects' };
}

async function checkTextResource(baseUrl, path){
  try{
    const r = await fetchHead(new URL(path, baseUrl).toString());
    return { exists: !!r.statusCode && r.statusCode < 400, statusCode: r.statusCode || null };
  }catch(e){
    return { exists: false, statusCode: null };
  }
}

async function getIpInfo(hostname){
  try{
    const addrs = await dns.resolve4(hostname).catch(() => []);
    const addrs6 = await dns.resolve6(hostname).catch(() => []);
    let geo = {};
    try{
      const resp = await fetch(`http://ip-api.com/json/${hostname}?fields=status,country,regionName,city,isp,org,as,query`);
      geo = await resp.json();
    }catch(e){}
    return { ipv4: addrs, ipv6: addrs6, geo };
  }catch(e){
    return { ipv4: [], ipv6: [], geo: {} };
  }
}

function detectTech(headers, body){
  const tech = [];
  const server = headers['server'];
  const poweredBy = headers['x-powered-by'];
  if(server) tech.push(server);
  if(poweredBy) tech.push(poweredBy);
  if(body){
    if(/wp-content|wordpress/i.test(body)) tech.push('WordPress');
    if(/__next|_next\//i.test(body)) tech.push('Next.js (React)');
    else if(/react/i.test(body)) tech.push('React');
    if(/ng-version/i.test(body)) tech.push('Angular');
    if(/\bvue\b/i.test(body)) tech.push('Vue.js');
    if(/shopify/i.test(body)) tech.push('Shopify');
  }
  return [...new Set(tech)];
}

function detectCDN(headers){
  const h = JSON.stringify(headers).toLowerCase();
  if(h.includes('cloudflare') || headers['cf-ray']) return 'Cloudflare';
  if(headers['x-served-by'] && String(headers['x-served-by']).includes('fastly')) return 'Fastly';
  if(h.includes('akamai')) return 'Akamai';
  if(headers['x-amz-cf-id']) return 'Amazon CloudFront';
  return 'Not detected';
}

function headerCheck(name, present, extraOk){
  return { name, pass: present ? (extraOk === false ? 'warn' : true) : false };
}

module.exports = async (req, res) => {
  if(req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if(!verifyToken(req)) return res.status(401).json({ error: 'Unauthorized' });

  let body = req.body;
  if(!body || typeof body === 'string'){
    try{ body = JSON.parse(body || '{}'); }catch(e){ body = {}; }
  }
  let { url: targetUrl } = body || {};
  if(!targetUrl) return res.status(400).json({ error: 'URL is required' });
  if(!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  let hostname;
  try{ hostname = new URL(targetUrl).hostname; }
  catch(e){ return res.status(400).json({ error: 'Invalid URL' }); }

  try{
    const [redirectResult, robots, sitemap, securityTxt, favicon, ipInfo] = await Promise.all([
      followRedirects(targetUrl),
      checkTextResource(targetUrl, '/robots.txt'),
      checkTextResource(targetUrl, '/sitemap.xml'),
      checkTextResource(targetUrl, '/.well-known/security.txt'),
      checkTextResource(targetUrl, '/favicon.ico'),
      getIpInfo(hostname)
    ]);

    if(redirectResult.error && !redirectResult.final){
      return res.status(200).json({ error: `Could not reach target: ${redirectResult.error}` });
    }

    const r = redirectResult.final;
    const headers = r.headers || {};
    const isHttps = targetUrl.startsWith('https://');

    const checks = [
      headerCheck('HTTPS Enforced', isHttps),
      headerCheck('HSTS (Strict-Transport-Security)', !!headers['strict-transport-security']),
      headerCheck('Content-Security-Policy', !!headers['content-security-policy']),
      headerCheck('X-Frame-Options', !!headers['x-frame-options']),
      headerCheck('X-Content-Type-Options', headers['x-content-type-options'] === 'nosniff'),
      headerCheck('Referrer-Policy', !!headers['referrer-policy']),
      headerCheck('Permissions-Policy', !!headers['permissions-policy']),
      headerCheck('CORS Restricted', headers['access-control-allow-origin'] !== '*'),
      headerCheck('Cache-Control Present', !!headers['cache-control']),
      headerCheck('Content-Encoding (Compression)', !!headers['content-encoding']),
      headerCheck('robots.txt Present', robots.exists),
      headerCheck('sitemap.xml Present', sitemap.exists),
      headerCheck('security.txt Present', securityTxt.exists),
      headerCheck('favicon Present', favicon.exists),
    ];

    // Cookie flags
    const setCookie = headers['set-cookie'] || [];
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie].filter(Boolean);
    const cookiesSecure = cookieArr.length === 0 || cookieArr.every(c => /secure/i.test(c));
    const cookiesHttpOnly = cookieArr.length === 0 || cookieArr.every(c => /httponly/i.test(c));
    checks.push(headerCheck('Cookies: Secure Flag', cookiesSecure));
    checks.push(headerCheck('Cookies: HttpOnly Flag', cookiesHttpOnly));

    const tech = detectTech(headers, r.body);
    const cdn = detectCDN(headers);

    const passCount = checks.filter(c => c.pass === true).length;
    const warnCount = checks.filter(c => c.pass === 'warn').length;
    const totalChecks = checks.length;
    const rawScore = ((passCount + warnCount * 0.5) / totalChecks) * 100;
    const riskScore = Math.round(rawScore);

    let grade = 'F';
    if(riskScore >= 97) grade = 'A+';
    else if(riskScore >= 90) grade = 'A';
    else if(riskScore >= 80) grade = 'B';
    else if(riskScore >= 70) grade = 'C';
    else if(riskScore >= 55) grade = 'D';
    else grade = 'F';

    const failedChecks = checks.filter(c => c.pass === false).map(c => c.name);
    const severityCounts = {
      Critical: failedChecks.filter(n => /HTTPS|HSTS/.test(n)).length,
      High: failedChecks.filter(n => /Content-Security-Policy|X-Frame|Cookies/.test(n)).length,
      Medium: failedChecks.filter(n => /X-Content-Type|CORS|Referrer|Permissions/.test(n)).length,
      Low: failedChecks.filter(n => /robots|sitemap|security\.txt|favicon|Cache|Compression/.test(n)).length
    };

    const scanResult = {
      target: targetUrl,
      hostname,
      scannedAt: new Date().toISOString(),
      statusCode: r.statusCode,
      responseTimeMs: r.elapsed,
      redirectChain: redirectResult.chain,
      headerChecks: checks,
      failedChecks,
      severityCounts,
      riskScore,
      grade,
      intel: {
        'Hosting Provider': (ipInfo.geo && ipInfo.geo.isp) || 'Unknown',
        'Organization': (ipInfo.geo && ipInfo.geo.org) || 'Unknown',
        'ASN': (ipInfo.geo && ipInfo.geo.as) || 'Unknown',
        'Country': (ipInfo.geo && ipInfo.geo.country) || 'Unknown',
        'City/Region': [ipInfo.geo && ipInfo.geo.city, ipInfo.geo && ipInfo.geo.regionName].filter(Boolean).join(', ') || 'Unknown',
        'IPv4': (ipInfo.ipv4 || []).join(', ') || 'None',
        'IPv6': (ipInfo.ipv6 || []).join(', ') || 'Not detected',
        'Server Header': headers['server'] || 'Not exposed',
        'CDN': cdn,
        'Technology': tech.join(', ') || 'Not detected',
        'TLS Protocol': (r.tlsInfo && r.tlsInfo.protocol) || (isHttps ? 'Detected (details unavailable)' : 'N/A — no HTTPS'),
        'Certificate Issuer': (r.tlsInfo && r.tlsInfo.issuer) || 'N/A',
        'Certificate Expiry': (r.tlsInfo && r.tlsInfo.validTo) || 'N/A'
      },
      rawHeaders: headers
    };

    res.status(200).json(scanResult);
  }catch(err){
    res.status(200).json({ error: err.message || 'Scan failed unexpectedly' });
  }
};
