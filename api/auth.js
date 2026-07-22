// Sentinel — auth endpoint. Developer: Anoop Dubey
const crypto = require('crypto');

function sign(payload, secret){
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

module.exports = async (req, res) => {
  if(req.method !== 'POST'){
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  let body = req.body;
  if(!body || typeof body === 'string'){
    try{ body = JSON.parse(body || '{}'); }catch(e){ body = {}; }
  }
  const { password } = body || {};
  const expected = process.env.APP_PASSWORD || 'Anoop';
  const secret = process.env.SESSION_SECRET || expected;

  if(typeof password !== 'string' || password !== expected){
    res.status(401).json({ error: 'Incorrect password' });
    return;
  }

  const token = sign({ exp: Date.now() + 1000 * 60 * 60 * 6 }, secret); // 6h session
  res.status(200).json({ token });
};

