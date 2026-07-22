// Sentinel — AI report generation via Groq. Developer: Anoop Dubey
const crypto = require('crypto');

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

function localFallbackReport(scan){
  const failed = scan.failedChecks || [];
  return {
    executiveSummary: `${scan.hostname} scored ${scan.riskScore}/100 (Grade ${scan.grade}). ${failed.length} of ${(scan.headerChecks||[]).length} passive checks failed, primarily around ${failed.slice(0,3).join(', ') || 'minor hardening gaps'}.`,
    technicalSummary: `Passive analysis found ${failed.length} missing or misconfigured controls${failed.length ? ': ' + failed.join('; ') : ' — configuration looks solid.'}`,
    businessImpact: failed.length > 3
      ? 'Multiple missing security headers increase exposure to clickjacking, MIME-sniffing, and data-leak risks, which could affect customer trust and compliance posture.'
      : 'Overall exposure is limited; remaining gaps are largely defense-in-depth improvements rather than critical risks.',
    riskExplanation: 'Findings are based on passive, read-only checks of public HTTP responses, DNS records, and certificate metadata — no exploitation or intrusive testing was performed.',
    owaspMapping: failed.map(f => ({
      category: /HTTPS|HSTS|Cookies/.test(f) ? 'A02:2021 – Cryptographic Failures' : 'A05:2021 – Security Misconfiguration',
      finding: f
    })),
    priorityFixes: failed.slice(0,6).map((f,i) => ({
      action: `Fix: ${f}`,
      difficulty: i < 2 ? 'Low' : 'Medium',
      eta: i < 2 ? '< 1 day' : '2-3 days'
    })),
    riskTimeline: [
      { when: 'Immediate', event: 'Address critical HTTPS/HSTS and cookie flag gaps' },
      { when: 'This week', event: 'Add missing security headers (CSP, X-Frame-Options)' },
      { when: 'This month', event: 'Review CORS policy and technology fingerprint exposure' }
    ],
    estimatedFixDifficulty: failed.length > 5 ? 'Medium-High' : 'Low',
    estimatedTimeToFix: failed.length > 5 ? '1-2 weeks' : '2-4 days',
    finalGrade: scan.grade
  };
}

module.exports = async (req, res) => {
  if(req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if(!verifyToken(req)) return res.status(401).json({ error: 'Unauthorized' });

  let body = req.body;
  if(!body || typeof body === 'string'){
    try{ body = JSON.parse(body || '{}'); }catch(e){ body = {}; }
  }
  const { scan } = body || {};
  if(!scan) return res.status(400).json({ error: 'Scan data required' });

  const groqKey = process.env.GROQ_API_KEY;
  if(!groqKey){
    return res.status(200).json(localFallbackReport(scan));
  }

  const prompt = `You are a senior application security consultant. Given this passive scan JSON, respond with ONLY a JSON object (no markdown, no prose outside JSON) with keys:
executiveSummary (string), technicalSummary (string), businessImpact (string), riskExplanation (string),
owaspMapping (array of {category, finding}), priorityFixes (array of {action, difficulty, eta}),
riskTimeline (array of {when, event}), estimatedFixDifficulty (string), estimatedTimeToFix (string), finalGrade (string).

Scan data:
${JSON.stringify(scan).slice(0, 6000)}`;

  try{
    const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${groqKey}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.4,
        response_format: { type: 'json_object' }
      })
    });
    const data = await resp.json();
    const text = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    if(!text) throw new Error('Empty AI response');
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.status(200).json(parsed);
  }catch(err){
    // Graceful fallback — app never breaks if Groq is unavailable/rate-limited
    res.status(200).json(localFallbackReport(scan));
  }
};
