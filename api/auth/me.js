const crypto = require('crypto');
module.exports = function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  const secret = process.env.SESSION_SECRET;
  if (!secret) return res.status(500).json({ authenticated: false, error: 'not_configured' });
  const header = req.headers.cookie || '';
  const part = header.split(';').map(v => v.trim()).find(v => v.startsWith('codek_telegram_session='));
  if (!part) return res.status(200).json({ authenticated: false });
  let token = '';
  try { token = decodeURIComponent(part.slice('codek_telegram_session='.length)); } catch (_) {}
  const [encoded, signature] = token.split('.');
  if (!encoded || !signature) return res.status(200).json({ authenticated: false });
  const expected = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  const a = Buffer.from(signature); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(200).json({ authenticated: false });
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000) || !payload.user) return res.status(200).json({ authenticated: false });
    return res.status(200).json({ authenticated: true, user: payload.user });
  } catch (_) { return res.status(200).json({ authenticated: false }); }
};
