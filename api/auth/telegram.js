const crypto = require('crypto');

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'hex');
  const right = Buffer.from(String(b || ''), 'hex');
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}
function cookieValue(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return '';
}
function sign(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}
function verifySession(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [encoded, signature] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  const a = Buffer.from(signature || ''); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) { return null; }
}
module.exports = async function handler(req, res) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const sessionSecret = process.env.SESSION_SECRET;
  if (!botToken || !sessionSecret) return res.status(500).send('Telegram login is not configured.');
  if (req.method !== 'GET') return res.status(405).setHeader('Allow', 'GET').send('Method not allowed');
  const url = new URL(req.url, `https://${req.headers.host || 'codek-sigma.vercel.app'}`);
  const params = url.searchParams;
  const hash = params.get('hash');
  const authDate = Number(params.get('auth_date'));
  if (!hash || !Number.isFinite(authDate)) return res.status(400).send('Invalid Telegram authentication data.');
  const now = Math.floor(Date.now() / 1000);
  if (authDate > now + 60 || now - authDate > 300) return res.status(401).send('Telegram login expired. Please try again.');
  const pairs = [];
  for (const [key, value] of params.entries()) if (key !== 'hash') pairs.push([key, value]);
  pairs.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  const checkString = pairs.map(([key, value]) => `${key}=${value}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(botToken).digest();
  const expectedHash = crypto.createHmac('sha256', secretKey).update(checkString).digest('hex');
  if (!safeEqual(hash, expectedHash)) return res.status(401).send('Telegram signature could not be verified.');
  const id = params.get('id');
  if (!id || !/^\d+$/.test(id)) return res.status(400).send('Invalid Telegram user.');
  const user = { id, first_name: params.get('first_name') || '', last_name: params.get('last_name') || '', username: params.get('username') || '', photo_url: params.get('photo_url') || '' };
  const token = sign({ user, iat: now, exp: now + 7 * 24 * 60 * 60 }, sessionSecret);
  res.setHeader('Set-Cookie', `codek_telegram_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`);
  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(302, '/?login=success');
};
