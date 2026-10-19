module.exports = function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).setHeader('Allow', 'POST').send('Method not allowed');
  res.setHeader('Set-Cookie', 'codek_telegram_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ ok: true });
};
