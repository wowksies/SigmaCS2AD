// api/submit-payment.js
// Reseller submits a payment claim for admin to confirm

const crypto = require('crypto');

function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', process.env.JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

function getCookie(req, name) {
  const match = (req.headers.cookie || '').match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function fbPost(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error(`Firebase POST failed: ${r.status}`);
  return r.json();
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { amount, method, note } = req.body || {};

  if (!amount || !method) {
    return res.status(400).json({ error: 'Missing amount or method' });
  }

  const validMethods = ['paypal', 'bitcoin', 'litecoin'];
  if (!validMethods.includes(method)) {
    return res.status(400).json({ error: 'Invalid payment method' });
  }

  try {
    const paymentData = {
      resellerId: payload.sub,
      resellerName: payload.nickname || payload.username,
      amount: parseFloat(amount).toFixed(2),
      method: method,
      note: note || '',
      confirmedByAdmin: false,
      confirmedAt: null,
      createdAt: Date.now(),
    };

    const result = await fbPost('/payments', paymentData);

    return res.json({ success: true, paymentId: result.name, message: 'Payment submitted for admin review' });

  } catch (error) {
    console.error('Submit Payment Error:', error);
    return res.status(500).json({ error: 'Failed to submit payment', detail: error.message });
  }
};
