// api/submit-payment.js — SECURED: uses DB-based role lookup
const { resolveUser } = require('./auth-helper');

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

  // DB-based role check — roles are NEVER trusted from the JWT
  const user = await resolveUser(req);
  if (!user || (!user.isReseller && !user.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (user.suspended) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  const { amount, method, note } = req.body || {};

  if (!amount || !method) {
    return res.status(400).json({ error: 'Missing amount or method' });
  }

  const parsedAmount = parseFloat(amount);
  if (isNaN(parsedAmount) || parsedAmount <= 0 || parsedAmount > 10000) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  const validMethods = ['paypal', 'bitcoin', 'litecoin'];
  if (!validMethods.includes(method)) {
    return res.status(400).json({ error: 'Invalid payment method' });
  }

  // Sanitize note — strip HTML
  const safeNote = (note || '').replace(/<[^>]*>/g, '').substring(0, 500);

  try {
    const paymentData = {
      resellerId: user.id,
      resellerName: user.nickname || user.username,
      amount: parsedAmount.toFixed(2),
      method: method,
      note: safeNote,
      confirmedByAdmin: false,
      confirmedAt: null,
      createdAt: Date.now(),
    };

    const result = await fbPost('/payments', paymentData);

    return res.json({ success: true, paymentId: result.name, message: 'Payment submitted for admin review' });

  } catch (error) {
    console.error('Submit Payment Error:', error);
    return res.status(500).json({ error: 'Failed to submit payment' });
  }
};
