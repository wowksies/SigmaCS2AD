// api/generate-key.js
// Generates license keys and stores them in Firebase Realtime Database

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

function generateKey() {
  const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `OMNIS-${seg()}-${seg()}-${seg()}`;
}

async function fbGet(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Firebase GET failed: ${r.status}`);
  return r.json();
}

async function fbPut(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error(`Firebase PUT failed: ${r.status}`);
  return r.json();
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

const VALID_PLANS = ['3days', '1week', '1month', 'lifetime'];

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Check if reseller is suspended
  const profile = await fbGet(`/resellers/${payload.sub}`);
  if (profile && profile.suspended) {
    return res.status(403).json({ error: 'Your account is suspended. Please contact admin to resolve payment.' });
  }

  const { plan, quantity, note } = req.body || {};

  if (!plan || !VALID_PLANS.includes(plan)) {
    return res.status(400).json({ error: 'Invalid plan. Must be: 3days, 1week, 1month, or lifetime' });
  }

  const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 10);

  try {
    const keys = [];
    const now = Date.now();

    for (let i = 0; i < qty; i++) {
      const key = generateKey();
      const keyData = {
        key: key,
        plan: plan,
        resellerId: payload.sub,
        resellerName: payload.nickname || payload.username,
        note: note || '',
        createdAt: now,
        active: true,
        hwid: '',        // Empty until customer activates
        excluded: false,  // Admin can set true to exclude from payment tracking
        activatedAt: null,
      };

      const result = await fbPost('/keys', keyData);
      keys.push({ key: key, id: result.name });
    }

    // Ensure reseller profile exists
    if (!profile) {
      await fbPut(`/resellers/${payload.sub}`, {
        username: payload.nickname || payload.username,
        avatar: payload.avatar,
        suspended: false,
        paymentDeadline: null,
        createdAt: now,
      });
    }

    return res.status(200).json({ keys });

  } catch (error) {
    console.error('Key Generation Error:', error);
    return res.status(500).json({ error: 'Failed to generate key', detail: error.message });
  }
};
