// api/generate-key.js
// Generates keys using same format as the Discord bot — key ID is the node name

const crypto = require('crypto');

const KEY_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateKeyChunk() {
  return Array.from({ length: 4 }, () => KEY_CHARSET[Math.floor(Math.random() * KEY_CHARSET.length)]).join('');
}

function generateKeyId(prefix) {
  return prefix + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk();
}

const BRANDS = {
  voltaris:         { name: 'Voltaris',           prefix: 'VOLTARIS-',  path: '/keys/voltaris/' },
  projectservices:  { name: 'Project Services',   prefix: 'PS-',        path: '/keys/projectservices/' },
  corvus:           { name: 'Corvus',             prefix: 'CORVUS-',    path: '/keys/corvus/' },
  omnis:            { name: 'Omnis',              prefix: 'OMNIS-',     path: '/keys/omnis/' },
};

const VALID_DURATIONS = [1, 3, 7, 14, 30, 90, 365, 99999];

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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Check suspension
  const profile = await fbGet(`/resellers/${payload.sub}`);
  if (profile && profile.suspended) {
    return res.status(403).json({ error: 'Your account is suspended. Contact admin.' });
  }

  const { brand, duration, quantity, note } = req.body || {};

  // Validate brand
  const brandConfig = BRANDS[brand];
  if (!brandConfig) {
    return res.status(400).json({ error: 'Invalid brand. Must be: ' + Object.keys(BRANDS).join(', ') });
  }

  // Check brand access for resellers (admins can gen any brand)
  if (!payload.isAdmin) {
    const userBrands = payload.brands || [];
    if (!userBrands.includes(brand)) {
      return res.status(403).json({ error: 'You don\'t have access to generate ' + brand + ' keys. Your brands: ' + userBrands.join(', ') });
    }
  }

  // Validate duration
  const dur = parseInt(duration);
  if (!VALID_DURATIONS.includes(dur)) {
    return res.status(400).json({ error: 'Invalid duration. Must be: ' + VALID_DURATIONS.join(', ') });
  }

  const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 50);

  try {
    const keys = [];
    const now = Math.floor(Date.now() / 1000);

    for (let i = 0; i < qty; i++) {
      const keyId = generateKeyId(brandConfig.prefix);
      // Same payload structure as the Discord bot
      const keyData = {
        hwid: '',
        expires_at: 0,
        duration_days: dur,
        active: true,
        created_at: now,
      };

      // PUT to /keys/{brand}/{KEYID} — same as bot does
      await fbPut(brandConfig.path + keyId, keyData);
      keys.push({ key: keyId, brand: brandConfig.name });
    }

    // Ensure reseller profile exists
    if (!profile) {
      const resellerPatch = {
        username: payload.nickname || payload.username,
        avatar: payload.avatar,
        suspended: false,
        createdAt: Date.now(),
      };
      await fbPut(`/resellers/${payload.sub}`, resellerPatch);
    }

    return res.status(200).json({ keys });

  } catch (error) {
    console.error('Key Generation Error:', error);
    return res.status(500).json({ error: 'Failed to generate key', detail: error.message });
  }
};
