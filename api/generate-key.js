// api/generate-key.js — uses DB-based role lookup
const { resolveUser, fbGet } = require('./auth-helper');

const BRANDS = {
  voltaris:        { name: 'Voltaris',         prefix: 'VOLTARIS-', path: '/keys/voltaris/' },
  projectservices: { name: 'Project Services', prefix: 'PS-',       path: '/keys/projectservices/' },
  corvus:          { name: 'Corvus',           prefix: 'CORVUS-',   path: '/keys/corvus/' },
  omnis:           { name: 'Omnis',            prefix: 'OMNIS-',    path: '/keys/omnis/' },
};

const VALID_DURATIONS = [1, 3, 7, 14, 30, 90, 365, 99999];

function generateKeyId(prefix) {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const seg = () => Array.from({ length: 4 }, () => chars[Math.random() * chars.length | 0]).join('');
  return `${prefix}${seg()}-${seg()}-${seg()}-${seg()}`;
}

async function fbPut(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  if (!r.ok) throw new Error(`Firebase PUT failed: ${r.status}`);
  return r.json();
}

async function fbPatch(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  await fetch(url, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const user = await resolveUser(req);
  if (!user || (!user.isReseller && !user.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (user.suspended) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  const { brand, duration, quantity, note } = req.body || {};

  const brandConfig = BRANDS[brand];
  if (!brandConfig) {
    return res.status(400).json({ error: 'Invalid brand' });
  }

  // Check brand access (DB-based, not JWT-based)
  if (!user.isAdmin) {
    if (!user.brands.includes(brand)) {
      return res.status(403).json({ error: 'No access to ' + brand });
    }
  }

  const dur = parseInt(duration);
  if (!VALID_DURATIONS.includes(dur)) {
    return res.status(400).json({ error: 'Invalid duration' });
  }

  const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 50);

  try {
    const keys = [];
    const now = Math.floor(Date.now() / 1000);

    for (let i = 0; i < qty; i++) {
      const keyId = generateKeyId(brandConfig.prefix);
      const keyData = {
        hwid: '',
        expires_at: 0,
        duration_days: dur,
        active: true,
        created_at: now,
        created_by: user.id,
        created_by_name: user.nickname || user.username || 'Unknown',
      };
      await fbPut(brandConfig.path + keyId, keyData);
      keys.push({ key: keyId, brand: brandConfig.name });
    }

    // Ensure reseller profile exists
    const profile = await fbGet(`/resellers/${user.id}`);
    if (!profile) {
      await fbPatch(`/resellers/${user.id}`, {
        username: user.username,
        brands: user.brands,
        createdAt: Date.now(),
      });
    }

    return res.status(200).json({
      success: true,
      keys: keys.map(k => k.key),
      brand: brandConfig.name,
      duration: dur,
    });

  } catch (error) {
    console.error('Generate Key Error:', error);
    return res.status(500).json({ error: 'Failed to generate keys' });
  }
};
