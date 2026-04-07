// api/generate-key.js — HARDENED: DB-based auth, rate limiting, audit logging
const crypto = require('crypto');
const { resolveUser, fbGet } = require('./auth-helper');

const BRANDS = {
  voltaris:        { name: 'Voltaris',         prefix: 'VOLTARIS-', path: '/keys/voltaris/' },
  projectservices: { name: 'Project Services', prefix: 'PS-',       path: '/keys/projectservices/' },
  corvus:          { name: 'Corvus',           prefix: 'CORVUS-',   path: '/keys/corvus/' },
  omnis:           { name: 'Omnis',            prefix: 'OMNIS-',    path: '/keys/omnis/' },
};

const VALID_DURATIONS = [1, 3, 7, 14, 30, 90, 365, 99999];

// In-memory rate limiter: max 10 key-gen requests per user per 5 minutes
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes
const RATE_LIMIT_MAX = 10;

function checkRateLimit(userId) {
  const now = Date.now();
  const entry = rateLimitMap.get(userId);
  if (!entry) {
    rateLimitMap.set(userId, { count: 1, windowStart: now });
    return true;
  }
  if (now - entry.windowStart > RATE_LIMIT_WINDOW) {
    // Reset window
    rateLimitMap.set(userId, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return false; // Rate limited
  }
  entry.count++;
  return true;
}

function generateKeyId(prefix) {
  // Use crypto.randomBytes for secure randomness (not Math.random)
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const seg = () => {
    const bytes = crypto.randomBytes(4);
    return Array.from(bytes).map(b => chars[b % chars.length]).join('');
  };
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

async function fbPost(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
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

  // SECURITY: Verify reseller actually exists in the database
  // Prevents ghost sessions from generating keys
  const resellerProfile = await fbGet(`/resellers/${user.id}`);
  if (!resellerProfile) {
    console.warn(`KEY GEN BLOCKED: User ${user.id} has no reseller profile in DB`);
    return res.status(403).json({ error: 'Account not registered' });
  }
  if (resellerProfile.suspended) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  // Rate limit check — 5 requests per 5 minutes
  if (!checkRateLimit(user.id)) {
    console.warn(`RATE LIMIT HIT: User ${user.id} (${user.username}) exceeded key generation limit`);
    return res.status(429).json({ error: 'Too many requests. Try again in a few minutes.' });
  }

  const { brand, duration, quantity } = req.body || {};

  const brandConfig = BRANDS[brand];
  if (!brandConfig) {
    return res.status(400).json({ error: 'Invalid brand' });
  }

  // Strict brand access check — from DB profile, not JWT
  const dbBrands = resellerProfile.brands || [];
  if (!user.isAdmin) {
    if (!dbBrands.includes(brand)) {
      console.warn(`UNAUTHORIZED KEY GEN ATTEMPT: User ${user.id} (${user.username}) tried brand ${brand} without access. DB brands: ${dbBrands}`);
      return res.status(403).json({ error: 'No access to this brand' });
    }
  }

  const dur = parseInt(duration);
  if (!VALID_DURATIONS.includes(dur)) {
    return res.status(400).json({ error: 'Invalid duration' });
  }

  // Cap quantity strictly
  const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 25);

  try {
    const keys = [];
    const now = Math.floor(Date.now() / 1000);
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';

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

    // Audit log — record every key generation event
    try {
      await fbPost('/audit_logs/key_generation', {
        user_id: user.id,
        username: user.nickname || user.username,
        brand: brand,
        quantity: qty,
        duration: dur,
        keys_generated: keys.map(k => k.key),
        ip: ip,
        timestamp: now,
        is_admin: user.isAdmin || false,
        source: 'reseller_panel',
      });
    } catch (e) { /* audit log failure should not block key gen */ }

    // DISCORD SECURITY WEBHOOK — notify owner on every key generation
    try {
      const alertWebhook = process.env.SECURITY_WEBHOOK_URL;
      if (alertWebhook) {
        const color = user.isAdmin ? 0x00FF00 : 0xFFA500;
        await fetch(alertWebhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            embeds: [{
              title: '🔑 Keys Generated',
              color: color,
              fields: [
                { name: 'User', value: `${user.nickname || user.username}\n\`${user.id}\``, inline: true },
                { name: 'Brand', value: brandConfig.name, inline: true },
                { name: 'Quantity', value: String(qty), inline: true },
                { name: 'Duration', value: dur === 99999 ? 'Lifetime' : dur + ' days', inline: true },
                { name: 'Source', value: user.isAdmin ? 'Admin Panel' : 'Reseller Panel', inline: true },
                { name: 'IP', value: '`' + ip + '`', inline: true },
              ],
              footer: { text: 'Key Security Monitor' },
              timestamp: new Date().toISOString(),
            }],
          }),
        });
      }
    } catch (e) { /* webhook failure should not block */ }

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
