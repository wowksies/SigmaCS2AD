const crypto = require('crypto');
const { resolveUser, fbGet } = require('../lib/auth-helper');
const {
  BRANDS,
  VALID_DURATIONS,
  getConfiguredPrice,
  getResellerCutRate,
  normalizeMoney,
} = require('../lib/pricing-helper');

// Firebase-backed rate limit. Survives serverless cold starts and is shared
// across all Vercel function instances. Entry shape:
//   /rate_limits/key_gen/{userId}: { bucket, count, updatedAt }
// Window is bucketed into 5-minute slots; each slot allows RATE_LIMIT_MAX calls.
const RATE_LIMIT_WINDOW_SEC = 5 * 60;
const RATE_LIMIT_MAX = 10;

function rateLimitBucket() {
  return Math.floor(Date.now() / 1000 / RATE_LIMIT_WINDOW_SEC);
}

async function _fbWriteRateLimit(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
}

// Returns true if the call is allowed and increments the counter.
// Read-modify-write — race-tolerant; under heavy contention an attacker
// might gain a couple of extra calls per bucket, which is acceptable for
// a key-gen throttle (the actual key-gen is also gated by reseller role).
async function checkRateLimit(userId) {
  const bucket = rateLimitBucket();
  const path = `/rate_limits/key_gen/${userId}`;
  let entry = null;
  try { entry = await fbGet(path); } catch (_) { entry = null; }

  let count = 1;
  if (entry && entry.bucket === bucket && typeof entry.count === 'number') {
    count = entry.count + 1;
  }
  if (count > RATE_LIMIT_MAX) {
    return false;
  }
  try {
    await _fbWriteRateLimit(path, { bucket, count, updatedAt: Math.floor(Date.now() / 1000) });
  } catch (e) {
    // Don't block legitimate key-gen on a transient counter write failure.
    console.warn(`[generate-key checkRateLimit] write failed for ${userId}:`, e.message);
  }
  return true;
}

function generateKeyId(prefix) {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const segment = () => {
    const bytes = crypto.randomBytes(4);
    return Array.from(bytes).map((byte) => chars[byte % chars.length]).join('');
  };
  return `${prefix}${segment()}-${segment()}-${segment()}-${segment()}`;
}

async function fbPut(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error(`Firebase PUT failed: ${response.status}`);
  return response.json();
}

async function fbPost(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
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

  const resellerProfile = await fbGet(`/resellers/${user.id}`);
  if (!resellerProfile) {
    console.warn(`KEY GEN BLOCKED: User ${user.id} has no reseller profile in DB`);
    return res.status(403).json({ error: 'Account not registered' });
  }
  if (resellerProfile.suspended) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  if (!(await checkRateLimit(user.id))) {
    console.warn(`RATE LIMIT HIT: User ${user.id} (${user.username}) exceeded key generation limit`);
    return res.status(429).json({ error: 'Too many requests. Try again in a few minutes.' });
  }

  const { brand, duration, quantity } = req.body || {};
  const brandConfig = BRANDS[brand];
  if (!brandConfig) {
    return res.status(400).json({ error: 'Invalid brand' });
  }

  const dbBrands = resellerProfile.brands || [];
  if (!user.isAdmin && !dbBrands.includes(brand)) {
    console.warn(`UNAUTHORIZED KEY GEN ATTEMPT: User ${user.id} (${user.username}) tried brand ${brand} without access. DB brands: ${dbBrands}`);
    return res.status(403).json({ error: 'No access to this brand' });
  }

  const durationDays = parseInt(duration, 10);
  if (!VALID_DURATIONS.includes(durationDays)) {
    return res.status(400).json({ error: 'Invalid duration' });
  }

  const qty = Math.min(Math.max(parseInt(quantity, 10) || 1, 1), 25);

  try {
    const keys = [];
    const now = Math.floor(Date.now() / 1000);
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
    const cutRate = user.isAdmin ? 0 : getResellerCutRate(resellerProfile);
    const unitPrice = user.isAdmin ? 0 : getConfiguredPrice(resellerProfile, brand, durationDays);
    const owedAmount = user.isAdmin ? 0 : normalizeMoney(unitPrice * cutRate, 0);

    for (let i = 0; i < qty; i++) {
      const keyId = generateKeyId(brandConfig.prefix);
      const keyData = {
        hwid: '',
        expires_at: 0,
        duration_days: durationDays,
        active: true,
        created_at: now,
        created_by: user.id,
        created_by_name: user.nickname || user.username || 'Unknown',
        is_admin: user.isAdmin === true,
        sale_price: unitPrice,
        cut_rate: cutRate,
        owed_amount: owedAmount,
      };
      await fbPut(brandConfig.path + keyId, keyData);
      keys.push({ key: keyId, brand: brandConfig.name });
    }

    try {
      await fbPost('/audit_logs/key_generation', {
        user_id: user.id,
        username: user.nickname || user.username,
        brand,
        quantity: qty,
        duration: durationDays,
        keys_generated: keys.map((entry) => entry.key),
        ip,
        timestamp: now,
        is_admin: user.isAdmin || false,
        source: 'reseller_panel',
        unit_price: unitPrice,
        cut_rate: cutRate,
      });
    } catch (error) {
      // Audit logging should not block key generation.
    }

    try {
      const alertWebhook = process.env.SECURITY_WEBHOOK_URL;
      if (alertWebhook) {
        const color = user.isAdmin ? 0x00FF00 : 0xFFA500;
        await fetch(alertWebhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            embeds: [{
              title: 'Keys Generated',
              color,
              fields: [
                { name: 'User', value: `${user.nickname || user.username}\n\`${user.id}\``, inline: true },
                { name: 'Brand', value: brandConfig.name, inline: true },
                { name: 'Quantity', value: String(qty), inline: true },
                { name: 'Duration', value: durationDays === 99999 ? 'Lifetime' : durationDays + ' days', inline: true },
                { name: 'Source', value: user.isAdmin ? 'Admin Panel' : 'Reseller Panel', inline: true },
                { name: 'IP', value: '`' + ip + '`', inline: true },
              ],
              footer: { text: 'Key Security Monitor' },
              timestamp: new Date().toISOString(),
            }],
          }),
        });
      }
    } catch (error) {
      // Webhook alerts should not block key generation.
    }

    return res.status(200).json({
      success: true,
      keys: keys.map((entry) => entry.key),
      brand: brandConfig.name,
      duration: durationDays,
      unitPrice,
      cutRate,
    });
  } catch (error) {
    console.error('Generate Key Error:', error);
    return res.status(500).json({ error: 'Failed to generate keys' });
  }
};