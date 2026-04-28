// api/keys.js — Combined keys endpoint (activate/purchase in one)
const {
  resolveClientUser, fbGet, fbPut, fbPatch, fbPost,
  sanitize,
} = require('./user-auth-helper');
const { resolveUser } = require('../lib/auth-helper');
const { BRANDS } = require('../lib/pricing-helper');
const crypto = require('crypto');

const KEY_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateKeyChunk() {
  const bytes = crypto.randomBytes(4);
  return Array.from(bytes).map((b) => KEY_CHARSET[b % KEY_CHARSET.length]).join('');
}

// Detect brand from key prefix. Returns { id, config } or null.
function detectBrandFromKey(keyValue) {
  // Sort prefixes longest-first so PROJECTSERVICES- wins over PS- if any overlap.
  const entries = Object.entries(BRANDS).sort((a, b) => b[1].prefix.length - a[1].prefix.length);
  for (const [id, cfg] of entries) {
    if (keyValue.startsWith(cfg.prefix)) return { id, config: cfg };
  }
  return null;
}

function generateKeyId(prefix) {
  const p = prefix || 'OMNIS-';
  return p + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk();
}

async function parseJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  return await new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; if (raw.length > 10000) reject(new Error('Too large')); });
    req.on('end', () => {
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

const VALID_DURATIONS = [1, 3, 7, 14, 30, 90, 365, 99999];

// Activation rate limits — Firebase-backed so they survive cold starts.
// Window is 24h; counters live at /rate_limits/activations/{bucket}.
const ACTIVATE_PER_IP_PER_DAY = 5;
const ACTIVATE_PER_USER_PER_DAY = 5;
const RATE_WINDOW_SEC = 24 * 60 * 60;

function dayBucket() {
  return Math.floor(Date.now() / 1000 / RATE_WINDOW_SEC);
}

function safeBucketKey(s) {
  // Firebase keys can't contain . # $ [ ] /
  return String(s).replace(/[.#$\[\]\/]/g, '_').substring(0, 64);
}

// Read-modify-write counter. Race-tolerant: worst case a couple of
// extra activations per IP under heavy concurrency, which is fine
// since the underlying key-bind logic still rejects re-binds.
async function bumpRateCounter(scope, id, limit) {
  const bucket = dayBucket();
  const path = `/rate_limits/activations/${scope}/${safeBucketKey(id)}`;
  let entry = null;
  try { entry = await fbGet(path); } catch (_) { entry = null; }

  let count = 1;
  if (entry && entry.bucket === bucket && typeof entry.count === 'number') {
    count = entry.count + 1;
  }
  if (count > limit) {
    return { allowed: false, count, retryAfter: ((bucket + 1) * RATE_WINDOW_SEC) - Math.floor(Date.now() / 1000) };
  }
  try {
    await fbPut(path, { bucket, count, updatedAt: Math.floor(Date.now() / 1000) });
  } catch (e) {
    // Counter write failure should NOT block activation (availability > strict counting).
    console.warn(`[bumpRateCounter] write failed for ${scope}/${id}:`, e.message);
  }
  return { allowed: true, count };
}

// ─── ACTIVATE KEY ──────────────────────────────────────────────
async function handleActivate(req, res) {
  const user = await resolveClientUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  // Require a confirmed email before any activation is allowed.
  // Open Supabase signup means anyone can create an account; gating
  // activation on a real, confirmable email significantly raises the
  // cost of mass-account abuse.
  if (user._supabase && user.emailConfirmed === false) {
    return res.status(403).json({
      error: 'Please confirm your email before activating a key.',
      code: 'email_not_confirmed',
    });
  }

  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';

  // Per-IP daily cap
  const ipCheck = await bumpRateCounter('ip', ip, ACTIVATE_PER_IP_PER_DAY);
  if (!ipCheck.allowed) {
    return res.status(429).json({
      error: `Too many activations from this IP today. Try again in ${Math.ceil(ipCheck.retryAfter / 3600)}h.`,
      code: 'rate_limited',
    });
  }
  // Per-account daily cap
  const userCheck = await bumpRateCounter('user', user.id, ACTIVATE_PER_USER_PER_DAY);
  if (!userCheck.allowed) {
    return res.status(429).json({
      error: `Too many activations on this account today. Try again in ${Math.ceil(userCheck.retryAfter / 3600)}h.`,
      code: 'rate_limited',
    });
  }

  try {
    const body = await parseJsonBody(req);
    const keyValue = sanitize((body.key || '').trim().toUpperCase(), 40);

    if (!keyValue) {
      return res.status(400).json({ error: 'Key is required' });
    }

    const brand = detectBrandFromKey(keyValue);
    if (!brand) {
      return res.status(400).json({ error: 'Invalid key format. Unknown brand prefix.' });
    }

    const keyPath = `${brand.config.path}${keyValue}`;
    const keyData = await fbGet(keyPath);
    if (!keyData) {
      return res.status(404).json({ error: 'Key not found. Check you typed it correctly.' });
    }

    if (keyData.boundToUser && keyData.boundToUser !== user.id) {
      return res.status(403).json({ error: 'This key is already activated on another account.' });
    }

    if (keyData.boundToUser === user.id && keyData.status === 'activated') {
      return res.status(200).json({
        success: true,
        message: 'Key is already active on your account.',
        keyId: keyValue,
        expiresAt: keyData.expires_at || 0,
        durationDays: keyData.duration_days || 0,
      });
    }

    if (keyData.active === false) {
      return res.status(403).json({ error: 'This key has been disabled.' });
    }

    const now = Math.floor(Date.now() / 1000);
    const isLifetime = (keyData.duration_days >= 99999);
    if (!isLifetime && keyData.expires_at > 0 && keyData.expires_at < now) {
      return res.status(403).json({ error: 'This key has expired.' });
    }

    if (user.activeKey && user.activeKey.keyId) {
      const existingBrand = detectBrandFromKey(user.activeKey.keyId);
      const existingPath = existingBrand
        ? `${existingBrand.config.path}${user.activeKey.keyId}`
        : `/keys/omnis/${user.activeKey.keyId}`;
      const existingKey = await fbGet(existingPath);
      const existingExpired = existingKey &&
        existingKey.duration_days < 99999 &&
        existingKey.expires_at > 0 &&
        existingKey.expires_at < now;

      if (!existingExpired) {
        return res.status(409).json({
          error: 'You already have an active key. Contact support if you need to change it.',
          currentKey: user.activeKey.keyId,
        });
      }
    }

    const activatedAt = now;
    let expiresAt = keyData.expires_at || 0;

    if (!keyData.hwid && expiresAt === 0) {
      expiresAt = now + (keyData.duration_days || 30) * 86400;
    }

    await fbPatch(keyPath, {
      status: 'activated',
      boundToUser: user.id,
      activatedAt: activatedAt,
      expires_at: expiresAt,
    });

    await fbPatch(`/users/${user.id}`, {
      activeKey: {
        keyId: keyValue,
        brand: brand.id,
        brandName: brand.config.name,
        expiresAt: expiresAt,
        activatedAt: activatedAt,
        durationDays: keyData.duration_days || 30,
        status: 'activated',
      },
    });

    // Audit trail — best-effort, never blocks activation
    try {
      await fbPost('/audit_logs/key_activations', {
        userId: user.id,
        email: user.email || '',
        keyId: keyValue,
        brand: brand.id,
        ip: ip,
        userAgent: (req.headers['user-agent'] || '').substring(0, 200),
        timestamp: now,
      });
    } catch (_) { /* audit failure is non-fatal */ }

    return res.status(200).json({
      success: true,
      message: 'Key activated successfully!',
      keyId: keyValue,
      brand: brand.id,
      brandName: brand.config.name,
      expiresAt: expiresAt,
      durationDays: keyData.duration_days || 30,
      isLifetime: isLifetime,
    });

  } catch (error) {
    console.error('Activate key error:', error);
    return res.status(500).json({ error: 'Activation failed. Try again.' });
  }
}

// ─── REMOVE KEY FROM ACCOUNT ───────────────────────────────────
async function handleRemove(req, res) {
  const user = await resolveClientUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  try {
    if (!user.activeKey || !user.activeKey.keyId) {
      return res.status(400).json({ error: 'No active key on your account.' });
    }

    const keyId = user.activeKey.keyId;
    const brand = detectBrandFromKey(keyId);
    const keyPath = brand ? `${brand.config.path}${keyId}` : `/keys/omnis/${keyId}`;
    const keyData = await fbGet(keyPath);

    if (keyData && keyData.boundToUser === user.id) {
      await fbPatch(keyPath, {
        boundToUser: null,
        hwid: '',
        status: 'unused',
        activatedAt: 0,
      });
    }

    await fbPatch(`/users/${user.id}`, { activeKey: null });

    return res.status(200).json({
      success: true,
      message: 'Key removed from your account.',
      keyId: keyId,
    });
  } catch (error) {
    console.error('Remove key error:', error);
    return res.status(500).json({ error: 'Failed to remove key. Try again.' });
  }
}

// ─── PURCHASE/GENERATE KEY ─────────────────────────────────────
async function handlePurchase(req, res) {
  const resellerUser = await resolveUser(req);
  if (resellerUser && (resellerUser.isReseller || resellerUser.isAdmin)) {
    return handleResellerGeneration(req, res, resellerUser);
  }

  const clientUser = await resolveClientUser(req);
  if (clientUser) {
    return handleUserPurchase(req, res, clientUser);
  }

  return res.status(401).json({ error: 'Not authenticated' });
}

async function handleResellerGeneration(req, res, resellerUser) {
  const body = await parseJsonBody(req);
  const durationDays = parseInt(body.duration, 10);
  const quantity = Math.min(Math.max(parseInt(body.quantity, 10) || 1, 1), 25);

  if (!VALID_DURATIONS.includes(durationDays)) {
    return res.status(400).json({ error: 'Invalid duration' });
  }

  const now = Math.floor(Date.now() / 1000);
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  const keys = [];

  try {
    for (let i = 0; i < quantity; i++) {
      const keyId = generateKeyId();
      const keyData = {
        hwid: '',
        expires_at: 0,
        duration_days: durationDays,
        active: true,
        created_at: now,
        created_by: resellerUser.id,
        created_by_name: resellerUser.nickname || resellerUser.username || 'Unknown',
        is_admin: resellerUser.isAdmin === true,
        status: 'unused',
        boundToUser: null,
        activatedAt: 0,
      };
      await fbPut(`/keys/omnis/${keyId}`, keyData);
      keys.push(keyId);
    }

    return res.status(200).json({
      success: true,
      keys: keys,
      duration: durationDays,
    });
  } catch (error) {
    console.error('Reseller key gen error:', error);
    return res.status(500).json({ error: 'Failed to generate keys' });
  }
}

async function handleUserPurchase(req, res, clientUser) {
  const body = await parseJsonBody(req);
  const durationDays = parseInt(body.duration, 10);
  const orderId = body.orderId || '';

  if (!VALID_DURATIONS.includes(durationDays)) {
    return res.status(400).json({ error: 'Invalid duration' });
  }

  if (clientUser.activeKey && clientUser.activeKey.keyId) {
    const existingKey = await fbGet(`/keys/omnis/${clientUser.activeKey.keyId}`);
    const now = Math.floor(Date.now() / 1000);
    const existingExpired = existingKey &&
      existingKey.duration_days < 99999 &&
      existingKey.expires_at > 0 &&
      existingKey.expires_at < now;

    if (!existingExpired) {
      return res.status(409).json({
        error: 'You already have an active key.',
        currentKey: clientUser.activeKey.keyId,
      });
    }
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = durationDays >= 99999 ? 0 : now + durationDays * 86400;
  const keyId = generateKeyId();

  try {
    await fbPut(`/keys/omnis/${keyId}`, {
      hwid: '',
      expires_at: expiresAt,
      duration_days: durationDays,
      active: true,
      created_at: now,
      created_by: 'purchase',
      created_by_name: clientUser.username,
      is_admin: false,
      status: 'activated',
      boundToUser: clientUser.id,
      activatedAt: now,
      orderId: orderId,
    });

    await fbPatch(`/users/${clientUser.id}`, {
      activeKey: {
        keyId: keyId,
        expiresAt: expiresAt,
        activatedAt: now,
        durationDays: durationDays,
        status: 'activated',
      },
    });

    return res.status(200).json({
      success: true,
      keyId: keyId,
      expiresAt: expiresAt,
      durationDays: durationDays,
      isLifetime: durationDays >= 99999,
      message: 'Key purchased and activated on your account!',
    });

  } catch (error) {
    console.error('Purchase key gen error:', error);
    return res.status(500).json({ error: 'Failed to process purchase' });
  }
}

// ─── MAIN HANDLER ──────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { action } = req.query;

  switch (action) {
    case 'activate':
      return handleActivate(req, res);
    case 'remove':
      return handleRemove(req, res);
    case 'purchase':
      return handlePurchase(req, res);
    default:
      return res.status(400).json({ error: 'Invalid action. Use: activate, remove, purchase' });
  }
};
