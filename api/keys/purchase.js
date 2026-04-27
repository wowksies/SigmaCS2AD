// api/keys/purchase.js — Generate a new key after a verified purchase
// Called after SellAuth payment is confirmed. Creates an unused key and
// optionally auto-activates it if the user is logged in.
const crypto = require('crypto');
const {
  resolveClientUser, fbGet, fbPut, fbPatch, fbPost,
} = require('../user-auth-helper');
const { resolveUser } = require('../auth-helper');

const KEY_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateKeyChunk() {
  const bytes = crypto.randomBytes(4);
  return Array.from(bytes).map((b) => KEY_CHARSET[b % KEY_CHARSET.length]).join('');
}

function generateKeyId() {
  return 'OMNIS-' + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk();
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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Two auth paths:
  // 1. Reseller generating a key for a customer (uses Discord reseller auth)
  // 2. System auto-generating after a purchase (called by verify.js with a secret)
  // For now, we support the reseller path. The purchase auto-gen will be added
  // when we integrate with the SellAuth verification flow.

  // Try reseller auth first
  const resellerUser = await resolveUser(req);
  if (resellerUser && (resellerUser.isReseller || resellerUser.isAdmin)) {
    // Reseller is generating a key — same as generate-key.js but with user-binding fields
    return await handleResellerGeneration(req, res, resellerUser);
  }

  // Try client user auth (for future auto-activation after purchase)
  const clientUser = await resolveClientUser(req);
  if (clientUser) {
    return await handleUserPurchase(req, res, clientUser);
  }

  return res.status(401).json({ error: 'Not authenticated' });
};

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

    // Audit
    try {
      await fbPost('/audit_logs/key_generation', {
        user_id: resellerUser.id,
        username: resellerUser.nickname || resellerUser.username,
        brand: 'omnis',
        quantity,
        duration: durationDays,
        keys_generated: keys,
        ip,
        timestamp: now,
        source: 'reseller_panel',
      });
    } catch (e) { /* don't block */ }

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
  // After SellAuth payment confirmed, auto-generate + activate a key for this user
  const body = await parseJsonBody(req);
  const durationDays = parseInt(body.duration, 10);
  const orderId = body.orderId || '';

  if (!VALID_DURATIONS.includes(durationDays)) {
    return res.status(400).json({ error: 'Invalid duration' });
  }

  // Check user doesn't already have an active key
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
    // Create key (already activated)
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

    // Bind to user
    await fbPatch(`/users/${clientUser.id}`, {
      activeKey: {
        keyId: keyId,
        expiresAt: expiresAt,
        activatedAt: now,
        durationDays: durationDays,
        status: 'activated',
      },
    });

    // Audit
    try {
      await fbPost('/audit_logs/key_purchase', {
        userId: clientUser.id,
        username: clientUser.username,
        keyId,
        durationDays,
        orderId,
        timestamp: now,
      });
    } catch (e) { /* don't block */ }

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
