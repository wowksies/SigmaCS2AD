// api/keys.js — Combined keys endpoint (activate/purchase in one)
const {
  resolveClientUser, fbGet, fbPut, fbPatch, fbPost,
  sanitize,
} = require('./user-auth-helper');
const { resolveUser } = require('./auth-helper');
const crypto = require('crypto');

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

// ─── ACTIVATE KEY ──────────────────────────────────────────────
async function handleActivate(req, res) {
  const user = await resolveClientUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  try {
    const body = await parseJsonBody(req);
    const keyValue = sanitize((body.key || '').trim().toUpperCase(), 30);

    if (!keyValue) {
      return res.status(400).json({ error: 'Key is required' });
    }

    if (!keyValue.startsWith('OMNIS-')) {
      return res.status(400).json({ error: 'Invalid key format. Key must start with OMNIS-' });
    }

    const keyData = await fbGet(`/keys/omnis/${keyValue}`);
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
      const existingKey = await fbGet(`/keys/omnis/${user.activeKey.keyId}`);
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

    await fbPatch(`/keys/omnis/${keyValue}`, {
      status: 'activated',
      boundToUser: user.id,
      activatedAt: activatedAt,
      expires_at: expiresAt,
    });

    await fbPatch(`/users/${user.id}`, {
      activeKey: {
        keyId: keyValue,
        expiresAt: expiresAt,
        activatedAt: activatedAt,
        durationDays: keyData.duration_days || 30,
        status: 'activated',
      },
    });

    return res.status(200).json({
      success: true,
      message: 'Key activated successfully!',
      keyId: keyValue,
      expiresAt: expiresAt,
      durationDays: keyData.duration_days || 30,
      isLifetime: isLifetime,
    });

  } catch (error) {
    console.error('Activate key error:', error);
    return res.status(500).json({ error: 'Activation failed. Try again.' });
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
    case 'purchase':
      return handlePurchase(req, res);
    default:
      return res.status(400).json({ error: 'Invalid action. Use: activate, purchase' });
  }
};
