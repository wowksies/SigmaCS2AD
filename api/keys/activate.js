// api/keys/activate.js — Bind an unused key to the logged-in user's account
// User enters their key on the website dashboard → this endpoint links it to their account
const {
  resolveClientUser, fbGet, fbPatch, fbPost,
  sanitize,
} = require('../user-auth-helper');

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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Must be logged in as a user (not reseller)
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

    // Must start with OMNIS-
    if (!keyValue.startsWith('OMNIS-')) {
      return res.status(400).json({ error: 'Invalid key format. Key must start with OMNIS-' });
    }

    // ── Step 1: Look up the key in Firebase ──────────────────────
    const keyData = await fbGet(`/keys/omnis/${keyValue}`);
    if (!keyData) {
      return res.status(404).json({ error: 'Key not found. Check you typed it correctly.' });
    }

    // ── Step 2: Check key status ─────────────────────────────────
    // Already bound to another user
    if (keyData.boundToUser && keyData.boundToUser !== user.id) {
      return res.status(403).json({ error: 'This key is already activated on another account.' });
    }

    // Already bound to THIS user
    if (keyData.boundToUser === user.id && keyData.status === 'activated') {
      return res.status(200).json({
        success: true,
        message: 'Key is already active on your account.',
        keyId: keyValue,
        expiresAt: keyData.expires_at || 0,
        durationDays: keyData.duration_days || 0,
      });
    }

    // Key is disabled
    if (keyData.active === false) {
      return res.status(403).json({ error: 'This key has been disabled.' });
    }

    // Key is expired
    const now = Math.floor(Date.now() / 1000);
    const isLifetime = (keyData.duration_days >= 99999);
    if (!isLifetime && keyData.expires_at > 0 && keyData.expires_at < now) {
      return res.status(403).json({ error: 'This key has expired.' });
    }

    // ── Step 3: User already has an active key? ──────────────────
    if (user.activeKey && user.activeKey.keyId) {
      // Check if existing key is still valid
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
      // Existing key is expired — allow replacement
    }

    // ── Step 4: Activate the key ─────────────────────────────────
    const activatedAt = now;
    let expiresAt = keyData.expires_at || 0;

    // If key was never activated (no HWID, no expiry set), set expiry now
    if (!keyData.hwid && expiresAt === 0) {
      expiresAt = now + (keyData.duration_days || 30) * 86400;
    }

    // Update key record in Firebase
    await fbPatch(`/keys/omnis/${keyValue}`, {
      status: 'activated',
      boundToUser: user.id,
      activatedAt: activatedAt,
      expires_at: expiresAt,
    });

    // Update user's activeKey
    await fbPatch(`/users/${user.id}`, {
      activeKey: {
        keyId: keyValue,
        expiresAt: expiresAt,
        activatedAt: activatedAt,
        durationDays: keyData.duration_days || 30,
        status: 'activated',
      },
    });

    // Audit log
    try {
      await fbPost('/audit_logs/key_activation', {
        userId: user.id,
        username: user.username,
        keyId: keyValue,
        activatedAt,
        ip: req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown',
        timestamp: now,
      });
    } catch (e) { /* don't block */ }

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
};
