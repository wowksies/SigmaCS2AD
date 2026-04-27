// api/auth/validate-client.js — Called by the C++ Omnis app to verify login + key
// This is the main endpoint the C++ binary hits instead of Firebase directly.
// Flow: username+password → verify creds → check active key → check expiry → return result
const {
  findUserByUsername,
  verifyPassword,
  signClientJWT,
  fbGet, fbPatch,
  isUserLockedOut, recordUserFailedAuth, clearUserFailedAuth,
} = require('../user-auth-helper');

const validateRateLimit = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 6;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = validateRateLimit.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    validateRateLimit.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';

  if (isUserLockedOut(ip)) {
    return res.status(429).json({ error: 'Locked out. Try again later.' });
  }

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many attempts.' });
  }

  try {
    const body = await parseJsonBody(req);
    const username = (body.username || '').trim();
    const password = body.password || '';
    const hwid = (body.hwid || '').trim();

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // ── Step 1: Verify credentials ──────────────────────────────
    const user = await findUserByUsername(username);
    if (!user) {
      recordUserFailedAuth(ip);
      return res.status(401).json({ error: 'invalid_credentials', message: 'Wrong username or password' });
    }

    const passwordMatch = await verifyPassword(password, user.passwordHash);
    if (!passwordMatch) {
      recordUserFailedAuth(ip);
      return res.status(401).json({ error: 'invalid_credentials', message: 'Wrong username or password' });
    }

    clearUserFailedAuth(ip);

    // ── Step 2: Check if user has an active key ─────────────────
    if (!user.activeKey || !user.activeKey.keyId) {
      return res.status(403).json({
        error: 'no_key',
        message: 'No active key on your account. Purchase and activate a key at omnis-cs2.xyz',
      });
    }

    // ── Step 3: Verify key still exists and is active in Firebase ─
    const keyData = await fbGet(`/keys/omnis/${user.activeKey.keyId}`);
    if (!keyData) {
      return res.status(403).json({
        error: 'key_not_found',
        message: 'Your key no longer exists. Contact support.',
      });
    }

    if (keyData.active === false) {
      return res.status(403).json({
        error: 'key_disabled',
        message: 'Your key has been disabled. Contact support.',
      });
    }

    // ── Step 4: Check expiry ─────────────────────────────────────
    const now = Math.floor(Date.now() / 1000);
    const isLifetime = (keyData.duration_days >= 99999);

    if (!isLifetime && keyData.expires_at > 0 && keyData.expires_at < now) {
      // Key expired — update status in Firebase
      try {
        await fbPatch(`/keys/omnis/${user.activeKey.keyId}`, { status: 'expired' });
        await fbPatch(`/users/${user.id}/activeKey`, { status: 'expired' });
      } catch (e) { /* non-critical */ }

      return res.status(403).json({
        error: 'key_expired',
        message: 'Your key has expired. Purchase a new one at omnis-cs2.xyz',
        expiredAt: keyData.expires_at,
      });
    }

    // ── Step 5: HWID binding (preserve existing behavior) ────────
    // If key already has HWID bound, check it matches
    if (hwid && keyData.hwid && keyData.hwid !== hwid) {
      return res.status(403).json({
        error: 'hwid_mismatch',
        message: 'Key is bound to a different machine',
      });
    }

    // If key has no HWID and client provided one, bind it
    if (hwid && !keyData.hwid) {
      try {
        await fbPatch(`/keys/omnis/${user.activeKey.keyId}`, { hwid: hwid });
        await fbPatch(`/users/${user.id}`, { hwid: hwid });
      } catch (e) { /* non-critical, don't block login */ }
    }

    // ── Step 6: Calculate time remaining ─────────────────────────
    let secondsLeft = -1; // lifetime
    if (!isLifetime && keyData.expires_at > 0) {
      secondsLeft = keyData.expires_at - now;
    }

    // ── Step 7: Issue client JWT ─────────────────────────────────
    const token = signClientJWT({
      sub: user.id,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      src: 'client',
      key: user.activeKey.keyId,
    });

    // Audit log
    try {
      const { fbPost } = require('../user-auth-helper');
      await fbPost('/audit_logs/client_login', {
        userId: user.id,
        username: user.username,
        keyId: user.activeKey.keyId,
        hwid: hwid || 'none',
        ip,
        timestamp: now,
      });
    } catch (e) { /* don't block */ }

    return res.status(200).json({
      success: true,
      token: token,
      username: user.username,
      keyId: user.activeKey.keyId,
      tier: keyData.tier || 'omnis',
      secondsLeft: secondsLeft,
      isLifetime: isLifetime,
      durationDays: keyData.duration_days || 0,
    });

  } catch (error) {
    console.error('Validate-client error:', error);
    return res.status(500).json({ error: 'server_error', message: 'Validation failed' });
  }
};
