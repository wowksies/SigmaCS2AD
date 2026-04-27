// api/auth.js — Combined auth endpoint (register/login/validate-client in one)
// Routes based on ?action= parameter to reduce serverless function count

const {
  fbPut, fbPost,
  findUserByUsername, findUserByEmail,
  hashPassword, verifyPassword,
  signClientJWT,
  validateUsername, validateEmail, validatePassword,
  sanitize, generateUserId,
  isUserLockedOut, recordUserFailedAuth, clearUserFailedAuth,
  fbGet, fbPatch,
  resolveClientUser, setCookie
} = require('./user-auth-helper');

const { resolveUser } = require('../lib/auth-helper');
const cookie = require('cookie');

// Rate limit maps
const registerRateLimit = new Map();
const loginRateLimit = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 20; // Temporarily increased for testing

function checkRateLimit(map, ip) {
  const now = Date.now();
  const entry = map.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    map.set(ip, { count: 1, windowStart: now });
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

// ─── REGISTER ────────────────────────────────────────────────
async function handleRegister(req, res) {
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!checkRateLimit(registerRateLimit, ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  try {
    const body = await parseJsonBody(req);
    const username = sanitize((body.username || '').trim(), 24);
    const email = sanitize((body.email || '').trim().toLowerCase(), 64);
    const password = body.password || '';

    // Validation
    const usernameError = validateUsername(username);
    if (usernameError) {
      return res.status(400).json({ error: usernameError });
    }
    const emailError = validateEmail(email);
    if (emailError) {
      return res.status(400).json({ error: emailError });
    }
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    // Check duplicates
    const existingUserByUsername = await findUserByUsername(username);
    if (existingUserByUsername) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const existingUserByEmail = await findUserByEmail(email);
    if (existingUserByEmail) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password
    const passwordHash = await hashPassword(password);
    const userId = generateUserId();
    const now = Math.floor(Date.now() / 1000);

    // Create user
    await fbPut(`/users/${userId}`, {
      id: userId,
      username: username,
      email: email,
      passwordHash: passwordHash,
      createdAt: now,
      activeKey: null,
      hwid: null,
      role: 'user',
    });

    // Audit log
    await fbPost('/audit_logs/user_registration', {
      userId: userId,
      username: username,
      email: email,
      ip: ip,
      timestamp: now,
    }).catch(() => {});

    return res.status(200).json({ success: true, userId: userId, username: username });

  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Registration failed. Try again.' });
  }
}

// ─── LOGIN ─────────────────────────────────────────────────────
async function handleLogin(req, res) {
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!checkRateLimit(loginRateLimit, ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  try {
    const body = await parseJsonBody(req);
    const username = sanitize((body.username || '').trim().toLowerCase(), 24);
    const password = body.password || '';
    const source = body.source || 'website'; // 'website' or 'client'

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Brute force check per user
    if (isUserLockedOut(username)) {
      return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
    }

    // Find user
    const user = await findUserByUsername(username);
    if (!user) {
      recordUserFailedAuth(username);
      return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid username or password' });
    }

    // Verify password
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      recordUserFailedAuth(username);
      return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid username or password' });
    }

    clearUserFailedAuth(username);

    // Check if user has active key
    if (!user.activeKey || !user.activeKey.keyId) {
      return res.status(403).json({ error: 'no_key', message: 'No active key on account' });
    }

    // Check key status
    const keyData = await fbGet(`/keys/omnis/${user.activeKey.keyId}`);
    if (!keyData) {
      return res.status(403).json({ error: 'key_not_found', message: 'Active key not found' });
    }

    if (keyData.active === false) {
      return res.status(403).json({ error: 'key_disabled', message: 'Key has been disabled' });
    }

    const now = Math.floor(Date.now() / 1000);
    const isLifetime = (keyData.duration_days >= 99999);
    if (!isLifetime && keyData.expires_at > 0 && keyData.expires_at < now) {
      return res.status(403).json({ error: 'key_expired', message: 'Key has expired' });
    }

    // Issue token
    const token = signClientJWT({
      sub: user.id,
      exp: now + 3600,
      src: source === 'client' ? 'client' : 'user',
      key: user.activeKey.keyId,
    });

    // Website gets cookie, client gets body
    if (source === 'website') {
      setCookie(res, 'omnis_user', token, { maxAge: 7 * 24 * 60 * 60 });
    }

    return res.status(200).json({
      success: true,
      token: token,
      username: user.username,
      userId: user.id,
      keyId: user.activeKey.keyId,
      tier: keyData.tier || 'standard',
      secondsLeft: isLifetime ? -1 : Math.max(0, keyData.expires_at - now),
      isLifetime: isLifetime,
      durationDays: keyData.duration_days || 30,
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Login failed. Try again.' });
  }
}

// ─── VALIDATE CLIENT ───────────────────────────────────────────
async function handleValidateClient(req, res) {
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!checkRateLimit(loginRateLimit, ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  try {
    const body = await parseJsonBody(req);
    const username = sanitize((body.username || '').trim().toLowerCase(), 24);
    const password = body.password || '';
    const hwid = sanitize((body.hwid || '').substr(0, 32), 32);

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Find user
    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    // Verify password
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    // Check active key
    if (!user.activeKey || !user.activeKey.keyId) {
      return res.status(403).json({ error: 'no_key', message: 'No active key on account' });
    }

    // Fetch key data
    const keyData = await fbGet(`/keys/omnis/${user.activeKey.keyId}`);
    if (!keyData) {
      return res.status(403).json({ error: 'key_not_found' });
    }

    // Check key status
    if (keyData.active === false) {
      return res.status(403).json({ error: 'key_disabled' });
    }

    const now = Math.floor(Date.now() / 1000);
    const isLifetime = (keyData.duration_days >= 99999);
    if (!isLifetime && keyData.expires_at > 0 && keyData.expires_at < now) {
      return res.status(403).json({ error: 'key_expired' });
    }

    // HWID check
    if (!keyData.hwid || keyData.hwid === '') {
      // First activation - bind HWID
      await fbPatch(`/keys/omnis/${user.activeKey.keyId}`, { hwid: hwid });
      keyData.hwid = hwid;
    } else if (keyData.hwid !== hwid) {
      return res.status(403).json({ error: 'hwid_mismatch', message: 'Key bound to different machine' });
    }

    // Issue token
    const token = signClientJWT({
      sub: user.id,
      exp: now + 3600,
      src: 'client',
      key: user.activeKey.keyId,
    });

    return res.status(200).json({
      success: true,
      token: token,
      username: user.username,
      keyId: user.activeKey.keyId,
      secondsLeft: isLifetime ? -1 : Math.max(0, keyData.expires_at - now),
      isLifetime: isLifetime,
    });

  } catch (error) {
    console.error('Validate client error:', error);
    return res.status(500).json({ error: 'server_error' });
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
    case 'register':
      return handleRegister(req, res);
    case 'login':
      return handleLogin(req, res);
    case 'validate-client':
      return handleValidateClient(req, res);
    default:
      return res.status(400).json({ error: 'Invalid action. Use: register, login, validate-client' });
  }
};
