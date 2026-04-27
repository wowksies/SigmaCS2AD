// api/auth/register.js — User registration (creates account in Firebase)
const {
  fbPut, fbPost,
  findUserByUsername, findUserByEmail,
  hashPassword,
  validateUsername, validateEmail, validatePassword,
  sanitize, generateUserId,
} = require('../user-auth-helper');

const registerRateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 3;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = registerRateLimit.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    registerRateLimit.set(ip, { count: 1, windowStart: now });
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
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many registration attempts. Wait a minute.' });
  }

  try {
    const body = await parseJsonBody(req);
    const username = sanitize((body.username || '').trim(), 24);
    const email = sanitize((body.email || '').trim(), 254);
    const password = body.password || '';

    // Validate inputs
    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const emailErr = validateEmail(email);
    if (emailErr) return res.status(400).json({ error: emailErr });

    const passwordErr = validatePassword(password);
    if (passwordErr) return res.status(400).json({ error: passwordErr });

    // Check uniqueness
    const existingUser = await findUserByUsername(username);
    if (existingUser) return res.status(409).json({ error: 'Username already taken' });

    const existingEmail = await findUserByEmail(email);
    if (existingEmail) return res.status(409).json({ error: 'Email already registered' });

    // Create user
    const userId = generateUserId();
    const passwordHash = await hashPassword(password);
    const now = Math.floor(Date.now() / 1000);

    const userData = {
      username: username,
      email: email.toLowerCase().trim(),
      passwordHash: passwordHash,
      createdAt: now,
      activeKey: null,
      hwid: '',
    };

    await fbPut(`/users/${userId}`, userData);

    // Audit log
    try {
      await fbPost('/audit_logs/user_registration', {
        userId,
        username,
        email: email.toLowerCase().trim(),
        ip,
        timestamp: now,
      });
    } catch (e) { /* don't block on audit failure */ }

    return res.status(201).json({
      success: true,
      message: 'Account created. You can now log in.',
      userId: userId,
    });

  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Registration failed. Try again.' });
  }
};
