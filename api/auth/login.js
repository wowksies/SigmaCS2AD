// api/auth/login.js — User login (website + C++ app)
// Returns a JWT on success. Website gets a cookie, C++ app gets JSON body.
const {
  findUserByUsername,
  verifyPassword,
  signClientJWT,
  isUserLockedOut, recordUserFailedAuth, clearUserFailedAuth,
} = require('../user-auth-helper');

const loginRateLimit = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 8;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = loginRateLimit.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    loginRateLimit.set(ip, { count: 1, windowStart: now });
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
    return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
  }

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many login attempts. Wait a few minutes.' });
  }

  try {
    const body = await parseJsonBody(req);
    const username = (body.username || '').trim();
    const password = body.password || '';
    const source = body.source || 'website'; // 'website' or 'client'

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Look up user
    const user = await findUserByUsername(username);
    if (!user) {
      recordUserFailedAuth(ip);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Verify password
    const passwordMatch = await verifyPassword(password, user.passwordHash);
    if (!passwordMatch) {
      recordUserFailedAuth(ip);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    clearUserFailedAuth(ip);

    // Issue JWT — 1 hour expiry, contains user ID only
    const token = signClientJWT({
      sub: user.id,
      exp: Math.floor(Date.now() / 1000) + 3600,
      src: source, // track whether this came from website or C++ client
    });

    // Build response with user info (no password hash)
    const userInfo = {
      userId: user.id,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
      activeKey: user.activeKey || null,
    };

    // If key is active, check if it's expired
    if (user.activeKey && user.activeKey.expiresAt) {
      const now = Math.floor(Date.now() / 1000);
      const isLifetime = user.activeKey.durationDays >= 99999;
      if (!isLifetime && user.activeKey.expiresAt < now) {
        userInfo.keyStatus = 'expired';
      } else {
        userInfo.keyStatus = 'active';
        if (!isLifetime) {
          userInfo.keyExpiresIn = user.activeKey.expiresAt - now;
        } else {
          userInfo.keyExpiresIn = -1; // lifetime
        }
      }
    } else {
      userInfo.keyStatus = 'none';
    }

    // Website: set HttpOnly cookie
    if (source === 'website') {
      res.setHeader('Set-Cookie',
        `omnis_user=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`
      );
    }

    return res.status(200).json({
      success: true,
      token: token, // C++ app uses this from JSON body
      user: userInfo,
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Login failed. Try again.' });
  }
};
