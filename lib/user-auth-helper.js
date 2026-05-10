/**
 * user-auth-helper.js — Shared helpers for the user (non-reseller) auth system
 * - bcrypt password hashing/verification
 * - JWT signing/verification for client auth (separate from reseller JWT)
 * - Firebase read/write helpers for /users collection
 * - Rate limiting and brute-force protection
 */
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
const CLIENT_JWT_SECRET = process.env.CLIENT_JWT_SECRET;

// ── Brute-force protection for user auth ───────────────────────
const userFailedAttempts = new Map();
const USER_LOCKOUT_WINDOW = 10 * 60 * 1000; // 10 minutes
const USER_MAX_FAILURES = 10;

function recordUserFailedAuth(ip) {
  const now = Date.now();
  const entry = userFailedAttempts.get(ip);
  if (!entry || now - entry.windowStart > USER_LOCKOUT_WINDOW) {
    userFailedAttempts.set(ip, { count: 1, windowStart: now });
    return;
  }
  entry.count++;
}

function isUserLockedOut(ip) {
  const entry = userFailedAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.windowStart > USER_LOCKOUT_WINDOW) {
    userFailedAttempts.delete(ip);
    return false;
  }
  return entry.count >= USER_MAX_FAILURES;
}

function clearUserFailedAuth(ip) {
  userFailedAttempts.delete(ip);
}

// ── JWT ────────────────────────────────────────────────────────
function signClientJWT(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', CLIENT_JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyClientJWT(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (header.alg !== 'HS256') return null;

    const sig = crypto.createHmac('sha256', CLIENT_JWT_SECRET)
      .update(`${parts[0]}.${parts[1]}`).digest('base64url');
    if (sig.length !== parts[2].length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    // Reject tokens with absurd expiry (max 2 hours from now)
    if (payload.exp > Math.floor(Date.now() / 1000) + 7200) return null;
    if (!payload.sub || typeof payload.sub !== 'string') return null;

    return payload;
  } catch { return null; }
}

// ── Firebase helpers for /users ─────────────────────────────────
async function fbGet(path) {
  if (!process.env.DATABASE_URL || !process.env.DATABASE_KEY) {
    console.error('[fbGet] Missing DATABASE_URL or DATABASE_KEY env var');
    return null;
  }
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url);
  if (!r.ok) return null;
  return r.json();
}

async function fbPatch(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const response = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error(`Firebase PATCH failed: ${response.status}`);
  return response.json();
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
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error(`Firebase POST failed: ${r.status}`);
  return r.json();
}

// ── User lookup ────────────────────────────────────────────────
// Firebase RTDB doesn't have queries by field natively without indexes,
// so we scan /users to find by username. This is fine for small-medium user bases.
// For scale, add a /usernames/{lowercase_username}: userId index.
async function findUserByUsername(username) {
  const allUsers = await fbGet('/users');
  if (!allUsers || typeof allUsers !== 'object') return null;

  const lower = username.toLowerCase();
  for (const [uid, profile] of Object.entries(allUsers)) {
    if (profile && profile.username && profile.username.toLowerCase() === lower) {
      return { id: uid, ...profile };
    }
  }
  return null;
}

async function findUserByEmail(email) {
  const allUsers = await fbGet('/users');
  if (!allUsers || typeof allUsers !== 'object') return null;

  const lower = email.toLowerCase();
  for (const [uid, profile] of Object.entries(allUsers)) {
    if (profile && profile.email && profile.email.toLowerCase() === lower) {
      return { id: uid, ...profile };
    }
  }
  return null;
}

async function getUserById(uid) {
  const profile = await fbGet(`/users/${uid}`);
  if (!profile) return null;
  return { id: uid, ...profile };
}

// ── Password ───────────────────────────────────────────────────
async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

// ── Input validation ───────────────────────────────────────────
function validateUsername(username) {
  if (typeof username !== 'string') return 'Username is required';
  const trimmed = username.trim();
  if (trimmed.length < 3) return 'Username must be at least 3 characters';
  if (trimmed.length > 24) return 'Username must be at most 24 characters';
  if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) return 'Username can only contain letters, numbers, and underscores';
  return null;
}

function validateEmail(email) {
  if (typeof email !== 'string') return 'Email is required';
  const trimmed = email.trim();
  if (trimmed.length > 254) return 'Email is too long';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return 'Invalid email format';
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'Password is required';
  if (password.length < 6) return 'Password must be at least 6 characters';
  if (password.length > 128) return 'Password is too long';
  return null;
}

function sanitize(input, maxLen = 500) {
  if (typeof input !== 'string') return '';
  return input.replace(/<[^>]*>/g, '').replace(/[^\x20-\x7E]/g, '').substring(0, maxLen);
}

// ── Supabase token validator ───────────────────────────────────
const SUPABASE_URL = 'https://euxtyzhcijdpueajvsvd.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV1eHR5emhjaWpkcHVlYWp2c3ZkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzczMDkwNTcsImV4cCI6MjA5Mjg4NTA1N30._rARSmYe7Sp40dvccuL-A9ZSnD_BcdFTHX4SXtxxp88';

async function resolveSupabaseUser(token) {
  let supaData = null;
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${token}`,
      },
    });
    if (!r.ok) {
      console.error(`[resolveSupabaseUser] /auth/v1/user returned ${r.status}`);
      return null;
    }
    supaData = await r.json();
    if (!supaData || !supaData.id) {
      console.error('[resolveSupabaseUser] response missing id');
      return null;
    }
  } catch (e) {
    console.error('[resolveSupabaseUser] supabase fetch threw:', e.message);
    return null;
  }

  // Firebase profile lookup is best-effort. If env vars are missing or RTDB
  // is unreachable, we still authenticate the user from Supabase alone.
  let profile = null;
  try {
    profile = await getUserById(supaData.id);
  } catch (e) {
    console.error('[resolveSupabaseUser] firebase profile fetch failed (non-fatal):', e.message);
  }

  return {
    id: supaData.id,
    email: supaData.email || '',
    emailConfirmed: !!(supaData.email_confirmed_at || supaData.confirmed_at),
    username: (supaData.user_metadata && supaData.user_metadata.username)
      || (profile && profile.username)
      || (supaData.email || '').split('@')[0],
    activeKey: profile ? profile.activeKey : null,
    createdAt: profile ? profile.createdAt : Math.floor(Date.now() / 1000),
    _supabase: true,
  };
}

// ── Resolve user from client JWT (for website dashboard) ──────
async function resolveClientUser(req) {
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';

  if (isUserLockedOut(ip)) {
    console.warn(`USER LOCKED OUT IP: ${ip}`);
    return null;
  }

  // Try cookie first (website), then Authorization header (C++ app)
  let token = null;

  // Cookie: omnis_user=JWT
  const cookies = (req.headers.cookie || '').split(';');
  for (const c of cookies) {
    const [k, ...v] = c.trim().split('=');
    if (k === 'omnis_user') { token = v.join('='); break; }
  }

  // Fallback: Authorization: Bearer JWT
  if (!token) {
    const authHeader = req.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) return null;

  // First try legacy custom JWT
  if (CLIENT_JWT_SECRET) {
    const payload = verifyClientJWT(token);
    if (payload && payload.sub) {
      clearUserFailedAuth(ip);
      const profile = await getUserById(payload.sub);
      if (profile) return profile;
    }
  }

  // Fall through to Supabase access token validation
  const supaUser = await resolveSupabaseUser(token);
  if (supaUser) {
    clearUserFailedAuth(ip);
    return supaUser;
  }

  recordUserFailedAuth(ip);
  return null;
}

// ── Generate unique user ID ────────────────────────────────────
function generateUserId() {
  return 'u_' + crypto.randomBytes(12).toString('hex');
}

// ── Set cookie helper ───────────────────────────────────────────
function setCookie(res, name, value, options = {}) {
  const maxAge = options.maxAge || 3600;
  const httpOnly = options.httpOnly !== false ? 'HttpOnly;' : '';
  const secure = 'Secure;';
  const sameSite = 'SameSite=Strict;';
  const path = 'Path=/;';
  const cookieValue = `${name}=${value}; ${path} Max-Age=${maxAge}; ${httpOnly} ${secure} ${sameSite}`;
  res.setHeader('Set-Cookie', cookieValue);
}

module.exports = {
  fbGet, fbPatch, fbPut, fbPost,
  signClientJWT, verifyClientJWT,
  findUserByUsername, findUserByEmail, getUserById,
  hashPassword, verifyPassword,
  validateUsername, validateEmail, validatePassword,
  sanitize,
  resolveClientUser,
  generateUserId,
  isUserLockedOut, recordUserFailedAuth, clearUserFailedAuth,
  setCookie,
};
