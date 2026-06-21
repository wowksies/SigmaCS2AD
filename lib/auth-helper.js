
const crypto = require('crypto');

const failedAttempts = new Map();
const LOCKOUT_WINDOW = 10 * 60 * 1000; // 10 minutes
const MAX_FAILURES = 15;

function recordFailedAuth(ip) {
    const now = Date.now();
    const entry = failedAttempts.get(ip);
    if (!entry || now - entry.windowStart > LOCKOUT_WINDOW) {
        failedAttempts.set(ip, { count: 1, windowStart: now });
        return;
    }
    entry.count++;
}

function isLockedOut(ip) {
    const entry = failedAttempts.get(ip);
    if (!entry) return false;
    if (Date.now() - entry.windowStart > LOCKOUT_WINDOW) {
        failedAttempts.delete(ip);
        return false;
    }
    return entry.count >= MAX_FAILURES;
}

function clearFailedAuth(ip) {
    failedAttempts.delete(ip);
}

function verifyJWT(token, secret) {
    try {
        if (!token || typeof token !== 'string') return null;
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        if (header.alg !== 'HS256') return null;

        const sig = crypto.createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest('base64url');
        if (sig.length !== parts[2].length) return null;
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;

        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
        if (payload.exp > Math.floor(Date.now() / 1000) + 7200) return null;
        if (!payload.sub || typeof payload.sub !== 'string') return null;
        if (!/^\d{17,20}$/.test(payload.sub)) return null;

        return payload;
    } catch { return null; }
}

function getCookie(req, name) {
    const cookies = (req.headers.cookie || '').split(';');
    for (const c of cookies) {
        const [k, ...v] = c.trim().split('=');
        if (k === name) return v.join('=');
    }
    return null;
}

async function fbGet(path) {
    const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
    const r = await fetch(url);
    if (!r.ok) return null;
    return r.json();
}

function validateOrigin(req) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return true;

    const origin = req.headers['origin'] || '';
    const referer = req.headers['referer'] || '';
    const host = req.headers['x-forwarded-host'] || req.headers['host'] || '';

    if (!origin && !referer) return false;

    if (origin) {
        try {
            const originHost = new URL(origin).host;
            if (originHost !== host) return false;
        } catch { return false; }
    }

    if (referer) {
        try {
            const refHost = new URL(referer).host;
            if (refHost !== host) return false;
        } catch { return false; }
    }

    return true;
}

function validateUserAgent(req) {
    const ua = req.headers['user-agent'] || '';
    if (!ua || ua.length < 10) return false;
    const blocked = ['curl/', 'wget/', 'python-', 'httpie/', 'postman', 'insomnia', 'httpclient', 'go-http-client'];
    const lowerUA = ua.toLowerCase();
    for (const b of blocked) {
        if (lowerUA.includes(b)) return false;
    }
    return true;
}

async function resolveUser(req, options = {}) {
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';

    if (isLockedOut(ip)) {
        console.warn(`LOCKED OUT IP: ${ip} — too many failed auth attempts`);
        return null;
    }

    if (options.requireOrigin !== false && !validateOrigin(req)) {
        console.warn(`ORIGIN MISMATCH: IP=${ip}, Origin=${req.headers['origin']}, Referer=${req.headers['referer']}`);
        recordFailedAuth(ip);
        return null;
    }

    if (!validateUserAgent(req)) {
        console.warn(`BLOCKED USER-AGENT: IP=${ip}, UA=${req.headers['user-agent']}`);
        recordFailedAuth(ip);
        return null;
    }

    const token = getCookie(req, 'omnis_reseller');
    if (!token) return null;

    const payload = verifyJWT(token, process.env.JWT_SECRET);
    if (!payload || !payload.sub) {
        recordFailedAuth(ip);
        return null;
    }

    clearFailedAuth(ip);

    const profile = await fbGet(`/resellers/${payload.sub}`);

    if (!profile) {
        return {
            id: payload.sub,
            username: 'Unknown',
            avatar: null,
            nickname: 'Unknown',
            isAdmin: false,
            isReseller: false,
            brands: [],
            suspended: false,
        };
    }

    const rawAllowlist = (process.env.ADMIN_ALLOWLIST || '').trim();
    const adminAllowlist = rawAllowlist
        ? rawAllowlist.split(',').map(s => s.trim()).filter(s => /^\d{17,20}$/.test(s))
        : [];
    const allowlistConfigured = adminAllowlist.length > 0;
    const isInAllowlist = !allowlistConfigured || adminAllowlist.includes(payload.sub);

    if (allowlistConfigured && profile.isAdmin === true && !isInAllowlist) {
        console.error(`SUSPICIOUS: User ${payload.sub} has isAdmin=true in DB but is NOT in ADMIN_ALLOWLIST! Possible Firebase injection attack.`);
    }

    return {
        id: payload.sub,
        username: profile.username || 'Unknown',
        avatar: profile.avatar || null,
        nickname: profile.nickname || profile.username || 'Unknown',
        isAdmin: isInAllowlist && profile.isAdmin === true,
        isReseller: profile.isReseller === true || (profile.brands && profile.brands.length > 0),
        brands: profile.brands || [],
        suspended: profile.suspended || false,
    };
}

function sanitize(input, maxLen = 500) {
    if (typeof input !== 'string') return '';
    return input.replace(/<[^>]*>/g, '').replace(/[^\x20-\x7E]/g, '').substring(0, maxLen);
}

module.exports = { verifyJWT, getCookie, fbGet, resolveUser, validateOrigin, validateUserAgent, sanitize, isLockedOut, recordFailedAuth };
