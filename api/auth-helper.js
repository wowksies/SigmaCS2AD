/**
 * Shared auth helper — verifies JWT and resolves user from database.
 * JWT only contains { sub, exp } — roles/brands are ALWAYS fetched from Firebase.
 * This prevents token tampering (e.g. flipping isAdmin to true).
 */
const crypto = require('crypto');

function verifyJWT(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const sig = crypto.createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest('base64url');
        if (sig !== parts[2]) return null;
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
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

/**
 * Resolves the authenticated user from JWT + Firebase.
 * Returns { id, username, avatar, nickname, isAdmin, isReseller, brands, suspended } or null.
 */
async function resolveUser(req) {
    const token = getCookie(req, 'omnis_reseller');
    if (!token) return null;

    const payload = verifyJWT(token, process.env.JWT_SECRET);
    if (!payload || !payload.sub) return null;

    // Fetch user profile from database — this is the source of truth for roles
    const profile = await fbGet(`/resellers/${payload.sub}`);
    if (!profile) return null;

    return {
        id: payload.sub,
        username: profile.username || 'Unknown',
        avatar: profile.avatar || null,
        nickname: profile.nickname || profile.username || 'Unknown',
        isAdmin: profile.isAdmin === true,
        isReseller: profile.isReseller === true || (profile.brands && profile.brands.length > 0),
        brands: profile.brands || [],
        suspended: profile.suspended || false,
    };
}

module.exports = { verifyJWT, getCookie, fbGet, resolveUser };
