// api/auth-check.js
// Lightweight session probe used by dashboard.html and admin.html on load.
// Reads the omnis_reseller cookie, validates it through the shared
// resolveUser helper, and returns the role flags. The handler is GET-only
// so it bypasses the Origin/Referer enforcement in resolveUser (which only
// fires for mutating verbs).

const { resolveUser } = require('../lib/auth-helper');

module.exports = async function handler(req, res) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');

    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const user = await resolveUser(req);
    if (!user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!user.isReseller && !user.isAdmin) {
        return res.status(403).json({ error: 'Not authorized' });
    }

    return res.status(200).json({
        isReseller: !!user.isReseller,
        isAdmin: !!user.isAdmin,
        username: user.username || null,
        nickname: user.nickname || null,
        avatar: user.avatar || null,
        suspended: !!user.suspended,
    });
};
