
const { resolveUser } = require('../lib/auth-helper');

function handleLogout(res) {
    res.setHeader(
        'Set-Cookie',
        'omnis_reseller=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    );
    res.writeHead(302, { Location: '/' });
    res.end();
}

module.exports = async function handler(req, res) {
    const action = (req.query && req.query.action) || '';

    if (action === 'logout') {
        return handleLogout(res);
    }

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
