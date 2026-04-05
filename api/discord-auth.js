const crypto = require('crypto');

// Brand role IDs — maps Discord role to brand access
const BRAND_ROLES = {
    '1488233437985898718': 'voltaris',
    '1488233505031848158': 'projectservices',
    '1488233530931806309': 'corvus',
    '1488233795105849444': 'omnis',
};

function signJWT(payload, secret) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

async function fbPatch(path, data) {
    const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
    await fetch(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
}

module.exports = async function handler(req, res) {
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || `${protocol}://${host}`;
    const REDIRECT_URI = `${BASE_URL}/api/discord-auth`;

    const url = new URL(req.url, BASE_URL);
    
    const code = (req.query && req.query.code) || url.searchParams.get('code');
    const login = (req.query && req.query.login) || url.searchParams.get('login');
    const discordError = (req.query && req.query.error) || url.searchParams.get('error');

    if (login) {
        const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify%20guilds`;
        res.writeHead(302, { Location: discordAuthUrl });
        return res.end();
    }

    if (discordError) {
        res.writeHead(302, { Location: `/?error=${discordError}` });
        return res.end();
    }

    if (!code) {
        res.writeHead(302, { Location: '/?error=NoCode' });
        return res.end();
    }

    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI
            })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) throw new Error('Invalid OAuth code');

        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userRes.json();

        const memberRes = await fetch(`https://discord.com/api/guilds/${process.env.DISCORD_GUILD_ID}/members/${userData.id}`, {
            headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}` }
        });
        const memberData = await memberRes.json();

        if (!memberRes.ok) {
            console.error('Bot member fetch failed:', memberRes.status, JSON.stringify(memberData));
            res.writeHead(302, { Location: `/?error=BotError_${memberRes.status}` });
            return res.end();
        }

        const userRoles = memberData.roles || [];

        // Detect admin
        const adminRoleId = (process.env.DISCORD_ADMIN_ROLE_ID || '').trim();
        const isAdmin = userRoles.includes(adminRoleId);

        // Detect which brand roles the user has
        const userBrands = [];
        for (const [roleId, brandId] of Object.entries(BRAND_ROLES)) {
            if (userRoles.includes(roleId)) {
                userBrands.push(brandId);
            }
        }

        // Also check generic reseller roles
        const allowedRoleIds = process.env.DISCORD_RESELLER_ROLE_IDS 
            ? process.env.DISCORD_RESELLER_ROLE_IDS.split(',').map(id => id.trim()) 
            : [];
        const isReseller = userBrands.length > 0 || userRoles.some(role => allowedRoleIds.includes(role));

        if (!isReseller && !isAdmin) {
            const debugInfo = `yourRoles=${userRoles.join('_')}&adminRole=${adminRoleId}&brandRoles=${Object.keys(BRAND_ROLES).join('_')}`;
            console.error('Role check failed. User roles:', userRoles);
            res.writeHead(302, { Location: `/?error=NotAReseller&${debugInfo}` });
            return res.end();
        }

        // Admin gets all brands
        const brands = isAdmin ? ['voltaris', 'projectservices', 'corvus', 'omnis'] : userBrands;

        // JWT only contains user ID + expiry — NEVER store roles in the token
        const payload = {
            sub: userData.id,
            exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
        };

        const token = signJWT(payload, process.env.JWT_SECRET);

        // Store ALL role data in Firebase BEFORE redirect (source of truth for permissions)
        try {
            await fbPatch(`/resellers/${userData.id}`, {
                username: memberData.nick || userData.global_name || userData.username,
                nickname: memberData.nick || userData.global_name || userData.username,
                avatar: userData.avatar,
                isAdmin: isAdmin,
                isReseller: isReseller || isAdmin,
                brands: brands,
                lastLogin: Date.now(),
            });
        } catch (e) { console.error('Firebase profile save error:', e); }

        // SameSite=Strict, HttpOnly, Secure, 1-hour lifetime
        res.setHeader('Set-Cookie', `omnis_reseller=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
        
        if (isAdmin) {
            res.writeHead(302, { Location: '/admin.html' });
        } else {
            res.writeHead(302, { Location: '/dashboard.html' });
        }
        return res.end();

    } catch (e) {
        console.error('Discord Auth Error:', e);
        res.writeHead(302, { Location: '/?error=AuthFailed' });
        return res.end();
    }
};
