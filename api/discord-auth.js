const crypto = require('crypto');

function signJWT(payload, secret) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

module.exports = async function handler(req, res) {
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || `${protocol}://${host}`;
    const REDIRECT_URI = `${BASE_URL}/api/discord-auth`;

    const url = new URL(req.url, BASE_URL);
    
    // Use Vercel's req.query to safely catch parameters, fallback to URL search params
    const code = (req.query && req.query.code) || url.searchParams.get('code');
    const login = (req.query && req.query.login) || url.searchParams.get('login');
    const discordError = (req.query && req.query.error) || url.searchParams.get('error');

    // Added ?login=true check to properly redirect to Discord
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

        // Support multiple Reseller Roles (comma separated in Vercel)
        const allowedRoleIds = process.env.DISCORD_RESELLER_ROLE_IDS 
            ? process.env.DISCORD_RESELLER_ROLE_IDS.split(',').map(id => id.trim()) 
            : [];
            
        // Setup Admin Role
        const adminRoleId = process.env.DISCORD_ADMIN_ROLE_ID;

        const isReseller = memberData.roles && memberData.roles.some(role => allowedRoleIds.includes(role));
        const isAdmin = memberData.roles && memberData.roles.includes(adminRoleId);

        if (!isReseller && !isAdmin) {
            res.writeHead(302, { Location: '/?error=NotAReseller' });
            return res.end();
        }

        // Mint JWT containing admin/reseller status
        const payload = {
            sub: userData.id,
            username: userData.username,
            avatar: userData.avatar,
            nickname: memberData.nick || userData.global_name || userData.username,
            isReseller: isReseller,
            isAdmin: isAdmin,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7) 
        };

        const token = signJWT(payload, process.env.JWT_SECRET);

        res.setHeader('Set-Cookie', `omnis_reseller=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}`);
        
        // Redirect logic based on Role
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
