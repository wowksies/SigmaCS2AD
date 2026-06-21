
const crypto = require('crypto');
const { fetchSellAuthJson, invoiceMatchesConfiguredProduct } = require('../lib/sellauth-helper');

const SELLAUTH_SHOP_ID = process.env.SELLAUTH_SHOP_ID;
const COOKIE_SECRET    = process.env.COOKIE_SECRET;
const FB_URL           = process.env.DATABASE_URL;
const FB_KEY           = process.env.DATABASE_KEY;
const SECURITY_WEBHOOK_URL = process.env.SECURITY_WEBHOOK_URL;
const WORK_INK_URL     = process.env.WORK_INK_URL || 'https://work.ink/2BHM/omnis-free';

const FREE_KEY_DURATION_DAYS = 1;            // 24h hard kill switch
const FREE_KEY_DURATION_SEC  = FREE_KEY_DURATION_DAYS * 86400;
const REQUIRE_IP_MATCH       = true;
const RATE_LIMIT_WINDOW      = 60 * 60;      // 1h
const RATE_LIMIT_MAX_PER_IP  = 10;

function sign(orderId) {
    return crypto.createHmac('sha256', COOKIE_SECRET).update(orderId).digest('hex');
}
async function handleSellAuthVerify(req, res) {
    const { order_id } = req.query;
    if (!order_id) return res.redirect(302, '/');
    try {
        const invoice = await fetchSellAuthJson(`/shops/${SELLAUTH_SHOP_ID}/invoices/${order_id}`);
        const isPaid    = invoice?.status === 'completed';
        const isProduct = invoiceMatchesConfiguredProduct(invoice);
        if (!isPaid || !isProduct) return res.redirect(302, '/?error=invalid');
        const sig     = sign(order_id);
        const payload = Buffer.from(JSON.stringify({ order_id, sig })).toString('base64');
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toUTCString();
        res.setHeader('Set-Cookie',
            `omnis_access=${payload}; Path=/; Expires=${expires}; HttpOnly; Secure; SameSite=Lax`);
        return res.redirect(302, '/thankyou.html');
    } catch (err) {
        console.error('Verify error:', err);
        return res.redirect(302, '/?error=server');
    }
}

async function fbPut(path, data) {
    const r = await fetch(`${FB_URL}${path}.json?auth=${FB_KEY}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!r.ok) throw new Error(`fb put ${r.status}`);
    return r.json();
}
async function fbPatch(path, data) {
    const r = await fetch(`${FB_URL}${path}.json?auth=${FB_KEY}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!r.ok) throw new Error(`fb patch ${r.status}`);
}
async function fbGet(path) {
    const r = await fetch(`${FB_URL}${path}.json?auth=${FB_KEY}`);
    if (!r.ok) return null;
    return r.json();
}

function realClientIp(req) {
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
    return (ip + '').split(',')[0].trim();
}
function generateFreeKey() {
    const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    const seg = () => Array.from(crypto.randomBytes(4)).map(b => chars[b % chars.length]).join('');
    return `FREE-${seg()}-${seg()}-${seg()}`;
}
async function checkIpLimit(ip) {
    const bucket = Math.floor(Date.now() / 1000 / RATE_LIMIT_WINDOW);
    const safeIp = (ip || 'unknown').replace(/[.:/]/g, '_');
    const path = `/rate_limits/free_key_init/${safeIp}`;
    const entry = await fbGet(path);
    let count = 1;
    if (entry && entry.bucket === bucket && typeof entry.count === 'number') count = entry.count + 1;
    if (count > RATE_LIMIT_MAX_PER_IP) return false;
    try { await fbPut(path, { bucket, count, updatedAt: Math.floor(Date.now() / 1000) }); } catch (_) {}
    return true;
}

async function actionFreeInit(req, res) {
    const ip = realClientIp(req);
    if (!(await checkIpLimit(ip))) return res.status(429).json({ error: 'too many requests, try later' });
    return res.status(200).json({ workInkUrl: WORK_INK_URL });
}

async function actionFreeClaim(req, res) {
    const { token } = req.body || {};
    if (!token || typeof token !== 'string') return res.status(400).json({ error: 'missing token' });

    const ip = realClientIp(req);
    const tokenPath = `/free_key_tokens/${encodeURIComponent(token)}`;
    const prior = await fbGet(tokenPath);
    if (prior && prior.key) {
        return res.status(200).json({ key: prior.key, expiresAt: prior.expiresAt, replay: true });
    }

    let wi = null;
    try {
        const r = await fetch(`https://work.ink/_api/v2/token/isValid/${encodeURIComponent(token)}?deleteToken=1`);
        wi = await r.json();
    } catch (e) {
        return res.status(502).json({ error: 'token validation failed' });
    }
    if (!wi || !wi.valid) return res.status(403).json({ error: 'invalid token' });

    if (REQUIRE_IP_MATCH && wi.info && wi.info.byIp) {
        const reported = wi.info.byIp;
        if (!/^[a-f0-9]{64}$/.test(reported) && reported !== ip) {
            return res.status(403).json({ error: 'ip mismatch' });
        }
    }

    const keyId = generateFreeKey();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + FREE_KEY_DURATION_SEC;

    await fbPut(`/keys/omnis_free/${keyId}`, {
        hwid: '',                       // bound on first validate
        expires_at: expiresAt,          // hard 24h kill
        duration_days: FREE_KEY_DURATION_DAYS,
        active: true,
        created_at: now,
        created_by: 'work.ink',
        created_by_name: 'work.ink free',
        source: 'free',
        ip,
        token,
    });
    await fbPut(tokenPath, { key: keyId, expiresAt, createdAt: now, ip });

    try {
        if (SECURITY_WEBHOOK_URL) {
            await fetch(SECURITY_WEBHOOK_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    embeds: [{
                        title: 'Omnis Free key claimed',
                        color: 0xA855F7,
                        fields: [
                            { name: 'Key',     value: '`' + keyId + '`',  inline: false },
                            { name: 'IP',      value: '`' + ip + '`',      inline: true },
                            { name: 'Expires', value: `<t:${expiresAt}:R>`, inline: true },
                        ],
                        timestamp: new Date().toISOString(),
                    }],
                }),
            });
        }
    } catch (_) {}

    return res.status(200).json({ key: keyId, expiresAt });
}

async function actionFreeValidate(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const key  = (req.query.key  || '').toUpperCase().trim();
    const hwid = (req.query.hwid || '').trim();

    if (!/^FREE-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
        return res.status(400).json({ valid: false, error: 'bad format' });
    }

    const path = `/keys/omnis_free/${key}`;
    const k = await fbGet(path);
    if (!k) return res.status(404).json({ valid: false, error: 'unknown' });
    if (!k.active) return res.status(403).json({ valid: false, error: 'inactive' });

    const now = Math.floor(Date.now() / 1000);
    if (k.expires_at && k.expires_at > 0 && now > k.expires_at) {
        try { await fbPatch(path, { active: false, expired_at: now }); } catch (_) {}
        return res.status(403).json({ valid: false, error: 'expired' });
    }

    if (hwid) {
        if (!k.hwid) {
            try { await fbPatch(path, { hwid, first_used_at: now }); } catch (_) {}
        } else if (k.hwid !== hwid) {
            return res.status(403).json({ valid: false, error: 'hwid mismatch' });
        }
    }

    return res.status(200).json({
        valid: true,
        expiresAt: k.expires_at,
        durationDays: k.duration_days,
    });
}

module.exports = async function handler(req, res) {
    const action = (req.query.action || '').toLowerCase();

    if (action === 'free-init' || action === 'free-claim' || action === 'free-validate') {
        res.setHeader('Content-Type', 'application/json');
        try {
            if (action === 'free-init') {
                if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
                return await actionFreeInit(req, res);
            }
            if (action === 'free-claim') {
                if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
                return await actionFreeClaim(req, res);
            }
            if (action === 'free-validate') {
                if (req.method !== 'GET' && req.method !== 'POST') return res.status(405).json({ error: 'method' });
                return await actionFreeValidate(req, res);
            }
        } catch (e) {
            console.error('[verify free-key]', e);
            return res.status(500).json({ error: 'internal' });
        }
    }

    return handleSellAuthVerify(req, res);
};
