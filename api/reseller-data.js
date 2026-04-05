// api/reseller-data.js
// Fetches keys from ALL brands in Firebase for the reseller dashboard

const crypto = require('crypto');

// Maps duration_days to plan labels and retail prices
const DURATION_MAP = {
  1: { label: '1 Day', price: 3 },
  3: { label: '3 Days', price: 5 },
  7: { label: '1 Week', price: 7 },
  14: { label: '14 Days', price: 10 },
  30: { label: '1 Month', price: 12 },
  90: { label: '90 Days', price: 20 },
  365: { label: '1 Year', price: 25 },
  99999: { label: 'Lifetime', price: 30 },
};
const CUT = 0.30; // 30% goes to admin

const BRANDS = {
  voltaris:         { name: 'Voltaris',           prefix: 'VOLTARIS-',  path: '/keys/voltaris/',          color: '#FF3344' },
  projectservices:  { name: 'Project Services',   prefix: 'PS-',        path: '/keys/projectservices/',   color: '#1E50C8' },
  corvus:           { name: 'Corvus',             prefix: 'CORVUS-',    path: '/keys/corvus/',            color: '#7832C8' },
  omnis:            { name: 'Omnis',              prefix: 'OMNIS-',     path: '/keys/omnis/',             color: '#A040FF' },
};

function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', process.env.JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

function getCookie(req, name) {
  const match = (req.headers.cookie || '').match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function fbGet(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Firebase GET ${path} failed: ${r.status}`);
  return r.json();
}

function getDurationInfo(days) {
  const d = parseInt(days) || 0;
  return DURATION_MAP[d] || { label: d + ' Days', price: 5 };
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    // Determine which brands this reseller can access
    const userBrands = payload.isAdmin ? Object.keys(BRANDS) : (payload.brands || []);

    // Fetch keys only from accessible brands
    const allKeys = [];
    for (const [brandId, brand] of Object.entries(BRANDS)) {
      if (!userBrands.includes(brandId)) continue;
      const data = await fbGet(brand.path);
      if (data && typeof data === 'object') {
        Object.entries(data).forEach(([keyId, k]) => {
          if (k && typeof k === 'object') {
            const info = getDurationInfo(k.duration_days);
            allKeys.push({
              id: brandId + '/' + keyId,
              key: keyId,
              brand: brand.name,
              brandId: brandId,
              brandColor: brand.color,
              durationDays: k.duration_days || 0,
              planLabel: info.label,
              price: info.price,
              owedAmount: (k.hwid && k.hwid.length > 0) ? (info.price * CUT).toFixed(2) : '0.00',
              active: k.active !== false,
              hwid: k.hwid || '',
              activated: !!(k.hwid && k.hwid.length > 0),
              expiresAt: k.expires_at || 0,
              createdAt: k.created_at || 0,
              excluded: k.excluded || false,
              createdBy: k.created_by || '',
              createdByName: k.created_by_name || '',
            });
          }
        });
      }
    }

    // Resellers only see their own keys; admins see all
    const myKeys = payload.isAdmin
      ? allKeys
      : allKeys.filter(k => k.createdBy === payload.sub);

    // Sort by creation date (newest first)
    myKeys.sort((a, b) => b.createdAt - a.createdAt);

    // Fetch reseller profile + payments
    const profile = await fbGet(`/resellers/${payload.sub}`) || {};
    const allPayments = await fbGet('/payments') || {};
    const myPayments = [];
    Object.entries(allPayments).forEach(([id, p]) => {
      if (p && p.resellerId === payload.sub) myPayments.push({ id, ...p });
    });

    // Stats — only activated keys (have HWID) and not excluded count
    const now = Math.floor(Date.now() / 1000);
    const activatedKeys = myKeys.filter(k => k.activated && !k.excluded);

    const totalOwed = activatedKeys.reduce((sum, k) => sum + (k.price * CUT), 0);
    const totalPaid = myPayments.filter(p => p.confirmedByAdmin).reduce((s, p) => s + (parseFloat(p.amount) || 0), 0);

    return res.status(200).json({
      reseller: {
        id: payload.sub,
        username: payload.username,
        avatar: payload.avatar,
        nickname: payload.nickname,
      },
      stats: {
        totalKeys: myKeys.length,
        activatedKeys: activatedKeys.length,
        unusedKeys: myKeys.filter(k => !k.activated).length,
        salesToday: activatedKeys.filter(k => (now - k.createdAt) < 86400).length,
        totalOwed: totalOwed.toFixed(2),
        totalPaid: totalPaid.toFixed(2),
        balance: Math.max(0, totalOwed - totalPaid).toFixed(2),
        suspended: profile.suspended || false,
        paymentDeadline: profile.paymentDeadline || null,
      },
      keys: myKeys.slice(0, 200),
      payments: myPayments.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 50),
      paymentMethods: {
        paypal: 'paypal.me/kayazskrdens',
        bitcoin: 'bc1qx68swgpyapa03tka8q6yaf9w03g6tshfrjqskc',
        litecoin: 'LbBLPFSzeXYYXxf7YD2B8SqcxTAc9Rk1u1',
      },
      brands: BRANDS,
      userBrands: userBrands,
    });

  } catch (error) {
    console.error('Reseller Data Error:', error);
    return res.status(500).json({ error: 'Failed to fetch data', detail: error.message });
  }
};
