// api/reseller-data.js — uses DB-based role lookup (not JWT claims)
const { resolveUser, fbGet } = require('./auth-helper');

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
const CUT = 0.30;

const BRANDS = {
  voltaris:        { name: 'Voltaris',         prefix: 'VOLTARIS-', color: '#FF3344' },
  projectservices: { name: 'Project Services', prefix: 'PS-',       color: '#1E50C8' },
  corvus:          { name: 'Corvus',           prefix: 'CORVUS-',   color: '#7832C8' },
  omnis:           { name: 'Omnis',            prefix: 'OMNIS-',    color: '#A040FF' },
};

// Internal paths — NEVER exposed to frontend
const BRAND_PATHS = {
  voltaris: '/keys/voltaris/',
  projectservices: '/keys/projectservices/',
  corvus: '/keys/corvus/',
  omnis: '/keys/omnis/',
};

function getDurationInfo(days) {
  const d = parseInt(days) || 0;
  return DURATION_MAP[d] || { label: d + ' Days', price: 5 };
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // Resolve user from JWT + Firebase (roles from DB, not JWT)
  const user = await resolveUser(req);
  if (!user || (!user.isReseller && !user.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (user.suspended) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  try {
    const userBrands = user.isAdmin ? Object.keys(BRANDS) : (user.brands || []);

    const allKeys = [];
    for (const [brandId, brand] of Object.entries(BRANDS)) {
      if (!userBrands.includes(brandId)) continue;
      const data = await fbGet(BRAND_PATHS[brandId]);
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

    // Resellers see: their own keys + legacy keys (no created_by). Admins see all.
    const myKeys = user.isAdmin ? allKeys : allKeys.filter(k => k.createdBy === user.id || !k.createdBy);
    myKeys.sort((a, b) => b.createdAt - a.createdAt);

    const profile = await fbGet(`/resellers/${user.id}`) || {};
    const allPayments = await fbGet('/payments') || {};
    const myPayments = [];
    Object.entries(allPayments).forEach(([id, p]) => {
      if (p && p.resellerId === user.id) myPayments.push({ id, ...p });
    });

    const now = Math.floor(Date.now() / 1000);
    const activatedKeys = myKeys.filter(k => k.activated && !k.excluded);
    const totalOwed = activatedKeys.reduce((sum, k) => sum + (k.price * CUT), 0);
    const totalPaid = myPayments.filter(p => p.confirmedByAdmin).reduce((s, p) => s + (parseFloat(p.amount) || 0), 0);

    // Response — NO internal paths exposed
    return res.status(200).json({
      reseller: {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
        nickname: user.nickname,
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
      userBrands: userBrands,
    });

  } catch (error) {
    console.error('Reseller Data Error:', error);
    return res.status(500).json({ error: 'Failed to fetch data' });
  }
};
