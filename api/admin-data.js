// api/admin-data.js
// Admin panel — reads ALL brands from Firebase, tracks payments

const crypto = require('crypto');

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
  voltaris:         { name: 'Voltaris',           prefix: 'VOLTARIS-',  path: '/keys/voltaris/',          color: '#FF3344', emoji: '🔴' },
  projectservices:  { name: 'Project Services',   prefix: 'PS-',        path: '/keys/projectservices/',   color: '#1E50C8', emoji: '🔵' },
  corvus:           { name: 'Corvus',             prefix: 'CORVUS-',    path: '/keys/corvus/',            color: '#7832C8', emoji: '🟣' },
  omnis:            { name: 'Omnis',              prefix: 'OMNIS-',     path: '/keys/omnis/',             color: '#A040FF', emoji: '🟪' },
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

function getKeyStatus(k) {
  if (!k.active) return 'Disabled';
  if (k.expiresAt && k.expiresAt > 0 && Math.floor(Date.now() / 1000) > k.expiresAt) return 'Expired';
  return 'Active';
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || !payload.isAdmin) {
    return res.status(401).json({ error: 'Admin only' });
  }

  try {
    // Fetch keys from ALL brands
    const allKeys = [];
    const brandStats = {};

    for (const [brandId, brand] of Object.entries(BRANDS)) {
      const data = await fbGet(brand.path);
      let brandTotal = 0, brandActive = 0, brandBound = 0;

      if (data && typeof data === 'object') {
        Object.entries(data).forEach(([keyId, k]) => {
          if (k && typeof k === 'object') {
            const info = getDurationInfo(k.duration_days);
            const activated = !!(k.hwid && k.hwid.length > 0);
            allKeys.push({
              id: brandId + '/' + keyId,
              key: keyId,
              brand: brand.name,
              brandId: brandId,
              brandColor: brand.color,
              brandEmoji: brand.emoji,
              durationDays: k.duration_days || 0,
              planLabel: info.label,
              price: info.price,
              owedAmount: (activated && !k.excluded) ? (info.price * CUT).toFixed(2) : '0.00',
              active: k.active !== false,
              hwid: k.hwid || '',
              activated: activated,
              expiresAt: k.expires_at || 0,
              createdAt: k.created_at || 0,
              excluded: k.excluded || false,
              status: getKeyStatus({ active: k.active !== false, expiresAt: k.expires_at }),
            });
            brandTotal++;
            if (k.active !== false && (!k.expires_at || Math.floor(Date.now() / 1000) <= k.expires_at)) brandActive++;
            if (k.hwid && k.hwid.length > 0) brandBound++;
          }
        });
      }

      brandStats[brandId] = { name: brand.name, emoji: brand.emoji, color: brand.color, total: brandTotal, active: brandActive, bound: brandBound };
    }

    allKeys.sort((a, b) => b.createdAt - a.createdAt);

    // Fetch resellers + payments
    const [allResellers, allPayments] = await Promise.all([
      fbGet('/resellers'),
      fbGet('/payments'),
    ]);

    const resellersArr = allResellers ? Object.entries(allResellers).map(([id, r]) => ({ id, ...r })) : [];
    const paymentsArr = allPayments ? Object.entries(allPayments).map(([id, p]) => ({ id, ...p })) : [];

    // Activated keys (have HWID, not excluded) for revenue
    const activatedKeys = allKeys.filter(k => k.activated && !k.excluded);
    const totalRevenue = activatedKeys.reduce((sum, k) => sum + (k.price * CUT), 0);
    const totalPaid = paymentsArr.filter(p => p.confirmedByAdmin).reduce((s, p) => s + (parseFloat(p.amount) || 0), 0);

    // Reseller stats
    const resellerStats = resellersArr.map(r => {
      const rPayments = paymentsArr.filter(p => p.resellerId === r.id);
      const rPaid = rPayments.filter(p => p.confirmedByAdmin).reduce((s, p) => s + (parseFloat(p.amount) || 0), 0);
      const pendingPayments = rPayments.filter(p => !p.confirmedByAdmin);
      return {
        id: r.id,
        username: r.username || 'Unknown',
        avatar: r.avatar || null,
        totalOwed: '0.00',  // We don't track per-reseller keys yet in the old system
        totalPaid: rPaid.toFixed(2),
        balance: Math.max(0, -rPaid).toFixed(2),
        suspended: r.suspended || false,
        paymentDeadline: r.paymentDeadline || null,
        pendingPayments: pendingPayments.length,
        createdAt: r.createdAt,
      };
    });

    // Pending payment claims
    const pendingPayments = paymentsArr
      .filter(p => !p.confirmedByAdmin)
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
      .map(p => ({
        id: p.id,
        resellerId: p.resellerId,
        resellerName: p.resellerName || resellersArr.find(r => r.id === p.resellerId)?.username || 'Unknown',
        amount: p.amount,
        method: p.method,
        note: p.note || '',
        createdAt: p.createdAt,
      }));

    // Protection logs (recent)
    let recentLogs = [];
    try {
      for (const [brandId, brand] of Object.entries(BRANDS)) {
        const logData = await fbGet('/protection_logs/' + brandId);
        if (logData && typeof logData === 'object') {
          Object.entries(logData).forEach(([eventId, entry]) => {
            if (entry && typeof entry === 'object' && (entry.created_at || entry.event)) {
              recentLogs.push({ ...entry, brand: brand.name, brandEmoji: brand.emoji });
            }
          });
        }
      }
    } catch (e) { /* logs may not exist */ }
    recentLogs.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    recentLogs = recentLogs.slice(0, 20);

    return res.json({
      stats: {
        totalKeys: allKeys.length,
        totalActivated: activatedKeys.length,
        totalBound: allKeys.filter(k => k.activated).length,
        totalActive: allKeys.filter(k => k.active).length,
        totalRevenue: totalRevenue.toFixed(2),
        totalPaid: totalPaid.toFixed(2),
        outstandingBalance: Math.max(0, totalRevenue - totalPaid).toFixed(2),
        totalResellers: resellersArr.length,
      },
      brandStats,
      resellers: resellerStats,
      keys: allKeys.slice(0, 300),
      pendingPayments,
      recentLogs,
    });

  } catch (e) {
    console.error('Admin Data Error:', e);
    return res.status(500).json({ error: 'Failed to fetch admin data', detail: e.message });
  }
};
