// api/admin-data.js
// Returns all resellers, keys, and payment data for admin panel

const crypto = require('crypto');

const PRICES = { '3days': 5, '1week': 7, '1month': 12, 'lifetime': 30 };
const CUT = 0.30;

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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || !payload.isAdmin) {
    return res.status(401).json({ error: 'Admin only' });
  }

  try {
    const [allKeys, allResellers, allPayments] = await Promise.all([
      fbGet('/keys'),
      fbGet('/resellers'),
      fbGet('/payments'),
    ]);

    const keysArr = allKeys ? Object.entries(allKeys).map(([id, k]) => ({ id, ...k })) : [];
    const resellersArr = allResellers ? Object.entries(allResellers).map(([id, r]) => ({ id, ...r })) : [];
    const paymentsArr = allPayments ? Object.entries(allPayments).map(([id, p]) => ({ id, ...p })) : [];

    const now = Date.now();
    const dayMs = 86400000;

    // Build reseller stats
    const resellerStats = resellersArr.map(r => {
      const rKeys = keysArr.filter(k => k.resellerId === r.id);
      const activatedKeys = rKeys.filter(k => k.hwid && !k.excluded);
      const totalOwed = activatedKeys.reduce((sum, k) => sum + ((PRICES[k.plan] || 0) * CUT), 0);
      const rPayments = paymentsArr.filter(p => p.resellerId === r.id);
      const totalPaid = rPayments.filter(p => p.confirmedByAdmin).reduce((sum, p) => sum + (parseFloat(p.amount) || 0), 0);
      const pendingPayments = rPayments.filter(p => !p.confirmedByAdmin);

      return {
        id: r.id,
        username: r.username || 'Unknown',
        avatar: r.avatar || null,
        totalKeys: rKeys.length,
        activatedKeys: activatedKeys.length,
        unusedKeys: rKeys.filter(k => !k.hwid).length,
        totalOwed: totalOwed.toFixed(2),
        totalPaid: totalPaid.toFixed(2),
        balance: Math.max(0, totalOwed - totalPaid).toFixed(2),
        suspended: r.suspended || false,
        paymentDeadline: r.paymentDeadline || null,
        pendingPayments: pendingPayments.length,
        createdAt: r.createdAt,
      };
    });

    // Global stats
    const totalActivated = keysArr.filter(k => k.hwid && !k.excluded).length;
    const totalRevenue = keysArr.filter(k => k.hwid && !k.excluded).reduce((sum, k) => sum + ((PRICES[k.plan] || 0) * CUT), 0);
    const totalPaidGlobal = paymentsArr.filter(p => p.confirmedByAdmin).reduce((sum, p) => sum + (parseFloat(p.amount) || 0), 0);

    // Map keys for display
    const planLabels = { '3days': '3 Days', '1week': '1 Week', '1month': '1 Month', 'lifetime': 'Lifetime' };
    const mappedKeys = keysArr.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).map(k => ({
      id: k.id,
      key: k.key,
      plan: k.plan,
      planLabel: planLabels[k.plan] || k.plan,
      price: PRICES[k.plan] || 0,
      owedAmount: (k.hwid && !k.excluded) ? ((PRICES[k.plan] || 0) * CUT).toFixed(2) : '0.00',
      resellerId: k.resellerId,
      resellerName: k.resellerName || 'Unknown',
      note: k.note || '',
      createdAt: k.createdAt,
      active: k.active !== false,
      hwid: k.hwid || null,
      activated: !!k.hwid,
      excluded: k.excluded || false,
      activatedAt: k.activatedAt || null,
    }));

    // Pending payment claims
    const pendingPayments = paymentsArr
      .filter(p => !p.confirmedByAdmin)
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
      .map(p => ({
        id: p.id,
        resellerId: p.resellerId,
        resellerName: resellersArr.find(r => r.id === p.resellerId)?.username || 'Unknown',
        amount: p.amount,
        method: p.method,
        note: p.note || '',
        createdAt: p.createdAt,
      }));

    return res.json({
      stats: {
        totalKeys: keysArr.length,
        totalActivated,
        totalRevenue: totalRevenue.toFixed(2),
        totalPaid: totalPaidGlobal.toFixed(2),
        outstandingBalance: Math.max(0, totalRevenue - totalPaidGlobal).toFixed(2),
        totalResellers: resellersArr.length,
        activationsToday: keysArr.filter(k => k.hwid && (now - (k.activatedAt || k.createdAt)) < dayMs).length,
      },
      resellers: resellerStats,
      keys: mappedKeys.slice(0, 200),
      pendingPayments,
    });

  } catch (e) {
    console.error('Admin Data Error:', e);
    return res.status(500).json({ error: 'Failed to fetch admin data', detail: e.message });
  }
};
