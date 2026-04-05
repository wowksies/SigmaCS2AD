// api/reseller-data.js
// Fetches reseller-specific data from Firebase Realtime Database

const crypto = require('crypto');

const PRICES = { '3days': 5, '1week': 7, '1month': 12, 'lifetime': 30 };
const CUT = 0.30; // 30% goes to admin

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

  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const resellerId = payload.sub;

  try {
    // Fetch this reseller's keys
    const allKeys = await fbGet('/keys') || {};
    const myKeys = [];
    Object.entries(allKeys).forEach(([id, k]) => {
      if (k.resellerId === resellerId) {
        myKeys.push({ id, ...k });
      }
    });

    // Fetch reseller profile
    const profile = await fbGet(`/resellers/${resellerId}`) || {};

    // Fetch payments
    const allPayments = await fbGet('/payments') || {};
    const myPayments = [];
    Object.entries(allPayments).forEach(([id, p]) => {
      if (p.resellerId === resellerId) {
        myPayments.push({ id, ...p });
      }
    });

    // Calculate stats
    const now = Date.now();
    const dayMs = 86400000;
    const weekMs = dayMs * 7;

    // Only activated keys (have HWID) and not excluded count toward payment
    const activatedKeys = myKeys.filter(k => k.hwid && !k.excluded);
    const totalOwed = activatedKeys.reduce((sum, k) => {
      const price = PRICES[k.plan] || 0;
      return sum + (price * CUT);
    }, 0);

    const totalPaid = myPayments
      .filter(p => p.confirmedByAdmin)
      .reduce((sum, p) => sum + (parseFloat(p.amount) || 0), 0);

    const balance = Math.max(0, totalOwed - totalPaid);

    const stats = {
      totalKeys: myKeys.length,
      activatedKeys: activatedKeys.length,
      unusedKeys: myKeys.filter(k => !k.hwid).length,
      salesToday: myKeys.filter(k => k.hwid && (now - (k.activatedAt || k.createdAt)) < dayMs).length,
      salesThisWeek: myKeys.filter(k => k.hwid && (now - (k.activatedAt || k.createdAt)) < weekMs).length,
      totalOwed: totalOwed.toFixed(2),
      totalPaid: totalPaid.toFixed(2),
      balance: balance.toFixed(2),
      suspended: profile.suspended || false,
      paymentDeadline: profile.paymentDeadline || null,
    };

    // Map keys for display
    const mappedKeys = myKeys.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).map(k => ({
      id: k.id,
      key: k.key,
      plan: k.plan,
      planLabel: { '3days': '3 Days', '1week': '1 Week', '1month': '1 Month', 'lifetime': 'Lifetime' }[k.plan] || k.plan,
      price: PRICES[k.plan] || 0,
      owedAmount: (k.hwid && !k.excluded) ? ((PRICES[k.plan] || 0) * CUT).toFixed(2) : '0.00',
      note: k.note || '',
      createdAt: k.createdAt,
      active: k.active !== false,
      hwid: k.hwid || null,
      activated: !!k.hwid,
      excluded: k.excluded || false,
      activatedAt: k.activatedAt || null,
    }));

    return res.status(200).json({
      reseller: {
        id: payload.sub,
        username: payload.username,
        avatar: payload.avatar,
        nickname: payload.nickname,
      },
      stats,
      keys: mappedKeys.slice(0, 100),
      payments: myPayments.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 50),
      paymentMethods: {
        paypal: 'paypal.me/kayazskrdens',
        bitcoin: 'bc1qx68swgpyapa03tka8q6yaf9w03g6tshfrjqskc',
        litecoin: 'LbBLPFSzeXYYXxf7YD2B8SqcxTAc9Rk1u1',
      },
    });

  } catch (error) {
    console.error('Reseller Data Error:', error);
    return res.status(500).json({ error: 'Failed to fetch data', detail: error.message });
  }
};
