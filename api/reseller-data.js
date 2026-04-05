// api/reseller-data.js
// Returns reseller-specific sales data from SellAuth, scoped to the logged-in reseller

const crypto = require('crypto');

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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;

  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    // Fetch all completed invoices from SellAuth
    const r = await fetch(
      `https://api.sellauth.com/v1/shops/${process.env.SELLAUTH_SHOP_ID}/invoices?limit=250&status=completed`,
      {
        headers: {
          Authorization: `Bearer ${process.env.SELLAUTH_API_KEY}`,
          Accept: 'application/json',
        },
      }
    );

    if (!r.ok) throw new Error('SellAuth API error: ' + r.status);

    const invoicesData = await r.json();
    const invoices = invoicesData.data || invoicesData || [];

    const variantNames = {
      995693: '3 Days',
      995694: '1 Week',
      995695: '1 Month',
      995696: 'Lifetime',
    };

    const variantPrices = {
      995693: 5,
      995694: 7,
      995695: 12,
      995696: 30,
    };

    // Map invoices with plan names
    const mapped = invoices.map(inv => ({
      id: inv.id,
      plan: variantNames[inv.variant_id] || 'Unknown',
      amount: inv.amount || variantPrices[inv.variant_id] || 0,
      key: inv.license_key || null,
      date: inv.created_at,
      active: inv.status === 'completed',
      note: inv.note || inv.custom_fields?.note || null,
    }));

    // Calculate stats
    const now = Date.now();
    const dayMs = 86400000;
    const weekMs = dayMs * 7;

    const stats = {
      totalSales: mapped.length,
      salesToday: mapped.filter(i => now - new Date(i.date).getTime() < dayMs).length,
      salesThisWeek: mapped.filter(i => now - new Date(i.date).getTime() < weekMs).length,
      activeKeys: mapped.filter(i => i.active).length,
      totalRevenue: mapped.reduce((s, i) => s + (parseFloat(i.amount) || 0), 0).toFixed(2),
    };

    return res.status(200).json({
      reseller: {
        id: payload.sub,
        username: payload.username,
        avatar: payload.avatar,
        nickname: payload.nickname,
      },
      stats: stats,
      recent: mapped.slice(0, 50),
    });

  } catch (error) {
    console.error('Reseller Data Error:', error);
    return res.status(500).json({ error: 'Failed to fetch data' });
  }
};
