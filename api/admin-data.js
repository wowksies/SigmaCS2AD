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
  
  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  
  // MUST have isAdmin flag in token
  if (!payload || !payload.isAdmin) {
    return res.status(401).json({ error: 'unauthorized, admin only' });
  }

  try {
    const r = await fetch(`https://api.sellauth.com/v1/shops/${process.env.SELLAUTH_SHOP_ID}/invoices?limit=250&status=completed`, {
      headers: { Authorization: `Bearer ${process.env.SELLAUTH_API_KEY}`, Accept: 'application/json' },
    });
    
    if (!r.ok) throw new Error("Sellauth fetch failed");
    
    const invoicesData = await r.json();
    const invoices = invoicesData.data || invoicesData || [];

    const variantNames = { 995693: '3 Days', 995694: '1 Week', 995695: '1 Month', 995696: 'Lifetime' };
    
    const now = Date.now();
    const dayMs = 86400000;
    
    const mappedInvoices = invoices.map(inv => ({
        ...inv,
        plan: variantNames[inv.variant_id] || 'Unknown Plan'
    }));

    return res.json({
      stats: {
        totalSales: mappedInvoices.length,
        totalRevenue: mappedInvoices.reduce((s, i) => s + (parseFloat(i.amount) || 0), 0).toFixed(2),
        salesToday: mappedInvoices.filter(i => now - new Date(i.created_at) < dayMs).length,
        activeKeys: mappedInvoices.length // Approximate based on completion status
      },
      invoices: mappedInvoices.slice(0, 100) // Send 100 most recent
    });

  } catch (e) {
    return res.status(500).json({ error: 'Failed to fetch admin data' });
  }
};
