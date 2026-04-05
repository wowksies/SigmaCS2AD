// api/generate-key.js
// Generates real license keys via SellAuth coupon/invoice creation

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

// SellAuth product ID for Omnis CS2
const PRODUCT_ID = '634549';

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;

  if (!payload || (!payload.isReseller && !payload.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Parse body (Vercel auto-parses JSON bodies)
  const { variantId, quantity, note } = req.body || {};

  if (!variantId) {
    return res.status(400).json({ error: 'Missing variantId' });
  }

  const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 10);

  const validVariants = ['995693', '995694', '995695', '995696'];
  if (!validVariants.includes(String(variantId))) {
    return res.status(400).json({ error: 'Invalid variant' });
  }

  try {
    const keys = [];

    for (let i = 0; i < qty; i++) {
      // Create a free invoice via SellAuth to generate a license key
      const r = await fetch(
        `https://api.sellauth.com/v1/shops/${process.env.SELLAUTH_SHOP_ID}/products/${PRODUCT_ID}/variants/${variantId}/invoices`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.SELLAUTH_API_KEY}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            customer_email: `reseller-${payload.sub}@omnis.internal`,
            note: note ? `[${payload.nickname || payload.username}] ${note}` : `[${payload.nickname || payload.username}] Reseller generated`,
            amount: 0, // Free — reseller-generated key
          }),
        }
      );

      if (!r.ok) {
        const errText = await r.text();
        console.error('SellAuth key gen error:', r.status, errText);

        if (keys.length > 0) {
          // Return partial success
          return res.status(200).json({
            keys: keys,
            warning: `Only ${keys.length} of ${qty} keys generated. SellAuth error on key ${i + 1}.`,
          });
        }

        return res.status(500).json({
          error: 'SellAuth key generation failed',
          detail: `Status ${r.status}`,
        });
      }

      const invoice = await r.json();
      const key = invoice.license_key || invoice.serials?.[0] || invoice.key || null;

      if (key) {
        keys.push({ key: key, invoice_id: invoice.id });
      } else {
        // If no key in response, try fetching the invoice to get the key
        const fetchRes = await fetch(
          `https://api.sellauth.com/v1/shops/${process.env.SELLAUTH_SHOP_ID}/invoices/${invoice.id}`,
          {
            headers: {
              Authorization: `Bearer ${process.env.SELLAUTH_API_KEY}`,
              Accept: 'application/json',
            },
          }
        );
        if (fetchRes.ok) {
          const fetchedInv = await fetchRes.json();
          keys.push({
            key: fetchedInv.license_key || fetchedInv.serials?.[0] || `INV-${invoice.id}`,
            invoice_id: invoice.id,
          });
        } else {
          keys.push({ key: `INV-${invoice.id}`, invoice_id: invoice.id });
        }
      }
    }

    return res.status(200).json({ keys: keys });

  } catch (error) {
    console.error('Key Generation Error:', error);
    return res.status(500).json({ error: 'Failed to generate key', detail: error.message });
  }
};
