const net = require('net');
const { validateOrigin, validateUserAgent } = require('./auth-helper');

const SELLAUTH_API_KEY = process.env.SELLAUTH_API_KEY;
const SELLAUTH_SHOP_ID = parseInt(process.env.SELLAUTH_SHOP_ID || '219036', 10);
const SELLAUTH_PRODUCT_ID = parseInt(process.env.SELLAUTH_PRODUCT_ID || '634549', 10);
const ALLOWED_VARIANTS = new Set([995693, 995694, 995695, 995696]);

const checkoutRateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 12;

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (net.isIP(forwarded)) return forwarded;

  const realIp = String(req.headers['x-real-ip'] || '').trim();
  if (net.isIP(realIp)) return realIp;

  return null;
}

function getRateLimitKey(req) {
  return getClientIp(req) || String(req.headers['user-agent'] || 'unknown');
}

function checkRateLimit(key) {
  const now = Date.now();
  const entry = checkoutRateLimit.get(key);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    checkoutRateLimit.set(key, { count: 1, windowStart: now });
    return true;
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }

  entry.count += 1;
  return true;
}

async function parseJsonBody(req) {
  if (req.body && typeof req.body === 'object') {
    return req.body;
  }

  return await new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 10000) {
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!validateOrigin(req)) {
    return res.status(403).json({ error: 'Invalid request origin' });
  }

  if (!validateUserAgent(req)) {
    return res.status(403).json({ error: 'Unsupported client' });
  }

  if (!checkRateLimit(getRateLimitKey(req))) {
    return res.status(429).json({ error: 'Too many checkout attempts. Please wait a moment.' });
  }

  if (!SELLAUTH_API_KEY || !Number.isFinite(SELLAUTH_SHOP_ID) || !Number.isFinite(SELLAUTH_PRODUCT_ID)) {
    console.error('SellAuth checkout is not configured correctly.');
    return res.status(500).json({ error: 'Checkout is not configured right now.' });
  }

  try {
    const body = await parseJsonBody(req);
    const variantId = parseInt(body.variantId, 10);
    if (!ALLOWED_VARIANTS.has(variantId)) {
      return res.status(400).json({ error: 'Invalid product selection' });
    }

    const payload = {
      cart: [{ productId: SELLAUTH_PRODUCT_ID, variantId, quantity: 1 }],
      user_agent: String(req.headers['user-agent'] || '').substring(0, 500),
    };

    const clientIp = getClientIp(req);
    if (clientIp) {
      payload.ip = clientIp;
    }

    const apiResponse = await fetch(`https://api.sellauth.com/v1/shops/${SELLAUTH_SHOP_ID}/checkout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SELLAUTH_API_KEY}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const responseText = await apiResponse.text();
    let responseData = {};
    if (responseText) {
      try {
        responseData = JSON.parse(responseText);
      } catch (error) {
        console.error('SellAuth checkout returned non-JSON:', responseText.slice(0, 300));
      }
    }

    if (!apiResponse.ok) {
      console.error('SellAuth checkout error:', apiResponse.status, responseData);
      return res.status(502).json({ error: 'SellAuth rejected the checkout request.' });
    }

    const checkoutUrl = responseData.invoice_url || responseData.url;
    if (!checkoutUrl) {
      console.error('SellAuth checkout missing URL:', responseData);
      return res.status(502).json({ error: 'No checkout URL was returned.' });
    }

    return res.status(200).json({
      success: true,
      checkoutUrl,
      invoiceId: responseData.invoice_id || null,
      invoiceUrl: responseData.invoice_url || null,
      providerUrl: responseData.url || null,
    });
  } catch (error) {
    console.error('Create checkout error:', error);
    return res.status(500).json({ error: 'Failed to start checkout' });
  }
};
