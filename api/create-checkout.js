const net = require('net');
const { validateOrigin, validateUserAgent } = require('./auth-helper');
const {
  buildCheckoutLink,
  fetchSellAuthJson,
  resolveCheckoutCatalog,
  resolvePlanKey,
} = require('./sellauth-helper');

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

function getSellAuthErrorMessage(error) {
  if (error && error.payload) {
    if (typeof error.payload.message === 'string' && error.payload.message) {
      return error.payload.message;
    }
    if (typeof error.payload.error === 'string' && error.payload.error) {
      return error.payload.error;
    }
  }

  return error && error.message ? error.message : 'SellAuth rejected the checkout request.';
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

  try {
    const body = await parseJsonBody(req);
    const planKey = resolvePlanKey(body.planKey || body.variantId || body.variant || body.duration);
    if (!planKey) {
      return res.status(400).json({ error: 'Invalid product selection' });
    }

    const catalog = await resolveCheckoutCatalog();
    const variantId = catalog.variants[planKey];
    if (!variantId) {
      return res.status(500).json({ error: 'SellAuth variant is not configured for this plan.' });
    }

    const payload = {
      cart: [{ productId: catalog.productId, variantId, quantity: 1 }],
      user_agent: String(req.headers['user-agent'] || '').substring(0, 500),
    };

    const clientIp = getClientIp(req);
    if (clientIp) {
      payload.ip = clientIp;
    }

    try {
      if (!catalog.shopId) {
        throw new Error('SELLAUTH_SHOP_ID is not configured for API checkout; using checkout-link fallback.');
      }

      const responseData = await fetchSellAuthJson(`/shops/${catalog.shopId}/checkout`, {
        method: 'POST',
        body: payload,
      });

      const checkoutUrl = responseData.invoice_url || responseData.url;
      if (!checkoutUrl) {
        throw new Error('SellAuth did not return a checkout URL.');
      }

      return res.status(200).json({
        success: true,
        checkoutUrl,
        invoiceId: responseData.invoice_id || null,
        invoiceUrl: responseData.invoice_url || null,
        providerUrl: responseData.url || null,
        planKey,
      });
    } catch (error) {
      const fallbackUrl = buildCheckoutLink(catalog, planKey);
      console.warn('SellAuth checkout API failed; falling back to checkout-link:', getSellAuthErrorMessage(error));
      return res.status(200).json({
        success: true,
        checkoutUrl: fallbackUrl,
        fallback: true,
        message: getSellAuthErrorMessage(error),
        planKey,
      });
    }
  } catch (error) {
    console.error('Create checkout error:', error);
    return res.status(500).json({ error: error.message || 'Failed to start checkout' });
  }
};
