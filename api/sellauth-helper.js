const SELLAUTH_API_BASE = 'https://api.sellauth.com/v1';

const PLAN_CONFIG = Object.freeze({
  three_days: {
    label: '4 Days',
    envKey: 'SELLAUTH_VARIANT_3_DAYS_ID',
    aliases: ['4 days', '4 day', '4d', '3 days', '3 day', '3d', 'trial'],
    legacyVariantIds: [995693],
  },
  one_week: {
    label: '1 Week',
    envKey: 'SELLAUTH_VARIANT_1_WEEK_ID',
    aliases: ['1 week', '7 days', '7 day', 'week', 'weekly'],
    legacyVariantIds: [995694],
  },
  one_month: {
    label: 'Month',
    envKey: 'SELLAUTH_VARIANT_1_MONTH_ID',
    aliases: ['1 month', '30 days', '30 day', 'month', 'monthly'],
    legacyVariantIds: [995695],
  },
  lifetime: {
    label: 'Lifetime',
    envKey: 'SELLAUTH_VARIANT_LIFETIME_ID',
    aliases: ['lifetime', 'life time', 'permanent', 'pay once'],
    legacyVariantIds: [995696],
  },
});

const LEGACY_VARIANT_ID_TO_PLAN = Object.freeze(
  Object.entries(PLAN_CONFIG).reduce((acc, [planKey, config]) => {
    config.legacyVariantIds.forEach((variantId) => {
      acc[String(variantId)] = planKey;
    });
    return acc;
  }, {})
);

let catalogCache = null;
let catalogCacheExpiresAt = 0;

function parseOptionalInt(value) {
  const parsed = parseInt(String(value || '').trim(), 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function getConfiguredShopId() {
  return parseOptionalInt(process.env.SELLAUTH_SHOP_ID);
}

function getConfiguredProductId() {
  return parseOptionalInt(process.env.SELLAUTH_PRODUCT_ID);
}

function getConfiguredStorefrontUrl() {
  const value = String(process.env.SELLAUTH_STOREFRONT_URL || '').trim();
  return value ? value.replace(/\/+$/, '') : '';
}

function getConfiguredProductUrl() {
  const explicit = String(process.env.SELLAUTH_PRODUCT_URL || '').trim();
  if (explicit) return explicit.replace(/\/+$/, '');

  return 'https://omniscs2.mysellauth.com/product/omnis-cs2';
}

function getConfiguredProductNameCandidates() {
  const raw = String(process.env.SELLAUTH_PRODUCT_NAME || '').trim();
  const values = raw
    ? raw.split(',').map((entry) => entry.trim()).filter(Boolean)
    : ['Omnis CS2', 'Omnis'];
  return values.map(normalizeText).filter(Boolean);
}

function getVariantEnvOverride(planKey) {
  const config = PLAN_CONFIG[planKey];
  if (!config) return null;
  return parseOptionalInt(process.env[config.envKey]);
}

function getSellAuthHeaders() {
  const apiKey = String(process.env.SELLAUTH_API_KEY || '').trim();
  if (!apiKey) {
    throw new Error('SELLAUTH_API_KEY is not configured');
  }

  return {
    Authorization: `Bearer ${apiKey}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };
}

async function fetchSellAuthJson(path, options = {}) {
  const response = await fetch(`${SELLAUTH_API_BASE}${path}`, {
    method: options.method || 'GET',
    headers: {
      ...getSellAuthHeaders(),
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const rawText = await response.text();
  let data = {};
  if (rawText) {
    try {
      data = JSON.parse(rawText);
    } catch (error) {
      data = { raw: rawText };
    }
  }

  if (!response.ok) {
    const message = typeof data.message === 'string' && data.message
      ? data.message
      : `SellAuth request failed with status ${response.status}`;
    const enrichedError = new Error(message);
    enrichedError.status = response.status;
    enrichedError.payload = data;
    throw enrichedError;
  }

  return data;
}

function scoreProduct(product, nameCandidates) {
  const normalizedName = normalizeText(product && product.name);
  const normalizedPath = normalizeText(product && product.path);
  let score = 0;

  nameCandidates.forEach((candidate) => {
    if (!candidate) return;
    if (normalizedName === candidate) score += 100;
    if (normalizedPath === candidate) score += 90;
    if (normalizedName.includes(candidate)) score += 60;
    if (normalizedPath.includes(candidate)) score += 50;
  });

  if (product && product.type === 'variant') score += 15;
  if (product && product.visibility === 'public') score += 5;
  if (product && Array.isArray(product.variants) && product.variants.length) score += 10;

  return score;
}

async function fetchConfiguredProduct(shopId) {
  const configuredProductId = getConfiguredProductId();
  if (configuredProductId) {
    try {
      return await fetchSellAuthJson(`/shops/${shopId}/products/${configuredProductId}`);
    } catch (error) {
      console.warn('SellAuth configured product lookup failed, falling back to name search:', error.message);
    }
  }

  const productsResponse = await fetchSellAuthJson(`/shops/${shopId}/products?perPage=100`);
  const products = Array.isArray(productsResponse.data) ? productsResponse.data : [];
  const nameCandidates = getConfiguredProductNameCandidates();

  let bestProduct = null;
  let bestScore = -1;
  products.forEach((product) => {
    const score = scoreProduct(product, nameCandidates);
    if (score > bestScore) {
      bestScore = score;
      bestProduct = product;
    }
  });

  if (!bestProduct || bestScore <= 0) {
    throw new Error('SellAuth product could not be found. Set SELLAUTH_PRODUCT_ID or SELLAUTH_PRODUCT_NAME.');
  }

  return bestProduct;
}

function resolvePlanKey(value) {
  if (value == null) return null;

  const raw = String(value).trim();
  if (!raw) return null;

  if (LEGACY_VARIANT_ID_TO_PLAN[raw]) {
    return LEGACY_VARIANT_ID_TO_PLAN[raw];
  }

  const normalized = normalizeText(raw);
  if (!normalized) return null;

  const directMap = {
    '4 days': 'three_days',
    '4 day': 'three_days',
    '4d': 'three_days',
    '3 days': 'three_days',
    '3 day': 'three_days',
    '3d': 'three_days',
    '1 week': 'one_week',
    '7 days': 'one_week',
    '7 day': 'one_week',
    week: 'one_week',
    weekly: 'one_week',
    '1 month': 'one_month',
    '30 days': 'one_month',
    '30 day': 'one_month',
    month: 'one_month',
    monthly: 'one_month',
    lifetime: 'lifetime',
    'life time': 'lifetime',
    permanent: 'lifetime',
  };

  if (directMap[normalized]) {
    return directMap[normalized];
  }

  return Object.entries(PLAN_CONFIG).find(([, config]) => (
    config.aliases.some((alias) => normalizeText(alias) === normalized)
  ))?.[0] || null;
}

function resolveVariantIdFromProduct(product, planKey) {
  const envOverride = getVariantEnvOverride(planKey);
  if (envOverride) {
    return envOverride;
  }

  const config = PLAN_CONFIG[planKey];
  if (!config) return null;

  const variants = Array.isArray(product && product.variants) ? product.variants : [];
  const normalizedAliases = config.aliases.map(normalizeText);

  let bestVariant = null;
  let bestScore = -1;

  variants.forEach((variant) => {
    const normalizedName = normalizeText(variant && variant.name);
    let score = 0;

    normalizedAliases.forEach((alias) => {
      if (!alias) return;
      if (normalizedName === alias) score += 100;
      if (normalizedName.includes(alias)) score += 50;
    });

    if (score > bestScore) {
      bestScore = score;
      bestVariant = variant;
    }
  });

  return bestVariant && bestScore > 0 ? parseOptionalInt(bestVariant.id) : null;
}

async function resolveCheckoutCatalog(options = {}) {
  const forceRefresh = options.forceRefresh === true;
  if (!forceRefresh && catalogCache && Date.now() < catalogCacheExpiresAt) {
    return catalogCache;
  }

  const shopId = getConfiguredShopId();
  const configuredProductId = getConfiguredProductId();
  const configuredStorefrontUrl = getConfiguredStorefrontUrl();
  const configuredVariants = Object.fromEntries(
    Object.keys(PLAN_CONFIG).map((planKey) => [planKey, getVariantEnvOverride(planKey)])
  );
  const hasFullEnvOverride = Boolean(
    configuredProductId &&
    configuredStorefrontUrl &&
    Object.values(configuredVariants).every(Boolean)
  );

  if (hasFullEnvOverride) {
    catalogCache = {
      shopId,
      shopUrl: configuredStorefrontUrl,
      productUrl: getConfiguredProductUrl(),
      productId: configuredProductId,
      productName: String(process.env.SELLAUTH_PRODUCT_NAME || '').trim(),
      variants: configuredVariants,
    };
    catalogCacheExpiresAt = Date.now() + (5 * 60 * 1000);
    return catalogCache;
  }

  if (!shopId) {
    throw new Error('SELLAUTH_SHOP_ID is not configured');
  }

  const [shop, product] = await Promise.all([
    fetchSellAuthJson(`/shops/${shopId}`),
    fetchConfiguredProduct(shopId),
  ]);

  const variants = {};
  Object.keys(PLAN_CONFIG).forEach((planKey) => {
    variants[planKey] = resolveVariantIdFromProduct(product, planKey);
  });

  catalogCache = {
    shopId,
    shopUrl: getConfiguredStorefrontUrl() || String(shop && shop.url || '').replace(/\/+$/, ''),
    productUrl: getConfiguredProductUrl(),
    productId: parseOptionalInt(product && product.id),
    productName: product && product.name ? String(product.name) : '',
    productPath: product && product.path ? String(product.path) : '',
    variants,
  };
  catalogCacheExpiresAt = Date.now() + (5 * 60 * 1000);

  return catalogCache;
}

function buildCheckoutLink(catalog, planKey) {
  if (!catalog || !catalog.shopUrl) {
    throw new Error('SellAuth storefront URL is unavailable');
  }

  const variantId = catalog.variants && catalog.variants[planKey];
  if (!catalog.productId || !variantId) {
    throw new Error('SellAuth checkout link is missing product or variant data');
  }

  const url = new URL(`${catalog.shopUrl}/checkout-link`);
  url.searchParams.set('cart[0][productId]', String(catalog.productId));
  url.searchParams.set('cart[0][variantId]', String(variantId));
  url.searchParams.set('cart[0][quantity]', '1');
  return url.toString();
}

function buildProductLink(catalog) {
  const explicitProductUrl = catalog && catalog.productUrl ? String(catalog.productUrl).trim() : '';
  if (explicitProductUrl) {
    return explicitProductUrl.replace(/\/+$/, '');
  }

  if (catalog && catalog.shopUrl && catalog.productPath) {
    return `${String(catalog.shopUrl).replace(/\/+$/, '')}/product/${String(catalog.productPath).replace(/^\/+|\/+$/g, '')}`;
  }

  throw new Error('SellAuth product page URL is unavailable');
}

function collectInvoiceProductMetadata(invoice) {
  const ids = new Set();
  const names = new Set();

  const addId = (value) => {
    const parsed = parseOptionalInt(value);
    if (parsed) ids.add(parsed);
  };

  const addName = (value) => {
    const normalized = normalizeText(value);
    if (normalized) names.add(normalized);
  };

  addId(invoice && invoice.product_id);
  addName(invoice && invoice.product_name);

  const items = Array.isArray(invoice && invoice.items) ? invoice.items : [];
  items.forEach((item) => {
    addId(item && item.product_id);
    addName(item && item.product_name);
    if (item && item.product && typeof item.product === 'object') {
      addId(item.product.id);
      addName(item.product.name);
    }
  });

  return {
    ids: Array.from(ids),
    names: Array.from(names),
  };
}

function invoiceMatchesConfiguredProduct(invoice) {
  const metadata = collectInvoiceProductMetadata(invoice);
  const configuredProductId = getConfiguredProductId();

  if (configuredProductId && metadata.ids.includes(configuredProductId)) {
    return true;
  }

  const nameCandidates = getConfiguredProductNameCandidates();
  if (!nameCandidates.length) return false;

  return metadata.names.some((name) => (
    nameCandidates.some((candidate) => name === candidate || name.includes(candidate))
  ));
}

module.exports = {
  PLAN_CONFIG,
  buildCheckoutLink,
  buildProductLink,
  fetchSellAuthJson,
  getConfiguredProductUrl,
  getConfiguredProductId,
  getConfiguredShopId,
  invoiceMatchesConfiguredProduct,
  resolveCheckoutCatalog,
  resolvePlanKey,
};
