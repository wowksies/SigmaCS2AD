const DURATION_MAP = Object.freeze({
  1: { label: '1 Day', price: 3 },
  3: { label: '3 Days', price: 5 },
  7: { label: '1 Week', price: 7 },
  14: { label: '14 Days', price: 10 },
  30: { label: '1 Month', price: 12 },
  90: { label: '90 Days', price: 20 },
  365: { label: '1 Year', price: 25 },
  99999: { label: 'Lifetime', price: 30 },
});

const DEFAULT_CUT_RATE = 0.30;

const BRANDS = Object.freeze({
  voltaris: {
    name: 'Voltaris',
    prefix: 'VOLTARIS-',
    path: '/keys/voltaris/',
    color: '#FF3344',
    emoji: '[V]',
  },
  projectservices: {
    name: 'Project Services',
    prefix: 'PS-',
    path: '/keys/projectservices/',
    color: '#1E50C8',
    emoji: '[P]',
  },
  corvus: {
    name: 'Corvus',
    prefix: 'CORVUS-',
    path: '/keys/corvus/',
    color: '#7832C8',
    emoji: '[C]',
  },
  omnis: {
    name: 'Omnis',
    prefix: 'OMNIS-',
    path: '/keys/omnis/',
    color: '#A040FF',
    emoji: '[O]',
  },
});

const VALID_DURATIONS = Object.freeze(Object.keys(DURATION_MAP).map(Number));

function roundMoney(value) {
  return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

function normalizeMoney(value, fallback = 0) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return roundMoney(fallback);
  return roundMoney(num);
}

function roundRate(value) {
  return Math.round((Number(value) + Number.EPSILON) * 1000000) / 1000000;
}

function normalizeRate(value, fallback = DEFAULT_CUT_RATE) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return roundRate(fallback);
  if (num <= 1) return roundRate(num);
  if (num <= 100) return roundRate(num / 100);
  return roundRate(fallback);
}

function rateToPercent(rate) {
  return normalizeMoney(normalizeRate(rate, DEFAULT_CUT_RATE) * 100, DEFAULT_CUT_RATE * 100);
}

function formatPercent(rate) {
  const value = rateToPercent(rate).toFixed(2);
  return value.replace(/\.00$/, '').replace(/(\.\d*[1-9])0$/, '$1');
}

function getDurationInfo(days) {
  const key = String(parseInt(days, 10) || 0);
  return DURATION_MAP[key] || { label: key + ' Days', price: 5 };
}

function getDurationEntries() {
  return VALID_DURATIONS.map((days) => ({
    days,
    label: DURATION_MAP[String(days)].label,
    defaultPrice: DURATION_MAP[String(days)].price,
  }));
}

function buildDefaultPriceMap() {
  const map = {};
  for (const [days, info] of Object.entries(DURATION_MAP)) {
    map[days] = normalizeMoney(info.price, info.price);
  }
  return map;
}

function getRawPricing(profile) {
  return profile && typeof profile.pricing === 'object' ? profile.pricing : {};
}

function getBrandPriceMap(profile, brandId) {
  const defaults = buildDefaultPriceMap();
  if (!brandId || !Object.prototype.hasOwnProperty.call(BRANDS, brandId)) {
    return defaults;
  }

  const pricing = getRawPricing(profile);
  const rawBrandPrices = pricing.brandPrices && typeof pricing.brandPrices === 'object'
    ? pricing.brandPrices[brandId]
    : null;

  if (!rawBrandPrices || typeof rawBrandPrices !== 'object') {
    return defaults;
  }

  for (const duration of VALID_DURATIONS) {
    const key = String(duration);
    if (Object.prototype.hasOwnProperty.call(rawBrandPrices, key)) {
      defaults[key] = normalizeMoney(rawBrandPrices[key], defaults[key]);
    }
  }

  return defaults;
}

function getResellerCutRate(profile) {
  const pricing = getRawPricing(profile);
  return normalizeRate(pricing.cutRate, DEFAULT_CUT_RATE);
}

function getResellerPricingProfile(profile) {
  const cutRate = getResellerCutRate(profile);
  const brandPrices = {};

  for (const brandId of Object.keys(BRANDS)) {
    brandPrices[brandId] = getBrandPriceMap(profile, brandId);
  }

  return {
    cutRate,
    cutPercent: rateToPercent(cutRate),
    brandPrices,
  };
}

function getConfiguredPrice(profile, brandId, durationDays) {
  const key = String(parseInt(durationDays, 10) || 0);
  const priceMap = getBrandPriceMap(profile, brandId);
  if (Object.prototype.hasOwnProperty.call(priceMap, key)) {
    return priceMap[key];
  }
  return normalizeMoney(getDurationInfo(durationDays).price, getDurationInfo(durationDays).price);
}

function getKeyFinancials(keyRecord, profile, brandId) {
  const durationDays = parseInt(keyRecord.duration_days || keyRecord.durationDays || 0, 10) || 0;
  const durationInfo = getDurationInfo(durationDays);
  const configuredPrice = getConfiguredPrice(profile, brandId, durationDays);
  const storedPrice = keyRecord.sale_price ?? keyRecord.unit_price ?? keyRecord.price;
  const unitPrice = normalizeMoney(storedPrice, configuredPrice);
  const cutRate = normalizeRate(keyRecord.cut_rate ?? keyRecord.cutRate, getResellerCutRate(profile));
  const computedOwed = normalizeMoney(unitPrice * cutRate, 0);
  const storedOwed = keyRecord.owed_amount ?? keyRecord.owedAmount;
  const owedAmount = normalizeMoney(storedOwed, computedOwed);

  return {
    durationDays,
    planLabel: durationInfo.label,
    unitPrice,
    cutRate,
    cutPercent: rateToPercent(cutRate),
    owedAmount,
  };
}

function formatMoney(value) {
  return normalizeMoney(value, 0).toFixed(2);
}

module.exports = {
  BRANDS,
  DEFAULT_CUT_RATE,
  DURATION_MAP,
  VALID_DURATIONS,
  buildDefaultPriceMap,
  formatMoney,
  formatPercent,
  getBrandPriceMap,
  getConfiguredPrice,
  getDurationEntries,
  getDurationInfo,
  getKeyFinancials,
  getResellerCutRate,
  getResellerPricingProfile,
  normalizeMoney,
  normalizeRate,
  rateToPercent,
};