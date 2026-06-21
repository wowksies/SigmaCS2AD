const crypto = require('crypto');
const { resolveUser, fbGet, sanitize } = require('../lib/auth-helper');
const {
  BRANDS,
  DEFAULT_CUT_RATE,
  VALID_DURATIONS,
  buildDefaultPriceMap,
  normalizeMoney,
  normalizeRate,
} = require('../lib/pricing-helper');

const KEY_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateKeyChunk() {
  const bytes = crypto.randomBytes(4);
  return Array.from(bytes).map((byte) => KEY_CHARSET[byte % KEY_CHARSET.length]).join('');
}

function generateKeyId(prefix) {
  return prefix + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk();
}

async function fbPatch(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const response = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error(`Firebase PATCH failed: ${response.status}`);
  return response.json();
}

async function fbDelete(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const response = await fetch(url, { method: 'DELETE' });
  if (!response.ok) throw new Error(`Firebase DELETE failed: ${response.status}`);
}

async function fbPut(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error(`Firebase PUT failed: ${response.status}`);
  return response.json();
}

async function fbPost(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
}

function isValidDiscordId(id) {
  return typeof id === 'string' && /^\d{17,20}$/.test(id);
}

function isValidKeyString(keyStr) {
  return typeof keyStr === 'string' && /^[A-Z0-9\-]{10,60}$/.test(keyStr);
}

function isValidBrandId(brandId) {
  return typeof brandId === 'string' && Object.prototype.hasOwnProperty.call(BRANDS, brandId);
}

function resolveKeyPath(keyId) {
  if (typeof keyId !== 'string') return null;
  const slashIndex = keyId.indexOf('/');
  if (slashIndex === -1) return null;

  const brandId = keyId.substring(0, slashIndex);
  const keyString = keyId.substring(slashIndex + 1);
  if (!isValidBrandId(brandId)) return null;
  if (!isValidKeyString(keyString)) return null;
  if (keyString.includes('.') || keyString.includes('/') || keyString.includes('\\')) return null;

  return BRANDS[brandId].path + keyString;
}

async function auditLog(action, user, details, req) {
  try {
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
    await fbPost('/audit_logs/admin_actions', {
      action,
      user_id: user.id,
      username: user.nickname || user.username,
      ip,
      details,
      timestamp: Math.floor(Date.now() / 1000),
    });
  } catch (error) {
  }
}

function sanitizePricingPayload(rawBrandPrices) {
  const defaultPrices = buildDefaultPriceMap();
  const cleanPrices = {};

  for (const brandId of Object.keys(BRANDS)) {
    const source = rawBrandPrices && typeof rawBrandPrices === 'object' && rawBrandPrices[brandId] && typeof rawBrandPrices[brandId] === 'object'
      ? rawBrandPrices[brandId]
      : {};
    cleanPrices[brandId] = {};

    for (const duration of VALID_DURATIONS) {
      const key = String(duration);
      const rawValue = source[key] ?? source[duration];
      if (rawValue === undefined || rawValue === null || rawValue === '') {
        cleanPrices[brandId][key] = defaultPrices[key];
        continue;
      }
      const numericValue = Number(rawValue);
      if (!Number.isFinite(numericValue) || numericValue < 0 || numericValue > 100000) {
        throw new Error(`Invalid price for ${brandId} ${key}`);
      }
      cleanPrices[brandId][key] = normalizeMoney(numericValue, defaultPrices[key]);
    }
  }

  return cleanPrices;
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const user = await resolveUser(req);
  if (!user || !user.isAdmin) {
    return res.status(401).json({ error: 'Admin only' });
  }

  const { action } = req.body || {};
  if (!action || typeof action !== 'string') {
    return res.status(400).json({ error: 'Missing action' });
  }

  try {
    switch (action) {
      case 'confirmPayment': {
        const { paymentId } = req.body;
        if (!paymentId || typeof paymentId !== 'string' || paymentId.length > 100) {
          return res.status(400).json({ error: 'Invalid paymentId' });
        }
        if (/[.\/\\]/.test(paymentId)) return res.status(400).json({ error: 'Invalid paymentId format' });
        await fbPatch(`/payments/${paymentId}`, { confirmedByAdmin: true, confirmedAt: Date.now() });
        await auditLog('confirmPayment', user, { paymentId }, req);
        return res.json({ success: true, message: 'Payment confirmed' });
      }

      case 'rejectPayment': {
        const { paymentId } = req.body;
        if (!paymentId || typeof paymentId !== 'string' || paymentId.length > 100) {
          return res.status(400).json({ error: 'Invalid paymentId' });
        }
        if (/[.\/\\]/.test(paymentId)) return res.status(400).json({ error: 'Invalid paymentId format' });
        await fbDelete(`/payments/${paymentId}`);
        await auditLog('rejectPayment', user, { paymentId }, req);
        return res.json({ success: true, message: 'Payment rejected' });
      }

      case 'suspendReseller': {
        const { resellerId } = req.body;
        if (!isValidDiscordId(resellerId)) {
          return res.status(400).json({ error: 'Invalid resellerId - must be Discord ID (17-20 digits)' });
        }
        await fbPatch(`/resellers/${resellerId}`, { suspended: true });
        await auditLog('suspendReseller', user, { resellerId }, req);
        return res.json({ success: true, message: 'Reseller suspended' });
      }

      case 'unsuspendReseller': {
        const { resellerId } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId' });
        await fbPatch(`/resellers/${resellerId}`, { suspended: false });
        await auditLog('unsuspendReseller', user, { resellerId }, req);
        return res.json({ success: true, message: 'Reseller unsuspended' });
      }

      case 'excludeKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { excluded: true });
        await auditLog('excludeKey', user, { keyId }, req);
        return res.json({ success: true, message: 'Key excluded from tracking' });
      }

      case 'includeKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { excluded: false });
        await auditLog('includeKey', user, { keyId }, req);
        return res.json({ success: true, message: 'Key included in tracking' });
      }

      case 'deactivateKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { active: false });
        await auditLog('deactivateKey', user, { keyId }, req);
        return res.json({ success: true, message: 'Key deactivated' });
      }

      case 'activateKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { active: true });
        await auditLog('activateKey', user, { keyId }, req);
        return res.json({ success: true, message: 'Key activated' });
      }

      case 'resetHwid': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { hwid: '', expires_at: 0 });
        await auditLog('resetHwid', user, { keyId }, req);
        return res.json({ success: true, message: 'HWID reset' });
      }

      case 'deleteKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbDelete(path);
        await auditLog('deleteKey', user, { keyId }, req);
        return res.json({ success: true, message: 'Key deleted' });
      }

      case 'setDeadline': {
        const { resellerId, deadline } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId' });
        const deadlineNum = parseInt(deadline, 10);
        if (!deadlineNum || deadlineNum < Date.now() - 86400000 || deadlineNum > Date.now() + 365 * 86400000) {
          return res.status(400).json({ error: 'Invalid deadline' });
        }
        await fbPatch(`/resellers/${resellerId}`, { paymentDeadline: deadlineNum });
        await auditLog('setDeadline', user, { resellerId, deadline: deadlineNum }, req);
        return res.json({ success: true, message: 'Deadline set' });
      }

      case 'addReseller': {
        const { discordId, username, brands } = req.body;
        if (!isValidDiscordId(discordId)) {
          return res.status(400).json({ error: 'Invalid discordId - must be 17-20 digits' });
        }
        const safeUsername = sanitize(username, 64);
        if (!safeUsername || safeUsername.length < 2) {
          return res.status(400).json({ error: 'Invalid username' });
        }
        const validBrands = (brands || []).filter((brandId) => isValidBrandId(brandId));
        if (validBrands.length === 0) {
          return res.status(400).json({ error: 'Must select at least one valid brand' });
        }

        const existing = await fbGet(`/resellers/${discordId}`);
        if (existing) {
          const mergedBrands = Array.from(new Set([...(existing.brands || []), ...validBrands]));
          await fbPatch(`/resellers/${discordId}`, {
            username: safeUsername,
            nickname: existing.nickname || safeUsername,
            brands: mergedBrands,
            isReseller: true,
            updatedAt: Date.now(),
            updatedBy: user.id,
            updatedByName: user.nickname || user.username,
          });
          await auditLog('addReseller', user, { discordId, username: safeUsername, brands: mergedBrands, mergedExisting: true }, req);
          return res.json({ success: true, message: 'Reseller ' + safeUsername + ' updated. Brands now: ' + mergedBrands.join(', ') });
        }

        await fbPut(`/resellers/${discordId}`, {
          username: safeUsername,
          nickname: safeUsername,
          avatar: null,
          brands: validBrands,
          isReseller: true,
          suspended: false,
          paymentDeadline: null,
          pricing: {
            cutRate: DEFAULT_CUT_RATE,
            brandPrices: {},
          },
          createdAt: Date.now(),
          addedBy: user.id,
          addedByName: user.nickname || user.username,
        });
        await auditLog('addReseller', user, { discordId, username: safeUsername, brands: validBrands }, req);
        return res.json({ success: true, message: 'Reseller ' + safeUsername + ' added with brands: ' + validBrands.join(', ') });
      }

      case 'updateResellerBrands': {
        const { resellerId, brands } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId' });
        const validBrands = (brands || []).filter((brandId) => isValidBrandId(brandId));

        const existing = await fbGet(`/resellers/${resellerId}`);
        if (!existing) return res.status(404).json({ error: 'Reseller not found. Use Add Reseller first.' });

        await fbPatch(`/resellers/${resellerId}`, {
          brands: validBrands,
          isReseller: validBrands.length > 0 || existing.isAdmin === true,
          updatedAt: Date.now(),
          updatedBy: user.id,
          updatedByName: user.nickname || user.username,
        });
        await auditLog('updateResellerBrands', user, { resellerId, brands: validBrands }, req);
        return res.json({ success: true, message: 'Brands updated: ' + (validBrands.length ? validBrands.join(', ') : 'none') });
      }

      case 'removeReseller': {
        const { resellerId } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId' });
        await fbDelete(`/resellers/${resellerId}`);
        await auditLog('removeReseller', user, { resellerId }, req);
        return res.json({ success: true, message: 'Reseller removed' });
      }

      case 'updateResellerPricing': {
        const { resellerId, cutPercent, brandPrices } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId' });

        const resellerProfile = await fbGet(`/resellers/${resellerId}`);
        if (!resellerProfile) return res.status(404).json({ error: 'Reseller not found' });

        const numericCut = Number(cutPercent);
        if (!Number.isFinite(numericCut) || numericCut < 0 || numericCut > 100) {
          return res.status(400).json({ error: 'Cut must be between 0 and 100' });
        }

        const cleanBrandPrices = sanitizePricingPayload(brandPrices);
        const cutRate = normalizeRate(numericCut, DEFAULT_CUT_RATE);
        await fbPatch(`/resellers/${resellerId}`, {
          pricing: {
            cutRate,
            brandPrices: cleanBrandPrices,
            updatedAt: Date.now(),
            updatedBy: user.id,
            updatedByName: user.nickname || user.username,
          },
        });
        await auditLog('updateResellerPricing', user, { resellerId, cutRate, brandPrices: cleanBrandPrices }, req);
        return res.json({ success: true, message: 'Reseller pricing updated' });
      }

      case 'generateKeys': {
        const { brand, duration, quantity } = req.body;
        if (!isValidBrandId(brand)) return res.status(400).json({ error: 'Invalid brand' });
        const durationDays = parseInt(duration, 10);
        if (!VALID_DURATIONS.includes(durationDays)) return res.status(400).json({ error: 'Invalid duration' });

        const qty = Math.min(Math.max(parseInt(quantity, 10) || 1, 1), 50);
        const now = Math.floor(Date.now() / 1000);
        const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
        const brandConfig = BRANDS[brand];
        const keys = [];

        for (let i = 0; i < qty; i++) {
          const keyId = generateKeyId(brandConfig.prefix);
          await fbPut(brandConfig.path + keyId, {
            hwid: '',
            expires_at: 0,
            duration_days: durationDays,
            active: true,
            created_at: now,
            created_by: user.id,
            created_by_name: user.nickname || user.username || 'Admin',
            is_admin: true,
            sale_price: 0,
            cut_rate: 0,
            owed_amount: 0,
          });
          keys.push(keyId);
        }

        await auditLog('generateKeys', user, { brand, duration: durationDays, quantity: qty, keys, ip, source: 'admin_panel' }, req);
        try {
          const alertWebhook = process.env.SECURITY_WEBHOOK_URL;
          if (alertWebhook) {
            await fetch(alertWebhook, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                embeds: [{
                  title: 'Admin Keys Generated',
                  color: 0x00FF00,
                  fields: [
                    { name: 'Admin', value: `${user.nickname || user.username}\n\`${user.id}\``, inline: true },
                    { name: 'Brand', value: brand, inline: true },
                    { name: 'Quantity', value: String(qty), inline: true },
                    { name: 'Duration', value: durationDays === 99999 ? 'Lifetime' : durationDays + ' days', inline: true },
                    { name: 'IP', value: '`' + ip + '`', inline: true },
                  ],
                  footer: { text: 'Key Security Monitor' },
                  timestamp: new Date().toISOString(),
                }],
              }),
            });
          }
        } catch (error) {
        }
        return res.json({ success: true, keys, message: qty + ' key(s) generated' });
      }

      case 'addTime': {
        const { keyId, days } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        const extraDays = parseInt(days, 10);
        if (!extraDays || extraDays < 1 || extraDays > 3650) {
          return res.status(400).json({ error: 'Invalid days (1-3650)' });
        }
        const keyData = await fbGet(path);
        if (!keyData) return res.status(404).json({ error: 'Key not found' });

        const patch = { duration_days: (keyData.duration_days || 0) + extraDays };
        if (keyData.expires_at && keyData.expires_at > 0) {
          patch.expires_at = keyData.expires_at + (extraDays * 86400);
        }
        await fbPatch(path, patch);
        await auditLog('addTime', user, { keyId, days: extraDays }, req);
        return res.json({ success: true, message: 'Added ' + extraDays + ' days to key' });
      }

      case 'bulkExtend': {
        const { brand: bulkBrand, filter, days } = req.body;
        const extraDays = parseInt(days, 10);
        if (!extraDays || extraDays < 1 || extraDays > 3650) {
          return res.status(400).json({ error: 'Invalid days (1-3650)' });
        }

        const targetBrands = bulkBrand === 'all'
          ? Object.keys(BRANDS)
          : (isValidBrandId(bulkBrand) ? [bulkBrand] : []);
        if (targetBrands.length === 0) return res.status(400).json({ error: 'Invalid brand' });

        const validFilters = ['all', 'active', 'bound', 'unbound'];
        if (!validFilters.includes(filter)) return res.status(400).json({ error: 'Invalid filter' });

        let count = 0;
        for (const brandId of targetBrands) {
          const data = await fbGet(BRANDS[brandId].path);
          if (!data || typeof data !== 'object') continue;

          for (const [keyId, keyData] of Object.entries(data)) {
            if (!keyData || typeof keyData !== 'object') continue;
            if (filter === 'active' && keyData.active === false) continue;
            if (filter === 'bound' && !(keyData.hwid && keyData.hwid.length > 0)) continue;
            if (filter === 'unbound' && keyData.hwid && keyData.hwid.length > 0) continue;

            const patch = { duration_days: (keyData.duration_days || 0) + extraDays };
            if (keyData.expires_at && keyData.expires_at > 0) {
              patch.expires_at = keyData.expires_at + (extraDays * 86400);
            }
            await fbPatch(BRANDS[brandId].path + keyId, patch);
            count++;
          }
        }

        await auditLog('bulkExtend', user, { brand: bulkBrand, filter, days: extraDays, keysAffected: count }, req);
        return res.json({ success: true, message: 'Extended ' + count + ' keys by ' + extraDays + ' days' });
      }

      default:
        return res.status(400).json({ error: 'Unknown action' });
    }
  } catch (error) {
    console.error('Admin Action Error:', error);
    return res.status(500).json({ error: 'Action failed' });
  }
};