// api/admin-action.js — uses DB-based role lookup
const crypto = require('crypto');
const { resolveUser, fbGet } = require('./auth-helper');

const KEY_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
function generateKeyChunk() {
  return Array.from({ length: 4 }, () => KEY_CHARSET[Math.floor(Math.random() * KEY_CHARSET.length)]).join('');
}
function generateKeyId(prefix) {
  return prefix + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk() + '-' + generateKeyChunk();
}

const BRANDS = {
  voltaris:         { path: '/keys/voltaris/',        prefix: 'VOLTARIS-' },
  projectservices:  { path: '/keys/projectservices/',  prefix: 'PS-' },
  corvus:           { path: '/keys/corvus/',           prefix: 'CORVUS-' },
  omnis:            { path: '/keys/omnis/',            prefix: 'OMNIS-' },
};

async function fbPatch(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  if (!r.ok) throw new Error(`Firebase PATCH failed: ${r.status}`);
  return r.json();
}

async function fbDelete(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, { method: 'DELETE' });
  if (!r.ok) throw new Error(`Firebase DELETE failed: ${r.status}`);
}

async function fbPut(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  if (!r.ok) throw new Error(`Firebase PUT failed: ${r.status}`);
  return r.json();
}

function resolveKeyPath(keyId) {
  const slash = keyId.indexOf('/');
  if (slash === -1) return null;
  const brandId = keyId.substring(0, slash);
  const keyString = keyId.substring(slash + 1);
  const brand = BRANDS[brandId];
  if (!brand) return null;
  return brand.path + keyString;
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // DB-based admin check
  const user = await resolveUser(req);
  if (!user || !user.isAdmin) {
    return res.status(401).json({ error: 'Admin only' });
  }

  const { action } = req.body || {};

  try {
    switch (action) {

      case 'confirmPayment': {
        const { paymentId } = req.body;
        if (!paymentId) return res.status(400).json({ error: 'Missing paymentId' });
        await fbPatch(`/payments/${paymentId}`, { confirmedByAdmin: true, confirmedAt: Date.now() });
        return res.json({ success: true, message: 'Payment confirmed' });
      }

      case 'rejectPayment': {
        const { paymentId } = req.body;
        if (!paymentId) return res.status(400).json({ error: 'Missing paymentId' });
        await fbDelete(`/payments/${paymentId}`);
        return res.json({ success: true, message: 'Payment rejected' });
      }

      case 'suspendReseller': {
        const { resellerId } = req.body;
        if (!resellerId) return res.status(400).json({ error: 'Missing resellerId' });
        await fbPatch(`/resellers/${resellerId}`, { suspended: true });
        return res.json({ success: true, message: 'Reseller suspended' });
      }

      case 'unsuspendReseller': {
        const { resellerId } = req.body;
        if (!resellerId) return res.status(400).json({ error: 'Missing resellerId' });
        await fbPatch(`/resellers/${resellerId}`, { suspended: false });
        return res.json({ success: true, message: 'Reseller unsuspended' });
      }

      case 'excludeKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format (expected brand/KEY)' });
        await fbPatch(path, { excluded: true });
        return res.json({ success: true, message: 'Key excluded from tracking' });
      }

      case 'includeKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { excluded: false });
        return res.json({ success: true, message: 'Key included in tracking' });
      }

      case 'deactivateKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { active: false });
        return res.json({ success: true, message: 'Key deactivated' });
      }

      case 'activateKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { active: true });
        return res.json({ success: true, message: 'Key activated' });
      }

      case 'resetHwid': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbPatch(path, { hwid: '', expires_at: 0 });
        return res.json({ success: true, message: 'HWID reset' });
      }

      case 'deleteKey': {
        const { keyId } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        await fbDelete(path);
        return res.json({ success: true, message: 'Key deleted' });
      }

      case 'setDeadline': {
        const { resellerId, deadline } = req.body;
        if (!resellerId || !deadline) return res.status(400).json({ error: 'Missing resellerId or deadline' });
        await fbPatch(`/resellers/${resellerId}`, { paymentDeadline: deadline });
        return res.json({ success: true, message: 'Deadline set' });
      }

      case 'addReseller': {
        const { discordId, username, brands } = req.body;
        if (!discordId || !username) return res.status(400).json({ error: 'Missing discordId or username' });
        const validBrands = (brands || []).filter(b => BRANDS[b]);
        if (validBrands.length === 0) return res.status(400).json({ error: 'Must select at least one brand' });
        await fbPut(`/resellers/${discordId}`, {
          username: username,
          avatar: null,
          brands: validBrands,
          suspended: false,
          paymentDeadline: null,
          createdAt: Date.now(),
          addedBy: 'admin',
        });
        return res.json({ success: true, message: 'Reseller ' + username + ' added with brands: ' + validBrands.join(', ') });
      }

      case 'removeReseller': {
        const { resellerId } = req.body;
        if (!resellerId) return res.status(400).json({ error: 'Missing resellerId' });
        await fbDelete(`/resellers/${resellerId}`);
        return res.json({ success: true, message: 'Reseller removed' });
      }

      case 'generateKeys': {
        const { brand, duration, quantity } = req.body;
        const brandConfig = BRANDS[brand];
        if (!brandConfig) return res.status(400).json({ error: 'Invalid brand' });
        const dur = parseInt(duration);
        if (!dur || dur < 1) return res.status(400).json({ error: 'Invalid duration' });
        const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 50);
        const now = Math.floor(Date.now() / 1000);
        const keys = [];
        for (let i = 0; i < qty; i++) {
          const keyId = generateKeyId(brandConfig.prefix);
          await fbPut(brandConfig.path + keyId, {
            hwid: '',
            expires_at: 0,
            duration_days: dur,
            active: true,
            created_at: now,
          });
          keys.push(keyId);
        }
        return res.json({ success: true, keys, message: qty + ' key(s) generated' });
      }

      case 'addTime': {
        const { keyId, days } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        const extraDays = parseInt(days);
        if (!extraDays || extraDays < 1) return res.status(400).json({ error: 'Invalid days' });
        const keyData = await fbGet(path);
        if (!keyData) return res.status(404).json({ error: 'Key not found' });
        const patch = { duration_days: (keyData.duration_days || 0) + extraDays };
        if (keyData.expires_at && keyData.expires_at > 0) {
          patch.expires_at = keyData.expires_at + (extraDays * 86400);
        }
        await fbPatch(path, patch);
        return res.json({ success: true, message: 'Added ' + extraDays + ' days to key' });
      }

      case 'bulkExtend': {
        const { brand: bulkBrand, filter, days } = req.body;
        const extraDays = parseInt(days);
        if (!extraDays || extraDays < 1) return res.status(400).json({ error: 'Invalid days' });
        
        // Determine which brands to operate on
        const targetBrands = bulkBrand === 'all' ? Object.keys(BRANDS) : (BRANDS[bulkBrand] ? [bulkBrand] : []);
        if (targetBrands.length === 0) return res.status(400).json({ error: 'Invalid brand' });

        let count = 0;
        for (const bId of targetBrands) {
          const data = await fbGet(BRANDS[bId].path);
          if (!data || typeof data !== 'object') continue;
          for (const [keyId, k] of Object.entries(data)) {
            if (!k || typeof k !== 'object') continue;
            // Apply filter
            if (filter === 'active' && k.active === false) continue;
            if (filter === 'bound' && !(k.hwid && k.hwid.length > 0)) continue;
            if (filter === 'unbound' && (k.hwid && k.hwid.length > 0)) continue;
            
            const patch = { duration_days: (k.duration_days || 0) + extraDays };
            if (k.expires_at && k.expires_at > 0) {
              patch.expires_at = k.expires_at + (extraDays * 86400);
            }
            await fbPatch(BRANDS[bId].path + keyId, patch);
            count++;
          }
        }
        return res.json({ success: true, message: 'Extended ' + count + ' keys by ' + extraDays + ' days' });
      }

      default:
        return res.status(400).json({ error: 'Unknown action: ' + action });
    }

  } catch (error) {
    console.error('Admin Action Error:', error);
    return res.status(500).json({ error: 'Action failed', detail: error.message });
  }
};
