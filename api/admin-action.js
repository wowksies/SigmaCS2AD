// api/admin-action.js — MAXIMUM SECURITY: DB-based auth + audit + input sanitization
const crypto = require('crypto');
const { resolveUser, fbGet, sanitize } = require('./auth-helper');

const KEY_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
function generateKeyChunk() {
  const bytes = crypto.randomBytes(4);
  return Array.from(bytes).map(b => KEY_CHARSET[b % KEY_CHARSET.length]).join('');
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

// ── Firebase helpers ────────────────────────────────────────
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

async function fbPost(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
}

// ── Input Validation ────────────────────────────────────────
// CRITICAL: Prevents Firebase path injection (../../ attacks)
function isValidDiscordId(id) {
  return typeof id === 'string' && /^\d{17,20}$/.test(id);
}

function isValidKeyString(keyStr) {
  // Keys must be alphanumeric + hyphens only (e.g. OMNIS-XXXX-XXXX-XXXX-XXXX)
  return typeof keyStr === 'string' && /^[A-Z0-9\-]{10,60}$/.test(keyStr);
}

function isValidBrandId(brandId) {
  return typeof brandId === 'string' && BRANDS.hasOwnProperty(brandId);
}

function resolveKeyPath(keyId) {
  if (typeof keyId !== 'string') return null;
  const slash = keyId.indexOf('/');
  if (slash === -1) return null;
  const brandId = keyId.substring(0, slash);
  const keyString = keyId.substring(slash + 1);
  
  // SECURITY: Validate brand exists
  if (!isValidBrandId(brandId)) return null;
  
  // SECURITY: Validate key string format — block path traversal (../ etc)
  if (!isValidKeyString(keyString)) return null;
  
  // SECURITY: Double-check no path traversal characters exist
  if (keyString.includes('.') || keyString.includes('/') || keyString.includes('\\')) return null;
  
  return BRANDS[brandId].path + keyString;
}

// ── Audit Logger ────────────────────────────────────────────
async function auditLog(action, user, details, req) {
  try {
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
    await fbPost('/audit_logs/admin_actions', {
      action: action,
      user_id: user.id,
      username: user.nickname || user.username,
      ip: ip,
      details: details,
      timestamp: Math.floor(Date.now() / 1000),
    });
  } catch (e) { /* audit failure should not block */ }
}

// ── Handler ─────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // DB-based admin check
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
        if (!paymentId || typeof paymentId !== 'string' || paymentId.length > 100) return res.status(400).json({ error: 'Invalid paymentId' });
        // Block path traversal in paymentId
        if (/[.\/\\]/.test(paymentId)) return res.status(400).json({ error: 'Invalid paymentId format' });
        await fbPatch(`/payments/${paymentId}`, { confirmedByAdmin: true, confirmedAt: Date.now() });
        await auditLog('confirmPayment', user, { paymentId }, req);
        return res.json({ success: true, message: 'Payment confirmed' });
      }

      case 'rejectPayment': {
        const { paymentId } = req.body;
        if (!paymentId || typeof paymentId !== 'string' || paymentId.length > 100) return res.status(400).json({ error: 'Invalid paymentId' });
        if (/[.\/\\]/.test(paymentId)) return res.status(400).json({ error: 'Invalid paymentId format' });
        await fbDelete(`/payments/${paymentId}`);
        await auditLog('rejectPayment', user, { paymentId }, req);
        return res.json({ success: true, message: 'Payment rejected' });
      }

      case 'suspendReseller': {
        const { resellerId } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId — must be Discord ID (17-20 digits)' });
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
        const deadlineNum = parseInt(deadline);
        if (!deadlineNum || deadlineNum < Date.now() - 86400000 || deadlineNum > Date.now() + 365 * 86400000) {
          return res.status(400).json({ error: 'Invalid deadline' });
        }
        await fbPatch(`/resellers/${resellerId}`, { paymentDeadline: deadlineNum });
        await auditLog('setDeadline', user, { resellerId, deadline: deadlineNum }, req);
        return res.json({ success: true, message: 'Deadline set' });
      }

      case 'addReseller': {
        const { discordId, username, brands } = req.body;
        if (!isValidDiscordId(discordId)) return res.status(400).json({ error: 'Invalid discordId — must be 17-20 digits' });
        // Sanitize username — strip HTML/special chars
        const safeUsername = sanitize(username, 64);
        if (!safeUsername || safeUsername.length < 2) return res.status(400).json({ error: 'Invalid username' });
        const validBrands = (brands || []).filter(b => isValidBrandId(b));
        if (validBrands.length === 0) return res.status(400).json({ error: 'Must select at least one valid brand' });
        await fbPut(`/resellers/${discordId}`, {
          username: safeUsername,
          avatar: null,
          brands: validBrands,
          suspended: false,
          paymentDeadline: null,
          createdAt: Date.now(),
          addedBy: user.id,
          addedByName: user.nickname || user.username,
        });
        await auditLog('addReseller', user, { discordId, username: safeUsername, brands: validBrands }, req);
        return res.json({ success: true, message: 'Reseller ' + safeUsername + ' added with brands: ' + validBrands.join(', ') });
      }

      case 'removeReseller': {
        const { resellerId } = req.body;
        if (!isValidDiscordId(resellerId)) return res.status(400).json({ error: 'Invalid resellerId' });
        await fbDelete(`/resellers/${resellerId}`);
        await auditLog('removeReseller', user, { resellerId }, req);
        return res.json({ success: true, message: 'Reseller removed' });
      }

      case 'generateKeys': {
        const { brand, duration, quantity } = req.body;
        if (!isValidBrandId(brand)) return res.status(400).json({ error: 'Invalid brand' });
        const brandConfig = BRANDS[brand];
        const dur = parseInt(duration);
        if (!dur || dur < 1 || dur > 99999) return res.status(400).json({ error: 'Invalid duration' });
        const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 50);
        const now = Math.floor(Date.now() / 1000);
        const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
        const keys = [];
        for (let i = 0; i < qty; i++) {
          const keyId = generateKeyId(brandConfig.prefix);
          await fbPut(brandConfig.path + keyId, {
            hwid: '',
            expires_at: 0,
            duration_days: dur,
            active: true,
            created_at: now,
            created_by: user.id,
            created_by_name: user.nickname || user.username || 'Admin',
          });
          keys.push(keyId);
        }
        await auditLog('generateKeys', user, { brand, duration: dur, quantity: qty, keys, ip, source: 'admin_panel' }, req);
        // DISCORD SECURITY WEBHOOK — real-time alert on key generation
        try {
          const alertWebhook = process.env.SECURITY_WEBHOOK_URL;
          if (alertWebhook) {
            await fetch(alertWebhook, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                embeds: [{
                  title: '\u{1F511} Admin Keys Generated',
                  color: 0x00FF00,
                  fields: [
                    { name: 'Admin', value: `${user.nickname || user.username}\n\`${user.id}\``, inline: true },
                    { name: 'Brand', value: brand, inline: true },
                    { name: 'Quantity', value: String(qty), inline: true },
                    { name: 'Duration', value: dur === 99999 ? 'Lifetime' : dur + ' days', inline: true },
                    { name: 'IP', value: '`' + ip + '`', inline: true },
                  ],
                  footer: { text: 'Key Security Monitor' },
                  timestamp: new Date().toISOString(),
                }],
              }),
            });
          }
        } catch (e) { /* webhook failure should not block */ }
        return res.json({ success: true, keys, message: qty + ' key(s) generated' });
      }

      case 'addTime': {
        const { keyId, days } = req.body;
        const path = resolveKeyPath(keyId);
        if (!path) return res.status(400).json({ error: 'Invalid keyId format' });
        const extraDays = parseInt(days);
        if (!extraDays || extraDays < 1 || extraDays > 3650) return res.status(400).json({ error: 'Invalid days (1-3650)' });
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
        const extraDays = parseInt(days);
        if (!extraDays || extraDays < 1 || extraDays > 3650) return res.status(400).json({ error: 'Invalid days (1-3650)' });
        
        const targetBrands = bulkBrand === 'all' ? Object.keys(BRANDS) : (isValidBrandId(bulkBrand) ? [bulkBrand] : []);
        if (targetBrands.length === 0) return res.status(400).json({ error: 'Invalid brand' });

        // Validate filter
        const validFilters = ['all', 'active', 'bound', 'unbound'];
        if (!validFilters.includes(filter)) return res.status(400).json({ error: 'Invalid filter' });

        let count = 0;
        for (const bId of targetBrands) {
          const data = await fbGet(BRANDS[bId].path);
          if (!data || typeof data !== 'object') continue;
          for (const [keyId, k] of Object.entries(data)) {
            if (!k || typeof k !== 'object') continue;
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
