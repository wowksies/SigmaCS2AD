// api/admin-action.js
// Admin actions — operates on correct Firebase paths per brand

const crypto = require('crypto');

const BRANDS = {
  voltaris:         { path: '/keys/voltaris/' },
  projectservices:  { path: '/keys/projectservices/' },
  corvus:           { path: '/keys/corvus/' },
  omnis:            { path: '/keys/omnis/' },
};

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

async function fbPatch(path, data) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error(`Firebase PATCH failed: ${r.status}`);
  return r.json();
}

async function fbDelete(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url, { method: 'DELETE' });
  if (!r.ok) throw new Error(`Firebase DELETE failed: ${r.status}`);
}

async function fbGet(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Firebase GET failed: ${r.status}`);
  return r.json();
}

// keyId format: "brandId/KEYSTRING" e.g. "omnis/OMNIS-XXXX-XXXX-XXXX-XXXX"
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

  const token = getCookie(req, 'omnis_reseller');
  const payload = token ? verifyJWT(token) : null;
  if (!payload || !payload.isAdmin) {
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

      default:
        return res.status(400).json({ error: 'Unknown action: ' + action });
    }

  } catch (error) {
    console.error('Admin Action Error:', error);
    return res.status(500).json({ error: 'Action failed', detail: error.message });
  }
};
