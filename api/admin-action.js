// api/admin-action.js
// Admin actions: confirm payment, suspend reseller, exclude key, set deadline

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

async function fbGet(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Firebase GET failed: ${r.status}`);
  return r.json();
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

      // ── Confirm a payment claim ──
      case 'confirmPayment': {
        const { paymentId } = req.body;
        if (!paymentId) return res.status(400).json({ error: 'Missing paymentId' });
        await fbPatch(`/payments/${paymentId}`, {
          confirmedByAdmin: true,
          confirmedAt: Date.now(),
        });
        return res.json({ success: true, message: 'Payment confirmed' });
      }

      // ── Reject/delete a payment claim ──
      case 'rejectPayment': {
        const { paymentId } = req.body;
        if (!paymentId) return res.status(400).json({ error: 'Missing paymentId' });
        await fbDelete(`/payments/${paymentId}`);
        return res.json({ success: true, message: 'Payment rejected and removed' });
      }

      // ── Suspend a reseller (deactivates all their keys) ──
      case 'suspendReseller': {
        const { resellerId } = req.body;
        if (!resellerId) return res.status(400).json({ error: 'Missing resellerId' });
        
        await fbPatch(`/resellers/${resellerId}`, { suspended: true });
        
        // Deactivate all their keys
        const allKeys = await fbGet('/keys') || {};
        const updates = {};
        Object.entries(allKeys).forEach(([id, k]) => {
          if (k.resellerId === resellerId) {
            updates[`/keys/${id}/active`] = false;
          }
        });
        // Apply all key deactivations
        for (const [path, val] of Object.entries(updates)) {
          await fbPatch(path.replace(/\/[^/]+$/, ''), { [path.split('/').pop()]: val });
        }

        return res.json({ success: true, message: 'Reseller suspended and keys deactivated' });
      }

      // ── Unsuspend a reseller (reactivates their keys) ──
      case 'unsuspendReseller': {
        const { resellerId } = req.body;
        if (!resellerId) return res.status(400).json({ error: 'Missing resellerId' });
        
        await fbPatch(`/resellers/${resellerId}`, { suspended: false });

        // Reactivate all their keys
        const allKeys2 = await fbGet('/keys') || {};
        for (const [id, k] of Object.entries(allKeys2)) {
          if (k.resellerId === resellerId) {
            await fbPatch(`/keys/${id}`, { active: true });
          }
        }

        return res.json({ success: true, message: 'Reseller unsuspended and keys reactivated' });
      }

      // ── Exclude a key from payment tracking ──
      case 'excludeKey': {
        const { keyId } = req.body;
        if (!keyId) return res.status(400).json({ error: 'Missing keyId' });
        await fbPatch(`/keys/${keyId}`, { excluded: true });
        return res.json({ success: true, message: 'Key excluded from payment tracking' });
      }

      // ── Include a key back in payment tracking ──
      case 'includeKey': {
        const { keyId } = req.body;
        if (!keyId) return res.status(400).json({ error: 'Missing keyId' });
        await fbPatch(`/keys/${keyId}`, { excluded: false });
        return res.json({ success: true, message: 'Key included in payment tracking' });
      }

      // ── Deactivate a specific key ──
      case 'deactivateKey': {
        const { keyId } = req.body;
        if (!keyId) return res.status(400).json({ error: 'Missing keyId' });
        await fbPatch(`/keys/${keyId}`, { active: false });
        return res.json({ success: true, message: 'Key deactivated' });
      }

      // ── Activate a specific key ──
      case 'activateKey': {
        const { keyId } = req.body;
        if (!keyId) return res.status(400).json({ error: 'Missing keyId' });
        await fbPatch(`/keys/${keyId}`, { active: true });
        return res.json({ success: true, message: 'Key activated' });
      }

      // ── Set payment deadline for a reseller ──
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
