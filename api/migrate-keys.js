// api/migrate-keys.js — ONE-TIME migration: adds status/boundToUser fields to existing Omnis keys
// Call this ONCE after deploying, then DELETE this file.
// Usage: POST /api/migrate-keys (requires admin reseller auth)
const { resolveUser } = require('./auth-helper');

async function fbGet(path) {
  const url = `${process.env.DATABASE_URL}${path}.json?auth=${process.env.DATABASE_KEY}`;
  const r = await fetch(url);
  if (!r.ok) return null;
  return r.json();
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

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Must be admin
  const user = await resolveUser(req);
  if (!user || !user.isAdmin) {
    return res.status(401).json({ error: 'Admin only' });
  }

  try {
    const keys = await fbGet('/keys/omnis');
    if (!keys || typeof keys !== 'object') {
      return res.status(200).json({ message: 'No Omnis keys found to migrate', migrated: 0 });
    }

    const now = Math.floor(Date.now() / 1000);
    let migrated = 0;
    let skipped = 0;
    const updates = [];

    for (const [keyId, data] of Object.entries(keys)) {
      if (!data || typeof data !== 'object') { skipped++; continue; }

      // Already has status field — skip
      if (data.status) { skipped++; continue; }

      let status = 'unused';
      let boundToUser = null;
      let activatedAt = 0;

      // If HWID is set, key was already activated
      if (data.hwid && data.hwid !== '') {
        status = 'activated';
        activatedAt = data.created_at || 0;

        // Check if expired
        if (data.duration_days < 99999 && data.expires_at > 0 && data.expires_at < now) {
          status = 'expired';
        }
      }

      updates.push(
        fbPatch(`/keys/omnis/${keyId}`, {
          status: status,
          boundToUser: boundToUser,
          activatedAt: activatedAt,
        })
      );
      migrated++;
    }

    // Run all updates in parallel
    await Promise.all(updates);

    return res.status(200).json({
      success: true,
      message: `Migration complete: ${migrated} keys migrated, ${skipped} skipped`,
      migrated,
      skipped,
      totalKeys: Object.keys(keys).length,
    });

  } catch (error) {
    console.error('Migration error:', error);
    return res.status(500).json({ error: 'Migration failed: ' + error.message });
  }
};
