// api/auth-check.js — Quick session validity check
// Returns 200 if session is valid, 401 if not.
// Used by admin.html and dashboard.html to kick out unauthenticated visitors.
const { resolveUser } = require('../lib/auth-helper');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

  const user = await resolveUser(req, { requireOrigin: false });
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  return res.status(200).json({
    authenticated: true,
    isAdmin: user.isAdmin,
    isReseller: user.isReseller,
    suspended: user.suspended,
  });
};
