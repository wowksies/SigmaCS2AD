// api/user.js — Combined user endpoint (status in one)
const {
  resolveClientUser, fbGet,
} = require('./user-auth-helper');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const { action } = req.query;

  if (action === 'status') {
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

    const user = await resolveClientUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    try {
      const now = Math.floor(Date.now() / 1000);
      const result = {
        userId: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
        key: null,
      };

      if (user.activeKey && user.activeKey.keyId) {
        const keyData = await fbGet(`/keys/omnis/${user.activeKey.keyId}`);

        if (keyData) {
          const isLifetime = (keyData.duration_days >= 99999);
          let secondsLeft = 0;
          let status = 'active';

          if (isLifetime) {
            secondsLeft = -1;
            status = 'active';
          } else if (keyData.expires_at > 0) {
            secondsLeft = keyData.expires_at - now;
            if (secondsLeft <= 0) {
              status = 'expired';
              secondsLeft = 0;
            }
          }

          if (keyData.active === false) {
            status = 'disabled';
          }

          result.key = {
            keyId: user.activeKey.keyId,
            status: status,
            durationDays: keyData.duration_days || 0,
            isLifetime: isLifetime,
            activatedAt: user.activeKey.activatedAt || keyData.activatedAt || 0,
            expiresAt: keyData.expires_at || 0,
            secondsLeft: secondsLeft,
            daysLeft: isLifetime ? -1 : Math.max(0, Math.ceil(secondsLeft / 86400)),
            hoursLeft: isLifetime ? -1 : Math.max(0, Math.ceil(secondsLeft / 3600)),
            hwid: keyData.hwid || '',
          };
        } else {
          result.key = {
            keyId: user.activeKey.keyId,
            status: 'not_found',
          };
        }
      }

      return res.status(200).json(result);

    } catch (error) {
      console.error('User status error:', error);
      return res.status(500).json({ error: 'Failed to fetch status' });
    }
  }

  return res.status(400).json({ error: 'Invalid action. Use: status' });
};
