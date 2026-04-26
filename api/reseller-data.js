const { resolveUser, fbGet } = require('../lib/auth-helper');
const {
  BRANDS,
  formatMoney,
  getDurationEntries,
  getKeyFinancials,
  getResellerPricingProfile,
} = require('../lib/pricing-helper');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const user = await resolveUser(req);
  if (!user || (!user.isReseller && !user.isAdmin)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const profile = await fbGet(`/resellers/${user.id}`) || {};
    const userBrands = user.isAdmin ? Object.keys(BRANDS) : (user.brands || []);
    const accessibleBrands = userBrands.filter((brandId) => Object.prototype.hasOwnProperty.call(BRANDS, brandId));

    const allKeys = [];
    for (const brandId of accessibleBrands) {
      const brand = BRANDS[brandId];
      const data = await fbGet(brand.path);
      if (!data || typeof data !== 'object') continue;

      Object.entries(data).forEach(([keyId, keyRecord]) => {
        if (!keyRecord || typeof keyRecord !== 'object') return;

        const activated = !!(keyRecord.hwid && keyRecord.hwid.length > 0);
        const financials = getKeyFinancials(keyRecord, profile, brandId, { useStoredPricing: user.isAdmin });
        const isAdminKey = keyRecord.is_admin === true;
        const owedAmountValue = activated && !keyRecord.excluded && !isAdminKey ? financials.owedAmount : 0;

        allKeys.push({
          id: brandId + '/' + keyId,
          key: keyId,
          brand: brand.name,
          brandId,
          brandColor: brand.color,
          durationDays: financials.durationDays,
          planLabel: financials.planLabel,
          price: financials.unitPrice,
          cutRate: financials.cutRate,
          cutPercent: financials.cutPercent,
          owedAmount: formatMoney(owedAmountValue),
          owedAmountValue,
          active: keyRecord.active !== false,
          hwid: keyRecord.hwid || '',
          activated,
          expiresAt: keyRecord.expires_at || 0,
          createdAt: keyRecord.created_at || 0,
          excluded: keyRecord.excluded || false,
          createdBy: keyRecord.created_by || '',
          createdByName: keyRecord.created_by_name || '',
          isAdminKey,
        });
      });
    }

    const myKeys = allKeys;
    myKeys.sort((a, b) => b.createdAt - a.createdAt);

    const allPayments = await fbGet('/payments') || {};
    const myPayments = [];
    Object.entries(allPayments).forEach(([id, payment]) => {
      if (payment && payment.resellerId === user.id) {
        myPayments.push({ id, ...payment });
      }
    });

    const activatedKeys = myKeys.filter((key) => key.activated && !key.excluded && !key.isAdminKey);
    const totalOwed = activatedKeys.reduce((sum, key) => sum + key.owedAmountValue, 0);
    const totalPaid = myPayments
      .filter((payment) => payment.confirmedByAdmin)
      .reduce((sum, payment) => sum + (parseFloat(payment.amount) || 0), 0);

    const pricingProfile = getResellerPricingProfile(profile);
    const pricingBrands = {};
    accessibleBrands.forEach((brandId) => {
      pricingBrands[brandId] = {
        name: BRANDS[brandId].name,
        color: BRANDS[brandId].color,
        prices: pricingProfile.brandPrices[brandId],
      };
    });

    return res.status(200).json({
      reseller: {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
        nickname: user.nickname,
      },
      stats: {
        totalKeys: myKeys.length,
        activatedKeys: activatedKeys.length,
        unusedKeys: myKeys.filter((key) => !key.activated).length,
        totalOwed: formatMoney(totalOwed),
        totalPaid: formatMoney(totalPaid),
        balance: formatMoney(Math.max(0, totalOwed - totalPaid)),
        suspended: profile.suspended || false,
        paymentDeadline: profile.paymentDeadline || null,
      },
      keys: myKeys.slice(0, 200).map((key) => ({
        ...key,
        price: formatMoney(key.price),
      })),
      payments: myPayments.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 50),
      paymentMethods: {
        paypal: 'paypal.me/kayazskrdens',
        bitcoin: 'bc1qx68swgpyapa03tka8q6yaf9w03g6tshfrjqskc',
        litecoin: 'LbBLPFSzeXYYXxf7YD2B8SqcxTAc9Rk1u1',
      },
      userBrands: accessibleBrands,
      pricing: {
        cutRate: pricingProfile.cutRate,
        cutPercent: pricingProfile.cutPercent,
        brands: pricingBrands,
        durations: getDurationEntries(),
      },
    });
  } catch (error) {
    console.error('Reseller Data Error:', error);
    return res.status(500).json({ error: 'Failed to fetch data' });
  }
};
