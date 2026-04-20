const { resolveUser, fbGet } = require('./auth-helper');
const {
  BRANDS,
  formatMoney,
  getDurationEntries,
  getKeyFinancials,
  getResellerPricingProfile,
} = require('./pricing-helper');

function getKeyStatus(key) {
  if (!key.active) return 'Disabled';
  if (key.expiresAt && key.expiresAt > 0 && Math.floor(Date.now() / 1000) > key.expiresAt) {
    return 'Expired';
  }
  return 'Active';
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  const user = await resolveUser(req);
  if (!user || !user.isAdmin) {
    return res.status(401).json({ error: 'Admin only' });
  }

  try {
    const [allResellers, allPayments] = await Promise.all([
      fbGet('/resellers'),
      fbGet('/payments'),
    ]);

    const resellerMap = allResellers && typeof allResellers === 'object' ? allResellers : {};
    const resellersArr = Object.entries(resellerMap).map(([id, reseller]) => ({ id, ...reseller }));
    const paymentsArr = allPayments ? Object.entries(allPayments).map(([id, payment]) => ({ id, ...payment })) : [];

    const allKeys = [];
    const brandStats = {};

    for (const [brandId, brand] of Object.entries(BRANDS)) {
      const data = await fbGet(brand.path);
      let brandTotal = 0;
      let brandActive = 0;
      let brandBound = 0;

      if (data && typeof data === 'object') {
        Object.entries(data).forEach(([keyId, keyRecord]) => {
          if (!keyRecord || typeof keyRecord !== 'object') return;

          const creatorProfile = keyRecord.created_by && resellerMap[keyRecord.created_by]
            ? resellerMap[keyRecord.created_by]
            : null;
          const financials = getKeyFinancials(keyRecord, creatorProfile, brandId);
          const activated = !!(keyRecord.hwid && keyRecord.hwid.length > 0);
          const isAdminKey = keyRecord.is_admin === true;
          const owedAmountValue = activated && !keyRecord.excluded && !isAdminKey ? financials.owedAmount : 0;
          const keyData = {
            id: brandId + '/' + keyId,
            key: keyId,
            brand: brand.name,
            brandId,
            brandColor: brand.color,
            brandEmoji: brand.emoji,
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
          };

          keyData.status = getKeyStatus(keyData);
          allKeys.push(keyData);
          brandTotal++;
          if (keyData.active && keyData.status !== 'Expired') brandActive++;
          if (activated) brandBound++;
        });
      }

      brandStats[brandId] = {
        name: brand.name,
        emoji: brand.emoji,
        color: brand.color,
        total: brandTotal,
        active: brandActive,
        bound: brandBound,
      };
    }

    allKeys.sort((a, b) => b.createdAt - a.createdAt);

    const activatedKeys = allKeys.filter((key) => key.activated && !key.excluded && !key.isAdminKey);
    const totalRevenue = activatedKeys.reduce((sum, key) => sum + key.owedAmountValue, 0);
    const totalPaid = paymentsArr
      .filter((payment) => payment.confirmedByAdmin)
      .reduce((sum, payment) => sum + (parseFloat(payment.amount) || 0), 0);

    const resellerStats = resellersArr.map((reseller) => {
      const resellerPayments = paymentsArr.filter((payment) => payment.resellerId === reseller.id);
      const resellerPaid = resellerPayments
        .filter((payment) => payment.confirmedByAdmin)
        .reduce((sum, payment) => sum + (parseFloat(payment.amount) || 0), 0);
      const pendingPayments = resellerPayments.filter((payment) => !payment.confirmedByAdmin);
      const resellerKeys = allKeys.filter((key) => key.createdBy === reseller.id && key.activated && !key.excluded && !key.isAdminKey);
      const resellerOwed = resellerKeys.reduce((sum, key) => sum + key.owedAmountValue, 0);
      const pricingProfile = getResellerPricingProfile(reseller);

      return {
        id: reseller.id,
        username: reseller.username || 'Unknown',
        avatar: reseller.avatar || null,
        brands: reseller.brands || [],
        cutRate: pricingProfile.cutRate,
        cutPercent: pricingProfile.cutPercent,
        pricing: pricingProfile,
        totalOwed: formatMoney(resellerOwed),
        totalPaid: formatMoney(resellerPaid),
        balance: formatMoney(Math.max(0, resellerOwed - resellerPaid)),
        suspended: reseller.suspended || false,
        paymentDeadline: reseller.paymentDeadline || null,
        pendingPayments: pendingPayments.length,
        createdAt: reseller.createdAt,
      };
    });

    const pendingPayments = paymentsArr
      .filter((payment) => !payment.confirmedByAdmin)
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
      .map((payment) => ({
        id: payment.id,
        resellerId: payment.resellerId,
        resellerName: payment.resellerName || resellerMap[payment.resellerId]?.username || 'Unknown',
        amount: payment.amount,
        method: payment.method,
        note: payment.note || '',
        createdAt: payment.createdAt,
      }));

    let recentLogs = [];
    try {
      for (const [brandId, brand] of Object.entries(BRANDS)) {
        const logData = await fbGet('/protection_logs/' + brandId);
        if (!logData || typeof logData !== 'object') continue;
        Object.entries(logData).forEach(([, entry]) => {
          if (!entry || typeof entry !== 'object' || !(entry.created_at || entry.event)) return;
          recentLogs.push({ ...entry, brand: brand.name, brandId, brandEmoji: brand.emoji });
        });
      }
    } catch (error) {
      // Protection logs are optional.
    }

    recentLogs.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    recentLogs = recentLogs.slice(0, 20);

    const pricingMeta = {
      durations: getDurationEntries(),
      brands: Object.fromEntries(
        Object.entries(BRANDS).map(([brandId, brand]) => [brandId, {
          name: brand.name,
          color: brand.color,
          emoji: brand.emoji,
        }])
      ),
    };

    return res.json({
      stats: {
        totalKeys: allKeys.length,
        totalActivated: activatedKeys.length,
        totalBound: allKeys.filter((key) => key.activated).length,
        totalActive: allKeys.filter((key) => key.active).length,
        totalRevenue: formatMoney(totalRevenue),
        totalPaid: formatMoney(totalPaid),
        outstandingBalance: formatMoney(Math.max(0, totalRevenue - totalPaid)),
        totalResellers: resellersArr.length,
      },
      brandStats,
      resellers: resellerStats,
      keys: allKeys.slice(0, 1000).map((key) => ({
        ...key,
        price: formatMoney(key.price),
      })),
      pendingPayments,
      recentLogs,
      pricingMeta,
    });
  } catch (error) {
    console.error('Admin Data Error:', error);
    return res.status(500).json({ error: 'Failed to fetch admin data', detail: error.message });
  }
};