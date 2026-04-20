// api/verify.js
// Vercel serverless function — verifies SellAuth order then sets a signed cookie

const crypto = require('crypto');
const { fetchSellAuthJson, invoiceMatchesConfiguredProduct } = require('./sellauth-helper');

const SELLAUTH_SHOP_ID = process.env.SELLAUTH_SHOP_ID;
const COOKIE_SECRET    = process.env.COOKIE_SECRET;      // random string you generate

function sign(orderId) {
    return crypto
    .createHmac('sha256', COOKIE_SECRET)
    .update(orderId)
    .digest('hex');
}

module.exports = async function handler(req, res) {
    const { order_id } = req.query;

    // No order ID — kick them back home
    if (!order_id) {
        return res.redirect(302, '/');
    }

    try {
        // Ask SellAuth if this order is real and paid
        const invoice = await fetchSellAuthJson(`/shops/${SELLAUTH_SHOP_ID}/invoices/${order_id}`);

        // Check it's paid and for the right product
        const isPaid    = invoice?.status === 'completed';
        const isProduct = invoiceMatchesConfiguredProduct(invoice);

        if (!isPaid || !isProduct) {
            return res.redirect(302, '/?error=invalid');
        }

        // All good — set a signed cookie valid for 24 hours
        const sig     = sign(order_id);
        const payload = Buffer.from(JSON.stringify({ order_id, sig })).toString('base64');
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toUTCString();

        res.setHeader('Set-Cookie',
                      `omnis_access=${payload}; Path=/; Expires=${expires}; HttpOnly; Secure; SameSite=Lax`
        );
        return res.redirect(302, '/thankyou.html');

    } catch (err) {
        console.error('Verify error:', err);
        return res.redirect(302, '/?error=server');
    }
};
