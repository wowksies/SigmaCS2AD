// api/reseller-logout.js
// Clears the omnis_reseller cookie and redirects the user back to the
// landing page. Triggered by the Log Out button on dashboard.html and
// admin.html (location.href = '/api/reseller-logout').

module.exports = async function handler(req, res) {
    // Expire cookie immediately. Match the attributes used at issue time
    // so browsers actually overwrite the cookie.
    res.setHeader(
        'Set-Cookie',
        'omnis_reseller=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    );
    res.writeHead(302, { Location: '/' });
    res.end();
};
