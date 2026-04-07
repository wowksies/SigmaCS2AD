// api/reseller-logout.js
// Clears the token cookie and redirects to the main site

module.exports = function handler(req, res) {
  res.setHeader('Set-Cookie',
    'omnis_reseller=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict'
  );
  res.writeHead(302, { Location: '/' });
  return res.end();
};
