// Supabase session helpers — shared by dashboard and any page that needs auth
(function () {
  const SUPABASE_URL = 'https://euxtyzhcijdpueajvsvd.supabase.co';
  const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV1eHR5emhjaWpkcHVlYWp2c3ZkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzczMDkwNTcsImV4cCI6MjA5Mjg4NTA1N30._rARSmYe7Sp40dvccuL-A9ZSnD_BcdFTHX4SXtxxp88';
  const STORAGE_KEY = 'omnis_user';
  const REFRESH_BEFORE_SEC = 120; // refresh if <2 min left

  function readSession() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  function writeSession(s) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  }

  function clearSession() {
    localStorage.removeItem(STORAGE_KEY);
  }

  function nowSec() { return Math.floor(Date.now() / 1000); }

  function isExpiringSoon(session) {
    if (!session || !session.expires_at) return false;
    return (session.expires_at - nowSec()) < REFRESH_BEFORE_SEC;
  }

  let inFlight = null;

  async function refreshSession(session) {
    if (inFlight) return inFlight;
    if (!session || !session.refresh_token) return null;

    inFlight = (async () => {
      try {
        const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'apikey': SUPABASE_ANON_KEY,
          },
          body: JSON.stringify({ refresh_token: session.refresh_token }),
        });
        if (!r.ok) {
          clearSession();
          return null;
        }
        const data = await r.json();
        if (!data.access_token) {
          clearSession();
          return null;
        }
        const updated = {
          email: data.user ? data.user.email : session.email,
          id: data.user ? data.user.id : session.id,
          access_token: data.access_token,
          refresh_token: data.refresh_token || session.refresh_token,
          expires_at: data.expires_at || (nowSec() + (data.expires_in || 3600)),
        };
        writeSession(updated);
        return updated;
      } catch (e) {
        console.error('refresh failed', e);
        return null;
      } finally {
        inFlight = null;
      }
    })();

    return inFlight;
  }

  // Get a valid session, auto-refreshing if access_token is near expiry.
  async function getValidSession() {
    let session = readSession();
    if (!session || !session.access_token) return null;
    if (isExpiringSoon(session)) {
      const refreshed = await refreshSession(session);
      if (refreshed) return refreshed;
      return null;
    }
    return session;
  }

  // Authed fetch — adds Authorization header and retries once on 401 after refresh.
  async function authedFetch(url, opts) {
    opts = opts || {};
    let session = await getValidSession();
    if (!session) {
      window.location.href = '/login.html';
      throw new Error('No session');
    }
    opts.headers = Object.assign({}, opts.headers || {}, {
      'Authorization': 'Bearer ' + session.access_token,
    });
    let r = await fetch(url, opts);
    if (r.status === 401) {
      const refreshed = await refreshSession(session);
      if (!refreshed) {
        window.location.href = '/login.html';
        throw new Error('Session refresh failed');
      }
      opts.headers['Authorization'] = 'Bearer ' + refreshed.access_token;
      r = await fetch(url, opts);
    }
    return r;
  }

  // Periodic refresh — kicks every 60s, refreshes if within window.
  function startBackgroundRefresh() {
    setInterval(async () => {
      const s = readSession();
      if (s && isExpiringSoon(s)) await refreshSession(s);
    }, 60 * 1000);
  }

  window.OmnisSession = {
    read: readSession,
    write: writeSession,
    clear: clearSession,
    refresh: refreshSession,
    getValid: getValidSession,
    authedFetch: authedFetch,
    startBackgroundRefresh: startBackgroundRefresh,
  };
})();
