/*!
 * MoneyWise auth helper - shared by every signed-in page
 * (admin-dashboard, admin-users, externalStakeholder).
 *
 * The backend issues JWT bearer tokens (POST /api/v1/auth/login). This helper:
 *   - attaches "Authorization: Bearer <access_token>" to every request;
 *   - transparently refreshes once on 401 via the stored refresh token;
 *   - sends the visitor to the login page when the session really is over;
 *   - logs out through the real endpoint (revoking the refresh token).
 *
 * Storage keys are the ones admin-login.js writes:
 *   mw_access_token / mw_refresh_token / mw_user / mw_token_expires_at
 *
 * API base resolution (same rules as admin-login.js):
 *   window.MONEYWISE_API_BASE > localStorage 'mw_api_base' > same origin.
 */
(function () {
  'use strict';

  var LOGIN_PAGE = 'admin-login.html';

  function apiBase() {
    if (window.MONEYWISE_API_BASE) {
      return String(window.MONEYWISE_API_BASE).replace(/\/+$/, '');
    }
    try {
      var saved = localStorage.getItem('mw_api_base');
      if (saved) return saved.replace(/\/+$/, '');
    } catch (e) { /* storage unavailable - fall through */ }
    return '';
  }

  function token() {
    try { return localStorage.getItem('mw_access_token') || ''; } catch (e) { return ''; }
  }

  function storedUser() {
    try {
      var raw = localStorage.getItem('mw_user');
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  function clearStorage() {
    try {
      ['mw_access_token', 'mw_refresh_token', 'mw_user', 'mw_token_expires_at']
        .forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) { /* ignore */ }
  }

  function toLogin() {
    clearStorage();
    window.location.href = LOGIN_PAGE;
    // Park the promise chain: the page is going away.
    return new Promise(function () {});
  }

  function refreshTokens() {
    var refresh;
    try { refresh = localStorage.getItem('mw_refresh_token'); } catch (e) { refresh = null; }
    if (!refresh) return Promise.reject(new Error('no refresh token'));
    return fetch(apiBase() + '/api/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh })
    }).then(function (res) {
      if (!res.ok) throw new Error('refresh failed');
      return res.json();
    }).then(function (data) {
      try {
        localStorage.setItem('mw_access_token', data.access_token);
        localStorage.setItem('mw_refresh_token', data.refresh_token);
        localStorage.setItem('mw_token_expires_at', String(Date.now() + data.expires_in * 1000));
      } catch (e) { /* ignore */ }
      return data.access_token;
    });
  }

  /**
   * fetch() with the bearer token attached. On 401 the token pair is
   * refreshed once and the request retried; if that fails, login page.
   */
  function authFetch(url, options) {
    var opts = options || {};
    opts.headers = Object.assign({}, opts.headers);
    opts.headers['Authorization'] = 'Bearer ' + token();
    if (opts.headers['Content-Type'] === undefined && opts.body &&
        !(opts.body instanceof FormData)) {
      opts.headers['Content-Type'] = 'application/json';
    }
    opts.headers['Accept'] = 'application/json';

    return fetch(apiBase() + url, opts).then(function (res) {
      if (res.status !== 401) return res;
      return refreshTokens().then(function (fresh) {
        opts.headers['Authorization'] = 'Bearer ' + fresh;
        return fetch(apiBase() + url, opts);
      }).catch(function () {
        return toLogin();
      });
    });
  }

  /**
   * Page guard: if there is no session or the stored user lacks one of the
   * given roles, go to the login page. Returns the stored user or null.
   */
  function requireRole(allowedRoles) {
    var user = storedUser();
    if (!user || !token()) { toLogin(); return null; }
    var roles = user.roles || [];
    var ok = (allowedRoles || []).some(function (r) { return roles.indexOf(r) !== -1; });
    if (!ok) { toLogin(); return null; }
    return user;
  }

  /** Revoke the refresh token server-side, then clear + go to login. */
  function logout() {
    var refresh;
    try { refresh = localStorage.getItem('mw_refresh_token'); } catch (e) { refresh = null; }
    var opts = {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token(), 'Accept': 'application/json' }
    };
    if (refresh) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify({ refresh_token: refresh });
    }
    return fetch(apiBase() + '/api/v1/auth/logout', opts)
      .catch(function () { /* network down: clear locally anyway */ })
      .then(function () { clearStorage(); window.location.href = LOGIN_PAGE; });
  }

  window.mwAuth = {
    fetch: authFetch,
    logout: logout,
    requireRole: requireRole,
    apiBase: apiBase,
    clearStorage: clearStorage
  };
})();
