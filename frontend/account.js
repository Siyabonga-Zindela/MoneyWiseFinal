/*!
 * MoneyWise user account page (wires up account.html).
 *
 * Two tabs against the real backend:
 *   POST {apiBase}/api/v1/auth/register  -> 201 { access_token, refresh_token, user }
 *   POST {apiBase}/api/v1/auth/login     -> 200 { access_token, refresh_token, user }
 *
 * Storage keys are the SAME ones admin-login.js writes (mw_access_token /
 * mw_refresh_token / mw_user / mw_token_expires_at), so an account created
 * here is recognised everywhere the shared helper runs. Admin and stakeholder
 * accounts are routed to their own portals; regular users go back to the
 * homepage signed in.
 */
(function () {
  'use strict';

  var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  function $(id) { return document.getElementById(id); }

  var tabs = { signin: $('tab-signin'), signup: $('tab-signup') };
  var forms = { signin: $('signin-form'), signup: $('signup-form') };
  var errorBox = $('auth-error');
  var signedInBox = $('signedin-box');

  function apiBase() {
    if (window.MONEYWISE_API_BASE) return String(window.MONEYWISE_API_BASE).replace(/\/+$/, '');
    try {
      var saved = localStorage.getItem('mw_api_base');
      if (saved) return saved.replace(/\/+$/, '');
    } catch (e) { /* ignore */ }
    return '';
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }
  function hideError() { errorBox.hidden = true; }

  function fieldError(inputId, errorId, message) {
    var input = $(inputId), el = $(errorId);
    if (el) { el.textContent = message || ''; el.hidden = !message; }
    if (input) input.setAttribute('aria-invalid', message ? 'true' : 'false');
    return !message;
  }

  function clearFieldErrors() {
    fieldError('si-email', 'si-email-error', '');
    fieldError('si-password', 'si-password-error', '');
    fieldError('su-name', 'su-name-error', '');
    fieldError('su-email', 'su-email-error', '');
    fieldError('su-password', 'su-password-error', '');
  }

  ['si-email', 'si-password', 'su-name', 'su-email', 'su-password'].forEach(function (id) {
    var el = $(id);
    if (el) el.addEventListener('input', function () {
      var map = {
        'si-email': ['si-email', 'si-email-error'],
        'si-password': ['si-password', 'si-password-error'],
        'su-name': ['su-name', 'su-name-error'],
        'su-email': ['su-email', 'su-email-error'],
        'su-password': ['su-password', 'su-password-error']
      };
      fieldError(map[id][0], map[id][1], '');
    });
  });

  function selectTab(name) {
    Object.keys(tabs).forEach(function (key) {
      var on = key === name;
      tabs[key].classList.toggle('is-active', on);
      tabs[key].setAttribute('aria-selected', String(on));
      tabs[key].tabIndex = on ? 0 : -1;
      forms[key].hidden = !on;
    });
    hideError();
  }
  tabs.signin.addEventListener('click', function () { selectTab('signin'); });
  tabs.signup.addEventListener('click', function () { selectTab('signup'); });

  function store(data) {
    try {
      localStorage.setItem('mw_access_token', data.access_token);
      localStorage.setItem('mw_refresh_token', data.refresh_token);
      localStorage.setItem('mw_user', JSON.stringify(data.user || {}));
      localStorage.setItem('mw_token_expires_at', String(Date.now() + (data.expires_in || 0) * 1000));
    } catch (e) { /* storage unavailable */ }
  }

  /* Where each kind of account lands. */
  function targetFor(user) {
    var roles = (user && user.roles) || [];
    if (roles.indexOf('ADMIN') !== -1) return 'admin-dashboard.html';
    if (roles.indexOf('STAKEHOLDER') !== -1) return 'externalStakeholder.html';
    return 'index.html';
  }

  function success(data, btn, label) {
    store(data);
    hideError();
    btn.textContent = 'Done';
    var target = targetFor(data.user);
    window.setTimeout(function () { window.location.assign(target); }, 500);
  }

  function messageForStatus(status, detail) {
    if (status === 401) return 'Invalid email or password.';
    if (status === 403) return 'This account is not active. Contact the MoneyWise team.';
    if (status === 409) return 'An account with this email already exists - sign in instead.';
    if (status === 423) return 'Account temporarily locked - try again later.';
    if (status === 429) return 'Too many attempts. Wait a minute and try again.';
    if (status >= 500) return 'The MoneyWise server had a problem. Try again shortly.';
    if (detail) return String(detail);
    return 'Something went wrong (HTTP ' + status + '). Please try again.';
  }

  /* FastAPI validation errors arrive as a list of {loc, msg}; flatten them. */
  function detailText(body) {
    if (!body || body.detail === undefined) return '';
    var d = body.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) {
      return d.map(function (item) {
        var field = (item.loc || []).filter(function (p) { return p !== 'body'; }).join('.');
        return (field ? field + ': ' : '') + item.msg;
      }).join(' ');
    }
    return JSON.stringify(d);
  }

  function post(path, payload, btn, done) {
    btn.disabled = true;
    var original = btn.textContent;
    btn.textContent = 'Please wait...';
    fetch(apiBase() + path, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (body) {
        if (!res.ok) throw new Error(messageForStatus(res.status, detailText(body)));
        return body;
      });
    }).then(function (data) { done(data); })
      .catch(function (err) {
        if (err instanceof TypeError) {
          showError('Cannot reach the MoneyWise server. Check your connection, or point this page at the backend with localStorage.setItem(\'mw_api_base\', \'http://127.0.0.1:8000\').');
        } else {
          showError(err.message || 'Something went wrong. Please try again.');
        }
      })
      .finally(function () { btn.disabled = false; btn.textContent = original; });
  }

  forms.signin.addEventListener('submit', function (evt) {
    evt.preventDefault();
    hideError();
    var ok = fieldError('si-email', 'si-email-error',
      !$('si-email').value.trim() ? 'Enter your email address.'
        : (!EMAIL_RE.test($('si-email').value.trim()) ? 'That does not look like a valid email address.' : ''));
    ok = fieldError('si-password', 'si-password-error',
      !$('si-password').value ? 'Enter your password.' : '') && ok;
    if (!ok) return;
    post('/api/v1/auth/login', {
      email: $('si-email').value.trim(),
      password: $('si-password').value
    }, $('signin-btn'), function (data) { success(data, $('signin-btn')); });
  });

  forms.signup.addEventListener('submit', function (evt) {
    evt.preventDefault();
    hideError();
    var pw = $('su-password').value;
    var ok = fieldError('su-name', 'su-name-error',
      !$('su-name').value.trim() ? 'Enter your name so the team knows who to follow up with.' : '');
    ok = fieldError('su-email', 'su-email-error',
      !$('su-email').value.trim() ? 'Enter your email address.'
        : (!EMAIL_RE.test($('su-email').value.trim()) ? 'That does not look like a valid email address.' : '')) && ok;
    ok = fieldError('su-password', 'su-password-error',
      pw.length < 8 ? 'Use at least 8 characters.'
        : (!/[A-Z]/.test(pw) ? 'Add at least one uppercase letter.'
          : (!/[a-z]/.test(pw) ? 'Add at least one lowercase letter.'
            : (!/\d/.test(pw) ? 'Add at least one number.' : '')))) && ok;
    if (!ok) return;
    var payload = {
      email: $('su-email').value.trim(),
      password: pw,
      full_name: $('su-name').value.trim()
    };
    if ($('su-phone').value.trim()) payload.phone = $('su-phone').value.trim();
    post('/api/v1/auth/register', payload, $('signup-btn'), function (data) {
      success(data, $('signup-btn'));
    });
  });

  /* Already signed in? Show the signed-in state instead of the forms. */
  function currentUser() {
    try {
      var raw = localStorage.getItem('mw_user');
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }
  var user = currentUser();
  if (user && localStorage.getItem('mw_access_token')) {
    forms.signin.hidden = true;
    forms.signup.hidden = true;
    Object.keys(tabs).forEach(function (k) { tabs[k].hidden = true; });
    $('signedin-as').textContent = 'You are signed in as ' +
      (user.full_name || user.email) + ' (' + ((user.roles || []).join(', ') || 'member') + ').';
    signedInBox.hidden = false;
  }

  $('signout-btn').addEventListener('click', function () {
    var refresh = null;
    try { refresh = localStorage.getItem('mw_refresh_token'); } catch (e) { /* ignore */ }
    var opts = {
      method: 'POST',
      headers: { 'Accept': 'application/json' }
    };
    try {
      var token = localStorage.getItem('mw_access_token');
      if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    } catch (e) { /* ignore */ }
    if (refresh) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify({ refresh_token: refresh });
    }
    fetch(apiBase() + '/api/v1/auth/logout', opts).catch(function () { /* ignore */ })
      .then(function () {
        try {
          ['mw_access_token', 'mw_refresh_token', 'mw_user', 'mw_token_expires_at']
            .forEach(function (k) { localStorage.removeItem(k); });
        } catch (e) { /* ignore */ }
        window.location.reload();
      });
  });
})();
