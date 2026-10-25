/*!
 * MoneyWise admin sign-in (wires up Admin-login.html).
 *
 * Talks to the FastAPI backend:
 *   POST {apiBase}/api/v1/auth/login  -> { access_token, refresh_token,
 *                                          expires_in, user: { roles, ... } }
 *
 * API base is resolved in this order:
 *   1. window.MONEYWISE_API_BASE   (set it before this script runs)
 *   2. localStorage "mw_api_base"  (handy during local development, e.g.
 *      localStorage.setItem('mw_api_base', 'http://127.0.0.1:8000'))
 *   3. same origin ("" -> relative URLs, for when the backend serves this page)
 *
 * On successful ADMIN sign-in the token pair is kept in localStorage
 * (mw_access_token / mw_refresh_token / mw_user / mw_token_expires_at) and the
 * browser is sent to the redirect target (form[data-redirect], default
 * "index.html" until a dedicated admin dashboard page exists).
 */
(function () {
  'use strict';

  var form = document.getElementById('login-form');
  var email = document.getElementById('email');
  var password = document.getElementById('password');
  var emailError = document.getElementById('email-error');
  var passwordError = document.getElementById('password-error');
  var capsHint = document.getElementById('caps-hint');
  var pwToggle = document.getElementById('pw-toggle');
  var submitBtn = document.getElementById('login-btn');
  var errorBox = document.getElementById('auth-error');
  var forgotLink = document.getElementById('forgot-link');

  var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  var SUBMIT_LABEL = submitBtn ? submitBtn.textContent : 'Sign in';

  function apiBase() {
    if (window.MONEYWISE_API_BASE) {
      return String(window.MONEYWISE_API_BASE).replace(/\/+$/, '');
    }
    try {
      var saved = localStorage.getItem('mw_api_base');
      if (saved) return saved.replace(/\/+$/, '');
    } catch (e) { /* storage unavailable (file://) - fall through */ }
    return '';
  }

  function store(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
  }

  function showError(message) {
    if (!errorBox) return;
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  function hideError() {
    if (errorBox) errorBox.hidden = true;
  }

  function setFieldError(input, errorEl, message) {
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.hidden = !message;
    }
    if (input) input.setAttribute('aria-invalid', message ? 'true' : 'false');
  }

  function validateEmail() {
    var value = email.value.trim();
    if (!value) {
      setFieldError(email, emailError, 'Enter your email address.');
      return false;
    }
    if (!EMAIL_RE.test(value)) {
      setFieldError(email, emailError, 'That does not look like a valid email address.');
      return false;
    }
    setFieldError(email, emailError, '');
    return true;
  }

  function validatePassword() {
    if (!password.value) {
      setFieldError(password, passwordError, 'Enter your password.');
      return false;
    }
    setFieldError(password, passwordError, '');
    return true;
  }

  function messageForStatus(status) {
    if (status === 401) return 'Invalid email or password.';
    if (status === 403) return 'Account is not active. Contact the MoneyWise team.';
    if (status === 423) return 'Account temporarily locked - try again later.';
    if (status === 429) return 'Too many attempts. Wait a minute and try again.';
    if (status >= 500) return 'The MoneyWise server had a problem. Try again shortly.';
    return 'Sign-in failed (HTTP ' + status + '). Please try again.';
  }

  function handleSuccess(data) {
    var user = data.user || {};
    var roles = user.roles || [];

    // Real role-based routing: the button that was pressed is only a hint;
    // where you land depends on what the account actually is.
    var isAdmin = roles.indexOf('ADMIN') !== -1;
    var isStakeholder = roles.indexOf('STAKEHOLDER') !== -1;
    if (!isAdmin && !isStakeholder) {
      // Do not keep unauthorised tokens on this admin/stakeholder page.
      password.value = '';
      showError('This sign-in page is for MoneyWise administrators and ' +
        'external stakeholders. Your account does not have that access.');
      return;
    }
    // Real role-based routing: where you land depends on what the account is.
    var target = isAdmin
      ? 'admin-dashboard.html'
      : (form.getAttribute('data-redirect-stakeholder') || 'externalStakeholder.html');

    store('mw_access_token', data.access_token);
    store('mw_refresh_token', data.refresh_token);
    store('mw_user', JSON.stringify(user));
    store('mw_token_expires_at', String(Date.now() + (data.expires_in || 0) * 1000));

    submitBtn.textContent = 'Signed in';
    hideError();

    window.setTimeout(function () { window.location.assign(target); }, 400);
  }

  function signIn(evt) {
    evt.preventDefault();
    hideError();

    var emailOk = validateEmail();
    var passwordOk = validatePassword();
    if (!emailOk) { email.focus(); return; }
    if (!passwordOk) { password.focus(); return; }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in...';

    fetch(apiBase() + '/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: email.value.trim(),
        password: password.value
      })
    }).then(function (resp) {
      if (!resp.ok) {
        // Try to surface the backend's own detail message where it is clearer.
        return resp.json().catch(function () { return null; }).then(function (body) {
          throw new Error(messageForStatus(resp.status) +
            (body && body.detail && resp.status >= 500 ? ' (' + body.detail + ')' : ''));
        });
      }
      return resp.json();
    }).then(function (data) {
      handleSuccess(data);
    }).catch(function (err) {
      if (err instanceof TypeError) {
        showError('Cannot reach the MoneyWise server. Check your connection, or point ' +
          'the page at the backend with localStorage.setItem(\'mw_api_base\', ' +
          '\'http://127.0.0.1:8000\').');
      } else {
        showError(err.message || 'Sign-in failed. Please try again.');
      }
    }).finally(function () {
      submitBtn.disabled = false;
      submitBtn.textContent = SUBMIT_LABEL;
      if (errorBox && !errorBox.hidden && document.activeElement !== errorBox) {
        password.focus();
      }
    });
  }

  // Show / hide password.
  if (pwToggle) {
    pwToggle.addEventListener('click', function () {
      var visible = password.type === 'text';
      password.type = visible ? 'password' : 'text';
      pwToggle.textContent = visible ? 'Show' : 'Hide';
      pwToggle.setAttribute('aria-pressed', String(!visible));
      pwToggle.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
      password.focus();
    });
  }

  // Caps Lock warning while typing the password.
  function checkCaps(evt) {
    if (!capsHint) return;
    var on = evt.getModifierState && evt.getModifierState('CapsLock');
    capsHint.hidden = !on;
  }

  // Clear per-field errors as the user fixes them.
  if (email) {
    email.addEventListener('input', function () { setFieldError(email, emailError, ''); });
  }
  if (password) {
    password.addEventListener('input', function () { setFieldError(password, passwordError, ''); });
    password.addEventListener('keydown', checkCaps);
    password.addEventListener('keyup', checkCaps);
    password.addEventListener('blur', function () { capsHint.hidden = true; });
  }

  // No self-service reset exists yet - explain instead of dead-ending.
  if (forgotLink) {
    forgotLink.addEventListener('click', function (evt) {
      evt.preventDefault();
      showError('Password resets are handled by the MoneyWise team. ' +
        'Ask an administrator to unlock or reset your account.');
    });
  }

  if (form) {
    form.addEventListener('submit', signIn);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      var late = document.getElementById('login-form');
      if (late) late.addEventListener('submit', signIn);
    });
  }
})();
