(function () {
  'use strict';
 
  /* ------------------------------------------------------------------
   * SETTINGS
   * DEMO_MODE lets you click through the screens before the backend exists:
   * any email + password is accepted. It is NOT secure. Set it to false
   * and fill in API_URL before this goes anywhere public.
   * ------------------------------------------------------------------ */
  var DEMO_MODE = true;
  var API_URL = '/api/admin/login';          // your backend sign-in endpoint
  var REDIRECT_TO = 'admin-dashboard.html';  // where to go after signing in
 
  var form = document.getElementById('login-form');
  var email = document.getElementById('email');
  var password = document.getElementById('password');
  var toggle = document.getElementById('pw-toggle');
  var caps = document.getElementById('caps-hint');
  var btn = document.getElementById('login-btn');
  var banner = document.getElementById('auth-error');
 
  // Testing aid: while DEMO_MODE is on, show a notice and let Sign in work with empty fields.
  if (DEMO_MODE) {
    var note = document.createElement('p');
    note.className = 'form-error';
    note.style.cssText = 'background:#fff6e5;border-color:#f3d29b;color:#a15c00';
    note.textContent = 'Test mode: sign-in is switched off. Click Sign in to open the dashboard without entering anything.';
    form.parentNode.insertBefore(note, form);
    email.required = false;
    password.required = false;
  }
 
  function setFieldError(input, msg) {
    var el = document.getElementById(input.id + '-error');
    el.textContent = msg || '';
    el.hidden = !msg;
    if (msg) { input.setAttribute('aria-invalid', 'true'); input.setAttribute('aria-describedby', el.id); }
    else { input.removeAttribute('aria-invalid'); input.removeAttribute('aria-describedby'); }
  }
 
  function showBanner(msg) {
    banner.textContent = msg || '';
    banner.hidden = !msg;
  }
 
  function validate() {
    var ok = true;
    var v = email.value.trim();
    if (!v) { setFieldError(email, 'Enter your email address.'); ok = false; }
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) { setFieldError(email, 'Enter a valid email address.'); ok = false; }
    else setFieldError(email, '');
 
    if (!password.value) { setFieldError(password, 'Enter your password.'); ok = false; }
    else setFieldError(password, '');
    return ok;
  }
 
  // Show / hide password
  toggle.addEventListener('click', function () {
    var show = password.type === 'password';
    password.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Hide' : 'Show';
    toggle.setAttribute('aria-pressed', String(show));
    toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    password.focus();
  });
 
  // Caps Lock hint
  function checkCaps(e) {
    if (e.getModifierState) caps.hidden = !e.getModifierState('CapsLock');
  }
  password.addEventListener('keydown', checkCaps);
  password.addEventListener('keyup', checkCaps);
  password.addEventListener('blur', function () { caps.hidden = true; });
 
  // Clear errors as the user types
  email.addEventListener('input', function () { setFieldError(email, ''); showBanner(''); });
  password.addEventListener('input', function () { setFieldError(password, ''); showBanner(''); });
 
  document.getElementById('forgot-link').addEventListener('click', function (e) {
    e.preventDefault();
    showBanner('Password reset is not set up yet. Contact the system owner.');
  });
 
  function signIn(emailValue, passwordValue) {
    if (DEMO_MODE) return Promise.resolve({ ok: true });
 
    return fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',          // lets the server set a secure session cookie
      body: JSON.stringify({ email: emailValue, password: passwordValue })
    }).then(function (res) {
      if (res.ok) return { ok: true };
      if (res.status === 429) return { ok: false, message: 'Too many attempts. Please wait a few minutes and try again.' };
      return { ok: false, message: 'Incorrect email or password.' };
    });
  }
 
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    showBanner('');
    if (DEMO_MODE) { window.location.href = REDIRECT_TO; return; }
    if (!validate()) {
      (email.getAttribute('aria-invalid') ? email : password).focus();
      return;
    }
 
    btn.disabled = true;
    btn.textContent = 'Signing in...';
 
    signIn(email.value.trim(), password.value)
      .then(function (result) {
        if (result.ok) { window.location.href = REDIRECT_TO; return; }
        showBanner(result.message);
        password.value = '';
        password.focus();
      })
      .catch(function () {
        showBanner('We could not reach the server. Check your connection and try again.');
      })
      .then(function () {
        btn.disabled = false;
        btn.textContent = 'Sign in';
      });
  });
})();