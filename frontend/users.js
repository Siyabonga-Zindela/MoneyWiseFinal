(function () {
  'use strict';

  /* ------------------------------------------------------------------
   * SETTINGS - wired to the real MoneyWise backend.
   * Stakeholders are real accounts (STAKEHOLDER role + org profile) managed
   * through /api/v1/admin/stakeholders; mwAuth.fetch handles the JWT and
   * the session. There is no mail provider yet, so create/resend return a
   * one-time temporary password which the toast shows for secure handover.
   * ------------------------------------------------------------------ */
  var API = {
    list:    '/api/v1/admin/stakeholders',
    create:  '/api/v1/admin/stakeholders',
    item:    function (id) { return '/api/v1/admin/stakeholders/' + encodeURIComponent(id); },
    resend:  function (id) { return '/api/v1/admin/stakeholders/' + encodeURIComponent(id) + '/resend'; },
    summary: '/api/v1/admin/summary'
  };
  var LOGIN_PAGE = 'admin-login.html';
  var PAGE_SIZE = 8;

  var TYPES = {
    bank: 'Bank or financial institution', telco: 'Mobile network operator', regulator: 'Regulator',
    police: 'Law enforcement', consumer: 'Consumer protection body', other: 'Other'
  };
  var ACCESS = { view: 'View only', review: 'Reviewer' };
  var ACCESS_HINT = {
    view: 'Can see reports but cannot change anything.',
    review: 'Can see reports, change their status and add notes.'
  };
  var ALERTS = { none: 'None', high: 'High risk', all: 'All reports' };
  var STATUS = { active: 'Active', invited: 'Invitation pending', suspended: 'Suspended' };
  var FREE_MAIL = /@(gmail|yahoo|hotmail|outlook|live|icloud|proton|protonmail|mweb|webmail)\./i;

  /* ---------- Data layer: the only part that talks to a server ---------- */
  function guard(res) {
    if (res.status === 401 || res.status === 403) { window.location.href = LOGIN_PAGE; return new Promise(function () {}); }
    if (!res.ok) throw new Error('request failed');
    return res;
  }
  function json(method, body) {
    return { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  }
  var data = {
    list: function () {
      return mwAuth.fetch(API.list).then(guard).then(function (r) { return r.json(); });
    },
    waiting: function () {
      return mwAuth.fetch(API.summary).then(guard).then(function (r) { return r.json(); })
        .then(function (s) { return s.new_reports; });
    },
    create: function (u) {
      return mwAuth.fetch(API.create, json('POST', u)).then(guard).then(function (r) { return r.json(); });
    },
    update: function (id, patch) {
      return mwAuth.fetch(API.item(id), json('PATCH', patch)).then(guard).then(function () { return patch; });
    },
    remove: function (id) {
      return mwAuth.fetch(API.item(id), { method: 'DELETE' }).then(guard);
    },
    resend: function (id) {
      return mwAuth.fetch(API.resend(id), { method: 'POST' }).then(guard).then(function (r) { return r.json(); });
    }
  };

  /* ---------- State and helpers ---------- */
  var users = [];
  var f = { q: '', type: '', status: '' };
  var page = 1;
  var editing = null;      // the stakeholder being managed, or null when adding
  var opener = null;

  var $ = function (id) { return document.getElementById(id); };
  function make(tag, cls, text) {   // user-supplied text is only ever written with textContent
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function fmtDate(iso) {
    if (!iso) return 'Never';
    var d = new Date(iso + 'T00:00:00');
    return isNaN(d) ? iso : d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
  }
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.hidden = true; }, 3500);
  }
  function setErr(input, msg) {
    var el = $(input.id + '-error');
    el.textContent = msg || ''; el.hidden = !msg;
    if (msg) { input.setAttribute('aria-invalid', 'true'); input.setAttribute('aria-describedby', el.id); }
    else { input.removeAttribute('aria-invalid'); input.removeAttribute('aria-describedby'); }
  }

  /* ---------- Rendering ---------- */
  function filtered() {
    var q = f.q.trim().toLowerCase();
    return users.filter(function (u) {
      if (f.type && u.org_type !== f.type) return false;
      if (f.status && u.status !== f.status) return false;
      if (q && (u.name + ' ' + u.email + ' ' + u.organisation).toLowerCase().indexOf(q) === -1) return false;
      return true;
    }).sort(function (a, b) { return a.name.localeCompare(b.name); });
  }

  function renderStats() {
    function n(s) { return users.filter(function (u) { return u.status === s; }).length; }
    $('stat-total').textContent = users.length;
    $('stat-active').textContent = n('active');
    $('stat-invited').textContent = n('invited');
    $('stat-suspended').textContent = n('suspended');
  }

  function renderTable() {
    var list = filtered();
    var pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    if (page > pages) page = pages;
    var start = (page - 1) * PAGE_SIZE;
    var slice = list.slice(start, start + PAGE_SIZE);

    var body = $('rows'); body.textContent = '';
    slice.forEach(function (u) {
      var tr = make('tr');
      var tdName = make('td', 'cell-name'); tdName.appendChild(make('strong', '', u.name)); tdName.appendChild(make('span', '', u.email));
      var tdOrg = make('td', 'cell-org', u.organisation); tdOrg.appendChild(make('span', '', TYPES[u.org_type] || u.org_type));
      var tdAcc = make('td'); tdAcc.appendChild(make('span', 'badge badge-' + u.access, ACCESS[u.access] || u.access));
      var tdAlert = make('td', '', ALERTS[u.alerts] || u.alerts);
      var tdStat = make('td'); tdStat.appendChild(make('span', 'badge badge-' + u.status, STATUS[u.status] || u.status));
      var tdLast = make('td', '', fmtDate(u.last_active));
      var tdAct = make('td');
      var b = make('button', 'review-btn', 'Manage'); b.type = 'button';
      b.setAttribute('aria-label', 'Manage ' + u.name);
      b.addEventListener('click', function () { openPanel(u, b); });
      tdAct.appendChild(b);
      [tdName, tdOrg, tdAcc, tdAlert, tdStat, tdLast, tdAct].forEach(function (td) { tr.appendChild(td); });
      body.appendChild(tr);
    });

    $('empty').hidden = list.length !== 0;
    $('pager-info').textContent = list.length
      ? 'Showing ' + (start + 1) + ' to ' + (start + slice.length) + ' of ' + list.length + ' stakeholders'
      : '0 stakeholders';
    $('prev-btn').disabled = page <= 1;
    $('next-btn').disabled = page >= pages;
  }

  function renderAll() { renderStats(); renderTable(); }

  function renderWaiting(n) {
    $('waiting-count').textContent = n;
    $('waiting-text').textContent = n === 1 ? 'new report is waiting for review' : 'new reports are waiting for review';
    $('waiting-link').hidden = n === 0;
  }

  /* ---------- Panel ---------- */
  function fillSelects() {
    var opts = Object.keys(TYPES).map(function (k) { var o = document.createElement('option'); o.value = k; o.textContent = TYPES[k]; return o; });
    opts.forEach(function (o) { $('s-type').appendChild(o); });
    var ft = $('f-type');
    Object.keys(TYPES).forEach(function (k) { var o = document.createElement('option'); o.value = k; o.textContent = TYPES[k]; ft.appendChild(o); });
  }

  function emailHint() {
    var v = $('s-email').value;
    var h = $('s-email-hint');
    if (FREE_MAIL.test(v)) { h.textContent = 'This looks like a personal address. Use a work email so the organisation stays in control of the account.'; h.hidden = false; }
    else h.hidden = true;
  }

  function openPanel(user, trigger) {
    editing = user || null;
    opener = trigger;
    ['s-name', 's-email', 's-org'].forEach(function (id) { setErr($(id), ''); });
    $('confirm-box').hidden = true;
    $('s-email-hint').hidden = true;

    var add = !user;
    $('panel-title').textContent = add ? 'Add stakeholder' : user.name;
    $('panel-kicker').textContent = add ? 'New external user' : user.organisation;
    $('panel-intro').textContent = add
      ? 'We email them an invitation to set up their own password. Never share a password with them.'
      : 'Update what this stakeholder can see and how they are notified.';
    $('save-btn').textContent = add ? 'Send invitation' : 'Save changes';

    $('s-name').value = add ? '' : user.name;
    $('s-email').value = add ? '' : user.email;
    $('s-email').readOnly = !add;                      // changing an email means inviting a new person
    $('s-org').value = add ? '' : user.organisation;
    $('s-type').value = add ? 'bank' : user.org_type;
    $('s-access').value = add ? 'view' : user.access;  // least access by default
    $('s-alerts').value = add ? 'none' : user.alerts;
    $('s-access-hint').textContent = ACCESS_HINT[$('s-access').value];

    $('manage-box').hidden = add;
    if (!add) refreshManage();

    $('panel-overlay').hidden = false;
    document.documentElement.style.overflow = 'hidden';
    $('panel').focus();
  }

  function refreshManage() {
    var u = editing;
    var s = $('m-status'); s.className = 'badge badge-' + u.status; s.textContent = STATUS[u.status] || u.status;
    $('m-last').textContent = u.last_active ? 'Last active ' + fmtDate(u.last_active) : 'Has not signed in yet';
    $('suspend-btn').textContent = u.status === 'suspended' ? 'Reactivate access' : 'Suspend access';
    $('suspend-btn').hidden = false;
    $('resend-btn').hidden = u.status !== 'invited';
  }

  function closePanel() {
    $('panel-overlay').hidden = true;
    document.documentElement.style.overflow = '';
    editing = null;
    if (opener && document.contains(opener)) opener.focus();
  }

  function validate() {
    var ok = true, first = null;
    function bad(input, msg) { setErr(input, msg); ok = false; if (!first) first = input; }
    var name = $('s-name'), email = $('s-email'), org = $('s-org');

    if (!name.value.trim()) bad(name, 'Enter the full name.'); else setErr(name, '');
    var e = email.value.trim().toLowerCase();
    if (!e) bad(email, 'Enter the work email address.');
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) bad(email, 'Enter a valid email address.');
    else if (!editing && users.some(function (u) { return u.email.toLowerCase() === e; })) bad(email, 'A stakeholder with this email already exists.');
    else setErr(email, '');
    if (!org.value.trim()) bad(org, 'Enter the organisation name.'); else setErr(org, '');

    if (first) first.focus();
    return ok;
  }

  function busy(btn, on, label) { btn.disabled = on; if (label) btn.textContent = label; }

  /* ---------- Events ---------- */
  function bind() {
    function onFilter() {
      f.q = $('f-search').value; f.type = $('f-type').value; f.status = $('f-status').value;
      page = 1; renderTable();
    }
    $('f-search').addEventListener('input', onFilter);
    $('f-type').addEventListener('change', onFilter);
    $('f-status').addEventListener('change', onFilter);
    $('reset-btn').addEventListener('click', function () {
      $('f-search').value = ''; $('f-type').value = ''; $('f-status').value = ''; onFilter();
    });
    $('prev-btn').addEventListener('click', function () { page--; renderTable(); });
    $('next-btn').addEventListener('click', function () { page++; renderTable(); });
    $('add-btn').addEventListener('click', function (e) { openPanel(null, e.currentTarget); });

    $('s-email').addEventListener('input', function () { setErr($('s-email'), ''); emailHint(); });
    $('s-name').addEventListener('input', function () { setErr($('s-name'), ''); });
    $('s-org').addEventListener('input', function () { setErr($('s-org'), ''); });
    $('s-access').addEventListener('change', function () { $('s-access-hint').textContent = ACCESS_HINT[$('s-access').value]; });

    $('panel-close').addEventListener('click', closePanel);
    $('cancel-btn').addEventListener('click', closePanel);
    $('panel-overlay').addEventListener('mousedown', function (e) { if (e.target === $('panel-overlay')) closePanel(); });
    $('panel-overlay').addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { e.preventDefault(); closePanel(); return; }
      if (e.key !== 'Tab') return;
      var nodes = Array.prototype.filter.call(
        $('panel').querySelectorAll('button, select, textarea, input'),
        function (n) { return !n.disabled && n.offsetParent !== null; });
      if (!nodes.length) return;
      var first = nodes[0], last = nodes[nodes.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === $('panel'))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });

    // Add or save
    $('user-form').addEventListener('submit', function (e) {
      e.preventDefault();
      if (!validate()) return;
      var fields = {
        name: $('s-name').value.trim(), email: $('s-email').value.trim().toLowerCase(),
        organisation: $('s-org').value.trim(), org_type: $('s-type').value,
        access: $('s-access').value, alerts: $('s-alerts').value
      };
      var btn = $('save-btn'), label = btn.textContent;
      busy(btn, true, 'Saving...');

      var job = editing
        ? data.update(editing.id, { name: fields.name, organisation: fields.organisation, org_type: fields.org_type, access: fields.access, alerts: fields.alerts })
            .then(function () { Object.assign(editing, fields, { email: editing.email }); return 'Changes saved.'; })
        : data.create(fields).then(function (created) {
            users.push(created);
            // No mail provider yet: the API returns a one-time temporary
            // password so the admin can hand it over over a safe channel.
            if (created.temporary_password) {
              return 'Invitation created for ' + fields.email + '. Temporary password: ' +
                created.temporary_password + ' (share it securely - it is shown once).';
            }
            return 'Invitation sent to ' + fields.email + '.';
          });

      job.then(function (msg) { renderAll(); closePanel(); toast(msg); })
         .catch(function () { toast('Could not save. Please try again.'); })
         .then(function () { busy(btn, false, label); });
    });

    // Suspend / reactivate
    $('suspend-btn').addEventListener('click', function () {
      var u = editing; if (!u) return;
      var next = u.status === 'suspended' ? (u.last_active ? 'active' : 'invited') : 'suspended';
      var btn = $('suspend-btn'); busy(btn, true);
      data.update(u.id, { status: next }).then(function () {
        u.status = next; renderAll(); refreshManage();
        toast(next === 'suspended' ? u.name + ' can no longer sign in.' : 'Access restored for ' + u.name + '.');
      }).catch(function () { toast('Could not update. Please try again.'); })
        .then(function () { busy(btn, false); });
    });

    // Resend invitation
    $('resend-btn').addEventListener('click', function () {
      var u = editing; if (!u) return;
      var btn = $('resend-btn'); busy(btn, true);
      data.resend(u.id).then(function (fresh) {
        var msg = 'Invitation sent again to ' + u.email + '.';
        if (fresh && fresh.temporary_password) {
          msg = 'New temporary password for ' + u.email + ': ' + fresh.temporary_password + ' (shown once).';
          Object.assign(u, { status: fresh.status });
          renderAll(); refreshManage();
        }
        toast(msg);
      })
        .catch(function () { toast('Could not send. Please try again.'); })
        .then(function () { busy(btn, false); });
    });

    // Remove (two steps)
    $('remove-btn').addEventListener('click', function () {
      if (!editing) return;
      $('confirm-text').textContent = 'Remove ' + editing.name + '? They will lose access straight away.';
      $('confirm-box').hidden = false;
      $('confirm-no').focus();
    });
    $('confirm-no').addEventListener('click', function () { $('confirm-box').hidden = true; $('remove-btn').focus(); });
    $('confirm-yes').addEventListener('click', function () {
      var u = editing; if (!u) return;
      var btn = $('confirm-yes'); busy(btn, true);
      data.remove(u.id).then(function () {
        users = users.filter(function (x) { return x.id !== u.id; });
        renderAll(); closePanel(); toast(u.name + ' was removed.');
      }).catch(function () { toast('Could not remove. Please try again.'); })
        .then(function () { busy(btn, false); });
    });

    $('signout-btn').addEventListener('click', function () {
      mwAuth.logout();
    });
  }

  fillSelects();
  bind();
  // Page guard: no session or not an ADMIN -> straight to the login page.
  if (mwAuth.requireRole(['ADMIN'])) {
    data.waiting().then(renderWaiting).catch(function () { $('waiting-link').hidden = true; });
    data.list().then(function (list) { users = list; renderAll(); })
      .catch(function () { $('empty').textContent = 'We could not load the stakeholders. Refresh the page to try again.'; $('empty').hidden = false; });
  }
})();