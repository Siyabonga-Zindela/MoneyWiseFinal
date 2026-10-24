(function () {
  'use strict';
 
  /* ------------------------------------------------------------------
   * SETTINGS
   * DEMO_MODE shows made-up sample reports so you can try the screen.
   * Set it to false and point the URLs below at your backend when it
   * is ready. The server must check the admin session on every request.
   * ------------------------------------------------------------------ */
  var DEMO_MODE = true;
  var API = {
    list: '/api/admin/reports',
    update: function (id) { return '/api/admin/reports/' + encodeURIComponent(id); },
    logout: '/api/admin/logout'
  };
  var LOGIN_PAGE = 'admin-login.html';
  var PAGE_SIZE = 8;
 
  var RISK = { high: 'High', medium: 'Medium', low: 'Low', unsure: 'Not sure' };
  var STATUS = { new: 'New', reviewing: 'Reviewing', confirmed: 'Confirmed scam', dismissed: 'Dismissed' };
  var money = new Intl.NumberFormat('en-ZA', { style: 'currency', currency: 'ZAR', maximumFractionDigits: 0 });
 
  /* ---------- Sample data (demo only) ---------- */
  function daysAgo(n) {
    var d = new Date(); d.setDate(d.getDate() - n);
    return d.toISOString().slice(0, 10);
  }
  function sampleReports() {
    var S = [
      ['Investment or pyramid scheme', '+27 71 555 0142', 'high', 1000, 5000, 'Invest Now! Invest R1000 and get a return of R5000 in 10 days. Get an extra R500 if you invite more than 3 people to also join.', 1, 'new'],
      ['WhatsApp or social media message', '+27 82 555 0178', 'high', 500, 2500, 'Join our WhatsApp stokvel. Pay R500 today and receive R2500 by Friday. Invite 5 friends for a bonus.', 2, 'new'],
      ['SMS phishing (smishing)', 'FNB-ALERTS', 'high', 0, 0, 'Your account is suspended. Verify now at fnb-secure-login.example to avoid closure.', 2, 'reviewing'],
      ['Fake website or link', 'cash-fast-loans.example', 'medium', 350, 0, 'Get a loan approved in 5 minutes. Pay a R350 admin fee first and the money is yours.', 3, 'confirmed'],
      ['Email phishing', 'support@capitec-help.example', 'high', 0, 0, 'We noticed unusual activity. Click the link and confirm your PIN to keep your account active.', 4, 'new'],
      ['Phone call (vishing)', '+27 11 555 0199', 'medium', 2000, 0, 'A caller said I won a prize but must pay R2000 in vouchers to release it.', 5, 'reviewing'],
      ['Investment or pyramid scheme', '@quick.returns.sa', 'high', 2500, 12500, 'Forex club: put in R2500 and we double it in a week. Recruit others to level up.', 6, 'new'],
      ['SMS phishing (smishing)', '+27 60 555 0113', 'low', 0, 0, 'Your parcel is waiting. Reschedule delivery using this link.', 7, 'dismissed'],
      ['WhatsApp or social media message', '+27 73 555 0166', 'high', 800, 4000, 'Ladies only savings group. R800 in, R4000 out in 14 days. Share with 3 friends.', 8, 'confirmed'],
      ['Email phishing', 'billing@streaming-help.example', 'medium', 0, 0, 'Your subscription payment failed. Update your card details here.', 9, 'new'],
      ['Fake website or link', 'bitcoin-doubler.example', 'high', 1500, 7500, 'Send R1500 in crypto and receive R7500 back. Limited slots, act now.', 10, 'new'],
      ['Phone call (vishing)', '+27 21 555 0121', 'unsure', 0, 0, 'Someone claiming to be from my bank asked me to read out a code sent by SMS.', 12, 'reviewing']
    ];
    return S.map(function (s, i) {
      return {
        id: 1001 + i, phishing_type: s[0], sender: s[1], risk_level: s[2],
        amount_asked: s[3], amount_promised: s[4], message: s[5],
        date_received: daysAgo(s[6]), submitted_at: daysAgo(Math.max(0, s[6] - 1)),
        status: s[7], note: '', screenshot_url: ''
      };
    });
  }
 
  /* ---------- Data layer: the only part that talks to a server ---------- */
  function loadReports() {
    if (DEMO_MODE) return Promise.resolve(sampleReports());
    return fetch(API.list, { credentials: 'same-origin' }).then(function (res) {
      if (res.status === 401 || res.status === 403) { window.location.href = LOGIN_PAGE; return new Promise(function () {}); }
      if (!res.ok) throw new Error('load failed');
      return res.json();
    });
  }
  function saveReport(id, patch) {
    if (DEMO_MODE) return Promise.resolve(patch);
    return fetch(API.update(id), {
      method: 'PATCH', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch)
    }).then(function (res) {
      if (res.status === 401 || res.status === 403) { window.location.href = LOGIN_PAGE; return new Promise(function () {}); }
      if (!res.ok) throw new Error('save failed');
      return patch;
    });
  }
 
  /* ---------- State ---------- */
  var reports = [];
  var f = { q: '', risk: '', status: '', type: '' };
  var sortDesc = true;
  var page = 1;
  var openId = null;
  var opener = null;
 
  var $ = function (id) { return document.getElementById(id); };
 
  // All report text comes from users, so it is only ever written with textContent.
  function make(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function badge(kind, value, label) {
    return make('span', 'badge badge-' + value, label);
  }
  function fmtDate(iso) {
    if (!iso) return 'Not given';
    var d = new Date(iso + 'T00:00:00');
    return isNaN(d) ? iso : d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
  }
  function fmtMoney(n) { return n > 0 ? money.format(n) : 'None'; }
 
  /* ---------- Filtering ---------- */
  function filtered() {
    var q = f.q.trim().toLowerCase();
    var list = reports.filter(function (r) {
      if (f.risk && r.risk_level !== f.risk) return false;
      if (f.status && r.status !== f.status) return false;
      if (f.type && r.phishing_type !== f.type) return false;
      if (q) {
        var hay = (r.message + ' ' + r.sender + ' ' + r.phishing_type + ' #' + r.id).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
    list.sort(function (a, b) {
      var c = a.date_received < b.date_received ? -1 : a.date_received > b.date_received ? 1 : a.id - b.id;
      return sortDesc ? -c : c;
    });
    return list;
  }
 
  /* ---------- Rendering ---------- */
  function renderStats() {
    $('stat-total').textContent = reports.length;
    $('stat-high').textContent = reports.filter(function (r) { return r.risk_level === 'high'; }).length;
    $('stat-new').textContent = reports.filter(function (r) { return r.status === 'new'; }).length;
    $('stat-money').textContent = money.format(reports.reduce(function (s, r) { return s + (r.amount_asked || 0); }, 0));
  }
 
  function renderTypes() {
    var sel = $('f-type');
    var types = Array.from(new Set(reports.map(function (r) { return r.phishing_type; }))).sort();
    sel.length = 1;
    types.forEach(function (t) { var o = document.createElement('option'); o.value = t; o.textContent = t; sel.appendChild(o); });
  }
 
  function renderTable() {
    var list = filtered();
    var pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    if (page > pages) page = pages;
    var start = (page - 1) * PAGE_SIZE;
    var slice = list.slice(start, start + PAGE_SIZE);
 
    var body = $('rows');
    body.textContent = '';
    slice.forEach(function (r) {
      var tr = make('tr');
      var tdDate = make('td', '', fmtDate(r.date_received));
      tdDate.appendChild(make('span', 'cell-sub', '#' + r.id));
      var tdType = make('td', '', r.phishing_type);
      var tdSender = make('td', 'cell-sender', r.sender || 'Not given');
      tdSender.title = r.sender || '';
      var tdRisk = make('td'); tdRisk.appendChild(badge('risk', r.risk_level, RISK[r.risk_level] || r.risk_level));
      var tdAsked = make('td', 'num', fmtMoney(r.amount_asked));
      var tdStatus = make('td'); tdStatus.appendChild(badge('status', r.status, STATUS[r.status] || r.status));
      var tdAct = make('td');
      var b = make('button', 'review-btn', 'Review');
      b.type = 'button';
      b.setAttribute('aria-label', 'Review report ' + r.id);
      b.addEventListener('click', function () { openPanel(r.id, b); });
      tdAct.appendChild(b);
      [tdDate, tdType, tdSender, tdRisk, tdAsked, tdStatus, tdAct].forEach(function (td) { tr.appendChild(td); });
      body.appendChild(tr);
    });
 
    $('empty').hidden = list.length !== 0;
    $('pager-info').textContent = list.length
      ? 'Showing ' + (start + 1) + ' to ' + (start + slice.length) + ' of ' + list.length + ' reports'
      : '0 reports';
    $('prev-btn').disabled = page <= 1;
    $('next-btn').disabled = page >= pages;
    $('sort-arrow').textContent = sortDesc ? '\u2193' : '\u2191';
  }
 
  function renderAll() { renderStats(); renderTable(); }
 
  /* ---------- Details panel ---------- */
  function openPanel(id, trigger) {
    var r = reports.find(function (x) { return x.id === id; });
    if (!r) return;
    openId = id; opener = trigger;
 
    $('panel-kicker').textContent = 'Report #' + r.id;
    var risk = $('p-risk'), st = $('p-status');
    risk.className = 'badge badge-' + r.risk_level; risk.textContent = (RISK[r.risk_level] || r.risk_level) + ' risk';
    st.className = 'badge badge-' + r.status; st.textContent = STATUS[r.status] || r.status;
    $('p-type').textContent = r.phishing_type;
    $('p-sender').textContent = r.sender || 'Not given';
    $('p-date').textContent = fmtDate(r.date_received);
    $('p-submitted').textContent = fmtDate(r.submitted_at);
    $('p-asked').textContent = fmtMoney(r.amount_asked);
    $('p-promised').textContent = fmtMoney(r.amount_promised);
    $('p-message').textContent = r.message;
 
    var url = r.screenshot_url || '';
    var okUrl = /^(https:\/\/|\/)/.test(url);       // never load javascript: or data: URLs
    $('p-shot-wrap').hidden = !okUrl;
    if (okUrl) $('p-shot').src = url; else $('p-shot').removeAttribute('src');
 
    $('r-status').value = r.status;
    $('r-note').value = r.note || '';
 
    $('panel-overlay').hidden = false;
    document.documentElement.style.overflow = 'hidden';
    $('panel').focus();
  }
 
  function closePanel() {
    $('panel-overlay').hidden = true;
    document.documentElement.style.overflow = '';
    openId = null;
    if (opener && document.contains(opener)) opener.focus();
  }
 
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.hidden = true; }, 3000);
  }
 
  /* ---------- CSV export (guards against spreadsheet formula injection) ---------- */
  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function exportCsv() {
    var head = ['ID', 'Date received', 'Phishing type', 'Sender', 'Risk', 'Status', 'Amount asked', 'Amount promised', 'Message'];
    var rows = filtered().map(function (r) {
      return [r.id, r.date_received, r.phishing_type, r.sender, RISK[r.risk_level], STATUS[r.status], r.amount_asked, r.amount_promised, r.message];
    });
    var csv = [head].concat(rows).map(function (row) { return row.map(csvCell).join(','); }).join('\r\n');
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' }));
    a.download = 'phishing-reports.csv';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
 
  /* ---------- Events ---------- */
  function bind() {
    function onFilter() {
      f.q = $('f-search').value; f.risk = $('f-risk').value; f.status = $('f-status').value; f.type = $('f-type').value;
      page = 1; renderTable();
    }
    ['f-search', 'f-risk', 'f-status', 'f-type'].forEach(function (id) {
      $(id).addEventListener(id === 'f-search' ? 'input' : 'change', onFilter);
    });
    $('reset-btn').addEventListener('click', function () {
      ['f-search', 'f-risk', 'f-status', 'f-type'].forEach(function (id) { $(id).value = ''; });
      onFilter();
    });
    $('export-btn').addEventListener('click', exportCsv);
    $('sort-date').addEventListener('click', function () { sortDesc = !sortDesc; page = 1; renderTable(); });
    $('prev-btn').addEventListener('click', function () { page--; renderTable(); });
    $('next-btn').addEventListener('click', function () { page++; renderTable(); });
 
    $('panel-close').addEventListener('click', closePanel);
    $('cancel-btn').addEventListener('click', closePanel);
    $('panel-overlay').addEventListener('mousedown', function (e) { if (e.target === $('panel-overlay')) closePanel(); });
    $('panel-overlay').addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { e.preventDefault(); closePanel(); return; }
      if (e.key !== 'Tab') return;
      var nodes = Array.prototype.filter.call(
        $('panel').querySelectorAll('button, select, textarea, input, [href]'),
        function (n) { return !n.disabled && n.offsetParent !== null; });
      if (!nodes.length) return;
      var first = nodes[0], last = nodes[nodes.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === $('panel'))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
 
    $('review-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var r = reports.find(function (x) { return x.id === openId; });
      if (!r) return;
      var patch = { status: $('r-status').value, note: $('r-note').value.trim() };
      var btn = $('save-btn');
      btn.disabled = true;
      saveReport(r.id, patch).then(function () {
        r.status = patch.status; r.note = patch.note;
        renderAll(); closePanel(); toast('Report #' + r.id + ' updated.');
      }).catch(function () {
        toast('Could not save. Please try again.');
      }).then(function () { btn.disabled = false; });
    });
 
    $('signout-btn').addEventListener('click', function () {
      if (DEMO_MODE) { window.location.href = LOGIN_PAGE; return; }
      fetch(API.logout, { method: 'POST', credentials: 'same-origin' })
        .catch(function () {})
        .then(function () { window.location.href = LOGIN_PAGE; });
    });
  }
 
  bind();
  loadReports().then(function (data) {
    reports = data;
    renderTypes(); renderAll();
  }).catch(function () {
    $('empty').textContent = 'We could not load the reports. Refresh the page to try again.';
    $('empty').hidden = false;
  });
})();