(function () {
  'use strict';

  /* ------------------------------------------------------------------
   * SETTINGS - wired to the real MoneyWise backend.
   * Every call goes through mwAuth.fetch (shared helper): it attaches the
   * JWT bearer token, refreshes an expired token once, and sends you to
   * the login page when the session is over. The backend enforces the
   * ADMIN role on every /api/v1/admin request.
   * ------------------------------------------------------------------ */
  var API = {
    list: '/api/v1/admin/reports',
    update: function (id) { return '/api/v1/admin/reports/' + encodeURIComponent(id); },
    forward: function (id) { return '/api/v1/admin/reports/' + encodeURIComponent(id) + '/forward'; },
    stakeholders: '/api/v1/admin/stakeholders'
  };
  var LOGIN_PAGE = 'admin-login.html';
  var PAGE_SIZE = 8;

  var RISK = { high: 'High', medium: 'Medium', low: 'Low', unsure: 'Not sure' };
  var STATUS = { new: 'New', reviewing: 'Reviewing', confirmed: 'Confirmed scam', dismissed: 'Dismissed' };
  var money = new Intl.NumberFormat('en-ZA', { style: 'currency', currency: 'ZAR', maximumFractionDigits: 0 });

  /* ---------- Data layer: the only part that talks to a server ---------- */
  function loadReports() {
    return mwAuth.fetch(API.list).then(function (res) {
      if (res.status === 401 || res.status === 403) { window.location.href = LOGIN_PAGE; return new Promise(function () {}); }
      if (!res.ok) throw new Error('load failed');
      return res.json();
    });
  }
  function loadStakeholders() {
    return mwAuth.fetch(API.stakeholders).then(function (res) {
      if (!res.ok) throw new Error('stakeholders failed');
      return res.json();
    }).catch(function () { return []; });  // empty list just hides the dropdown options
  }
  function forwardReport(id, payload) {
    return mwAuth.fetch(API.forward(id), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      if (res.status === 401 || res.status === 403) { window.location.href = LOGIN_PAGE; return new Promise(function () {}); }
      if (!res.ok) throw new Error('forward failed');
      return res.json();
    });
  }
  function saveReport(id, patch) {
    return mwAuth.fetch(API.update(id), {
      method: 'PATCH',
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
  var stakeholders = [];
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
      if (r.repeat_count >= 1) {
        tdSender.appendChild(make('span', 'chip-repeat',
          '· reported ' + (r.repeat_count === 1 ? 'once' : r.repeat_count + '×') + ' before'));
      }
      var tdRisk = make('td'); tdRisk.appendChild(badge('risk', r.risk_level, RISK[r.risk_level] || r.risk_level));
      var tdAsked = make('td', 'num', fmtMoney(r.amount_asked));
      var tdStatus = make('td');
      tdStatus.appendChild(badge('status', r.status, STATUS[r.status] || r.status));
      if ((r.forwarded_to || []).length) {
        var seenAll = r.forwarded_to.every(function (x) { return x.acknowledged; });
        tdStatus.appendChild(make('span', 'chip-forward',
          '· sent to ' + r.forwarded_to.map(function (x) { return x.organisation; }).join(', ') +
          (seenAll ? ' ✓' : '')));
      }
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

    renderRepeat(r);
    renderForwards(r);
    fillStakeholderSelect(r);
    $('f-note').value = '';
    setForwardError('');

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

  /* ---------- Repeat scam signal + stakeholder forwarding ---------- */
  function renderRepeat(r) {
    var wrap = $('p-repeat-wrap'), text = $('p-repeat');
    if (r.repeat_count >= 1) {
      text.textContent = 'This sender or provider matches ' + r.repeat_count +
        (r.repeat_count === 1 ? ' other report' : ' other reports') +
        ' already in the system - treat as a repetitive scam pattern.';
      wrap.hidden = false;
    } else {
      text.textContent = '';
      wrap.hidden = true;
    }
  }

  function setForwardError(message) {
    var el = $('f-error');
    el.textContent = message;
    el.hidden = !message;
  }

  /* Word-boundary match of a stakeholder's organisation name against the
     report - powers the "likely impersonated" suggestion in the dropdown. */
  function organisationMentions(hay, org) {
    if (!hay || !org || org.trim().length < 3) return false;
    try {
      var pattern = new RegExp('(^|[^a-z0-9])' + org.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^a-z0-9]|$)', 'i');
      return pattern.test(hay);
    } catch (e) { return false; }
  }

  function fillStakeholderSelect(r) {
    var sel = $('f-stake');
    sel.textContent = '';
    var placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = stakeholders.length ? 'Choose an organisation\u2026' : 'No stakeholders yet - add them on the Stakeholders page';
    sel.appendChild(placeholder);

    var haystack = (r.message || '') + ' ' + (r.phishing_type || '') + ' ' + (r.sender || '');
    var alreadySent = (r.forwarded_to || []).map(function (x) { return x.stakeholder_id; });

    stakeholders.forEach(function (s) {
      if (s.status === 'suspended') return;
      var opt = document.createElement('option');
      opt.value = String(s.id);
      var label = s.organisation + ' (' + s.name + ', ' + s.email + ')';
      if (organisationMentions(haystack, s.organisation)) label += ' - likely impersonated';
      if (alreadySent.indexOf(s.id) !== -1) label += ' - already sent';
      opt.textContent = label;
      sel.appendChild(opt);
    });

    // Pre-select the first organisation the report actually mentions.
    for (var i = 0; i < stakeholders.length; i++) {
      var s = stakeholders[i];
      if (s.status !== 'suspended' && organisationMentions(haystack, s.organisation)) {
        sel.value = String(s.id);
        break;
      }
    }
  }

  function renderForwards(r) {
    var box = $('forwarded-list');
    var list = r.forwarded_to || [];
    box.textContent = '';
    if (!list.length) { box.hidden = true; return; }
    list.forEach(function (x) {
      var p = make('p', 'forward-item', '');
      var when = x.sent_at ? new Date(x.sent_at) : null;
      var line = 'Sent to ' + x.organisation;
      if (when && !isNaN(when)) {
        line += ' on ' + when.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short' });
      }
      line += x.acknowledged ? ' \u2713 received' : ' \u00b7 not yet acknowledged';
      p.textContent = line;
      if (x.note) {
        var note = make('span', 'cell-sub', 'Note: ' + x.note);
        p.appendChild(document.createElement('br'));
        p.appendChild(note);
      }
      box.appendChild(p);
    });
    box.hidden = false;
  }

  function submitForward() {
    var r = reports.find(function (x) { return x.id === openId; });
    if (!r) return;
    var sel = $('f-stake');
    setForwardError('');
    if (!sel.value) {
      setForwardError(stakeholders.length
        ? 'Choose the organisation being impersonated first.'
        : 'No stakeholders exist yet. Add them under Stakeholders.');
      return;
    }
    var btn = $('forward-btn');
    btn.disabled = true;
    var label = btn.textContent;
    btn.textContent = 'Sending...';
    forwardReport(r.id, {
      stakeholder_user_id: Number(sel.value),
      note: $('f-note').value.trim() || null
    }).then(function (data) {
      if (data && data.report) {
        var i = reports.findIndex(function (x) { return x.id === r.id; });
        if (i !== -1) reports[i] = data.report;
        renderAll();
        renderForwards(data.report);
        renderRepeat(data.report);
        fillStakeholderSelect(data.report);
      }
      $('f-note').value = '';
      toast(data && data.detail ? data.detail : 'Report sent.');
    }).catch(function () {
      setForwardError('Could not send the report. Please try again.');
    }).finally(function () {
      btn.disabled = false;
      btn.textContent = label;
    });
  }

  /* ---------- CSV export (guards against spreadsheet formula injection) ---------- */
  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function exportCsv() {
    var head = ['ID', 'Date received', 'Phishing type', 'Sender', 'Repeat count', 'Risk', 'Status', 'Sent to', 'Amount asked', 'Amount promised', 'Message'];
    var rows = filtered().map(function (r) {
      return [r.id, r.date_received, r.phishing_type, r.sender, r.repeat_count || 0, RISK[r.risk_level], STATUS[r.status],
        (r.forwarded_to || []).map(function (x) { return x.organisation + (x.acknowledged ? ' (received)' : ''); }).join('; '),
        r.amount_asked, r.amount_promised, r.message];
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
      saveReport(r.id, patch).then(function (updated) {
        // The PATCH response carries fresh repeat/forward data as well.
        if (updated && updated.id) {
          var i = reports.findIndex(function (x) { return x.id === r.id; });
          if (i !== -1) reports[i] = updated;
        } else {
          r.status = patch.status; r.note = patch.note;
        }
        renderAll(); closePanel(); toast('Report #' + r.id + ' updated.');
      }).catch(function () {
        toast('Could not save. Please try again.');
      }).then(function () { btn.disabled = false; });
    });

    $('forward-btn').addEventListener('click', submitForward);

    $('signout-btn').addEventListener('click', function () {
      mwAuth.logout();
    });
  }

  bind();
  // Page guard: no session or not an ADMIN -> straight to the login page.
  if (mwAuth.requireRole(['ADMIN'])) {
    loadReports().then(function (data) {
      reports = data;
      renderTypes(); renderAll();
    }).catch(function () {
      $('empty').textContent = 'We could not load the reports. Refresh the page to try again.';
      $('empty').hidden = false;
    });
    // Stakeholder dropdown for the forward action (silently empty if none).
    loadStakeholders().then(function (list) { stakeholders = list || []; });
  }
})();