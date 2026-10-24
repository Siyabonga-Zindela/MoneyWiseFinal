/*!
 * MoneyWise report popup (self-contained).
 * Injects its own styles and markup, so it works even if the rest of your
 * HTML/CSS is out of date. Add ONE line before </body>:
 *   <script src="report-popup.js" defer></script>
 * Any button with id="report-btn", a data-report attribute, or the text
 * "Report this" will open it.
 */
(function () {
  'use strict';

  var STYLE_ID = 'mw-report-style';
  var overlay, panel, form, success, opener;

  var CSS = `
  .mw-overlay{position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;justify-content:center;padding:1rem;background:rgba(15,26,54,.55);font-family:var(--font,"Space Grotesk","Segoe UI",system-ui,Arial,sans-serif);color:var(--ink,#0f1a36)}
  .mw-overlay[hidden]{display:none}
  .mw-panel{width:100%;max-width:36rem;max-height:calc(100vh - 2rem);overflow:auto;background:var(--surface,#fff);border:1px solid var(--line,#cfd7e8);border-radius:18px;box-shadow:0 24px 60px rgba(15,26,54,.28)}
  .mw-head{position:sticky;top:0;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1.15rem 1.5rem;background:var(--surface,#fff);border-bottom:1px solid var(--line,#cfd7e8)}
  .mw-head h2{margin:0;font-size:1.35rem;font-weight:700;letter-spacing:-.01em}
  .mw-x{display:grid;place-items:center;width:2.5rem;height:2.5rem;border:1px solid var(--line,#cfd7e8);border-radius:10px;background:var(--surface,#fff);cursor:pointer}
  .mw-x svg{width:1.1rem;height:1.1rem;fill:none;stroke:#3d4a66;stroke-width:2;stroke-linecap:round}
  .mw-body{padding:1.25rem 1.5rem 1.5rem}
  .mw-intro{margin:0 0 1.25rem;font-size:.95rem;color:#3d4a66}
  .mw-group{margin-bottom:1rem}
  .mw-row{display:grid;gap:0 1rem}
  @media(min-width:520px){.mw-row{grid-template-columns:1fr 1fr}}
  .mw-label{display:block;margin-bottom:.6rem;font-weight:700;font-size:.95rem}
  .mw-opt{font-weight:400;color:#5b6784}
  .mw-field{display:block;width:100%;box-sizing:border-box;padding:.85rem 1rem;border:1px solid var(--line,#cfd7e8);border-radius:12px;background:var(--field,#f4f6fb);font:inherit;font-size:1rem;color:inherit}
  .mw-field:focus{outline:none;border-color:var(--red,#dc2a1c);box-shadow:0 0 0 3px rgba(220,42,28,.18)}
  textarea.mw-field{min-height:6.5rem;resize:vertical;line-height:1.45}
  select.mw-field{min-height:3rem}
  .mw-money{position:relative}
  .mw-money span{position:absolute;left:1rem;top:50%;transform:translateY(-50%);color:#5b6784;pointer-events:none}
  .mw-money .mw-field{padding-left:2rem}
  .mw-file{padding:.55rem .6rem;font-size:.9rem}
  .mw-file::file-selector-button{margin-right:.75rem;padding:.45rem .9rem;border:1px solid var(--line,#cfd7e8);border-radius:8px;background:#fff;color:#3d4a66;font:inherit;cursor:pointer}
  .mw-hint{margin:.5rem 0 0;font-size:.85rem;color:#5b6784}
  .mw-actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1.5rem}
  .mw-btn{min-height:3rem;padding:0 1.6rem;border:1px solid transparent;border-radius:12px;font:inherit;font-size:.95rem;cursor:pointer}
  .mw-primary{background:var(--red,#dc2a1c);color:#fff;font-weight:700}
  .mw-primary:hover{background:var(--red-dark,#b21f14)}
  .mw-outline{background:#fff;border-color:var(--line,#cfd7e8);color:#3d4a66}
  .mw-outline:hover{border-color:#5b6784}
  .mw-success{display:grid;justify-items:center;gap:.75rem;padding:2.5rem 1.5rem;text-align:center}
  .mw-success[hidden]{display:none}
  .mw-success svg{width:3rem;height:3rem;fill:none;stroke:#1a7f4b;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
  .mw-success h3{margin:0;font-size:1.5rem}
  .mw-success p{max-width:28rem;margin:0 0 .75rem;color:#3d4a66}
  .mw-panel :focus-visible{outline:3px solid #8fb0ff;outline-offset:2px}
  @media(max-width:480px){.mw-btn{flex:1 1 100%}}
  `;

  var HTML = `
  <div class="mw-panel" role="dialog" aria-modal="true" aria-labelledby="mw-title">
    <div class="mw-head">
      <h2 id="mw-title">Report a phishing attempt</h2>
      <button type="button" class="mw-x" data-mw-close aria-label="Close report form"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </div>
    <form class="mw-body" novalidate>
      <p class="mw-intro">Your report helps us warn other people. Do not include your PIN, password or ID number.</p>
      <div class="mw-group"><label class="mw-label" for="mw-type">Phishing type <small style="color: #6b7280;"> (How did you receive it?)</small></label>
        <input class="mw-field" id="mw-type" name="phishing_type" list="mw-types" placeholder="Type or choose" autocomplete="off" required>
        <datalist id="mw-types"><option value="Email phishing"><option value="SMS phishing (smishing)"><option value="WhatsApp or social media message"><option value="Fake website or link"><option value="Phone call (vishing)"><option value="Investment or pyramid scheme"></datalist></div>
      <div class="mw-group"><label class="mw-label" for="mw-message">Message</label>
        <textarea class="mw-field" id="mw-message" name="message" rows="4" placeholder="Paste the message you received" required></textarea></div>
      <div class="mw-row">
        <div class="mw-group"><label class="mw-label" for="mw-risk">Risk level</label>
          <select class="mw-field" id="mw-risk" name="risk_level" required><option value="high" selected>High risk</option><option value="medium">Medium risk</option><option value="low">Low risk</option><option value="unsure">Not sure</option></select></div>
        <div class="mw-group"><label class="mw-label" for="mw-date">Date received</label>
          <input class="mw-field" id="mw-date" name="date_received" type="date"></div>
      </div>
      <div class="mw-group"><label class="mw-label" for="mw-sender">Sender identifier</label>
        <input class="mw-field" id="mw-sender" name="sender" placeholder="Phone number, email, username or website" autocomplete="off"></div>
      <div class="mw-row">
        <div class="mw-group"><label class="mw-label" for="mw-asked">Amount asked for</label>
          <div class="mw-money"><span aria-hidden="true">R</span><input class="mw-field" id="mw-asked" name="amount_asked" type="number" min="0" step="0.01" inputmode="decimal" placeholder="0.00"></div></div>
        <div class="mw-group"><label class="mw-label" for="mw-promised">Amount promised</label>
          <div class="mw-money"><span aria-hidden="true">R</span><input class="mw-field" id="mw-promised" name="amount_promised" type="number" min="0" step="0.01" inputmode="decimal" placeholder="0.00"></div></div>
      </div>
      <div class="mw-group"><label class="mw-label" for="mw-shot">Screenshot <span class="mw-opt">(optional)</span></label>
        <input class="mw-field mw-file" id="mw-shot" name="screenshot" type="file" accept="image/*">
        <p class="mw-hint">PNG or JPG, up to 5 MB. Hide any personal details first.</p></div>
      <div class="mw-actions">
        <button type="submit" class="mw-btn mw-primary">Submit report</button>
        <button type="button" class="mw-btn mw-outline" data-mw-close>Cancel</button>
      </div>
    </form>
    <div class="mw-success" hidden>
      <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
      <h3>Thank you</h3>
      <p>Your report was received. It helps protect other people from the same scam.</p>
      <button type="button" class="mw-btn mw-primary" data-mw-close>Close</button>
    </div>
  </div>`;

  function build() {
    if (overlay) return;
    if (!document.getElementById(STYLE_ID)) {
      var s = document.createElement('style');
      s.id = STYLE_ID;
      s.textContent = CSS;
      document.head.appendChild(s);
    }
    overlay = document.createElement('div');
    overlay.className = 'mw-overlay';
    overlay.hidden = true;
    overlay.innerHTML = HTML;
    document.body.appendChild(overlay);

    panel = overlay.querySelector('.mw-panel');
    form = overlay.querySelector('form');
    success = overlay.querySelector('.mw-success');
    var shot = overlay.querySelector('#mw-shot');

    Array.prototype.forEach.call(overlay.querySelectorAll('[data-mw-close]'), function (b) {
      b.addEventListener('click', close);
    });
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) close(); });

    shot.addEventListener('change', function () {
      var f = shot.files[0];
      shot.setCustomValidity(f && f.size > 5 * 1024 * 1024 ? 'Please choose an image under 5 MB.' : '');
    });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (form.reportValidity && !form.reportValidity()) return;
      var data = new FormData(form);
      // TODO: send `data` to your backend, for example:
      // fetch('/api/reports', { method: 'POST', body: data });
      console.log('Report ready to send:', Array.from(data.entries()));
      form.hidden = true;
      success.hidden = false;
      success.querySelector('button').focus();
    });

    overlay.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key !== 'Tab') return;
      var f = Array.prototype.filter.call(
        panel.querySelectorAll('a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])'),
        function (el) { return !el.disabled && el.offsetParent !== null; }
      );
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  }

  function open(trigger) {
    build();
    opener = trigger;
    form.reset();
    form.hidden = false;
    success.hidden = true;

    var offer = document.getElementById('offer');          // text the user was checking
    if (offer) overlay.querySelector('#mw-message').value = offer.value;

    var d = new Date();
    d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
    var today = d.toISOString().slice(0, 10);
    var date = overlay.querySelector('#mw-date');
    date.max = today;
    date.value = today;

    overlay.hidden = false;
    document.documentElement.style.overflow = 'hidden';
    overlay.querySelector('#mw-type').focus();
  }

  function close() {
    if (!overlay) return;
    overlay.hidden = true;
    document.documentElement.style.overflow = '';
    if (opener && opener.focus) opener.focus();
  }

  // Event delegation: works no matter when or how the button was added.
  document.addEventListener('click', function (e) {
    var el = e.target.closest ? e.target.closest('button, a') : null;
    if (!el) return;
    var isReport = el.id === 'report-btn' ||
      el.hasAttribute('data-report') ||
      /^report this$/i.test((el.textContent || '').trim());
    if (isReport) { e.preventDefault(); open(el); }
  });

  console.log('MoneyWise report popup ready');
})();