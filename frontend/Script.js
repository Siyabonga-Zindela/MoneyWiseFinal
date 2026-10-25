(function () {
  'use strict';

  var pills = Array.prototype.slice.call(document.querySelectorAll('.pill'));
  var offer = document.getElementById('offer');
  var offerLabel = document.getElementById('offer-label');
  var offerCounter = document.getElementById('offer-counter');
  var sourceGroup = document.getElementById('source-group');
  var sourceSelect = document.getElementById('source');
  var senderInput = document.getElementById('sender');
  var reportBtn = document.getElementById('report-btn');

  var MODES = {
    message:  { label: 'Message to check',  placeholder: 'Paste the offer you received', source: true },
    link:     { label: 'Link to check',     placeholder: 'Paste the web address, for example https://example.com', source: true },
    provider: { label: 'Provider to check', placeholder: 'Type the name of the company or person', source: false }
  };

  /* Map the "How did you receive it?" choice onto the report popup's
     phishing-type options, so users do not have to answer it twice. */
  var SOURCE_TO_REPORT_TYPE = {
    'WhatsApp': 'WhatsApp or social media message',
    'SMS': 'SMS phishing (smishing)',
    'Email': 'Email phishing',
    'Facebook or Instagram': 'WhatsApp or social media message',
    'Phone call': 'Phone call (vishing)'
  };

  function select(pill) {
    var mode = MODES[pill.dataset.type];
    pills.forEach(function (p) {
      var on = p === pill;
      p.classList.toggle('is-active', on);
      p.setAttribute('aria-selected', String(on));
      p.tabIndex = on ? 0 : -1;
    });
    offerLabel.textContent = mode.label;
    offer.placeholder = mode.placeholder;
    offer.value = '';
    if (offerCounter) offerCounter.textContent = '0';
    sourceGroup.hidden = !mode.source;
    offer.focus();
  }

  pills.forEach(function (pill, i) {
    pill.addEventListener('click', function () { select(pill); });
    pill.addEventListener('keydown', function (e) {
      var next;
      if (e.key === 'ArrowRight') next = pills[(i + 1) % pills.length];
      if (e.key === 'ArrowLeft')  next = pills[(i - 1) % pills.length];
      if (next) { e.preventDefault(); next.focus(); select(next); }
    });
  });

  if (offerCounter) {
    offer.addEventListener('input', function () {
      offerCounter.textContent = String(offer.value.length);
    });
  }

  document.getElementById('clear-btn').addEventListener('click', function () {
    offer.value = '';
    if (offerCounter) offerCounter.textContent = '0';
    offer.focus();
  });

  /* ------------------------------------------------------------------
   * Real check: the text goes to POST /api/v1/analysis (rule engine +
   * optional AI explanation) and the full evidence-based result is
   * rendered into the result card: verdict, the exact phrases that led
   * to it, what the check cannot confirm, next steps and how to verify.
   * The assessment_id is kept so "Report this" links the report to the
   * same analysis in the database.
   * ------------------------------------------------------------------ */
  var VERDICTS = {
    high:         { title: 'High risk: likely scam', text: 'Strong scam warning signs found. Do not pay or share any personal information.' },
    medium:       { title: 'Warning signs found',    text: 'This offer shows real warning signs. Verify before you send anything.' },
    low:          { title: 'No obvious scam signs',  text: 'The known warning-sign patterns were not found in this text. That does not prove it is safe.' },
    inconclusive: { title: 'Not enough information', text: 'There is not enough in this text to judge. Check with the provider directly.' }
  };

  /* What the rating means, in plain language, so colour is never the only cue. */
  var RATING_MEANING = {
    high:         'High risk means the text contains several or severe scam patterns. Treat it as unsafe until a trusted source proves otherwise.',
    medium:       'Medium risk means at least one recognised warning sign was found. Pause and verify independently before responding or paying.',
    low:          'Low risk means none of the patterns this check looks for were found. It is not a certificate of safety - new scams exist that no check can recognise.',
    inconclusive: 'A check is inconclusive when there is too little information, for example an empty or very short submission.'
  };

  var SOURCE_LABELS = {
    deterministic_rules: 'Automated rule check',
    openrouter_ai_explanation: 'Automated rule check + AI-assisted explanation'
  };

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text != null) n.textContent = text;
    return n;
  }

  function showResultBody() {
    document.getElementById('result-empty').hidden = true;
    document.getElementById('result-body').hidden = false;
  }

  function renderEvidence(indicators) {
    var list = document.getElementById('evidence-list');
    list.textContent = '';

    if (!indicators.length) {
      list.appendChild(el('p', 'reason',
        'No known warning-sign patterns were found in the text you submitted. ' +
        'This check looks for patterns such as upfront "release fees", guaranteed returns, ' +
        'recruitment-based earnings, requests for PINs or OTPs, urgent payment pressure and ' +
        'hard-to-reverse payment methods.'));
      return;
    }

    indicators.forEach(function (ind) {
      var item = el('div', 'evidence-item severity-' + ind.severity);
      var head = el('p', 'evidence-head');
      var badge = el('span', 'badge evidence-badge', ind.severity === 'high' ? 'Strong sign' : 'Warning sign');
      head.appendChild(badge);
      head.appendChild(document.createTextNode(ind.title));
      item.appendChild(head);

      if (ind.evidence) {
        var quote = el('p', 'evidence-quote');
        quote.appendChild(el('span', 'sr-only', 'Quote from your message: '));
        quote.appendChild(document.createTextNode('\u201C' + (ind.context || ind.evidence) + '\u201D'));
        item.appendChild(quote);
      }

      item.appendChild(el('p', 'evidence-why', ind.explanation));
      list.appendChild(item);
    });
  }

  function renderResult(data) {
    var verdict = VERDICTS[data.category] || VERDICTS.inconclusive;

    document.getElementById('result-tag').textContent = 'Live check';
    document.getElementById('verdict-title').textContent = verdict.title;
    document.getElementById('verdict-text').textContent = verdict.text;

    var score = document.getElementById('risk-score');
    var scoreLabel = document.getElementById('risk-score-label');
    if (data.category === 'inconclusive') {
      score.hidden = true;
      scoreLabel.hidden = true;
    } else {
      score.hidden = false;
      scoreLabel.hidden = false;
      score.textContent = Math.round(data.risk_score || 0) + '%';
      scoreLabel.textContent = 'warning-sign score (higher = more warning signs)';
    }

    renderEvidence(data.indicators || []);
    document.getElementById('rating-meaning').textContent =
      RATING_MEANING[data.category] || RATING_MEANING.inconclusive;
    document.getElementById('uncertainty').textContent =
      data.limitations || 'The check cannot confirm who sent this message or whether the offer is real.';
    document.getElementById('verification').textContent =
      data.verification || 'Verify any provider through official channels before paying.';

    var steps = document.getElementById('next-steps');
    steps.textContent = '';
    (data.next_steps && data.next_steps.length ? data.next_steps : [
      'Do not send money or share PINs, passwords or one-time codes.',
      'Verify the person or provider using contact details from an official source.'
    ]).forEach(function (step) {
      steps.appendChild(el('li', null, step));
    });

    document.getElementById('source-note').textContent =
      'Checked by: ' + (SOURCE_LABELS[data.source] || 'Automated rule check') +
      '. This is an automated opinion about the text you submitted, not proof of fraud.';

    showResultBody();
    var result = document.getElementById('result');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
    result.focus({ preventScroll: true });
  }

  function renderError(message) {
    document.getElementById('result-tag').textContent = 'Live check';
    document.getElementById('verdict-title').textContent = 'Check failed';
    document.getElementById('verdict-text').textContent =
      message || 'We could not check that just now. Your text is still in the box - try again in a moment.';
    document.getElementById('risk-score').hidden = true;
    document.getElementById('risk-score-label').hidden = true;
    document.getElementById('result-detail').hidden = true;
    showResultBody();
    var result = document.getElementById('result');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
    result.focus({ preventScroll: true });
  }

  function resetResultDetail() {
    document.getElementById('result-detail').hidden = false;
  }

  /* Signed-in users: attach the access token so the check (and any report
     filed from it) is linked to the account. A stale token must never block
     a check - on 401 we retry once as anonymous. */
  function authHeaders() {
    var h = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    try {
      var token = localStorage.getItem('mw_access_token');
      if (token) h['Authorization'] = 'Bearer ' + token;
    } catch (e) { /* storage unavailable - anonymous check */ }
    return h;
  }
  function anonymousHeaders() {
    return { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  }

  document.getElementById('check-btn').addEventListener('click', function () {
    var btn = this;
    var text = offer.value.trim();
    if (!text) {
      offer.focus();
      return;
    }
    btn.disabled = true;
    var original = btn.textContent;
    btn.textContent = 'Checking...';
    resetResultDetail();

    var body = { text: text };
    if (senderInput && senderInput.value.trim()) {
      body.sender = senderInput.value.trim();
    }

    var call = function (headers) {
      return fetch('/api/v1/analysis', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(body)
      }).then(function (res) {
        // Signed-in but the stored token is stale: fall back to an
        // anonymous check instead of showing the user an error.
        if (res.status === 401 && headers['Authorization']) {
          return call(anonymousHeaders());
        }
        return res;
      });
    };

    call(authHeaders()).then(function (res) {
      if (!res.ok) {
        if (res.status === 422) {
          throw new Error('That text cannot be checked. Keep it between 1 and 5000 characters.');
        }
        if (res.status === 429) {
          throw new Error('Too many checks in a short time. Please wait a minute and try again.');
        }
        return res.json().catch(function () { return null; }).then(function (body) {
          var detail = body && body.detail ? String(body.detail) : null;
          throw new Error('The check service returned an error (' + res.status + '). ' + (detail || 'Please try again.'));
        });
      }
      return res.json();
    }).then(function (data) {
      if (data.assessment_id) {
        try { sessionStorage.setItem('mw_assessment_id', String(data.assessment_id)); } catch (e) { /* ignore */ }
      }
      renderResult(data);
    }).catch(function (err) {
      renderError(err instanceof TypeError ? null : err.message);
    }).finally(function () {
      btn.disabled = false;
      btn.textContent = original;
    });
  });

  /* Pass the "How did you receive it?" choice to the report popup, so the
     phishing-type field is pre-filled when the user reports the message. */
  if (sourceSelect && reportBtn) {
    var syncReportType = function () {
      var mapped = SOURCE_TO_REPORT_TYPE[sourceSelect.value];
      if (mapped) reportBtn.setAttribute('data-mw-type', mapped);
      else reportBtn.removeAttribute('data-mw-type');
    };
    sourceSelect.addEventListener('change', syncReportType);
    syncReportType();
  }
})();
