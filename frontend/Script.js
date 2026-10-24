(function () {
  'use strict';

  var pills = Array.prototype.slice.call(document.querySelectorAll('.pill'));
  var offer = document.getElementById('offer');
  var offerLabel = document.getElementById('offer-label');
  var sourceGroup = document.getElementById('source-group');

  var MODES = {
    message:  { label: 'Message to check',  placeholder: 'Paste the offer you received', source: true },
    link:     { label: 'Link to check',     placeholder: 'Paste the web address, for example https://example.com', source: true },
    provider: { label: 'Provider to check', placeholder: 'Type the name of the company or person', source: false }
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
    sourceGroup.hidden = !mode.source;
    offer.focus();
  }

  pills.forEach(function (pill, i) {
    pill.addEventListener('click', function () { select(pill); });
    pill.addEventListener('keydown', function (e) {
      var next;
      if (e.key === 'ArrowRight') next = pills[(i + 1) % pills.length];
      if (e.key === 'ArrowLeft')  next = pills[(i - 1 + pills.length) % pills.length];
      if (next) { e.preventDefault(); next.focus(); select(next); }
    });
  });

  document.getElementById('clear-btn').addEventListener('click', function () {
    offer.value = '';
    offer.focus();
  });

  // Real checks are not live yet: move to the sample result.
  document.getElementById('check-btn').addEventListener('click', function () {
    var result = document.getElementById('result');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
    result.focus({ preventScroll: true });
  });
})();