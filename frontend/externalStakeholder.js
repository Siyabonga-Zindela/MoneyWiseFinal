const $ = id => document.getElementById(id);

// Add-form field ids, keyed by DB column name
const ADD_FIELDS = {
  product_name: "productName",
  product_category: "productCategory",
  description: "description",
  min_investment: "minInvestment",
  max_investment: "maxInvestment",
  fees_summary: "feesSummary",
  indicative_return_range: "returnRange",
  access_condition: "accessCondition",
  material_risk: "materialRisk",
  suitable_timeframe: "timeframe",
  url: "url"
};

// Update pop-up field ids, keyed by DB column name
const MODAL_FIELDS = {
  product_name: "mProductName",
  product_category: "mProductCategory",
  description: "mDescription",
  min_investment: "mMin",
  max_investment: "mMax",
  fees_summary: "mFees",
  indicative_return_range: "mReturn",
  access_condition: "mAccess",
  material_risk: "mRisk",
  suitable_timeframe: "mTimeframe",
  url: "mUrl"
};

// The only columns a partner can change after an offer exists - the API
// rejects anything else on PATCH (see /api/v1/stakeholder/offers/{id}).
// To allow more, add the column name here and remove "readonly" from its input in the HTML.
const EDITABLE = ["min_investment", "max_investment", "indicative_return_range"];

// Real offers come from the MoneyWise API; currency is always ZAR.
// mwAuth (loaded before this script) attaches the JWT and handles expiry.
const LOGIN_PAGE = "admin-login.html";
let offers = [];

let editingId = null;

const rand = n => "R" + Number(n).toLocaleString("en-ZA");
const formatDate = iso => new Date(iso).toLocaleString("en-ZA", { dateStyle: "medium", timeStyle: "short" });

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 2500);
}

function el(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined) n.textContent = text;
  return n;
}

function fact(label, value) {
  const wrap = el("div");
  wrap.append(el("span", "", label + ": "), el("strong", "", value));
  return wrap;
}

/* ---------- Data layer: the only part that talks to a server ---------- */
function guard(res) {
  if (res.status === 401 || res.status === 403) {
    window.location.href = LOGIN_PAGE;
    return new Promise(() => {});
  }
  if (!res.ok) throw new Error("request failed");
  return res;
}

function loadOffers() {
  return mwAuth.fetch("/api/v1/stakeholder/offers").then(guard).then(r => r.json());
}

function createOffer(fields) {
  return mwAuth.fetch("/api/v1/stakeholder/offers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(fields)
  }).then(guard).then(r => r.json());
}

function updateOffer(id, changes) {
  return mwAuth.fetch("/api/v1/stakeholder/offers/" + encodeURIComponent(id), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changes)
  }).then(guard).then(r => r.json());
}

/* Reports the MoneyWise admin forwarded to this organisation. */
function loadSharedReports() {
  return mwAuth.fetch("/api/v1/stakeholder/reports").then(guard).then(r => r.json());
}
function acknowledgeReport(reportId) {
  return mwAuth.fetch("/api/v1/stakeholder/reports/" + encodeURIComponent(reportId) + "/acknowledge", {
    method: "POST"
  }).then(guard).then(r => r.json());
}

let sharedReports = [];

function renderInbox() {
  const list = $("inboxList");
  list.replaceChildren();
  $("inboxCount").textContent = sharedReports.length +
    (sharedReports.length === 1 ? " report" : " reports");
  $("inboxEmpty").hidden = sharedReports.length !== 0;

  sharedReports.forEach(item => {
    const li = el("li", "inbox-item");

    const head = el("div", "inbox-head");
    head.append(el("h3", "", "Report #" + item.report_id + ": " + item.title));
    head.append(el("span", "badge badge-" + (item.risk_level || "unsure"),
      (item.risk_level || "unsure") + " risk"));
    li.append(head);

    const received = item.date_received ? new Date(item.date_received + "T00:00:00") : null;
    const sent = item.sent_at ? new Date(item.sent_at) : null;
    const meta = el("p", "inbox-meta",
      (item.phishing_type || "Other") +
      (item.channel ? " · via " + item.channel.toLowerCase().replace("_", " ") : "") +
      (item.sender ? " · sender: " + item.sender : "") +
      (received && !isNaN(received) ? " · received " + received.toLocaleDateString("en-ZA") : "") +
      (sent && !isNaN(sent) ? " · shared " + sent.toLocaleDateString("en-ZA") : ""));
    li.append(meta);

    li.append(el("p", "inbox-msg", item.message || ""));

    if (item.amount_asked || item.amount_promised) {
      const asked = item.amount_asked ? "R" + Number(item.amount_asked).toLocaleString("en-ZA") : "-";
      const promised = item.amount_promised ? "R" + Number(item.amount_promised).toLocaleString("en-ZA") : "-";
      li.append(el("p", "inbox-meta", "Asked for: " + asked + " · Promised: " + promised));
    }

    if (item.note) li.append(el("p", "inbox-note", "Note from the MoneyWise team: " + item.note));

    if (item.acknowledged) {
      li.append(el("p", "inbox-ack", "\u2713 Marked as received" +
        (item.acknowledged_at ? " " + new Date(item.acknowledged_at).toLocaleDateString("en-ZA") : "")));
    } else {
      const btn = el("button", "btn btn-secondary btn-small", "Mark as received");
      btn.type = "button";
      btn.setAttribute("aria-label", "Mark report " + item.report_id + " as received");
      btn.addEventListener("click", () => {
        btn.disabled = true;
        acknowledgeReport(item.report_id).then(() => {
          item.acknowledged = true;
          item.acknowledged_at = new Date().toISOString();
          renderInbox();
          toast("Thanks - the MoneyWise team can see the confirmation.");
        }).catch(() => {
          btn.disabled = false;
          toast("Could not confirm receipt. Please try again.");
        });
      });
      li.append(btn);
    }

    list.append(li);
  });
}

/* ---------- My offers list ---------- */
function renderList() {
  const list = $("offerList");
  list.replaceChildren();
  $("listCount").textContent = offers.length + (offers.length === 1 ? " offer" : " offers");

  if (offers.length === 0) {
    list.append(el("li", "empty", "No offers yet. Use the form to add your first one."));
    return;
  }

  offers.forEach(o => {
    const li = el("li", "offer");

    const info = el("div");
    const name = el("h3", "offer-name", o.product_name);
    name.append(el("span", "tag", o.product_category));
    const meta = el("p", "offer-meta", "Last updated " + formatDate(o.updated_at));
    const facts = el("div", "offer-facts");
    facts.append(
      fact("Range", rand(o.min_investment) + " - " + rand(o.max_investment)),
      fact("Return", o.indicative_return_range || "Not given")
    );
    info.append(name, meta, facts);

    const btn = el("button", "btn btn-secondary btn-small", "Update");
    btn.type = "button";
    btn.setAttribute("aria-label", "Update " + o.product_name);
    btn.addEventListener("click", () => openModal(o.id));

    li.append(info, btn);
    list.append(li);
  });
}

/* ---------- Add offer (form always empty) ---------- */
$("addForm").addEventListener("submit", e => {
  e.preventDefault();

  const max = $("maxInvestment");
  max.setCustomValidity(Number(max.value) < Number($("minInvestment").value) ? "Maximum must be at least the minimum." : "");
  if (!$("addForm").reportValidity()) return;

  const fields = { currency: "ZAR" };
  Object.entries(ADD_FIELDS).forEach(([key, elId]) => {
    const v = $(elId).value.trim();
    fields[key] = (key === "min_investment" || key === "max_investment") ? Number(v) : v;
  });

  const btn = $("addForm").querySelector('button[type="submit"]');
  btn.disabled = true;
  createOffer(fields).then(created => {
    offers.unshift(created);
    $("addForm").reset();
    renderList();
    toast("Offer added");
  }).catch(err => {
    if (err instanceof TypeError) toast("Cannot reach the MoneyWise server. Check your connection.");
    else toast("Could not save the offer. Please try again.");
  }).finally(() => { btn.disabled = false; });
});
$("maxInvestment").addEventListener("input", e => e.target.setCustomValidity(""));

/* ---------- Update pop-up ---------- */
function openModal(id) {
  const o = offers.find(x => x.id === id);
  if (!o) return;
  editingId = id;
  Object.entries(MODAL_FIELDS).forEach(([key, elId]) => { $(elId).value = o[key] == null ? "" : o[key]; });
  $("mCurrency").value = "ZAR (Rands)";
  $("mUpdated").value = formatDate(o.updated_at);
  $("modalTitle").textContent = "Update " + o.product_name;
  $("mMax").setCustomValidity("");
  $("updateModal").classList.remove("hidden");
  $("mMin").focus();
}

function closeModal() {
  $("updateModal").classList.add("hidden");
  editingId = null;
}

$("closeModal").addEventListener("click", closeModal);
$("updateModal").addEventListener("click", e => { if (e.target === $("updateModal")) closeModal(); });
document.addEventListener("keydown", e => { if (e.key === "Escape" && editingId !== null) closeModal(); });
$("mMax").addEventListener("input", e => e.target.setCustomValidity(""));

$("updateForm").addEventListener("submit", e => {
  e.preventDefault();

  const max = $("mMax");
  max.setCustomValidity(Number(max.value) < Number($("mMin").value) ? "Maximum must be at least the minimum." : "");
  if (!$("updateForm").reportValidity()) return;

  const changes = {};
  EDITABLE.forEach(key => {
    const v = $(MODAL_FIELDS[key]).value.trim();
    changes[key] = (key === "min_investment" || key === "max_investment") ? Number(v) : v;
  });

  const btn = $("updateForm").querySelector('button[type="submit"]');
  btn.disabled = true;
  updateOffer(editingId, changes).then(updated => {
    const i = offers.findIndex(o => o.id === editingId);
    if (i !== -1) offers[i] = updated;
    closeModal();
    renderList();
    toast("Offer updated");
  }).catch(err => {
    if (err instanceof TypeError) toast("Cannot reach the MoneyWise server. Check your connection.");
    else toast("Could not save. Please try again.");
  }).finally(() => { btn.disabled = false; });
});

/* ---------- Boot ---------- */
if (mwAuth.requireRole(["STAKEHOLDER", "ADMIN"])) {
  loadOffers().then(list => {
    offers = list;
    renderList();
  }).catch(() => {
    const list = $("offerList");
    list.replaceChildren();
    list.append(el("li", "empty", "We could not load your offers. Refresh the page to try again."));
    $("listCount").textContent = "0 offers";
  });

  // The report inbox belongs to the organisation, so show it to both roles.
  loadSharedReports().then(list => {
    sharedReports = list || [];
    renderInbox();
  }).catch(() => {
    $("inboxCount").textContent = "";
    $("inboxEmpty").textContent = "We could not load the shared reports. Refresh the page to try again.";
    $("inboxEmpty").hidden = false;
  });
}
