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
 
// The only columns a partner can change after an offer exists.
// To allow more, add the column name here and remove "readonly" from its input in the HTML.
const EDITABLE = ["min_investment", "max_investment", "indicative_return_range"];
 
// Hardcoded offers (replace with data from your backend later). currency is always ZAR.
const offers = [
  {
    id: 1,
    product_name: "12 Month Fixed Deposit",
    product_category: "Fixed deposit",
    description: "Lock in your money for 12 months and earn a fixed rate of interest.",
    currency: "ZAR",
    min_investment: 1000,
    max_investment: 5000000,
    fees_summary: "No monthly fee (simulated).",
    indicative_return_range: "7.5% – 8.5% p.a.",
    access_condition: "32 days notice for withdrawals",
    material_risk: "Withdrawing early may reduce your return. Rates are indicative and may change.",
    suitable_timeframe: "1 to 3 years",
    url: "https://www.fnb.co.za",
    updated_at: "2026-10-20T09:00:00+02:00"
  },
  {
    id: 2,
    product_name: "Tax-Free Savings Account",
    product_category: "Call account",
    description: "A savings account where the interest you earn is not taxed, up to the yearly limit.",
    currency: "ZAR",
    min_investment: 100,
    max_investment: 36000,
    fees_summary: "No monthly fee (simulated).",
    indicative_return_range: "5.0% – 7.0% p.a.",
    access_condition: "Withdraw at any time. Contribution limits apply.",
    material_risk: "Contributions above the yearly limit are taxed. Rates can change.",
    suitable_timeframe: "Under 1 year",
    url: "https://www.fnb.co.za",
    updated_at: "2026-10-18T14:30:00+02:00"
  },
  {
    id: 3,
    product_name: "Balanced Unit Trust",
    product_category: "Unit trust",
    description: "A mix of shares, bonds and cash managed for you by a fund manager.",
    currency: "ZAR",
    min_investment: 500,
    max_investment: 1000000,
    fees_summary: "Annual management fee plus underlying fund fees.",
    indicative_return_range: "6% – 12% p.a.",
    access_condition: "Withdrawals paid within 3 working days",
    material_risk: "The value of your investment can go down as well as up.",
    suitable_timeframe: "3 to 5 years",
    url: "https://www.fnb.co.za",
    updated_at: "2026-10-22T11:15:00+02:00"
  }
];
 
let editingId = null;
 
const rand = n => "R" + Number(n).toLocaleString("en-ZA");
const formatDate = iso => new Date(iso).toLocaleString("en-ZA", { dateStyle: "medium", timeStyle: "short" });
const nextId = () => offers.reduce((m, o) => Math.max(m, o.id), 0) + 1;
 
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
      fact("Range", rand(o.min_investment) + " – " + rand(o.max_investment)),
      fact("Return", o.indicative_return_range)
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
 
  const row = { id: nextId(), currency: "ZAR" };
  Object.entries(ADD_FIELDS).forEach(([key, elId]) => {
    const v = $(elId).value.trim();
    row[key] = (key === "min_investment" || key === "max_investment") ? Number(v) : v;
  });
  row.updated_at = new Date().toISOString(); // timestamp with time zone
 
  offers.unshift(row);
  console.log("Offer added:", row);
 
  $("addForm").reset(); // back to an empty form
  renderList();
  toast("Offer added");
});
$("maxInvestment").addEventListener("input", e => e.target.setCustomValidity(""));
 
/* ---------- Update pop-up ---------- */
function openModal(id) {
  const o = offers.find(x => x.id === id);
  if (!o) return;
  editingId = id;
  Object.entries(MODAL_FIELDS).forEach(([key, elId]) => { $(elId).value = o[key]; });
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
 
  const i = offers.findIndex(o => o.id === editingId);
  if (i === -1) return;
 
  const changes = {};
  EDITABLE.forEach(key => {
    const v = $(MODAL_FIELDS[key]).value.trim();
    changes[key] = (key === "min_investment" || key === "max_investment") ? Number(v) : v;
  });
  offers[i] = { ...offers[i], ...changes, updated_at: new Date().toISOString() };
  console.log("Offer updated:", offers[i]);
 
  closeModal();
  renderList();
  toast("Offer updated");
});
 
renderList();