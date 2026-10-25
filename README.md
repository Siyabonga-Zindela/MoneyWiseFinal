# MoneyWiseFinal

MoneyWise is a financial scam-awareness application: paste a suspicious money
offer, message, link or provider name and get an evidence-based risk verdict
with the exact phrases that led to it, what the check cannot confirm, and
practical next steps. Users can report scams (optionally with a screenshot)
for administrator review.

## Run it

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt
cp .env.example .env                                 # fill in DATABASE_URL etc.
uvicorn app.main:app --port 8000
```

One server serves everything from a single origin:

- `http://127.0.0.1:8000/`            - landing page
- `http://127.0.0.1:8000/check.html`  - scam checker + report popup
- `http://127.0.0.1:8000/Admin-login.html` - admin / stakeholder sign-in
- `http://127.0.0.1:8000/api/v1/...`  - REST API (docs at `/docs`)

The scam checker works without any AI key: a deterministic rule engine
decides every verdict. Setting `OPENROUTER_API_KEY` (+ optional
`OPENROUTER_MODEL`) lets an AI rewrite the wording of the explanation; the
verdict, score and evidence stay deterministic, and any provider failure
falls back to the rule engine result, honestly labelled via the `source`
field of the response.

## Architecture

```
frontend/               vanilla HTML/CSS/JS (no build step)
  index.html            landing page (hero, how-it-works, features, privacy, education)
  check.html            scam checker + report popup
  Script.js             checker page logic (calls /api/v1/analysis, renders evidence)
  report-popup.js       self-contained report dialog (calls /api/v1/reports)
  mw-auth.js            shared bearer-token helper (refresh-on-401, role guard)
  admin-login.js        login page logic (role-based redirect)
  admin-dashboard.html / dashboard.js    admin report review (ADMIN only)
  admin-users.html / users.js            stakeholder management (ADMIN only)
  externalStakeholder.html / .js         partner offer portal (STAKEHOLDER/ADMIN)
backend/                FastAPI + SQLAlchemy + PostgreSQL (Neon) + Alembic
  app/routes/           analysis, auth, reports, reviews, education, privacy,
                        audit, admin, stakeholder
  app/services/ai_analysis/
    baseline.py         deterministic rules (evidence quotes + why-it-matters)
    prompts.py          hardened AI prompt (message = untrusted data)
    service.py          orchestrator: rules decide, AI only rewords, honest fallback
    openrouter_client.py backend-only AI client (timeouts, safe error mapping)
  migrations/           0001 baseline, 0002 scam_reports alignment, 0003 stakeholders
  tests/                pytest integration suite (runs against the DATABASE_URL DB)
```

Data flow: landing page -> `check.html` -> `POST /api/v1/analysis`
(rate-limited 30/min) -> rule engine + optional AI -> persisted to
`risk_assessments` + `assessment_evidence` -> rendered with evidence quotes.
"Report this" opens the popup -> `POST /api/v1/reports`
(rate-limited 10/min, JSON or multipart with optional PNG/JPG screenshot
<= 5 MB) -> admin review queue.

## Security notes

- Passwords: bcrypt (cost 12); short-lived JWT access tokens (15 min) +
  rotating refresh tokens (hash-only storage, revocable logout).
- Brute force: failed-login lockout backed by `login_attempts`; auth routes
  rate-limited 5/min; anonymous report uploads 10/min; analysis 30/min.
- Every response carries security headers: CSP (`script-src 'self'`,
  no inline script), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy`, `Permissions-Policy`; HSTS added in production.
- Request bodies > `MAX_BODY_MB` (default 8 MB) are rejected with 413.
- CORS is an explicit origin list; the same-origin deployment needs none.
- IPs are stored only as salted hashes (POPIA); POPIA export / correction /
  deletion endpoints live under `/api/v1/privacy`.
- AI prompt hardening: the submitted message travels as JSON data, the
  system prompt forbids following in-message instructions, opening links,
  or inventing facts; the model cannot change the deterministic verdict.
- Screenshots are stored but never served by the API (identity safety).

## Known limitations

- The rule engine checks phrases and payout multiples in the submitted text
  only; it cannot see who sent a message or whether a company exists. A LOW
  result is not a safety certificate.
- The AI layer needs an `OPENROUTER_API_KEY`; without one the deterministic
  result is used (and labelled as such). No live provider call was verified
  in the development environment - the AI path is covered by mocked tests.
- `X-Forwarded-For` is trusted for client IP extraction, so deploy behind a
  proxy that overwrites it; otherwise clients could spoof rate-limit keys.
- Report screenshots are stored but there is no admin UI to view them yet.
- No e-mail provider is wired; stakeholder invite passwords are shown once
  in the admin toast.

## Tests

```bash
cd backend
export DATABASE_URL=postgresql+psycopg2://...   # a dedicated test DB is safest
python -m pytest tests -q
```

Covers auth (registration, login, lockout, refresh rotation, role gates),
reports (popup shape, multipart, ownership), admin/stakeholder APIs,
education, POPIA privacy, audit trail, security controls (headers, body
limit, validation, rate-limit wiring) and the AI layer (provider success,
timeouts, malformed output, injection resistance, verdict immutability).
