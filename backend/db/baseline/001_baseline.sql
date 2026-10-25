-- ============================================================================
--  AI-POWERED SCAM AND INVESTMENT PROTECTION APPLICATION
--  Neon PostgreSQL -- BASELINE SCHEMA SCRIPT (v1.1, 2026-10-25)
-- ============================================================================
--
--  v1.1 CHANGE (2026-10-25): the FSCA verification feature tables
--  (fsca_provider_records, fsca_warnings, fsca_verification_checks) and the
--  financial_products catalogue were REMOVED from the product by decision of
--  the owner. They were dropped from the live database and MUST NOT be
--  re-created. This baseline creates 19 tables and never references the
--  removed ones. product_providers.fsca_record_id and
--  assessment_product_matches.product_id remain as plain BIGINT columns
--  (no foreign keys) so a future, replacement feature can adopt them without
--  a destructive migration.
--
--  HOW TO USE THIS SCRIPT
--  ----------------------
--  1. Create your Neon project, then run this whole file ONCE against the
--     empty database (Neon SQL Editor, or `psql $NEON_DATABASE_URL -f this_file.sql`).
--  2. This script is the SCHEMA BASELINE. After it is applied, all future
--     schema changes go through Alembic migrations (per master prompt §6).
--     Once your Alembic migration chain matches this baseline, run:
--         alembic stamp head
--     so Alembic treats the baseline as applied and never re-creates it.
--  3. Requires PostgreSQL 14+ (Neon runs PostgreSQL 15/16/17 -- fine).
--
--  CONVENTIONS
--  -----------
--  * snake_case names; BIGINT GENERATED ALWAYS AS IDENTITY primary keys.
--  * Native PostgreSQL ENUM types for fixed value sets (created via DO blocks
--    so the script can be re-run safely without erroring).
--  * All timestamps are TIMESTAMPTZ (UTC in Neon).
--  * Every table has created_at; mutable tables also have updated_at
--    maintained by the trigger function set_updated_at() (defined below).
--  * Simulated/demo data is ALWAYS flagged: is_simulated = TRUE plus a
--    data_source / source_name value of 'SIMULATED_...' -- per master prompt
--    requirement to distinguish simulated data from verified external data.
--  * NO plaintext passwords, PINs, one-time passwords or card numbers are
--    ever stored (master prompt §6 and §9).
--  * IPs are stored only as salted SHA-256 hashes (ip_hash) for POPIA care.
--
--  TABLE INVENTORY (19 tables)
--  ---------------------------
--   1. users                       Registered accounts (bcrypt/argon2 hashes only)
--   2. roles                       USER / ADMIN / STAKEHOLDER role definitions
--   3. user_roles                  users <-> roles junction
--   4. user_financial_preferences  Optional income/goals/risk preferences
--   5. refresh_tokens              JWT refresh-token store (hashed, revocable)
--   6. login_attempts              Brute-force tracking for auth rate limiting
--   7. user_privacy_requests       POPIA deletion/export/correction requests
--   8. scam_indicators             Risk indicator & detection-rule catalogue
--   9. risk_assessments            Scam/investment risk assessment results
--  10. assessment_evidence         Per-indicator evidence behind each assessment
--  11. pre_payment_checks          Simulated pre-payment journey & user decision
--  12. product_providers           Participating banks / authorised providers
--  13. assessment_product_matches  Alternatives shown per assessment (plain product_id)
--  14. scam_reports                User-submitted suspected scam reports
--  15. scam_report_reviews         Admin decision trail on reports
--  16. educational_resources       Scam-awareness / financial-education content
--  17. audit_logs                  Append-only admin & security action log
--  18. stakeholder_profiles        External stakeholder org metadata (migration 0003)
--  19. stakeholder_offers          Investment offers listed by stakeholders (migration 0003)
--
--  KEY RELATIONSHIPS (mini-ERD)
--  ----------------------------
--    users 1--* user_roles *--1 roles
--    users 1--* refresh_tokens | login_attempts | user_privacy_requests
--    users 1--* user_financial_preferences | risk_assessments (anonymised via ON DELETE SET NULL)
--    users 1--1 stakeholder_profiles ; users 1--* stakeholder_offers
--    risk_assessments 1--* assessment_evidence *--1 scam_indicators (code snapshot kept)
--    risk_assessments 1--* pre_payment_checks
--    risk_assessments 1--* assessment_product_matches
--        (product_id is a plain column since v1.1 - the financial_products
--         catalogue it used to reference was removed; no FK exists today)
--    scam_reports 1--* scam_report_reviews ; scam_reports self-ref duplicate_of_id
--    audit_logs references users (actor) by soft link only
--
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- EXTENSIONS
-- (none required since v1.1: the pg_trgm extension was only used by the
--  fuzzy-name search indexes of the removed FSCA register tables; all
--  remaining indexes are plain btree and need no extension)
-- ----------------------------------------------------------------------------

-- ----------------------------------------------------------------------------
-- ENUM TYPES (idempotent DO blocks)
-- ----------------------------------------------------------------------------

DO $$ BEGIN
    CREATE TYPE user_status AS ENUM ('ACTIVE', 'SUSPENDED', 'DELETED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE assessment_type AS ENUM (
        'SCAM_CONTENT',        -- Module 2: suspicious message / link / description
        'INVESTMENT_OFFER',    -- Module 3: investment opportunity screening
        'PYRAMID_PONZI',       -- Module 3: specialised pyramid/Ponzi assessment
        'PRE_PAYMENT'          -- Module 5: before a simulated payment is confirmed
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE assessment_source AS ENUM (
        'BASELINE_ENGINE',     -- deterministic rule engine (must always work)
        'NVIDIA_AI',           -- NVIDIA-assisted analysis (validated)
        'HYBRID',              -- baseline + AI combined
        'MANUAL'               -- human decision (e.g. admin override)
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE risk_category AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'INCONCLUSIVE');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE indicator_category AS ENUM (
        'URGENCY_PRESSURE', 'CREDENTIAL_REQUEST', 'SUSPICIOUS_LINK',
        'IMPERSONATION', 'UNREALISTIC_RETURN', 'RECRUITMENT_PRESSURE',
        'PAYMENT_INSTRUCTION', 'OPAQUE_BUSINESS_MODEL',
        'WITHDRAWAL_RESTRICTION', 'OTHER'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE indicator_severity AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE report_status AS ENUM (
        'SUBMITTED', 'UNDER_REVIEW', 'APPROVED', 'REJECTED', 'REQUIRES_INVESTIGATION'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE review_action AS ENUM ('APPROVED', 'REJECTED', 'REQUIRES_INVESTIGATION');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE scam_channel AS ENUM (
        'SMS', 'WHATSAPP', 'EMAIL', 'WEBSITE', 'SOCIAL_MEDIA',
        'PHONE_CALL', 'IN_PERSON', 'OTHER'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pre_payment_action AS ENUM (
        'PROCEEDED_WITH_WARNING', 'CANCELLED_BY_USER',
        'SIMULATED_HOLD', 'VERIFICATION_REQUESTED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE income_range AS ENUM (
        'BELOW_R5_000', 'R5_000_TO_R10_000', 'R10_001_TO_R20_000',
        'R20_001_TO_R50_000', 'R50_001_TO_R100_000', 'ABOVE_R100_000',
        'PREFER_NOT_TO_SAY'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE investment_timeframe AS ENUM (
        'UNDER_1_YEAR', 'ONE_TO_THREE_YEARS',
        'THREE_TO_FIVE_YEARS', 'OVER_FIVE_YEARS'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE risk_profile AS ENUM ('CONSERVATIVE', 'MODERATE', 'AGGRESSIVE');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE education_topic AS ENUM (
        'PYRAMID_SCHEMES', 'PONZI_SCHEMES', 'INVESTMENT_PROMISES',
        'PROVIDER_VERIFICATION', 'IMPERSONATION', 'RISK_AND_LIQUIDITY',
        'CREDENTIAL_SAFETY', 'AFTER_A_SCAM', 'OTHER'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE privacy_request_type AS ENUM (
        'ACCOUNT_DELETION', 'DATA_EXPORT', 'DATA_CORRECTION', 'MARKETING_OPT_OUT'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE privacy_request_status AS ENUM (
        'RECEIVED', 'IN_PROGRESS', 'COMPLETED', 'PARTIALLY_COMPLETED', 'REJECTED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE audit_action AS ENUM (
        'CREATE', 'UPDATE', 'DELETE', 'STATUS_CHANGE',
        'LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'PERMISSION_DENIED',
        'CONFIG_CHANGE', 'EXPORT'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ----------------------------------------------------------------------------
-- updated_at MAINTENANCE (applied to mutable tables below)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $fn$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

-- ============================================================================
-- IDENTITY & ACCESS (tables 1-7)
-- ============================================================================

-- 1. USERS -------------------------------------------------------------------
-- Passwords stored ONLY as bcrypt/argon2/pbkdf2 hashes (enforced by CHECK).
-- user_id, email etc. are the only identifiers; never store ID numbers.
CREATE TABLE IF NOT EXISTS users (
    user_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email          VARCHAR(255) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    full_name      VARCHAR(150),
    phone          VARCHAR(32),
    status         user_status  NOT NULL DEFAULT 'ACTIVE',
    locked_until   TIMESTAMPTZ,            -- brute-force lockout window (NULL = unlocked)
    last_login_at  TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_email_unique UNIQUE (email),
    CONSTRAINT users_password_not_empty CHECK (password_hash <> ''),
    CONSTRAINT users_no_plaintext_password CHECK (
        password_hash LIKE '$2%'          -- bcrypt
        OR password_hash LIKE '$argon2%'  -- argon2i/id
        OR password_hash LIKE 'pbkdf2%'   -- pbkdf2 (Django/passlib style)
    )
);
COMMENT ON TABLE users IS 'Registered accounts. Deletion requests anonymise assessments/reports by ON DELETE SET NULL (POPIA retention-aware).';
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);
CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 2. ROLES -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    role_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name   VARCHAR(50)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT roles_name_unique UNIQUE (role_name)
);
COMMENT ON TABLE roles IS 'Role catalogue: USER and ADMIN seeded. Extend via migration only.';

-- 3. USER_ROLES (junction) ---------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id     BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id     BIGINT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT user_roles_pk PRIMARY KEY (user_id, role_id)
);
COMMENT ON TABLE user_roles IS 'Authorisation is enforced in the BACKEND from this mapping - never by hiding frontend buttons (master prompt §8).';
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role_id);

-- 4. USER_FINANCIAL_PREFERENCES ---------------------------------------------
-- All analysis fields optional (voluntary disclosure, Module 7).
CREATE TABLE IF NOT EXISTS user_financial_preferences (
    preference_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id              BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    income_range         income_range,
    available_budget     NUMERIC(14,2),
    savings_goal         VARCHAR(255),
    investment_timeframe investment_timeframe,
    risk_preference      risk_profile,
    needs_liquid_access  BOOLEAN,          -- "need for immediate access to funds"
    consent_given_at     TIMESTAMPTZ NOT NULL DEFAULT now(),  -- POPIA consent marker
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ufp_budget_non_negative CHECK (available_budget IS NULL OR available_budget >= 0),
    CONSTRAINT ufp_has_data CHECK (
        income_range IS NOT NULL OR available_budget IS NOT NULL
        OR savings_goal IS NOT NULL OR investment_timeframe IS NOT NULL
        OR risk_preference IS NOT NULL OR needs_liquid_access IS NOT NULL
    )
);
COMMENT ON TABLE user_financial_preferences IS 'Voluntary financial profile used to filter Module 7 alternatives. Multiple rows = history; latest row is current.';
CREATE INDEX IF NOT EXISTS idx_ufp_user_recent
    ON user_financial_preferences (user_id, created_at DESC);
CREATE TRIGGER user_financial_preferences_set_updated_at
    BEFORE UPDATE ON user_financial_preferences
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 5. REFRESH_TOKENS ----------------------------------------------------------
-- Only SHA-256 HASHES of refresh tokens are stored - a stolen DB cannot be
-- used to mint sessions. Revoke = set revoked_at (logout-everywhere support).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash CHAR(64)   NOT NULL,           -- hex SHA-256 of token, never raw token
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent VARCHAR(255),
    ip_hash    CHAR(64),                       -- hashed, POPIA-friendly
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT refresh_tokens_hash_len CHECK (char_length(token_hash) = 64),
    CONSTRAINT refresh_tokens_expiry_after_issue CHECK (expires_at > created_at),
    CONSTRAINT refresh_tokens_revoked_after_issue
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
COMMENT ON TABLE refresh_tokens IS 'Revocable JWT refresh sessions. Access tokens stay stateless + short-lived; refresh is the revocation point.';
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user    ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry  ON refresh_tokens (expires_at);

-- 6. LOGIN_ATTEMPTS ----------------------------------------------------------
-- Backs the mandated auth rate-limiting / brute-force protection (§9) and
-- survives process restarts (unlike in-memory counters).
CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email_attempted VARCHAR(255),              -- normalised lowercase by app
    user_id         BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    ip_hash         CHAR(64),
    success         BOOLEAN NOT NULL,
    failure_reason  VARCHAR(100),              -- e.g. INVALID_PASSWORD, UNKNOWN_EMAIL, ACCOUNT_LOCKED
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE login_attempts IS 'Security telemetry for rate limiting. Raw IPs are never stored - only hashes.';
CREATE INDEX IF NOT EXISTS idx_login_attempts_email_time ON login_attempts (email_attempted, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time    ON login_attempts (ip_hash, attempted_at DESC);

-- 7. USER_PRIVACY_REQUESTS ---------------------------------------------------
CREATE TABLE IF NOT EXISTS user_privacy_requests (
    request_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    request_type   privacy_request_type   NOT NULL,
    status         privacy_request_status NOT NULL DEFAULT 'RECEIVED',
    details        TEXT,                       -- user's own notes
    retention_note TEXT,                       -- why some data was retained (legal obligation)
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ,
    processed_by   BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT privacy_requests_completion_has_timestamp CHECK (
        status NOT IN ('COMPLETED', 'PARTIALLY_COMPLETED', 'REJECTED')
        OR completed_at IS NOT NULL
    )
);
COMMENT ON TABLE user_privacy_requests IS 'POPIA rights fulfilment trail (§9: deletion subject to retention obligations).';
CREATE TRIGGER user_privacy_requests_set_updated_at
    BEFORE UPDATE ON user_privacy_requests
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================================
-- RISK DETECTION CORE (tables 8-11)
-- ============================================================================

-- 8. SCAM_INDICATORS ---------------------------------------------------------
-- The rule catalogue. Open/Closed principle: new rules = new rows, no rewrites.
CREATE TABLE IF NOT EXISTS scam_indicators (
    indicator_id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_code             VARCHAR(50) NOT NULL,     -- machine key, e.g. OTP_PIN_REQUEST
    name                       VARCHAR(150) NOT NULL,    -- human-readable short name
    description                TEXT NOT NULL,            -- plain-language explanation
    category                   indicator_category NOT NULL,
    severity                   indicator_severity NOT NULL DEFAULT 'MEDIUM',
    default_weight             SMALLINT NOT NULL DEFAULT 5,  -- 1..10 contribution to score
    is_scam_indicator          BOOLEAN NOT NULL DEFAULT TRUE,   -- applies to Module 2
    is_pyramid_ponzi_indicator BOOLEAN NOT NULL DEFAULT FALSE,  -- applies to Module 3
    is_pre_payment_indicator   BOOLEAN NOT NULL DEFAULT FALSE,  -- applies to Module 5
    is_active                  BOOLEAN NOT NULL DEFAULT TRUE,
    source                     VARCHAR(255),             -- approved source reference (or 'Demo seed')
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scam_indicators_code_unique UNIQUE (indicator_code),
    CONSTRAINT scam_indicators_weight_range CHECK (default_weight BETWEEN 1 AND 10)
);
COMMENT ON TABLE scam_indicators IS 'Detection rules & risk indicators. Weights feed the deterministic baseline engine (Module 2 first, then AI layer).';
CREATE TRIGGER scam_indicators_set_updated_at
    BEFORE UPDATE ON scam_indicators
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 9. RISK_ASSESSMENTS --------------------------------------------------------
-- One row per user submission analysis. Risk score = indicator for further
-- assessment, NEVER a legal finding (master prompt §3/§6).
CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT REFERENCES users(user_id) ON DELETE SET NULL, -- anonymised on POPIA deletion
    assessment_type     assessment_type NOT NULL,
    risk_category       risk_category   NOT NULL,
    risk_score          NUMERIC(5,2)    NOT NULL,        -- 0..100, engine-computed
    engine_source       assessment_source NOT NULL DEFAULT 'BASELINE_ENGINE',
    ai_model_name       VARCHAR(120),         -- configurable NVIDIA model used (if any)
    ai_validated        BOOLEAN,              -- did AI output pass schema validation?
    ai_response         JSONB,                -- validated AI payload (never executed, display-only)
    input_content       TEXT NOT NULL,        -- the submitted text/description
    input_url           VARCHAR(2048),        -- submitted link (never auto-fetched app-side)
    input_amount        NUMERIC(14,2),        -- e.g. the R2,000 demo investment
    summary             TEXT NOT NULL,        -- plain-language explanation
    recommended_actions TEXT,                 -- next steps shown to the user
    limitations         TEXT,                 -- recorded uncertainty / limitations
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT risk_assessments_score_range CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT risk_assessments_amount_non_negative CHECK (input_amount IS NULL OR input_amount >= 0),
    CONSTRAINT risk_assessments_ai_needs_model
        CHECK (engine_source NOT IN ('NVIDIA_AI', 'HYBRID') OR ai_model_name IS NOT NULL),
    CONSTRAINT risk_assessments_ai_needs_validation_flag
        CHECK (engine_source NOT IN ('NVIDIA_AI', 'HYBRID') OR ai_validated IS NOT NULL)
);
COMMENT ON TABLE risk_assessments IS 'Assessment history (Module 2/3/5). AI output is advisory only and validated before storage.';
CREATE INDEX IF NOT EXISTS idx_assessments_user_time ON risk_assessments (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_type      ON risk_assessments (assessment_type);
CREATE INDEX IF NOT EXISTS idx_assessments_category  ON risk_assessments (risk_category);
CREATE TRIGGER risk_assessments_set_updated_at
    BEFORE UPDATE ON risk_assessments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 10. ASSESSMENT_EVIDENCE ----------------------------------------------------
-- Every fired indicator is stored with a code snapshot so results stay
-- explainable even if the indicator is later retired (§6 explainability).
CREATE TABLE IF NOT EXISTS assessment_evidence (
    evidence_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id           BIGINT NOT NULL REFERENCES risk_assessments(assessment_id) ON DELETE CASCADE,
    indicator_id            BIGINT REFERENCES scam_indicators(indicator_id) ON DELETE SET NULL,
    indicator_code_snapshot VARCHAR(50) NOT NULL,   -- frozen code at assessment time
    description             TEXT NOT NULL,          -- WHY this indicator fired for this input
    matched_text            TEXT,                   -- excerpt of the submission that triggered it
    weight_applied          NUMERIC(5,2),           -- weight snapshot (catalogue may change later)
    source                  assessment_source NOT NULL DEFAULT 'BASELINE_ENGINE',
    confidence              NUMERIC(4,3),           -- AI confidence 0..1 for this evidence, if any
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT assessment_evidence_confidence_range
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);
COMMENT ON TABLE assessment_evidence IS 'Per-indicator supporting evidence - "Store sufficient assessment evidence to explain results".';
CREATE INDEX IF NOT EXISTS idx_evidence_assessment ON assessment_evidence (assessment_id);

-- 11. PRE_PAYMENT_CHECKS -----------------------------------------------------
-- Module 5 journey: simulated payment details -> warning -> user decision.
-- NEVER store full account numbers or credentials - only masked references.
CREATE TABLE IF NOT EXISTS pre_payment_checks (
    payment_check_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id             BIGINT NOT NULL REFERENCES risk_assessments(assessment_id) ON DELETE CASCADE,
    recipient_name            VARCHAR(200) NOT NULL,
    recipient_reference_masked VARCHAR(60),  -- e.g. '**** 4521' - full numbers are forbidden
    payment_amount            NUMERIC(14,2) NOT NULL,
    payment_description       VARCHAR(500),
    warning_shown             BOOLEAN NOT NULL DEFAULT FALSE,
    user_action               pre_payment_action,   -- NULL while journey in progress
    decided_at                TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ppc_amount_positive CHECK (payment_amount > 0),
    CONSTRAINT ppc_decision_pairing CHECK (
        (user_action IS NULL AND decided_at IS NULL)
        OR (user_action IS NOT NULL AND decided_at IS NOT NULL)
    )
);
COMMENT ON TABLE pre_payment_checks IS 'Pre-payment protection journey log; feeds the "successful completion" evaluation metric (Phase 6).';
CREATE INDEX IF NOT EXISTS idx_ppc_assessment ON pre_payment_checks (assessment_id);

-- ============================================================================
-- PROVIDER CATALOGUE (table 12)
-- ============================================================================

-- 12. PRODUCT_PROVIDERS ------------------------------------------------------
-- v1.1: fsca_record_id is a PLAIN BIGINT. It used to reference
-- fsca_provider_records, which was removed by product decision and must not
-- be re-created. The column is kept so a future verification feature can
-- adopt it without a destructive migration.
CREATE TABLE IF NOT EXISTS product_providers (
    provider_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider_name       VARCHAR(200) NOT NULL,
    fsca_record_id      BIGINT,
    fsca_license_number VARCHAR(50),
    website_url         VARCHAR(2048),
    contact_email       VARCHAR(255),
    contact_phone       VARCHAR(32),
    is_participating    BOOLEAN NOT NULL DEFAULT FALSE, -- hackathon participating provider
    is_simulated        BOOLEAN NOT NULL DEFAULT TRUE,  -- safe default: treat as simulated until verified
    data_source         VARCHAR(100) NOT NULL DEFAULT 'SIMULATED',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT product_providers_name_unique UNIQUE (provider_name)
);
COMMENT ON TABLE product_providers IS 'Participating banks / authorised providers. Sponsored results MUST be disclosed in the UI (§7).';
CREATE TRIGGER product_providers_set_updated_at
    BEFORE UPDATE ON product_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 13. ASSESSMENT_PRODUCT_MATCHES --------------------------------------------
-- v1.1: product_id is a PLAIN BIGINT NOT NULL. It used to reference
-- financial_products (also removed). The unique (assessment_id, product_id)
-- pair and the product index are kept so a future catalogue can be attached
-- with a single non-destructive migration.
CREATE TABLE IF NOT EXISTS assessment_product_matches (
    match_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id   BIGINT NOT NULL REFERENCES risk_assessments(assessment_id) ON DELETE CASCADE,
    product_id      BIGINT NOT NULL,
    relevance_score NUMERIC(5,2),   -- how well the product matched stated preferences
    match_reasons   TEXT,           -- explainability: why this alternative was suggested
    presented_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT matches_unique UNIQUE (assessment_id, product_id)
);
COMMENT ON TABLE assessment_product_matches IS 'Records which alternatives were shown for which assessment (traceability + sponsored-result disclosure).';
CREATE INDEX IF NOT EXISTS idx_matches_product ON assessment_product_matches (product_id);

-- ============================================================================
-- REPORTS, EDUCATION & AUDIT (tables 14-17)
-- ============================================================================

-- 14. SCAM_REPORTS -----------------------------------------------------------
-- Reporter identity is protected: reporter_id is nulled if the user deletes
-- their account; reports are not public by default (is_public = FALSE).
CREATE TABLE IF NOT EXISTS scam_reports (
    report_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reporter_id      BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    assessment_id    BIGINT REFERENCES risk_assessments(assessment_id) ON DELETE SET NULL, -- report may originate from an assessment
    title            VARCHAR(200) NOT NULL,
    description      TEXT NOT NULL,
    channel          scam_channel NOT NULL DEFAULT 'OTHER',
    reported_url     VARCHAR(2048),
    reported_contact VARCHAR(255),          -- scammer's phone/email/handle (never displayed publicly)
    occurred_at      TIMESTAMPTZ,           -- when the incident happened (user-supplied)
    -- UI report-popup fields (migration 0002) - the form the frontend collects:
    phishing_type    VARCHAR(120),          -- free text w/ datalist, e.g. 'SMS phishing (smishing)'
    risk_level       risk_category,         -- high/medium/low/unsure (unsure = INCONCLUSIVE)
    amount_asked     NUMERIC(14,2),         -- 'Amount asked for' (Rand)
    amount_promised  NUMERIC(14,2),         -- 'Amount promised' (Rand)
    screenshot_path  VARCHAR(500),          -- uploaded PNG/JPG path (max 5 MB, API-enforced)
    content_hash     CHAR(64)   NOT NULL,   -- SHA-256 of normalised content for duplicate detection
    duplicate_of_id  BIGINT REFERENCES scam_reports(report_id) ON DELETE SET NULL,
    status           report_status NOT NULL DEFAULT 'SUBMITTED',
    is_public        BOOLEAN NOT NULL DEFAULT FALSE,  -- unpublished by default (§8 protects identities)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT reports_hash_required CHECK (char_length(content_hash) = 64),
    CONSTRAINT scam_reports_amount_asked_non_negative    CHECK (amount_asked    IS NULL OR amount_asked    >= 0),
    CONSTRAINT scam_reports_amount_promised_non_negative CHECK (amount_promised IS NULL OR amount_promised >= 0)
);
COMMENT ON TABLE scam_reports IS 'Duplicates are LINKED via duplicate_of_id, not silently merged - duplicates never become independently verified evidence (§8).';
CREATE INDEX IF NOT EXISTS idx_reports_reporter ON scam_reports (reporter_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_status   ON scam_reports (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_hash     ON scam_reports (content_hash);
CREATE INDEX IF NOT EXISTS idx_reports_risk_level ON scam_reports (risk_level) WHERE risk_level IS NOT NULL;
CREATE TRIGGER scam_reports_set_updated_at
    BEFORE UPDATE ON scam_reports
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 15. SCAM_REPORT_REVIEWS ----------------------------------------------------
-- Admin decision trail. Append-only by convention: a later decision is a NEW
-- row, never an UPDATE of history (see audit hardening notes below).
CREATE TABLE IF NOT EXISTS scam_report_reviews (
    review_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    report_id   BIGINT NOT NULL REFERENCES scam_reports(report_id) ON DELETE CASCADE,
    reviewer_id BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    action      review_action NOT NULL,
    notes       TEXT,
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE scam_report_reviews IS 'One row per admin decision (approve / reject / requires investigation).';
CREATE INDEX IF NOT EXISTS idx_reviews_report ON scam_report_reviews (report_id, decided_at DESC);

-- 16. EDUCATIONAL_RESOURCES --------------------------------------------------
-- language column exists so additional South African languages can be added
-- later without schema changes (§6 Module 6 requirement).
CREATE TABLE IF NOT EXISTS educational_resources (
    resource_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title          VARCHAR(200) NOT NULL,
    slug           VARCHAR(220) NOT NULL,          -- include language, e.g. 'ponzi-schemes-en'
    topic          education_topic NOT NULL,
    summary        VARCHAR(500) NOT NULL,
    content        TEXT NOT NULL,
    language       VARCHAR(10)  NOT NULL DEFAULT 'en',
    official_links JSONB,                          -- [{label, url}] to OFFICIAL resources only
    display_order  SMALLINT NOT NULL DEFAULT 0,
    is_published   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by     BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT edu_slug_unique UNIQUE (slug)
);
COMMENT ON TABLE educational_resources IS 'Learning hub content (Module 6). Links must point to official sources (FSCA, SAPS, SAFPS, SABRIC...).';
CREATE INDEX IF NOT EXISTS idx_edu_topic_lang ON educational_resources (topic, language);
CREATE TRIGGER educational_resources_set_updated_at
    BEFORE UPDATE ON educational_resources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 17. AUDIT_LOGS -------------------------------------------------------------
-- Append-only by design. The application must never UPDATE or DELETE rows
-- here, and admins must not be able to alter audit history (§10).
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    action        audit_action NOT NULL,
    entity_type   VARCHAR(100) NOT NULL,   -- e.g. 'scam_report', 'educational_resource'
    entity_id     BIGINT,                  -- id at time of action (may reference deleted rows)
    details       JSONB,                   -- context/changes; NEVER secrets or raw personal data
    ip_hash       CHAR(64),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE audit_logs IS 'Append-only security & admin trail. Enforce immutability with the grants below (owner bypasses REVOKE - use a dedicated app role).';
CREATE INDEX IF NOT EXISTS idx_audit_entity     ON audit_logs (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_logs (action, created_at DESC);

-- ----------------------------------------------------------------------------
-- PRODUCTION HARDENING (run manually as the Neon owner AFTER creating a
-- dedicated least-privilege app role, e.g. `scam_shield_app`):
--
--   REVOKE UPDATE, DELETE ON audit_logs        FROM scam_shield_app;
--   REVOKE UPDATE, DELETE ON scam_report_reviews FROM scam_shield_app;
--
-- This makes the audit trail and review history physically append-only for
-- the application role, even if application code contains a bug.
-- (The Neon/owner role bypasses REVOKEs - that is expected for migrations.)
-- ----------------------------------------------------------------------------

COMMIT;

-- ============================================================================
-- HANDOVER TO ALEMBIC
-- ============================================================================
-- 1. Keep this file under version control as db/baseline/001_baseline.sql.
-- 2. Build your SQLAlchemy models to match this schema.
-- 3. Generate the initial Alembic revision and verify (offline) that its DDL
--    is consistent with this baseline.
-- 4. On the Neon database that ran this script, execute:
--        alembic stamp head
--    Alembic now records the baseline as applied and only NEW migrations run.
--
-- DEMO SEED follows in this file (clearly labelled).
-- ============================================================================

-- ============================================================================
-- ============================ DEMO SEED DATA ================================
-- DEMONSTRATION DATA ONLY - every row below is synthetic and clearly labelled.
-- Safe to run against a demo environment; SKIP this section in production.
-- Re-running is safe (idempotent guards prevent duplicates).
-- ============================================================================

-- ---- Roles -----------------------------------------------------------------
INSERT INTO roles (role_name, description) VALUES
    ('USER',  'General user: submits checks, views assessments, manages profile'),
    ('ADMIN', 'Administrator: reviews reports, manages content, providers, audit'),
    ('STAKEHOLDER', 'External partner who lists investment offers and can be granted report visibility')
ON CONFLICT (role_name) DO NOTHING;

-- ---- Demo accounts ---------------------------------------------------------
-- Email domain 'demo.example' is reserved for documentation - never deliverable.
-- Passwords (demo only, change for any real deployment):
--   admin@demo.example -> 'Admin!Demo2026'
--   user@demo.example  -> 'User!Demo2026'
INSERT INTO users (email, password_hash, full_name) VALUES
    ('admin@demo.example', '$2b$12$3S2OvSldsg3ADr7VEEi2D.caWia/V8vo9fvgbt8jDy/PIgwthmPJC', 'Demo Administrator'),
    ('user@demo.example',  '$2b$12$88c8BwxGMeikTnARdNPTQuDsbcnmYPnlhZ45OCfYgcSc2hx6svgoW', 'Demo User')
ON CONFLICT (email) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u
JOIN roles r ON r.role_name IN ('ADMIN', 'USER')
WHERE (u.email = 'admin@demo.example' AND r.role_name = 'ADMIN')
   OR (u.email = 'user@demo.example'  AND r.role_name = 'USER')
ON CONFLICT DO NOTHING;

-- ---- Scam indicator catalogue (12 demo rules) -------------------------------
INSERT INTO scam_indicators
    (indicator_code, name, description, category, severity, default_weight,
     is_scam_indicator, is_pyramid_ponzi_indicator, is_pre_payment_indicator, source)
VALUES
    ('URGENT_PAYMENT_DEMAND',
     'Urgent payment demand',
     'The message pressures you to pay or act within hours, using threats or ''limited offer'' language. Legitimate financial providers do not rush you.',
     'URGENCY_PRESSURE', 'HIGH', 8, TRUE, FALSE, TRUE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('OTP_PIN_REQUEST',
     'Requests your OTP, PIN or password',
     'Anyone asking for your one-time PIN, banking PIN or password is attempting fraud. No bank or service provider will ever ask you for these.',
     'CREDENTIAL_REQUEST', 'CRITICAL', 10, TRUE, FALSE, TRUE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('SUSPICIOUS_LINK',
     'Suspicious or mismatched link',
     'The link does not match the claimed organisation''s official domain, or hides its real destination. This is common in phishing messages.',
     'SUSPICIOUS_LINK', 'HIGH', 7, TRUE, FALSE, FALSE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('BANK_IMPERSONATION',
     'Impersonation of a bank or brand',
     'The sender claims to represent a bank or well-known brand but uses unofficial contact details, generic greetings or unusual language.',
     'IMPERSONATION', 'HIGH', 8, TRUE, FALSE, TRUE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('UNEXPECTED_RECIPIENT',
     'Payment to an unexpected recipient',
     'You are asked to pay a person or account you have never paid before, or that does not match the story you were given.',
     'PAYMENT_INSTRUCTION', 'MEDIUM', 6, FALSE, FALSE, TRUE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('UNUSUAL_PAYMENT_METHOD',
     'Unusual payment method requested',
     'Payment is requested via gift vouchers, cryptocurrency, ''flipping'' e-wallets or cash deposits to a stranger - hallmarks of common South African scams.',
     'PAYMENT_INSTRUCTION', 'HIGH', 7, TRUE, FALSE, TRUE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('UNREALISTIC_RETURN_PROMISE',
     'Unrealistic return promise',
     'The promised returns are far above normal market returns while claiming little or no risk. High returns always carry high risk.',
     'UNREALISTIC_RETURN', 'HIGH', 8, FALSE, TRUE, FALSE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('GUARANTEED_RETURNS',
     'Guaranteed fixed returns',
     'Guaranteed fixed returns are not a feature of legitimate regulated investments. Regulators, including the FSCA, warn against anyone guaranteeing returns.',
     'UNREALISTIC_RETURN', 'CRITICAL', 9, FALSE, TRUE, FALSE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('RECRUITMENT_BASED_EARNINGS',
     'Earnings depend on recruiting',
     'Your earnings depend mainly on signing up new members instead of selling a genuine product or service - the core mechanic of a pyramid scheme.',
     'RECRUITMENT_PRESSURE', 'CRITICAL', 10, FALSE, TRUE, FALSE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('VAGUE_BUSINESS_MODEL',
     'Vague or unclear business model',
     'It is unclear how the scheme actually makes money. ''Trading secrets'' or ''matching bonuses'' with no real product are red flags.',
     'OPAQUE_BUSINESS_MODEL', 'MEDIUM', 6, FALSE, TRUE, FALSE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('WITHDRAWAL_RESTRICTIONS',
     'Withdrawal restrictions or fees',
     'You cannot withdraw your money, or withdrawals require unexplained fees or new deposits - a common sign of a Ponzi scheme running out of new money.',
     'WITHDRAWAL_RESTRICTION', 'HIGH', 8, FALSE, TRUE, FALSE,
     'Demo seed (based on public scam-awareness guidance)'),
    ('PRESSURE_TO_INVEST_NOW',
     'Pressure to invest immediately',
     'You are told the offer closes today or that spots are limited, to stop you verifying the provider through the FSCA first.',
     'URGENCY_PRESSURE', 'HIGH', 7, FALSE, TRUE, TRUE,
     'Demo seed (based on public scam-awareness guidance)')
ON CONFLICT (indicator_code) DO NOTHING;

-- ---- Simulated participating providers (2) ----------------------------------
-- v1.1: no fsca_provider_records join (that table was removed);
-- fsca_record_id stays NULL in fresh installs.
INSERT INTO product_providers
    (provider_name, fsca_license_number, website_url,
     contact_email, is_participating, is_simulated, data_source)
SELECT v.name, v.lic, v.site, v.email, TRUE, TRUE, 'SIMULATED_DEMO'
FROM (VALUES
    ('Example Bank Ltd (simulated)', 'FSP 10001', 'https://www.examplebank.example',
     'info@examplebank.example'),
    ('Example Wealth Managers (Pty) Ltd (simulated)', 'FSP 20002', 'https://www.examplewealth.example',
     'info@examplewealth.example')
) AS v(name, lic, site, email)
WHERE NOT EXISTS (
    SELECT 1 FROM product_providers x WHERE x.provider_name = v.name
);

-- ---- Educational resources (5 demo articles) --------------------------------
-- Links point to real OFFICIAL South African organisations' home pages only
-- (no fabricated deep links). Language 'en'; add more languages later by
-- inserting rows with a new slug suffix (e.g. '-zu').
INSERT INTO educational_resources
    (title, slug, topic, summary, content, language, official_links,
     display_order, is_published, created_by)
SELECT v.title, v.slug, v.topic::education_topic, v.summary, v.content, 'en',
       v.links::jsonb, v.ord, TRUE,
       (SELECT user_id FROM users WHERE email = 'admin@demo.example')
FROM (VALUES
    ('How pyramid schemes work', 'how-pyramid-schemes-work-en', 'PYRAMID_SCHEMES',
     'A pyramid scheme pays old members with money from new recruits, and collapses when recruitment slows.',
     'In a pyramid scheme, you are asked to join by paying a fee and to earn money mainly by recruiting new members. There is usually no real product, or an overpriced token product, so the only money entering the scheme comes from new recruits. Because recruitment eventually slows down, the scheme must collapse, and most members - those at the bottom - lose their money. Warning signs include ''matching bonuses'', team-building pressure and income claims that depend on your downline rather than sales. Remember: a risk score in this application is an indicator for further assessment, not a legal finding.',
     '[{"label": "FSCA", "url": "https://www.fsca.co.za"}]'::jsonb,
     1),
    ('How Ponzi schemes work', 'how-ponzi-schemes-work-en', 'PONZI_SCHEMES',
     'A Ponzi scheme pretends to invest your money but actually pays earlier investors with newer investors'' deposits.',
     'A Ponzi scheme collects money from investors and claims it is being invested, but in reality the operator simply moves money between investors. Early investors may be paid impressive ''returns'' taken from later investors'' deposits, which builds false trust and triggers word-of-mouth growth. When new deposits slow down, withdrawals stop - ''technical problems'' and unexplained fees appear - and the scheme collapses. The difference from a pyramid scheme is that a Ponzi scheme hides behind a fake investment story, while a pyramid scheme openly rewards recruitment. Both are illegal, and neither is a licensed investment.',
     '[{"label": "FSCA", "url": "https://www.fsca.co.za"}]'::jsonb,
     2),
    ('Verify a provider with the FSCA', 'verify-provider-fsca-en', 'PROVIDER_VERIFICATION',
     'Before you hand over money, check that the person or company is authorised by the Financial Sector Conduct Authority.',
     'Anyone selling financial products or advice in South Africa must be authorised by the FSCA and appear on its public register with an FSP number. Search the official FSCA website directly and confirm the authorisation covers the specific service you are being offered. Check the provider''s name, FSP number and contact details carefully, because fraudsters impersonate real companies with slightly changed names, domains or phone numbers. If no match exists, that is not proof of fraud by itself, but you should stop and investigate further before paying anything.',
     '[{"label": "FSCA", "url": "https://www.fsca.co.za"}]'::jsonb,
     3),
    ('Protect your PIN, password and OTP', 'protect-pin-otp-en', 'CREDENTIAL_SAFETY',
     'Your PIN, password and one-time PINs are the keys to your money - never share them with anyone.',
     'No bank, provider or IT support person will ever call, SMS or email you to ask for your PIN, password or a one-time PIN (OTP). Criminals create urgency - ''your account will be closed'', ''confirm a payment'' - to make you share codes before you have time to think. Use long, unique passwords for banking, switch on app-based notifications, and treat any unexpected OTP request as an attack in progress. If you shared a code by mistake, contact your bank immediately and change your password.',
     '[{"label": "SABRIC", "url": "https://www.sabric.co.za"}]'::jsonb,
     4),
    ('What to do after a suspected scam', 'after-suspected-scam-en', 'AFTER_A_SCAM',
     'Act fast: contact your bank, report the incident, and keep every message and receipt as evidence.',
     'If you suspect you paid a scammer, call your bank''s fraud line immediately - banks can sometimes stop or reverse a payment if you act quickly. Report the incident to the South African Police Service and to the Southern African Fraud Prevention Service so your details are protected and the case is on record. Do not delete the messages, links or proof of payment - screenshot everything, because this is the evidence investigators and this application''s report review will rely on. Finally, be alert to ''recovery scams'': fraudsters who contact victims promising to recover lost money for a fee.',
     '[{"label": "SAPS", "url": "https://www.saps.gov.za"}, {"label": "SAFPS", "url": "https://www.safps.org.za"}]'::jsonb,
     5)
) AS v(title, slug, topic, summary, content, links, ord)
WHERE NOT EXISTS (
    SELECT 1 FROM educational_resources e WHERE e.slug = v.slug
);

-- ---- Demo financial preferences for the demo user ---------------------------
INSERT INTO user_financial_preferences
    (user_id, income_range, available_budget, savings_goal,
     investment_timeframe, risk_preference, needs_liquid_access, consent_given_at)
SELECT u.user_id, 'R5_000_TO_R10_000', 2000.00, 'Build an emergency fund',
       'ONE_TO_THREE_YEARS', 'CONSERVATIVE', TRUE, now()
FROM users u
WHERE u.email = 'user@demo.example'
  AND NOT EXISTS (
      SELECT 1 FROM user_financial_preferences f WHERE f.user_id = u.user_id
  );

-- ============================================================================
-- Migration 0003: stakeholders + investment offers (frontend integration)
-- ============================================================================

-- ---- Stakeholder org/profile metadata (1:1 with users) ---------------------
CREATE TABLE stakeholder_profiles (
    stakeholder_id  SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
    organisation    VARCHAR(150) NOT NULL,
    org_type        VARCHAR(20)  NOT NULL,
    access          VARCHAR(10)  NOT NULL DEFAULT 'view',
    alerts          VARCHAR(10)  NOT NULL DEFAULT 'none',
    invite_pending  BOOLEAN      NOT NULL DEFAULT TRUE,
    last_active_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT stakeholder_profiles_org_type CHECK (
        org_type IN ('bank','telco','regulator','police','consumer','other')),
    CONSTRAINT stakeholder_profiles_access CHECK (access IN ('view','review')),
    CONSTRAINT stakeholder_profiles_alerts CHECK (alerts IN ('none','high','all'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stakeholder_profiles_user ON stakeholder_profiles (user_id);
CREATE TRIGGER stakeholder_profiles_set_updated_at
    BEFORE UPDATE ON stakeholder_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---- Investment offers owned by stakeholder users --------------------------
CREATE TABLE stakeholder_offers (
    offer_id                 SERIAL PRIMARY KEY,
    user_id                  INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    product_name             VARCHAR(150) NOT NULL,
    product_category         VARCHAR(80)  NOT NULL,
    description              TEXT NOT NULL,
    currency                 VARCHAR(8)   NOT NULL DEFAULT 'ZAR',
    min_investment           NUMERIC(14,2) NOT NULL,
    max_investment           NUMERIC(14,2) NOT NULL,
    fees_summary             TEXT,
    indicative_return_range  VARCHAR(120),
    access_condition         VARCHAR(300),
    material_risk            TEXT,
    suitable_timeframe       VARCHAR(120),
    url                      VARCHAR(500),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT stakeholder_offers_min_max CHECK (max_investment >= min_investment),
    CONSTRAINT stakeholder_offers_amounts_non_negative
        CHECK (min_investment >= 0 AND max_investment >= 0)
);
CREATE INDEX IF NOT EXISTS idx_stakeholder_offers_user ON stakeholder_offers (user_id);
CREATE TRIGGER stakeholder_offers_set_updated_at
    BEFORE UPDATE ON stakeholder_offers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END OF SCRIPT
-- ============================================================================
-- * All 19 tables created; triggers, indexes and constraints in place.
--   (v1.1: fsca_provider_records, fsca_warnings, fsca_verification_checks and
--   financial_products were REMOVED and are intentionally absent.)
-- * Demo seed data inserted and clearly labelled (is_simulated = TRUE,
--   'demo.example' emails, 'Demo ...' names).
-- * risk_assessments, assessment_evidence, pre_payment_checks,
--   assessment_product_matches, scam_reports, scam_report_reviews,
--   login_attempts, refresh_tokens and audit_logs are intentionally EMPTY -
--   they are populated at runtime by the application.
-- * Next step: build SQLAlchemy models to match, then `alembic stamp head`.
-- ============================================================================

