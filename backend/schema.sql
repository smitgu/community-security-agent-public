-- schema.sql
-- Run once against your PostgreSQL database to create all required tables.
-- Example: psql -h localhost -U postgres -d bgin_agent -f schema.sql

-- ── Incidents ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id                          SERIAL PRIMARY KEY,
    incident_name               TEXT NOT NULL,
    on_chain_iocs               TEXT NOT NULL DEFAULT '',
    behavioral_iocs             TEXT NOT NULL DEFAULT '',
    governance_operational_iocs TEXT NOT NULL DEFAULT '',
    source_file                 TEXT NOT NULL DEFAULT '',
    content_hash                VARCHAR(16) UNIQUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incidents_name ON incidents (incident_name);
CREATE INDEX IF NOT EXISTS idx_incidents_hash ON incidents (content_hash);

-- ── Company Policies ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS company_policies (
    id          SERIAL PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    policy_text TEXT NOT NULL DEFAULT '',
    source_file TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policies_name ON company_policies (policy_name);

-- ── Allowed Users ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS allowed_users (
    user_id  BIGINT PRIMARY KEY,
    role     TEXT NOT NULL DEFAULT '',
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Sensitivity Audit Log ──────────────────────────────────────────────────────
-- Records every uploaded document with its classification and detection details.
-- Provides an admin review queue for CONFIDENTIAL and INTERNAL documents.
CREATE TABLE IF NOT EXISTS sensitivity_audit (
    id                SERIAL PRIMARY KEY,
    uploaded_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    uploaded_by       BIGINT,                          -- optional user identifier
    filename          TEXT,
    classification    TEXT NOT NULL,                   -- PUBLIC | INTERNAL | CONFIDENTIAL
    action_taken      TEXT NOT NULL,                   -- PASSED | SCRUBBED | BLOCKED
    detected_entities JSONB         NOT NULL DEFAULT '[]',  -- JSON array of detected signals
    raw_document      TEXT,                            -- full text (stored for CONFIDENTIAL only)
    review_status     TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected | reclassified
    reviewed_by       TEXT,
    reviewed_at       TIMESTAMPTZ,
    reviewer_notes    TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_classification ON sensitivity_audit (classification);
CREATE INDEX IF NOT EXISTS idx_audit_review_status  ON sensitivity_audit (review_status);
CREATE INDEX IF NOT EXISTS idx_audit_uploaded_at    ON sensitivity_audit (uploaded_at);
CREATE INDEX IF NOT EXISTS idx_audit_uploaded_by    ON sensitivity_audit (uploaded_by);

-- ── Add sensitivity_level to incidents (safe to run on existing DB) ────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS sensitivity_level TEXT NOT NULL DEFAULT 'PUBLIC';

