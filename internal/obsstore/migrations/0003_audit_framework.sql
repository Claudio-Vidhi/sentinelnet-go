-- 0003_audit_framework.sql: Framework di NetSec Audit e Audit Checklist

CREATE TABLE IF NOT EXISTS netsec_audit_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    tenant          TEXT,
    device_name     TEXT,
    device_ip       TEXT,
    benchmark       TEXT NOT NULL,
    benchmark_title TEXT,
    vendor          TEXT,
    lang            TEXT DEFAULT 'it',
    score           INTEGER,
    summary_json    TEXT,
    result_json     TEXT NOT NULL,
    actor           TEXT,
    run_name        TEXT
);
CREATE INDEX IF NOT EXISTS idx_netsec_audit_ts     ON netsec_audit_runs(ts);
CREATE INDEX IF NOT EXISTS idx_netsec_audit_tenant ON netsec_audit_runs(tenant, ts);

CREATE TABLE IF NOT EXISTS audit_templates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version    INTEGER NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'published',
    created_ts INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'system',
    notes      TEXT
);

CREATE TABLE IF NOT EXISTS audit_template_items (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id       INTEGER NOT NULL,
    ref               TEXT NOT NULL,
    section_no        INTEGER NOT NULL DEFAULT 1,
    section_title     TEXT NOT NULL,
    title             TEXT NOT NULL,
    guidance_why      TEXT,
    guidance_good     TEXT,
    guidance_how      TEXT,
    thresholds_json   TEXT,
    check_kind        TEXT NOT NULL DEFAULT 'manual',
    severity_default  TEXT NOT NULL DEFAULT 'media',
    is_prerequisite   INTEGER NOT NULL DEFAULT 0,
    requires_evidence INTEGER NOT NULL DEFAULT 0,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(template_id) REFERENCES audit_templates(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_tpl_items ON audit_template_items(template_id, ref);

CREATE TABLE IF NOT EXISTS audit_engagements (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id       INTEGER NOT NULL,
    customer_name     TEXT NOT NULL,
    tenant            TEXT,
    site_id           TEXT,
    created_ts        INTEGER NOT NULL,
    status            TEXT NOT NULL DEFAULT 'in_corso',
    assigned_to       TEXT,
    scope_notes       TEXT,
    onsite_or_remote  TEXT NOT NULL DEFAULT 'remote',
    interviewee       TEXT,
    FOREIGN KEY(template_id) REFERENCES audit_templates(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_eng_tenant ON audit_engagements(tenant, created_ts);

CREATE TABLE IF NOT EXISTS audit_engagement_items (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id       INTEGER NOT NULL,
    item_ref            TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'non_valutato',
    severity            TEXT,
    finding_text        TEXT,
    recommendation_text TEXT,
    ai_assisted         INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(engagement_id) REFERENCES audit_engagements(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_eng_item_ref ON audit_engagement_items(engagement_id, item_ref);

CREATE TABLE IF NOT EXISTS audit_evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    item_ref      TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'text',
    filename      TEXT,
    path          TEXT,
    payload_json  TEXT,
    confidential  INTEGER NOT NULL DEFAULT 1,
    created_ts    INTEGER NOT NULL,
    FOREIGN KEY(engagement_id) REFERENCES audit_engagements(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_evidence_eng ON audit_evidence(engagement_id, item_ref);

CREATE TABLE IF NOT EXISTS audit_engagement_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    item_ref      TEXT NOT NULL,
    field_changed TEXT NOT NULL,
    old_value     TEXT,
    new_value     TEXT,
    changed_by    TEXT,
    changed_ts    INTEGER NOT NULL,
    FOREIGN KEY(engagement_id) REFERENCES audit_engagements(id) ON DELETE CASCADE
);
