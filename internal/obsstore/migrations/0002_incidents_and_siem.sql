-- 0002_incidents_and_siem.sql: Modello eventi unificato, evidenze, incidenti, conclusioni e soppressioni SIEM

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    ingested_ts  INTEGER NOT NULL,
    tenant       TEXT NOT NULL,
    source       TEXT NOT NULL,
    source_id    INTEGER,
    event_type   TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    entity_id    TEXT NOT NULL,
    severity     INTEGER,
    device_ip    TEXT,
    interface    TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    dst_port     INTEGER,
    protocol     TEXT,
    metrics_json TEXT,
    attrs_json   TEXT,
    dedup_key    TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_events_ts_tenant  ON events(ts, tenant);
CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_entity     ON events(tenant, entity_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ingested   ON events(ingested_ts);

CREATE TABLE IF NOT EXISTS normalize_cursors (
    source   TEXT PRIMARY KEY,
    last_id  INTEGER NOT NULL DEFAULT 0,
    last_ts  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY,
    tenant         TEXT NOT NULL,
    entity_key     TEXT NOT NULL,
    opened_ts      INTEGER NOT NULL,
    last_event_ts  INTEGER NOT NULL,
    closed_ts      INTEGER,
    title          TEXT,
    severity       INTEGER,
    event_count    INTEGER NOT NULL DEFAULT 0,
    status         TEXT DEFAULT 'new' CHECK(status IN ('new','ack','resolved')),
    cause_kind     TEXT,
    confidence     INTEGER,
    reasoning_json TEXT,
    ai_narrative    TEXT,
    ai_narrative_ts INTEGER,
    ai_assisted     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incidents_open   ON incidents(tenant, closed_ts, last_event_ts);
CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents(tenant, entity_key, closed_ts);

CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY,
    created_ts   INTEGER NOT NULL,
    ts           INTEGER NOT NULL,
    tenant       TEXT NOT NULL,
    incident_id  INTEGER,
    event_id     INTEGER,
    entity_key   TEXT,
    role         TEXT NOT NULL CHECK(role IN ('trigger','supporting','symptom','consequence')),
    rule_id      TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    params_json  TEXT,
    weight       INTEGER NOT NULL DEFAULT 1,
    severity     INTEGER,
    src_ip       TEXT,
    dst_ip       TEXT,
    switch_port  TEXT,
    summary      TEXT,
    attrs_json   TEXT,
    dedup_key    TEXT UNIQUE,
    status                  TEXT NOT NULL DEFAULT 'active'
                            CHECK(status IN ('active', 'retracted')),
    retracted_by_evidence_id INTEGER,
    retracted_by_rule_id     TEXT,
    retracted_at             INTEGER,
    retracted_reason         TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_evidence_open     ON evidence(tenant, incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_evidence_event    ON evidence(event_id);
CREATE INDEX IF NOT EXISTS idx_evidence_status   ON evidence(status, incident_id);

CREATE TABLE IF NOT EXISTS incident_conclusions (
    id             INTEGER PRIMARY KEY,
    incident_id    INTEGER NOT NULL,
    concluded_ts   INTEGER NOT NULL,
    cause_kind     TEXT,
    confidence     INTEGER,
    reasoning_json TEXT,
    superseded_ts  INTEGER,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_conclusions_incident ON incident_conclusions(incident_id, concluded_ts);

CREATE TABLE IF NOT EXISTS siem_suppressions (
    event_id      INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    tenant        TEXT,
    reason        TEXT,
    suppressed_by TEXT
);
