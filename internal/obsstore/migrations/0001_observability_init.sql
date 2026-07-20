-- observability.db — porta di observability/storage/schema.sql.
-- Database SEPARATO da sentinelnet.db di proposito: il volume di scrittura
-- dell'ingest UDP e le DELETE orarie di retention non devono contendere con
-- letture e scritture di inventario e autenticazione.

-- 1. FLUSSI AGGREGATI (rollup al minuto via UPSERT)
CREATE TABLE IF NOT EXISTS flow_aggregates (
    window_start   INTEGER NOT NULL,          -- unix ts troncato a 60s
    tenant         TEXT NOT NULL,             -- gruppo/sede (scope multi-gruppo)
    src_ip         TEXT NOT NULL,
    dst_ip         TEXT NOT NULL,
    protocol       INTEGER,
    dst_port       INTEGER,
    total_bytes    INTEGER NOT NULL DEFAULT 0,
    total_packets  INTEGER NOT NULL DEFAULT 0,
    flow_count     INTEGER NOT NULL DEFAULT 0,
    exporter_ip    TEXT,
    source         TEXT,                      -- listener di origine: ipfix|netflow|sflow
    UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
);
CREATE INDEX IF NOT EXISTS idx_flow_window_tenant ON flow_aggregates(window_start, tenant);
CREATE INDEX IF NOT EXISTS idx_flow_src_dst       ON flow_aggregates(src_ip, dst_ip);

-- 2. EVENTI SYSLOG normalizzati
CREATE TABLE IF NOT EXISTS syslog_events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    tenant      TEXT NOT NULL,
    device_ip   TEXT,
    severity    INTEGER,
    action      TEXT,
    message     TEXT,
    exporter_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_syslog_ts_tenant ON syslog_events(ts, tenant);
CREATE INDEX IF NOT EXISTS idx_syslog_src       ON syslog_events(device_ip);

-- 3. EVENTI CORRELATI (popolati dal correlatore)
CREATE TABLE IF NOT EXISTS correlated_events (
    id            INTEGER PRIMARY KEY,
    created_ts    INTEGER NOT NULL,
    tenant        TEXT NOT NULL,
    kind          TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    switch_port   TEXT,
    severity      INTEGER,
    status        TEXT DEFAULT 'new' CHECK(status IN ('new','ack','resolved')),
    dedup_key     TEXT UNIQUE,
    evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_corr_tenant_status ON correlated_events(tenant, status);

-- 4. OSSERVAZIONI API: snapshot periodici via REST poller.
CREATE TABLE IF NOT EXISTS api_observations (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    tenant       TEXT NOT NULL,
    device_ip    TEXT NOT NULL,
    kind         TEXT NOT NULL,            -- system_status | interfaces | sessions | wifi_clients ...
    summary_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apiobs_device_kind_ts ON api_observations(device_ip, kind, ts);

-- 5. EXPORTER SCONOSCIUTI in quarantena
CREATE TABLE IF NOT EXISTS quarantined_exporters (
    exporter_ip  TEXT PRIMARY KEY,
    first_seen   INTEGER,
    last_seen    INTEGER,
    packet_count INTEGER NOT NULL DEFAULT 0
);
