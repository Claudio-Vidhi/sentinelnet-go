-- Migrazione 0011: tabella identities per i profili credenziali legati ai tenant

CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tenant TEXT NOT NULL,
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL DEFAULT '',
    secret_enc TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identities_tenant ON identities(tenant);
