CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    messages_json TEXT NOT NULL DEFAULT '[]',
    created_ts INTEGER NOT NULL,
    updated_ts INTEGER NOT NULL,
    username TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_conversations_user_updated
    ON ai_conversations(username, updated_ts DESC);

CREATE TABLE IF NOT EXISTS snmp_tenant_defaults (
    tenant TEXT PRIMARY KEY,
    community TEXT NOT NULL
);
