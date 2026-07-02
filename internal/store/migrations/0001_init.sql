CREATE TABLE IF NOT EXISTS users (
  username             TEXT PRIMARY KEY,
  hashed_password      TEXT NOT NULL,
  role                 TEXT NOT NULL DEFAULT 'viewer',   -- admin|operator|viewer
  disabled             INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0
);

-- sedi/tenant visibili per utente (vuoto = tutti)
CREATE TABLE IF NOT EXISTS user_tenants (
  username TEXT,
  tenant   TEXT,
  PRIMARY KEY(username, tenant)
);

CREATE TABLE IF NOT EXISTS tenants (                     -- ex "groups"
  name        TEXT PRIMARY KEY,
  description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS devices (
  ip                TEXT PRIMARY KEY,
  vendor            TEXT NOT NULL,
  profile           TEXT DEFAULT 'custom',
  username          TEXT DEFAULT '',
  password_enc      TEXT DEFAULT '',                     -- AES-GCM
  enable_secret_enc TEXT DEFAULT '',
  tenant            TEXT NOT NULL DEFAULT 'Generale',
  hostname          TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS detected_versions (
  ip         TEXT PRIMARY KEY,
  vendor     TEXT,
  version    TEXT,
  status     TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS categories (
  key     TEXT PRIMARY KEY,
  label   TEXT,
  builtin INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS subcategories (
  category TEXT,
  name     TEXT,
  PRIMARY KEY(category, name)
);

-- assegnazioni/override manuali per nodo (ex category_assignments)
CREATE TABLE IF NOT EXISTS device_meta (
  node_id     TEXT PRIMARY KEY,   -- IP o "discovered_<host>"
  category    TEXT DEFAULT '',
  subcategory TEXT DEFAULT '',
  vendor      TEXT DEFAULT '',
  model       TEXT DEFAULT '',
  ha_group    TEXT DEFAULT '',
  name        TEXT DEFAULT '',
  ver         TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vendors (
  name      TEXT PRIMARY KEY,
  euvd_term TEXT,
  driver    TEXT
);

CREATE TABLE IF NOT EXISTS models (
  vendor TEXT,
  model  TEXT,
  PRIMARY KEY(vendor, model)
);

CREATE TABLE IF NOT EXISTS mac_sightings (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  mac          TEXT NOT NULL,
  oui_vendor   TEXT DEFAULT '',
  vlan         TEXT DEFAULT '',
  switch_ip    TEXT NOT NULL,
  switch_name  TEXT DEFAULT '',
  interface    TEXT DEFAULT '',
  port_channel TEXT DEFAULT '',
  is_uplink    INTEGER DEFAULT 0,
  tenant       TEXT DEFAULT '',
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  seen_count   INTEGER DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mac_pos ON mac_sightings(mac, switch_ip, interface, vlan);
CREATE INDEX IF NOT EXISTS ix_mac       ON mac_sightings(mac);
CREATE INDEX IF NOT EXISTS ix_switch    ON mac_sightings(switch_ip);
CREATE INDEX IF NOT EXISTS ix_last_seen ON mac_sightings(last_seen);
CREATE INDEX IF NOT EXISTS ix_tenant    ON mac_sightings(tenant);

CREATE TABLE IF NOT EXISTS mac_cmd_overrides (
  switch_ip TEXT PRIMARY KEY,
  command   TEXT NOT NULL,
  fmt       TEXT DEFAULT 'generic'
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);
