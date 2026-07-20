-- Binding MAC<->IP raccolti dalle tabelle ARP dei gateway L3 (switch SVI,
-- firewall o router). Porta di arp_entries in collectors/mac_history.py.
-- Chiave di upsert: (mac, ip, source_ip) — lo stesso binding visto da gateway
-- diversi resta una riga per gateway, che è l'informazione utile.
CREATE TABLE IF NOT EXISTS arp_entries (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  mac         TEXT NOT NULL,
  ip          TEXT NOT NULL,
  vlan        TEXT DEFAULT '',
  interface   TEXT DEFAULT '',
  source_ip   TEXT NOT NULL,
  source_name TEXT DEFAULT '',
  source_type TEXT DEFAULT '',
  tenant      TEXT DEFAULT '',
  site        TEXT DEFAULT 'central',
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  seen_count  INTEGER DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_arp    ON arp_entries(mac, ip, source_ip);
CREATE INDEX IF NOT EXISTS ix_arp_mac       ON arp_entries(mac);
CREATE INDEX IF NOT EXISTS ix_arp_ip        ON arp_entries(ip);
CREATE INDEX IF NOT EXISTS ix_arp_tenant    ON arp_entries(tenant);
CREATE INDEX IF NOT EXISTS ix_arp_last_seen ON arp_entries(last_seen);
