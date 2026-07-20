-- Colonne presenti nel CSV Python (network_hosts.csv) e mancanti nella tabella Go:
--   Site       -> scoping per sede (services/site_manager.py)
--   SSH Port   -> porta SSH non standard
--   Transports -> mappa {protocollo: porta|null} (§11.6), JSON; vuoto = solo ssh:22 (sintesi legacy)
ALTER TABLE devices ADD COLUMN site TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22;
ALTER TABLE devices ADD COLUMN transports TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_devices_site ON devices(site);
