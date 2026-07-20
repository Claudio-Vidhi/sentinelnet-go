-- Sedi multi-sito e coda dei job di comando (relay CLI centrale -> agente).
--
-- Il Python tiene le sedi in data/sites.json e i job in un agent_jobs.db
-- separato; qui vanno entrambi in tabella, come ogni altro registro già
-- migrato (gruppi, vendor, categorie, target FortiGate).
--
-- token_hash è un HASH SHA-256, non un valore cifrato: il token di sede non
-- deve mai essere recuperabile, nemmeno da chi ha la chiave del vault. È
-- mostrato una volta sola alla creazione e poi solo verificato.
CREATE TABLE IF NOT EXISTS sites (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL DEFAULT '',
  -- 'central': il centrale raggiunge i dispositivi via VPN.
  -- 'agent':   un agente remoto si connette in uscita e riceve job.
  mode       TEXT NOT NULL DEFAULT 'central',
  -- Lista JSON: le subnet di una sede sono un elenco ordinato senza query
  -- proprie, quindi una tabella figlia non aggiungerebbe niente.
  subnets    TEXT NOT NULL DEFAULT '[]',
  token_hash TEXT NOT NULL DEFAULT '',
  created    REAL NOT NULL DEFAULT 0,
  -- NULL finché l'agente non si è mai fatto vivo.
  last_seen  REAL
);

CREATE TABLE IF NOT EXISTS command_jobs (
  id           TEXT PRIMARY KEY,
  site_id      TEXT NOT NULL,
  device_ip    TEXT NOT NULL,
  command      TEXT NOT NULL,
  -- pending -> running (prelevato dall'agente) -> done | error
  status       TEXT NOT NULL DEFAULT 'pending',
  result       TEXT NOT NULL DEFAULT '',
  requested_by TEXT NOT NULL DEFAULT '',
  created      REAL NOT NULL,
  updated      REAL NOT NULL
);

-- L'agente interroga sempre per (sede, stato): è la query del polling.
CREATE INDEX IF NOT EXISTS ix_jobs_site ON command_jobs(site_id, status);

-- La sede 'central' esiste sempre e non è eliminabile.
INSERT OR IGNORE INTO sites(id, name, mode, subnets, token_hash, created)
VALUES('central', 'Central', 'central', '[]', '', 0);
