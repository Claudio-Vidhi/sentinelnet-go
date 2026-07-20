-- Target FortiGate per l'accesso REST (token API "api-user").
-- Il Python li tiene in data/fortigate_tokens.json; qui vanno in tabella come
-- ogni altro registro già migrato (gruppi, vendor, categorie).
--
-- Il token è cifrato con lo stesso vault delle password apparato: in chiaro
-- darebbe accesso amministrativo al firewall.
CREATE TABLE IF NOT EXISTS fortigate_targets (
  ip         TEXT PRIMARY KEY,
  name       TEXT NOT NULL DEFAULT '',
  port       INTEGER NOT NULL DEFAULT 443,
  verify_tls INTEGER NOT NULL DEFAULT 0,
  token_enc  TEXT NOT NULL DEFAULT '',
  -- Un solo target può essere attivo: SetActiveFortiGateTarget azzera gli altri.
  active     INTEGER NOT NULL DEFAULT 0
);
