-- Dati di topologia per apparato, popolati dal triage (CDP/LLDP, port-channel, VTP).
CREATE TABLE IF NOT EXISTS topology_data (
  ip                TEXT PRIMARY KEY,
  hostname          TEXT DEFAULT '',
  vtp_domain        TEXT DEFAULT '',
  vtp_mode          TEXT DEFAULT '',
  neighbors_json    TEXT DEFAULT '[]',   -- []Neighbor serializzato
  portchannels_json TEXT DEFAULT '[]',   -- []PortChannel serializzato
  updated_at        TEXT DEFAULT ''
);
