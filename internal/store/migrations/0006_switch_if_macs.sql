-- MAC delle interfacce PROPRIE degli switch (indirizzi di infrastruttura).
-- Servono a classificare un avvistamento come "switch-interface" invece che
-- come endpoint: sono MAC di apparati di rete, non di client.
-- Porta di switch_if_macs in collectors/mac_history.py.
CREATE TABLE IF NOT EXISTS switch_if_macs (
  mac         TEXT NOT NULL,
  switch_ip   TEXT NOT NULL,
  switch_name TEXT DEFAULT '',
  interface   TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  PRIMARY KEY (mac, switch_ip, interface)
);

CREATE INDEX IF NOT EXISTS ix_if_macs_mac ON switch_if_macs(mac);
