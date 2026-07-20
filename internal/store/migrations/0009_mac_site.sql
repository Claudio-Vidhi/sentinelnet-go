-- Sede di provenienza di un avvistamento MAC.
--
-- Il Python ce l'ha (collectors/mac_history.py la aggiunge con una ALTER e la
-- usa come filtro in search); il port l'aveva persa. Serve al push MAC degli
-- agenti: senza, gli avvistamenti raccolti in una sede remota sarebbero
-- indistinguibili da quelli del centrale, che è esattamente l'attribuzione per
-- cui esiste la modalità agent.
ALTER TABLE mac_sightings ADD COLUMN site TEXT NOT NULL DEFAULT 'central';

CREATE INDEX IF NOT EXISTS ix_mac_site ON mac_sightings(site);
