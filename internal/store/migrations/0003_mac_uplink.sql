-- Vicino verso cui punta l'uplink su cui il MAC è stato visto in transito
-- (hostname del device raggiunto via quell'interfaccia). Vuoto = porta d'accesso.
ALTER TABLE mac_sightings ADD COLUMN uplink_to TEXT DEFAULT '';
