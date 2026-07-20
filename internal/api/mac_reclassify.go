package api

import "github.com/Claudio-Vidhi/sentinelnet-go/internal/store"

// macReclassifier ricalcola in LETTURA la classificazione degli avvistamenti
// contro la topologia corrente. Porta di _reclassify_sightings (routers/mac.py).
//
// Serve perché is_uplink viene deciso al momento della raccolta: dopo un
// cambio di topologia (nuovo vicino CDP/LLDP, port-channel creato o rimosso)
// le righe già salvate resterebbero classificate come prima finché non si
// riscansiona. Ricalcolando a ogni lettura, la risposta riflette sempre la
// topologia nota adesso.
type macReclassifier struct {
	// uplinks: switch_ip → porta normalizzata → vicino raggiunto.
	// Contiene SOLO gli switch per cui esistono dati topologici.
	uplinks map[string]map[string]string
	ifMacs  map[string]store.SwitchIfMac
}

// newMacReclassifier raccoglie una volta sola i dati necessari
// (topologia di tutti i device + MAC di infrastruttura).
func (a *App) newMacReclassifier() *macReclassifier {
	rc := &macReclassifier{uplinks: map[string]map[string]string{}}
	rc.ifMacs, _ = a.store.SwitchIfMacs()

	devices, err := a.store.ListDevices()
	if err != nil {
		return rc
	}
	for _, d := range devices {
		if m := a.uplinkInterfaces(d.IP); len(m) > 0 {
			rc.uplinks[d.IP] = m
		}
	}
	return rc
}

// apply aggiorna le righe sul posto.
//
// Per gli switch con dati topologici la topologia è autorevole: assenza della
// porta in mappa significa porta di accesso. Per gli switch senza topologia si
// conserva il valore rilevato in raccolta (port-channel ed euristica trunk),
// che è il fallback descritto dal docstring del Python.
func (rc *macReclassifier) apply(rows []*store.MacSighting) {
	for _, s := range rows {
		if ups, known := rc.uplinks[s.SwitchIP]; known {
			neigh := ups[normPort(s.Interface)]
			if neigh == "" && s.PortChannel != "" {
				neigh = ups[normPort(s.PortChannel)]
			}
			s.IsUplink = neigh != ""
			s.UplinkTo = neigh
		}
		// I MAC delle interfacce proprie degli switch sono infrastruttura:
		// si taggano, non si scartano.
		if info, ok := rc.ifMacs[s.Mac]; ok {
			s.OriginType = "switch-interface"
			s.OriginSwitch = info.SwitchName
			if s.OriginSwitch == "" {
				s.OriginSwitch = info.SwitchIP
			}
			s.OriginInterface = info.Interface
		} else {
			s.OriginType = "endpoint"
		}
	}
}
