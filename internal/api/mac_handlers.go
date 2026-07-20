package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/mac"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/topology"
	"github.com/go-chi/chi/v5"
	"golang.org/x/sync/errgroup"
)

type macScanReq struct {
	Group     string   `json:"group"`
	IP        string   `json:"ip"`
	IPs       []string `json:"ips"`
	Transport string   `json:"transport"` // netconf|restconf|cli (qui: sempre CLI)
}

func (a *App) handleMacScan(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	var req macScanReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	devices, err := a.store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	wanted := map[string]bool{}
	for _, ip := range req.IPs {
		wanted[ip] = true
	}
	if req.IP != "" {
		wanted[req.IP] = true
	}
	var targets []*store.Device
	for _, d := range devices {
		if !canSeeTenant(scoped, d.Tenant) {
			continue
		}
		if req.Group != "" && req.Group != "all" && d.Tenant != req.Group {
			continue
		}
		if len(wanted) > 0 && !wanted[d.IP] {
			continue
		}
		targets = append(targets, d)
	}

	results := make([]map[string]any, 0, len(targets))
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(r.Context())
	g.SetLimit(8)
	for _, d := range targets {
		d := d
		g.Go(func() error {
			dctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			defer cancel()
			count, err := a.macScanDevice(dctx, d)
			entry := map[string]any{"ip": d.IP, "count": count}
			if err != nil {
				entry["error"] = err.Error()
			}
			mu.Lock()
			results = append(results, entry)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	// La prune del Python agisce su entrambe le tabelle nella stessa passata;
	// "pruned" resta il conteggio dei soli avvistamenti, come nel contratto.
	retention := a.store.RetentionDays()
	pruned, _ := a.store.PruneSightings(retention)
	_, _ = a.store.PruneARP(retention)
	writeJSON(w, http.StatusOK, map[string]any{
		"scanned": len(targets),
		"results": results,
		"pruned":  pruned,
	})
}

// macScanDevice legge la MAC-table via CLI (o comando ad-hoc) e la persiste.
func (a *App) macScanDevice(ctx context.Context, d *store.Device) (int, error) {
	command := "show mac address-table"
	format := "mac-address-table"
	if ov, _ := a.store.GetMacOverride(d.IP); ov != nil {
		command = ov.Command
		format = ov.Fmt
	}

	// Interfacce uplink note dalla topologia (porte con vicino CDP/LLDP o membri
	// di port-channel): i MAC visti qui sono in transito, non collegati localmente.
	uplinkMap := a.uplinkInterfaces(d.IP)

	sess, err := collect.Dial(ctx, d.IP, a.resolveCreds(d))
	if err != nil {
		_ = a.store.SetVersionStatus(d.IP, "offline")
		return 0, err
	}
	defer sess.Close()

	out := sess.Run(command)
	var entries []mac.Entry
	switch format {
	case "bridge-domain":
		entries = mac.ParseBridgeDomain(out)
	default:
		entries = mac.ParseMacTable(out)
	}

	// Conta i MAC per interfaccia per marcare gli uplink (trunk con molti MAC).
	perIface := map[string]int{}
	for _, e := range entries {
		perIface[e.Interface]++
	}
	switchName := d.Hostname
	if switchName == "" {
		switchName = d.IP
	}
	saved := 0
	for _, e := range entries {
		if e.Mac == "" {
			continue
		}
		pc := ""
		if strings.HasPrefix(strings.ToLower(e.Interface), "po") {
			pc = e.Interface
		}
		// Uplink se: la topologia lo conferma (vicino noto), è un port-channel,
		// oppure la porta trasporta molti MAC (euristica trunk di fallback).
		neighbor, topoUplink := uplinkMap[normPort(e.Interface)]
		isUplink := topoUplink || pc != "" || mac.IsUplinkPort(perIface[e.Interface])
		uplinkTo := neighbor
		s := &store.MacSighting{
			Mac: e.Mac, OuiVendor: "", Vlan: e.Vlan, SwitchIP: d.IP, SwitchName: switchName,
			Interface: e.Interface, PortChannel: pc, IsUplink: isUplink, UplinkTo: uplinkTo,
			Tenant: d.Tenant,
		}
		if err := a.store.UpsertSighting(s); err == nil {
			saved++
		}
	}

	// MAC delle interfacce proprie dello switch: servono a classificarli come
	// infrastruttura invece che come endpoint. Non è un dato critico, quindi
	// un fallimento qui non compromette la scansione della MAC-table.
	if ifMacs := mac.ParseCLIIfMacs(sess.Run("show interfaces")); len(ifMacs) > 0 {
		rows := make([]store.IfMacInput, 0, len(ifMacs))
		for _, m := range ifMacs {
			rows = append(rows, store.IfMacInput{Interface: m.Interface, Mac: m.Mac})
		}
		_, _, _, _ = a.store.RecordSwitchIfMacs(rows, d.IP, switchName)
	}
	return saved, nil
}

// uplinkInterfaces mappa le porte uplink di uno switch (forma canonica) al nome
// del vicino raggiunto. Deriva da CDP/LLDP (porte con vicino) e dai port-channel
// (il nome del PC — es. "Po10" — è ciò che compare nella MAC-table per i bundle).
func (a *App) uplinkInterfaces(ip string) map[string]string {
	out := map[string]string{}
	row, err := a.store.GetTopology(ip)
	if err != nil || row == nil {
		return out
	}
	var neighbors []topology.Neighbor
	_ = json.Unmarshal([]byte(row.NeighborsJSON), &neighbors)
	byLocal := map[string]string{} // normPort(localPort) -> remoteHost
	for _, n := range neighbors {
		if n.LocalPort == "" {
			continue
		}
		host := n.RemoteHost
		if host == "" {
			host = n.RemoteIP
		}
		np := normPort(n.LocalPort)
		out[np] = host
		byLocal[np] = host
	}
	var pcs []topology.PortChannel
	_ = json.Unmarshal([]byte(row.PortChannelsJSON), &pcs)
	for _, pc := range pcs {
		// Vicino dell'aggregato = vicino di un qualsiasi membro.
		neigh := ""
		for _, m := range pc.Members {
			if h, ok := byLocal[normPort(m)]; ok && h != "" {
				neigh = h
				break
			}
			out[normPort(m)] = byLocal[normPort(m)] // membro fisico → uplink
		}
		out[normPort(pc.Name)] = neigh // "Po10" com'è nella MAC-table
	}
	return out
}

// handleMacLocate individua l'origine di un MAC: la/e porta/e d'accesso dove è
// realmente collegato, distinte dagli switch che l'hanno visto solo in transito
// sugli uplink (e verso quale vicino puntava quell'uplink).
func (a *App) handleMacLocate(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	macQuery := strings.TrimSpace(r.URL.Query().Get("mac"))
	if macQuery == "" {
		writeErr(w, http.StatusBadRequest, "parametro mac obbligatorio")
		return
	}
	sightings, err := a.store.SearchSightings(macQuery, "", "", "", scoped, 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(sightings) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"origin": []any{}, "transit": []any{}})
		return
	}
	// Prima di separare origine e transito: is_uplink va ricalcolato contro la
	// topologia corrente, non quello registrato al momento della raccolta.
	a.newMacReclassifier().apply(sightings)

	// Raggruppa per MAC esatto (una ricerca parziale può restituire più MAC).
	byMac := map[string][]*store.MacSighting{}
	order := []string{}
	for _, s := range sightings {
		if _, ok := byMac[s.Mac]; !ok {
			order = append(order, s.Mac)
		}
		byMac[s.Mac] = append(byMac[s.Mac], s)
	}

	type result struct {
		Mac       string               `json:"mac"`
		OUIVendor string               `json:"oui_vendor"`
		Origin    []*store.MacSighting `json:"origin"`
		Transit   []*store.MacSighting `json:"transit"`
	}
	var results []result
	for _, m := range order {
		rows := byMac[m]
		res := result{Mac: m}
		for _, s := range rows {
			if s.OuiVendor != "" {
				res.OUIVendor = s.OuiVendor
			}
			if s.IsUplink {
				res.Transit = append(res.Transit, s)
			} else {
				res.Origin = append(res.Origin, s)
			}
		}
		results = append(results, res)
	}

	// Compatibilità: se cercato un singolo MAC, esponi anche origin/transit piatti.
	if len(results) == 1 {
		writeJSON(w, http.StatusOK, map[string]any{
			"mac":     results[0].Mac,
			"origin":  results[0].Origin,
			"transit": results[0].Transit,
			"results": results,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *App) handleMacSearch(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	q := r.URL.Query()
	results, err := a.store.SearchSightings(
		q.Get("mac"), q.Get("vlan"), q.Get("interface"), q.Get("switch"), scoped, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.newMacReclassifier().apply(results)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleMacSwitchTable ritorna l'ultimo stato noto della MAC-table di uno
// switch, porto di GET /api/mac/switch/{ip} (mac_history.switch_table).
func (a *App) handleMacSwitchTable(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	ip := chi.URLParam(r, "ip")
	results, err := a.store.SearchSightings("", "", "", ip, scoped, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.newMacReclassifier().apply(results)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *App) handleMacStats(w http.ResponseWriter, _ *http.Request) {
	sightings, uniqueMacs, switches, err := a.store.MacStats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sightings":      sightings,
		"unique_macs":    uniqueMacs,
		"switches":       switches,
		"retention_days": a.store.RetentionDays(),
	})
}

type macSettingsReq struct {
	Days int `json:"days"`
}

func (a *App) handleMacSettings(w http.ResponseWriter, r *http.Request) {
	var req macSettingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Days < 1 || req.Days > 3650 {
		writeErr(w, http.StatusBadRequest, "giorni di retention non validi (1–3650)")
		return
	}
	if err := a.store.SetSetting("mac_retention_days", strconv.Itoa(req.Days)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"retention_days": req.Days})
}

func (a *App) handleMacOverrides(w http.ResponseWriter, _ *http.Request) {
	list, err := a.store.ListMacOverrides()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"overrides": list})
}

type macOverrideReq struct {
	IP      string `json:"ip"`
	Command string `json:"command"`
	Fmt     string `json:"fmt"`
}

func (a *App) handleMacOverrideSave(w http.ResponseWriter, r *http.Request) {
	var req macOverrideReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.IP == "" || strings.TrimSpace(req.Command) == "" {
		writeErr(w, http.StatusBadRequest, "IP e comando obbligatori")
		return
	}
	if req.Fmt == "" {
		req.Fmt = "generic"
	}
	if err := a.store.UpsertMacOverride(req.IP, strings.TrimSpace(req.Command), req.Fmt); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleMacOverrideDelete(w http.ResponseWriter, r *http.Request) {
	var req ipReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := a.store.DeleteMacOverride(req.IP); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
