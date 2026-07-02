package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/mac"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
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

	pruned, _ := a.store.PruneSightings(a.store.RetentionDays())
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
		s := &store.MacSighting{
			Mac: e.Mac, OuiVendor: "", Vlan: e.Vlan, SwitchIP: d.IP, SwitchName: switchName,
			Interface: e.Interface, PortChannel: pc, IsUplink: mac.IsUplinkPort(perIface[e.Interface]),
			Tenant: d.Tenant,
		}
		if err := a.store.UpsertSighting(s); err == nil {
			saved++
		}
	}
	return saved, nil
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
