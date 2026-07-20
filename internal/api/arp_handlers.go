package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/arp"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/driver"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"golang.org/x/sync/errgroup"
)

// arpScanReq ha la stessa forma di macScanReq (MacScanSchema lato Python).
type arpScanReq struct {
	Group string   `json:"group"`
	IP    string   `json:"ip"`
	IPs   []string `json:"ips"`
}

// handleARPScan raccoglie le tabelle ARP dagli apparati selezionati e
// storicizza i binding MAC<->IP.
//
// Il gateway di una VLAN può essere uno switch L3 o un firewall: si interroga
// tutto ciò che è selezionato e chi non ruota VLAN torna "empty", che non è un
// errore.
func (a *App) handleARPScan(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req arpScanReq
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
	if len(targets) == 0 {
		writeErr(w, http.StatusNotFound, "Nessun dispositivo idoneo per la scansione ARP.")
		return
	}

	perDevice := map[string]map[string]any{}
	totalNew, totalUpdated := 0, 0
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(r.Context())
	g.SetLimit(8)
	for _, d := range targets {
		d := d
		g.Go(func() error {
			dctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			defer cancel()
			entry, counts := a.arpScanDevice(dctx, d)
			mu.Lock()
			perDevice[d.IP] = entry
			totalNew += counts.New
			totalUpdated += counts.Updated
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	a.auditLog("Scansione ARP eseguita da '" + claims.Username + "' su " +
		strconv.Itoa(len(targets)) + " apparati (nuovi: " + strconv.Itoa(totalNew) +
		", aggiornati: " + strconv.Itoa(totalUpdated) + ").")

	writeJSON(w, http.StatusOK, map[string]any{
		"devices":       perDevice,
		"total_new":     totalNew,
		"total_updated": totalUpdated,
	})
}

// arpScanDevice interroga un singolo apparato e registra i binding trovati.
func (a *App) arpScanDevice(ctx context.Context, d *store.Device) (map[string]any, store.ARPCounts) {
	var zero store.ARPCounts

	// I FortiGate espongono la ARP via REST (fortigate_service lato Python).
	// Finché quel client non è portato, si dichiara l'apparato non gestibile
	// invece di inviargli un comando CLI sbagliato.
	if driver.IsFortinet(d.Vendor) {
		return map[string]any{
			"status":  "error",
			"message": "raccolta ARP FortiGate non disponibile: richiede il client REST (non ancora portato)",
		}, zero
	}

	drv := a.driverFor(d.Vendor)
	sess, err := collect.Dial(ctx, d.IP, a.resolveCreds(d))
	if err != nil {
		return map[string]any{"status": "error", "message": err.Error()}, zero
	}
	defer sess.Close()

	entries := arp.ParseOutput(sess.Run(drv.ARPCommand()))
	if len(entries) == 0 {
		return map[string]any{
			"status":  "empty",
			"message": "nessuna entry ARP (non ruota VLAN?)",
		}, zero
	}

	rows := make([]store.ARPInput, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, store.ARPInput{MAC: e.MAC, IP: e.IP, VLAN: e.VLAN, Interface: e.Interface})
	}
	// PAN-OS è l'unico driver non-Fortinet che rappresenta un firewall.
	sourceType := "switch"
	if _, isPan := drv.(driver.PaloAlto); isPan {
		sourceType = "firewall"
	}
	counts, err := a.store.RecordARPEntries(rows, d.IP, d.Hostname, sourceType, d.Tenant, d.Site)
	if err != nil {
		return map[string]any{"status": "error", "message": err.Error()}, zero
	}
	return map[string]any{
		"status":  "success",
		"entries": len(entries),
		"new":     counts.New,
		"updated": counts.Updated,
		"skipped": counts.Skipped,
	}, counts
}

func (a *App) handleARPSearch(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	q := r.URL.Query()

	res, err := a.store.SearchARP(q.Get("mac"), q.Get("ip"), q.Get("source_ip"),
		scoped, queryLimit(q.Get("limit"), 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": res})
}

// handleARPClientMap: vista client unificata (MAC + IP + switch/porta di accesso).
// Il parametro tenant restringe la vista, sempre dentro lo scope dell'utente.
func (a *App) handleARPClientMap(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	q := r.URL.Query()

	if tenant := q.Get("tenant"); tenant != "" && tenant != "all" {
		if canSeeTenant(scoped, tenant) {
			scoped = []string{tenant}
		} else {
			scoped = []string{} // fuori scope: nessun risultato, mai un errore
		}
	}

	res, err := a.store.ClientMap(q.Get("mac"), q.Get("ip"), q.Get("source_ip"),
		scoped, queryLimit(q.Get("limit"), 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": res})
}

func (a *App) handleARPStats(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)

	bindings, macs, sources, err := a.store.ARPStats(scoped)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bindings": bindings, "unique_macs": macs, "sources": sources,
	})
}

func queryLimit(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}
