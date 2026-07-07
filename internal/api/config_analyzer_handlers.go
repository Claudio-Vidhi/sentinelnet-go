package api

import (
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/go-chi/chi/v5"
)

// handleConfigAnalyzerAll: GET /api/config-analyzer?group=all — analizza tutti i
// dispositivi in inventario che hanno un backup, applicando lo scoping per sede
// (tenant consentiti) ed un eventuale filtro di gruppo. Contratto: {"devices":[...]}.
func (a *App) handleConfigAnalyzerAll(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	group := r.URL.Query().Get("group")

	devices, err := a.store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	backupDir := a.cfg.BackupDir()
	results := []*configanalyzer.DeviceResult{}
	for _, d := range devices {
		g := d.Tenant
		if g == "" {
			g = "Generale"
		}
		if !canSeeTenant(scoped, g) {
			continue
		}
		if group != "" && group != "all" && g != group {
			continue
		}
		if res := configanalyzer.AnalyzeDevice(backupDir, d.IP, d.Tenant, d.Hostname); res != nil {
			results = append(results, res)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": results})
}

// handleConfigAnalyzerDevice: GET /api/config-analyzer/{ip} — analizza il singolo
// dispositivo. 403 se fuori dallo scope dell'utente, 404 se nessun backup.
func (a *App) handleConfigAnalyzerDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	ip := chi.URLParam(r, "ip")

	dev, err := a.store.GetDevice(ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	invGroup, invHostname := "", ""
	if dev != nil {
		invGroup, invHostname = dev.Tenant, dev.Hostname
		if scoped != nil {
			g := dev.Tenant
			if g == "" {
				g = "Generale"
			}
			if !canSeeTenant(scoped, g) {
				writeErr(w, http.StatusForbidden, "Dispositivo non consentito per il tuo profilo.")
				return
			}
		}
	}

	res := configanalyzer.AnalyzeDevice(a.cfg.BackupDir(), ip, invGroup, invHostname)
	if res == nil {
		writeErr(w, http.StatusNotFound, "Nessun backup trovato per "+ip+".")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
