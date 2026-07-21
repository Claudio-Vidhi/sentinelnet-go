package api

import (
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fwanalyzer"
	"github.com/go-chi/chi/v5"
)

type convertReq struct {
	Text   string `json:"text"`
	IP     string `json:"ip"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// handleConfigAnalyzerConvert: POST /api/config-analyzer/convert — conversione
// deterministica (preview) FortiOS <-> PAN-OS. Accetta testo esplicito oppure
// {ip} -> backup più recente del dispositivo (con scoping per sede).
func (a *App) handleConfigAnalyzerConvert(w http.ResponseWriter, r *http.Request) {
	var req convertReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	text := req.Text
	fromIP := false
	if text == "" && req.IP != "" {
		// Il backup di un dispositivo: risolto con lo scoping per sede, come le
		// altre rotte del config analyzer.
		if _, ok := a.assertDeviceAllowed(w, r, req.IP); !ok {
			return
		}
		t, ok := configanalyzer.LoadBackupRunningConfig(a.cfg.BackupDir(), req.IP)
		if !ok {
			writeErr(w, http.StatusNotFound, "Nessun backup trovato per "+req.IP+".")
			return
		}
		text, fromIP = t, true
	}
	if text == "" {
		writeErr(w, http.StatusBadRequest, "Fornire 'text' oppure 'ip'.")
		return
	}

	res, err := fwanalyzer.ConvertConfig(text, req.Source, req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	out := map[string]any{
		"mapped": res.Mapped, "unmapped": res.Unmapped, "preview_text": res.PreviewText,
	}
	if fromIP {
		out["source_text"] = text
	}
	writeJSON(w, http.StatusOK, out)
}

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
	results := []any{}
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
		if res := configanalyzer.AnalyzeDevice(backupDir, d.IP, d.Vendor, d.Tenant, d.Hostname); res != nil {
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
	invGroup, invHostname, vendor := "", "", ""
	if dev != nil {
		invGroup, invHostname, vendor = dev.Tenant, dev.Hostname, dev.Vendor
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

	res := configanalyzer.AnalyzeDevice(a.cfg.BackupDir(), ip, vendor, invGroup, invHostname)
	if res == nil {
		writeErr(w, http.StatusNotFound, "Nessun backup trovato per "+ip+".")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
