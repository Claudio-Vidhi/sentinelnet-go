// Package api: handler HTTP delle sedi multi-sito e del relay comandi verso
// le sedi in modalità agent. Porta di routers/sites.py.
package api

import (
	"net/http"
	"regexp"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

var reIPv4 = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// handleListSites: GET /api/sites.
func (a *App) handleListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := a.store.ListSites()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": sites})
}

type siteReq struct {
	Name    string   `json:"name"`
	Mode    string   `json:"mode"`
	Subnets []string `json:"subnets"`
}

// handleCreateSite: POST /api/sites.
//
// Il token in chiaro è restituito UNA SOLA VOLTA: su disco resta solo l'hash,
// e nessuna API può più recuperarlo.
func (a *App) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var req siteReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Mode == "" {
		req.Mode = store.ModeCentral
	}
	site, token, err := a.store.CreateSite(req.Name, req.Mode, req.Subnets)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Sede '" + site.ID + "' (mode: " + req.Mode + ") creata da '" + claims.Username + "'.")

	out := map[string]any{"status": "success", "site": site}
	if token != "" {
		out["token"] = token
	}
	writeJSON(w, http.StatusOK, out)
}

type siteUpdateReq struct {
	ID      string    `json:"id"`
	Name    *string   `json:"name"`
	Mode    *string   `json:"mode"`
	Subnets *[]string `json:"subnets"`
}

// handleUpdateSite: POST /api/sites/update. I campi assenti restano invariati.
func (a *App) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	var req siteUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	ok, err := a.store.UpdateSite(req.ID, req.Name, req.Mode, req.Subnets)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "Sede non trovata.")
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Sede '" + req.ID + "' aggiornata da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

type siteIDReq struct {
	ID string `json:"id"`
}

// handleDeleteSite: POST /api/sites/delete.
func (a *App) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	var req siteIDReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	ok, err := a.store.DeleteSite(req.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, "Sede non eliminabile o inesistente.")
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Sede '" + req.ID + "' eliminata da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

// handleRegenerateSiteToken: POST /api/sites/regenerate-token.
func (a *App) handleRegenerateSiteToken(w http.ResponseWriter, r *http.Request) {
	var req siteIDReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	token, err := a.store.RegenerateSiteToken(req.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if token == "" {
		writeErr(w, http.StatusBadRequest, "Sede inesistente o non in modalità agent.")
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Token della sede '" + req.ID + "' rigenerato da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "token": token})
}

type siteCommandReq struct {
	IP      string `json:"ip"`
	Command string `json:"command"`
}

// handleSiteCommand: POST /api/sites/{site_id}/command — accoda un comando CLI
// per un dispositivo di una sede agent. L'agente lo preleva in polling, lo
// esegue in locale e ne posta il risultato.
func (a *App) handleSiteCommand(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "site_id")
	site, err := a.store.GetSite(siteID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if site == nil {
		writeErr(w, http.StatusNotFound, "Sede non trovata.")
		return
	}
	if site.Mode != store.ModeAgent {
		writeErr(w, http.StatusBadRequest,
			"Il relay comandi è disponibile solo per sedi in modalità agent.")
		return
	}

	var req siteCommandReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !reIPv4.MatchString(req.IP) {
		writeErr(w, http.StatusBadRequest, "IP non valido.")
		return
	}

	claims := claimsFrom(r.Context())
	if !a.commandAllowed(req.Command, claims) {
		a.auditLog("Relay comando bloccato (blacklist) '" + req.Command + "' su '" + req.IP +
			"' sede '" + siteID + "' da '" + claims.Username + "'.")
		writeErr(w, http.StatusBadRequest,
			"Comando non consentito per motivi di sicurezza (in blacklist).")
		return
	}
	// Un comando distruttivo relayato è eseguito da un agente su un apparato
	// remoto, dove nessuno è in sala macchine a rimediare: se qualcuno lo
	// autorizza, deve restare scritto chi e perché.
	if !isCommandSafe(req.Command) {
		a.auditLog("Relay comando in blacklist '" + req.Command + "' su '" + req.IP +
			"' sede '" + siteID + "' consentito a '" + claims.Username + "' " +
			bypassNote(claims) + ".")
	}

	job, err := a.store.EnqueueJob(siteID, req.IP, req.Command, claims.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Comando CLI accodato per sede agent '" + siteID + "' su '" + req.IP +
		"' da '" + claims.Username + "' (job " + job.ID + ").")
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "job_id": job.ID})
}

// handleGetCommandJob: GET /api/command-jobs/{job_id}.
func (a *App) handleGetCommandJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetJob(chi.URLParam(r, "job_id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if job == nil {
		writeErr(w, http.StatusNotFound, "Job non trovato.")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleListSiteCommandJobs: GET /api/sites/{site_id}/command-jobs.
func (a *App) handleListSiteCommandJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.ListJobs(chi.URLParam(r, "site_id"), 100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}
