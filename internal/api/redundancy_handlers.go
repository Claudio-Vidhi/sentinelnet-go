package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/redundancy"
	"github.com/go-chi/chi/v5"
)

// GET /api/redundancy/groups
func (a *App) handleListRedundancyGroups(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"results": []any{}})
		return
	}

	groups, err := redundancy.ListGroups(a.obs.DB, allowedTenants)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": groups})
}



// GET /api/redundancy/groups/{id}
func (a *App) handleGetRedundancyGroup(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Gruppo non trovato.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	g, err := redundancy.GetGroup(a.obs.DB, id)
	if err != nil || g == nil {
		writeErr(w, http.StatusNotFound, "Group not found")
		return
	}

	if allowedTenants != nil && !containsStr(allowedTenants, g.GroupName) {
		writeErr(w, http.StatusForbidden, "Access denied")
		return
	}

	writeJSON(w, http.StatusOK, g)
}

// POST /api/redundancy/groups
func (a *App) handleCreateRedundancyGroup(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusInternalServerError, "Database osservabilita non disponibile.")
		return
	}

	var g redundancy.GroupInfo
	if err := decodeJSON(r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	if g.GroupName == "" {
		g.GroupName = "default"
	}
	if allowedTenants != nil && !containsStr(allowedTenants, g.GroupName) {
		writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", g.GroupName))
		return
	}

	if g.DetectionSource == "" {
		g.DetectionSource = "manual"
	}
	if g.Health == "" {
		g.Health = g.ComputeHealth()
	}

	id, err := redundancy.SaveGroup(a.obs.DB, g)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	created, _ := redundancy.GetGroup(a.obs.DB, id)
	a.auditLog(fmt.Sprintf("Gruppo ridondanza '%s' creato da '%s'.", g.Name, claims.Username))
	writeJSON(w, http.StatusCreated, created)
}

// PUT /api/redundancy/groups/{id}
func (a *App) handleUpdateRedundancyGroup(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusInternalServerError, "Database osservabilita non disponibile.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	existing, err := redundancy.GetGroup(a.obs.DB, id)
	if err != nil || existing == nil {
		writeErr(w, http.StatusNotFound, "Group not found")
		return
	}

	if allowedTenants != nil && !containsStr(allowedTenants, existing.GroupName) {
		writeErr(w, http.StatusForbidden, "Access denied")
		return
	}

	var g redundancy.GroupInfo
	if err := decodeJSON(r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	g.ID = id
	if g.GroupName == "" {
		g.GroupName = existing.GroupName
	}
	if allowedTenants != nil && !containsStr(allowedTenants, g.GroupName) {
		writeErr(w, http.StatusForbidden, "Access denied")
		return
	}
	if g.DetectionSource == "" {
		g.DetectionSource = existing.DetectionSource
	}
	if g.Health == "" {
		g.Health = g.ComputeHealth()
	}

	_, err = redundancy.SaveGroup(a.obs.DB, g)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, _ := redundancy.GetGroup(a.obs.DB, id)
	a.auditLog(fmt.Sprintf("Gruppo ridondanza #%d ('%s') aggiornato da '%s'.", id, g.Name, claims.Username))
	writeJSON(w, http.StatusOK, updated)
}

// DELETE /api/redundancy/groups/{id}
func (a *App) handleDeleteRedundancyGroup(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusInternalServerError, "Database osservabilita non disponibile.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	existing, err := redundancy.GetGroup(a.obs.DB, id)
	if err != nil || existing == nil {
		writeErr(w, http.StatusNotFound, "Group not found")
		return
	}

	if allowedTenants != nil && !containsStr(allowedTenants, existing.GroupName) {
		writeErr(w, http.StatusForbidden, "Access denied")
		return
	}

	_ = redundancy.DeleteGroup(a.obs.DB, id)
	a.auditLog(fmt.Sprintf("Gruppo ridondanza #%d ('%s') eliminato da '%s'.", id, existing.Name, claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})
}

