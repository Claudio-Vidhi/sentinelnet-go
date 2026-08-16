package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// GET /api/endpoints/list
func (a *App) handleGetEndpointsList(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	tenant := r.URL.Query().Get("tenant")
	site := r.URL.Query().Get("site")
	switchIP := r.URL.Query().Get("switch")
	vlan := r.URL.Query().Get("vlan")
	q := r.URL.Query().Get("q")
	staleDays, _ := strconv.Atoi(r.URL.Query().Get("stale_days"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	var scopedTenants []string
	if tenant != "" && tenant != "all" {
		if allowedTenants != nil && !containsStr(allowedTenants, tenant) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", tenant))
			return
		}
		scopedTenants = []string{tenant}
	} else if allowedTenants != nil {
		scopedTenants = allowedTenants
	}

	opts := store.EndpointInventoryOptions{
		Tenants:   scopedTenants,
		Site:      site,
		SwitchIP:  switchIP,
		VLAN:      vlan,
		Query:     strings.TrimSpace(q),
		StaleDays: staleDays,
		Limit:     limit,
	}

	res, err := a.store.EndpointInventory(opts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// GET /api/endpoints/ports
func (a *App) handleGetEndpointPorts(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	switchIP := strings.TrimSpace(r.URL.Query().Get("switch"))
	if switchIP == "" {
		writeErr(w, http.StatusBadRequest, "Parametro switch obbligatorio")
		return
	}

	dev, err := a.store.GetDevice(switchIP)
	if err != nil || dev == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("Apparato %s non in inventario.", switchIP))
		return
	}
	if allowedTenants != nil && !containsStr(allowedTenants, dev.Tenant) {
		writeErr(w, http.StatusForbidden, "Dispositivo non consentito per il tuo profilo.")
		return
	}

	res, err := a.store.PortOccupancy(switchIP, allowedTenants)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}
