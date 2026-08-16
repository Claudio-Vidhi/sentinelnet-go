package api

import (
	"fmt"
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/clientdiag"
)

// POST /api/diagnose/client
func (a *App) handleDiagnoseClient(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req clientdiag.Request
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	if req.Tenant != "" {
		if allowedTenants != nil && !containsStr(allowedTenants, req.Tenant) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", req.Tenant))
			return
		}
	} else if allowedTenants != nil {
		req.Scope = allowedTenants
	}

	rep, err := clientdiag.Diagnose(r.Context(), a.store, a.obs, req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	logMsg := fmt.Sprintf("Diagnosi client '%s'", req.Client)
	if req.Dest != "" {
		logMsg += fmt.Sprintf(" verso '%s'", req.Dest)
	}
	logMsg += fmt.Sprintf(" richiesta da '%s'.", claims.Username)
	a.auditLog(logMsg)

	writeJSON(w, http.StatusOK, rep)
}

// GET /api/diagnose/gateway-candidates
func (a *App) handleGetGatewayCandidates(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	tenant := r.URL.Query().Get("tenant")
	if tenant != "" && allowedTenants != nil && !containsStr(allowedTenants, tenant) {
		writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", tenant))
		return
	}

	candidates, err := clientdiag.GetGatewayCandidates(a.store, tenant, allowedTenants)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, candidates)
}

type tracerouteGatewayReq struct {
	Target string `json:"target"`
}

// POST /api/diagnose/traceroute-gateway
func (a *App) handleTracerouteGateway(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req tracerouteGatewayReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	res, err := clientdiag.DetectGatewayTraceroute(req.Target, allowedTenants)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}
