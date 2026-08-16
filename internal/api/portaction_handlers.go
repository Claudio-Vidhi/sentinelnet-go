package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/portaction"
)

type portBounceReq struct {
	ClientMAC string `json:"client_mac"`
	SwitchIP  string `json:"switch_ip"`
	Interface string `json:"interface"`
}

// POST /api/diagnose/port-bounce
func (a *App) handleDiagnosePortBounce(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req portBounceReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	dev, err := a.store.GetDevice(req.SwitchIP)
	if err != nil || dev == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("Apparato %s non in inventario.", req.SwitchIP))
		return
	}
	if allowedTenants != nil && !containsStr(allowedTenants, dev.Tenant) {
		writeErr(w, http.StatusForbidden, "Dispositivo non consentito per il tuo profilo.")
		return
	}

	if req.ClientMAC != "" {
		ok, reason := portaction.VerifyPort(a.store, req.ClientMAC, req.SwitchIP, req.Interface, allowedTenants)
		if !ok {
			a.auditLog(fmt.Sprintf("Port bounce RIFIUTATO su '%s' porta '%s' per client '%s' (utente '%s'): %s",
				req.SwitchIP, req.Interface, req.ClientMAC, claims.Username, reason))
			writeErr(w, http.StatusConflict, reason)
			return
		}
	}

	creds := a.resolveCreds(dev)
	if dev.SSHPort > 0 {
		creds.Port = dev.SSHPort
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	a.auditLog(fmt.Sprintf("Port bounce AVVIATO da '%s' su '%s' porta '%s'.", claims.Username, req.SwitchIP, req.Interface))

	res, err := portaction.Bounce(ctx, dev.IP, creds, dev.Vendor, req.Interface, 2.0)
	if err != nil {
		a.auditLog(fmt.Sprintf("Port bounce FALLITO su '%s' porta '%s': %v", req.SwitchIP, req.Interface, err))
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	a.auditLog(fmt.Sprintf("Port bounce ESEGUITO con successo su '%s' porta '%s' da '%s'.", req.SwitchIP, req.Interface, claims.Username))
	writeJSON(w, http.StatusOK, res)
}

type interfaceStateReq struct {
	SwitchIP  string `json:"switch_ip"`
	Interface string `json:"interface"`
	AdminUp   bool   `json:"admin_up"`
}

// POST /api/interfaces/state
func (a *App) handleSetInterfaceState(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req interfaceStateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	dev, err := a.store.GetDevice(req.SwitchIP)
	if err != nil || dev == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("Apparato %s non in inventario.", req.SwitchIP))
		return
	}
	if allowedTenants != nil && !containsStr(allowedTenants, dev.Tenant) {
		writeErr(w, http.StatusForbidden, "Dispositivo non consentito per il tuo profilo.")
		return
	}

	creds := a.resolveCreds(dev)
	if dev.SSHPort > 0 {
		creds.Port = dev.SSHPort
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	stateStr := "riaccensione (no shutdown)"
	if !req.AdminUp {
		stateStr = "spegnimento (shutdown)"
	}
	a.auditLog(fmt.Sprintf("Cambio stato interfaccia '%s' su '%s' ad '%s' richiesto da '%s'.",
		req.Interface, req.SwitchIP, stateStr, claims.Username))

	res, err := portaction.SetAdminState(ctx, dev.IP, creds, dev.Vendor, req.Interface, req.AdminUp)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}
