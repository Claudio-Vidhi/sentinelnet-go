package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

type identitySchema struct {
	Name     string `json:"name"`
	Tenant   string `json:"tenant"`
	Username string `json:"username"`
	Password string `json:"password"`
	Secret   string `json:"secret"`
}

func newIdentityID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *App) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)

	tenantFilter := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if tenantFilter != "" {
		if !a.assertGroupAllowed(w, r, tenantFilter) {
			return
		}
	}

	list, err := a.store.ListIdentities(tenantFilter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Filter identities if user is scoped
	if scoped != nil {
		allowedSet := make(map[string]bool)
		for _, t := range scoped {
			allowedSet[t] = true
		}
		var filtered []*store.Identity
		for _, item := range list {
			if allowedSet[item.Tenant] {
				filtered = append(filtered, item)
			}
		}
		list = filtered
	}

	if list == nil {
		list = []*store.Identity{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"identities": list})
}

func (a *App) handleCreateIdentity(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "operator") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	var req identitySchema
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	tenant := strings.TrimSpace(req.Tenant)
	name := strings.TrimSpace(req.Name)
	if tenant == "" || name == "" {
		writeErr(w, http.StatusBadRequest, "Sede/tenant e nome identificativo sono obbligatori.")
		return
	}

	if !a.assertGroupAllowed(w, r, tenant) {
		return
	}

	passEnc := ""
	if req.Password != "" && a.vault != nil {
		enc, err := a.vault.Encrypt(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "errore cifratura password")
			return
		}
		passEnc = enc
	}

	secEnc := ""
	if req.Secret != "" && a.vault != nil {
		enc, err := a.vault.Encrypt(req.Secret)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "errore cifratura enable secret")
			return
		}
		secEnc = enc
	}

	ident := &store.Identity{
		ID:          newIdentityID(),
		Name:        name,
		Tenant:      tenant,
		Username:    strings.TrimSpace(req.Username),
		PasswordEnc: passEnc,
		SecretEnc:   secEnc,
	}

	if err := a.store.UpsertIdentity(ident); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog("Identità credenziali '" + name + "' (tenant '" + tenant + "') creata dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"identity": map[string]any{"id": ident.ID, "name": ident.Name, "tenant": tenant},
	})
}

func (a *App) handleUpdateIdentity(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "operator") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "ID identità mancante")
		return
	}

	existing, err := a.store.GetIdentity(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Identità non trovata.")
		return
	}

	if !a.assertGroupAllowed(w, r, existing.Tenant) {
		return
	}

	var req identitySchema
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	tenant := strings.TrimSpace(req.Tenant)
	name := strings.TrimSpace(req.Name)
	if tenant == "" || name == "" {
		writeErr(w, http.StatusBadRequest, "Sede/tenant e nome identificativo sono obbligatori.")
		return
	}

	if !a.assertGroupAllowed(w, r, tenant) {
		return
	}

	passEnc := existing.PasswordEnc
	if req.Password != "" && a.vault != nil {
		enc, err := a.vault.Encrypt(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "errore cifratura password")
			return
		}
		passEnc = enc
	}

	secEnc := existing.SecretEnc
	if req.Secret != "" && a.vault != nil {
		enc, err := a.vault.Encrypt(req.Secret)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "errore cifratura enable secret")
			return
		}
		secEnc = enc
	}

	ident := &store.Identity{
		ID:          id,
		Name:        name,
		Tenant:      tenant,
		Username:    strings.TrimSpace(req.Username),
		PasswordEnc: passEnc,
		SecretEnc:   secEnc,
	}

	if err := a.store.UpsertIdentity(ident); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog("Identità credenziali '" + name + "' (ID '" + id + "') aggiornata dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

func (a *App) handleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "operator") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "ID identità mancante")
		return
	}

	existing, err := a.store.GetIdentity(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Identità non trovata.")
		return
	}

	if !a.assertGroupAllowed(w, r, existing.Tenant) {
		return
	}

	blocked, devices, err := a.store.DeleteIdentity(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if blocked {
		writeJSON(w, http.StatusConflict, map[string]any{
			"detail":  fmt.Sprintf("Impossibile eliminare: l'identità è in uso da %d dispositivi.", len(devices)),
			"devices": devices,
		})
		return
	}

	a.auditLog("Identità credenziali '" + existing.Name + "' (ID '" + id + "') eliminata dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}
