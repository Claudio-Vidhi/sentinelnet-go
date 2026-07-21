package api

import (
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
)

func (a *App) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := a.store.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		groups := u.Tenants
		if groups == nil {
			groups = []string{}
		}
		tabs := u.AllowedTabs
		if tabs == nil {
			tabs = []string{}
		}
		out = append(out, map[string]any{
			"username":     u.Username,
			"role":         u.Role,
			"disabled":     u.Disabled,
			"groups":       groups,
			"allowed_tabs": tabs,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *App) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Username == "" {
		writeErr(w, http.StatusBadRequest, "username obbligatorio")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validRole(req.Role) {
		req.Role = "viewer"
	}
	if existing, _ := a.store.GetUser(req.Username); existing != nil {
		writeErr(w, http.StatusConflict, "utente già esistente")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Creato da admin → deve cambiare password al primo accesso.
	if err := a.store.CreateUser(req.Username, hash, req.Role, true); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type usernameReq struct {
	Username string `json:"username"`
}

func (a *App) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req usernameReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Username == claims.Username {
		writeErr(w, http.StatusBadRequest, "non puoi eliminare te stesso")
		return
	}
	if err := a.guardLastAdmin(req.Username, ""); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.store.DeleteUser(req.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type roleReq struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (a *App) handleUserRole(w http.ResponseWriter, r *http.Request) {
	var req roleReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !validRole(req.Role) {
		writeErr(w, http.StatusBadRequest, "ruolo non valido")
		return
	}
	// Se sto degradando l'ultimo admin, blocco.
	if req.Role != "admin" {
		if err := a.guardLastAdmin(req.Username, req.Role); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := a.store.SetUserRole(req.Username, req.Role); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type disableReq struct {
	Username string `json:"username"`
	Disabled bool   `json:"disabled"`
}

func (a *App) handleUserDisable(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req disableReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Username == claims.Username {
		writeErr(w, http.StatusBadRequest, "non puoi disabilitare te stesso")
		return
	}
	if req.Disabled {
		if err := a.guardLastAdmin(req.Username, ""); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := a.store.SetUserDisabled(req.Username, req.Disabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type userGroupsReq struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

func (a *App) handleUserGroups(w http.ResponseWriter, r *http.Request) {
	var req userGroupsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := a.store.SetUserTenants(req.Username, req.Groups); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type userTabsReq struct {
	Username    string   `json:"username"`
	AllowedTabs []string `json:"allowed_tabs"`
}

// handleUserTabs: POST /api/users/tabs — assegna le tab visibili di un utente
// (vuoto = tutte). Difetto D5.
//
// È enforcement solo lato frontend: nasconde i pulsanti delle tab. Le API
// sensibili restano protette da ruolo e sede a prescindere da questo campo,
// quindi non è un controllo di sicurezza. Resta comunque in audit perché è un
// cambiamento amministrativo a un altro utente.
func (a *App) handleUserTabs(w http.ResponseWriter, r *http.Request) {
	var req userTabsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	ok, err := a.store.SetAllowedTabs(req.Username, req.AllowedTabs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "Utente non trovato.")
		return
	}
	claims := claimsFrom(r.Context())
	scope := "tutte"
	if len(req.AllowedTabs) > 0 {
		scope = strings.Join(req.AllowedTabs, ", ")
	}
	a.auditLog("Tab visibili di '" + req.Username + "' impostate a " + scope +
		" da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

func validRole(role string) bool {
	return role == "admin" || role == "operator" || role == "viewer"
}

// guardLastAdmin impedisce di rimuovere/degradare/disabilitare l'ultimo admin.
// newRole="" indica eliminazione o disabilitazione.
func (a *App) guardLastAdmin(username, newRole string) error {
	u, err := a.store.GetUser(username)
	if err != nil || u == nil || u.Role != "admin" || u.Disabled {
		return nil // il target non è un admin attivo: nessun vincolo
	}
	n, err := a.store.AdminCount()
	if err != nil {
		return err
	}
	if n <= 1 {
		return errString("deve restare almeno un amministratore attivo")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }
