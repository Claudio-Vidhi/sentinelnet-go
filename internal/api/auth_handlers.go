package api

import (
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
)

func (a *App) handleAuthStatus(w http.ResponseWriter, _ *http.Request) {
	n, err := a.store.UserCount()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_users": n > 0})
}

type registerReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleRegister crea il PRIMO admin (solo se non esistono utenti).
func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.UserCount()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		writeErr(w, http.StatusForbidden, "esiste già un amministratore")
		return
	}
	var req registerReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if len(req.Username) == 0 {
		writeErr(w, http.StatusBadRequest, "username obbligatorio")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.store.CreateUser(req.Username, hash, "admin", false); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := a.auth.CheckLockout(req.Username); err != nil {
		writeErr(w, http.StatusTooManyRequests, err.Error())
		return
	}
	u, err := a.store.GetUser(req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if u == nil || u.Disabled || !auth.CheckPassword(u.HashedPassword, req.Password) {
		a.auth.RecordFailure(req.Username)
		writeErr(w, http.StatusUnauthorized, "credenziali non valide")
		return
	}
	a.auth.ResetFailures(req.Username)
	token, err := a.auth.IssueToken(u.Username, u.Role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     "net_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":         token,
		"token_type":           "bearer",
		"role":                 u.Role,
		"must_change_password": u.MustChangePassword,
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "net_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type changePwReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req changePwReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := a.store.GetUser(claims.Username)
	if err != nil || u == nil {
		writeErr(w, http.StatusUnauthorized, "utente non trovato")
		return
	}
	if !auth.CheckPassword(u.HashedPassword, req.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "vecchia password errata")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.store.SetUserPassword(claims.Username, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	// Gli admin non sono mai ristretti: niente tab da nascondere lato frontend,
	// quindi lista vuota senza nemmeno leggere il DB.
	tabs := []string{}
	if claims.Role != "admin" {
		if u, err := a.store.GetUser(claims.Username); err == nil && u != nil {
			tabs = u.AllowedTabs
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     claims.Username,
		"role":         claims.Role,
		"allowed_tabs": tabs,
	})
}
