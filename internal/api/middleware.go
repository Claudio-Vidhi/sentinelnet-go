package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// requireAuth: estrae il Bearer JWT, valida e inietta i claims nel context.
// Livello minimo di ruolo: "" (viewer+), "operator", "admin".
func (a *App) requireAuth(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeErr(w, http.StatusUnauthorized, "token mancante")
			return
		}
		claims, err := a.auth.ParseToken(token)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "token non valido")
			return
		}
		// L'utente potrebbe essere stato disabilitato/eliminato dopo l'emissione.
		u, err := a.store.GetUser(claims.Username)
		if err != nil || u == nil || u.Disabled {
			writeErr(w, http.StatusUnauthorized, "utente non valido o disabilitato")
			return
		}
		claims.Role = u.Role // fonte di verità: il ruolo nel DB
		if !roleAtLeast(u.Role, minRole) {
			writeErr(w, http.StatusForbidden, "privilegi insufficienti")
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	if cookie, err := r.Cookie("net_session"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}

// assertDeviceAllowed risolve un IP nel device di inventario e ne verifica lo scoping
// per tenant. Porta di routers/deps.py:assert_device_allowed.
//
// È il punto unico di controllo: gli endpoint che accettano un IP dal client
// (FortiGate, WLC, AI, observability) devono passare da qui e non reimplementare
// la coppia lookup+scoping, altrimenti un utente può leggere device di altri tenant.
// In caso di esito negativo scrive già la risposta HTTP e ritorna ok=false.
func (a *App) assertDeviceAllowed(w http.ResponseWriter, r *http.Request, ip string) (*store.Device, bool) {
	claims := claimsFrom(r.Context())
	d, err := a.store.GetDevice(ip)
	if err != nil || d == nil {
		writeErr(w, http.StatusNotFound, "Dispositivo non presente in inventario")
		return nil, false
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, d.Tenant) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return nil, false
	}
	return d, true
}

var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

func roleAtLeast(role, min string) bool {
	if min == "" {
		return true
	}
	return roleRank[role] >= roleRank[min]
}
