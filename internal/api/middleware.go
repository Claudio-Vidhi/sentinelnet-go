package api

import (
	"context"
	"net/http"
	"strings"
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
	return ""
}

var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

func roleAtLeast(role, min string) bool {
	if min == "" {
		return true
	}
	return roleRank[role] >= roleRank[min]
}
