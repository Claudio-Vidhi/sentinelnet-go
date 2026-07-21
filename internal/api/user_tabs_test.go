package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
)

// meRequest costruisce una GET /api/auth/me con i claim indicati.
func meRequest(username, role string) *http.Request {
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	return req.WithContext(context.WithValue(req.Context(), claimsKey,
		&auth.Claims{Username: username, Role: role}))
}

// /me riporta le tab visibili di un utente ristretto, così il frontend nasconde
// i pulsanti. Difetto D5: senza questo campo la UI non poteva applicarle.
func TestMeReturnsAllowedTabs(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.CreateUser("viewer1", "hash", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetAllowedTabs("viewer1", []string{"topology", "mac"}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	app.handleMe(rec, meRequest("viewer1", "viewer"))
	out := decodeBody(t, rec)

	tabs, ok := out["allowed_tabs"].([]any)
	if !ok || len(tabs) != 2 {
		t.Fatalf("allowed_tabs = %#v", out["allowed_tabs"])
	}
	if tabs[0] != "topology" || tabs[1] != "mac" {
		t.Errorf("tab = %v", tabs)
	}
}

// Un admin non è mai ristretto, anche se per errore avesse delle tab salvate:
// il campo torna sempre vuoto, come nel Python. Altrimenti un admin potrebbe
// auto-nascondersi delle tab e non avere il modo di rimetterle.
func TestMeAdminNeverRestricted(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.CreateUser("capo", "hash", "admin", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetAllowedTabs("capo", []string{"solo-questa"}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	app.handleMe(rec, meRequest("capo", "admin"))
	out := decodeBody(t, rec)

	tabs, ok := out["allowed_tabs"].([]any)
	if !ok || len(tabs) != 0 {
		t.Errorf("allowed_tabs = %#v, attesa vuota per un admin", out["allowed_tabs"])
	}
}

// /me deve rispondere anche per un utente presente solo nei claim (JWT valido,
// riga rimossa): allowed_tabs vuoto invece di un errore.
func TestMeUnknownUserYieldsEmptyTabs(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := httptest.NewRecorder()
	app.handleMe(rec, meRequest("fantasma", "viewer"))
	out := decodeBody(t, rec)
	if tabs, ok := out["allowed_tabs"].([]any); !ok || len(tabs) != 0 {
		t.Errorf("allowed_tabs = %#v", out["allowed_tabs"])
	}
}

func postTabs(t *testing.T, app *App, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/users/tabs", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, adminClaims))
	rec := httptest.NewRecorder()
	app.handleUserTabs(rec, req)
	return rec
}

// La rotta di assegnazione salva le tab e le rende visibili a /me e a /users.
func TestSetUserTabsRoundTrip(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.CreateUser("op1", "hash", "operator", false); err != nil {
		t.Fatal(err)
	}
	audit := captureAudit(t)

	rec := postTabs(t, app, `{"username":"op1","allowed_tabs":["topology","arp"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(audit(), "op1") {
		t.Errorf("assegnazione non registrata in audit: %s", audit())
	}

	u, _ := st.GetUser("op1")
	if len(u.AllowedTabs) != 2 {
		t.Errorf("tab non salvate: %#v", u.AllowedTabs)
	}
}

// Un utente inesistente risponde 404, come nel Python.
func TestSetUserTabsUnknownUserIs404(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := postTabs(t, app, `{"username":"nessuno","allowed_tabs":["topology"]}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, atteso 404: %s", rec.Code, rec.Body.String())
	}
}

// Lista vuota = tutte le tab: rimuove una restrizione precedente.
func TestSetUserTabsEmptyClearsRestriction(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.CreateUser("op2", "hash", "operator", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetAllowedTabs("op2", []string{"topology"}); err != nil {
		t.Fatal(err)
	}
	if rec := postTabs(t, app, `{"username":"op2","allowed_tabs":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	u, _ := st.GetUser("op2")
	if len(u.AllowedTabs) != 0 {
		t.Errorf("restrizione non rimossa: %#v", u.AllowedTabs)
	}
}
