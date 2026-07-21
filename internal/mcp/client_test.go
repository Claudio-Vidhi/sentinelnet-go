package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Call fa login pigro, poi la richiesta col Bearer; su 401 la prima volta
// rifà login e riprova una sola volta.
func TestClientLoginAndRetry(t *testing.T) {
	var loginHits, apiHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			loginHits++
			w.Write([]byte(`{"access_token":"tok` + itoa(loginHits) + `"}`))
		case "/api/thing":
			apiHits++
			if r.Header.Get("Authorization") == "Bearer tok1" && apiHits == 1 {
				w.WriteHeader(401)
				w.Write([]byte(`{"detail":"scaduto"}`))
				return
			}
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, username: "u", password: "p", httpc: srv.Client()}
	got, err := c.Call("GET", "/api/thing", nil, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m, _ := got.(map[string]any); m["ok"] != true {
		t.Errorf("risultato = %#v", got)
	}
	if loginHits != 2 || apiHits != 2 {
		t.Errorf("login=%d api=%d, attesi 2 e 2 (retry dopo 401)", loginHits, apiHits)
	}
}

// Un errore HTTP >=400 (non 401) diventa un error con detail.
func TestClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			w.Write([]byte(`{"access_token":"t"}`))
			return
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"detail":"vietato"}`))
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, username: "u", password: "p", httpc: srv.Client()}
	if _, err := c.Call("GET", "/api/x", nil, nil); err == nil || err.Error() != "HTTP 403: vietato" {
		t.Errorf("err = %v, atteso 'HTTP 403: vietato'", err)
	}
}

func itoa(n int) string { return string(rune('0' + n)) }
