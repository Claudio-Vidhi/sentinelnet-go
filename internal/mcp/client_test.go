package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// Python's _login() calls raise_for_status() before decoding, so a failed
// login (bad credentials, 5xx, ...) fails fast with the detail from the
// body. The Go port must do the same: login() must not silently succeed
// with an empty token on a non-2xx response.
func TestClientLoginFailsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			w.WriteHeader(401)
			w.Write([]byte(`{"detail":"credenziali errate"}`))
			return
		}
		t.Errorf("richiesta inattesa verso %s: il login doveva fallire prima", r.URL.Path)
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, username: "u", password: "p", httpc: srv.Client()}
	_, err := c.Call("GET", "/api/thing", nil, nil)
	if err == nil {
		t.Fatal("err = nil, atteso errore di login fallito")
	}
	if !strings.Contains(err.Error(), "credenziali errate") {
		t.Errorf("err = %v, atteso messaggio con 'credenziali errate'", err)
	}
}
