package fortigate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// newTestClient avvia un server TLS con certificato self-signed (come un
// FortiGate reale) e ritorna un client che punta a esso.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	c := New(u.Hostname(), port, "token-di-prova", false)
	return c, srv
}

func TestGetSendsBearerTokenAndPath(t *testing.T) {
	var gotAuth, gotPath, gotQuery string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotQuery = r.Header.Get("Authorization"), r.URL.Path, r.URL.RawQuery
		w.Write([]byte(`{"results":{"hostname":"FGT"}}`))
	})

	data, err := c.Get(context.Background(), "monitor/system/status", map[string]string{"vdom": "root"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer token-di-prova" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPath != "/api/v2/monitor/system/status" {
		t.Errorf("path = %q", gotPath)
	}
	if gotQuery != "vdom=root" {
		t.Errorf("query = %q", gotQuery)
	}
	results := data["results"].(map[string]any)
	if results["hostname"] != "FGT" {
		t.Errorf("risposta = %v", data)
	}
}

// Il certificato self-signed deve funzionare con verify_tls disattivo: è la
// configurazione normale di un FortiGate.
func TestSelfSignedCertificateIsAcceptedWhenVerifyDisabled(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":{}}`))
	})
	if _, err := c.Get(context.Background(), "monitor/system/status", nil); err != nil {
		t.Fatalf("con verify_tls disattivo il self-signed doveva essere accettato: %v", err)
	}
}

// Con la verifica attiva lo stesso certificato deve essere rifiutato, con il
// messaggio che spiega come procedere.
func TestSelfSignedCertificateIsRejectedWhenVerifyEnabled(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	c.VerifyTLS = true
	c.HTTP = nil // forza la ricostruzione del transport

	_, err := c.Get(context.Background(), "monitor/system/status", nil)
	if err == nil {
		t.Fatal("atteso errore con verifica TLS attiva")
	}
	if !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("messaggio senza il suggerimento diagnostico: %v", err)
	}
}

func TestStatusCodesProduceSpecificMessages(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{http.StatusUnauthorized, "token non valido o scaduto (401)"},
		{http.StatusForbidden, "accprofile dell'api-user insufficiente"},
		{http.StatusInternalServerError, "HTTP 500"},
	}
	for _, tc := range cases {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
			w.Write([]byte("dettaglio errore"))
		})
		_, err := c.Get(context.Background(), "monitor/system/status", nil)
		if err == nil {
			t.Fatalf("%d: atteso errore", tc.code)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%d: messaggio %q, atteso contenesse %q", tc.code, err.Error(), tc.want)
		}
	}
}

func TestMissingTokenFailsBeforeAnyRequest(t *testing.T) {
	called := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { called = true })
	c.Token = ""

	if _, err := c.Get(context.Background(), "monitor/system/status", nil); err == nil {
		t.Fatal("atteso errore senza token")
	} else if !strings.Contains(err.Error(), "Nessun token API configurato") {
		t.Errorf("messaggio = %v", err)
	}
	if called {
		t.Error("nessuna richiesta doveva partire senza token")
	}
}

// Alcuni endpoint (backup della configurazione) rispondono con testo puro.
func TestNonJSONResponseIsReturnedAsRaw(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("config system global\nend"))
	})
	data, err := c.Get(context.Background(), "monitor/system/config/backup", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data["raw"].(string), "config system global") {
		t.Errorf("risposta non JSON non conservata: %v", data)
	}
}

func TestGetCMDBBuildsProjectionParams(t *testing.T) {
	var gotQuery url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Write([]byte(`{"results":[]}`))
	})
	if _, err := c.GetCMDB(context.Background(), "cmdb/firewall/address", "name|subnet", "name=@X"); err != nil {
		t.Fatal(err)
	}
	if gotQuery.Get("format") != "name|subnet" {
		t.Errorf("format = %q", gotQuery.Get("format"))
	}
	if gotQuery.Get("filter") != "name=@X" {
		t.Errorf("filter = %q", gotQuery.Get("filter"))
	}
}

func TestPostSendsJSONBody(t *testing.T) {
	var gotMethod, gotType string
	var gotBody []byte
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotType = r.Method, r.Header.Get("Content-Type")
		gotBody, _ = readAll(r)
		w.Write([]byte(`{"results":{}}`))
	})
	if _, err := c.Post(context.Background(), "monitor/firewall/policy-lookup",
		map[string]any{"srcintf": "port1"}, nil); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotType != "application/json" {
		t.Errorf("method=%q content-type=%q", gotMethod, gotType)
	}
	if !strings.Contains(string(gotBody), "port1") {
		t.Errorf("body = %q", gotBody)
	}
}

// TestConnection non deve mai propagare un errore: l'esito negativo fa parte
// del risultato, perché la UI mostra lo stato di tutti i target insieme.
func TestTestConnectionReportsInsteadOfFailing(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":{"version":"v7.2.5"}}`))
	})
	if res := c.TestConnection(context.Background()); !res.OK || res.Version != "7.2.5" {
		t.Errorf("esito = %+v, attesi ok=true versione=7.2.5 (senza la v)", res)
	}

	bad, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	res := bad.TestConnection(context.Background())
	if res.OK || res.Error == "" {
		t.Errorf("esito = %+v, attesi ok=false con errore valorizzato", res)
	}
}

// La versione può stare in "results" o al livello superiore, a seconda della
// release di FortiOS.
func TestVersionFromBothShapes(t *testing.T) {
	if got := versionFrom(map[string]any{"results": map[string]any{"version": "v7.0.1"}}); got != "v7.0.1" {
		t.Errorf("results.version = %q", got)
	}
	if got := versionFrom(map[string]any{"version": "v6.4.9"}); got != "v6.4.9" {
		t.Errorf("version = %q", got)
	}
	if got := versionFrom(map[string]any{}); got != "" {
		t.Errorf("assente = %q, attesa stringa vuota", got)
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}
