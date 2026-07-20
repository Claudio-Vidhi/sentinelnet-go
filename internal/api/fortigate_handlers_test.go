package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

// testFGTApp prepara uno Store temporaneo, un vault e un App pronti per i test
// degli handler FortiGate.
func testFGTApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })

	key := make([]byte, 32)
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault), st
}

// withIPParam inietta il parametro di rotta chi {ip}, come farebbe il router
// reale, e i claims dell'utente autenticato.
func withIPParam(r *http.Request, ip string, claims *auth.Claims) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("ip", ip)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, claimsKey, claims)
	return r.WithContext(ctx)
}

var adminClaims = &auth.Claims{Username: "admin", Role: "admin"}

// newFakeFortiGate avvia un server TLS che risponde come un FortiGate reale
// (stesso pattern di internal/fortigate/client_test.go) e ritorna host/porta.
func newFakeFortiGate(t *testing.T, h http.HandlerFunc) (string, int) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return u.Hostname(), port
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("risposta non JSON: %v (%s)", err, rec.Body.String())
	}
	return out
}

// GET /tokens non deve mai esporre il token, in nessuna forma.
func TestHandleFGTTokensNeverExposesToken(t *testing.T) {
	app, st := testFGTApp(t)
	enc, _ := app.vault.Encrypt("segreto-super-riservato")
	if err := st.UpsertFortiGateTarget(&store.FortiGateTarget{
		IP: "10.0.0.1", Name: "Sede", Port: 8443, VerifyTLS: true, TokenEnc: enc,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/fortigate/tokens", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, adminClaims))
	rec := httptest.NewRecorder()
	app.handleFGTTokens(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "segreto-super-riservato") || strings.Contains(rec.Body.String(), enc) {
		t.Fatalf("il token compare nella risposta: %s", rec.Body.String())
	}
	out := decodeBody(t, rec)
	entry, ok := out["10.0.0.1"].(map[string]any)
	if !ok {
		t.Fatalf("voce mancante per 10.0.0.1: %+v", out)
	}
	if entry["port"] != float64(8443) || entry["verify_tls"] != true {
		t.Errorf("voce inattesa: %+v", entry)
	}
	if _, hasToken := entry["token"]; hasToken {
		t.Error("la chiave 'token' non deve esistere nella risposta")
	}
}

// POST /token con token vuoto elimina il target esistente.
func TestHandleFGTSetTokenEmptyDeletesTarget(t *testing.T) {
	app, st := testFGTApp(t)
	enc, _ := app.vault.Encrypt("abc123")
	if err := st.UpsertFortiGateTarget(&store.FortiGateTarget{IP: "10.0.0.5", TokenEnc: enc}); err != nil {
		t.Fatal(err)
	}

	body := `{"ip":"10.0.0.5","token":""}`
	req := httptest.NewRequest("POST", "/api/fortigate/token", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, adminClaims))
	rec := httptest.NewRecorder()
	app.handleFGTSetToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	got, err := st.GetFortiGateTarget("10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("target non eliminato: %+v", got)
	}
}

// PUT parziale: conserva il token e i campi non passati nel payload.
func TestHandleFGTUpdateTargetPartialKeepsTokenAndFields(t *testing.T) {
	app, st := testFGTApp(t)
	enc, _ := app.vault.Encrypt("token-originale")
	if err := st.UpsertFortiGateTarget(&store.FortiGateTarget{
		IP: "10.0.0.9", Name: "Originale", Port: 8443, VerifyTLS: true, TokenEnc: enc,
	}); err != nil {
		t.Fatal(err)
	}

	// Aggiorna solo il nome: porta, verify_tls e token devono restare invariati.
	body := `{"name":"Rinominato"}`
	req := httptest.NewRequest("PUT", "/api/fortigate/targets/10.0.0.9", strings.NewReader(body))
	req = withIPParam(req, "10.0.0.9", adminClaims)
	rec := httptest.NewRecorder()
	app.handleFGTUpdateTarget(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	got, err := st.GetFortiGateTarget("10.0.0.9")
	if err != nil || got == nil {
		t.Fatalf("target non trovato: %v", err)
	}
	if got.Name != "Rinominato" {
		t.Errorf("nome = %q, atteso Rinominato", got.Name)
	}
	if got.Port != 8443 || !got.VerifyTLS {
		t.Errorf("campi non passati alterati: %+v", got)
	}
	if got.TokenEnc != enc {
		t.Errorf("token alterato: %q, atteso invariato (%q)", got.TokenEnc, enc)
	}

	// IP inesistente: 404.
	req2 := httptest.NewRequest("PUT", "/api/fortigate/targets/10.9.9.9", strings.NewReader(`{}`))
	req2 = withIPParam(req2, "10.9.9.9", adminClaims)
	rec2 := httptest.NewRecorder()
	app.handleFGTUpdateTarget(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("status = %d, atteso 404", rec2.Code)
	}
}

// setupFGTDevice registra un device FortiGate in inventario con un target che
// punta a un server REST fasullo, e ritorna il suo IP.
func setupFGTDevice(t *testing.T, app *App, st *store.Store, h http.HandlerFunc) string {
	t.Helper()
	host, port := newFakeFortiGate(t, h)
	// Username non vuoto: evita che resolveCreds tocchi a.cfg (nil in questi
	// test) per il ripiego SSH, che qui non deve comunque riuscire a collegarsi.
	if err := st.UpsertDevice(&store.Device{IP: host, Vendor: "fortinet", Tenant: "Generale", Username: "test"}); err != nil {
		t.Fatal(err)
	}
	enc, _ := app.vault.Encrypt("token-di-prova")
	if err := st.UpsertFortiGateTarget(&store.FortiGateTarget{
		IP: host, Port: port, VerifyTLS: false, TokenEnc: enc,
	}); err != nil {
		t.Fatal(err)
	}
	return host
}

// Un endpoint di osservabilità ritorna la busta {source:"api", data:...}.
func TestHandleFGTStatusReturnsAPIResult(t *testing.T) {
	app, st := testFGTApp(t)
	ip := setupFGTDevice(t, app, st, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":{"hostname":"FGT-TEST"},"version":"v7.2.5","serial":"FGT001"}`))
	})

	req := httptest.NewRequest("GET", "/api/fortigate/"+ip+"/status", nil)
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()
	app.handleFGTStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if out["source"] != "api" {
		t.Errorf("source = %v, atteso api", out["source"])
	}
	data, ok := out["data"].(map[string]any)
	if !ok || data["hostname"] != "FGT-TEST" {
		t.Errorf("data inattesi: %+v", out["data"])
	}
}

// Un dispositivo con vendor non FortiGate risponde 400.
func TestHandleFGTStatusRejectsNonFortiGateVendor(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.2", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/fortigate/10.0.0.2/status", nil)
	req = withIPParam(req, "10.0.0.2", adminClaims)
	rec := httptest.NewRecorder()
	app.handleFGTStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400: %s", rec.Code, rec.Body.String())
	}
}

// Un IP non presente in inventario risponde 404 (via assertDeviceAllowed).
func TestHandleFGTStatusUnknownDeviceIs404(t *testing.T) {
	app, _ := testFGTApp(t)

	req := httptest.NewRequest("GET", "/api/fortigate/10.9.9.9/status", nil)
	req = withIPParam(req, "10.9.9.9", adminClaims)
	rec := httptest.NewRecorder()
	app.handleFGTStatus(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, atteso 404: %s", rec.Code, rec.Body.String())
	}
}

// Un errore REST (senza ripiego SSH possibile in test, ma qui il target non
// risponde correttamente) si traduce in 502.
func TestHandleFGTStatusRESTErrorIs502(t *testing.T) {
	app, st := testFGTApp(t)
	ip := setupFGTDevice(t, app, st, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("errore interno"))
	})

	req := httptest.NewRequest("GET", "/api/fortigate/"+ip+"/status", nil)
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()
	app.handleFGTStatus(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, atteso 502: %s", rec.Code, rec.Body.String())
	}
}
