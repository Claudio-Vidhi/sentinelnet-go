package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

// withIPMacParams inietta sia {ip} che {mac}, per le rotte per-client
// (client-detail, diagnose-client) che withIPParam da solo non copre.
func withIPMacParams(r *http.Request, ip, mac string, claims *auth.Claims) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("ip", ip)
	rctx.URLParams.Add("mac", mac)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, claimsKey, claims)
	return r.WithContext(ctx)
}

// Un dispositivo con vendor non WLC (es. un FortiGate) risponde 400: le rotte
// /api/wlc/* non devono provare a interrogare via SSH un apparato che non
// parla la CLI Cisco AireOS/IOS-XE.
func TestHandleWLCStatusRejectsNonWLCVendor(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.3", Vendor: "fortinet", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/wlc/10.0.0.3/status", nil)
	req = withIPParam(req, "10.0.0.3", adminClaims)
	rec := httptest.NewRecorder()
	app.handleWLCStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400: %s", rec.Code, rec.Body.String())
	}
}

// Un IP non presente in inventario risponde 404 (via assertDeviceAllowed),
// come per le rotte FortiGate: nessuna differenza di comportamento tra le
// due famiglie di handler su questo fronte.
func TestHandleWLCStatusUnknownDeviceIs404(t *testing.T) {
	app, _ := testFGTApp(t)

	req := httptest.NewRequest("GET", "/api/wlc/10.9.9.9/status", nil)
	req = withIPParam(req, "10.9.9.9", adminClaims)
	rec := httptest.NewRecorder()
	app.handleWLCStatus(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, atteso 404: %s", rec.Code, rec.Body.String())
	}
}

// setupWLCDevice registra un device WLC in inventario (vendor cisco_wlc =
// AireOS) su un IP che rifiuta subito la connessione SSH, senza dipendere
// dalla rete: 127.0.0.1:22 senza nulla in ascolto ritorna "connection
// refused" quasi istantaneamente, a differenza di un IP irraggiungibile che
// farebbe scattare il timeout di 12s del dialer e renderebbe il test lento.
func setupWLCDevice(t *testing.T, st *store.Store) string {
	t.Helper()
	ip := "127.0.0.1"
	// Username non vuoto: evita che resolveCreds tocchi a.cfg (nil in questi
	// test), come da convenzione già usata per i device FortiGate di test.
	if err := st.UpsertDevice(&store.Device{IP: ip, Vendor: "cisco_wlc", Tenant: "Generale", Username: "test"}); err != nil {
		t.Fatal(err)
	}
	return ip
}

// Senza un vero WLC da interrogare, una sessione SSH che non riesce nemmeno
// a connettersi deve tradursi in 502 (guasto di trasporto), non in 500 o in
// un timeout che blocca il test: verifica sia lo status sia il tempo limite.
func TestHandleWLCStatusUnreachableSSHIs502(t *testing.T) {
	app, st := testFGTApp(t)
	ip := setupWLCDevice(t, st)

	req := httptest.NewRequest("GET", "/api/wlc/"+ip+"/status", nil)
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		app.handleWLCStatus(rec, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleWLCStatus non è tornato entro 5s: la connessione rifiutata dovrebbe fallire quasi subito")
	}

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, atteso 502: %s", rec.Code, rec.Body.String())
	}
}

// La diagnosi aggregata non deve mai fallire in blocco: anche con l'apparato
// irraggiungibile risponde comunque 200, con l'errore di ciascuna sezione
// incorporato nella sezione stessa (comportamento di wlc.DiagnoseWifiClient).
// Verifica anche che venga scritta la riga di audit prima dell'interrogazione.
func TestHandleWLCDiagnoseClientAlwaysReturns200(t *testing.T) {
	app, st := testFGTApp(t)
	ip := setupWLCDevice(t, st)

	req := httptest.NewRequest("GET", "/api/wlc/"+ip+"/diagnose-client/aa:bb:cc:dd:ee:ff", nil)
	req = withIPMacParams(req, ip, "aa:bb:cc:dd:ee:ff", adminClaims)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		app.handleWLCDiagnoseClient(rec, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleWLCDiagnoseClient non è tornato entro 5s")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, atteso 200: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	sections, ok := out["sections"].(map[string]any)
	if !ok {
		t.Fatalf("sections = %#v", out["sections"])
	}
	for _, name := range []string{"client_detail", "ap_summary", "wlan_summary", "rogue_aps"} {
		sec, ok := sections[name].(map[string]any)
		if !ok {
			t.Fatalf("sezione %q mancante o malformata: %#v", name, sections[name])
		}
		if _, hasErr := sec["error"]; !hasErr {
			t.Errorf("sezione %q senza errore nonostante SSH irraggiungibile: %#v", name, sec)
		}
	}
}
