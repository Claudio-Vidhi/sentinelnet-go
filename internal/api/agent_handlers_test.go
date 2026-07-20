package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

// agentReq costruisce una richiesta di agente con gli header del contratto.
func agentReq(method, path, body, token, siteID string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Site-Token", token)
	}
	if siteID != "" {
		req.Header.Set("X-Site-Id", siteID)
	}
	return req
}

// newAgentSite crea una sede agent e ne ritorna id e token in chiaro.
func newAgentSite(t *testing.T, st *store.Store, name string) (string, string) {
	t.Helper()
	site, token, err := st.CreateSite(name, store.ModeAgent, []string{"10.9.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	return site.ID, token
}

// Il token di sede è l'unica credenziale dell'agente: senza, o con uno
// sbagliato, nessuna rotta deve rispondere.
func TestAgentRoutesRejectBadToken(t *testing.T) {
	app, st := testFGTApp(t)
	_, token := newAgentSite(t, st, "Sede Agente")

	for _, tc := range []struct{ name, token string }{
		{"assente", ""},
		{"sbagliato", "token-inventato"},
		{"quasi giusto", token + "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			app.handleAgentHeartbeat(rec, agentReq("POST", "/api/agent/heartbeat", "", tc.token, ""))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, atteso 401: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// Un X-Site-Id che non corrisponde al token è un tentativo di spacciarsi per
// un'altra sede, o un agente mal configurato: in entrambi i casi 401.
func TestAgentRejectsMismatchedSiteID(t *testing.T) {
	app, st := testFGTApp(t)
	_, token := newAgentSite(t, st, "Sede A")
	otherID, _ := newAgentSite(t, st, "Sede B")

	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, agentReq("POST", "/api/agent/heartbeat", "", token, otherID))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, atteso 401", rec.Code)
	}
}

// Il token di una sede central non esiste: solo le sedi agent hanno agenti.
func TestAgentCentralSiteHasNoAccess(t *testing.T) {
	app, st := testFGTApp(t)
	siteID, token := newAgentSite(t, st, "Sede Cambio")
	mode := store.ModeCentral
	if _, err := st.UpdateSite(siteID, nil, &mode, nil); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, agentReq("POST", "/api/agent/heartbeat", "", token, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, atteso 401 dopo il passaggio a central", rec.Code)
	}
}

// Heartbeat riuscito: risponde con l'identità della sede e ne aggiorna
// last_seen, che è il modo in cui il centrale sa che l'agente è vivo.
func TestAgentHeartbeatUpdatesLastSeen(t *testing.T) {
	app, st := testFGTApp(t)
	siteID, token := newAgentSite(t, st, "Sede Viva")

	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, agentReq("POST", "/api/agent/heartbeat", "", token, siteID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if out["ok"] != true || out["site_id"] != siteID {
		t.Errorf("risposta = %+v", out)
	}
	if subnets, ok := out["subnets"].([]any); !ok || len(subnets) != 1 {
		t.Errorf("subnets = %#v", out["subnets"])
	}

	site, _ := st.GetSite(siteID)
	if site.LastSeen == nil {
		t.Error("last_seen non aggiornato dall'heartbeat")
	}
}

// Il push di inventario non deve declassare il tenant di un dispositivo che
// un operatore ha già attribuito: sarebbe una regressione a ogni ciclo.
func TestAgentInventoryPreservesExistingTenant(t *testing.T) {
	app, st := testFGTApp(t)
	siteID, token := newAgentSite(t, st, "Sede Inv")
	if err := st.UpsertDevice(&store.Device{
		IP: "10.9.0.5", Vendor: "cisco", Tenant: "Cliente Importante",
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"devices":[{"ip":"10.9.0.5","vendor":"cisco","hostname":"SW-REMOTO"},
	                     {"ip":"10.9.0.6","vendor":"hp"},
	                     {"ip":"non-un-ip","vendor":"cisco"}]}`
	rec := httptest.NewRecorder()
	app.handleAgentInventory(rec, agentReq("POST", "/api/agent/inventory", body, token, siteID))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if n := decodeBody(t, rec)["updated"]; n != float64(2) {
		t.Errorf("updated = %v, attesi 2 (l'IP non valido va scartato)", n)
	}

	devices, _ := st.ListDevices()
	byIP := map[string]*store.Device{}
	for _, d := range devices {
		byIP[d.IP] = d
	}
	if got := byIP["10.9.0.5"]; got == nil || got.Tenant != "Cliente Importante" {
		t.Errorf("tenant sovrascritto dal push: %+v", got)
	}
	if got := byIP["10.9.0.5"]; got != nil && got.Site != siteID {
		t.Errorf("site = %q, atteso %q", got.Site, siteID)
	}
	if got := byIP["10.9.0.6"]; got == nil || got.Tenant != "Generale" {
		t.Errorf("nuovo device senza tenant di default: %+v", got)
	}
	if _, ok := byIP["non-un-ip"]; ok {
		t.Error("un IP non valido è finito in inventario")
	}
}

// Gli avvistamenti spinti da un agente sono attribuiti alla sua sede: è
// l'attribuzione per cui esiste la modalità agent.
func TestAgentMacPushAttributesSite(t *testing.T) {
	app, st := testFGTApp(t)
	siteID, token := newAgentSite(t, st, "Sede Mac")
	if err := st.UpsertDevice(&store.Device{
		IP: "10.9.0.5", Vendor: "cisco", Tenant: "Cliente A",
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"collections":[{"switch_ip":"10.9.0.5","switch_name":"SW-REMOTO",
	  "rows":[{"mac":"aa:bb:cc:dd:ee:ff","vlan":"10","interface":"Gi1/0/1"},
	          {"mac":"","vlan":"10"}]}]}`
	rec := httptest.NewRecorder()
	app.handleAgentMac(rec, agentReq("POST", "/api/agent/mac", body, token, siteID))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if n := decodeBody(t, rec)["recorded"]; n != float64(1) {
		t.Errorf("recorded = %v, atteso 1 (la riga senza MAC va scartata)", n)
	}

	found, err := st.SearchSightings("aa:bb:cc:dd:ee:ff", "", "", "", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("avvistamenti = %d", len(found))
	}
	if found[0].Site != siteID {
		t.Errorf("site = %q, atteso %q", found[0].Site, siteID)
	}
	// Il tenant è quello del device, non l'id sede: lo scoping utenti filtra
	// per tenant.
	if found[0].Tenant != "Cliente A" {
		t.Errorf("tenant = %q, atteso quello del device", found[0].Tenant)
	}
}

// Il polling preleva solo i job della propria sede e li marca 'running'.
func TestAgentPollJobsIsolatesSites(t *testing.T) {
	app, st := testFGTApp(t)
	siteA, tokenA := newAgentSite(t, st, "Sede Poll A")
	siteB, _ := newAgentSite(t, st, "Sede Poll B")
	if _, err := st.EnqueueJob(siteA, "10.9.0.5", "show version", "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueJob(siteB, "10.9.0.6", "show clock", "op"); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	app.handleAgentPollJobs(rec, agentReq("GET", "/api/agent/jobs", "", tokenA, siteA))

	jobs, ok := decodeBody(t, rec)["jobs"].([]any)
	if !ok || len(jobs) != 1 {
		t.Fatalf("jobs = %#v", decodeBody(t, rec)["jobs"])
	}
	j := jobs[0].(map[string]any)
	if j["site_id"] != siteA || j["status"] != "running" {
		t.Errorf("job = %+v", j)
	}
}

// Un agente non deve poter chiudere il job di un'altra sede, e la risposta
// non deve confermarne l'esistenza.
func TestAgentJobResultRejectsForeignJob(t *testing.T) {
	app, st := testFGTApp(t)
	siteA, tokenA := newAgentSite(t, st, "Sede Res A")
	siteB, _ := newAgentSite(t, st, "Sede Res B")
	job, err := st.EnqueueJob(siteB, "10.9.0.6", "show clock", "op")
	if err != nil {
		t.Fatal(err)
	}

	req := agentReq("POST", "/api/agent/jobs/"+job.ID+"/result",
		`{"status":"done","result":"risultato falsificato"}`, tokenA, siteA)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("job_id", job.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	app.handleAgentJobResult(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, atteso 404", rec.Code)
	}
	again, _ := st.GetJob(job.ID)
	if again.Result != "" {
		t.Error("il job di un'altra sede è stato alterato")
	}
}
