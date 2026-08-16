package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/clientdiag"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestDiagnosisAPIRoutes(t *testing.T) {
	app, st, _ := setupIncidentTestApp(t)

	_ = st.UpsertDevice(&store.Device{
		IP:       "192.168.1.1",
		Hostname: "FGT-CORE-01",
		Tenant:   "T1",
		Vendor:   "fortinet",
	})
	_, _ = st.RecordARPEntries([]store.ARPInput{
		{IP: "192.168.1.50", MAC: "001122334455"},
	}, "192.168.1.1", "FGT-CORE-01", "fortigate", "T1", "HQ")

	// 1. POST /api/diagnose/client
	body := `{"client": "192.168.1.50", "dest": "10.0.0.10"}`
	req := withAdminAuth(httptest.NewRequest("POST", "/api/diagnose/client", strings.NewReader(body)))
	rec := httptest.NewRecorder()
	app.handleDiagnoseClient(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/diagnose/client got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var rep clientdiag.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Client != "192.168.1.50" || !rep.L3.Known || rep.L3.GatewayIP != "192.168.1.1" {
		t.Fatalf("unexpected diagnosis report: %+v", rep)
	}

	// 2. GET /api/diagnose/gateway-candidates
	req = withAdminAuth(httptest.NewRequest("GET", "/api/diagnose/gateway-candidates?tenant=T1", nil))
	rec = httptest.NewRecorder()
	app.handleGetGatewayCandidates(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/diagnose/gateway-candidates got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var candidates []map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &candidates)
	if len(candidates) != 1 || candidates[0]["ip"] != "192.168.1.1" {
		t.Fatalf("expected FGT-CORE-01 candidate, got %+v", candidates)
	}

	// 3. POST /api/diagnose/traceroute-gateway
	body = `{"target": "10.0.0.1"}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/diagnose/traceroute-gateway", strings.NewReader(body)))
	rec = httptest.NewRecorder()
	app.handleTracerouteGateway(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/diagnose/traceroute-gateway got %d; want 200: %s", rec.Code, rec.Body.String())
	}
}
