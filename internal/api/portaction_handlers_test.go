package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestPortActionAPIRoutes(t *testing.T) {
	app, st, _ := setupIncidentTestApp(t)

	_ = st.UpsertDevice(&store.Device{
		IP:       "10.0.0.10",
		Hostname: "SW-ACCESS-01",
		Tenant:   "T1",
		Vendor:   "cisco",
	})

	// 1. POST /api/diagnose/port-bounce (unknown device -> 404)
	body := `{"switch_ip": "10.0.0.99", "interface": "Gi1/0/1"}`
	req := withAdminAuth(httptest.NewRequest("POST", "/api/diagnose/port-bounce", strings.NewReader(body)))
	rec := httptest.NewRecorder()
	app.handleDiagnosePortBounce(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown device, got %d", rec.Code)
	}

	// 2. POST /api/diagnose/port-bounce with client_mac mismatch (verify port fails -> 409)
	body = `{"switch_ip": "10.0.0.10", "interface": "Gi1/0/1", "client_mac": "00:11:22:33:44:55"}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/diagnose/port-bounce", strings.NewReader(body)))
	rec = httptest.NewRecorder()
	app.handleDiagnosePortBounce(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict when MAC not mapped to port, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. POST /api/interfaces/state (unknown device -> 404)
	body = `{"switch_ip": "10.0.0.99", "interface": "Gi1/0/1", "admin_up": false}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/interfaces/state", strings.NewReader(body)))
	rec = httptest.NewRecorder()
	app.handleSetInterfaceState(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown device in set state, got %d", rec.Code)
	}
}
