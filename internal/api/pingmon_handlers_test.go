package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/pingmon"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestPingMonitorAPIRoutes(t *testing.T) {
	app, st, _ := setupIncidentTestApp(t)

	_ = st.UpsertDevice(&store.Device{IP: "10.0.0.1", Hostname: "GW-1", Tenant: "T1"})
	_ = st.UpsertDevice(&store.Device{IP: "10.0.0.2", Hostname: "SW-1", Tenant: "T2"})

	app.pingMon.SetProbeFunc(func(ctx context.Context, host string) bool {
		return host == "10.0.0.1"
	})

	// 1. GET /api/settings/ping-monitor
	req := withAdminAuth(httptest.NewRequest("GET", "/api/settings/ping-monitor", nil))
	rec := httptest.NewRecorder()
	app.handleGetPingMonitorSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET ping-monitor settings got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 2. POST /api/settings/ping-monitor
	body := `{"enabled": true, "interval_seconds": 15}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/settings/ping-monitor", strings.NewReader(body)))
	rec = httptest.NewRecorder()
	app.handleSetPingMonitorSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST ping-monitor settings got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 3. Run a cycle
	app.pingMon.RunCycle()

	// 4. GET /api/ping-monitor/status
	req = withAdminAuth(httptest.NewRequest("GET", "/api/ping-monitor/status", nil))
	rec = httptest.NewRecorder()
	app.handleGetPingMonitorStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/ping-monitor/status got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var status pingmon.StatusResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if !status.Enabled || status.Summary.Total != 2 || status.Summary.Up != 1 || status.Summary.Down != 1 {
		t.Fatalf("unexpected ping status response: %+v", status)
	}
}
