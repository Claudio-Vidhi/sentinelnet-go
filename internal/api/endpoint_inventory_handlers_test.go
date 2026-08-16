package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestEndpointInventoryAPIRoutes(t *testing.T) {
	app, st, _ := setupIncidentTestApp(t)

	_ = st.UpsertDevice(&store.Device{
		IP:       "10.0.0.10",
		Hostname: "SW-ACCESS-01",
		Tenant:   "T1",
		Vendor:   "cisco",
	})

	_, _ = st.RecordARPEntries([]store.ARPInput{
		{IP: "10.0.0.55", MAC: "001122334455"},
	}, "10.0.0.1", "GW-1", "cisco", "T1", "HQ")

	_ = st.UpsertSighting(&store.MacSighting{
		Mac:        "00:11:22:33:44:55",
		SwitchIP:   "10.0.0.10",
		SwitchName: "SW-ACCESS-01",
		Interface:  "Gi1/0/2",
		Vlan:       "10",
		Tenant:     "T1",
		Site:       "HQ",
	})

	// 1. GET /api/endpoints/list
	req := withAdminAuth(httptest.NewRequest("GET", "/api/endpoints/list?tenant=T1", nil))
	rec := httptest.NewRecorder()
	app.handleGetEndpointsList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/endpoints/list got %d: %s", rec.Code, rec.Body.String())
	}

	var res store.EndpointInventoryResult
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Total != 1 || len(res.Results) != 1 {
		t.Fatalf("expected 1 endpoint result, got %+v", res)
	}

	// 2. GET /api/endpoints/ports
	req = withAdminAuth(httptest.NewRequest("GET", "/api/endpoints/ports?switch=10.0.0.10", nil))
	rec = httptest.NewRecorder()
	app.handleGetEndpointPorts(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/endpoints/ports got %d: %s", rec.Code, rec.Body.String())
	}

	var portRes store.PortOccupancyResult
	_ = json.Unmarshal(rec.Body.Bytes(), &portRes)
	if !portRes.PortListKnown || len(portRes.Ports) != 1 || portRes.Ports[0].State != "occupied" {
		t.Fatalf("expected occupied port on Gi1/0/2, got %+v", portRes)
	}
}
