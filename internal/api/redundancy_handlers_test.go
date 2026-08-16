package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/redundancy"
	"github.com/go-chi/chi/v5"
)

func TestRedundancyAPIRoutes(t *testing.T) {
	app, _, _ := setupIncidentTestApp(t)

	// 1. POST /api/redundancy/groups
	body := `{
		"group_name": "T1",
		"group_type": "ha_pair",
		"name": "Core-HA-Cluster",
		"virtual_ip": "10.0.0.254",
		"members": [
			{"member_index": 1, "role": "active", "serial": "FGT60FT12345", "state": "ready"},
			{"member_index": 2, "role": "standby", "serial": "FGT60FT12346", "state": "ready"}
		]
	}`
	req := withAdminAuth(httptest.NewRequest("POST", "/api/redundancy/groups", strings.NewReader(body)))
	rec := httptest.NewRecorder()
	app.handleCreateRedundancyGroup(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/redundancy/groups got %d: %s", rec.Code, rec.Body.String())
	}

	var created redundancy.GroupInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == 0 || len(created.Members) != 2 || created.Health != redundancy.GroupHealthOK {
		t.Fatalf("unexpected created group: %+v", created)
	}

	// 2. GET /api/redundancy/groups
	req = withAdminAuth(httptest.NewRequest("GET", "/api/redundancy/groups", nil))
	rec = httptest.NewRecorder()
	app.handleListRedundancyGroups(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/redundancy/groups got %d: %s", rec.Code, rec.Body.String())
	}

	var listResp struct {
		Results []redundancy.GroupInfo `json:"results"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if len(listResp.Results) != 1 {
		t.Fatalf("expected 1 group, got %d", len(listResp.Results))
	}

	// 3. GET /api/redundancy/groups/{id}
	req = withAdminAuth(httptest.NewRequest("GET", fmt.Sprintf("/api/redundancy/groups/%d", created.ID), nil))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprintf("%d", created.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleGetRedundancyGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET group by id got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. PUT /api/redundancy/groups/{id}
	updateBody := `{
		"group_name": "T1",
		"group_type": "ha_pair",
		"name": "Core-HA-Cluster-Renamed",
		"virtual_ip": "10.0.0.254",
		"members": [
			{"member_index": 1, "role": "active", "serial": "FGT60FT12345", "state": "ready"}
		]
	}`
	req = withAdminAuth(httptest.NewRequest("PUT", fmt.Sprintf("/api/redundancy/groups/%d", created.ID), strings.NewReader(updateBody)))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleUpdateRedundancyGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT group got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. DELETE /api/redundancy/groups/{id}
	req = withAdminAuth(httptest.NewRequest("DELETE", fmt.Sprintf("/api/redundancy/groups/%d", created.ID), nil))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleDeleteRedundancyGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE group got %d: %s", rec.Code, rec.Body.String())
	}
}
