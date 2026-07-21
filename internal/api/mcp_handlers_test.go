package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPSettingsRoundTrip(t *testing.T) {
	app, _ := testFGTApp(t)

	// GET iniziale: default disabilitati = get_top_talkers, get_anomalies.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mcp/settings", nil).
		WithContext(context.WithValue(context.Background(), claimsKey, adminClaims))
	app.handleGetMCPSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET status %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	dis, _ := out["disabled_tools"].([]any)
	if len(dis) != 2 {
		t.Errorf("default disabled = %v, attesi 2", out["disabled_tools"])
	}
	if tools, _ := out["tools"].([]any); len(tools) < 40 {
		t.Errorf("catalogo tool = %d, attesi ~40", len(tools))
	}

	// POST: disabilita list_devices.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/mcp/settings", strings.NewReader(`{"disabled_tools":["list_devices"]}`)).
		WithContext(context.WithValue(context.Background(), claimsKey, adminClaims))
	app.handleSetMCPSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("POST status %d: %s", rec.Code, rec.Body.String())
	}

	// tool-config riflette la modifica.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/mcp/tool-config", nil).
		WithContext(context.WithValue(context.Background(), claimsKey, adminClaims))
	app.handleGetMCPToolConfig(rec, req)
	tc := decodeBody(t, rec)
	dl, _ := tc["disabled_tools"].([]any)
	if len(dl) != 1 || dl[0] != "list_devices" {
		t.Errorf("tool-config = %v", tc["disabled_tools"])
	}
}

func TestMCPSetRejectsUnknownTool(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/mcp/settings", strings.NewReader(`{"disabled_tools":["nope"]}`)).
		WithContext(context.WithValue(context.Background(), claimsKey, adminClaims))
	app.handleSetMCPSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400", rec.Code)
	}
}

func TestMCPSetRejectsMultipleUnknownTools(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/mcp/settings", strings.NewReader(`{"disabled_tools":["nope1","nope2"]}`)).
		WithContext(context.WithValue(context.Background(), claimsKey, adminClaims))
	app.handleSetMCPSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "nope1") || !strings.Contains(body, "nope2") {
		t.Errorf("body = %q, atteso sia nope1 che nope2", body)
	}
}
