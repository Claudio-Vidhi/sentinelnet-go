package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestAuditAPIRoutes(t *testing.T) {
	app, _, _ := setupIncidentTestApp(t)

	// 1. GET /api/netsec-audit/benchmarks
	req := withAdminAuth(httptest.NewRequest("GET", "/api/netsec-audit/benchmarks", nil))
	rec := httptest.NewRecorder()
	app.handleNetSecAuditBenchmarks(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/netsec-audit/benchmarks got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var bmResp map[string][]map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &bmResp)
	if len(bmResp["cis"]) == 0 {
		t.Fatalf("expected cis rules in benchmarks response")
	}

	// 2. POST /api/netsec-audit/scan
	scanBody := `{
		"config_text": "config system global\n set admin-https-ssl-versions tlsv1-2 tlsv1-3\n set admintimeout 5\n end",
		"device_name": "TestFW",
		"benchmark": "cis",
		"lang": "it",
		"save": true,
		"run_name": "Test Scan Run"
	}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/netsec-audit/scan", strings.NewReader(scanBody)))
	rec = httptest.NewRecorder()
	app.handleNetSecAuditScan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/netsec-audit/scan got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var scanResp struct {
		Score   *int   `json:"score"`
		SavedID *int64 `json:"saved_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &scanResp)
	if scanResp.Score == nil || scanResp.SavedID == nil {
		t.Fatalf("expected scan score and saved_id, got %+v", scanResp)
	}

	// 3. GET /api/netsec-audit/history
	req = withAdminAuth(httptest.NewRequest("GET", "/api/netsec-audit/history", nil))
	rec = httptest.NewRecorder()
	app.handleNetSecAuditHistory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/netsec-audit/history got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 4. GET /api/audit-checklist/templates
	req = withAdminAuth(httptest.NewRequest("GET", "/api/audit-checklist/templates", nil))
	rec = httptest.NewRecorder()
	app.handleListAuditTemplates(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/audit-checklist/templates got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 5. POST /api/audit-checklist/engagements
	engBody := `{
		"customer_name": "Globex Corp",
		"tenant": "default",
		"site_id": "Datacenter",
		"onsite_or_remote": "remote",
		"interviewee": "Security Lead"
	}`
	req = withOperatorAuth(httptest.NewRequest("POST", "/api/audit-checklist/engagements", strings.NewReader(engBody)))
	rec = httptest.NewRecorder()
	app.handleCreateAuditEngagement(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/audit-checklist/engagements got %d; want 201: %s", rec.Code, rec.Body.String())
	}

	var engResp struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &engResp)
	if engResp.ID == 0 {
		t.Fatalf("expected created engagement ID > 0")
	}

	// 6. GET /api/audit-checklist/engagements/{id}
	req = withAdminAuth(httptest.NewRequest("GET", fmt.Sprintf("/api/audit-checklist/engagements/%d", engResp.ID), nil))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("engagement_id", fmt.Sprintf("%d", engResp.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleGetAuditEngagement(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET engagement got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 7. GET report
	req = withAdminAuth(httptest.NewRequest("GET", fmt.Sprintf("/api/audit-checklist/engagements/%d/report", engResp.ID), nil))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleGetAuditReport(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Globex Corp") {
		t.Fatalf("GET report got %d: %s", rec.Code, rec.Body.String())
	}
}
