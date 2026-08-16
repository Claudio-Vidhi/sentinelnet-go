package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

func setupIncidentTestApp(t *testing.T) (*App, *store.Store, *obsstore.Store) {
	t.Helper()
	tmpDir := t.TempDir()
	st, err := store.Open(filepath.Join(tmpDir, "sentinelnet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })

	obs, err := obsstore.Open(filepath.Join(tmpDir, "observability.db"), metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { obs.Close() })

	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Addr:    ":8000",
		DataDir: tmpDir,
	}
	if err := os.MkdirAll(cfg.BackupDir(), 0755); err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, st, nil, vault)
	app.obs = obs
	return app, st, obs
}

func withAdminAuth(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
}

func withOperatorAuth(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "operator", Role: "operator"}))
}

func TestIncidentsAPI(t *testing.T) {
	app, _, obs := setupIncidentTestApp(t)

	// 1. GET /api/incidents/rules
	req := withAdminAuth(httptest.NewRequest("GET", "/api/incidents/rules", nil))
	rec := httptest.NewRecorder()
	app.handleListCorrelationRules(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/incidents/rules got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var rulesResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rulesResp)
	rulesList, ok := rulesResp["rules"].([]any)
	if !ok || len(rulesList) == 0 {
		t.Fatalf("expected rules catalog in response, got %v", rulesResp)
	}

	// 2. POST /api/incidents/rules/IFACE_FLAPPING_001/parameters
	body := `{"min_transitions": 6}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/incidents/rules/IFACE_FLAPPING_001/parameters", strings.NewReader(body)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("rule_id", "IFACE_FLAPPING_001")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleSetRuleParameters(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/incidents/rules/... got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 3. Create sample incident in obsstore
	now := time.Now().Unix()
	obs.DB.Exec(`INSERT INTO incidents (id, tenant, entity_key, opened_ts, last_event_ts, title, severity, event_count, status, cause_kind, confidence)
	             VALUES (1, 'default', 'ip:10.0.0.1', ?, ?, '10.0.0.1', 3, 2, 'new', 'IFACE_FLAPPING_001', 70)`, now, now)

	// 4. GET /api/incidents
	req = withAdminAuth(httptest.NewRequest("GET", "/api/incidents", nil))
	rec = httptest.NewRecorder()
	app.handleListIncidents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/incidents got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	var incsResp struct {
		Incidents []struct {
			ID int64 `json:"id"`
		} `json:"incidents"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &incsResp)
	if len(incsResp.Incidents) != 1 || incsResp.Incidents[0].ID != 1 {
		t.Fatalf("expected incident ID 1, got %v", incsResp.Incidents)
	}

	// 5. GET /api/incidents/1
	req = withAdminAuth(httptest.NewRequest("GET", "/api/incidents/1", nil))
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleGetIncident(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/incidents/1 got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 6. POST /api/incidents/1/status
	statusBody := `{"from_status":"new","status":"ack"}`
	req = withOperatorAuth(httptest.NewRequest("POST", "/api/incidents/1/status", strings.NewReader(statusBody)))
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleSetIncidentStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/incidents/1/status got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 7. POST /api/incidents/interfaces/expected
	suppBody := `{"tenant":"default","device_ip":"10.0.0.1","interface":"Gi1/0/1","suppressed":true,"note":"Manutenzione"}`
	req = withOperatorAuth(httptest.NewRequest("POST", "/api/incidents/interfaces/expected", strings.NewReader(suppBody)))
	rec = httptest.NewRecorder()
	app.handleSetSuppression(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/incidents/interfaces/expected got %d; want 200: %s", rec.Code, rec.Body.String())
	}

	// 8. GET /api/incidents/interfaces
	req = withAdminAuth(httptest.NewRequest("GET", "/api/incidents/interfaces", nil))
	rec = httptest.NewRecorder()
	app.handleListInterfaces(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/incidents/interfaces got %d; want 200: %s", rec.Code, rec.Body.String())
	}
}

