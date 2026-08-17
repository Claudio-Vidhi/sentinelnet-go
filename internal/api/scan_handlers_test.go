package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

func TestSubnetScanAndVerify(t *testing.T) {
	app, st, _ := setupIncidentTestApp(t)

	// 1. Test POST /api/scan-subnet (start scan on /30)
	body := map[string]any{
		"network": "192.0.2.0/30",
		"ports":   []int{22, 80},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/scan-subnet", bytes.NewReader(raw))
	req = withAdminAuth(req)
	rr := httptest.NewRecorder()
	app.handleScanSubnet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handleScanSubnet returned status %d: %s", rr.Code, rr.Body.String())
	}

	var startResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("Failed to parse start response: %v", err)
	}

	jobID, ok := startResp["job_id"].(string)
	if !ok || jobID == "" {
		t.Fatalf("Missing job_id in response: %+v", startResp)
	}

	// Poll until done or timeout
	deadline := time.Now().Add(5 * time.Second)
	var finalJob *Job
	for time.Now().Before(deadline) {
		pollReq := httptest.NewRequest("GET", "/api/scan-subnet/"+jobID, nil)
		pollReq = withAdminAuth(pollReq)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("job_id", jobID)
		pollReq = pollReq.WithContext(context.WithValue(pollReq.Context(), chi.RouteCtxKey, rctx))

		pollRr := httptest.NewRecorder()
		app.handleJobStatus(pollRr, pollReq)

		if pollRr.Code == http.StatusOK {
			var j Job
			if err := json.Unmarshal(pollRr.Body.Bytes(), &j); err == nil && j.Status == "done" {
				finalJob = &j
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalJob == nil {
		t.Fatalf("Scan job %s did not complete in time", jobID)
	}

	// 2. Test POST /api/scan-verify with identity
	ident := &store.Identity{
		ID:       "test-ident-1",
		Name:     "Test Admin",
		Tenant:   "Generale",
		Username: "admin",
	}
	if err := st.UpsertIdentity(ident); err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	verifyBody := map[string]any{
		"ips":         []string{"192.0.2.1"},
		"vendor":      "cisco",
		"identity_id": "test-ident-1",
	}
	rawVerify, _ := json.Marshal(verifyBody)
	vReq := httptest.NewRequest("POST", "/api/scan-verify", bytes.NewReader(rawVerify))
	vReq = withAdminAuth(vReq)
	vRr := httptest.NewRecorder()
	app.handleScanVerify(vRr, vReq)

	if vRr.Code != http.StatusOK {
		t.Fatalf("handleScanVerify returned status %d: %s", vRr.Code, vRr.Body.String())
	}

	var vStartResp map[string]any
	if err := json.Unmarshal(vRr.Body.Bytes(), &vStartResp); err != nil {
		t.Fatalf("Failed to parse verify start response: %v", err)
	}
	vJobID, ok := vStartResp["job_id"].(string)
	if !ok || vJobID == "" {
		t.Fatalf("Missing job_id in verify start: %+v", vStartResp)
	}
}
