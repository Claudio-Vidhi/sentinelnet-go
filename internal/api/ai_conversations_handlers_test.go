package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

func TestAIConversationsAndSettingsAPIRoutes(t *testing.T) {
	app, st, _ := setupIncidentTestApp(t)

	_ = st.UpsertDevice(&store.Device{
		IP:       "10.0.0.1",
		Hostname: "GW-CORE",
		Tenant:   "T1",
		Vendor:   "cisco",
	})

	// 1. POST /api/ai/conversations
	body := `{"title": "Debug OSPF", "messages": [{"role": "user", "content": "help"}]}`
	req := withAdminAuth(httptest.NewRequest("POST", "/api/ai/conversations", strings.NewReader(body)))
	rec := httptest.NewRecorder()
	app.handleCreateAIConversation(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/ai/conversations got %d: %s", rec.Code, rec.Body.String())
	}

	var created store.AIConversation
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == 0 || created.Title != "Debug OSPF" {
		t.Fatalf("unexpected created conv: %+v", created)
	}

	// 2. GET /api/ai/conversations
	req = withAdminAuth(httptest.NewRequest("GET", "/api/ai/conversations", nil))
	rec = httptest.NewRecorder()
	app.handleListAIConversations(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/ai/conversations got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. GET /api/ai/conversations/{id}
	req = withAdminAuth(httptest.NewRequest("GET", fmt.Sprintf("/api/ai/conversations/%d", created.ID), nil))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprintf("%d", created.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleGetAIConversation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET conv by id got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. PUT /api/ai/conversations/{id}
	putBody := `{"title": "Debug OSPF v2", "messages": [{"role": "user", "content": "fixed"}]}`
	req = withAdminAuth(httptest.NewRequest("PUT", fmt.Sprintf("/api/ai/conversations/%d", created.ID), strings.NewReader(putBody)))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleUpdateAIConversation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT conv got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. DELETE /api/ai/conversations/{id}
	req = withAdminAuth(httptest.NewRequest("DELETE", fmt.Sprintf("/api/ai/conversations/%d", created.ID), nil))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	app.handleDeleteAIConversation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE conv got %d: %s", rec.Code, rec.Body.String())
	}

	// 6. Global Search
	req = withAdminAuth(httptest.NewRequest("GET", "/api/search?q=GW-CORE", nil))
	rec = httptest.NewRecorder()
	app.handleGlobalSearch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/search got %d: %s", rec.Code, rec.Body.String())
	}

	// 7. SNMP Defaults
	snmpBody := `{"tenant": "T1", "community": "public-ro"}`
	req = withAdminAuth(httptest.NewRequest("POST", "/api/settings/snmp-defaults", strings.NewReader(snmpBody)))
	rec = httptest.NewRecorder()
	app.handleSetSNMPDefaults(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/settings/snmp-defaults got %d: %s", rec.Code, rec.Body.String())
	}

	req = withAdminAuth(httptest.NewRequest("GET", "/api/settings/snmp-defaults", nil))
	rec = httptest.NewRecorder()
	app.handleGetSNMPDefaults(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "T1") {
		t.Fatalf("GET /api/settings/snmp-defaults got %d: %s", rec.Code, rec.Body.String())
	}
}
