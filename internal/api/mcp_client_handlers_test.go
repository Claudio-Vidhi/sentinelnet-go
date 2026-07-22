package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func mcpClientApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault)
}

func mcpClientReq(method, path, body, role string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	return r.WithContext(context.WithValue(r.Context(), claimsKey, &auth.Claims{Username: "admin", Role: role}))
}

func TestMCPClientSettingsAndServers(t *testing.T) {
	app := mcpClientApp(t)

	// 1. Initial settings
	w := httptest.NewRecorder()
	app.handleGetMCPClientSettings(w, mcpClientReq("GET", "/api/mcp-client/settings", "", "admin"))
	if w.Code != 200 {
		t.Fatalf("GET settings code=%d body=%s", w.Code, w.Body.String())
	}
	var settings map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &settings)
	if settings["preview_enabled"] != false {
		t.Errorf("expected preview_enabled = false, got %v", settings["preview_enabled"])
	}

	// 2. Enable Preview
	w = httptest.NewRecorder()
	app.handleSetMCPClientPreview(w, mcpClientReq("POST", "/api/mcp-client/preview", `{"enabled":true}`, "admin"))
	if w.Code != 200 {
		t.Fatalf("POST preview code=%d body=%s", w.Code, w.Body.String())
	}

	// 3. Upsert Server
	w = httptest.NewRecorder()
	app.handleUpsertMCPClientServer(w, mcpClientReq("POST", "/api/mcp-client/servers", `{"name":"jira","url":"http://localhost:8080","auth_token":"secret123"}`, "admin"))
	if w.Code != 200 {
		t.Fatalf("POST server code=%d body=%s", w.Code, w.Body.String())
	}

	// 4. List Servers
	w = httptest.NewRecorder()
	app.handleListMCPClientServers(w, mcpClientReq("GET", "/api/mcp-client/servers", "", "admin"))
	if w.Code != 200 {
		t.Fatalf("GET servers code=%d body=%s", w.Code, w.Body.String())
	}
	var srvResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &srvResp)
	servers, ok := srvResp["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("expected 1 server, got %+v", srvResp)
	}

	// 5. Delete Server
	w = httptest.NewRecorder()
	r := mcpClientReq("DELETE", "/api/mcp-client/servers/jira", "", "admin")
	r.SetPathValue("name", "jira")
	app.handleDeleteMCPClientServer(w, r)
	if w.Code != 200 {
		t.Fatalf("DELETE server code=%d body=%s", w.Code, w.Body.String())
	}
}
