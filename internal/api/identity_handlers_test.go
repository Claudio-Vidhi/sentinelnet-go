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

func identityApp(t *testing.T) *App {
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
	_ = st.CreateTenant("acme", "")
	return NewApp(nil, st, nil, vault)
}

func identityReq(method, path, body, role string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	return r.WithContext(context.WithValue(r.Context(), claimsKey, &auth.Claims{Username: "u", Role: role}))
}

func TestIdentitiesAPIWorkflow(t *testing.T) {
	app := identityApp(t)

	// 1. Create Identity (POST)
	body := `{"name":"Cisco Standard","tenant":"acme","username":"admin","password":"secretpass","secret":"enablepass"}`
	w := httptest.NewRecorder()
	app.handleCreateIdentity(w, identityReq("POST", "/api/identities", body, "operator"))
	if w.Code != 200 {
		t.Fatalf("POST /api/identities code=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	ident, ok := resp["identity"].(map[string]any)
	if !ok || ident["id"] == nil {
		t.Fatalf("invalid identity response: %+v", resp)
	}
	id := ident["id"].(string)

	// 2. List Identities (GET)
	w = httptest.NewRecorder()
	app.handleListIdentities(w, identityReq("GET", "/api/identities?tenant=acme", "", "viewer"))
	if w.Code != 200 {
		t.Fatalf("GET /api/identities code=%d body=%s", w.Code, w.Body.String())
	}
	var listResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &listResp)
	items, ok := listResp["identities"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 identity in list, got %+v", listResp)
	}

	// 3. Update Identity (PUT)
	updateBody := `{"name":"Cisco Updated","tenant":"acme","username":"netadmin","password":"newpass","secret":"newsecret"}`
	w = httptest.NewRecorder()
	r := identityReq("PUT", "/api/identities/"+id, updateBody, "operator")
	r.SetPathValue("id", id)
	app.handleUpdateIdentity(w, r)
	if w.Code != 200 {
		t.Fatalf("PUT /api/identities/%s code=%d body=%s", id, w.Code, w.Body.String())
	}

	// 4. Delete Identity (DELETE)
	w = httptest.NewRecorder()
	r = identityReq("DELETE", "/api/identities/"+id, "", "operator")
	r.SetPathValue("id", id)
	app.handleDeleteIdentity(w, r)
	if w.Code != 200 {
		t.Fatalf("DELETE /api/identities/%s code=%d body=%s", id, w.Code, w.Body.String())
	}
}
