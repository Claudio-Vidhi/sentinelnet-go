package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	key, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault)
}

func adminReq(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
}

func TestProfilesEmptyByDefault(t *testing.T) {
	app := newTestApp(t)
	list, active := app.loadProfiles()
	if len(list) != 0 || active != "" {
		t.Fatalf("want empty list and no active, got %d profiles active=%q", len(list), active)
	}
}

func TestSaveLoadFindRoundtrip(t *testing.T) {
	app := newTestApp(t)
	p := aiProfile{ID: newProfileID(), Name: "p1", Provider: "ollama", APIKeyEnc: "secret-enc"}
	if err := app.saveProfiles([]aiProfile{p}, p.ID); err != nil {
		t.Fatal(err)
	}
	list, active := app.loadProfiles()
	if len(list) != 1 || active != p.ID {
		t.Fatalf("roundtrip mismatch: %d profiles active=%q", len(list), active)
	}
	if findProfile(list, p.ID) == nil {
		t.Error("findProfile should locate saved profile")
	}
	if findProfile(list, "nope") != nil || findProfile(list, "") != nil {
		t.Error("findProfile must return nil for missing/empty id")
	}
}

func TestMaskNeverExposesKey(t *testing.T) {
	m := maskProfile(aiProfile{ID: "x", Name: "n", Provider: "openai", APIKeyEnc: "ciphertext"})
	if _, ok := m["api_key_enc"]; ok {
		t.Error("mask must not include api_key_enc")
	}
	if _, ok := m["api_key"]; ok {
		t.Error("mask must not include api_key")
	}
	if m["api_key_set"] != true {
		t.Error("api_key_set should be true when key present")
	}
	if maskProfile(aiProfile{})["api_key_set"] != false {
		t.Error("api_key_set should be false when key absent")
	}
}

func TestAssertUnredactedAllowed(t *testing.T) {
	if assertUnredactedAllowed(false, "anthropic", "") != nil {
		t.Error("allow=false must always pass")
	}
	if assertUnredactedAllowed(true, "ollama", "") != nil {
		t.Error("ollama must be allowed")
	}
	if assertUnredactedAllowed(true, "openai", "http://127.0.0.1:1234/v1") != nil {
		t.Error("openai on local base_url must be allowed")
	}
	if assertUnredactedAllowed(true, "openai", "https://api.openai.com/v1") == nil {
		t.Error("openai on remote base_url must be rejected")
	}
	if assertUnredactedAllowed(true, "anthropic", "") == nil {
		t.Error("anthropic must be rejected")
	}
}

func TestCreateAndListProfile(t *testing.T) {
	app := newTestApp(t)

	// Nome vuoto → 400.
	rec := httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles", `{"name":"","provider":"ollama"}`))
	if rec.Code != 400 {
		t.Fatalf("empty name: status = %d, want 400", rec.Code)
	}

	// Provider non valido → 400.
	rec = httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles", `{"name":"x","provider":"foo"}`))
	if rec.Code != 400 {
		t.Fatalf("bad provider: status = %d, want 400", rec.Code)
	}

	// unredacted su provider remoto → 400.
	rec = httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
		`{"name":"x","provider":"anthropic","allow_unredacted":true}`))
	if rec.Code != 400 {
		t.Fatalf("unredacted remote: status = %d, want 400", rec.Code)
	}

	// Creazione valida con chiave.
	rec = httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
		`{"name":"Primo","provider":"anthropic","api_key":"sk-123","rate_limit_rpm":-5}`))
	if rec.Code != 200 {
		t.Fatalf("create: status = %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created["api_key_set"] != true || created["rate_limit_rpm"] != float64(0) {
		t.Errorf("created payload wrong: %+v", created)
	}
	if _, ok := created["api_key_enc"]; ok {
		t.Error("create response must not leak api_key_enc")
	}

	// Il primo profilo diventa attivo; la chiave è cifrata a riposo.
	list, active := app.loadProfiles()
	if len(list) != 1 || active != list[0].ID {
		t.Fatalf("first profile should be active: %d active=%q", len(list), active)
	}
	if list[0].APIKeyEnc == "" || list[0].APIKeyEnc == "sk-123" {
		t.Errorf("api key must be stored encrypted, got %q", list[0].APIKeyEnc)
	}

	// List riporta il profilo mascherato e l'attivo.
	rec = httptest.NewRecorder()
	app.handleListAIProfiles(rec, adminReq("GET", "/api/ai/profiles", ""))
	var lst map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &lst)
	if lst["active_profile"] != active {
		t.Errorf("active_profile = %v, want %v", lst["active_profile"], active)
	}
	if profs, _ := lst["profiles"].([]any); len(profs) != 1 {
		t.Errorf("profiles length = %d, want 1", len(profs))
	}
}
